//! Vues du bureau : la fenêtre principale et, en multi-écran, une fenêtre par écran secondaire.
//!
//! Le bureau distant est une seule sortie (rectangle englobant de tous les écrans) ; chaque vue
//! en affiche un rectangle. L'écran de la fenêtre principale est l'écran principal du PC
//! (coordonnées (0,0) dans la disposition envoyée, MS-RDPEDISP 2.2.2.2.1).

use js_sys::Reflect;
use rdp_gfx::Rect;
use wasm_bindgen::{Clamped, JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{CanvasRenderingContext2d, HtmlCanvasElement, ImageData, Window};

/// Écran du poste client (API Window Management), en pixels CSS.
#[derive(Debug, Clone, PartialEq)]
pub struct ScreenGeom {
    pub left: i32,
    pub top: i32,
    pub width: u32,
    pub height: u32,
    pub label: String,
}

pub struct View {
    pub canvas: HtmlCanvasElement,
    ctx: CanvasRenderingContext2d,
    /// Rectangle du bureau affiché, en coordonnées de sortie.
    pub rect: Rect,
    /// Fenêtre secondaire (None pour la fenêtre principale).
    pub window: Option<Window>,
    /// Gestionnaires d'événements de la fenêtre secondaire, gardés en vie avec elle.
    pub closures: Vec<JsValue>,
}

fn context(canvas: &HtmlCanvasElement) -> Result<CanvasRenderingContext2d, String> {
    Ok(canvas.get_context("2d").ok().flatten().ok_or("canevas 2D indisponible")?.unchecked_into())
}

impl View {
    pub fn new(canvas: HtmlCanvasElement, rect: Rect, window: Option<Window>) -> Result<Self, String> {
        let ctx = context(&canvas)?;
        canvas.set_width(rect.w);
        canvas.set_height(rect.h);
        Ok(Self { canvas, ctx, rect, window, closures: Vec::new() })
    }

    pub fn set_rect(&mut self, rect: Rect) {
        self.rect = rect;
        self.canvas.set_width(rect.w);
        self.canvas.set_height(rect.h);
    }

    /// Recopie les zones modifiées de la sortie (`fb`, `fb_width` × `fb_height`) qui tombent dans
    /// cette vue.
    pub fn blit(&self, fb: &[u8], fb_width: u32, fb_height: u32, damage: &[Rect]) {
        let v = self.rect;
        // Tampon plus court qu'annoncé : on ne lit que ses lignes complètes.
        let fb_height = fb_height.min((fb.len() / (fb_width.max(1) as usize * 4)) as u32);
        for d in damage {
            let Some(Rect { x: x1, y: y1, w, h }) = blit_area(*d, v, fb_width, fb_height) else { continue };
            let mut tmp = Vec::with_capacity((w * h * 4) as usize);
            for row in y1..y1 + h {
                let o = ((row * fb_width + x1) * 4) as usize;
                tmp.extend_from_slice(&fb[o..o + (w * 4) as usize]);
            }
            if let Ok(img) = ImageData::new_with_u8_clamped_array_and_sh(Clamped(&tmp), w, h) {
                let _ = self.ctx.put_image_data(&img, (x1 - v.x) as i32, (y1 - v.y) as i32);
            }
        }
    }

    pub fn set_cursor(&self, css: &str) {
        let _ = self.canvas.style().set_property("cursor", css);
    }

    /// Ferme la fenêtre secondaire.
    pub fn close(&self) {
        if let Some(w) = &self.window {
            let _ = w.close();
        }
    }
}

/// Partie de la zone `d` à recopier dans la vue `v`, bornée au tampon courant : une zone d'une
/// image d'avant un changement de taille peut déborder du nouveau tampon.
fn blit_area(d: Rect, v: Rect, fb_width: u32, fb_height: u32) -> Option<Rect> {
    let x1 = d.x.max(v.x);
    let y1 = d.y.max(v.y);
    let x2 = d.x.saturating_add(d.w).min(v.x.saturating_add(v.w)).min(fb_width);
    let y2 = d.y.saturating_add(d.h).min(v.y.saturating_add(v.h)).min(fb_height);
    (x1 < x2 && y1 < y2).then(|| Rect { x: x1, y: y1, w: x2 - x1, h: y2 - y1 })
}

fn num(v: &JsValue, key: &str) -> f64 {
    Reflect::get(v, &key.into()).ok().and_then(|x| x.as_f64()).unwrap_or(0.0)
}

/// `ScreenDetails` du poste (demande la permission « gestion des fenêtres ») : le navigateur le
/// tient à jour quand un écran est branché, débranché ou change de définition.
pub async fn screen_details() -> Result<JsValue, String> {
    let window = web_sys::window().ok_or("pas de fenêtre")?;
    let f = Reflect::get(&window, &"getScreenDetails".into()).map_err(|_| "API indisponible")?;
    let f: js_sys::Function = f.dyn_into().map_err(|_| "multi-écran non pris en charge par ce navigateur")?;
    JsFuture::from(js_sys::Promise::from(f.call0(&window).map_err(|e| format!("{e:?}"))?))
        .await
        .map_err(|_| "permission refusée".into())
}

/// Écrans décrits par `details` à cet instant, et index de l'écran courant.
pub fn screens(details: &JsValue) -> Result<(Vec<ScreenGeom>, usize), String> {
    let list: js_sys::Array =
        Reflect::get(details, &"screens".into()).map_err(|e| format!("{e:?}"))?.unchecked_into();
    let current = Reflect::get(details, &"currentScreen".into()).unwrap_or(JsValue::NULL);
    let mut out = Vec::new();
    let mut cur = 0;
    for (i, s) in list.iter().enumerate() {
        if s == current {
            cur = i;
        }
        out.push(ScreenGeom {
            left: num(&s, "left") as i32,
            top: num(&s, "top") as i32,
            width: num(&s, "width") as u32,
            height: num(&s, "height") as u32,
            label: Reflect::get(&s, &"label".into()).ok().and_then(|l| l.as_string()).unwrap_or_default(),
        });
    }
    Ok((out, cur))
}

/// Écran envoyé au PC : x, y relatifs à l'écran principal, largeur, hauteur.
pub type Monitor = (i32, i32, u32, u32);

/// Disposition à envoyer (relative à l'écran principal) et rectangles attendus en sortie.
pub fn layout(screens: &[ScreenGeom], primary: usize) -> (Vec<Monitor>, Vec<Rect>) {
    let p = &screens[primary];
    let rel: Vec<Monitor> = screens
        .iter()
        .map(|s| {
            let (w, h) = crate::session::engine::clamp_size(s.width, s.height);
            (s.left - p.left, s.top - p.top, w, h)
        })
        .collect();
    let min_x = rel.iter().map(|r| r.0).min().unwrap_or(0);
    let min_y = rel.iter().map(|r| r.1).min().unwrap_or(0);
    let rects =
        rel.iter().map(|&(x, y, w, h)| Rect { x: (x - min_x) as u32, y: (y - min_y) as u32, w, h }).collect();
    (rel, rects)
}

/// Limites annoncées par le PC (DISPLAYCONTROL_CAPS_PDU, MS-RDPEDISP 2.2.2.1).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DisplayCaps {
    pub max_monitors: u32,
    /// Surface totale permise (px²) : MaxMonitorAreaFactorA × MaxMonitorAreaFactorB × MaxNumMonitors.
    pub max_area: u64,
}

impl DisplayCaps {
    /// `None` si `pdu` n'est pas une DISPLAYCONTROL_CAPS_PDU complète (`Length` : la PDU entière).
    pub fn parse(pdu: &[u8]) -> Option<Self> {
        let u = |i: usize| pdu.get(i..i + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        let len = u(4)? as usize;
        if u(0)? != 5 || len < 20 || len > pdu.len() {
            return None;
        }
        let (n, a, b) = (u(8)?, u(12)?, u(16)?);
        Some(Self {
            max_monitors: n,
            max_area: u64::try_from(u128::from(n) * u128::from(a) * u128::from(b)).unwrap_or(u64::MAX),
        })
    }

    /// La disposition tient-elle dans les limites du PC ? Sinon, la raison à afficher.
    pub fn check(&self, monitors: &[Monitor]) -> Result<(), String> {
        if monitors.len() as u64 > u64::from(self.max_monitors) {
            return Err(format!("le PC accepte au plus {} écran(s)", self.max_monitors));
        }
        let area: u64 = monitors.iter().map(|m| u64::from(m.2) * u64::from(m.3)).sum();
        if area > self.max_area {
            return Err("surface des écrans trop grande pour le PC".into());
        }
        Ok(())
    }

    /// Taille d'un écran seul ramenée dans la surface permise, proportions gardées (largeur paire,
    /// bornes du protocole). Un PC trop limité pour 200×200 reste refusé par `check`.
    pub fn fit(&self, w: u32, h: u32) -> (u32, u32) {
        let area = u64::from(w) * u64::from(h);
        if area <= self.max_area {
            return (w, h);
        }
        let k = (self.max_area as f64 / area as f64).sqrt();
        let (w, h) = crate::session::engine::clamp_size((f64::from(w) * k) as u32, (f64::from(h) * k) as u32);
        // L'arrondi flottant ne doit pas faire déborder d'un pixel : hauteur recalculée en entiers.
        let h = h.min(u32::try_from(self.max_area / u64::from(w)).unwrap_or(u32::MAX)).max(200);
        (w, h)
    }
}

/// DISPLAYCONTROL_MONITOR_LAYOUT_PDU (MS-RDPEDISP 2.2.2.2), écran `primary` principal.
pub fn layout_pdu(monitors: &[Monitor], primary: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(16 + 40 * monitors.len());
    p.extend_from_slice(&2u32.to_le_bytes());
    p.extend_from_slice(&((16 + 40 * monitors.len()) as u32).to_le_bytes());
    p.extend_from_slice(&40u32.to_le_bytes());
    p.extend_from_slice(&(monitors.len() as u32).to_le_bytes());
    for (i, &(x, y, w, h)) in monitors.iter().enumerate() {
        let flags = u32::from(i == primary);
        for v in [flags, x as u32, y as u32, w, h, 0, 0, 0, 100, 100] {
            p.extend_from_slice(&v.to_le_bytes());
        }
    }
    p
}

/// Ouvre une fenêtre plein écran sur `screen` avec un canevas noir. Appel dans un geste
/// utilisateur, UNE fenêtre par geste : une deuxième ouverture dans le même clic peut être
/// bloquée (l'activation est consommée par la première). Fermée si sa préparation échoue.
pub fn open_window(screen: &ScreenGeom, n: usize) -> Result<(Window, HtmlCanvasElement), String> {
    let window = web_sys::window().ok_or("pas de fenêtre")?;
    let features = format!(
        "popup,fullscreen,left={},top={},width={},height={}",
        screen.left, screen.top, screen.width, screen.height
    );
    let w = window
        .open_with_url_and_target_and_features("about:blank", &format!("portique-ecran-{n}"), &features)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("fenêtre bloquée par le navigateur (autoriser les fenêtres surgissantes)")?;
    match fill_window(&w, n) {
        Ok(canvas) => Ok((w, canvas)),
        Err(e) => {
            let _ = w.close();
            Err(e)
        }
    }
}

fn fill_window(w: &Window, n: usize) -> Result<HtmlCanvasElement, String> {
    let doc = w.document().ok_or("document de la fenêtre indisponible")?;
    doc.set_title(&format!("Portique — écran {}", n + 1));
    let body = doc.body().ok_or("corps de document absent")?;
    let _ = body.style().set_property("margin", "0");
    let _ = body.style().set_property("background", "#000");
    let _ = body.style().set_property("overflow", "hidden");
    let canvas: HtmlCanvasElement =
        doc.create_element("canvas").map_err(|e| format!("{e:?}"))?.unchecked_into();
    for (k, v) in [
        ("position", "fixed"),
        ("inset", "0"),
        ("width", "100%"),
        ("height", "100%"),
        ("object-fit", "contain"),
        ("touch-action", "none"),
        ("outline", "none"),
    ] {
        let _ = canvas.style().set_property(k, v);
    }
    canvas.set_tab_index(0);
    body.append_child(&canvas).map_err(|e| format!("{e:?}"))?;
    Ok(canvas)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(left: i32, top: i32, width: u32, height: u32) -> ScreenGeom {
        ScreenGeom { left, top, width, height, label: String::new() }
    }

    #[test]
    fn secondary_on_the_left() {
        let screens = [s(0, 0, 1920, 1080), s(-1280, 56, 1280, 1024)];
        let (rel, rects) = layout(&screens, 0);
        assert_eq!(rel, [(0, 0, 1920, 1080), (-1280, 56, 1280, 1024)]);
        assert_eq!(rects[0], Rect { x: 1280, y: 0, w: 1920, h: 1080 });
        assert_eq!(rects[1], Rect { x: 0, y: 56, w: 1280, h: 1024 });
        let pdu = layout_pdu(&rel, 0);
        assert_eq!(pdu.len(), 96);
        assert_eq!(&pdu[16..20], &1u32.to_le_bytes(), "principal");
        assert_eq!(&pdu[60..64], &(-1280i32).to_le_bytes());
    }

    #[test]
    fn display_caps_limit_layouts() {
        let le = |v: [u32; 5]| v.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>();
        let one = DisplayCaps::parse(&le([5, 20, 1, 3840, 2400])).unwrap();
        assert_eq!(one, DisplayCaps { max_monitors: 1, max_area: 3840 * 2400 });
        let two = [(0, 0, 1920, 1080), (1920, 0, 1920, 1080)];
        assert!(one.check(&two).is_err(), "deux écrans pour un PC qui n'en accepte qu'un");
        assert!(one.check(&two[..1]).is_ok());
        let small = DisplayCaps::parse(&le([5, 20, 2, 1920, 1080])).unwrap();
        assert!(small.check(&two).is_ok());
        assert!(small.check(&[(0, 0, 3840, 2160), (3840, 0, 1920, 1080)]).is_err(), "surface");
        assert_eq!(DisplayCaps::parse(&le([2, 20, 1, 1, 1])), None, "pas une CAPS PDU");
        assert_eq!(DisplayCaps::parse(&le([5, 20, 1, 1, 1])[..16]), None, "tronquée");
        assert_eq!(DisplayCaps::parse(&le([5, 40, 1, 1, 1])), None, "Length au-delà des 20 octets reçus");
        assert!(DisplayCaps::parse(&[le([5, 20, 1, 1, 1]), vec![0; 4]].concat()).is_some(), "octets en plus");
        // 16 × 2^30 × 2^30 = 2^64 : plafonné, pas de débordement silencieux.
        assert_eq!(
            DisplayCaps::parse(&le([5, 20, 16, 1 << 30, 1 << 30])).map(|c| c.max_area),
            Some(u64::MAX)
        );
    }

    #[test]
    fn single_monitor_size_fits_the_caps() {
        let caps = DisplayCaps { max_monitors: 1, max_area: 1920 * 1080 };
        assert_eq!(caps.fit(1920, 1080), (1920, 1080), "dans la limite : inchangé");
        let (w, h) = caps.fit(2560, 1440);
        assert!(caps.check(&[(0, 0, w, h)]).is_ok(), "{w}×{h}");
        assert_eq!((w, h), (1920, 1080), "même rapport 16:9");
        let (w, h) = caps.fit(3001, 1999);
        assert!(w % 2 == 0 && caps.check(&[(0, 0, w, h)]).is_ok(), "{w}×{h}");
        assert!(u64::from(w) * u64::from(h) > 1920 * 1080 * 99 / 100, "pas de réduction excessive");
        let tiny = DisplayCaps { max_monitors: 1, max_area: 100 * 100 };
        let (w, h) = tiny.fit(1920, 1080);
        assert!(w >= 200 && h >= 200 && tiny.check(&[(0, 0, w, h)]).is_err(), "bornes du protocole");
    }

    #[test]
    fn blit_area_bounded_by_current_buffer() {
        let view = Rect { x: 0, y: 0, w: 1920, h: 1080 };
        let d = Rect { x: 100, y: 900, w: 200, h: 100 };
        assert_eq!(blit_area(d, view, 1920, 1080), Some(d));
        // Tampon passé à 1280×720 avant la recopie d'une zone de l'image précédente.
        assert_eq!(blit_area(d, view, 1280, 720), None);
        let d = Rect { x: 1200, y: 700, w: 200, h: 100 };
        assert_eq!(blit_area(d, view, 1280, 720), Some(Rect { x: 1200, y: 700, w: 80, h: 20 }));
        assert_eq!(blit_area(Rect { x: u32::MAX, y: 0, w: 10, h: 10 }, view, 1280, 720), None);
    }
}
