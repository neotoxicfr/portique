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

/// Côté maximal du bureau englobant : plafond de la sortie de `rdp-gfx` (`MAX_SIDE`).
const MAX_DESKTOP_SIDE: u32 = rdp_gfx::MAX_SIDE;

/// Disposition à envoyer (relative à l'écran principal) et rectangles attendus en sortie, ou la
/// raison pour laquelle le PC l'ignorerait (MS-RDPEDISP 2.2.2.2.1). La largeur doit être paire :
/// tous les bords verticaux sont ramenés au pair inférieur, si bien que deux écrans voisins le
/// restent (arrondir la seule largeur ouvrirait un intervalle d'un pixel).
pub fn layout(screens: &[ScreenGeom], primary: usize) -> Result<(Vec<Monitor>, Vec<Rect>), String> {
    let p = &screens[primary];
    let even = |v: i64| v & !1;
    let mut rel: Vec<Monitor> = Vec::with_capacity(screens.len());
    for s in screens {
        let x = i64::from(s.left) - i64::from(p.left);
        let w = u32::try_from(even(x + i64::from(s.width)) - even(x)).unwrap_or(0);
        if !(200..=8192).contains(&w) || !(200..=8192).contains(&s.height) {
            return Err(format!(
                "écran {}×{} hors des limites du protocole (200 à 8192 px)",
                s.width, s.height
            ));
        }
        rel.push((even(x) as i32, (i64::from(s.top) - i64::from(p.top)) as i32, w, s.height));
    }
    check_arrangement(&rel)?;
    let min_x = rel.iter().map(|r| r.0).min().unwrap_or(0);
    let min_y = rel.iter().map(|r| r.1).min().unwrap_or(0);
    // Le PC enverrait un bureau englobant que `rdp-gfx` refuse (Reset Graphics hors bornes) : la
    // session se fermerait. Refusé ici, avant toute fenêtre, le mode à un écran reste.
    let side = |v: i64| u32::try_from(v).unwrap_or(u32::MAX);
    let bw = side(rel.iter().map(|r| i64::from(r.0) + i64::from(r.2)).max().unwrap_or(0) - i64::from(min_x));
    let bh = side(rel.iter().map(|r| i64::from(r.1) + i64::from(r.3)).max().unwrap_or(0) - i64::from(min_y));
    if bw > MAX_DESKTOP_SIDE || bh > MAX_DESKTOP_SIDE {
        return Err(format!("bureau de {bw}×{bh} : au plus {MAX_DESKTOP_SIDE} px par côté"));
    }
    let rects =
        rel.iter().map(|&(x, y, w, h)| Rect { x: (x - min_x) as u32, y: (y - min_y) as u32, w, h }).collect();
    Ok((rel, rects))
}

/// Conditions du PC pour appliquer une disposition (MS-RDPEDISP 3.1.5.2) : aucun recouvrement, et
/// chaque écran adjacent à au moins un autre, même par un seul point. Rien de plus : deux paires
/// d'écrans séparées par un intervalle restent valides.
fn check_arrangement(m: &[Monitor]) -> Result<(), String> {
    let r: Vec<[i64; 4]> = m
        .iter()
        .map(|&(x, y, w, h)| [x.into(), y.into(), i64::from(x) + i64::from(w), i64::from(y) + i64::from(h)])
        .collect();
    // Projections sur l'axe `k` (0 : x, 1 : y) : recouvrement d'une longueur non nulle, ou contact.
    let cross = |a: &[i64; 4], b: &[i64; 4], k: usize| a[k].max(b[k]) < a[k + 2].min(b[k + 2]);
    let meet = |a: &[i64; 4], b: &[i64; 4], k: usize| a[k].max(b[k]) <= a[k + 2].min(b[k + 2]);
    let touch = |a: &[i64; 4], b: &[i64; 4]| {
        ((a[2] == b[0] || b[2] == a[0]) && meet(a, b, 1)) || ((a[3] == b[1] || b[3] == a[1]) && meet(a, b, 0))
    };
    for (i, a) in r.iter().enumerate() {
        if r[i + 1..].iter().any(|b| cross(a, b, 0) && cross(a, b, 1)) {
            return Err("écrans qui se recouvrent : disposition refusée par le protocole".into());
        }
    }
    // Un écran seul n'a pas de voisin à toucher.
    let isolated = |i: usize| (0..r.len()).all(|j| j == i || !touch(&r[i], &r[j]));
    if r.len() > 1 && (0..r.len()).any(isolated) {
        return Err("écran isolé par un intervalle : disposition refusée par le protocole".into());
    }
    Ok(())
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
        // Ni l'arrondi flottant ni une borne minimale de 200 ne doivent faire déborder : chaque
        // côté est recalculé en entiers sur l'autre (largeur paire).
        let side = |other: u32| u32::try_from(self.max_area / u64::from(other)).unwrap_or(u32::MAX);
        let h = h.min(side(w)).max(200);
        let w = (w.min(side(h)) & !1).max(200);
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
        let (rel, rects) = layout(&screens, 0).unwrap();
        assert_eq!(rel, [(0, 0, 1920, 1080), (-1280, 56, 1280, 1024)]);
        assert_eq!(rects[0], Rect { x: 1280, y: 0, w: 1920, h: 1080 });
        assert_eq!(rects[1], Rect { x: 0, y: 56, w: 1280, h: 1024 });
        let pdu = layout_pdu(&rel, 0);
        assert_eq!(pdu.len(), 96);
        assert_eq!(&pdu[16..20], &1u32.to_le_bytes(), "principal");
        assert_eq!(&pdu[60..64], &(-1280i32).to_le_bytes());
    }

    #[test]
    fn odd_widths_keep_screens_adjacent() {
        // 1025 px puis un écran à x = 1025 : le bord commun passe à 1024 pour les deux.
        let (rel, rects) = layout(&[s(0, 0, 1025, 768), s(1025, 0, 1920, 1080)], 0).unwrap();
        assert_eq!(rel, [(0, 0, 1024, 768), (1024, 0, 1920, 1080)]);
        assert_eq!(rects[1], Rect { x: 1024, y: 0, w: 1920, h: 1080 });
        // Écran secondaire de largeur impaire à gauche (1366 px à 125 %) : collé au principal.
        let (rel, _) = layout(&[s(0, 0, 1920, 1080), s(-1093, 0, 1093, 614)], 0).unwrap();
        assert_eq!(rel[1], (-1094, 0, 1094, 614));
        // Contact par un coin : accepté ; intervalle, recouvrement, taille hors bornes : refusés.
        assert!(layout(&[s(0, 0, 1920, 1080), s(1920, 1080, 1920, 1080)], 0).is_ok());
        assert!(layout(&[s(0, 0, 1920, 1080), s(1930, 0, 1920, 1080)], 0).is_err(), "intervalle");
        assert!(layout(&[s(0, 0, 1920, 1080), s(1000, 0, 1920, 1080)], 1).is_err(), "recouvrement");
        assert!(layout(&[s(0, 0, 1920, 1080), s(1920, 0, 9000, 1080)], 0).is_err(), "trop large");
        assert!(layout(&[s(0, 0, 1920, 1080), s(1920, 0, 1920, 150)], 0).is_err(), "trop bas");
        // Trois écrans en ligne : le troisième n'est relié qu'au deuxième.
        let row = [s(0, 0, 1920, 1080), s(1920, 0, 1920, 1080), s(3840, 0, 1920, 1080)];
        assert!(layout(&row, 1).is_ok());
    }

    #[test]
    fn each_screen_needs_one_neighbour_not_one_group() {
        // MS-RDPEDISP 3.1.5.2 : un voisin par écran. Deux paires séparées par un intervalle passent.
        let pairs =
            [s(0, 0, 1920, 1080), s(1920, 0, 1920, 1080), s(4000, 0, 1920, 1080), s(5920, 0, 1920, 1080)];
        assert!(layout(&pairs, 0).is_ok());
        // Un écran sans aucun voisin reste refusé, même si les autres se touchent.
        let lone = [s(0, 0, 1920, 1080), s(1920, 0, 1920, 1080), s(4000, 0, 1920, 1080)];
        assert!(layout(&lone, 0).is_err(), "écran isolé");
    }

    #[test]
    fn bounding_desktop_within_the_graphics_limit() {
        // Deux 5120×1440 côte à côte : chacun est valide, le bureau de 10240 px ne l'est pas.
        assert!(layout(&[s(0, 0, 5120, 1440), s(5120, 0, 5120, 1440)], 0).is_err());
        assert!(layout(&[s(0, 0, 1920, 5000), s(0, 5000, 1920, 5000)], 1).is_err(), "en hauteur");
        // Deux 4K côte à côte (7680×2160) restent admissibles, de même qu'un bureau de 8192 px.
        assert!(layout(&[s(0, 0, 3840, 2160), s(3840, 0, 3840, 2160)], 0).is_ok());
        assert!(layout(&[s(0, 0, 4096, 2160), s(-4096, 0, 4096, 2160)], 0).is_ok());
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
        // Fenêtre très plate ou très haute : le côté au minimum (200) réduit l'autre.
        let flat = DisplayCaps { max_monitors: 1, max_area: 200_000 };
        assert_eq!(flat.fit(8192, 200), (1000, 200));
        assert_eq!(flat.fit(200, 8192), (200, 1000));
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
