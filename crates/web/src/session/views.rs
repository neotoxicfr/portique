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

    /// Recopie les zones modifiées de la sortie qui tombent dans cette vue.
    pub fn blit(&self, fb: &[u8], fb_width: u32, damage: &[Rect]) {
        let v = self.rect;
        for d in damage {
            let x1 = d.x.max(v.x);
            let y1 = d.y.max(v.y);
            let x2 = (d.x + d.w).min(v.x + v.w);
            let y2 = (d.y + d.h).min(v.y + v.h);
            if x1 >= x2 || y1 >= y2 {
                continue;
            }
            let (w, h) = (x2 - x1, y2 - y1);
            let mut tmp = Vec::with_capacity((w * h * 4) as usize);
            for row in y1..y2 {
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

fn num(v: &JsValue, key: &str) -> f64 {
    Reflect::get(v, &key.into()).ok().and_then(|x| x.as_f64()).unwrap_or(0.0)
}

/// Écrans du poste (demande la permission « gestion des fenêtres ») et index de l'écran courant.
pub async fn screens() -> Result<(Vec<ScreenGeom>, usize), String> {
    let window = web_sys::window().ok_or("pas de fenêtre")?;
    let f = Reflect::get(&window, &"getScreenDetails".into()).map_err(|_| "API indisponible")?;
    let f: js_sys::Function = f.dyn_into().map_err(|_| "multi-écran non pris en charge par ce navigateur")?;
    let details = JsFuture::from(js_sys::Promise::from(f.call0(&window).map_err(|e| format!("{e:?}"))?))
        .await
        .map_err(|_| "permission refusée")?;
    let list: js_sys::Array =
        Reflect::get(&details, &"screens".into()).map_err(|e| format!("{e:?}"))?.unchecked_into();
    let current = Reflect::get(&details, &"currentScreen".into()).unwrap_or(JsValue::NULL);
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

/// Ouvre une fenêtre plein écran sur `screen` avec un canevas noir (appel dans un geste
/// utilisateur, sinon le navigateur bloque la fenêtre).
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
    Ok((w, canvas))
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
}
