//! Bouton de clavier et de déconnexion déplaçables : position bornée et retenue par appareil.

pub const SIDE: f64 = 44.0;
pub const GAP: f64 = 8.0;
pub const WIDTH: f64 = SIDE;
pub const HEIGHT: f64 = SIDE * 2.0 + GAP;
pub const MARGIN: f64 = 8.0;
/// Glissé minimal (px) avant que le toucher devienne un déplacement.
pub const DRAG_START: f64 = 8.0;
const KEY: &str = "portique.session.dock";

/// Zone où le groupe peut se poser : (gauche, haut, droite, bas).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Area(pub f64, pub f64, pub f64, pub f64);

impl Area {
    /// Vue visible `(x, y, largeur, hauteur)` moins les zones sûres `(haut, droite, bas, gauche)`,
    /// une marge, et `reserved` px en bas (barre de touches).
    pub fn new(view: (f64, f64, f64, f64), insets: (f64, f64, f64, f64), reserved: f64) -> Area {
        let (x, y, w, h) = view;
        let (t, r, b, l) = insets;
        Area(x + l + MARGIN, y + t + MARGIN, x + w - r - MARGIN, y + h - b - MARGIN - reserved)
    }
}

/// Coin haut-gauche ramené dans la zone ; une zone trop petite garde le coin haut-gauche.
pub fn clamp(pos: (f64, f64), a: Area) -> (f64, f64) {
    let x = pos.0.clamp(a.0, (a.2 - WIDTH).max(a.0));
    let y = pos.1.clamp(a.1, (a.3 - HEIGHT).max(a.1));
    (x, y)
}

/// Position affichée : la retenue bornée, à défaut en haut à droite.
pub fn place(saved: Option<(f64, f64)>, a: Area) -> (f64, f64) {
    clamp(saved.unwrap_or((a.2 - WIDTH, a.1)), a)
}

fn parse(s: &str) -> Option<(f64, f64)> {
    let (x, y) = s.split_once(',')?;
    let (x, y) = (x.trim().parse::<f64>().ok()?, y.trim().parse::<f64>().ok()?);
    (x.is_finite() && y.is_finite()).then_some((x, y))
}

pub fn load() -> Option<(f64, f64)> {
    parse(&web_sys::window()?.local_storage().ok()??.get_item(KEY).ok()??)
}

pub fn save(pos: (f64, f64)) {
    if let Some(Some(s)) = web_sys::window().and_then(|w| w.local_storage().ok()) {
        let _ = s.set_item(KEY, &format!("{:.0},{:.0}", pos.0, pos.1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn position_stays_inside_the_safe_area() {
        let a = Area::new((0.0, 0.0, 390.0, 844.0), (47.0, 0.0, 34.0, 0.0), 0.0);
        assert_eq!(a, Area(8.0, 55.0, 382.0, 802.0));
        assert_eq!(clamp((-50.0, -50.0), a), (8.0, 55.0));
        assert_eq!(clamp((1000.0, 1000.0), a), (382.0 - WIDTH, 802.0 - HEIGHT));
        assert_eq!(clamp((100.0, 300.0), a), (100.0, 300.0), "dedans : inchangé");
        assert_eq!(place(None, a), (382.0 - WIDTH, 55.0), "défaut : en haut à droite");
    }

    #[test]
    fn keyboard_bar_and_viewport_offset_shrink_the_area() {
        // Clavier iOS ouvert : vue visible plus basse, barre de 106 px réservée.
        let a = Area::new((0.0, 0.0, 390.0, 500.0), (0.0, 0.0, 0.0, 0.0), 106.0);
        assert_eq!(clamp((0.0, 9999.0), a).1, 500.0 - 8.0 - 106.0 - HEIGHT);
        let scrolled = Area::new((0.0, 120.0, 390.0, 500.0), (0.0, 0.0, 0.0, 0.0), 0.0);
        assert_eq!(clamp((0.0, 0.0), scrolled).1, 128.0);
    }

    #[test]
    fn tiny_area_does_not_panic() {
        let a = Area(8.0, 8.0, 20.0, 20.0);
        assert_eq!(clamp((500.0, 500.0), a), (8.0, 8.0));
    }

    #[test]
    fn storage_value_roundtrip() {
        assert_eq!(parse("12,34"), Some((12.0, 34.0)));
        assert_eq!(parse(" 12 , 34 "), Some((12.0, 34.0)));
        assert_eq!(parse("x,1"), None);
        assert_eq!(parse("NaN,1"), None);
        assert_eq!(parse("5"), None);
    }
}
