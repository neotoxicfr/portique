//! Gestes tactiles → souris et zoom local, sans navigateur (testable).
//!
//! Un doigt : toucher = clic gauche, appui long immobile = clic droit, glisser = glisser bouton
//! gauche enfoncé. Deux doigts : glisser = molette, pincer = zoom local du canevas ; une fois zoomé,
//! deux doigts déplacent et zooment la vue (plus de molette avant d'être revenu à 1:1).
//! Coordonnées : pixels CSS de la page (`clientX/Y`) ; l'appelant les convertit en coordonnées
//! bureau au moment de l'envoi, transformation du canevas comprise.

/// Déplacement au-delà duquel un doigt posé n'est plus un toucher (px CSS).
const SLOP: f64 = 10.0;
/// Variation de l'écart entre deux doigts qui fait d'un geste un pincement (px CSS).
const PINCH_SLOP: f64 = 24.0;
/// Mouvements d'un doigt sans que l'autre bouge au-delà desquels celui-ci est tenu pour fixe :
/// avant, il peut s'agir d'un défilement dont le second doigt n'est pas encore signalé.
const SOLO_MOVES: u32 = 3;
/// Durée d'un appui long (ms).
pub const LONG_PRESS_MS: i32 = 500;
/// Toucher suivant dans ce délai et ce rayon : même point que le précédent, pour que Windows y
/// voie un double clic (il tolère peu de pixels d'écart).
const DOUBLE_TAP_MS: f64 = 500.0;
const DOUBLE_TAP_RADIUS: f64 = 24.0;
/// Molette (1/120 de cran) par pixel de glissement à deux doigts.
const WHEEL_PER_PX: f64 = 2.0;
const MAX_ZOOM: f64 = 5.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Button {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Action {
    Move {
        x: f64,
        y: f64,
    },
    Button {
        button: Button,
        down: bool,
        x: f64,
        y: f64,
    },
    /// `delta` : positif = vers le haut / la droite (convention RDP).
    Wheel {
        delta: i16,
        horizontal: bool,
        x: f64,
        y: f64,
    },
    Zoom(Zoom),
}

/// Transformation CSS du canevas (origine en haut à gauche) : le point local p s'affiche en
/// (tx, ty) + scale·p.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Zoom {
    pub scale: f64,
    pub tx: f64,
    pub ty: f64,
}

impl Default for Zoom {
    fn default() -> Self {
        Zoom { scale: 1.0, tx: 0.0, ty: 0.0 }
    }
}

#[derive(Debug, Clone, Copy)]
struct Finger {
    id: i32,
    x: f64,
    y: f64,
}

#[derive(Debug, Clone, Copy)]
enum Mode {
    Undecided,
    Scroll { acc_x: f64, acc_y: f64 },
    Pinch,
}

#[derive(Debug, Clone, Copy)]
enum State {
    Idle,
    /// Un doigt posé, pas encore décidé (toucher, appui long ou glisser).
    Pending {
        f: Finger,
        x0: f64,
        y0: f64,
    },
    Dragging {
        f: Finger,
    },
    /// Geste terminé (appui long rendu, doigt principal levé) : on attend que tout soit levé.
    Done,
    /// `a0`, `b0`, `d0`, `m0` : doigts, écart et milieu au départ ; `last` : milieu précédent ;
    /// `zoom0` : zoom au départ ; `moves` : mouvements signalés de chaque doigt.
    Two {
        a: Finger,
        b: Finger,
        moves: [u32; 2],
        a0: (f64, f64),
        b0: (f64, f64),
        d0: f64,
        m0: (f64, f64),
        last: (f64, f64),
        zoom0: Zoom,
        mode: Mode,
    },
}

pub struct Touch {
    /// Doigts posés (identifiants de pointeur).
    down: Vec<i32>,
    state: State,
    zoom: Zoom,
    /// Canevas non transformé : gauche, haut, largeur, hauteur (px CSS).
    area: (f64, f64, f64, f64),
    /// Dernier toucher rendu en clic : (x, y, instant).
    last_tap: Option<(f64, f64, f64)>,
    /// Numéro du geste à un doigt en cours, rappelé par la minuterie d'appui long.
    serial: u32,
}

impl Default for Touch {
    fn default() -> Self {
        Touch {
            down: Vec::new(),
            state: State::Idle,
            zoom: Zoom::default(),
            area: (0.0, 0.0, 1.0, 1.0),
            last_tap: None,
            serial: 0,
        }
    }
}

fn dist(a: (f64, f64), b: (f64, f64)) -> f64 {
    (a.0 - b.0).hypot(a.1 - b.1)
}

fn click(button: Button, x: f64, y: f64) -> Vec<Action> {
    vec![
        Action::Move { x, y },
        Action::Button { button, down: true, x, y },
        Action::Button { button, down: false, x, y },
    ]
}

impl Touch {
    pub fn set_area(&mut self, left: f64, top: f64, width: f64, height: f64) {
        self.area = (left, top, width.max(1.0), height.max(1.0));
    }

    pub fn down(&mut self, id: i32, x: f64, y: f64) -> Vec<Action> {
        if !self.down.contains(&id) {
            self.down.push(id);
        }
        let f = Finger { id, x, y };
        match self.state {
            State::Idle => {
                self.serial = self.serial.wrapping_add(1);
                self.state = State::Pending { f, x0: x, y0: y };
            }
            // Second doigt avant toute décision : geste à deux doigts, le toucher est annulé.
            State::Pending { f: a, .. } if a.id != id => {
                let m = ((a.x + x) / 2.0, (a.y + y) / 2.0);
                self.state = State::Two {
                    a,
                    b: f,
                    moves: [0, 0],
                    a0: (a.x, a.y),
                    b0: (x, y),
                    d0: dist((a.x, a.y), (x, y)).max(1.0),
                    m0: m,
                    last: m,
                    zoom0: self.zoom,
                    mode: if self.zoom.scale > 1.0 { Mode::Pinch } else { Mode::Undecided },
                };
            }
            // Doigts supplémentaires pendant un glisser ou un geste à deux : ignorés.
            _ => {}
        }
        Vec::new()
    }

    /// Geste dont l'appui long est à surveiller (numéro à rendre à `long_press`).
    pub fn long_press_serial(&self) -> Option<u32> {
        matches!(self.state, State::Pending { .. }).then_some(self.serial)
    }

    /// Minuterie d'appui long échue : clic droit si le doigt est resté immobile depuis.
    pub fn long_press(&mut self, serial: u32) -> Vec<Action> {
        match self.state {
            State::Pending { x0, y0, .. } if serial == self.serial => {
                self.state = State::Done;
                click(Button::Right, x0, y0)
            }
            _ => Vec::new(),
        }
    }

    pub fn moved(&mut self, id: i32, x: f64, y: f64) -> Vec<Action> {
        match &mut self.state {
            State::Pending { f, x0, y0 } if f.id == id => {
                let (x0, y0) = (*x0, *y0);
                if dist((x, y), (x0, y0)) <= SLOP {
                    (f.x, f.y) = (x, y);
                    return Vec::new();
                }
                self.state = State::Dragging { f: Finger { id, x, y } };
                vec![
                    Action::Move { x: x0, y: y0 },
                    Action::Button { button: Button::Left, down: true, x: x0, y: y0 },
                    Action::Move { x, y },
                ]
            }
            State::Dragging { f } if f.id == id => {
                (f.x, f.y) = (x, y);
                vec![Action::Move { x, y }]
            }
            State::Two { a, b, moves, .. } if a.id == id || b.id == id => {
                let (f, k) = if a.id == id { (a, 0) } else { (b, 1) };
                (f.x, f.y) = (x, y);
                moves[k] += 1;
                self.two_moved()
            }
            _ => Vec::new(),
        }
    }

    fn two_moved(&mut self) -> Vec<Action> {
        let State::Two { a, b, moves, a0, b0, d0, m0, last, zoom0, mode } = &mut self.state else {
            return Vec::new();
        };
        let m = ((a.x + b.x) / 2.0, (a.y + b.y) / 2.0);
        let d = dist((a.x, a.y), (b.x, b.y));
        if let Mode::Undecided = mode {
            // Défilement : les deux doigts ont bougé, dans le même sens. Un seul doigt parti change
            // l'écart comme un pincement, mais l'autre peut n'être signalé qu'à l'événement suivant :
            // pincement à un doigt fixe seulement après plusieurs mouvements du premier.
            let (da, db) = ((a.x - a0.0, a.y - a0.1), (b.x - b0.0, b.y - b0.1));
            let moved = |v: (f64, f64)| v.0.hypot(v.1) > SLOP / 2.0;
            let (ma, mb) = (moved(da), moved(db));
            let together = ma && mb && da.0 * db.0 + da.1 * db.1 > 0.0;
            let solo = (ma && !mb && moves[0] >= SOLO_MOVES) || (mb && !ma && moves[1] >= SOLO_MOVES);
            if (d - *d0).abs() > PINCH_SLOP && (ma && mb || solo) {
                *mode = Mode::Pinch;
            } else if together && dist(m, *m0) > SLOP {
                *mode = Mode::Scroll { acc_x: 0.0, acc_y: 0.0 };
            } else {
                return Vec::new();
            }
        }
        let prev = std::mem::replace(last, m);
        match mode {
            Mode::Undecided => Vec::new(),
            Mode::Scroll { acc_x, acc_y } => {
                // Défilement « naturel » : le contenu suit le doigt.
                *acc_y += (m.1 - prev.1) * WHEEL_PER_PX;
                *acc_x -= (m.0 - prev.0) * WHEEL_PER_PX;
                let mut out = Vec::new();
                for (acc, horizontal) in [(acc_y, false), (acc_x, true)] {
                    let v = acc.trunc().clamp(-255.0, 255.0);
                    if v != 0.0 {
                        *acc -= v;
                        out.push(Action::Wheel { delta: v as i16, horizontal, x: m.0, y: m.1 });
                    }
                }
                out
            }
            Mode::Pinch => {
                let (left, top, w, h) = self.area;
                let z0 = *zoom0;
                // Point du contenu sous le milieu de départ : il reste sous le milieu courant.
                let px = (m0.0 - left - z0.tx) / z0.scale;
                let py = (m0.1 - top - z0.ty) / z0.scale;
                let scale = (z0.scale * d / *d0).clamp(1.0, MAX_ZOOM);
                let tx = (m.0 - left - scale * px).clamp(w * (1.0 - scale), 0.0);
                let ty = (m.1 - top - scale * py).clamp(h * (1.0 - scale), 0.0);
                let z = Zoom { scale, tx, ty };
                if z == self.zoom {
                    return Vec::new();
                }
                self.zoom = z;
                vec![Action::Zoom(z)]
            }
        }
    }

    pub fn up(&mut self, id: i32, x: f64, y: f64, t: f64) -> Vec<Action> {
        self.down.retain(|d| *d != id);
        let out = match self.state {
            State::Pending { f, x0, y0 } if f.id == id => {
                self.state = State::Done;
                let (x, y) = match self.last_tap {
                    Some((lx, ly, lt))
                        if t - lt <= DOUBLE_TAP_MS && dist((lx, ly), (x0, y0)) <= DOUBLE_TAP_RADIUS =>
                    {
                        (lx, ly)
                    }
                    _ => (x0, y0),
                };
                self.last_tap = Some((x, y, t));
                click(Button::Left, x, y)
            }
            State::Dragging { f } if f.id == id => {
                self.state = State::Done;
                vec![Action::Move { x, y }, Action::Button { button: Button::Left, down: false, x, y }]
            }
            State::Two { a, b, .. } if a.id == id || b.id == id => {
                self.state = State::Done;
                Vec::new()
            }
            _ => Vec::new(),
        };
        if self.down.is_empty() {
            self.state = State::Idle;
        }
        out
    }

    /// Geste interrompu par le système : un bouton enfoncé est relâché, rien n'est cliqué. Un doigt
    /// supplémentaire (ignoré par le geste) annulé ne termine pas le geste en cours.
    pub fn cancel(&mut self, id: i32) -> Vec<Action> {
        self.down.retain(|d| *d != id);
        let ours = match self.state {
            State::Pending { f, .. } | State::Dragging { f } => f.id == id,
            State::Two { a, b, .. } => a.id == id || b.id == id,
            State::Idle | State::Done => false,
        };
        let out = match self.state {
            State::Dragging { f } if ours => {
                vec![Action::Button { button: Button::Left, down: false, x: f.x, y: f.y }]
            }
            _ => Vec::new(),
        };
        if self.down.is_empty() {
            self.state = State::Idle;
        } else if ours {
            self.state = State::Done;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch() -> Touch {
        let mut t = Touch::default();
        t.set_area(0.0, 0.0, 400.0, 800.0);
        t
    }

    #[test]
    fn tap_is_left_click_at_touch_point() {
        let mut t = touch();
        assert!(t.down(1, 100.0, 200.0).is_empty());
        assert!(t.moved(1, 104.0, 203.0).is_empty(), "tremblement sous le seuil");
        assert_eq!(t.up(1, 104.0, 203.0, 0.0), click(Button::Left, 100.0, 200.0));
    }

    #[test]
    fn second_tap_snaps_to_first_for_double_click() {
        let mut t = touch();
        t.down(1, 100.0, 200.0);
        t.up(1, 100.0, 200.0, 1000.0);
        t.down(2, 108.0, 195.0);
        assert_eq!(t.up(2, 108.0, 195.0, 1300.0), click(Button::Left, 100.0, 200.0));
        // Trop tard : point réel.
        t.down(3, 108.0, 195.0);
        assert_eq!(t.up(3, 108.0, 195.0, 2500.0), click(Button::Left, 108.0, 195.0));
    }

    #[test]
    fn long_press_is_right_click_once() {
        let mut t = touch();
        t.down(1, 50.0, 60.0);
        let serial = t.long_press_serial().unwrap();
        assert_eq!(t.long_press(serial), click(Button::Right, 50.0, 60.0));
        assert!(t.moved(1, 200.0, 200.0).is_empty());
        assert!(t.up(1, 200.0, 200.0, 0.0).is_empty(), "pas de clic gauche en plus");
        // Minuterie d'un geste déjà fini : ignorée.
        t.down(2, 10.0, 10.0);
        t.up(2, 10.0, 10.0, 5000.0);
        assert!(t.long_press(serial).is_empty());
        assert!(t.long_press(serial + 1).is_empty());
    }

    #[test]
    fn drag_holds_left_button() {
        let mut t = touch();
        t.down(1, 10.0, 10.0);
        assert_eq!(
            t.moved(1, 40.0, 10.0),
            vec![
                Action::Move { x: 10.0, y: 10.0 },
                Action::Button { button: Button::Left, down: true, x: 10.0, y: 10.0 },
                Action::Move { x: 40.0, y: 10.0 },
            ]
        );
        assert!(t.long_press_serial().is_none(), "plus d'appui long une fois parti");
        assert_eq!(t.moved(1, 50.0, 12.0), vec![Action::Move { x: 50.0, y: 12.0 }]);
        // Un second doigt pendant le glisser ne change rien.
        assert!(t.down(2, 300.0, 300.0).is_empty());
        assert!(t.moved(2, 310.0, 300.0).is_empty());
        assert_eq!(
            t.up(1, 55.0, 12.0, 0.0),
            vec![
                Action::Move { x: 55.0, y: 12.0 },
                Action::Button { button: Button::Left, down: false, x: 55.0, y: 12.0 },
            ]
        );
        assert!(t.up(2, 310.0, 300.0, 0.0).is_empty());
    }

    #[test]
    fn cancel_releases_dragged_button() {
        let mut t = touch();
        t.down(1, 10.0, 10.0);
        t.moved(1, 40.0, 10.0);
        assert_eq!(t.cancel(1), vec![Action::Button { button: Button::Left, down: false, x: 40.0, y: 10.0 }]);
        t.down(2, 10.0, 10.0);
        assert!(t.cancel(2).is_empty(), "un toucher annulé ne clique pas");
    }

    #[test]
    fn cancelled_extra_finger_keeps_drag() {
        let mut t = touch();
        t.down(1, 10.0, 10.0);
        t.moved(1, 40.0, 10.0);
        t.down(2, 300.0, 300.0);
        assert!(t.cancel(2).is_empty());
        assert_eq!(
            t.up(1, 45.0, 10.0, 0.0),
            vec![
                Action::Move { x: 45.0, y: 10.0 },
                Action::Button { button: Button::Left, down: false, x: 45.0, y: 10.0 },
            ],
            "le bouton est relâché par le doigt qui glisse"
        );
    }

    #[test]
    fn two_finger_slide_scrolls() {
        let mut t = touch();
        t.down(1, 100.0, 300.0);
        t.down(2, 200.0, 300.0);
        // Les deux doigts descendent de 30 px : défilement vers le haut (positif), au milieu, dès
        // que le second doigt confirme le mouvement du premier.
        assert!(t.moved(1, 100.0, 330.0).is_empty(), "un seul doigt : rien de décidé");
        let out = t.moved(2, 200.0, 330.0);
        assert_eq!(out, vec![Action::Wheel { delta: 60, horizontal: false, x: 150.0, y: 330.0 }]);
        // Vers la gauche : défilement vers la droite (positif).
        t.moved(1, 80.0, 330.0);
        let out = t.moved(2, 180.0, 330.0);
        assert_eq!(out, vec![Action::Wheel { delta: 20, horizontal: true, x: 130.0, y: 330.0 }]);
        assert!(t.up(1, 0.0, 0.0, 0.0).is_empty(), "pas de clic à la fin");
        assert!(t.up(2, 0.0, 0.0, 0.0).is_empty());
        assert_eq!(t.zoom, Zoom::default());
    }

    #[test]
    fn pinch_started_by_one_finger_is_not_a_scroll() {
        // Le doigt gauche part seul de 22 px (milieu déplacé de 11, écart +22), puis le droit :
        // écart +44, milieu revenu. Dans les deux ordres, c'est un zoom, jamais une molette.
        for (first, second) in [((1, 78.0), (2, 222.0)), ((2, 222.0), (1, 78.0))] {
            let mut t = touch();
            t.down(1, 100.0, 300.0);
            t.down(2, 200.0, 300.0);
            assert!(t.moved(first.0, first.1, 300.0).is_empty(), "un seul doigt : rien de décidé");
            let out = t.moved(second.0, second.1, 300.0);
            assert!(matches!(out[..], [Action::Zoom(z)] if (z.scale - 1.44).abs() < 1e-9), "{out:?}");
        }
    }

    #[test]
    fn aligned_fingers_scroll_in_either_order() {
        // Doigts l'un au-dessus de l'autre, qui descendent de 30 px : le premier mouvement seul
        // réduit ou allonge l'écart de 30 px, sans faire un pincement.
        for (first, second) in [((1, 330.0), (2, 430.0)), ((2, 430.0), (1, 330.0))] {
            let mut t = touch();
            t.down(1, 100.0, 300.0);
            t.down(2, 100.0, 400.0);
            assert!(t.moved(first.0, 100.0, first.1).is_empty(), "un seul doigt : rien de décidé");
            let out = t.moved(second.0, 100.0, second.1);
            assert_eq!(out, vec![Action::Wheel { delta: 60, horizontal: false, x: 100.0, y: 380.0 }]);
            assert_eq!(t.zoom, Zoom::default());
        }
    }

    #[test]
    fn pinch_with_one_finger_held_still() {
        let mut t = touch();
        t.down(1, 100.0, 300.0);
        t.down(2, 200.0, 300.0);
        // Le doigt gauche reste posé ; le droit s'écarte : zoom dès qu'il a bougé seul trois fois.
        assert!(t.moved(2, 230.0, 300.0).is_empty());
        assert!(t.moved(2, 260.0, 300.0).is_empty());
        let out = t.moved(2, 290.0, 300.0);
        assert!(matches!(out[..], [Action::Zoom(z)] if (z.scale - 1.9).abs() < 1e-9), "{out:?}");
    }

    #[test]
    fn pinch_zooms_around_midpoint_then_pans_and_clamps() {
        let mut t = touch();
        t.down(1, 150.0, 400.0);
        t.down(2, 250.0, 400.0);
        // Écart 100 → 200 : zoom ×2 centré sur (200, 400).
        t.moved(1, 100.0, 400.0);
        let out = t.moved(2, 300.0, 400.0);
        assert_eq!(out, vec![Action::Zoom(Zoom { scale: 2.0, tx: -200.0, ty: -400.0 })]);
        t.up(1, 0.0, 0.0, 0.0);
        t.up(2, 0.0, 0.0, 0.0);
        // Zoomé : deux doigts qui glissent déplacent la vue (pas de molette), bornée au bord.
        t.down(3, 100.0, 400.0);
        t.down(4, 300.0, 400.0);
        let mut out = Vec::new();
        for k in 1..=30 {
            let dx = 10.0 * k as f64;
            t.moved(3, 100.0 + dx, 400.0);
            out = t.moved(4, 300.0 + dx, 400.0);
        }
        assert_eq!(out, vec![Action::Zoom(Zoom { scale: 2.0, tx: 0.0, ty: -400.0 })]);
        t.up(3, 0.0, 0.0, 0.0);
        t.up(4, 0.0, 0.0, 0.0);
        // Pincer pour revenir : jamais en dessous de 1:1, vue recalée.
        t.down(5, 100.0, 400.0);
        t.down(6, 300.0, 400.0);
        t.moved(5, 190.0, 400.0);
        let out = t.moved(6, 210.0, 400.0);
        assert_eq!(out, vec![Action::Zoom(Zoom::default())]);
    }
}
