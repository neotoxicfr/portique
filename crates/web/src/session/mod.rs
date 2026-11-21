//! Page de session : canevas plein écran, entrées (souris, clavier, gestes tactiles, clavier
//! virtuel), menu, reconnexion automatique.

mod clip;
mod dock;
mod engine;
mod h264;
mod keys;
mod touch;
mod views;

use std::rc::Rc;

use engine::{Engine, Extend, Open, Retry, Status};
use leptos::{
    ev,
    html::{Button, Canvas, Div, Textarea},
    prelude::*,
    task::spawn_local,
};
use leptos_router::hooks::{use_navigate, use_params_map};
use views::ScreenGeom;
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use web_sys::{KeyboardEvent, PointerEvent, WheelEvent};

/// Délais de reconnexion automatique (s) : le PC peut redémarrer, le réseau mobile changer.
const RETRY_DELAYS: [u32; 8] = [1, 2, 3, 5, 8, 13, 21, 30];

/// Icône du bouton de clavier virtuel.
const KEYBOARD: &str = r#"<rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M8 14h8"/>"#;

/// Hauteur de la barre de touches (CSS `.session-keys`) : deux rangées de 44 px et leurs marges.
const KEYS_HEIGHT: f64 = 106.0;

/// Rangée 2 de la barre de touches (défilante) : (libellé, nom accessible, `KeyboardEvent.code`).
const KEYS_MORE: [(&str, &str, &str); 17] = [
    ("Suppr", "Supprimer", "Delete"),
    ("Début", "Début", "Home"),
    ("Fin", "Fin", "End"),
    ("Pg ↑", "Page précédente", "PageUp"),
    ("Pg ↓", "Page suivante", "PageDown"),
    ("F1", "F1", "F1"),
    ("F2", "F2", "F2"),
    ("F3", "F3", "F3"),
    ("F4", "F4", "F4"),
    ("F5", "F5", "F5"),
    ("F6", "F6", "F6"),
    ("F7", "F7", "F7"),
    ("F8", "F8", "F8"),
    ("F9", "F9", "F9"),
    ("F10", "F10", "F10"),
    ("F11", "F11", "F11"),
    ("F12", "F12", "F12"),
];

/// Texte collé dans le champ du clavier virtuel quand le navigateur le met dans `dataTransfer`
/// plutôt que dans `data` (lu par réflexion : pas de feature web-sys `DataTransfer`).
fn transfer_text(e: &web_sys::InputEvent) -> Option<String> {
    let dt = js_sys::Reflect::get(e, &"dataTransfer".into()).ok().filter(|v| v.is_object())?;
    let get: js_sys::Function = js_sys::Reflect::get(&dt, &"getData".into()).ok()?.dyn_into().ok()?;
    get.call1(&dt, &"text/plain".into()).ok()?.as_string()
}

/// Délai avant le prochain essai de reconnexion (`attempt` essais déjà faits), `None` pour
/// s'arrêter.
fn retry_delay(retry: Retry, attempt: usize) -> Option<u32> {
    match retry {
        Retry::Yes => RETRY_DELAYS.get(attempt).copied(),
        // Série en cours (PC qui redémarre) : un essai qui échoue avant d'aboutir ne l'arrête pas.
        Retry::Transient if attempt > 0 => RETRY_DELAYS.get(attempt).copied(),
        _ => None,
    }
}

/// Ctrl+Alt+Maj enfoncées ensemble puis relâchées sans autre touche : sortie clavier du bureau
/// vers le menu. Avec une autre touche (Ctrl+Alt+Maj+S…), tout part au PC sans rien déclencher.
fn escape_chord(armed: &mut bool, key: &str, ctrl: bool, alt: bool, shift: bool, down: bool) -> bool {
    if !matches!(key, "Control" | "Alt" | "AltGraph" | "Shift") {
        *armed = false;
        return false;
    }
    if down {
        *armed |= ctrl && alt && shift;
        return false;
    }
    std::mem::take(armed)
}

fn viewport() -> (u32, u32) {
    let w = window();
    let px = |v: Result<JsValue, JsValue>| v.ok().and_then(|v| v.as_f64()).unwrap_or(1024.0) as u32;
    (px(w.inner_width()), px(w.inner_height()))
}

/// Vue visible `(x, y, largeur, hauteur)` : celle du clavier ouvert sur iOS (`visualViewport`).
fn visible_area() -> (f64, f64, f64, f64) {
    let w = window();
    if let Some(v) = w.visual_viewport() {
        return (v.offset_left(), v.offset_top(), v.width(), v.height());
    }
    let (iw, ih) = viewport();
    (0.0, 0.0, iw as f64, ih as f64)
}

/// Zones sûres `(haut, droite, bas, gauche)` : le `padding` de `.session` les reprend (env()).
fn safe_insets(el: Option<web_sys::HtmlElement>) -> (f64, f64, f64, f64) {
    let Some(style) = el.and_then(|e| window().get_computed_style(&e).ok().flatten()) else {
        return (0.0, 0.0, 0.0, 0.0);
    };
    let px = |p: &str| {
        style
            .get_property_value(p)
            .ok()
            .and_then(|v| v.trim_end_matches("px").parse::<f64>().ok())
            .unwrap_or(0.0)
    };
    (px("padding-top"), px("padding-right"), px("padding-bottom"), px("padding-left"))
}

/// Glissé du groupe clavier / déconnexion en cours.
#[derive(Clone, Copy)]
struct Drag {
    id: i32,
    start: (f64, f64),
    origin: (f64, f64),
    moving: bool,
}

fn sleep(seconds: u32) -> impl std::future::Future<Output = ()> {
    let p = js_sys::Promise::new(&mut |resolve, _| {
        let _ =
            window().set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, (seconds * 1000) as i32);
    });
    async move {
        let _ = wasm_bindgen_futures::JsFuture::from(p).await;
    }
}

#[component]
pub fn SessionPage() -> impl IntoView {
    let params = use_params_map();
    let id = move || params.with(|p| p.get("id").and_then(|s| s.parse::<i64>().ok()));
    let canvas_ref = NodeRef::<Canvas>::new();
    let kbd_ref = NodeRef::<Textarea>::new();
    let handle_ref = NodeRef::<Button>::new();
    let session_ref = NodeRef::<Div>::new();
    // Clavier système affiché (champ caché focalisé), vue visible, position retenue du groupe
    // clavier / déconnexion, modificateurs collants de la barre de touches.
    // Le champ a le focus ET la vue visible a rétréci : sur iPad, la touche native de fermeture du
    // clavier laisse le focus, seule la vue visible le dit.
    let kbd_focus = RwSignal::new(false);
    let kbd_shown = RwSignal::new(false);
    let kbd_open = Memo::new(move |_| kbd_focus.get() && kbd_shown.get());
    let kbd_watch = StoredValue::new(dock::KeyboardWatch::default());
    let visible = RwSignal::new(visible_area());
    let refresh_visible = move || {
        let v = visible_area();
        visible.set(v);
        let inner = window().inner_height().ok().and_then(|h| h.as_f64()).unwrap_or(v.3);
        if let Some(shown) = kbd_watch.try_update_value(|w| w.update(v.2, inner, v.3)) {
            kbd_shown.set(shown);
        }
    };
    let dock_pos = RwSignal::new(dock::load());
    let mods = RwSignal::new(keys::Mods::default());
    let drag = StoredValue::new(None::<Drag>);
    let swallow_click = StoredValue::new(false);
    let status = RwSignal::new(Status::Connecting("Préparation…".into()));
    let attempt = RwSignal::new(0usize);
    let menu_open = RwSignal::new(false);
    // Valeur locale (non Send) gardée par Leptos : la poignée de session.
    let engine = StoredValue::new_local(None::<Engine>);
    // Jeton d'ouverture : une ouverture, ses rappels et ses délais de reconnexion n'agissent que
    // tant qu'aucune autre ne l'a remplacée et que la page est là (valeur détruite = page quittée).
    let open_gen = StoredValue::new(0u64);
    // Multi-écran : 1) détecter les écrans (demande la permission), 2) ouvrir les fenêtres, une
    // par clic (un navigateur bloque une fenêtre ouverte hors d'un geste utilisateur).
    // Écrans détectés et `ScreenDetails` (tenu à jour par le navigateur), relu à chaque clic.
    let screens = StoredValue::new_local(None::<(Vec<ScreenGeom>, JsValue)>);
    let multi_label = RwSignal::new(None::<String>);
    let multi_active = RwSignal::new(false);
    let extend_label =
        move || screens.with_value(|s| s.as_ref().map(|(l, _)| format!("Étendre sur {} écrans", l.len())));

    // Ouverture (et réouverture) de la session.
    let open = move |trust: Option<String>| {
        let Some(cid) = id() else { return };
        let Some(canvas) = canvas_ref.get_untracked() else { return };
        let generation = open_gen.get_value() + 1;
        open_gen.set_value(generation);
        let current = move || open_gen.try_get_value() == Some(generation);
        spawn_local(async move {
            // Relu à chaque ouverture : le navigateur a pu être noté inapte pendant la session.
            let t0 = js_sys::Date::now();
            let avc = h264::support().await;
            let support_ms = js_sys::Date::now() - t0;
            if !current() {
                return;
            }
            if let Some(old) = engine.try_update_value(Option::take).flatten() {
                old.close();
            }
            // Le nouveau moteur repart d'un seul écran.
            multi_active.set(false);
            multi_label.set(extend_label());
            let (w, h) = viewport();
            let on_status: Rc<dyn Fn(Status)> = Rc::new(move |s| {
                if current() {
                    status.set(s)
                }
            });
            let on_single: Rc<dyn Fn(&str)> = Rc::new(move |why: &str| {
                if current() {
                    multi_active.set(false);
                    multi_label.set(Some(why.into()));
                }
            });
            match Engine::open(
                canvas,
                Open { connection_id: cid, width: w, height: h, trust, avc, support_ms },
                on_status,
                on_single,
            ) {
                Ok(e) => engine.set_value(Some(e)),
                Err(e) => status.set(Status::Closed { reason: e, retry: Retry::No }),
            }
        });
    };
    let with_engine = move |f: &dyn Fn(&Engine)| {
        engine.with_value(|e| {
            if let Some(e) = e.as_ref() {
                f(e);
            }
        })
    };

    Effect::new(move |_| {
        if canvas_ref.get().is_some() {
            open(None);
        }
    });
    // Attribut propre à Safari, inconnu de `view!` : pas de correction automatique au clavier virtuel.
    Effect::new(move |_| {
        if let Some(t) = kbd_ref.get() {
            let _ = t.set_attribute("autocorrect", "off");
        }
    });

    // Reconnexion automatique après une coupure en cours de session.
    Effect::new(move |_| match status.get() {
        Status::Closed { retry, .. } => {
            if let Some(delay) = retry_delay(retry, attempt.get_untracked()) {
                status.set(Status::Connecting(format!("Connexion perdue, nouvel essai dans {delay} s…")));
                let generation = open_gen.get_value();
                spawn_local(async move {
                    sleep(delay).await;
                    // Page quittée ou autre ouverture entre-temps : ce délai ne vaut plus.
                    if open_gen.try_get_value() != Some(generation) {
                        return;
                    }
                    attempt.update(|a| *a += 1);
                    open(None);
                });
            }
        }
        Status::Connected => attempt.set(0),
        _ => {}
    });

    // Clavier : positions physiques → scancodes ; à défaut, caractère Unicode. Seulement quand le
    // bureau a le focus (canevas, rien, ou le champ du clavier virtuel) : sur une commande locale
    // (menu, alerte), Tab, Entrée et Espace restent au navigateur.
    let chord = StoredValue::new(false);
    let key_handler = move |e: KeyboardEvent, down: bool| {
        let active = document().active_element();
        let is = |el: Option<web_sys::Element>| matches!((&active, el), (Some(a), Some(b)) if *a == b);
        let virtual_kbd = is(kbd_ref.get_untracked().map(Into::into));
        let on_desktop = virtual_kbd
            || is(canvas_ref.get_untracked().map(Into::into))
            || active.as_ref().is_none_or(|a| matches!(a.tag_name().as_str(), "BODY" | "HTML"));
        if !on_desktop {
            if down && e.key() == "Escape" {
                // Retour au bureau depuis le menu.
                menu_open.set(false);
                if let Some(c) = canvas_ref.get_untracked() {
                    let _ = c.focus();
                }
            } else if !down {
                with_engine(&|eng| eng.release_key(&e));
            }
            return;
        }
        let exit = chord
            .try_update_value(|c| escape_chord(c, &e.key(), e.ctrl_key(), e.alt_key(), e.shift_key(), down))
            .unwrap_or(false);
        if exit {
            e.prevent_default();
            with_engine(&|eng| eng.release_all());
            menu_open.set(true);
            if let Some(b) = handle_ref.get_untracked() {
                let _ = b.focus();
            }
            return;
        }
        // Composition en cours dans le champ (IME, accents) : ses touches, Entrée de validation
        // comprise, restent locales ; seul le texte final part (`compositionend`). Safari envoie
        // l'Entrée de validation après `compositionend`, `isComposing` faux mais keyCode 229 ; une
        // vraie Entrée ainsi écartée arrive encore par `beforeinput` (insertLineBreak).
        if virtual_kbd
            && (e.is_composing() || (e.key_code() == 229 && (e.key() == "Enter" || e.code() == "Enter")))
        {
            if !down {
                with_engine(&|eng| eng.release_key(&e));
            }
            return;
        }
        with_engine(&|eng| eng.key_input(&e, down, virtual_kbd));
    };
    let kd = window_event_listener(ev::keydown, move |e| key_handler(e, true));
    let ku = window_event_listener(ev::keyup, move |e| key_handler(e, false));
    // Focus perdu : touches relâchées côté PC, et Ctrl+Alt+Maj désarmé (relâchées ailleurs, elles
    // ne doivent pas ouvrir le menu au prochain relâchement de Maj).
    let blur = window_event_listener(ev::blur, move |_| {
        chord.set_value(false);
        with_engine(&|e| e.release_all());
    });
    // Retour sur la page : le presse-papier local a pu changer.
    let focus = window_event_listener(ev::focus, move |_| {
        with_engine(&|e| {
            let e = e.clone();
            spawn_local(async move {
                e.sync_local_clipboard().await;
            });
        })
    });

    // Taille : la session suit la fenêtre (contrôle d'affichage), après 400 ms de calme. Le délai
    // et son rappel sont gardés ensemble : annulés et libérés au suivant comme à la sortie.
    let resize_timer = StoredValue::new_local(None::<(i32, Closure<dyn FnMut()>)>);
    let cancel_resize = move || {
        if let Some((t, _cb)) = resize_timer.try_update_value(Option::take).flatten() {
            window().clear_timeout_with_handle(t);
        }
    };
    let resize = window_event_listener(ev::resize, move |_| {
        cancel_resize();
        let cb = Closure::<dyn FnMut()>::new(move || {
            let (w, h) = viewport();
            with_engine(&|e| e.resize(w, h));
        });
        if let Ok(t) =
            window().set_timeout_with_callback_and_timeout_and_arguments_0(cb.as_ref().unchecked_ref(), 400)
        {
            resize_timer.set_value(Some((t, cb)));
        }
    });

    let vp_window = window_event_listener(ev::resize, move |_| refresh_visible());
    // Clavier iOS : la vue visible change de hauteur et de décalage sans que la fenêtre bouge.
    let vp_cb = Closure::<dyn FnMut()>::new(refresh_visible);
    if let Some(v) = window().visual_viewport() {
        let f = vp_cb.as_ref().unchecked_ref();
        let _ = v.add_event_listener_with_callback("resize", f);
        let _ = v.add_event_listener_with_callback("scroll", f);
    }
    let vp_cb = StoredValue::new_local(Some(vp_cb));

    let listeners = StoredValue::new_local(Some((kd, ku, blur, resize, focus, vp_window)));
    on_cleanup(move || {
        open_gen.try_update_value(|g| *g += 1);
        cancel_resize();
        if let Some(cb) = vp_cb.try_update_value(Option::take).flatten()
            && let Some(v) = window().visual_viewport()
        {
            let f = cb.as_ref().unchecked_ref();
            let _ = v.remove_event_listener_with_callback("resize", f);
            let _ = v.remove_event_listener_with_callback("scroll", f);
        }
        if let Some((kd, ku, blur, resize, focus, vp_window)) =
            listeners.try_update_value(Option::take).flatten()
        {
            vp_window.remove();
            kd.remove();
            ku.remove();
            blur.remove();
            resize.remove();
            focus.remove();
        }
        if let Some(e) = engine.try_update_value(Option::take).flatten() {
            e.close();
        }
    });

    // Souris, stylet et doigts (événements pointeur sur le canevas).
    let pointer =
        move |e: PointerEvent, kind: &'static str| with_engine(&|eng| eng.pointer_input(0, &e, kind));
    let wheel = move |e: WheelEvent| with_engine(&|eng| eng.wheel_input(0, &e));

    // Clavier virtuel (téléphone, tablette) : un champ caché reçoit le focus dans le geste, ses
    // saisies partent au PC et il reste vide.
    let toggle_keyboard = move |_| {
        if swallow_click.get_value() {
            return;
        }
        let Some(t) = kbd_ref.get_untracked() else { return };
        let el: &web_sys::Element = t.as_ref();
        let focused = document().active_element().is_some_and(|a| &a == el);
        if focused && kbd_shown.get_untracked() {
            let _ = t.blur();
        } else {
            // Focus gardé sans clavier (fermé par sa touche native) : il faut le perdre pour que
            // le focus suivant rouvre le clavier.
            if focused {
                let _ = t.blur();
            }
            let opts = web_sys::FocusOptions::new();
            opts.set_prevent_scroll(true);
            let _ = t.focus_with_options(&opts);
        }
    };
    let focus_keyboard = move || {
        if let Some(t) = kbd_ref.get_untracked() {
            let opts = web_sys::FocusOptions::new();
            opts.set_prevent_scroll(true);
            let _ = t.focus_with_options(&opts);
        }
    };
    let clear_keyboard = move || {
        if let Some(t) = kbd_ref.get_untracked() {
            t.set_value("");
        }
    };
    let composing = StoredValue::new(false);

    // Menu de session.
    // API Fullscreen absente (iPhone) : pas de bouton.
    let can_fullscreen = js_sys::Reflect::get(&document(), &"fullscreenEnabled".into())
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let fullscreen = move |_| {
        let doc = document();
        if doc.fullscreen_element().is_some() {
            doc.exit_fullscreen();
        } else if let Some(el) = doc.document_element() {
            let _ = el.request_fullscreen();
            // Keyboard Lock (Chrome/Edge) : Alt+Tab, Win, Échap partent vers le PC.
            let nav = window().navigator();
            if let Ok(kb) = js_sys::Reflect::get(&nav, &"keyboard".into())
                && let Ok(lock) = js_sys::Reflect::get(&kb, &"lock".into())
                && let Some(f) = lock.dyn_ref::<js_sys::Function>()
            {
                let _ = f.call0(&kb);
            }
        }
        menu_open.set(false);
    };
    let detect = move |_| {
        spawn_local(async move {
            let found = views::screen_details().await.and_then(|d| Ok((views::screens(&d)?.0, d)));
            // Page quittée pendant la demande de permission : ses valeurs sont détruites.
            if screens.is_disposed() {
                return;
            }
            match found {
                Ok((list, details)) if list.len() > 1 => {
                    screens.set_value(Some((list, details)));
                    multi_label.set(extend_label());
                }
                Ok(_) => multi_label.set(Some("Un seul écran détecté".into())),
                Err(e) => multi_label.set(Some(format!("Multi-écran indisponible : {e}"))),
            }
        });
    };
    let extend = move |_| {
        let Some((_, details)) = screens.get_value() else { return };
        let (list, cur) = match views::screens(&details) {
            Ok(s) => s,
            Err(err) => return multi_label.set(Some(err)),
        };
        with_engine(&|e| match e.enable_multi(&list, cur) {
            Ok(Extend::Done(n)) => {
                multi_active.set(true);
                multi_label.set(Some(format!("{n} écrans")));
                menu_open.set(false);
            }
            // Fenêtre suivante : un nouveau clic, le menu reste ouvert.
            Ok(Extend::Next { opened, total }) => {
                multi_label.set(Some(format!("Ouvrir l'écran {} sur {total}", opened + 1)));
            }
            Err(err) => multi_label.set(Some(err)),
        });
    };
    let single = move |_| {
        let (w, h) = viewport();
        with_engine(&|e| e.disable_multi(w, h));
        multi_active.set(false);
        multi_label.set(None);
        screens.set_value(None);
        menu_open.set(false);
    };
    let cad = move |_| {
        with_engine(&|e| e.ctrl_alt_del());
        menu_open.set(false);
    };
    let navigate = use_navigate();
    let quit = move |_| {
        if let Some(e) = engine.try_update_value(Option::take).flatten() {
            e.close();
        }
        navigate("/", Default::default());
    };
    // « Netteté maximale » : sans H.264 (RemoteFX/ClearCodec, sans sous-échantillonnage de chroma) ;
    // le choix est retenu par navigateur et la session se rouvre pour qu'il prenne effet.
    let sharp = move |_| {
        h264::set_sharp(!h264::is_off());
        menu_open.set(false);
        attempt.set(0);
        open(None);
    };
    let retry = move |_| {
        attempt.set(0);
        open(None);
    };
    let approve = move |fp: String| {
        attempt.set(0);
        open(Some(fp));
    };
    // Alerte affichée : le bureau, le clavier et le menu passent en `inert` (ni clic, ni Tab, ni
    // touches vers le PC) et le focus va sur la première action de l'alerte.
    let blocked = move || !matches!(status.get(), Status::Connected);
    Effect::new(move |_| {
        if blocked() {
            request_animation_frame(|| {
                if let Some(el) = document()
                    .query_selector(".session-overlay :is(button, a)")
                    .ok()
                    .flatten()
                    .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
                {
                    let _ = el.focus();
                }
            });
        }
    });

    // Zone du groupe clavier / déconnexion : vue visible, zones sûres, barre de touches si affichée.
    let area = move || {
        let reserved = if kbd_open.get() { KEYS_HEIGHT } else { 0.0 };
        let insets = safe_insets(session_ref.get_untracked().map(Into::into));
        dock::Area::new(visible.get(), insets, reserved)
    };
    let dock_style = move || {
        let (x, y) = dock::place(dock_pos.get(), area());
        format!("left:{x}px;top:{y}px")
    };
    let dock_down = move |e: PointerEvent| {
        // Sans défaut : le focus reste sur le champ du clavier (qui ne se ferme pas).
        e.prevent_default();
        if !e.is_primary() || (e.pointer_type() == "mouse" && e.button() != 0) {
            return;
        }
        swallow_click.set_value(false);
        let origin = dock::place(dock_pos.get_untracked(), area());
        let start = (e.client_x(), e.client_y());
        drag.set_value(Some(Drag { id: e.pointer_id(), start, origin, moving: false }));
    };
    // Suivi sur `window` : le glissé continue et se termine même si le pointeur sort du groupe.
    let dock_move = move |e: PointerEvent| {
        let Some(mut d) = drag.get_value().filter(|d| d.id == e.pointer_id()) else { return };
        let (dx, dy) = (e.client_x() - d.start.0, e.client_y() - d.start.1);
        if !d.moving && dx.hypot(dy) >= dock::DRAG_START {
            d.moving = true;
            drag.set_value(Some(d));
        }
        if d.moving {
            dock_pos.set(Some(dock::clamp((d.origin.0 + dx, d.origin.1 + dy), area())));
        }
    };
    let dock_up = move |e: PointerEvent| {
        let Some(d) = drag.get_value().filter(|d| d.id == e.pointer_id()) else { return };
        drag.set_value(None);
        if d.moving {
            // Le clic qui suit un glissé ne déclenche ni clavier ni déconnexion.
            swallow_click.set_value(true);
            if let Some(p) = dock_pos.get_untracked() {
                dock::save(p);
            }
        }
    };
    let dock_listeners = StoredValue::new_local(Some((
        window_event_listener(ev::pointermove, dock_move),
        window_event_listener(ev::pointerup, dock_up),
        window_event_listener(ev::pointercancel, dock_up),
    )));
    on_cleanup(move || {
        if let Some((m, u, c)) = dock_listeners.try_update_value(Option::take).flatten() {
            m.remove();
            u.remove();
            c.remove();
        }
    });
    let quit_dock = {
        let quit = quit.clone();
        move |e: web_sys::MouseEvent| {
            if !swallow_click.get_value() {
                quit(e);
            }
        }
    };

    // Barre de touches : envoi en scancodes ; les modificateurs collants valent pour la prochaine
    // touche de la barre (jamais pour les lettres du clavier système, envoyées en Unicode).
    let bar_style = move || {
        let (_, oy, _, vh) = visible.get();
        let below = (window().inner_height().ok().and_then(|v| v.as_f64()).unwrap_or(0.0) - oy - vh).max(0.0);
        format!("bottom:max({below}px, env(safe-area-inset-bottom))")
    };
    let bar_key = move |label: &'static str, name: &'static str, code: &'static str| {
        view! {
            <button class="sk-key" type="button" aria-label=name title=name
                on:pointerdown=|e| e.prevent_default()
                on:mousedown=|e| e.prevent_default()
                on:click=move |_| {
                    let m = mods.get_untracked();
                    mods.set(keys::Mods::default());
                    with_engine(&|eng| eng.bar_chord(m, Some(code)));
                    focus_keyboard();
                }>{label}</button>
        }
    };
    let sticky = move |label: &'static str,
                       name: &'static str,
                       get: fn(&keys::Mods) -> bool,
                       flip: fn(&mut keys::Mods)| {
        view! {
            <button class="sk-key" class:on=move || get(&mods.get()) type="button" aria-label=name title=name
                aria-pressed=move || get(&mods.get()).to_string()
                on:pointerdown=|e| e.prevent_default()
                on:mousedown=|e| e.prevent_default()
                on:click=move |_| {
                    mods.update(flip);
                    focus_keyboard();
                }>{label}</button>
        }
    };

    view! {
        <div class="session" node_ref=session_ref>
            <canvas
                node_ref=canvas_ref
                class="screen"
                tabindex="0"
                inert=blocked
                on:pointermove=move |e| pointer(e, "pointermove")
                on:pointerdown=move |e| pointer(e, "pointerdown")
                on:pointerup=move |e| pointer(e, "pointerup")
                on:pointercancel=move |e| pointer(e, "pointercancel")
                on:wheel=wheel
                on:contextmenu=|e| e.prevent_default()
            ></canvas>
            <textarea
                node_ref=kbd_ref
                class=engine::KEYBOARD_CLASS
                aria-label="Clavier du PC"
                autocapitalize="off"
                autocomplete="off"
                spellcheck="false"
                inputmode="text"
                enterkeyhint="enter"
                rows="1"
                tabindex="-1"
                on:beforeinput=move |e: web_sys::InputEvent| {
                    // Composition (accents, IME) : seul le résultat final compte.
                    if !e.is_composing() {
                        e.prevent_default();
                        let data = e.data().or_else(|| transfer_text(&e));
                        with_engine(&|eng| eng.text_input(&e.input_type(), data.clone()));
                    }
                }
                on:focus=move |_| kbd_focus.set(true)
                on:blur=move |_| kbd_focus.set(false)
                on:compositionstart=move |_| composing.set_value(true)
                on:compositionend=move |e: web_sys::CompositionEvent| {
                    composing.set_value(false);
                    with_engine(&|eng| eng.text_input("insertText", e.data()));
                    clear_keyboard();
                }
                on:input=move |_| {
                    // Saisie non annulable (dictée…) : déjà transmise, le champ reste vide.
                    if !composing.get_value() {
                        clear_keyboard();
                    }
                }
            ></textarea>
            <div
                class="session-dock"
                style=dock_style
                inert=blocked
                on:pointerdown=dock_down
            >
                <button
                    type="button"
                    aria-label="Clavier"
                    title="Clavier"
                    on:mousedown=|e| e.prevent_default()
                    on:click=toggle_keyboard
                >
                    {crate::icon(KEYBOARD)}
                </button>
                <button
                    type="button"
                    class="danger"
                    aria-label="Déconnexion"
                    title="Déconnexion"
                    on:mousedown=|e| e.prevent_default()
                    on:click=quit_dock
                >
                    {crate::icon(crate::glyph::LOGOUT)}
                </button>
            </div>
            <Show when=move || kbd_open.get()>
                <div class="session-keys" style=bar_style inert=blocked>
                    <div class="sk-row">
                        {bar_key("Esc", "Échap", "Escape")}
                        {bar_key("Tab", "Tabulation", "Tab")}
                        {sticky("Ctrl", "Ctrl", |m| m.ctrl, |m| m.ctrl = !m.ctrl)}
                        {sticky("Alt", "Alt", |m| m.alt, |m| m.alt = !m.alt)}
                        <button class="sk-key" class:on=move || mods.get().win type="button"
                            aria-label="Windows : une 2e pression ouvre le menu Démarrer" title="Windows"
                            aria-pressed=move || mods.get().win.to_string()
                            on:pointerdown=|e| e.prevent_default()
                            on:mousedown=|e| e.prevent_default()
                            on:click=move |_| {
                                let m = mods.get_untracked();
                                if m.win {
                                    // Win déjà armée : seule, elle ouvre le menu Démarrer.
                                    mods.set(keys::Mods::default());
                                    with_engine(&|eng| eng.bar_chord(keys::Mods { win: true, ..Default::default() }, None));
                                } else {
                                    mods.update(|m| m.win = true);
                                }
                                focus_keyboard();
                            }>"Win"</button>
                        {bar_key("←", "Flèche gauche", "ArrowLeft")}
                        {bar_key("↑", "Flèche haut", "ArrowUp")}
                        {bar_key("↓", "Flèche bas", "ArrowDown")}
                        {bar_key("→", "Flèche droite", "ArrowRight")}
                    </div>
                    <div class="sk-row scroll">
                        {KEYS_MORE.iter().map(|(l, n, c)| bar_key(l, n, c)).collect_view()}
                        {bar_key("Impr", "Impression d'écran", "PrintScreen")}
                        <button class="sk-key special" type="button" aria-label="Ctrl+Alt+Suppr" title="Ctrl+Alt+Suppr"
                            on:pointerdown=|e| e.prevent_default()
                            on:mousedown=|e| e.prevent_default()
                            on:click=move |_| {
                                mods.set(keys::Mods::default());
                                with_engine(&|eng| eng.ctrl_alt_del());
                                focus_keyboard();
                            }>"Ctrl+Alt+Suppr"</button>
                    </div>
                </div>
            </Show>
            <div class="session-menu" class:open=move || menu_open.get() inert=blocked>
                <button
                    node_ref=handle_ref
                    class="session-handle"
                    title="Menu de session (Ctrl+Alt+Maj depuis le bureau)"
                    on:click=move |_| {
                        let open = !menu_open.get_untracked();
                        menu_open.set(open);
                        // Refermé par la poignée, qui reste là avec le focus : le clavier revient au
                        // bureau (sinon la frappe suivante resterait sur une commande locale).
                        if !open && let Some(c) = canvas_ref.get_untracked() {
                            let _ = c.focus();
                        }
                    }
                >
                    "⋯"
                </button>
                <Show when=move || menu_open.get()>
                    <div class="session-actions">
                        <p class="session-info">
                            {move || engine.with_value(|e| e.as_ref().map(Engine::image_path)).unwrap_or_default()}
                        </p>
                        {can_fullscreen.then(|| view! { <button on:click=fullscreen>"Plein écran"</button> })}
                        {move || {
                            multi_label.track();
                            if multi_active.get() {
                                view! { <button on:click=single>"Un seul écran"</button> }.into_any()
                            } else if screens.with_value(Option::is_some) {
                                view! { <button on:click=extend>{multi_label.get().unwrap_or_default()}</button> }.into_any()
                            } else {
                                view! {
                                    <button on:click=detect title=move || multi_label.get().unwrap_or_default()>"Multi-écran"</button>
                                }.into_any()
                            }
                        }}
                        <button on:click=cad>"Ctrl+Alt+Suppr"</button>
                        <button on:click=sharp>
                            {if h264::is_off() { "Revenir au H.264" } else { "Netteté maximale" }}
                        </button>
                        <button class="secondary" on:click=quit.clone()>"Quitter"</button>
                    </div>
                </Show>
            </div>
            {move || {
                match status.get() {
                    Status::Connected => None,
                    Status::Connecting(t) => Some(view! {
                        <div class="session-overlay">
                            <div class="spinner" aria-hidden="true"></div>
                            <p role="status">{t}</p>
                            <a href="/" class="button secondary">"Retour"</a>
                        </div>
                    }.into_any()),
                    Status::Closed { reason, .. } => Some(view! {
                        <div class="session-overlay">
                            <p class="error" role="alert">{crate::sentence(&reason)}</p>
                            <div class="row">
                                <button on:click=retry>"Réessayer"</button>
                                <a href="/" class="button secondary">"Retour"</a>
                            </div>
                        </div>
                    }.into_any()),
                    Status::UntrustedCertificate { fingerprint, can_approve } => {
                        let fp = fingerprint.clone();
                        Some(view! {
                            <div class="session-overlay">
                                <h2>"Nouveau certificat"</h2>
                                <p>"Le PC présente un certificat jamais vu. Compare cette empreinte avec celle affichée par le script de préparation sur le PC :"</p>
                                <p class="mono">{fingerprint}</p>
                                {if can_approve {
                                    view! { <button on:click=move |_| approve(fp.clone())>"Elle est identique : approuver"</button> }.into_any()
                                } else {
                                    view! { <p class="muted">"Seul un admin peut approuver ce certificat."</p> }.into_any()
                                }}
                                <a href="/" class="button secondary">"Retour"</a>
                            </div>
                        }.into_any())
                    }
                }
            }}
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnection_series_survives_transient_failures() {
        assert_eq!(retry_delay(Retry::Yes, 0), Some(1), "coupure : la série démarre");
        assert_eq!(retry_delay(Retry::Transient, 0), None, "premier échec à l'ouverture : on s'arrête");
        assert_eq!(retry_delay(Retry::Transient, 1), Some(2), "PC encore absent pendant la série");
        assert_eq!(retry_delay(Retry::Transient, 7), Some(30));
        assert_eq!(retry_delay(Retry::Transient, 8), None, "série épuisée");
        assert_eq!(retry_delay(Retry::No, 3), None, "refus définitif");
    }

    #[test]
    fn ctrl_alt_shift_alone_exits_desktop() {
        let mut armed = false;
        let mut press = |key, ctrl, alt, shift, down| escape_chord(&mut armed, key, ctrl, alt, shift, down);
        assert!(!press("Control", true, false, false, true));
        assert!(!press("Alt", true, true, false, true));
        assert!(!press("Shift", true, true, true, true));
        assert!(press("Shift", true, true, false, false), "relâchement : sortie");
        assert!(!press("Alt", true, false, false, false), "une seule fois");
        // Ctrl+Alt+Maj+S : raccourci pour le PC, pas de sortie.
        assert!(!press("Shift", true, true, true, true));
        assert!(!press("S", true, true, true, true));
        assert!(!press("Shift", true, true, false, false));
    }
}
