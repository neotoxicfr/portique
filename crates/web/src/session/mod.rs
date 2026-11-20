//! Page de session : canevas plein écran, entrées (souris, clavier, gestes tactiles, clavier
//! virtuel), menu, reconnexion automatique.

mod clip;
mod engine;
mod h264;
mod keys;
mod touch;
mod views;

use std::rc::Rc;

use engine::{Engine, Extend, Open, Retry, Status};
use leptos::{
    ev,
    html::{Button, Canvas, Textarea},
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
    let screens = StoredValue::new_local(None::<(Vec<ScreenGeom>, usize)>);
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
            let on_single: Rc<dyn Fn()> = Rc::new(move || {
                if current() {
                    multi_active.set(false);
                    multi_label.set(Some("Disposition refusée par le PC".into()));
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
    let blur = window_event_listener(ev::blur, move |_| with_engine(&|e| e.release_all()));
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

    let listeners = StoredValue::new_local(Some((kd, ku, blur, resize, focus)));
    on_cleanup(move || {
        open_gen.try_update_value(|g| *g += 1);
        cancel_resize();
        if let Some((kd, ku, blur, resize, focus)) = listeners.try_update_value(Option::take).flatten() {
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
        let Some(t) = kbd_ref.get_untracked() else { return };
        let el: &web_sys::Element = t.as_ref();
        if document().active_element().is_some_and(|a| &a == el) {
            let _ = t.blur();
        } else {
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
            match views::screens().await {
                Ok((list, cur)) if list.len() > 1 => {
                    screens.set_value(Some((list, cur)));
                    multi_label.set(extend_label());
                }
                Ok(_) => multi_label.set(Some("Un seul écran détecté".into())),
                Err(e) => multi_label.set(Some(format!("Multi-écran indisponible : {e}"))),
            }
        });
    };
    let extend = move |_| {
        let Some((list, cur)) = screens.get_value() else { return };
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
    let retry = move |_| {
        attempt.set(0);
        open(None);
    };
    let approve = move |fp: String| {
        attempt.set(0);
        open(Some(fp));
    };

    view! {
        <div class="session">
            <canvas
                node_ref=canvas_ref
                class="screen"
                tabindex="0"
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
            <button
                class="session-keyboard"
                aria-label="Clavier"
                title="Clavier"
                on:mousedown=|e| e.prevent_default()
                on:click=toggle_keyboard
            >
                {crate::icon(KEYBOARD)}
            </button>
            <div class="session-menu" class:open=move || menu_open.get()>
                <button
                    node_ref=handle_ref
                    class="session-handle"
                    title="Menu de session (Ctrl+Alt+Maj depuis le bureau)"
                    on:click=move |_| menu_open.update(|o| *o = !*o)
                >
                    "⋯"
                </button>
                <Show when=move || menu_open.get()>
                    <div class="session-actions">
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
