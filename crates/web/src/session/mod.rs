//! Page de session : canevas plein écran, entrées, menu, reconnexion automatique.

mod clip;
mod engine;
mod h264;
mod keys;
mod views;

use std::rc::Rc;

use engine::{Engine, Open, Status};
use leptos::{ev, html::Canvas, prelude::*, task::spawn_local};
use leptos_router::hooks::{use_navigate, use_params_map};
use views::ScreenGeom;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{KeyboardEvent, PointerEvent, WheelEvent};

/// Délais de reconnexion automatique (s) : le PC peut redémarrer, le réseau mobile changer.
const RETRY_DELAYS: [u32; 8] = [1, 2, 3, 5, 8, 13, 21, 30];

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
    let status = RwSignal::new(Status::Connecting("Préparation…".into()));
    let attempt = RwSignal::new(0usize);
    let menu_open = RwSignal::new(false);
    // Valeur locale (non Send) gardée par Leptos : la poignée de session.
    let engine = StoredValue::new_local(None::<Engine>);

    // Ouverture (et réouverture) de la session.
    let open = move |trust: Option<String>| {
        let Some(cid) = id() else { return };
        let Some(canvas) = canvas_ref.get_untracked() else { return };
        spawn_local(async move {
            // Relu à chaque ouverture : le navigateur a pu être noté inapte pendant la session.
            let avc = h264::support().await;
            if let Some(old) = engine.try_update_value(Option::take).flatten() {
                old.close();
            }
            let (w, h) = viewport();
            let on_status: Rc<dyn Fn(Status)> = Rc::new(move |s| status.set(s));
            match Engine::open(
                canvas,
                Open { connection_id: cid, width: w, height: h, trust, avc },
                on_status,
            ) {
                Ok(e) => engine.set_value(Some(e)),
                Err(e) => status.set(Status::Closed { reason: e, retry: false }),
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

    // Reconnexion automatique après une coupure en cours de session.
    {
        Effect::new(move |_| {
            if let Status::Closed { retry: true, .. } = status.get() {
                let n = attempt.get_untracked();
                if n < RETRY_DELAYS.len() {
                    let delay = RETRY_DELAYS[n];
                    status.set(Status::Connecting(format!("Connexion perdue, nouvel essai dans {delay} s…")));
                    spawn_local(async move {
                        sleep(delay).await;
                        attempt.update(|a| *a += 1);
                        open(None);
                    });
                }
            } else if status.get() == Status::Connected {
                attempt.set(0);
            }
        });
    }

    // Clavier : positions physiques → scancodes ; à défaut (clavier virtuel), caractère Unicode.
    let key_handler = move |e: KeyboardEvent, down: bool| with_engine(&|eng| eng.key_input(&e, down));
    let kd = window_event_listener(ev::keydown, move |e| key_handler(e, true));
    let ku = window_event_listener(ev::keyup, move |e| key_handler(e, false));
    let blur = window_event_listener(ev::blur, move |_| with_engine(&|e| e.release_all()));
    // Retour sur la page : le presse-papier local a pu changer.
    let focus = window_event_listener(ev::focus, move |_| {
        with_engine(&|e| {
            let e = e.clone();
            spawn_local(async move { e.sync_local_clipboard().await });
        })
    });

    // Taille : la session suit la fenêtre (contrôle d'affichage), après 400 ms de calme.
    let resize_timer = StoredValue::new_local(None::<i32>);
    let resize = window_event_listener(ev::resize, move |_| {
        if let Some(t) = resize_timer.try_update_value(Option::take).flatten() {
            window().clear_timeout_with_handle(t);
        }
        let cb = wasm_bindgen::closure::Closure::once_into_js(move || {
            let (w, h) = viewport();
            with_engine(&|e| e.resize(w, h));
        });
        if let Ok(t) = window().set_timeout_with_callback_and_timeout_and_arguments_0(cb.unchecked_ref(), 400)
        {
            resize_timer.set_value(Some(t));
        }
    });

    let listeners = StoredValue::new_local(Some((kd, ku, blur, resize, focus)));
    on_cleanup(move || {
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

    // Souris et tactile (événements pointeur sur le canevas).
    let pointer =
        move |e: PointerEvent, kind: &'static str| with_engine(&|eng| eng.pointer_input(0, &e, kind));
    let wheel = move |e: WheelEvent| with_engine(&|eng| eng.wheel_input(0, &e));

    // Menu de session.
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
    // Multi-écran : 1) détecter les écrans (demande la permission), 2) ouvrir les fenêtres dans
    // un second clic (un navigateur bloque une fenêtre ouverte hors d'un geste utilisateur).
    let screens = StoredValue::new_local(None::<(Vec<ScreenGeom>, usize)>);
    let multi_label = RwSignal::new(None::<String>);
    let multi_active = RwSignal::new(false);
    let detect = move |_| {
        spawn_local(async move {
            match views::screens().await {
                Ok((list, cur)) if list.len() > 1 => {
                    multi_label.set(Some(format!("Étendre sur {} écrans", list.len())));
                    screens.set_value(Some((list, cur)));
                }
                Ok(_) => multi_label.set(Some("Un seul écran détecté".into())),
                Err(e) => multi_label.set(Some(format!("Multi-écran indisponible : {e}"))),
            }
        });
    };
    let extend = move |_| {
        let Some((list, cur)) = screens.get_value() else { return };
        with_engine(&|e| match e.enable_multi(&list, cur) {
            Ok(n) => {
                multi_active.set(true);
                multi_label.set(Some(format!("{n} écrans")));
            }
            Err(err) => multi_label.set(Some(err)),
        });
        menu_open.set(false);
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
                on:wheel=wheel
                on:contextmenu=|e| e.prevent_default()
            ></canvas>
            <div class="session-menu" class:open=move || menu_open.get()>
                <button class="session-handle" title="Menu de session" on:click=move |_| menu_open.update(|o| *o = !*o)>"⋯"</button>
                <Show when=move || menu_open.get()>
                    <div class="session-actions">
                        <button on:click=fullscreen>"Plein écran"</button>
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
