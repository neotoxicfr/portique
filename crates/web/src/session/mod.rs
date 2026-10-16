//! Page de session : canevas plein écran, entrées, menu, reconnexion automatique.

mod clip;
mod engine;
mod h264;
mod keys;

use std::rc::Rc;

use engine::{Engine, Open, Status};
use leptos::{ev, html::Canvas, prelude::*, task::spawn_local};
use leptos_router::hooks::{use_navigate, use_params_map};
use rdp_pdu::fastpath::{Input, ptr};
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{KeyboardEvent, PointerEvent, WheelEvent};

/// Délais de reconnexion automatique (s) : le PC peut redémarrer, le réseau mobile changer.
const RETRY_DELAYS: [u32; 8] = [1, 2, 3, 5, 8, 13, 21, 30];

fn viewport() -> (u32, u32) {
    let w = window();
    let px = |v: Result<JsValue, JsValue>| v.ok().and_then(|v| v.as_f64()).unwrap_or(1024.0) as u32;
    (px(w.inner_width()), px(w.inner_height()))
}

/// Coordonnées bureau d'un événement pointeur (canevas affiché en `object-fit: contain`).
fn desktop_point(canvas: &web_sys::HtmlCanvasElement, x: f64, y: f64) -> (u16, u16) {
    let r = canvas.get_bounding_client_rect();
    let (cw, ch) = (canvas.width() as f64, canvas.height() as f64);
    let scale = (r.width() / cw).min(r.height() / ch).max(1e-6);
    let (ox, oy) = ((r.width() - cw * scale) / 2.0, (r.height() - ch * scale) / 2.0);
    let dx = ((x - r.left() - ox) / scale).clamp(0.0, cw - 1.0);
    let dy = ((y - r.top() - oy) / scale).clamp(0.0, ch - 1.0);
    (dx as u16, dy as u16)
}

fn button_flags(button: i16) -> Option<(u16, bool)> {
    match button {
        0 => Some((ptr::BUTTON1, false)),
        1 => Some((ptr::BUTTON3, false)),
        2 => Some((ptr::BUTTON2, false)),
        3 => Some((ptr::X_BUTTON1, true)),
        4 => Some((ptr::X_BUTTON2, true)),
        _ => None,
    }
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
    let status = RwSignal::new(Status::Connecting("préparation…".into()));
    let attempt = RwSignal::new(0usize);
    let menu_open = RwSignal::new(false);
    // Valeurs locales (non Send) gardées par Leptos : la poignée de session et le support H.264.
    let engine = StoredValue::new_local(None::<Engine>);
    let avc = StoredValue::new_local(None::<bool>);

    // Ouverture (et réouverture) de la session.
    let open = move |trust: Option<String>| {
        let Some(cid) = id() else { return };
        let Some(canvas) = canvas_ref.get_untracked() else { return };
        spawn_local(async move {
            let supported = match avc.get_value() {
                Some(v) => v,
                None => {
                    let v = h264::supported().await;
                    avc.set_value(Some(v));
                    v
                }
            };
            if let Some(old) = engine.try_update_value(Option::take).flatten() {
                old.close();
            }
            let (w, h) = viewport();
            let on_status: Rc<dyn Fn(Status)> = Rc::new(move |s| status.set(s));
            match Engine::open(
                canvas,
                Open { connection_id: cid, width: w, height: h, trust, avc: supported },
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
                    status.set(Status::Connecting(format!("connexion perdue, nouvel essai dans {delay} s…")));
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
    let key_handler = move |e: KeyboardEvent, down: bool| {
        with_engine(&|eng| {
            if !eng.is_connected() {
                return;
            }
            eng.user_gesture();
            // Ctrl+V / Cmd+V : le presse-papier local part vers le PC avant la touche V.
            if down && (e.ctrl_key() || e.meta_key()) && e.code() == "KeyV" {
                eng.paste_guard();
            }
            if let Some((code, ext)) = keys::scancode(&e.code()) {
                e.prevent_default();
                eng.key(code, ext, down);
            } else {
                let key = e.key();
                let mut chars = key.chars();
                if let (Some(c), None) = (chars.next(), chars.next()) {
                    e.prevent_default();
                    let mut buf = [0u16; 2];
                    let events: Vec<Input> = c
                        .encode_utf16(&mut buf)
                        .iter()
                        .map(|u| Input::Unicode { code: *u, release: !down })
                        .collect();
                    eng.input(&events);
                }
            }
        })
    };
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
    let pointer = move |e: PointerEvent, kind: &'static str| {
        let Some(canvas) = canvas_ref.get_untracked() else { return };
        with_engine(&|eng| {
            if !eng.is_connected() {
                return;
            }
            e.prevent_default();
            if kind == "down" {
                eng.user_gesture();
            }
            let (x, y) = desktop_point(&canvas, e.client_x() as f64, e.client_y() as f64);
            let event = match kind {
                "move" => Input::Mouse { flags: ptr::MOVE, x, y },
                _ => {
                    let Some((flag, extended)) = button_flags(e.button()) else { return };
                    let down = kind == "down";
                    if down {
                        let _ = canvas.set_pointer_capture(e.pointer_id());
                    }
                    match (extended, down) {
                        (false, true) => Input::Mouse { flags: flag | ptr::DOWN, x, y },
                        (false, false) => Input::Mouse { flags: flag, x, y },
                        (true, true) => Input::MouseX { flags: flag | ptr::X_DOWN, x, y },
                        (true, false) => Input::MouseX { flags: flag, x, y },
                    }
                }
            };
            eng.input(&[event]);
        })
    };
    let wheel = move |e: WheelEvent| {
        let Some(canvas) = canvas_ref.get_untracked() else { return };
        with_engine(&|eng| {
            if !eng.is_connected() {
                return;
            }
            e.prevent_default();
            let (x, y) = desktop_point(&canvas, e.client_x() as f64, e.client_y() as f64);
            // Pixels → crans de 120 (une molette classique envoie ~100 px par cran).
            let unit = match e.delta_mode() {
                0 => 1.2,
                1 => 40.0,
                _ => 120.0,
            };
            let (dx, dy) = (e.delta_x() * unit, e.delta_y() * unit);
            if dy.abs() >= 1.0 {
                eng.input(&[Input::wheel((-dy).clamp(-255.0, 255.0) as i16, false, x, y)]);
            }
            if dx.abs() >= 1.0 {
                eng.input(&[Input::wheel(dx.clamp(-255.0, 255.0) as i16, true, x, y)]);
            }
        })
    };

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
                on:pointermove=move |e| pointer(e, "move")
                on:pointerdown=move |e| pointer(e, "down")
                on:pointerup=move |e| pointer(e, "up")
                on:wheel=wheel
                on:contextmenu=|e| e.prevent_default()
            ></canvas>
            <div class="session-menu" class:open=move || menu_open.get()>
                <button class="session-handle" title="Menu de session" on:click=move |_| menu_open.update(|o| *o = !*o)>"⋯"</button>
                <Show when=move || menu_open.get()>
                    <div class="session-actions">
                        <button on:click=fullscreen>"Plein écran"</button>
                        <button on:click=cad>"Ctrl+Alt+Suppr"</button>
                        <button class="secondary" on:click=quit.clone()>"Quitter"</button>
                    </div>
                </Show>
            </div>
            {move || {
                match status.get() {
                    Status::Connected => None,
                    Status::Connecting(t) => Some(view! { <div class="session-overlay"><p>{t}</p></div> }.into_any()),
                    Status::Closed { reason, .. } => Some(view! {
                        <div class="session-overlay">
                            <p class="error">{reason}</p>
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
