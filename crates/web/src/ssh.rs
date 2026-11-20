//! Terminal SSH : xterm.js (servi par Portique, chargé à la demande) relié au WebSocket
//! `/api/connections/{id}/ssh`. Sur écran tactile, une barre de touches (Échap, Tab, Ctrl et Alt
//! collants, flèches, combinaisons du compte) se tient juste au-dessus du clavier virtuel.

use std::{cell::RefCell, rc::Rc};

use js_sys::{Promise, Reflect, Uint8Array};
use leptos::{html::Div, prelude::*, task::spawn_local};
use leptos_router::hooks::use_params_map;
use portique_proto::{Combo, SshControl, SshMessage, ctrl_code};
use wasm_bindgen::{JsCast, JsValue, closure::Closure, prelude::wasm_bindgen};
use wasm_bindgen_futures::JsFuture;
use web_sys::{BinaryType, MessageEvent, WebSocket};

#[wasm_bindgen]
extern "C" {
    type Terminal;
    #[wasm_bindgen(constructor)]
    fn new(options: &JsValue) -> Terminal;
    #[wasm_bindgen(method)]
    fn open(this: &Terminal, parent: &web_sys::HtmlElement);
    #[wasm_bindgen(method, js_name = write)]
    fn write_bytes(this: &Terminal, data: &Uint8Array);
    #[wasm_bindgen(method, js_name = onData)]
    fn on_data(this: &Terminal, f: &js_sys::Function);
    #[wasm_bindgen(method)]
    fn focus(this: &Terminal);
    #[wasm_bindgen(method)]
    fn dispose(this: &Terminal);
    #[wasm_bindgen(method, js_name = loadAddon)]
    fn load_addon(this: &Terminal, addon: &FitAddon);
    #[wasm_bindgen(method, getter)]
    fn cols(this: &Terminal) -> u16;
    #[wasm_bindgen(method, getter)]
    fn rows(this: &Terminal) -> u16;
    #[wasm_bindgen(method, getter)]
    fn options(this: &Terminal) -> JsValue;
}

#[wasm_bindgen]
extern "C" {
    /// Instance de `FitAddon.FitAddon` (construite par `new_fit`, le script UMD l'expose ainsi).
    type FitAddon;
    #[wasm_bindgen(method)]
    fn fit(this: &FitAddon);
}

fn new_fit() -> Result<FitAddon, String> {
    let ns = Reflect::get(&window(), &"FitAddon".into()).map_err(|_| "FitAddon absent")?;
    let ctor: js_sys::Function = Reflect::get(&ns, &"FitAddon".into())
        .ok()
        .and_then(|c| c.dyn_into().ok())
        .ok_or("FitAddon.FitAddon absent")?;
    Reflect::construct(&ctor, &js_sys::Array::new()).map(JsCast::unchecked_into).map_err(|e| format!("{e:?}"))
}

/// Couleurs des thèmes de `portique_proto::TERMINAL_THEMES` (palette ANSI de xterm sinon).
fn theme_json(name: &str) -> &'static str {
    match name {
        "clair" => {
            r##"{"background":"#fafafa","foreground":"#1f2328","cursor":"#1f2328","selectionBackground":"#c8d1dc",
            "black":"#1f2328","red":"#cf222e","green":"#116329","yellow":"#7d4e00","blue":"#0550ae",
            "magenta":"#8250df","cyan":"#1b7c83","white":"#6e7781","brightBlack":"#57606a","brightRed":"#a40e26",
            "brightGreen":"#1a7f37","brightYellow":"#633c01","brightBlue":"#0969da","brightMagenta":"#a475f9",
            "brightCyan":"#3192aa","brightWhite":"#8c959f"}"##
        }
        "solarise" => {
            r##"{"background":"#002b36","foreground":"#93a1a1","cursor":"#93a1a1","selectionBackground":"#073642",
            "black":"#073642","red":"#dc322f","green":"#859900","yellow":"#b58900","blue":"#268bd2",
            "magenta":"#d33682","cyan":"#2aa198","white":"#eee8d5","brightBlack":"#586e75","brightRed":"#cb4b16",
            "brightGreen":"#859900","brightYellow":"#b58900","brightBlue":"#839496","brightMagenta":"#6c71c4",
            "brightCyan":"#93a1a1","brightWhite":"#fdf6e3"}"##
        }
        "dracula" => {
            r##"{"background":"#282a36","foreground":"#f8f8f2","cursor":"#f8f8f2","selectionBackground":"#44475a",
            "black":"#21222c","red":"#ff5555","green":"#50fa7b","yellow":"#f1fa8c","blue":"#bd93f9",
            "magenta":"#ff79c6","cyan":"#8be9fd","white":"#f8f8f2","brightBlack":"#6272a4","brightRed":"#ff6e6e",
            "brightGreen":"#69ff94","brightYellow":"#ffffa5","brightBlue":"#d6acff","brightMagenta":"#ff92df",
            "brightCyan":"#a4ffff","brightWhite":"#ffffff"}"##
        }
        "nord" => {
            r##"{"background":"#2e3440","foreground":"#d8dee9","cursor":"#d8dee9","selectionBackground":"#434c5e",
            "black":"#3b4252","red":"#bf616a","green":"#a3be8c","yellow":"#ebcb8b","blue":"#81a1c1",
            "magenta":"#b48ead","cyan":"#88c0d0","white":"#e5e9f0","brightBlack":"#4c566a","brightRed":"#bf616a",
            "brightGreen":"#a3be8c","brightYellow":"#ebcb8b","brightBlue":"#81a1c1","brightMagenta":"#b48ead",
            "brightCyan":"#8fbcbb","brightWhite":"#eceff4"}"##
        }
        // Rouge sombre : pour repérer d'un coup d'œil un hôte sensible (production, routeur).
        "alerte" => {
            r##"{"background":"#2b0b0e","foreground":"#f4e4e5","cursor":"#ff6b6b","selectionBackground":"#5a1d23"}"##
        }
        _ => {
            r##"{"background":"#111317","foreground":"#e7e9ed","cursor":"#e7e9ed","selectionBackground":"#3a3f4b"}"##
        }
    }
}

fn window() -> web_sys::Window {
    web_sys::window().expect("fenêtre")
}

/// Charge un script du site (une fois) et attend qu'il soit exécuté.
async fn load_script(src: &str) -> Result<(), String> {
    let doc = window().document().ok_or("document absent")?;
    let el: web_sys::HtmlScriptElement =
        doc.create_element("script").map_err(|e| format!("{e:?}"))?.unchecked_into();
    let done = Promise::new(&mut |resolve, reject| {
        el.set_onload(Some(&resolve));
        el.set_onerror(Some(&reject));
    });
    el.set_src(src);
    doc.head().ok_or("en-tête absent")?.append_child(&el).map_err(|e| format!("{e:?}"))?;
    JsFuture::from(done).await.map(|_| ()).map_err(|_| format!("chargement de {src} impossible"))
}

/// xterm.js et son extension d'ajustement, servis par Portique (aucun CDN : CSP `script-src 'self'`).
async fn load_xterm() -> Result<(), String> {
    let w = window();
    if Reflect::has(&w, &"Terminal".into()).unwrap_or(false)
        && Reflect::has(&w, &"FitAddon".into()).unwrap_or(false)
    {
        return Ok(());
    }
    let doc = w.document().ok_or("document absent")?;
    let link: web_sys::HtmlLinkElement =
        doc.create_element("link").map_err(|e| format!("{e:?}"))?.unchecked_into();
    link.set_rel("stylesheet");
    link.set_href("/xterm/xterm.css");
    doc.head().ok_or("en-tête absent")?.append_child(&link).map_err(|e| format!("{e:?}"))?;
    load_script("/xterm/xterm.js").await?;
    load_script("/xterm/addon-fit.js").await
}

#[derive(Debug, Clone, PartialEq)]
enum Status {
    Loading(String),
    Connected,
    Closed(String),
    UntrustedKey { connection_id: i64, name: String, fingerprint: String, can_approve: bool },
}

/// Terminal vivant : xterm, ajustement, WebSocket courant et gestionnaires gardés en vie.
struct Live {
    term: Terminal,
    fit: FitAddon,
    ws: RefCell<Option<WebSocket>>,
    size: RefCell<(u16, u16)>,
    closures: RefCell<Vec<JsValue>>,
}

impl Live {
    fn send(&self, bytes: &[u8]) {
        if let Some(ws) = self.ws.borrow().as_ref()
            && ws.ready_state() == WebSocket::OPEN
        {
            let _ = ws.send_with_u8_array(bytes);
        }
    }

    /// Ajuste le terminal à son cadre et prévient le serveur si la taille change.
    fn refit(&self) {
        self.fit.fit();
        let size = (self.term.cols(), self.term.rows());
        if *self.size.borrow() != size {
            *self.size.borrow_mut() = size;
            if let (Some(ws), Ok(msg)) = (
                self.ws.borrow().as_ref(),
                serde_json::to_string(&SshControl::Resize { cols: size.0, rows: size.1 }),
            ) && ws.ready_state() == WebSocket::OPEN
            {
                let _ = ws.send_with_str(&msg);
            }
        }
    }

    fn close(&self) {
        if let Some(ws) = self.ws.borrow_mut().take() {
            ws.set_onmessage(None);
            ws.set_onclose(None);
            let _ = ws.close();
        }
    }
}

fn ws_url(id: i64, (cols, rows): (u16, u16), trust: Option<&(i64, String)>) -> String {
    let loc = window().location();
    let proto = if loc.protocol().unwrap_or_default() == "https:" { "wss" } else { "ws" };
    let host = loc.host().unwrap_or_default();
    let mut url = format!("{proto}://{host}/api/connections/{id}/ssh?cols={cols}&rows={rows}");
    if let Some((host_id, fp)) = trust {
        url.push_str(&format!(
            "&trust_for={host_id}&trust={}",
            String::from(js_sys::encode_uri_component(fp))
        ));
    }
    url
}

/// Octets d'une saisie, Ctrl/Alt collants appliqués à un caractère seul.
fn typed(data: &str, ctrl: bool, alt: bool) -> Vec<u8> {
    let mut chars = data.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) if (ctrl || alt) && c.is_ascii() => {
            let mut b = Vec::with_capacity(2);
            if alt {
                b.push(0x1b);
            }
            b.push(if ctrl { ctrl_code(c) } else { c as u8 });
            b
        }
        _ => data.as_bytes().to_vec(),
    }
}

#[component]
pub fn SshPage() -> impl IntoView {
    let params = use_params_map();
    let id = move || params.with_untracked(|p| p.get("id").and_then(|s| s.parse::<i64>().ok()));
    let term_ref = NodeRef::<Div>::new();
    let status = RwSignal::new(Status::Loading("Chargement du terminal…".into()));
    let combos = RwSignal::new(Vec::<String>::new());
    let ctrl = RwSignal::new(false);
    let alt = RwSignal::new(false);
    let touch = window().match_media("(pointer: coarse)").ok().flatten().is_some_and(|m| m.matches());
    let show_bar = RwSignal::new(touch);
    // Cadre visible (hors clavier virtuel) : hauteur et décalage de la VisualViewport.
    let frame = RwSignal::new(None::<(f64, f64)>);
    let live = StoredValue::new_local(None::<Rc<Live>>);

    let connect = move |trust: Option<(i64, String)>| {
        let Some(id) = id() else { return };
        let Some(l) = live.get_value() else { return };
        l.close();
        status.set(Status::Loading("Connexion…".into()));
        let size = (l.term.cols(), l.term.rows());
        *l.size.borrow_mut() = size;
        let Ok(ws) = WebSocket::new(&ws_url(id, size, trust.as_ref())) else {
            status.set(Status::Closed("WebSocket impossible".into()));
            return;
        };
        ws.set_binary_type(BinaryType::Arraybuffer);
        let lm = l.clone();
        let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
            let data = e.data();
            if let Some(text) = data.as_string() {
                match serde_json::from_str::<SshMessage>(&text) {
                    Ok(SshMessage::Ready { theme, combos: c }) => {
                        if let Ok(t) = js_sys::JSON::parse(theme_json(&theme)) {
                            let _ = Reflect::set(&lm.term.options(), &"theme".into(), &t);
                        }
                        combos.set(c);
                        status.set(Status::Connected);
                        lm.refit();
                        lm.term.focus();
                    }
                    Ok(SshMessage::UntrustedHostKey { connection_id, name, fingerprint, can_approve }) => {
                        status.set(Status::UntrustedKey { connection_id, name, fingerprint, can_approve })
                    }
                    Ok(SshMessage::Error { message }) => status.set(Status::Closed(message)),
                    Err(_) => {}
                }
            } else {
                lm.term.write_bytes(&Uint8Array::new(&data));
            }
        });
        let onclose = Closure::<dyn FnMut(web_sys::CloseEvent)>::new(move |_| {
            status.update(|s| {
                if matches!(s, Status::Connected | Status::Loading(_)) {
                    *s = Status::Closed("Session terminée.".into());
                }
            });
        });
        ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));
        l.closures.borrow_mut().extend([onmessage.into_js_value(), onclose.into_js_value()]);
        *l.ws.borrow_mut() = Some(ws);
    };

    Effect::new(move |_| {
        let Some(el) = term_ref.get() else { return };
        spawn_local(async move {
            if let Err(e) = load_xterm().await {
                status.set(Status::Closed(e));
                return;
            }
            let opts = js_sys::JSON::parse(
                r#"{"cursorBlink":true,"scrollback":5000,"fontSize":14,
                "fontFamily":"ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"}"#,
            )
            .unwrap_or(JsValue::NULL);
            let fit = match new_fit() {
                Ok(f) => f,
                Err(e) => return status.set(Status::Closed(e)),
            };
            let term = Terminal::new(&opts);
            term.load_addon(&fit);
            term.open(&el);
            let l = Rc::new(Live {
                term,
                fit,
                ws: RefCell::new(None),
                size: RefCell::new((80, 24)),
                closures: RefCell::new(Vec::new()),
            });
            l.fit.fit();
            let ld = l.clone();
            let on_data = Closure::<dyn FnMut(String)>::new(move |d: String| {
                let (c, a) = (ctrl.get_untracked(), alt.get_untracked());
                ld.send(&typed(&d, c, a));
                if c || a {
                    ctrl.set(false);
                    alt.set(false);
                }
            });
            l.term.on_data(on_data.as_ref().unchecked_ref());
            l.closures.borrow_mut().push(on_data.into_js_value());
            // Taille : fenêtre redimensionnée, rotation, clavier virtuel qui s'ouvre ou se ferme.
            let lr = l.clone();
            let on_view = Closure::<dyn FnMut()>::new(move || {
                if let Some(vv) = window().visual_viewport() {
                    frame.set(Some((vv.height(), vv.offset_top())));
                }
                let lr = lr.clone();
                // Après le rendu du nouveau cadre.
                let cb = Closure::once_into_js(move || lr.refit());
                let _ = window().request_animation_frame(cb.unchecked_ref());
            });
            let _ = window().add_event_listener_with_callback("resize", on_view.as_ref().unchecked_ref());
            if let Some(vv) = window().visual_viewport() {
                let _ = vv.add_event_listener_with_callback("resize", on_view.as_ref().unchecked_ref());
                let _ = vv.add_event_listener_with_callback("scroll", on_view.as_ref().unchecked_ref());
                frame.set(Some((vv.height(), vv.offset_top())));
            }
            l.closures.borrow_mut().push(on_view.into_js_value());
            live.set_value(Some(l));
            connect(None);
        });
    });

    on_cleanup(move || {
        if let Some(l) = live.get_value() {
            l.close();
            l.term.dispose();
        }
    });

    let send = move |bytes: Vec<u8>| {
        if let Some(l) = live.get_value() {
            l.send(&bytes);
            l.term.focus();
        }
    };
    // Bouton de la barre : pointerdown sans défaut, pour garder le focus (et le clavier virtuel).
    let key = move |label: &'static str, bytes: &'static [u8]| {
        view! {
            <button class="key" on:pointerdown=move |e| { e.prevent_default(); send(bytes.to_vec()); }>{label}</button>
        }
    };
    let sticky = move |label: &'static str, flag: RwSignal<bool>| {
        view! {
            <button class="key" class:on=move || flag.get()
                on:pointerdown=move |e| {
                    e.prevent_default();
                    flag.update(|f| *f = !*f);
                    if let Some(l) = live.get_value() { l.term.focus(); }
                }>{label}</button>
        }
    };

    view! {
        <div class="ssh"
            style:height=move || frame.get().map(|(h, _)| format!("{h}px"))
            style:top=move || frame.get().map(|(_, t)| format!("{t}px"))>
            <div class="ssh-top">
                <a href="/" class="ssh-back" title="Retour aux connexions" aria-label="Retour aux connexions">"←"</a>
                <button class="ssh-toggle" title="Afficher ou masquer la barre de touches" aria-label="Barre de touches" on:click=move |_| {
                    show_bar.update(|s| *s = !*s);
                    let cb = Closure::once_into_js(move || if let Some(l) = live.get_value() { l.refit() });
                    let _ = window().request_animation_frame(cb.unchecked_ref());
                }>"⌨"</button>
            </div>
            <div class="ssh-term" node_ref=term_ref></div>
            <Show when=move || show_bar.get()>
                <div class="keybar">
                    {key("Échap", b"\x1b")}
                    {key("Tab", b"\t")}
                    {sticky("Ctrl", ctrl)}
                    {sticky("Alt", alt)}
                    {key("←", b"\x1b[D")}
                    {key("↑", b"\x1b[A")}
                    {key("↓", b"\x1b[B")}
                    {key("→", b"\x1b[C")}
                    {move || combos.get().into_iter().filter_map(|c| {
                        let bytes = Combo::parse(&c)?.bytes();
                        Some(view! {
                            <button class="key combo" on:pointerdown=move |e| { e.prevent_default(); send(bytes.clone()); }>{c}</button>
                        })
                    }).collect_view()}
                </div>
            </Show>
            {move || match status.get() {
                Status::Connected => None,
                Status::Loading(t) => Some(view! {
                    <div class="session-overlay">
                        <div class="spinner" aria-hidden="true"></div>
                        <p role="status">{t}</p>
                        <a href="/" class="button secondary">"Retour"</a>
                    </div>
                }.into_any()),
                Status::Closed(reason) => Some(view! {
                    <div class="session-overlay">
                        <p class="error" role="alert">{crate::sentence(&reason)}</p>
                        <div class="row">
                            <button on:click=move |_| connect(None)>"Reconnecter"</button>
                            <a href="/" class="button secondary">"Retour"</a>
                        </div>
                    </div>
                }.into_any()),
                Status::UntrustedKey { connection_id, name, fingerprint, can_approve } => {
                    let fp = fingerprint.clone();
                    Some(view! {
                        <div class="session-overlay">
                            <h2>"Nouvelle clé d'hôte"</h2>
                            <p>{format!("« {name} » présente une clé SSH jamais vue. Compare-la avec celle de la machine (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub) :")}</p>
                            <p class="mono">{fingerprint}</p>
                            {if can_approve {
                                view! { <button on:click=move |_| connect(Some((connection_id, fp.clone())))>"Elle est identique : approuver"</button> }.into_any()
                            } else {
                                view! { <p class="muted">"Seul un admin peut approuver cette clé."</p> }.into_any()
                            }}
                            <a href="/" class="button secondary">"Retour"</a>
                        </div>
                    }.into_any())
                }
            }}
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::typed;

    #[test]
    fn sticky_modifiers() {
        assert_eq!(typed("c", true, false), [0x03]);
        assert_eq!(typed("b", false, true), [0x1b, b'b']);
        assert_eq!(typed("d", true, true), [0x1b, 0x04]);
        assert_eq!(typed("ls", true, false), b"ls", "collé (plusieurs caractères) : tel quel");
        assert_eq!(typed("é", false, false), "é".as_bytes());
    }
}
