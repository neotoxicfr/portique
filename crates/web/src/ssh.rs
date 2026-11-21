//! Terminal SSH : xterm.js (servi par Portique, chargé à la demande) relié au WebSocket
//! `/api/connections/{id}/ssh`. Sur écran tactile, une barre de touches (Échap, Tab, Ctrl et Alt
//! collants, flèches, combinaisons du compte) se tient juste au-dessus du clavier virtuel.

use std::{
    any::Any,
    cell::{Cell, RefCell},
    rc::Rc,
};

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
    /// Dernière taille connue du serveur (celle de l'URL d'ouverture, puis des `Resize` envoyés).
    size: RefCell<(u16, u16)>,
    /// Gestionnaires du terminal (saisie) : libérés avec lui.
    closures: RefCell<Vec<Box<dyn Any>>>,
    /// Gestionnaires du WebSocket courant : remplacés à chaque reconnexion.
    ws_closures: RefCell<Vec<Box<dyn Any>>>,
    /// Écouteur `resize`/`scroll` de la fenêtre et de la VisualViewport, à retirer au nettoyage.
    on_view: RefCell<Option<Closure<dyn FnMut()>>>,
    disposed: Cell<bool>,
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
        if self.disposed.get() {
            return;
        }
        self.fit.fit();
        let size = (self.term.cols(), self.term.rows());
        // La taille n'est mémorisée qu'une fois envoyée : un changement pendant la connexion
        // part à `Ready`.
        if *self.size.borrow() != size
            && let (Some(ws), Ok(msg)) = (
                self.ws.borrow().as_ref(),
                serde_json::to_string(&SshControl::Resize { cols: size.0, rows: size.1 }),
            )
            && ws.ready_state() == WebSocket::OPEN
            && ws.send_with_str(&msg).is_ok()
        {
            *self.size.borrow_mut() = size;
        }
    }

    fn close(&self) {
        if let Some(ws) = self.ws.borrow_mut().take() {
            ws.set_onmessage(None);
            ws.set_onclose(None);
            let _ = ws.close();
        }
        self.ws_closures.borrow_mut().clear();
    }

    /// Fin de vie : socket, écouteurs de la fenêtre, terminal et gestionnaires.
    fn dispose(&self) {
        self.disposed.set(true);
        self.close();
        if let Some(cb) = self.on_view.borrow_mut().take() {
            let f = cb.as_ref().unchecked_ref();
            let w = window();
            let _ = w.remove_event_listener_with_callback("resize", f);
            if let Some(vv) = w.visual_viewport() {
                let _ = vv.remove_event_listener_with_callback("resize", f);
                let _ = vv.remove_event_listener_with_callback("scroll", f);
            }
        }
        self.term.dispose();
        self.closures.borrow_mut().clear();
    }
}

/// Icônes propres au terminal (le reste vient de `crate::glyph`).
mod glyphs {
    pub const BACK: &str = r#"<path d="M15 5l-7 7 7 7"/>"#;
    pub const KEYBOARD: &str = r#"<rect x="2.5" y="6" width="19" height="12" rx="2.5"/><path d="M6.5 10h.01M10 10h.01M14 10h.01M17.5 10h.01M7 14h10"/>"#;
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
    let host_name = RwSignal::new(String::new());
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
                    Ok(SshMessage::Ready { name, theme, combos: c }) => {
                        host_name.set(name);
                        if let Ok(t) = js_sys::JSON::parse(theme_json(&theme)) {
                            // Le cadre autour du terminal prend le fond du thème : pas de liseré sombre.
                            let bg = Reflect::get(&t, &"background".into()).ok().and_then(|v| v.as_string());
                            let frame = Reflect::get(lm.term.as_ref(), &"element".into())
                                .ok()
                                .and_then(|e| e.dyn_into::<web_sys::Element>().ok())
                                .and_then(|e| e.parent_element())
                                .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok());
                            if let (Some(bg), Some(frame)) = (bg, frame) {
                                let _ = frame.style().set_property("background", &bg);
                            }
                            let _ = Reflect::set(&lm.term.options(), &"theme".into(), &t);
                        }
                        combos.set(c);
                        status.set(Status::Connected);
                        lm.refit();
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
        l.ws_closures.borrow_mut().extend([Box::new(onmessage) as Box<dyn Any>, Box::new(onclose)]);
        *l.ws.borrow_mut() = Some(ws);
    };

    // Faux dès que la page est quittée : la tâche d'initialisation ne doit plus rien créer.
    let alive = StoredValue::new(true);
    let init = move || {
        let Some(el) = term_ref.get_untracked() else { return };
        status.set(Status::Loading("Chargement du terminal…".into()));
        spawn_local(async move {
            let loaded = load_xterm().await;
            if alive.try_get_value() != Some(true) {
                return;
            }
            if let Err(e) = loaded {
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
                ws_closures: RefCell::new(Vec::new()),
                on_view: RefCell::new(None),
                disposed: Cell::new(false),
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
            l.closures.borrow_mut().push(Box::new(on_data));
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
            *l.on_view.borrow_mut() = Some(on_view);
            live.set_value(Some(l));
            connect(None);
        });
    };
    Effect::new(move |_| {
        if term_ref.get().is_some() {
            init();
        }
    });
    // « Reconnecter » : sans terminal (chargement de xterm en échec), c'est l'initialisation qu'on relance.
    let reconnect = move || {
        if live.get_value().is_some() {
            connect(None);
        } else {
            init();
        }
    };

    on_cleanup(move || {
        alive.set_value(false);
        if let Some(l) = live.get_value() {
            l.dispose();
        }
    });

    let send = move |bytes: Vec<u8>| {
        if let Some(l) = live.get_value() {
            l.send(&bytes);
            l.term.focus();
        }
    };
    // Bouton de la barre : pointerdown sans défaut, pour garder le focus (et le clavier virtuel).
    // L'action part sur `click` (clavier et lecteurs d'écran compris), une seule fois.
    let key = move |label: &'static str, name: &'static str, bytes: &'static [u8]| {
        view! {
            <button class="key" aria-label=name
                on:pointerdown=|e| e.prevent_default()
                on:click=move |_| send(bytes.to_vec())>{label}</button>
        }
    };
    let sticky = move |label: &'static str, flag: RwSignal<bool>| {
        view! {
            <button class="key" class:on=move || flag.get() aria-pressed=move || flag.get().to_string()
                on:pointerdown=|e| e.prevent_default()
                on:click=move |_| {
                    flag.update(|f| *f = !*f);
                    if let Some(l) = live.get_value() { l.term.focus(); }
                }>{label}</button>
        }
    };

    // Alerte affichée : l'en-tête, le terminal et la barre de touches passent en `inert` (ni clic, ni
    // Tab, ni frappe vers l'hôte), le focus va sur la première action de l'alerte, puis revient au
    // terminal une fois connecté. Après l'image suivante : `inert` n'est posé ou levé qu'ensuite.
    let blocked = move || !matches!(status.get(), Status::Connected);
    Effect::new(move |_| {
        let b = blocked();
        request_animation_frame(move || {
            if b {
                if let Some(el) = document()
                    .query_selector(".session-overlay :is(button, a)")
                    .ok()
                    .flatten()
                    .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
                {
                    let _ = el.focus();
                }
            } else if let Some(Some(l)) = live.try_get_value() {
                l.term.focus();
            }
        });
    });

    view! {
        <div class="ssh"
            style:height=move || frame.get().map(|(h, _)| format!("{h}px"))
            style:top=move || frame.get().map(|(_, t)| format!("{t}px"))>
            <div class="ssh-top" inert=blocked>
                <a href="/" class="ssh-back" title="Retour aux connexions" aria-label="Retour aux connexions">{crate::icon(glyphs::BACK)}</a>
                <span class="ssh-name">{move || host_name.get()}</span>
                <button class="ssh-toggle" title="Afficher ou masquer la barre de touches" aria-label="Barre de touches" aria-pressed=move || show_bar.get().to_string() on:click=move |_| {
                    show_bar.update(|s| *s = !*s);
                    let cb = Closure::once_into_js(move || {
                        if let Some(Some(l)) = live.try_get_value() {
                            l.refit()
                        }
                    });
                    let _ = window().request_animation_frame(cb.unchecked_ref());
                }>{crate::icon(glyphs::KEYBOARD)}</button>
            </div>
            <div class="ssh-term" node_ref=term_ref inert=blocked></div>
            <Show when=move || show_bar.get()>
                <div class="keybar" inert=blocked>
                    {key("Échap", "Échap", b"\x1b")}
                    {key("Tab", "Tabulation", b"\t")}
                    {sticky("Ctrl", ctrl)}
                    {sticky("Alt", alt)}
                    {key("←", "Flèche gauche", b"\x1b[D")}
                    {key("↑", "Flèche haut", b"\x1b[A")}
                    {key("↓", "Flèche bas", b"\x1b[B")}
                    {key("→", "Flèche droite", b"\x1b[C")}
                    {move || combos.get().into_iter().filter_map(|c| {
                        let bytes = Combo::parse(&c)?.bytes();
                        Some(view! {
                            <button class="key combo" on:pointerdown=|e| e.prevent_default()
                                on:click=move |_| send(bytes.clone())>{c}</button>
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
                            <button on:click=move |_| reconnect()>"Reconnecter"</button>
                            <a href="/" class="button secondary">"Retour"</a>
                        </div>
                    </div>
                }.into_any()),
                Status::UntrustedKey { connection_id, name, fingerprint, can_approve } => {
                    let fp = fingerprint.clone();
                    Some(view! {
                        <div class="session-overlay">
                            <h2>"Nouvelle clé d'hôte"</h2>
                            <p>{format!("« {name} » présente une clé SSH jamais vue. Compare son empreinte avec celle de la machine :")}</p>
                            <p class="mono">{fingerprint}</p>
                            <p class="mono">"ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"</p>
                            {if can_approve {
                                view! { <button on:click=move |_| connect(Some((connection_id, fp.clone())))>"Approuver"</button> }.into_any()
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
