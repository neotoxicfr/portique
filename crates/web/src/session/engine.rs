//! Moteur de session dans le navigateur : WebSocket ↔ `rdp-session`, EGFX ↔ canevas.
//!
//! Tout passe par une seule boucle asynchrone (`pump`) qui traite les messages dans l'ordre et
//! attend le décodage des images H.264 : l'ordre des commandes graphiques et les accusés
//! d'image restent exacts. Les entrées (clavier, souris) partent directement sur le WebSocket.

use std::{cell::RefCell, collections::HashSet, rc::Rc};

use futures::{StreamExt, channel::mpsc};
use rdp_gfx::{Gfx, Out, Rect};
use rdp_pdu::fastpath::{Input, PointerUpdate};
use rdp_session::{Config, Event, Session};
use wasm_bindgen::{Clamped, JsCast, closure::Closure};
use web_sys::{
    BinaryType, CanvasRenderingContext2d, CloseEvent, HtmlCanvasElement, ImageData, MessageEvent, WebSocket,
};
use yawrdp_proto::SessionMessage;

use super::{
    clip,
    h264::H264,
    views::{self, ScreenGeom, View},
};

/// État visible par l'interface.
#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    Connecting(String),
    Connected,
    /// Coupure : `retry` = la reconnexion automatique est tentée.
    Closed {
        reason: String,
        retry: bool,
    },
    UntrustedCertificate {
        fingerprint: String,
        can_approve: bool,
    },
}

enum Incoming {
    Text(String),
    Binary(Vec<u8>),
    Closed(String),
}

struct Inner {
    ws: WebSocket,
    /// Vue 0 = fenêtre principale ; les suivantes = fenêtres des écrans secondaires.
    views: Vec<View>,
    /// Multi-écran demandé : rectangles attendus en sortie, dans l'ordre des vues.
    multi: Option<Vec<Rect>>,
    session: Option<Session>,
    gfx: Gfx,
    buf: Vec<u8>,
    gfx_channel: Option<u32>,
    display_channel: Option<u32>,
    display_ready: bool,
    desktop: (u32, u32),
    cursors: Vec<Option<String>>,
    pressed: HashSet<(u8, bool)>,
    connected: bool,
    closing: bool,
    avc: bool,
    clip: rdp_clip::Clipboard,
    /// Formats encore à demander au serveur pour son contenu courant.
    clip_wanted: Vec<rdp_clip::ClipFormat>,
    clip_received: Vec<rdp_clip::LocalData>,
    /// Écriture locale refusée (page sans focus) : retentée au prochain geste.
    clip_pending_write: Option<Vec<rdp_clip::LocalData>>,
    /// Empreinte du dernier contenu échangé (évite l'écho PC → navigateur → PC).
    clip_last: Option<u64>,
    /// Ctrl+V en cours : les entrées attendent la synchronisation du presse-papier.
    holding: bool,
    held: Vec<Input>,
    /// Attente de l'accusé (Format List Response) de notre dernière liste de formats : Windows ne
    /// l'envoie qu'une fois notre contenu installé, c'est le moment de relâcher un Ctrl+V.
    clip_ack: Option<futures::channel::oneshot::Sender<()>>,
}

/// Poignée partagée sur une session en cours.
#[derive(Clone)]
pub struct Engine {
    inner: Rc<RefCell<Inner>>,
    status: Rc<dyn Fn(Status)>,
}

/// Paramètres d'ouverture.
pub struct Open {
    pub connection_id: i64,
    pub width: u32,
    pub height: u32,
    /// Empreinte approuvée par l'admin pour un premier contact.
    pub trust: Option<String>,
    pub avc: bool,
}

fn ws_url(id: i64, trust: Option<&str>) -> String {
    let loc = web_sys::window().unwrap().location();
    let proto = if loc.protocol().unwrap_or_default() == "https:" { "wss" } else { "ws" };
    let host = loc.host().unwrap_or_default();
    match trust {
        Some(t) => format!("{proto}://{host}/api/connections/{id}/session?trust={t}"),
        None => format!("{proto}://{host}/api/connections/{id}/session"),
    }
}

/// Largeur paire, bornes du protocole de contrôle d'affichage (200 à 8192).
pub fn clamp_size(w: u32, h: u32) -> (u32, u32) {
    ((w.clamp(200, 8192)) & !1, h.clamp(200, 8192))
}

impl Engine {
    pub fn open(canvas: HtmlCanvasElement, opts: Open, status: Rc<dyn Fn(Status)>) -> Result<Self, String> {
        let ws = WebSocket::new(&ws_url(opts.connection_id, opts.trust.as_deref()))
            .map_err(|e| format!("{e:?}"))?;
        ws.set_binary_type(BinaryType::Arraybuffer);
        let (w, h) = clamp_size(opts.width, opts.height);
        let main_view = View::new(canvas, Rect { x: 0, y: 0, w, h }, None)?;
        let inner = Rc::new(RefCell::new(Inner {
            ws: ws.clone(),
            views: vec![main_view],
            multi: None,
            session: None,
            gfx: Gfx::new(),
            buf: Vec::new(),
            gfx_channel: None,
            display_channel: None,
            display_ready: false,
            desktop: (w, h),
            cursors: vec![None; 32],
            pressed: HashSet::new(),
            connected: false,
            closing: false,
            avc: opts.avc,
            clip: rdp_clip::Clipboard::new(),
            clip_wanted: Vec::new(),
            clip_received: Vec::new(),
            clip_pending_write: None,
            clip_last: None,
            holding: false,
            held: Vec::new(),
            clip_ack: None,
        }));
        let engine = Engine { inner, status };
        (engine.status)(Status::Connecting("connexion au PC…".into()));

        let (tx, rx) = mpsc::unbounded::<Incoming>();
        let t = tx.clone();
        let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
            let data = e.data();
            let msg = if let Some(s) = data.as_string() {
                Incoming::Text(s)
            } else {
                Incoming::Binary(js_sys::Uint8Array::new(&data).to_vec())
            };
            let _ = t.unbounded_send(msg);
        });
        let t = tx.clone();
        let onclose = Closure::<dyn FnMut(CloseEvent)>::new(move |e: CloseEvent| {
            let reason = if e.reason().is_empty() { "connexion fermée".to_owned() } else { e.reason() };
            let _ = t.unbounded_send(Incoming::Closed(reason));
        });
        ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));
        onmessage.forget();
        onclose.forget();

        let e = engine.clone();
        wasm_bindgen_futures::spawn_local(async move { e.pump(rx).await });
        Ok(engine)
    }

    pub fn is_connected(&self) -> bool {
        self.inner.borrow().connected
    }

    /// Fermeture demandée par l'utilisateur (pas de reconnexion).
    pub fn close(&self) {
        let mut i = self.inner.borrow_mut();
        i.closing = true;
        for v in i.views.iter().skip(1) {
            v.close();
        }
        if let Some(s) = i.session.as_mut()
            && s.is_active()
        {
            let bye = s.shutdown();
            let _ = i.ws.send_with_u8_array(&bye);
        }
        let _ = i.ws.close();
    }

    async fn pump(&self, mut rx: mpsc::UnboundedReceiver<Incoming>) {
        let mut h264: Option<H264> = None;
        while let Some(msg) = rx.next().await {
            let result = match msg {
                Incoming::Text(t) => self.control(&t),
                Incoming::Binary(b) => self.stream(&b, &mut h264).await,
                Incoming::Closed(reason) => {
                    let (connected, closing) = {
                        let i = self.inner.borrow();
                        (i.connected, i.closing)
                    };
                    self.inner.borrow_mut().connected = false;
                    if !closing {
                        (self.status)(Status::Closed { reason, retry: connected });
                    }
                    break;
                }
            };
            if let Err(e) = result {
                (self.status)(Status::Closed { reason: e, retry: false });
                self.inner.borrow_mut().closing = true;
                let _ = self.inner.borrow().ws.close();
                break;
            }
        }
    }

    fn control(&self, text: &str) -> Result<(), String> {
        match serde_json::from_str::<SessionMessage>(text).map_err(|e| e.to_string())? {
            SessionMessage::Ready { selected_protocol, username, domain, .. } => {
                let mut i = self.inner.borrow_mut();
                let (w, h) = i.desktop;
                let session = Session::new(Config {
                    width: w as u16,
                    height: h as u16,
                    keyboard_layout: 0x040C,
                    client_name: "yawrdp".into(),
                    selected_protocol,
                    username,
                    domain,
                    display_control: true,
                });
                let first = session.start();
                i.ws.send_with_u8_array(&first).map_err(|e| format!("{e:?}"))?;
                i.session = Some(session);
                drop(i);
                (self.status)(Status::Connecting("ouverture de la session Windows…".into()));
            }
            SessionMessage::Error { message } => {
                self.inner.borrow_mut().closing = true;
                (self.status)(Status::Closed { reason: message, retry: false });
            }
            SessionMessage::UntrustedCertificate { fingerprint, can_approve } => {
                self.inner.borrow_mut().closing = true;
                (self.status)(Status::UntrustedCertificate { fingerprint, can_approve });
            }
        }
        Ok(())
    }

    /// Octets RDP reçus : découpe en trames, session, puis graphique.
    async fn stream(&self, data: &[u8], h264: &mut Option<H264>) -> Result<(), String> {
        let events = {
            let mut i = self.inner.borrow_mut();
            i.buf.extend_from_slice(data);
            let mut events = Vec::new();
            while let Some(n) = rdp_pdu::x224::frame_len(&i.buf) {
                if n < 2 {
                    return Err("trame RDP invalide".into());
                }
                if i.buf.len() < n {
                    break;
                }
                let frame: Vec<u8> = i.buf.drain(..n).collect();
                let session = i.session.as_mut().ok_or("données RDP avant la session")?;
                events.extend(session.feed(&frame).map_err(|e| e.to_string())?);
            }
            events
        };
        for ev in events {
            self.event(ev, h264).await?;
        }
        Ok(())
    }

    fn send(&self, bytes: &[u8]) {
        let _ = self.inner.borrow().ws.send_with_u8_array(bytes);
    }

    fn dvc_send(&self, channel: u32, data: &[u8]) {
        let frames = match self.inner.borrow().session.as_ref() {
            Some(s) => s.dvc_send(channel, data),
            None => return,
        };
        for f in frames {
            self.send(&f);
        }
    }

    async fn event(&self, ev: Event, h264: &mut Option<H264>) -> Result<(), String> {
        match ev {
            Event::Send(b) => self.send(&b),
            Event::Connected { width, height } => {
                {
                    let mut i = self.inner.borrow_mut();
                    i.connected = true;
                    i.desktop = (width as u32, height as u32);
                }
                (self.status)(Status::Connected);
            }
            Event::DvcOpened { channel_id, name } => {
                if name == rdp_session::DVC_GRAPHICS {
                    let avc = self.inner.borrow().avc;
                    self.inner.borrow_mut().gfx_channel = Some(channel_id);
                    self.dvc_send(channel_id, &rdp_gfx::caps_advertise(avc));
                } else if name == rdp_session::DVC_DISPLAY_CONTROL {
                    self.inner.borrow_mut().display_channel = Some(channel_id);
                }
            }
            Event::DvcData { channel_id, data } => {
                let (gfx, display) = {
                    let i = self.inner.borrow();
                    (i.gfx_channel == Some(channel_id), i.display_channel == Some(channel_id))
                };
                if gfx {
                    let outs = self.inner.borrow_mut().gfx.process(&data).map_err(|e| e.to_string())?;
                    self.gfx_outputs(channel_id, outs, h264).await?;
                } else if display {
                    // DISPLAYCONTROL_CAPS_PDU : le serveur accepte désormais des dispositions d'écran.
                    self.inner.borrow_mut().display_ready = true;
                }
            }
            Event::DvcClosed { channel_id } => {
                let mut i = self.inner.borrow_mut();
                if i.gfx_channel == Some(channel_id) {
                    i.gfx_channel = None;
                }
                if i.display_channel == Some(channel_id) {
                    i.display_channel = None;
                    i.display_ready = false;
                }
            }
            Event::Pointer(p) => self.pointer(p),
            Event::ServerError(t) => (self.status)(Status::Closed { reason: t, retry: false }),
            Event::Disconnected(t) => {
                self.inner.borrow_mut().connected = false;
                (self.status)(Status::Closed { reason: t, retry: false });
            }
            Event::Clipboard(msg) => self.clipboard(&msg).await,
            Event::Deactivated | Event::KeyboardIndicators(_) | Event::Ignored(_) => {}
        }
        Ok(())
    }

    async fn gfx_outputs(&self, channel: u32, outs: Vec<Out>, h264: &mut Option<H264>) -> Result<(), String> {
        let mut queue: std::collections::VecDeque<Out> = outs.into();
        while let Some(o) = queue.pop_front() {
            match o {
                Out::Send(m) => self.dvc_send(channel, &m),
                Out::Reset { width, height, monitors } => self.reset_views(width, height, &monitors),
                Out::Present { damage } => self.present(&damage),
                Out::Avc420 { data } => {
                    if h264.is_none() {
                        *h264 = H264::new().ok();
                    }
                    let decoded = match h264.as_mut() {
                        Some(d) => d.decode(&data).await,
                        None => Err("décodeur H.264 indisponible".into()),
                    };
                    let more = match decoded {
                        Ok(p) => {
                            let frame = rdp_gfx::Yuv420 {
                                width: p.width,
                                height: p.height,
                                y: &p.y,
                                u: &p.u,
                                v: &p.v,
                                y_stride: p.y_stride,
                                uv_stride: p.uv_stride,
                            };
                            self.inner.borrow_mut().gfx.submit_yuv420(&frame)
                        }
                        Err(e) => {
                            web_sys::console::warn_1(&format!("H.264 : {e}").into());
                            self.inner.borrow_mut().gfx.skip_frame()
                        }
                    }
                    .map_err(|e| e.to_string())?;
                    queue.extend(more);
                }
                Out::Avc444 { main, aux } => {
                    if h264.is_none() {
                        *h264 = H264::new().ok();
                    }
                    // Un seul décodeur pour les deux sous-images, dans l'ordre (MS-RDPEGFX 2.2.4.5).
                    let mut decoded = Vec::new();
                    let mut failed = None;
                    for part in [main, aux] {
                        let planes = match (part, h264.as_mut()) {
                            (None, _) => None,
                            (Some(d), Some(dec)) => match dec.decode(&d).await {
                                Ok(p) => Some(p),
                                Err(e) => {
                                    failed = Some(e);
                                    None
                                }
                            },
                            (Some(_), None) => {
                                failed = Some("décodeur H.264 indisponible".into());
                                None
                            }
                        };
                        decoded.push(planes);
                    }
                    let more = match failed {
                        Some(e) => {
                            web_sys::console::warn_1(&format!("H.264 (4:4:4) : {e}").into());
                            self.inner.borrow_mut().gfx.skip_frame()
                        }
                        None => {
                            let (m, a) = (
                                decoded[0].as_ref().map(|p| p.view()),
                                decoded[1].as_ref().map(|p| p.view()),
                            );
                            self.inner.borrow_mut().gfx.submit_avc444(m.as_ref(), a.as_ref())
                        }
                    }
                    .map_err(|e| e.to_string())?;
                    queue.extend(more);
                }
                Out::Ignored(t) => web_sys::console::debug_1(&t.into()),
            }
        }
        Ok(())
    }

    /// Recopie les zones modifiées de la sortie composée vers chaque vue.
    fn present(&self, damage: &[Rect]) {
        let i = self.inner.borrow();
        let (fb, w, _) = i.gfx.output();
        for v in &i.views {
            v.blit(fb, w, damage);
        }
    }

    /// Nouvelle sortie : en multi-écran, chaque vue reçoit le rectangle de son écran si le
    /// serveur a bien adopté la disposition demandée ; sinon on revient à une seule vue.
    fn reset_views(&self, width: u32, height: u32, monitors: &[Rect]) {
        let mut i = self.inner.borrow_mut();
        i.desktop = (width, height);
        let expected = i.multi.clone();
        let adopted = expected.as_ref().is_some_and(|rects| {
            let bw = rects.iter().map(|r| r.x + r.w).max().unwrap_or(0);
            let bh = rects.iter().map(|r| r.y + r.h).max().unwrap_or(0);
            (bw, bh) == (width, height)
                && rects.len() == i.views.len()
                && (monitors.is_empty() || rects.iter().all(|r| monitors.contains(r)))
        });
        if adopted {
            for (v, r) in i.views.iter_mut().zip(expected.unwrap()) {
                v.set_rect(r);
            }
            return;
        }
        if expected.is_some() && monitors.len() < 2 && i.views.len() > 1 {
            web_sys::console::warn_1(&"multi-écran : disposition non adoptée par le serveur".into());
        }
        if i.multi.is_none() || monitors.len() < 2 {
            for v in i.views.iter().skip(1) {
                v.close();
            }
            i.views.truncate(1);
            i.multi = None;
        }
        i.views[0].set_rect(Rect { x: 0, y: 0, w: width, h: height });
    }

    /// Étend la session sur tous les écrans : ouvre une fenêtre par écran secondaire (appel dans
    /// un geste utilisateur) et envoie la disposition au PC.
    pub fn enable_multi(&self, screens: &[ScreenGeom], current: usize) -> Result<usize, String> {
        if screens.len() < 2 {
            return Err("un seul écran détecté".into());
        }
        let (channel, ready) = {
            let i = self.inner.borrow();
            (i.display_channel, i.display_ready)
        };
        let (Some(channel), true) = (channel, ready) else {
            return Err("le PC n'accepte pas encore de changement d'affichage".into());
        };
        self.disable_multi_views();
        let (monitors, rects) = views::layout(screens, current);
        let mut ordered = vec![rects[current]];
        for (idx, screen) in screens.iter().enumerate() {
            if idx == current {
                continue;
            }
            let (win, canvas) = views::open_window(screen, idx)?;
            let mut v = View::new(canvas, rects[idx], Some(win))?;
            let n = self.inner.borrow().views.len();
            self.wire_view(&mut v, n);
            self.inner.borrow_mut().views.push(v);
            ordered.push(rects[idx]);
        }
        self.inner.borrow_mut().multi = Some(ordered);
        self.dvc_send(channel, &views::layout_pdu(&monitors, current));
        Ok(screens.len())
    }

    fn disable_multi_views(&self) {
        let mut i = self.inner.borrow_mut();
        for v in i.views.iter().skip(1) {
            v.close();
        }
        i.views.truncate(1);
        i.multi = None;
    }

    /// Revient à un seul écran (taille de la fenêtre principale).
    pub fn disable_multi(&self, width: u32, height: u32) {
        self.disable_multi_views();
        self.resize(width, height);
    }

    /// Branche les entrées d'une fenêtre secondaire sur le moteur.
    fn wire_view(&self, v: &mut View, idx: usize) {
        use wasm_bindgen::closure::Closure;
        use web_sys::{KeyboardEvent, PointerEvent, WheelEvent};
        let target: &web_sys::EventTarget = v.canvas.as_ref();
        for kind in ["pointermove", "pointerdown", "pointerup"] {
            let e = self.clone();
            let f = Closure::<dyn FnMut(PointerEvent)>::new(move |ev: PointerEvent| {
                e.pointer_input(idx, &ev, kind)
            })
            .into_js_value();
            let _ = target.add_event_listener_with_callback(kind, f.unchecked_ref());
            v.closures.push(f);
        }
        let e = self.clone();
        let f = Closure::<dyn FnMut(WheelEvent)>::new(move |ev: WheelEvent| e.wheel_input(idx, &ev))
            .into_js_value();
        let _ = target.add_event_listener_with_callback("wheel", f.unchecked_ref());
        v.closures.push(f);
        let f = Closure::<dyn FnMut(web_sys::Event)>::new(|ev: web_sys::Event| ev.prevent_default())
            .into_js_value();
        let _ = target.add_event_listener_with_callback("contextmenu", f.unchecked_ref());
        v.closures.push(f);
        if let Some(w) = &v.window {
            for (kind, down) in [("keydown", true), ("keyup", false)] {
                let e = self.clone();
                let f =
                    Closure::<dyn FnMut(KeyboardEvent)>::new(move |ev: KeyboardEvent| e.key_input(&ev, down))
                        .into_js_value();
                let _ = w.add_event_listener_with_callback(kind, f.unchecked_ref());
                v.closures.push(f);
            }
        }
    }

    /// Coordonnées bureau d'un point de la vue `idx` (canevas en `object-fit: contain`).
    fn desktop_point(&self, idx: usize, client_x: f64, client_y: f64) -> Option<(u16, u16)> {
        let i = self.inner.borrow();
        let v = i.views.get(idx)?;
        let r = v.canvas.get_bounding_client_rect();
        let (cw, ch) = (v.canvas.width() as f64, v.canvas.height() as f64);
        let scale = (r.width() / cw).min(r.height() / ch).max(1e-6);
        let (ox, oy) = ((r.width() - cw * scale) / 2.0, (r.height() - ch * scale) / 2.0);
        let x = ((client_x - r.left() - ox) / scale).clamp(0.0, cw - 1.0) as u32 + v.rect.x;
        let y = ((client_y - r.top() - oy) / scale).clamp(0.0, ch - 1.0) as u32 + v.rect.y;
        Some((x.min(u16::MAX as u32) as u16, y.min(u16::MAX as u32) as u16))
    }

    /// Événement pointeur (souris, stylet, tactile) d'une vue.
    pub fn pointer_input(&self, idx: usize, e: &web_sys::PointerEvent, kind: &str) {
        use rdp_pdu::fastpath::ptr;
        if !self.is_connected() {
            return;
        }
        e.prevent_default();
        if kind == "pointerdown" {
            self.user_gesture();
        }
        let Some((x, y)) = self.desktop_point(idx, e.client_x() as f64, e.client_y() as f64) else { return };
        let event = match kind {
            "pointermove" => Input::Mouse { flags: ptr::MOVE, x, y },
            _ => {
                let (flag, extended) = match e.button() {
                    0 => (ptr::BUTTON1, false),
                    1 => (ptr::BUTTON3, false),
                    2 => (ptr::BUTTON2, false),
                    3 => (ptr::X_BUTTON1, true),
                    4 => (ptr::X_BUTTON2, true),
                    _ => return,
                };
                let down = kind == "pointerdown";
                if down && let Some(v) = self.inner.borrow().views.get(idx) {
                    let _ = v.canvas.set_pointer_capture(e.pointer_id());
                }
                match (extended, down) {
                    (false, true) => Input::Mouse { flags: flag | ptr::DOWN, x, y },
                    (false, false) => Input::Mouse { flags: flag, x, y },
                    (true, true) => Input::MouseX { flags: flag | ptr::X_DOWN, x, y },
                    (true, false) => Input::MouseX { flags: flag, x, y },
                }
            }
        };
        self.input(&[event]);
    }

    /// Molette : pixels → crans de 120 (une molette classique envoie ~100 px par cran).
    pub fn wheel_input(&self, idx: usize, e: &web_sys::WheelEvent) {
        if !self.is_connected() {
            return;
        }
        e.prevent_default();
        let Some((x, y)) = self.desktop_point(idx, e.client_x() as f64, e.client_y() as f64) else { return };
        let unit = match e.delta_mode() {
            0 => 1.2,
            1 => 40.0,
            _ => 120.0,
        };
        let (dx, dy) = (e.delta_x() * unit, e.delta_y() * unit);
        if dy.abs() >= 1.0 {
            self.input(&[Input::wheel((-dy).clamp(-255.0, 255.0) as i16, false, x, y)]);
        }
        if dx.abs() >= 1.0 {
            self.input(&[Input::wheel(dx.clamp(-255.0, 255.0) as i16, true, x, y)]);
        }
    }

    /// Clavier : positions physiques → scancodes ; à défaut (clavier virtuel), caractère Unicode.
    pub fn key_input(&self, e: &web_sys::KeyboardEvent, down: bool) {
        if !self.is_connected() {
            return;
        }
        self.user_gesture();
        // Ctrl+V / Cmd+V : le presse-papier local part vers le PC avant la touche V.
        if down && (e.ctrl_key() || e.meta_key()) && e.code() == "KeyV" {
            self.paste_guard();
        }
        if let Some((code, ext)) = super::keys::scancode(&e.code()) {
            e.prevent_default();
            self.key(code, ext, down);
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
                self.input(&events);
            }
        }
    }

    fn pointer(&self, p: PointerUpdate) {
        let mut i = self.inner.borrow_mut();
        let css = match p {
            PointerUpdate::Hidden => "none".to_owned(),
            PointerUpdate::Default => "default".to_owned(),
            PointerUpdate::Position { .. } => return,
            PointerUpdate::New { cache_index, pointer } => {
                let css = cursor_css(&pointer).unwrap_or_else(|| "default".into());
                let idx = cache_index as usize;
                if idx < i.cursors.len() {
                    i.cursors[idx] = Some(css.clone());
                }
                css
            }
            PointerUpdate::Cached { cache_index } => {
                i.cursors.get(cache_index as usize).cloned().flatten().unwrap_or_else(|| "default".into())
            }
        };
        for v in &i.views {
            v.set_cursor(&css);
        }
    }

    // --- Entrées ---

    // --- Presse-papier ---

    fn clip_send(&self, events: Vec<rdp_clip::ClipEvent>) -> Vec<rdp_clip::ClipEvent> {
        let mut rest = Vec::new();
        for ev in events {
            match ev {
                rdp_clip::ClipEvent::Send(m) => {
                    let frames = match self.inner.borrow().session.as_ref() {
                        Some(s) => s.static_send(rdp_session::CLIPRDR, &m),
                        None => Vec::new(),
                    };
                    for f in frames {
                        self.send(&f);
                    }
                }
                other => rest.push(other),
            }
        }
        rest
    }

    async fn clipboard(&self, msg: &[u8]) {
        let events = match self.inner.borrow_mut().clip.receive(msg) {
            Ok(e) => e,
            Err(e) => {
                web_sys::console::warn_1(&format!("presse-papier : {e:?}").into());
                return;
            }
        };
        let kind = u16::from_le_bytes([msg.first().copied().unwrap_or(0), msg.get(1).copied().unwrap_or(0)]);
        if kind == 3
            && let Some(tx) = self.inner.borrow_mut().clip_ack.take()
        {
            let _ = tx.send(());
        }
        web_sys::console::debug_1(
            &format!("cliprdr ← type {kind} ({} o) → {} événement(s)", msg.len(), events.len()).into(),
        );
        let mut queue = self.clip_send(events);
        while let Some(ev) = queue.pop() {
            web_sys::console::debug_1(
                &format!(
                    "cliprdr : {}",
                    match &ev {
                        rdp_clip::ClipEvent::RemoteChanged(f) => format!("le PC propose {f:?}"),
                        rdp_clip::ClipEvent::RemoteData(d) => format!("données reçues : {}", d.is_some()),
                        rdp_clip::ClipEvent::Send(_) => "envoi".into(),
                    }
                )
                .into(),
            );
            match ev {
                rdp_clip::ClipEvent::RemoteChanged(formats) => {
                    let mut i = self.inner.borrow_mut();
                    i.clip_wanted = clip::wanted(&formats);
                    i.clip_wanted.reverse();
                    i.clip_received.clear();
                    let next = i.clip_wanted.pop();
                    let ev = next.map(|f| i.clip.request(&[f])).unwrap_or_default();
                    drop(i);
                    queue.extend(self.clip_send(ev));
                }
                rdp_clip::ClipEvent::RemoteData(data) => {
                    let next = {
                        let mut i = self.inner.borrow_mut();
                        if let Some(d) = data {
                            i.clip_received.push(d);
                        }
                        match i.clip_wanted.pop() {
                            Some(f) => Some(i.clip.request(&[f])),
                            None => None,
                        }
                    };
                    match next {
                        Some(ev) => queue.extend(self.clip_send(ev)),
                        None => {
                            let items = std::mem::take(&mut self.inner.borrow_mut().clip_received);
                            if items.is_empty() {
                                continue;
                            }
                            self.inner.borrow_mut().clip_last = Some(clip::fingerprint(&items));
                            if let Err(e) = clip::write_local(&items).await {
                                web_sys::console::debug_1(
                                    &format!("presse-papier local : {e} (nouvel essai au prochain geste)")
                                        .into(),
                                );
                                self.inner.borrow_mut().clip_pending_write = Some(items);
                            }
                        }
                    }
                }
                rdp_clip::ClipEvent::Send(_) => {}
            }
        }
    }

    /// Envoie au PC le contenu du presse-papier local s'il a changé.
    pub async fn sync_local_clipboard(&self) {
        if !self.is_connected() {
            return;
        }
        let t0 = js_sys::Date::now();
        let items = clip::read_local().await;
        web_sys::console::debug_1(
            &format!("presse-papier local lu en {:.0} ms", js_sys::Date::now() - t0).into(),
        );
        let Some(items) = items else { return };
        if items.is_empty() {
            return;
        }
        let fp = clip::fingerprint(&items);
        let (tx, rx) = futures::channel::oneshot::channel();
        let events = {
            let mut i = self.inner.borrow_mut();
            if i.clip_last == Some(fp) {
                return;
            }
            i.clip_last = Some(fp);
            i.clip_ack = Some(tx);
            i.clip.set_local(items)
        };
        self.clip_send(events);
        // Attend que Windows ait installé notre contenu (borné par l'appelant).
        let _ = rx.await;
    }

    /// Geste utilisateur : occasion de réussir une écriture locale refusée plus tôt.
    pub fn user_gesture(&self) {
        let pending = self.inner.borrow_mut().clip_pending_write.take();
        if let Some(items) = pending {
            let e = self.clone();
            wasm_bindgen_futures::spawn_local(async move {
                if clip::write_local(&items).await.is_err() {
                    e.inner.borrow_mut().clip_pending_write = Some(items);
                }
            });
        }
    }

    /// Ctrl+V : synchronise d'abord le presse-papier (2 s au plus), puis laisse passer les touches retenues.
    pub fn paste_guard(&self) {
        if self.inner.borrow().holding {
            return;
        }
        self.inner.borrow_mut().holding = true;
        let e = self.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let sync = e.sync_local_clipboard();
            let timeout = async {
                let p = js_sys::Promise::new(&mut |resolve, _| {
                    let _ = web_sys::window()
                        .unwrap()
                        .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 2000);
                });
                let _ = wasm_bindgen_futures::JsFuture::from(p).await;
            };
            futures::pin_mut!(sync, timeout);
            futures::future::select(sync, timeout).await;
            let held = {
                let mut i = e.inner.borrow_mut();
                i.holding = false;
                std::mem::take(&mut i.held)
            };
            e.input(&held);
        });
    }

    pub fn input(&self, events: &[Input]) {
        {
            let mut i = self.inner.borrow_mut();
            if i.holding {
                i.held.extend_from_slice(events);
                return;
            }
        }
        let frame = match self.inner.borrow().session.as_ref() {
            Some(s) => s.input(events),
            None => return,
        };
        if !frame.is_empty() {
            self.send(&frame);
        }
    }

    pub fn key(&self, scancode: u8, extended: bool, down: bool) {
        {
            let mut i = self.inner.borrow_mut();
            if down {
                i.pressed.insert((scancode, extended));
            } else {
                i.pressed.remove(&(scancode, extended));
            }
        }
        let mut flags = if extended { rdp_pdu::fastpath::kbd::EXTENDED } else { 0 };
        if !down {
            flags |= rdp_pdu::fastpath::kbd::RELEASE;
        }
        self.input(&[Input::Scancode { code: scancode, flags }]);
    }

    /// Relâche tout (perte de focus) : évite les touches « collées » côté Windows.
    pub fn release_all(&self) {
        let keys: Vec<(u8, bool)> = self.inner.borrow_mut().pressed.drain().collect();
        let events: Vec<Input> = keys
            .into_iter()
            .map(|(code, ext)| Input::Scancode {
                code,
                flags: rdp_pdu::fastpath::kbd::RELEASE
                    | if ext { rdp_pdu::fastpath::kbd::EXTENDED } else { 0 },
            })
            .collect();
        self.input(&events);
    }

    pub fn ctrl_alt_del(&self) {
        use rdp_pdu::fastpath::kbd::{EXTENDED, RELEASE};
        self.input(&[
            Input::Scancode { code: 0x1D, flags: 0 },
            Input::Scancode { code: 0x38, flags: 0 },
            Input::Scancode { code: 0x53, flags: EXTENDED },
            Input::Scancode { code: 0x53, flags: EXTENDED | RELEASE },
            Input::Scancode { code: 0x38, flags: RELEASE },
            Input::Scancode { code: 0x1D, flags: RELEASE },
        ]);
    }

    /// Demande au serveur une nouvelle taille de bureau (contrôle d'affichage).
    pub fn resize(&self, width: u32, height: u32) {
        let (w, h) = clamp_size(width, height);
        let (channel, ready, current, multi) = {
            let i = self.inner.borrow();
            (i.display_channel, i.display_ready, i.desktop, i.multi.is_some())
        };
        // En multi-écran, la disposition vient des écrans, pas de la taille de la fenêtre.
        if multi {
            return;
        }
        let (Some(channel), true) = (channel, ready) else { return };
        if (w, h) == current {
            return;
        }
        // DISPLAYCONTROL_MONITOR_LAYOUT_PDU (MS-RDPEDISP 2.2.2.2), un écran principal.
        let mut p = Vec::with_capacity(56);
        p.extend_from_slice(&2u32.to_le_bytes());
        p.extend_from_slice(&56u32.to_le_bytes());
        p.extend_from_slice(&40u32.to_le_bytes());
        p.extend_from_slice(&1u32.to_le_bytes());
        for v in [1u32, 0, 0, w, h, 0, 0, 0, 100, 100] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        self.dvc_send(channel, &p);
    }
}

/// Curseur RGBA → valeur CSS `url(data:…) x y, auto` (canevas temporaire).
fn cursor_css(p: &rdp_pdu::fastpath::Pointer) -> Option<String> {
    if p.width == 0 || p.height == 0 || p.width > 128 || p.height > 128 {
        return None;
    }
    let doc = web_sys::window()?.document()?;
    let c: HtmlCanvasElement = doc.create_element("canvas").ok()?.unchecked_into();
    c.set_width(p.width as u32);
    c.set_height(p.height as u32);
    let ctx: CanvasRenderingContext2d = c.get_context("2d").ok()??.unchecked_into();
    let img = ImageData::new_with_u8_clamped_array_and_sh(Clamped(&p.rgba), p.width as u32, p.height as u32)
        .ok()?;
    ctx.put_image_data(&img, 0, 0).ok()?;
    let url = c.to_data_url().ok()?;
    Some(format!("url(\"{url}\") {} {}, auto", p.hot_x, p.hot_y))
}
