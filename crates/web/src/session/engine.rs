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

use super::{clip, h264::H264};

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
    canvas: HtmlCanvasElement,
    ctx: CanvasRenderingContext2d,
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
        let ctx: CanvasRenderingContext2d =
            canvas.get_context("2d").ok().flatten().ok_or("canevas 2D indisponible")?.unchecked_into();
        let (w, h) = clamp_size(opts.width, opts.height);
        canvas.set_width(w);
        canvas.set_height(h);
        let inner = Rc::new(RefCell::new(Inner {
            ws: ws.clone(),
            canvas,
            ctx,
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
                Out::Reset { width, height } => {
                    let mut i = self.inner.borrow_mut();
                    i.canvas.set_width(width);
                    i.canvas.set_height(height);
                    i.desktop = (width, height);
                }
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
                Out::Ignored(t) => web_sys::console::debug_1(&t.into()),
            }
        }
        Ok(())
    }

    /// Recopie les zones modifiées de la sortie composée vers le canevas.
    fn present(&self, damage: &[Rect]) {
        let i = self.inner.borrow();
        let (fb, w, _) = i.gfx.output();
        for r in damage {
            let mut tmp = Vec::with_capacity((r.w * r.h * 4) as usize);
            for row in r.y..r.y + r.h {
                let o = ((row * w + r.x) * 4) as usize;
                tmp.extend_from_slice(&fb[o..o + (r.w * 4) as usize]);
            }
            if let Ok(img) = ImageData::new_with_u8_clamped_array_and_sh(Clamped(&tmp), r.w, r.h) {
                let _ = i.ctx.put_image_data(&img, r.x as i32, r.y as i32);
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
        let _ = i.canvas.style().set_property("cursor", &css);
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
        let (channel, ready, current) = {
            let i = self.inner.borrow();
            (i.display_channel, i.display_ready, i.desktop)
        };
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
