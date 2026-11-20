//! Moteur de session dans le navigateur : WebSocket ↔ `rdp-session`, EGFX ↔ canevas.
//!
//! Tout passe par une seule boucle asynchrone (`pump`) qui traite les messages dans l'ordre et
//! attend le décodage des images H.264 : l'ordre des commandes graphiques et les accusés
//! d'image restent exacts. Les entrées (clavier, souris) partent directement sur le WebSocket.

use std::{cell::RefCell, collections::HashSet, rc::Rc};

use futures::{StreamExt, channel::mpsc};
use portique_proto::SessionMessage;
use rdp_gfx::{Gfx, Out, Rect};
use rdp_pdu::fastpath::{Input, PointerUpdate};
use rdp_session::{Config, Event, Session};
use wasm_bindgen::{Clamped, JsCast, closure::Closure};
use web_sys::{
    BinaryType, CanvasRenderingContext2d, CloseEvent, HtmlCanvasElement, ImageData, MessageEvent, WebSocket,
};

use super::{
    clip,
    h264::{self, DecodeError, Decoded, H264},
    touch::{self, Touch},
    views::{self, DisplayCaps, ScreenGeom, View},
};

/// Suite à donner à une coupure.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Retry {
    /// Coupure en cours de session : la reconnexion automatique démarre.
    Yes,
    /// Échec peut-être passager (PC qui redémarre, réseau) : une série de reconnexions déjà
    /// lancée continue, mais aucune ne démarre.
    Transient,
    /// Refus ou fin voulue par le PC : on s'arrête.
    No,
}

/// État visible par l'interface.
#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    Connecting(String),
    Connected,
    Closed { reason: String, retry: Retry },
    UntrustedCertificate { fingerprint: String, can_approve: bool },
}

enum Incoming {
    Text(String),
    Binary(Vec<u8>),
    Closed(String),
}

/// Repères d'ouverture (ms, `Date.now()`), résumés en console à la première image.
#[derive(Default)]
struct Marks {
    /// Vérification du décodeur H.264 avant l'ouverture.
    support_ms: f64,
    opened: f64,
    ready: Option<f64>,
    connected: Option<f64>,
    first_frame: bool,
    /// Images H.264 traitées (décodage, copie, conversion, composition) et leurs durées (ms).
    h264_frames: u32,
    h264_total_ms: f64,
    h264_max_ms: f64,
}

struct Inner {
    marks: Marks,
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
    /// Limites du contrôle d'affichage, une fois sa CAPS PDU reçue (canal prêt).
    display_caps: Option<DisplayCaps>,
    /// Fenêtres secondaires ouvertes pendant une extension pas encore terminée (une par geste).
    staged: Vec<View>,
    /// Écrans (et écran courant) sur lesquels porte l'extension en cours.
    staged_screens: Option<(Vec<ScreenGeom>, usize)>,
    touch: Touch,
    /// Taille voulue (fenêtre) : appliquée dès que le contrôle d'affichage devient prêt.
    desired: Option<(u32, u32)>,
    desktop: (u32, u32),
    cursors: Vec<Option<String>>,
    pressed: HashSet<(u8, bool)>,
    connected: bool,
    closing: bool,
    /// Fermeture volontaire suivie d'une réouverture (H.264 inexploitable par ce navigateur).
    restart: bool,
    avc: h264::Avc,
    clip: rdp_clip::Clipboard,
    clip_fetch: clip::Fetch,
    /// Génération du contenu à écrire localement : une écriture ou un réessai d'une génération
    /// dépassée (nouvelle copie d'un côté ou de l'autre) n'écrit rien.
    clip_write_gen: u32,
    /// Écriture locale refusée (page sans focus) : retentée au prochain geste.
    clip_pending_write: Option<(u32, Vec<rdp_clip::LocalData>)>,
    /// Empreinte du dernier contenu commun aux deux côtés (évite l'écho PC → navigateur → PC) :
    /// reçu du PC, ou annoncé par nous ET accepté par Windows. Gardée quand Windows copie un
    /// contenu sans format pris en charge (fichiers…) : le contenu local, plus ancien que cette
    /// copie, ne doit pas l'écraser au prochain Ctrl+V.
    clip_last: Option<u64>,
    /// Nos listes de formats sans réponse et leurs attentes : Windows n'accuse une liste qu'une
    /// fois notre contenu installé, c'est le moment de relâcher un Ctrl+V. Vidées à la fermeture.
    clip_announces: clip::Announces,
    /// Ctrl+V en cours : les entrées attendent la synchronisation du presse-papier.
    holding: bool,
    held: Vec<Input>,
}

impl Inner {
    /// Session finie : plus d'accusé à attendre, ni d'écriture locale (conversion en cours,
    /// réessai, repli) — un autre moteur a pu prendre la relève.
    fn end_clipboard(&mut self) {
        self.clip_announces.clear();
        self.clip_write_gen = self.clip_write_gen.wrapping_add(1);
        self.clip_pending_write = None;
    }
}

/// Poignée partagée sur une session en cours.
#[derive(Clone)]
pub struct Engine {
    inner: Rc<RefCell<Inner>>,
    status: Rc<dyn Fn(Status)>,
    /// Le moteur est revenu de lui-même à un seul écran (disposition non adoptée par le PC).
    on_single: Rc<dyn Fn()>,
}

/// Étape d'une extension multi-écran.
pub enum Extend {
    /// Toutes les fenêtres sont ouvertes et la disposition envoyée (nombre d'écrans).
    Done(usize),
    /// Une fenêtre de plus est ouverte ; la suivante attend un nouveau geste.
    Next { opened: usize, total: usize },
}

/// Durée de validité d'une annonce de presse-papier sans réponse (ms) : au-delà, on réannonce.
const ANNOUNCE_TTL_MS: f64 = 2000.0;
/// Classe du champ caché qui reçoit le clavier virtuel (voir `SessionPage`).
pub const KEYBOARD_CLASS: &str = "session-kbd";

/// Paramètres d'ouverture.
pub struct Open {
    pub connection_id: i64,
    pub width: u32,
    pub height: u32,
    /// Empreinte approuvée par l'admin pour un premier contact.
    pub trust: Option<String>,
    pub avc: h264::Avc,
    /// Durée de la vérification du décodeur, pour le résumé d'ouverture.
    pub support_ms: f64,
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
    pub fn open(
        canvas: HtmlCanvasElement,
        opts: Open,
        status: Rc<dyn Fn(Status)>,
        on_single: Rc<dyn Fn()>,
    ) -> Result<Self, String> {
        let ws = WebSocket::new(&ws_url(opts.connection_id, opts.trust.as_deref()))
            .map_err(|e| format!("{e:?}"))?;
        ws.set_binary_type(BinaryType::Arraybuffer);
        let (w, h) = clamp_size(opts.width, opts.height);
        // Le canevas sert d'une session à l'autre : le zoom tactile repart de 1:1.
        apply_zoom(&canvas, touch::Zoom::default());
        let main_view = View::new(canvas, Rect { x: 0, y: 0, w, h }, None)?;
        let inner = Rc::new(RefCell::new(Inner {
            marks: Marks { support_ms: opts.support_ms, opened: js_sys::Date::now(), ..Default::default() },
            ws: ws.clone(),
            views: vec![main_view],
            multi: None,
            session: None,
            gfx: Gfx::new(),
            buf: Vec::new(),
            gfx_channel: None,
            display_channel: None,
            display_caps: None,
            staged: Vec::new(),
            staged_screens: None,
            touch: Touch::default(),
            desired: None,
            desktop: (w, h),
            cursors: vec![None; 32],
            pressed: HashSet::new(),
            connected: false,
            closing: false,
            restart: false,
            avc: opts.avc,
            clip: rdp_clip::Clipboard::new(),
            clip_fetch: clip::Fetch::default(),
            clip_write_gen: 0,
            clip_pending_write: None,
            clip_last: None,
            clip_announces: clip::Announces::default(),
            holding: false,
            held: Vec::new(),
        }));
        let engine = Engine { inner, status, on_single };
        (engine.status)(Status::Connecting("Connexion au PC…".into()));

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
        // Une synchronisation qui attend l'accusé ne le recevra plus : elle libère le moteur.
        i.end_clipboard();
        for v in i.views.iter().skip(1).chain(&i.staged) {
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
                        let retry = if connected { Retry::Yes } else { Retry::Transient };
                        (self.status)(Status::Closed { reason, retry });
                    }
                    break;
                }
            };
            if let Err(e) = result {
                let retry = if self.inner.borrow().restart { Retry::Yes } else { Retry::Transient };
                (self.status)(Status::Closed { reason: e, retry });
                self.inner.borrow_mut().closing = true;
                let _ = self.inner.borrow().ws.close();
                break;
            }
        }
        let mut i = self.inner.borrow_mut();
        i.connected = false;
        i.end_clipboard();
    }

    fn control(&self, text: &str) -> Result<(), String> {
        match serde_json::from_str::<SessionMessage>(text).map_err(|e| e.to_string())? {
            SessionMessage::Ready { selected_protocol, username, domain, .. } => {
                let mut i = self.inner.borrow_mut();
                i.marks.ready = Some(js_sys::Date::now());
                let (w, h) = i.desktop;
                let session = Session::new(Config {
                    width: w as u16,
                    height: h as u16,
                    keyboard_layout: 0x040C,
                    client_name: "portique".into(),
                    selected_protocol,
                    username,
                    domain,
                    display_control: true,
                });
                let first = session.start();
                i.ws.send_with_u8_array(&first).map_err(|e| format!("{e:?}"))?;
                i.session = Some(session);
                drop(i);
                (self.status)(Status::Connecting("Ouverture de la session Windows…".into()));
            }
            SessionMessage::Error { message } => {
                // Refus du serveur ou PC injoignable (redémarrage) : rien ne les distingue ici.
                self.inner.borrow_mut().closing = true;
                (self.status)(Status::Closed { reason: message, retry: Retry::Transient });
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
                    i.marks.connected = Some(js_sys::Date::now());
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
                } else if display && let Some(caps) = DisplayCaps::parse(&data) {
                    // DISPLAYCONTROL_CAPS_PDU : le serveur accepte désormais des dispositions d'écran,
                    // dans ces limites. Windows n'ouvre ce canal que quelques secondes après la
                    // connexion : on applique alors la taille demandée entre-temps.
                    let desired = {
                        let mut i = self.inner.borrow_mut();
                        i.display_caps = Some(caps);
                        i.desired
                    };
                    if let Some((w, h)) = desired {
                        self.resize(w, h);
                    }
                }
            }
            Event::DvcClosed { channel_id } => {
                let mut i = self.inner.borrow_mut();
                if i.gfx_channel == Some(channel_id) {
                    i.gfx_channel = None;
                }
                if i.display_channel == Some(channel_id) {
                    i.display_channel = None;
                    i.display_caps = None;
                }
            }
            Event::Pointer(p) => self.pointer(p),
            Event::ServerError(t) => (self.status)(Status::Closed { reason: t, retry: Retry::No }),
            Event::Disconnected(t) => {
                self.inner.borrow_mut().connected = false;
                (self.status)(Status::Closed { reason: t, retry: Retry::No });
            }
            Event::Clipboard(msg) => self.clipboard(&msg),
            Event::Deactivated | Event::KeyboardIndicators(_) | Event::Ignored(_) => {}
        }
        Ok(())
    }

    /// Décodeur H.264 en échec : on le désactive pour ce navigateur et on rouvre la session.
    fn h264_disable(&self, reason: &str) -> Result<(), String> {
        h264::disable(reason);
        self.inner.borrow_mut().restart = true;
        Err("le décodeur H.264 de ce navigateur a échoué : reconnexion sans H.264…".into())
    }

    async fn gfx_outputs(&self, channel: u32, outs: Vec<Out>, h264: &mut Option<H264>) -> Result<(), String> {
        let mut queue: std::collections::VecDeque<Out> = drop_stale_presents(outs).into();
        while let Some(o) = queue.pop_front() {
            match o {
                Out::Send(m) => self.dvc_send(channel, &m),
                Out::Reset { width, height, monitors } => self.reset_views(width, height, &monitors),
                Out::Present { damage } => self.present(&damage),
                Out::Avc420 { data } => {
                    let t0 = js_sys::Date::now();
                    if h264.is_none() {
                        *h264 = H264::new().ok();
                    }
                    let decoded = match h264.as_mut() {
                        Some(d) => d.decode(&data).await,
                        None => Err(DecodeError::Unusable("décodeur H.264 indisponible".into())),
                    };
                    let more = match decoded {
                        Ok(Decoded::Yuv(p)) => self.inner.borrow_mut().gfx.submit_yuv420(&p.view()),
                        Ok(Decoded::Rgba { width, height, data }) => self
                            .inner
                            .borrow_mut()
                            .gfx
                            .submit_rgba(&rdp_gfx::Rgba { width, height, data: &data, stride: width * 4 }),
                        Err(DecodeError::Unusable(e)) => return self.h264_disable(&e),
                        Err(e) => {
                            web_sys::console::warn_1(&format!("H.264 : {e}").into());
                            self.inner.borrow_mut().gfx.skip_frame()
                        }
                    }
                    .map_err(|e| e.to_string())?;
                    self.count_h264(t0);
                    queue.extend(drop_stale_presents(more));
                }
                Out::Avc444 { main, aux } => {
                    let t0 = js_sys::Date::now();
                    if h264.is_none() {
                        *h264 = H264::new().ok();
                    }
                    // Un seul décodeur pour les deux sous-images, dans l'ordre (MS-RDPEGFX 2.2.4.5).
                    let mut decoded = Vec::new();
                    let mut failed = None;
                    for part in [main, aux] {
                        let frame = match (part, h264.as_mut()) {
                            (None, _) => None,
                            (Some(d), Some(dec)) => match dec.decode(&d).await {
                                Ok(f) => Some(f),
                                Err(DecodeError::Unusable(e)) => return self.h264_disable(&e),
                                Err(e) => {
                                    failed = Some(e);
                                    None
                                }
                            },
                            (Some(_), None) => return self.h264_disable("décodeur H.264 indisponible"),
                        };
                        decoded.push(frame);
                    }
                    let mut gfx = std::cell::RefMut::map(self.inner.borrow_mut(), |i| &mut i.gfx);
                    let more = match (failed, &decoded[0], &decoded[1]) {
                        (Some(e), ..) => {
                            web_sys::console::warn_1(&format!("H.264 (4:4:4) : {e}").into());
                            gfx.skip_frame()
                        }
                        // Navigateur qui ne rend que du RGB : la sous-image principale est une image
                        // 4:2:0 complète ; l'auxiliaire (chroma) a seulement nourri le décodeur.
                        (None, Some(Decoded::Rgba { width, height, data }), _) => {
                            gfx.submit_rgba(&rdp_gfx::Rgba {
                                width: *width,
                                height: *height,
                                data,
                                stride: width * 4,
                            })
                        }
                        (None, None, Some(Decoded::Rgba { .. })) => gfx.skip_frame(),
                        (None, m, a) => {
                            fn yuv(f: &Option<Decoded>) -> Option<rdp_gfx::Yuv420<'_>> {
                                match f {
                                    Some(Decoded::Yuv(p)) => Some(p.view()),
                                    _ => None,
                                }
                            }
                            gfx.submit_avc444(yuv(m).as_ref(), yuv(a).as_ref())
                        }
                    }
                    .map_err(|e| e.to_string())?;
                    drop(gfx);
                    self.count_h264(t0);
                    queue.extend(drop_stale_presents(more));
                }
                Out::Ignored(t) => web_sys::console::debug_1(&t.into()),
            }
        }
        Ok(())
    }

    /// Recopie les zones modifiées de la sortie composée vers chaque vue.
    /// Coût par image H.264, résumé en console toutes les 100 images.
    fn count_h264(&self, t0: f64) {
        let dt = js_sys::Date::now() - t0;
        let mut i = self.inner.borrow_mut();
        let m = &mut i.marks;
        m.h264_frames += 1;
        m.h264_total_ms += dt;
        m.h264_max_ms = m.h264_max_ms.max(dt);
        if m.h264_frames.is_multiple_of(100) {
            web_sys::console::info_1(
                &format!(
                    "Portique : H.264 {} images, {:.1} ms par image en moyenne, {:.0} ms au pire",
                    m.h264_frames,
                    m.h264_total_ms / f64::from(m.h264_frames),
                    m.h264_max_ms
                )
                .into(),
            );
        }
    }

    /// Où passe le temps d'ouverture : décodeur, serveur (TCP + TLS + NLA), session Windows, image.
    fn log_opening(&self) {
        let i = self.inner.borrow();
        let m = &i.marks;
        let since =
            |t: Option<f64>| t.map(|t| format!("{:.0} ms", t - m.opened)).unwrap_or_else(|| "?".into());
        web_sys::console::info_1(
            &format!(
                "Portique : décodeur vérifié en {:.0} ms ; serveur prêt à {} ; session Windows à {} ; première image à {:.0} ms ({:?})",
                m.support_ms,
                since(m.ready),
                since(m.connected),
                js_sys::Date::now() - m.opened,
                i.avc
            )
            .into(),
        );
    }

    fn present(&self, damage: &[Rect]) {
        let i = self.inner.borrow();
        if !i.marks.first_frame {
            drop(i);
            self.log_opening();
            self.inner.borrow_mut().marks.first_frame = true;
        }
        let i = self.inner.borrow();
        let (fb, w, h) = i.gfx.output();
        for v in &i.views {
            v.blit(fb, w, h, damage);
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
        let mut fell_back = false;
        if i.multi.is_none() || monitors.len() < 2 {
            for v in i.views.iter().skip(1) {
                v.close();
            }
            i.views.truncate(1);
            fell_back = i.multi.take().is_some();
        }
        i.views[0].set_rect(Rect { x: 0, y: 0, w: width, h: height });
        drop(i);
        if fell_back {
            (self.on_single)();
        }
    }

    /// Étend la session sur tous les écrans, une fenêtre secondaire par appel (chaque appel dans
    /// son propre geste utilisateur : un clic suffit avec deux écrans). Les fenêtres attendent dans
    /// `staged` ; la disposition part quand toutes sont ouvertes. Un échec les ferme toutes.
    /// `screens` : écrans relus juste avant l'appel (ils doivent rester ceux de la première étape).
    pub fn enable_multi(&self, screens: &[ScreenGeom], current: usize) -> Result<Extend, String> {
        let result = self.extend_step(screens, current);
        if result.is_err() {
            self.close_staged();
        }
        result
    }

    fn extend_step(&self, screens: &[ScreenGeom], current: usize) -> Result<Extend, String> {
        if screens.len() < 2 || current >= screens.len() {
            return Err("un seul écran détecté".into());
        }
        let (channel, caps) = {
            let i = self.inner.borrow();
            (i.display_channel, i.display_caps)
        };
        let (Some(channel), Some(caps)) = (channel, caps) else {
            return Err("le PC n'accepte pas encore de changement d'affichage".into());
        };
        let (monitors, rects) = views::layout(screens, current);
        caps.check(&monitors)?;
        let secondary: Vec<usize> = (0..screens.len()).filter(|&i| i != current).collect();
        let (k, closed, changed) = {
            let i = self.inner.borrow();
            let closed =
                i.staged.iter().any(|v| v.window.as_ref().is_some_and(|w| w.closed().unwrap_or(true)));
            // `screens` est relu à chaque geste : un écran branché, débranché ou redéfini depuis la
            // première fenêtre rendrait fausses la géométrie des suivantes et la disposition.
            let changed =
                i.staged_screens.as_ref().is_some_and(|(l, c)| (l.as_slice(), *c) != (screens, current));
            (i.staged.len(), closed, changed)
        };
        // Une fenêtre déjà préparée a été fermée : la disposition annoncerait un écran invisible.
        if closed {
            return Err("fenêtre d'écran fermée pendant l'extension : recommencer".into());
        }
        if changed {
            return Err("écrans changés pendant l'extension : recommencer".into());
        }
        if k == 0 {
            self.disable_multi_views();
            self.inner.borrow_mut().staged_screens = Some((screens.to_vec(), current));
        }
        let Some(&idx) = secondary.get(k) else {
            return Err("écrans changés pendant l'extension : recommencer".into());
        };
        let (win, canvas) = views::open_window(&screens[idx], idx)?;
        let mut v = View::new(canvas, rects[idx], Some(win.clone())).inspect_err(|_| {
            let _ = win.close();
        })?;
        // Index définitif de la vue une fois installée (la vue 0 est la fenêtre principale).
        self.wire_view(&mut v, 1 + k);
        let mut i = self.inner.borrow_mut();
        i.staged.push(v);
        if i.staged.len() < secondary.len() {
            return Ok(Extend::Next { opened: 1 + i.staged.len(), total: screens.len() });
        }
        let staged = std::mem::take(&mut i.staged);
        i.staged_screens = None;
        i.views.extend(staged);
        i.multi = Some(std::iter::once(current).chain(secondary).map(|idx| rects[idx]).collect());
        drop(i);
        self.dvc_send(channel, &views::layout_pdu(&monitors, current));
        Ok(Extend::Done(screens.len()))
    }

    fn close_staged(&self) {
        let staged = {
            let mut i = self.inner.borrow_mut();
            i.staged_screens = None;
            std::mem::take(&mut i.staged)
        };
        for v in staged {
            v.close();
        }
    }

    fn disable_multi_views(&self) {
        self.close_staged();
        let mut i = self.inner.borrow_mut();
        for v in i.views.iter().skip(1) {
            v.close();
        }
        i.views.truncate(1);
        i.multi = None;
    }

    /// Revient à un seul écran (taille de la fenêtre principale). La disposition à un écran part
    /// même si la taille n'a pas changé : le PC a encore les écrans de l'extension.
    pub fn disable_multi(&self, width: u32, height: u32) {
        self.disable_multi_views();
        self.send_size(width, height, true);
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
                let f = Closure::<dyn FnMut(KeyboardEvent)>::new(move |ev: KeyboardEvent| {
                    e.key_input(&ev, down, false)
                })
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
            self.focus_view(idx);
        }
        // Doigt sur la fenêtre principale : gestes (toucher, appui long, glisser, molette, zoom).
        if idx == 0 && e.pointer_type() == "touch" {
            return self.touch_input(e, kind);
        }
        if kind == "pointercancel" {
            return;
        }
        let Some((x, y)) = self.desktop_point(idx, e.client_x(), e.client_y()) else {
            return;
        };
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
        let Some((x, y)) = self.desktop_point(idx, e.client_x(), e.client_y()) else {
            return;
        };
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

    /// Le clavier suit le bureau cliqué ou touché (le défaut du pointeur est annulé, le navigateur
    /// ne déplace plus le focus lui-même) ; le champ du clavier virtuel ouvert garde le sien.
    fn focus_view(&self, idx: usize) {
        // Copies : `focus()` déclenche des événements de focus synchrones, l'état reste libre.
        let Some((canvas, doc)) = self.inner.borrow().views.get(idx).map(|v| {
            let doc = match &v.window {
                Some(w) => w.document(),
                None => web_sys::window().and_then(|w| w.document()),
            };
            (v.canvas.clone(), doc)
        }) else {
            return;
        };
        let active = doc.and_then(|d| d.active_element());
        let el: &web_sys::Element = canvas.as_ref();
        if active.is_some_and(|a| &a == el || a.class_name().split_whitespace().any(|c| c == KEYBOARD_CLASS))
        {
            return;
        }
        let _ = canvas.focus();
    }

    fn touch_input(&self, e: &web_sys::PointerEvent, kind: &str) {
        let (id, x, y) = (e.pointer_id(), e.client_x(), e.client_y());
        let actions = {
            let mut i = self.inner.borrow_mut();
            let Inner { touch, views, .. } = &mut *i;
            match kind {
                "pointerdown" => {
                    let c = &views[0].canvas;
                    let (l, t) = (f64::from(c.offset_left()), f64::from(c.offset_top()));
                    touch.set_area(l, t, f64::from(c.offset_width()), f64::from(c.offset_height()));
                    touch.down(id, x, y)
                }
                "pointermove" => touch.moved(id, x, y),
                "pointerup" => touch.up(id, x, y, e.time_stamp()),
                _ => touch.cancel(id),
            }
        };
        self.touch_actions(actions);
        let serial = self.inner.borrow().touch.long_press_serial();
        if kind == "pointerdown"
            && let Some(serial) = serial
        {
            // Jamais annulée : un geste fini entre-temps rend la minuterie sans effet.
            let e = self.clone();
            let cb = Closure::once_into_js(move || {
                if e.is_connected() {
                    let actions = e.inner.borrow_mut().touch.long_press(serial);
                    e.touch_actions(actions);
                }
            });
            if let Some(w) = web_sys::window() {
                let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(
                    cb.unchecked_ref(),
                    touch::LONG_PRESS_MS,
                );
            }
        }
    }

    fn touch_actions(&self, actions: Vec<touch::Action>) {
        use rdp_pdu::fastpath::ptr;
        let mut events = Vec::new();
        for a in actions {
            match a {
                touch::Action::Zoom(z) => apply_zoom(&self.inner.borrow().views[0].canvas, z),
                touch::Action::Move { x, y } => {
                    if let Some((x, y)) = self.desktop_point(0, x, y) {
                        events.push(Input::Mouse { flags: ptr::MOVE, x, y });
                    }
                }
                touch::Action::Button { button, down, x, y } => {
                    if let Some((x, y)) = self.desktop_point(0, x, y) {
                        let flag = match button {
                            touch::Button::Left => ptr::BUTTON1,
                            touch::Button::Right => ptr::BUTTON2,
                        };
                        events.push(Input::Mouse { flags: flag | if down { ptr::DOWN } else { 0 }, x, y });
                    }
                }
                touch::Action::Wheel { delta, horizontal, x, y } => {
                    if let Some((x, y)) = self.desktop_point(0, x, y) {
                        events.push(Input::wheel(delta, horizontal, x, y));
                    }
                }
            }
        }
        self.input(&events);
    }

    /// Clavier : positions physiques → scancodes ; à défaut, caractère Unicode. `virtual_kbd` :
    /// l'événement vient du champ du clavier virtuel, dont les caractères arrivent par
    /// `text_input` (indépendants de la disposition) ; seules les touches nommées et les
    /// raccourcis partent d'ici.
    pub fn key_input(&self, e: &web_sys::KeyboardEvent, down: bool, virtual_kbd: bool) {
        if !self.is_connected() {
            return;
        }
        self.user_gesture();
        let code = e.code();
        if let Some(events) = super::keys::sequence(&code, down) {
            e.prevent_default();
            self.input(&events);
            return;
        }
        // Ctrl+V / Cmd+V : le presse-papier local part vers le PC avant la touche V.
        if down && (e.ctrl_key() || e.meta_key()) && code == "KeyV" {
            self.paste_guard();
        }
        let key = e.key();
        let mut chars = key.chars();
        let single = match (chars.next(), chars.next()) {
            (Some(c), None) => Some(c),
            _ => None,
        };
        // Touche morte comprise : l'accent composé arrive par la fin de composition.
        if virtual_kbd
            && (single.is_some() || key == "Dead")
            && !(e.ctrl_key() || e.alt_key() || e.meta_key())
        {
            return;
        }
        // Clavier virtuel : `code` vide, mais les touches nommées (Retour arrière, Entrée,
        // flèches…) portent dans `key` le même nom que leur position.
        let scan = super::keys::scancode(&code)
            .or_else(|| code.is_empty().then(|| super::keys::scancode(&key)).flatten());
        if let Some((code, ext)) = scan {
            e.prevent_default();
            self.key(code, ext, down);
        } else if let Some(c) = single {
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

    /// Relâche sur le PC une touche encore enfoncée alors que le focus est passé à une commande
    /// locale (sans annuler l'événement : Espace active un bouton au relâchement).
    pub fn release_key(&self, e: &web_sys::KeyboardEvent) {
        let Some(k) = super::keys::scancode(&e.code()) else { return };
        if self.inner.borrow().pressed.contains(&k) {
            self.key(k.0, k.1, false);
        }
    }

    /// Saisie du clavier virtuel (`beforeinput` du champ caché, ou fin de composition) : texte en
    /// Unicode, effacement et Entrée en vraies touches. « Coller » du menu du champ : texte tapé
    /// sur le PC (Ctrl+V, lui, est annulé au keydown et passe par le presse-papier).
    pub fn text_input(&self, input_type: &str, data: Option<String>) {
        use super::keys::{tap, text_events};
        if !self.is_connected() {
            return;
        }
        self.user_gesture();
        let events = match input_type {
            "insertText" | "insertReplacementText" | "insertFromPaste" => {
                text_events(&data.unwrap_or_default())
            }
            "insertLineBreak" | "insertParagraph" => tap(0x1C, false).to_vec(),
            "deleteContentBackward" | "deleteWordBackward" => tap(0x0E, false).to_vec(),
            "deleteContentForward" | "deleteWordForward" => tap(0x53, true).to_vec(),
            _ => return,
        };
        self.input(&events);
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

    fn clipboard(&self, msg: &[u8]) {
        let events = match self.inner.borrow_mut().clip.receive(msg) {
            Ok(e) => e,
            Err(e) => {
                web_sys::console::warn_1(&format!("presse-papier : {e:?}").into());
                return;
            }
        };
        let le16 = |o: usize| {
            u16::from_le_bytes([msg.get(o).copied().unwrap_or(0), msg.get(o + 1).copied().unwrap_or(0)])
        };
        // En-tête incomplet (réponse mutilée soldée par `rdp-clip`) : pas de type à interpréter.
        let kind = if msg.len() >= 8 { le16(0) } else { 0 };
        match kind {
            // Monitor Ready : `rdp-clip` y répond par notre liste de formats, que Windows accusera.
            1 => self.inner.borrow_mut().clip_announces.sent(None, js_sys::Date::now(), None),
            // Format List Response : CB_RESPONSE_OK (0x0001) ou CB_RESPONSE_FAIL.
            3 => self.format_list_answered(le16(2) & 0x0001 != 0),
            _ => {}
        }
        web_sys::console::debug_1(
            &format!("cliprdr ← type {kind} ({} o) → {} événement(s)", msg.len(), events.len()).into(),
        );
        // Les demandes de `fetch_step` ne produisent que des envois : la file ne grossit plus.
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
                    // Windows a copié (liste acceptée par `rdp-clip`) : nos annonces en attente sont
                    // dépassées, leur accusé ne validera rien ; une écriture locale en attente aussi.
                    {
                        let mut i = self.inner.borrow_mut();
                        i.clip_announces.remote_changed();
                        i.clip_write_gen = i.clip_write_gen.wrapping_add(1);
                        i.clip_pending_write = None;
                    }
                    self.fetch_step(|f, request| f.changed(&formats, request));
                }
                rdp_clip::ClipEvent::RemoteData(data) => {
                    self.fetch_step(|f, request| f.received(data, request))
                }
                rdp_clip::ClipEvent::Send(_) => {}
            }
        }
    }

    /// Fait avancer la récupération du contenu du PC : envoie la demande suivante, ou écrit
    /// localement le contenu complet.
    fn fetch_step(
        &self,
        step: impl FnOnce(
            &mut clip::Fetch,
            &mut dyn FnMut(rdp_clip::ClipFormat) -> bool,
        ) -> Option<Vec<rdp_clip::LocalData>>,
    ) {
        let mut sends = Vec::new();
        let done = {
            let mut i = self.inner.borrow_mut();
            let Inner { clip, clip_fetch, .. } = &mut *i;
            let mut request = |f| {
                let ev = clip.request(&[f]);
                let sent = !ev.is_empty();
                sends.extend(ev);
                sent
            };
            step(clip_fetch, &mut request)
        };
        self.clip_send(sends);
        if let Some(items) = done {
            self.write_remote(items);
        }
    }

    /// Réponse de Windows à l'une de nos listes de formats (il répond dans l'ordre d'envoi).
    /// Acceptée et pas remplacée : notre contenu est celui du PC.
    fn format_list_answered(&self, ok: bool) {
        let mut i = self.inner.borrow_mut();
        if let Some(fp) = i.clip_announces.answered(ok) {
            i.clip_last = Some(fp);
        }
    }

    /// Écrit localement ce que Windows a copié, hors de la boucle de réception : une demande de
    /// permission du navigateur peut faire attendre l'écriture longtemps. Un PNG que le navigateur
    /// ne décode pas est remplacé par le DIB, s'il est proposé, plutôt que réessayé à chaque geste.
    fn write_remote(&self, items: Vec<rdp_clip::LocalData>) {
        let (generation, announce) = {
            let mut i = self.inner.borrow_mut();
            // Réponse restée dans la file après la fermeture : plus rien à écrire.
            if i.closing {
                return;
            }
            i.clip_last = Some(clip::fingerprint(&items));
            i.clip_write_gen = i.clip_write_gen.wrapping_add(1);
            i.clip_pending_write = None;
            (i.clip_write_gen, i.clip_fetch.generation())
        };
        let e = self.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let png = items.iter().find_map(|d| match d {
                rdp_clip::LocalData::Png(p) => Some(p),
                _ => None,
            });
            if let Some(p) = png
                && !clip::png_decodes(p).await
            {
                // Contenu dépassé ou session finie pendant le décodage : pas de repli non plus.
                if e.inner.borrow().clip_write_gen == generation {
                    web_sys::console::debug_1(
                        &"presse-papier : PNG du PC illisible, repli sur le DIB".into(),
                    );
                    e.fetch_step(|f, request| f.png_unusable(announce, request));
                }
                return;
            }
            e.write_local(generation, items);
        });
    }

    fn write_local(&self, generation: u32, items: Vec<rdp_clip::LocalData>) {
        let e = self.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let current = || e.inner.borrow().clip_write_gen == generation;
            let result = clip::write_local(&items, &current).await;
            if let Err(err) = result
                && current()
            {
                web_sys::console::debug_1(
                    &format!("presse-papier local : {err} (nouvel essai au prochain geste)").into(),
                );
                e.inner.borrow_mut().clip_pending_write = Some((generation, items));
            }
        });
    }

    /// Envoie au PC le contenu du presse-papier local s'il a changé, et attend que Windows l'ait
    /// accepté (borné par l'appelant). Faux si Windows a refusé la liste, ou si une liste plus
    /// récente l'a remplacée avant sa réponse : il reste à réannoncer ou à rejoindre la suivante.
    pub async fn sync_local_clipboard(&self) -> bool {
        if !self.is_connected() {
            return true;
        }
        let t0 = js_sys::Date::now();
        let copies = self.inner.borrow().clip_announces.remote_copies();
        let items = clip::read_local().await;
        web_sys::console::debug_1(
            &format!("presse-papier local lu en {:.0} ms", js_sys::Date::now() - t0).into(),
        );
        let Some(items) = items else { return true };
        if items.is_empty() {
            return true;
        }
        let fp = clip::fingerprint(&items);
        let (tx, rx) = futures::channel::oneshot::channel();
        let events = {
            let mut i = self.inner.borrow_mut();
            // Session fermée pendant la lecture : plus d'accusé à attendre.
            if !i.connected || i.closing {
                return true;
            }
            // Windows a copié pendant la lecture : son contenu est le plus récent, le nôtre ne doit
            // ni l'écraser ni invalider sa récupération.
            if i.clip_announces.remote_copies() != copies {
                return true;
            }
            let now = js_sys::Date::now();
            match i.clip_announces.latest() {
                // Déjà annoncé, pas encore accepté (retour du focus juste avant un Ctrl+V) : on
                // attend le même accusé.
                Some((a, at)) if a == fp && now - at < ANNOUNCE_TTL_MS => {
                    i.clip_announces.join(tx);
                    Vec::new()
                }
                None if i.clip_last == Some(fp) => return true,
                _ => {
                    let events = i.clip.set_local(items);
                    // Canal pas encore prêt : la liste partira avec Monitor Ready.
                    if events.is_empty() {
                        return true;
                    }
                    i.clip_announces.sent(Some(fp), now, Some(tx));
                    // Copie locale plus récente : une écriture en attente du contenu du PC est dépassée,
                    // tout comme une récupération en cours (une réponse en retard ne doit rien écrire).
                    i.clip_write_gen = i.clip_write_gen.wrapping_add(1);
                    i.clip_pending_write = None;
                    i.clip_fetch.local_published();
                    events
                }
            }
        };
        self.clip_send(events);
        // Attente abandonnée (session fermée) : rien de plus à tenter.
        matches!(rx.await, Ok(clip::Ack::Accepted) | Err(_))
    }

    /// Geste utilisateur : occasion de réussir une écriture locale refusée plus tôt, si son
    /// contenu est toujours le plus récent.
    pub fn user_gesture(&self) {
        let pending = {
            let mut i = self.inner.borrow_mut();
            match i.clip_pending_write.take() {
                Some((g, items)) if g == i.clip_write_gen => Some((g, items)),
                _ => None,
            }
        };
        if let Some((g, items)) = pending {
            self.write_local(g, items);
        }
    }

    /// Ctrl+V : synchronise d'abord le presse-papier (2 s au plus), puis laisse passer les touches
    /// retenues. Une liste refusée par Windows est réannoncée dans ce délai, une liste remplacée
    /// laisse rejoindre la suivante ; après trois essais, les touches partent quand même (sinon
    /// Ctrl resterait enfoncé sur le PC) et Windows colle son propre contenu.
    pub fn paste_guard(&self) {
        if self.inner.borrow().holding {
            return;
        }
        self.inner.borrow_mut().holding = true;
        let e = self.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let sync = async {
                for _ in 0..3 {
                    if e.sync_local_clipboard().await {
                        return true;
                    }
                }
                false
            };
            let timeout = async {
                let p = js_sys::Promise::new(&mut |resolve, _| {
                    let _ = web_sys::window()
                        .unwrap()
                        .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 2000);
                });
                let _ = wasm_bindgen_futures::JsFuture::from(p).await;
            };
            futures::pin_mut!(sync, timeout);
            if let futures::future::Either::Left((false, _)) = futures::future::select(sync, timeout).await {
                web_sys::console::warn_1(&"presse-papier : contenu local pas accepté par Windows".into());
            }
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
        // Une trame fast-path porte au plus 255 entrées (Ctrl+V retenu longtemps : bien plus).
        let frames: Vec<Vec<u8>> = match self.inner.borrow().session.as_ref() {
            Some(s) => events.chunks(255).map(|c| s.input(c)).collect(),
            None => return,
        };
        for f in frames.iter().filter(|f| !f.is_empty()) {
            self.send(f);
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
        self.send_size(width, height, false);
    }

    /// `force` : envoyer même à taille égale (retour d'une extension multi-écran).
    fn send_size(&self, width: u32, height: u32, force: bool) {
        let (w, h) = clamp_size(width, height);
        let (channel, caps, current, multi) = {
            let i = self.inner.borrow();
            (i.display_channel, i.display_caps, i.desktop, i.multi.is_some())
        };
        // En multi-écran, la disposition vient des écrans, pas de la taille de la fenêtre.
        if multi {
            return;
        }
        self.inner.borrow_mut().desired = Some((w, h));
        let (Some(channel), Some(caps)) = (channel, caps) else { return };
        // Fenêtre plus grande que la surface permise : le PC ignorerait la disposition.
        let (w, h) = caps.fit(w, h);
        let monitor = [(0, 0, w, h)];
        if let Err(e) = caps.check(&monitor) {
            web_sys::console::warn_1(&format!("contrôle d'affichage : {e}").into());
            return;
        }
        if !force && (w, h) == current {
            return;
        }
        self.dvc_send(channel, &views::layout_pdu(&monitor, 0));
    }
}

/// Zones d'image d'avant le dernier changement de taille d'un lot : `Gfx::process` a déjà remplacé
/// le tampon, elles ne le décrivent plus. Les accusés (`Send`) gardent leur ordre.
fn drop_stale_presents(outs: Vec<Out>) -> Vec<Out> {
    let Some(last_reset) = outs.iter().rposition(|o| matches!(o, Out::Reset { .. })) else { return outs };
    outs.into_iter()
        .enumerate()
        .filter(|(k, o)| *k > last_reset || !matches!(o, Out::Present { .. }))
        .map(|(_, o)| o)
        .collect()
}

/// Zoom tactile local : transformation CSS du canevas principal (le bureau distant ne change pas).
fn apply_zoom(canvas: &HtmlCanvasElement, z: touch::Zoom) {
    let style = canvas.style();
    if z == touch::Zoom::default() {
        let _ = style.remove_property("transform");
        let _ = style.remove_property("transform-origin");
    } else {
        let _ = style.set_property("transform-origin", "0 0");
        let _ =
            style.set_property("transform", &format!("translate({}px, {}px) scale({})", z.tx, z.ty, z.scale));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presents_before_last_reset_are_dropped() {
        let present = |x| Out::Present { damage: vec![Rect { x, y: 0, w: 1, h: 1 }] };
        let reset = || Out::Reset { width: 800, height: 600, monitors: Vec::new() };
        let outs = vec![present(1), Out::Send(vec![1]), reset(), Out::Send(vec![2]), present(2)];
        assert_eq!(
            drop_stale_presents(outs),
            vec![Out::Send(vec![1]), reset(), Out::Send(vec![2]), present(2)]
        );
        let outs = vec![present(1), reset(), present(2), reset(), Out::Send(vec![3])];
        assert_eq!(drop_stale_presents(outs), vec![reset(), reset(), Out::Send(vec![3])]);
        let outs = vec![present(1), Out::Send(vec![1])];
        assert_eq!(drop_stale_presents(outs), vec![present(1), Out::Send(vec![1])]);
    }
}
