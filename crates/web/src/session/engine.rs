//! Moteur de session dans le navigateur : WebSocket ↔ `rdp-session`, EGFX ↔ canevas.
//!
//! Tout passe par une seule boucle asynchrone (`pump`) qui traite les messages dans l'ordre et
//! attend le décodage des images H.264 : l'ordre des commandes graphiques et les accusés
//! d'image restent exacts. Les entrées (clavier, souris) partent directement sur le WebSocket.

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    rc::Rc,
};

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
    /// Extensions envoyées, et celle qui attend encore le Reset Graphics qui l'adopte (délai de
    /// garde : un PC qui ne peut l'appliquer garde son affichage sans rien renvoyer).
    extend_seq: u32,
    extend_wait: Option<u32>,
    touch: Touch,
    /// Taille voulue (fenêtre) et retour forcé à un écran pas encore envoyé : appliqués dès que
    /// le contrôle d'affichage devient prêt (voir `single_layout`).
    desired: Option<((u32, u32), bool)>,
    /// Tailles à un écran envoyées et pas encore confirmées par un Reset Graphics, la plus ancienne
    /// d'abord : le bureau prendra la dernière, une nouvelle demande s'y compare (voir
    /// `single_layout` et `size_confirmed`).
    size_sent: VecDeque<(u32, u32)>,
    /// Envoi de la dernière taille (ms, `Date.now()`), voir `forget_unanswered`.
    size_sent_at: f64,
    desktop: (u32, u32),
    cursors: Vec<Option<String>>,
    pressed: HashSet<(u8, bool)>,
    buttons: Held,
    connected: bool,
    closing: bool,
    /// Fermeture volontaire suivie d'une réouverture (H.264 inexploitable par ce navigateur).
    restart: bool,
    avc: h264::Avc,
    /// Dernier chemin d'image H.264 reçu et format d'image du décodeur (menu de session).
    image: (Option<h264::Kind>, Option<&'static str>),
    /// Signale au menu de session un changement de `image`.
    image_changed: leptos::prelude::ArcTrigger,
    clip: rdp_clip::Clipboard,
    clip_fetch: clip::Fetch,
    /// Génération du contenu à écrire localement : une écriture ou un réessai d'une génération
    /// dépassée (nouvelle copie d'un côté ou de l'autre) n'écrit rien.
    clip_write_gen: u32,
    /// Écriture locale refusée (page sans focus) : retentée au prochain geste. Génération, contenu,
    /// empreinte de relecture.
    clip_pending_write: Option<(u32, Vec<rdp_clip::LocalData>, u64)>,
    /// Empreinte du dernier contenu commun aux deux côtés (évite l'écho PC → navigateur → PC) :
    /// reçu du PC, ou annoncé par nous ET accepté par Windows ; effacée quand Windows accepte une
    /// autre de nos listes (remplacée ensuite, ou au contenu inconnu), et quand Windows copie
    /// (inconnu jusqu'à la réception ; le contenu local d'avant reste protégé par `Announces`,
    /// même pour une copie sans format pris en charge).
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
    /// Le moteur est revenu de lui-même à un seul écran (disposition non adoptée par le PC), motif.
    on_single: Rc<dyn Fn(&str)>,
}

/// Étape d'une extension multi-écran.
pub enum Extend {
    /// Toutes les fenêtres sont ouvertes et la disposition envoyée (nombre d'écrans).
    Done(usize),
    /// Une fenêtre de plus est ouverte ; la suivante attend un nouveau geste.
    Next { opened: usize, total: usize },
}

/// Délai (s) laissé au PC pour adopter une disposition à plusieurs écrans (Reset Graphics).
const EXTEND_CONFIRM_S: u32 = 10;

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
        on_single: Rc<dyn Fn(&str)>,
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
            extend_seq: 0,
            extend_wait: None,
            touch: Touch::default(),
            desired: None,
            size_sent: VecDeque::new(),
            size_sent_at: 0.0,
            desktop: (w, h),
            cursors: vec![None; 32],
            pressed: HashSet::new(),
            buttons: Held::new(),
            connected: false,
            closing: false,
            restart: false,
            avc: opts.avc,
            image: (None, None),
            image_changed: leptos::prelude::ArcTrigger::new(),
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
            SessionMessage::Error { message, lasting } => {
                // Refus durable (accès, identifiants, certificat changé) : pas de reconnexion ;
                // échec passager (PC qui redémarre) : la reconnexion automatique reprend.
                self.inner.borrow_mut().closing = true;
                let retry = if lasting { Retry::No } else { Retry::Transient };
                (self.status)(Status::Closed { reason: message, retry });
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
        self.inner.borrow_mut().buf.extend_from_slice(data);
        // Une trame à la fois : ses événements sont distribués avant que la suivante n'entre dans la
        // session (ce que rejoue une reprise de canal ne passe pas derrière une suspension arrivée
        // dans le même bloc).
        while let Some(events) = self.next_frame()? {
            for ev in events {
                self.event(ev, h264).await?;
            }
        }
        Ok(())
    }

    /// Prochaine trame complète du tampon, passée à la session : ses événements ; `None` tant
    /// qu'elle n'est pas arrivée en entier.
    fn next_frame(&self) -> Result<Option<Vec<Event>>, String> {
        let mut i = self.inner.borrow_mut();
        let Some(n) = rdp_pdu::x224::frame_len(&i.buf) else { return Ok(None) };
        if n < 2 {
            return Err("trame RDP invalide".into());
        }
        if i.buf.len() < n {
            return Ok(None);
        }
        let frame: Vec<u8> = i.buf.drain(..n).collect();
        let session = i.session.as_mut().ok_or("données RDP avant la session")?;
        session.feed(&frame).map(Some).map_err(|e| e.to_string())
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
                    // Les limites sont celles du canal qui les annonce : un nouveau canal ouvert avant
                    // la fermeture de l'ancien n'est prêt qu'à sa propre CAPS PDU.
                    // Une taille demandée sur l'ancien canal ne sera peut-être jamais confirmée.
                    let mut i = self.inner.borrow_mut();
                    i.display_channel = Some(channel_id);
                    i.display_caps = None;
                    i.size_sent.clear();
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
                    // Un retour forcé en attente reste forcé (`single_layout`).
                    if let Some(((w, h), _)) = desired {
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
                    i.size_sent.clear();
                }
            }
            Event::Pointer(p) => self.pointer(p),
            // Refus ou fin voulue par le PC : la fermeture du WebSocket qui suit ne relance rien et
            // garde le premier motif (Set Error Info, plus précis, précède la déconnexion MCS).
            Event::ServerError(t) | Event::Disconnected(t) => {
                let first = {
                    let mut i = self.inner.borrow_mut();
                    i.connected = false;
                    !std::mem::replace(&mut i.closing, true)
                };
                if first {
                    (self.status)(Status::Closed { reason: t, retry: Retry::No });
                }
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
                    self.set_image(h264::Kind::Avc420, h264.as_ref().and_then(H264::format));
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
                    let mut kind = h264::Kind::Avc444;
                    let mut gfx = std::cell::RefMut::map(self.inner.borrow_mut(), |i| &mut i.gfx);
                    fn rgba(f: &Option<Decoded>) -> Option<rdp_gfx::Rgba<'_>> {
                        match f {
                            Some(Decoded::Rgba { width, height, data }) => Some(rdp_gfx::Rgba {
                                width: *width,
                                height: *height,
                                data,
                                stride: width * 4,
                            }),
                            _ => None,
                        }
                    }
                    let (m_rgb, a_rgb) = (rgba(&decoded[0]), rgba(&decoded[1]));
                    let more = match (failed, &decoded[0], &decoded[1]) {
                        (Some(e), ..) => {
                            web_sys::console::warn_1(&format!("H.264 (4:4:4) : {e}").into());
                            gfx.skip_frame()
                        }
                        // Navigateur qui ne rend que du RGB : plans YUV retrouvés en inversant sa
                        // conversion, puis 4:4:4 comme d'habitude. Si elle ne s'inverse pas, la
                        // sous-image principale seule (image 4:2:0 complète) ; l'auxiliaire n'a alors
                        // que nourri le décodeur.
                        _ if m_rgb.is_some() || (decoded[0].is_none() && a_rgb.is_some()) => {
                            match gfx.submit_avc444_rgba(m_rgb.as_ref(), a_rgb.as_ref()) {
                                Ok(out) => {
                                    if gfx.rgb_444() {
                                        kind = h264::Kind::Avc444Rgb;
                                    }
                                    Ok(out)
                                }
                                Err(_) => match &m_rgb {
                                    Some(m) => gfx.submit_rgba(m),
                                    None => gfx.skip_frame(),
                                },
                            }
                        }
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
                    self.set_image(kind, h264.as_ref().and_then(H264::format));
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
        let freed = size_confirmed(&mut i.size_sent, (width, height));
        let expected = i.multi.clone();
        let adopted = expected.as_ref().is_some_and(|rects| {
            let bw = rects.iter().map(|r| r.x + r.w).max().unwrap_or(0);
            let bh = rects.iter().map(|r| r.y + r.h).max().unwrap_or(0);
            (bw, bh) == (width, height)
                && rects.len() == i.views.len()
                && (monitors.is_empty() || rects.iter().all(|r| monitors.contains(r)))
        });
        if adopted {
            i.extend_wait = None;
            for (v, r) in i.views.iter_mut().zip(expected.unwrap()) {
                v.set_rect(r);
            }
            return;
        }
        let single = back_to_single(expected.is_some(), i.extend_wait.is_some(), monitors.len());
        if expected.is_some() && single && i.views.len() > 1 {
            web_sys::console::warn_1(&"multi-écran : disposition non adoptée par le serveur".into());
        }
        let mut fell_back = false;
        let mut released = Vec::new();
        if single {
            released = release_secondary(&mut i.buttons);
            for v in i.views.iter().skip(1) {
                v.close();
            }
            i.views.truncate(1);
            i.extend_wait = None;
            fell_back = i.multi.take().is_some();
        }
        i.views[0].set_rect(Rect { x: 0, y: 0, w: width, h: height });
        let desired = i.desired;
        drop(i);
        self.input(&released);
        if fell_back {
            (self.on_single)("Disposition refusée par le PC");
        } else if freed && let Some(((w, h), _)) = desired {
            // Place libérée : la taille retenue faute de place part (forçage compris).
            self.send_size(w, h, false);
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
        let (monitors, rects) = views::layout(screens, current)?;
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
        let v = View::new(canvas, rects[idx], Some(win.clone())).inspect_err(|_| {
            let _ = win.close();
        })?;
        let mut i = self.inner.borrow_mut();
        i.staged.push(v);
        if i.staged.len() < secondary.len() {
            return Ok(Extend::Next { opened: 1 + i.staged.len(), total: screens.len() });
        }
        let mut staged = std::mem::take(&mut i.staged);
        i.staged_screens = None;
        // Entrées branchées à l'installation seulement : une fenêtre préparée (noire) ne transmet
        // rien au PC, pas même ses touches. Index définitif : la vue 0 est la fenêtre principale.
        for (k, v) in staged.iter_mut().enumerate() {
            self.wire_view(v, 1 + k);
        }
        i.views.extend(staged);
        i.multi = Some(std::iter::once(current).chain(secondary).map(|idx| rects[idx]).collect());
        // La disposition remplace toute taille à un écran encore en vol.
        i.size_sent.clear();
        i.extend_seq = i.extend_seq.wrapping_add(1);
        let seq = i.extend_seq;
        i.extend_wait = Some(seq);
        drop(i);
        self.dvc_send(channel, &views::layout_pdu(&monitors, current));
        self.watch_extension(seq);
        Ok(Extend::Done(screens.len()))
    }

    /// Délai de garde d'une extension : un PC qui ne peut pas appliquer la disposition garde son
    /// affichage sans Reset Graphics (MS-RDPEDISP 3.1.5.2), les fenêtres secondaires resteraient
    /// noires. Sans adoption dans le délai, retour à un écran.
    fn watch_extension(&self, seq: u32) {
        let e = self.clone();
        wasm_bindgen_futures::spawn_local(async move {
            super::sleep(EXTEND_CONFIRM_S).await;
            let waiting = {
                let i = e.inner.borrow();
                !i.closing && i.extend_wait == Some(seq)
            };
            if waiting {
                web_sys::console::warn_1(&"multi-écran : disposition non confirmée par le PC".into());
                // Retour forcé à un écran côté PC aussi : s'il adopte l'extension après le délai, il ne
                // garderait pas des écrans dont les fenêtres sont fermées.
                let (w, h) = super::viewport();
                e.disable_multi(w, h);
                (e.on_single)("Extension non confirmée par le PC");
            }
        });
    }

    /// Taille retenue faute de place (file pleine) : rejouée une fois la file oubliable
    /// (`forget_unanswered`), si rien n'est parti depuis sur le même canal. Un Reset qui libère une
    /// place la rejoue plus tôt (`reset_views`).
    fn watch_parked_size(&self, channel: Option<u32>, sent_at: f64) {
        let e = self.clone();
        wasm_bindgen_futures::spawn_local(async move {
            super::sleep(SIZE_ANSWER_MS as u32 / 1000 + 1).await;
            let desired = {
                let i = e.inner.borrow();
                let current = !i.closing && i.display_channel == channel && i.size_sent_at == sent_at;
                current.then_some(i.desired).flatten()
            };
            if let Some(((w, h), _)) = desired {
                e.send_size(w, h, false);
            }
        });
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
        let released = release_secondary(&mut i.buttons);
        for v in i.views.iter().skip(1) {
            v.close();
        }
        i.views.truncate(1);
        i.multi = None;
        i.extend_wait = None;
        drop(i);
        self.input(&released);
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
        for kind in ["pointermove", "pointerdown", "pointerup", "pointercancel"] {
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
        let Some(point) = self.desktop_point(idx, e.client_x(), e.client_y()) else {
            return;
        };
        let events =
            button_input(&mut self.inner.borrow_mut().buttons, e.pointer_id(), idx, kind, e.buttons(), point);
        // Capture même sans entrée RDP (bouton déjà tenu par un autre pointeur) : sinon le relâchement
        // hors du canevas n'arriverait pas, et le bouton resterait enfoncé côté PC.
        if kind == "pointerdown"
            && let Some(v) = self.inner.borrow().views.get(idx)
        {
            let _ = v.canvas.set_pointer_capture(e.pointer_id());
        }
        if events.is_empty() {
            return;
        }
        self.input(&events);
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
                    let mut out = touch_area(touch, &views[0].canvas);
                    out.extend(touch.down(id, x, y));
                    out
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
                    if let Some(at) = self.desktop_point(0, x, y) {
                        let bit = match button {
                            touch::Button::Left => 1,
                            touch::Button::Right => 2,
                        };
                        events.extend(touch_button(&mut self.inner.borrow_mut().buttons, bit, down, at));
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
        if let Some((code, ext)) = super::keys::scancode_of(&code, &key) {
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
        // Même repli qu'à l'appui : une touche nommée du clavier virtuel se relâche aussi.
        let Some(k) = super::keys::scancode_of(&e.code(), &e.key()) else { return };
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
            // Monitor Ready : `rdp-clip` y répond par notre liste de formats, que Windows accusera ;
            // rdpclip relancé ne répondra pas aux listes d'avant.
            1 => self.inner.borrow_mut().clip_announces.ready(js_sys::Date::now()),
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
                    // Le contenu commun est inconnu jusqu'à la réponse de données.
                    {
                        let mut i = self.inner.borrow_mut();
                        let Inner { clip_announces, clip_last, .. } = &mut *i;
                        clip_announces.remote_changed(clip_last);
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
    fn format_list_answered(&self, ok: bool) {
        let mut i = self.inner.borrow_mut();
        let Inner { clip_announces, clip_last, .. } = &mut *i;
        clip_announces.answered(ok, clip_last);
    }

    /// Écrit localement ce que Windows a copié, hors de la boucle de réception : une demande de
    /// permission du navigateur peut faire attendre l'écriture longtemps. Un PNG que le navigateur
    /// ne décode pas est remplacé par le DIB, s'il est proposé, plutôt que réessayé à chaque geste.
    fn write_remote(&self, items: Vec<rdp_clip::LocalData>) {
        let (generation, announce, provisional) = {
            let mut i = self.inner.borrow_mut();
            // Réponse restée dans la file après la fermeture : plus rien à écrire.
            if i.closing {
                return;
            }
            let provisional = clip::fingerprint(&items);
            i.clip_last = Some(provisional);
            i.clip_write_gen = i.clip_write_gen.wrapping_add(1);
            i.clip_pending_write = None;
            (i.clip_write_gen, i.clip_fetch.generation(), provisional)
        };
        let e = self.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let fp = clip::written_fingerprint(&items).await;
            let mut i = e.inner.borrow_mut();
            // Contenu dépassé ou session finie pendant le décodage : ni repli ni écriture.
            if i.clip_write_gen != generation {
                return;
            }
            let Some(fp) = fp else {
                drop(i);
                web_sys::console::debug_1(&"presse-papier : PNG du PC illisible, repli sur le DIB".into());
                e.fetch_step(|f, request| f.png_unusable(announce, request));
                return;
            };
            // Empreinte d'un PNG connue après décodage : celle que donnera une relecture.
            if i.clip_last == Some(provisional) {
                i.clip_last = Some(fp);
            }
            drop(i);
            e.write_local(generation, items, fp);
        });
    }

    /// `fp` : empreinte de `items` relus après écriture (`clip::written_fingerprint`).
    fn write_local(&self, generation: u32, items: Vec<rdp_clip::LocalData>, fp: u64) {
        let e = self.clone();
        wasm_bindgen_futures::spawn_local(async move {
            // Relu juste avant l'écriture (après l'encodage PNG) : contenu dépassé, ou déjà dans le
            // presse-papier local (copié là aussi), l'écrire pourrait écraser une copie locale faite
            // depuis.
            let current = || {
                let i = e.inner.borrow();
                i.clip_write_gen == generation && i.clip_announces.unwritten()
            };
            let result = clip::write_local(&items, &current).await;
            if !current() {
                return;
            }
            let mut i = e.inner.borrow_mut();
            match result {
                Ok(()) => i.clip_announces.written_locally(fp),
                Err(err) => {
                    web_sys::console::debug_1(
                        &format!("presse-papier local : {err} (nouvel essai au prochain geste)").into(),
                    );
                    i.clip_pending_write = Some((generation, items, fp));
                }
            }
        });
    }

    /// Envoie au PC le contenu du presse-papier local s'il a changé, et attend que Windows l'ait
    /// accepté (borné par l'appelant). `Some(false)` si Windows a refusé la liste, si une liste plus
    /// récente l'a remplacée avant sa réponse, ou si la lecture plus récente qui a dépassé celle-ci
    /// a été refusée : il reste à relire, réannoncer ou rejoindre la suivante ; aussi si Windows ne
    /// répond plus à nos listes (rien n'est annoncé). `None` si rien n'a été lu (lecture refusée
    /// par le navigateur, presse-papier vide) : rien n'a changé côté PC.
    pub async fn sync_local_clipboard(&self) -> Option<bool> {
        if !self.is_connected() {
            return Some(true);
        }
        let t0 = js_sys::Date::now();
        let mark = self.inner.borrow_mut().clip_announces.mark();
        let items = clip::read_local().await;
        web_sys::console::debug_1(
            &format!("presse-papier local lu en {:.0} ms", js_sys::Date::now() - t0).into(),
        );
        let items = items.filter(|items| !items.is_empty())?;
        let fp = clip::fingerprint(&items);
        let (tx, rx) = futures::channel::oneshot::channel();
        let events = {
            let mut i = self.inner.borrow_mut();
            // Session fermée pendant la lecture : plus d'accusé à attendre.
            if !i.connected || i.closing {
                return Some(true);
            }
            let now = js_sys::Date::now();
            let common = i.clip_last;
            match i.clip_announces.after_read(mark, fp, common, now) {
                clip::AfterRead::Done => return Some(true),
                clip::AfterRead::Retry | clip::AfterRead::Stalled => return Some(false),
                clip::AfterRead::Join => {
                    i.clip_announces.join(tx);
                    Vec::new()
                }
                clip::AfterRead::Publish => {
                    let events = i.clip.set_local(items);
                    // Canal pas encore prêt : la liste partira avec Monitor Ready.
                    if events.is_empty() {
                        return Some(true);
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
        Some(matches!(rx.await, Ok(clip::Ack::Accepted) | Err(_)))
    }

    /// Geste utilisateur : occasion de réussir une écriture locale refusée plus tôt, si son
    /// contenu est toujours le plus récent.
    pub fn user_gesture(&self) {
        let pending = {
            let mut i = self.inner.borrow_mut();
            match i.clip_pending_write.take() {
                // Copie du PC déjà dans le presse-papier local (copiée là aussi) : plus rien à écrire,
                // l'écrire encore pourrait écraser une copie locale faite depuis.
                Some((g, items, fp)) if g == i.clip_write_gen && i.clip_announces.unwritten() => {
                    Some((g, items, fp))
                }
                _ => None,
            }
        };
        if let Some((g, items, fp)) = pending {
            self.write_local(g, items, fp);
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
            let sync = paste_attempts(|| e.sync_local_clipboard());
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

    /// Chemin d'image réellement utilisé (ligne d'information du menu de session). Lu dans un
    /// contexte réactif, il s'y met à jour quand ce chemin change.
    pub fn image_path(&self) -> String {
        use leptos::prelude::Track;
        let i = self.inner.borrow();
        i.image_changed.track();
        h264::path_label(i.avc != h264::Avc::Off, h264::chosen(), i.image.0, i.image.1)
    }

    /// Note le chemin de la dernière image H.264 et prévient le menu s'il a changé.
    fn set_image(&self, kind: h264::Kind, format: Option<&'static str>) {
        use leptos::prelude::Notify;
        let trigger = {
            let mut i = self.inner.borrow_mut();
            let changed = i.image != (Some(kind), format);
            i.image = (Some(kind), format);
            changed.then(|| i.image_changed.clone())
        };
        // Hors de l'emprunt : la mise à jour du menu relit `image`.
        if let Some(t) = trigger {
            t.notify();
        }
    }

    /// Touche de la barre de touches (scancodes), avec ses modificateurs collants.
    pub fn bar_chord(&self, mods: super::keys::Mods, code: Option<&str>) {
        if !self.is_connected() {
            return;
        }
        self.user_gesture();
        // Modificateurs déjà maintenus au clavier matériel : la barre n'y touche pas.
        let held = {
            let i = self.inner.borrow();
            let any =
                |a: u8, b: u8, ext: bool| i.pressed.contains(&(a, ext)) || i.pressed.contains(&(b, ext));
            super::keys::Mods {
                ctrl: i.pressed.contains(&(0x1D, false)) || i.pressed.contains(&(0x1D, true)),
                alt: i.pressed.contains(&(0x38, false)) || i.pressed.contains(&(0x38, true)),
                win: any(0x5B, 0x5C, true),
            }
        };
        self.input(&super::keys::chord(mods, code, held));
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
        // Le canevas suit la fenêtre : le zoom tactile se reborne sur sa nouvelle taille.
        let actions = {
            let mut i = self.inner.borrow_mut();
            let Inner { touch, views, .. } = &mut *i;
            touch_area(touch, &views[0].canvas)
        };
        self.touch_actions(actions);
        self.send_size(width, height, false);
    }

    /// `force` : envoyer même à taille égale (retour d'une extension multi-écran).
    fn send_size(&self, width: u32, height: u32, force: bool) {
        let (channel, layout, parked) = {
            let mut i = self.inner.borrow_mut();
            let Inner {
                desired, size_sent, size_sent_at, display_channel, display_caps, desktop, multi, ..
            } = &mut *i;
            // En multi-écran, la disposition vient des écrans, pas de la taille de la fenêtre.
            if multi.is_some() {
                return;
            }
            let caps = display_caps.filter(|_| display_channel.is_some());
            let size = clamp_size(width, height);
            let now = js_sys::Date::now();
            forget_unanswered(size_sent, *size_sent_at, now);
            let layout = single_layout(desired, size_sent, caps, size, force, *desktop);
            if matches!(layout, Ok(Some(_))) {
                *size_sent_at = now;
            }
            // Taille retenue faute de place : sans Reset ni nouveau redimensionnement, elle ne
            // partirait jamais.
            let parked =
                matches!(layout, Ok(None)) && caps.is_some() && size_sent.len() >= MAX_SIZES_IN_FLIGHT;
            (*display_channel, layout, parked.then_some(*size_sent_at))
        };
        if let Some(sent_at) = parked {
            self.watch_parked_size(channel, sent_at);
        }
        match (channel, layout) {
            (Some(channel), Ok(Some(monitor))) => self.dvc_send(channel, &views::layout_pdu(&[monitor], 0)),
            (_, Err(e)) => web_sys::console::warn_1(&format!("contrôle d'affichage : {e}").into()),
            _ => {}
        }
    }
}

/// Essais de synchronisation d'un Ctrl+V (`sync_local_clipboard`, trois au plus). Une lecture
/// sans résultat ne vaut succès que si aucun essai n'a échoué : après un refus de Windows, le PC
/// n'a toujours pas le contenu local, l'échec reste jusqu'à un essai accepté.
async fn paste_attempts<F: std::future::Future<Output = Option<bool>>>(
    mut attempt: impl FnMut() -> F,
) -> bool {
    let mut failed = false;
    for _ in 0..3 {
        match attempt().await {
            Some(true) => return true,
            None if !failed => return true,
            _ => failed = true,
        }
    }
    false
}

/// Pointeurs suivis depuis leur `pointerdown` (souris, stylet, doigt d'une fenêtre secondaire) :
/// vue d'origine, boutons transmis au PC (masque `PointerEvent.buttons`), dernière position envoyée.
/// Boutons tenus par pointeur, clé (vue, pointerId) : un `pointerId` n'est unique que dans sa fenêtre.
/// Valeur : (masque des boutons, dernière position envoyée).
type Held = HashMap<(usize, i32), (u16, (u16, u16))>;

/// RDP n'a qu'une souris : le PC voit l'union des boutons tenus par tous les pointeurs.
fn held_mask(held: &Held) -> u16 {
    held.values().fold(0, |m, h| m | h.0)
}

/// Bits de `PointerEvent.buttons` transmis, et bouton RDP de chacun (étendu : X1/X2).
const BUTTONS: [(u16, u16, bool); 5] = {
    use rdp_pdu::fastpath::ptr;
    [
        (1, ptr::BUTTON1, false),
        (2, ptr::BUTTON2, false),
        (4, ptr::BUTTON3, false),
        (8, ptr::X_BUTTON1, true),
        (16, ptr::X_BUTTON2, true),
    ]
};

/// Appuis et relâchements qui font passer le PC du masque `from` au masque `to`, en (x, y).
fn button_changes(from: u16, to: u16, (x, y): (u16, u16)) -> Vec<Input> {
    use rdp_pdu::fastpath::ptr;
    let changes = BUTTONS.iter().filter(|b| (from ^ to) & b.0 != 0);
    changes
        .map(|&(bit, flag, extended)| match (extended, to & bit != 0) {
            (false, true) => Input::Mouse { flags: flag | ptr::DOWN, x, y },
            (false, false) => Input::Mouse { flags: flag, x, y },
            (true, true) => Input::MouseX { flags: flag | ptr::X_DOWN, x, y },
            (true, false) => Input::MouseX { flags: flag, x, y },
        })
        .collect()
}

/// Entrées RDP d'un événement pointeur hors gestes tactiles. Pour un pointeur suivi, `buttons`
/// est comparé aux boutons transmis : un appui ou un relâchement pendant le geste n'arrive que
/// par `pointermove` (boutons combinés, Pointer Events). `pointerup` et `pointercancel`
/// relâchent tout ce qui reste, une seule fois : après une annulation, le navigateur n'envoie
/// pas de `pointerup` (relâché à la dernière position envoyée, celle d'une annulation n'est pas
/// fiable). Un pointeur entré déjà enfoncé (appui hors du bureau) ne fait que bouger.
fn button_input(
    held: &mut Held,
    id: i32,
    view: usize,
    kind: &str,
    buttons: u16,
    at: (u16, u16),
) -> Vec<Input> {
    let buttons = buttons & BUTTONS.iter().map(|b| b.0).sum::<u16>();
    let key = (view, id);
    let target = match kind {
        "pointerdown" => {
            held.entry(key).or_insert((0, at));
            buttons
        }
        "pointermove" if held.contains_key(&key) => buttons,
        "pointermove" => return vec![Input::Mouse { flags: rdp_pdu::fastpath::ptr::MOVE, x: at.0, y: at.1 }],
        _ => 0,
    };
    let before = held_mask(held);
    let Some(h) = held.get_mut(&key) else { return Vec::new() };
    if kind != "pointercancel" {
        h.1 = at;
    }
    h.0 = target;
    let pos = h.1;
    if kind == "pointerup" || kind == "pointercancel" {
        held.remove(&key);
    }
    // Transitions du masque global : un bouton encore tenu par un autre pointeur reste enfoncé.
    let out = button_changes(before, held_mask(held), pos);
    if out.is_empty() && kind == "pointermove" {
        return vec![Input::Mouse { flags: rdp_pdu::fastpath::ptr::MOVE, x: at.0, y: at.1 }];
    }
    out
}

/// Clé réservée des gestes tactiles de la fenêtre principale dans `Held` (aucun `pointerId` réel).
const TOUCH_KEY: (usize, i32) = (0, i32::MIN);

/// Clic d'un geste tactile (`bit` : masque `PointerEvent.buttons`), dans le même masque que les
/// autres pointeurs : un toucher pendant qu'une souris tient le bouton ne le relâche pas.
fn touch_button(held: &mut Held, bit: u16, down: bool, at: (u16, u16)) -> Vec<Input> {
    let before = held_mask(held);
    let h = held.entry(TOUCH_KEY).or_insert((0, at));
    h.0 = if down { h.0 | bit } else { h.0 & !bit };
    h.1 = at;
    if h.0 == 0 {
        held.remove(&TOUCH_KEY);
    }
    button_changes(before, held_mask(held), at)
}

/// Relâche les boutons des pointeurs partis d'une fenêtre secondaire, avant sa fermeture : son
/// `pointerup` n'arrivera plus au moteur. Ceux de la fenêtre principale restent.
fn release_secondary(held: &mut Held) -> Vec<Input> {
    let before = held_mask(held);
    let mut pos = None;
    held.retain(|&(view, _), &mut (_, at)| {
        if view != 0 {
            pos.get_or_insert(at);
        }
        view == 0
    });
    // Seuls les boutons que plus personne ne tient sont relâchés.
    pos.map_or_else(Vec::new, |at| button_changes(before, held_mask(held), at))
}

/// Écran seul à envoyer pour `size` (déjà bornée), `None` s'il n'y a rien à envoyer. `desired`
/// retient la taille et un retour forcé à un écran tant qu'aucune disposition n'est partie :
/// contrôle d'affichage pas prêt (`caps` absent) ou PC trop limité. Le PC peut garder sa
/// disposition à plusieurs écrans pendant la fermeture du canal, même à taille de bureau égale.
/// `sent` : taille envoyée pas encore confirmée ; c'est elle que le bureau va prendre, une taille
/// égale au bureau actuel doit donc encore partir (fenêtre revenue à sa taille entre-temps).
fn single_layout(
    desired: &mut Option<((u32, u32), bool)>,
    sent: &mut VecDeque<(u32, u32)>,
    caps: Option<DisplayCaps>,
    size: (u32, u32),
    force: bool,
    desktop: (u32, u32),
) -> Result<Option<views::Monitor>, String> {
    let force = force || desired.is_some_and(|(_, f)| f);
    *desired = Some((size, force));
    let Some(caps) = caps else { return Ok(None) };
    // Fenêtre plus grande que la surface permise : le PC ignorerait la disposition.
    let (w, h) = caps.fit(size.0, size.1);
    let monitor = (0, 0, w, h);
    caps.check(&[monitor])?;
    if !force && (w, h) == sent.back().copied().unwrap_or(desktop) {
        return Ok(None);
    }
    // Trop de demandes sans réponse : aucune n'est oubliée (un Reset tardif serait pris pour celui
    // d'une autre) ; la taille voulue, retenue dans `desired`, part quand une place se libère.
    if sent.len() >= MAX_SIZES_IN_FLIGHT {
        return Ok(None);
    }
    *desired = Some((size, false));
    sent.push_back((w, h));
    Ok(Some(monitor))
}

/// Tailles en vol au plus (voir `single_layout`).
const MAX_SIZES_IN_FLIGHT: usize = 8;

/// File pleine sans aucune réponse depuis la dernière demande : elles sont perdues (PC qui ignore
/// une disposition ou répond à une autre taille). Oubliées, sinon le bureau ne suivrait plus la
/// fenêtre de toute la session ; un Reset tardif de l'une d'elles ne correspond alors à rien.
fn forget_unanswered(sent: &mut VecDeque<(u32, u32)>, last_sent: f64, now: f64) {
    if sent.len() >= MAX_SIZES_IN_FLIGHT && now - last_sent > SIZE_ANSWER_MS {
        sent.clear();
    }
}

/// Délai de réponse d'une demande de taille au-delà duquel une file pleine est oubliée (ms).
const SIZE_ANSWER_MS: f64 = 10_000.0;

/// Reset Graphics à `size` : il répond à la plus ancienne demande en vol de cette taille (Windows
/// les traite dans l'ordre), les précédentes sont dépassées. Les suivantes restent en vol : une
/// demande plus récente de la même taille peut encore être contredite par un Reset intermédiaire.
/// Vrai s'il libère une place dans une file pleine : la taille voulue retenue peut partir.
fn size_confirmed(sent: &mut VecDeque<(u32, u32)>, size: (u32, u32)) -> bool {
    let full = sent.len() >= MAX_SIZES_IN_FLIGHT;
    if let Some(k) = sent.iter().position(|s| *s == size) {
        sent.drain(..=k);
    }
    full && sent.len() < MAX_SIZES_IN_FLIGHT
}

/// Un Reset Graphics qui n'adopte pas la disposition attendue ramène-t-il à un écran ? Oui sans
/// extension, ou s'il n'a qu'un écran. Sauf pendant l'attente d'une extension : le PC traite les
/// demandes dans l'ordre, ce Reset peut répondre à une taille à un écran envoyée avant elle ; le
/// Reset de l'extension suit, ou le délai de garde ramène à un écran.
fn back_to_single(extending: bool, waiting: bool, monitors: usize) -> bool {
    !extending || (monitors < 2 && !waiting)
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

/// Zone du canevas principal non transformé (`offset*` ignore le zoom CSS) pour les gestes tactiles.
fn touch_area(touch: &mut Touch, c: &HtmlCanvasElement) -> Vec<touch::Action> {
    let (l, t) = (f64::from(c.offset_left()), f64::from(c.offset_top()));
    touch.set_area(l, t, f64::from(c.offset_width()), f64::from(c.offset_height()))
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
    fn forced_single_layout_survives_a_closed_display_channel() {
        let caps = Some(DisplayCaps { max_monitors: 2, max_area: 4 * 1920 * 1080 });
        let (mut desired, mut sent) = (None, VecDeque::new());
        // Retour à un écran pendant que le canal est fermé : rien ne part, le forçage est retenu.
        assert_eq!(single_layout(&mut desired, &mut sent, None, (1920, 1080), true, (1920, 1080)), Ok(None));
        // Redimensionnement ordinaire entre-temps, canal toujours fermé : toujours forcé.
        assert_eq!(single_layout(&mut desired, &mut sent, None, (1920, 1080), false, (1920, 1080)), Ok(None));
        assert_eq!(desired, Some(((1920, 1080), true)));
        // Canal rouvert (rejeu sans forçage) : la disposition part malgré la taille égale.
        let monitor = Some((0, 0, 1920, 1080));
        assert_eq!(
            single_layout(&mut desired, &mut sent, caps, (1920, 1080), false, (1920, 1080)),
            Ok(monitor)
        );
        // Envoyée : le forçage est consommé.
        assert_eq!(single_layout(&mut desired, &mut sent, caps, (1920, 1080), false, (1920, 1080)), Ok(None));
        assert_eq!(
            single_layout(&mut desired, &mut sent, caps, (1280, 720), false, (1920, 1080)),
            Ok(Some((0, 0, 1280, 720)))
        );
        // PC trop limité : refus, le forçage attend une disposition acceptable.
        let tiny = Some(DisplayCaps { max_monitors: 1, max_area: 100 * 100 });
        assert!(single_layout(&mut desired, &mut sent, tiny, (1920, 1080), true, (1920, 1080)).is_err());
        assert_eq!(desired, Some(((1920, 1080), true)));
    }

    #[test]
    fn size_in_flight_is_the_reference() {
        let caps = Some(DisplayCaps { max_monitors: 1, max_area: 8192 * 8192 });
        let (mut desired, mut sent) = (None, VecDeque::new());
        let desktop = (1600, 900);
        // 1280×720 part ; la fenêtre revient à la taille du bureau avant que le PC ne l'applique.
        assert_eq!(
            single_layout(&mut desired, &mut sent, caps, (1280, 720), false, desktop),
            Ok(Some((0, 0, 1280, 720)))
        );
        assert_eq!(
            single_layout(&mut desired, &mut sent, caps, (1600, 900), false, desktop),
            Ok(Some((0, 0, 1600, 900))),
            "le bureau va passer à 1280×720 : la taille actuelle doit repartir"
        );
        // Reset à 1280×720 (pas celui de la dernière demande) : 1600×900 est toujours en vol.
        size_confirmed(&mut sent, (1280, 720));
        assert_eq!(single_layout(&mut desired, &mut sent, caps, (1600, 900), false, (1280, 720)), Ok(None));
        // Confirmée : une taille déjà appliquée reste ignorée.
        size_confirmed(&mut sent, (1600, 900));
        assert!(sent.is_empty());
        assert_eq!(single_layout(&mut desired, &mut sent, caps, (1600, 900), false, desktop), Ok(None));
    }

    #[test]
    fn a_reset_settles_only_its_own_size_request() {
        let caps = Some(DisplayCaps { max_monitors: 1, max_area: 8192 * 8192 });
        let (mut desired, mut sent) = (None, VecDeque::new());
        let (a, b) = ((1280, 720), (1440, 900));
        let monitor = |(w, h)| Ok(Some((0, 0, w, h)));
        // A, B puis A partent (bureau 1600×900).
        for size in [a, b, a] {
            assert_eq!(single_layout(&mut desired, &mut sent, caps, size, false, (1600, 900)), monitor(size));
        }
        // Reset à A (1re demande) puis à B : la dernière demande, A, est encore en vol. La fenêtre
        // revient à B, la taille du bureau à cet instant : elle repart quand même.
        size_confirmed(&mut sent, a);
        size_confirmed(&mut sent, b);
        assert_eq!(single_layout(&mut desired, &mut sent, caps, b, false, b), monitor(b));
        size_confirmed(&mut sent, a);
        size_confirmed(&mut sent, b);
        assert!(sent.is_empty());
        // Une seule demande en vol : la même taille n'est pas renvoyée.
        assert_eq!(single_layout(&mut desired, &mut sent, caps, a, false, b), monitor(a));
        assert_eq!(single_layout(&mut desired, &mut sent, caps, a, false, b), Ok(None));
    }

    #[test]
    fn sizes_beyond_the_queue_wait_for_a_free_slot() {
        let caps = Some(DisplayCaps { max_monitors: 1, max_area: 8192 * 8192 });
        let (mut desired, mut sent) = (None, VecDeque::new());
        let monitor = |(w, h)| Ok(Some((0, 0, w, h)));
        let start = (1600, 900);
        // Huit demandes en vol (1280 à 1420) ; la neuvième, 1280 répétée, attend une place.
        let widths = [1280, 1300, 1320, 1340, 1360, 1380, 1400, 1420];
        for w in widths {
            assert_eq!(
                single_layout(&mut desired, &mut sent, caps, (w, 720), false, start),
                monitor((w, 720))
            );
        }
        assert_eq!(single_layout(&mut desired, &mut sent, caps, (1280, 720), false, start), Ok(None));
        assert_eq!(desired, Some(((1280, 720), false)));
        // Reset tardif de la 1re demande : il ne solde qu'elle, et la taille retenue part.
        assert!(size_confirmed(&mut sent, (1280, 720)));
        let held = desired.unwrap().0;
        assert_eq!(single_layout(&mut desired, &mut sent, caps, held, false, (1280, 720)), monitor(held));
        assert_eq!(sent.len(), MAX_SIZES_IN_FLIGHT);
        // Reset 1300, puis la fenêtre demande 1300 : la file finit à 1280, elle repart (place libre).
        assert!(size_confirmed(&mut sent, (1300, 720)));
        assert_eq!(
            single_layout(&mut desired, &mut sent, caps, (1300, 720), false, (1300, 720)),
            monitor((1300, 720))
        );
        // Les confirmations restantes arrivent dans l'ordre : la file se vide sur la dernière voulue
        // (seule la première libère une place dans une file pleine).
        assert!(size_confirmed(&mut sent, (1320, 720)));
        for w in [1340, 1360, 1380, 1400, 1420, 1280] {
            assert!(!size_confirmed(&mut sent, (w, 720)));
        }
        assert_eq!(sent, [(1300, 720)]);
        size_confirmed(&mut sent, (1300, 720));
        assert!(sent.is_empty());
    }

    #[test]
    fn unanswered_full_queue_is_forgotten() {
        let caps = Some(DisplayCaps { max_monitors: 1, max_area: 8192 * 8192 });
        let (mut desired, mut sent) = (None, VecDeque::new());
        // Huit demandes auxquelles le PC ne répond pas (ignorées, ou Reset à une autre taille).
        for w in (0..8).map(|k| 1280 + 20 * k) {
            assert!(
                single_layout(&mut desired, &mut sent, caps, (w, 720), false, (1600, 900)).unwrap().is_some()
            );
        }
        let last = 1_000.0;
        forget_unanswered(&mut sent, last, last + SIZE_ANSWER_MS);
        assert_eq!(sent.len(), MAX_SIZES_IN_FLIGHT, "encore dans le délai : on attend");
        forget_unanswered(&mut sent, last, last + SIZE_ANSWER_MS + 1.0);
        assert!(sent.is_empty(), "délai passé : la fenêtre est de nouveau suivie");
        assert!(
            single_layout(&mut desired, &mut sent, caps, (1024, 768), false, (1600, 900)).unwrap().is_some()
        );
        // File pas pleine : jamais oubliée, même ancienne (le Reset peut encore venir).
        forget_unanswered(&mut sent, last, last + 10.0 * SIZE_ANSWER_MS);
        assert_eq!(sent.len(), 1);
    }

    #[test]
    fn earlier_single_reset_keeps_a_pending_extension() {
        // Extension envoyée, pas encore adoptée : un Reset à un écran (taille demandée avant elle)
        // ne la défait pas ; le délai de garde reste seul juge.
        assert!(!back_to_single(true, true, 1));
        assert!(!back_to_single(true, true, 0), "Reset sans liste d'écrans");
        // Extension adoptée puis Reset à un écran : le PC est revenu à un écran.
        assert!(back_to_single(true, false, 1));
        // Plusieurs écrans dans une autre disposition : on attend, comme avant.
        assert!(!back_to_single(true, false, 2));
        assert!(back_to_single(false, false, 2), "sans extension : une seule vue");
    }

    #[test]
    fn pointer_button_released_once_on_up_or_cancel() {
        use rdp_pdu::fastpath::ptr;
        let mut held = Held::new();
        let mouse = |flags, (x, y)| vec![Input::Mouse { flags, x, y }];
        // Stylet posé, déplacé, puis geste annulé par le navigateur : relâché où il était, une fois.
        assert_eq!(
            button_input(&mut held, 7, 0, "pointerdown", 1, (10, 20)),
            mouse(ptr::BUTTON1 | ptr::DOWN, (10, 20))
        );
        assert_eq!(button_input(&mut held, 7, 0, "pointermove", 1, (30, 40)), mouse(ptr::MOVE, (30, 40)));
        assert_eq!(button_input(&mut held, 7, 0, "pointercancel", 0, (0, 0)), mouse(ptr::BUTTON1, (30, 40)));
        assert_eq!(button_input(&mut held, 7, 0, "pointercancel", 0, (0, 0)), vec![]);
        assert_eq!(button_input(&mut held, 7, 0, "pointerup", 0, (30, 40)), vec![], "déjà relâché");
        // Boutons étendus, et bouton inconnu (gomme, 32) ignoré jusqu'au bout.
        assert_eq!(
            button_input(&mut held, 1, 0, "pointerdown", 8, (1, 2)),
            vec![Input::MouseX { flags: ptr::X_BUTTON1 | ptr::X_DOWN, x: 1, y: 2 }]
        );
        assert_eq!(
            button_input(&mut held, 1, 0, "pointerup", 0, (1, 2)),
            vec![Input::MouseX { flags: ptr::X_BUTTON1, x: 1, y: 2 }]
        );
        assert_eq!(button_input(&mut held, 2, 0, "pointerdown", 32, (1, 2)), vec![]);
        assert_eq!(button_input(&mut held, 2, 0, "pointerup", 0, (1, 2)), vec![]);
        // Pointeur entré déjà enfoncé (appui hors du bureau) : il ne fait que bouger.
        assert_eq!(button_input(&mut held, 3, 0, "pointermove", 1, (5, 5)), mouse(ptr::MOVE, (5, 5)));
        assert_eq!(button_input(&mut held, 3, 0, "pointerup", 0, (5, 5)), vec![]);
        assert!(held.is_empty());
    }

    #[test]
    fn paste_attempts_keep_a_refusal_over_unread_clipboards() {
        use futures::FutureExt;
        let run = |script: &[Option<bool>]| {
            let mut it = script.iter().copied();
            paste_attempts(|| std::future::ready(it.next().unwrap())).now_or_never().unwrap()
        };
        assert!(run(&[None]), "presse-papier illisible d'emblée : rien à attendre");
        assert!(run(&[Some(false), Some(true)]));
        assert!(!run(&[Some(false), None, None]), "refus puis lecture refusée : toujours en échec");
        assert!(run(&[Some(false), None, Some(true)]));
        assert!(!run(&[Some(false); 3]));
    }

    #[test]
    fn chorded_buttons_follow_pointermove() {
        use rdp_pdu::fastpath::ptr;
        let mut held = Held::new();
        let mouse = |flags, (x, y)| vec![Input::Mouse { flags, x, y }];
        // Gauche, puis droit (pointermove, buttons = 3), gauche relâché (buttons = 2), puis droit.
        assert_eq!(
            button_input(&mut held, 1, 0, "pointerdown", 1, (5, 5)),
            mouse(ptr::BUTTON1 | ptr::DOWN, (5, 5))
        );
        assert_eq!(
            button_input(&mut held, 1, 0, "pointermove", 3, (6, 6)),
            mouse(ptr::BUTTON2 | ptr::DOWN, (6, 6))
        );
        assert_eq!(button_input(&mut held, 1, 0, "pointermove", 2, (7, 7)), mouse(ptr::BUTTON1, (7, 7)));
        assert_eq!(button_input(&mut held, 1, 0, "pointerup", 0, (8, 8)), mouse(ptr::BUTTON2, (8, 8)));
        // Sans les transitions intermédiaires, `pointerup` relâche quand même tout ce qui reste.
        button_input(&mut held, 1, 0, "pointerdown", 1, (5, 5));
        button_input(&mut held, 1, 0, "pointermove", 5, (5, 5));
        assert_eq!(
            button_input(&mut held, 1, 0, "pointercancel", 0, (0, 0)),
            vec![
                Input::Mouse { flags: ptr::BUTTON1, x: 5, y: 5 },
                Input::Mouse { flags: ptr::BUTTON3, x: 5, y: 5 }
            ]
        );
        assert!(held.is_empty());
    }

    #[test]
    fn closing_secondary_views_releases_only_their_buttons() {
        use rdp_pdu::fastpath::ptr;
        let mut held = Held::new();
        button_input(&mut held, 1, 1, "pointerdown", 1, (2000, 10));
        button_input(&mut held, 1, 1, "pointermove", 3, (2010, 20));
        button_input(&mut held, 9, 0, "pointerdown", 1, (10, 10));
        // Le gauche est aussi tenu dans la vue principale : seul le droit est relâché.
        assert_eq!(release_secondary(&mut held), vec![Input::Mouse { flags: ptr::BUTTON2, x: 2010, y: 20 }]);
        assert_eq!(held.keys().collect::<Vec<_>>(), [&(0, 9)], "la vue principale garde son bouton");
        assert_eq!(
            button_input(&mut held, 9, 0, "pointerup", 0, (12, 12)),
            vec![Input::Mouse { flags: ptr::BUTTON1, x: 12, y: 12 }]
        );
        // Même pointerId dans deux vues : suivis séparément.
        button_input(&mut held, 7, 0, "pointerdown", 1, (1, 1));
        assert_eq!(
            button_input(&mut held, 7, 1, "pointermove", 0, (2000, 5)),
            vec![Input::Mouse { flags: ptr::MOVE, x: 2000, y: 5 }]
        );
        assert_eq!(held.len(), 1, "le déplacement sans bouton d'une autre vue ne relâche rien");
        assert_eq!(release_secondary(&mut held), vec![]);
    }

    #[test]
    fn touch_and_mouse_share_buttons() {
        use rdp_pdu::fastpath::ptr;
        let mut held = Held::new();
        let mouse = |flags, (x, y)| vec![Input::Mouse { flags, x, y }];
        // Toucher seul : clic complet.
        assert_eq!(touch_button(&mut held, 1, true, (5, 5)), mouse(ptr::BUTTON1 | ptr::DOWN, (5, 5)));
        assert_eq!(touch_button(&mut held, 1, false, (5, 5)), mouse(ptr::BUTTON1, (5, 5)));
        assert!(held.is_empty());
        // Souris qui glisse (gauche tenu) puis toucher : le glisser n'est pas interrompu.
        button_input(&mut held, 1, 0, "pointerdown", 1, (10, 10));
        assert_eq!(touch_button(&mut held, 1, true, (50, 50)), vec![]);
        assert_eq!(touch_button(&mut held, 1, false, (50, 50)), vec![]);
        assert_eq!(button_input(&mut held, 1, 0, "pointermove", 1, (20, 20)), mouse(ptr::MOVE, (20, 20)));
        // Appui long (droit) pendant le glisser : seul le droit change.
        assert_eq!(touch_button(&mut held, 2, true, (50, 50)), mouse(ptr::BUTTON2 | ptr::DOWN, (50, 50)));
        // Souris relâchée pendant que le doigt tient : le gauche part, le droit reste.
        assert_eq!(button_input(&mut held, 1, 0, "pointerup", 0, (30, 30)), mouse(ptr::BUTTON1, (30, 30)));
        assert_eq!(touch_button(&mut held, 2, false, (50, 50)), mouse(ptr::BUTTON2, (50, 50)));
        assert!(held.is_empty());
        // Le geste tactile appartient à la fenêtre principale : fermer les secondaires le garde.
        touch_button(&mut held, 1, true, (5, 5));
        assert_eq!(release_secondary(&mut held), vec![]);
    }

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
