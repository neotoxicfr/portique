//! Session RDP côté client, sans I/O : reprend la connexion après NLA (MCS Connect Initial)
//! jusqu'à la session active, puis aiguille les PDU reçues (curseur, canaux statiques et
//! dynamiques, erreurs) et encode les entrées.
//!
//! L'appelant découpe le flux en trames avec `rdp_pdu::x224::frame_len`, appelle `feed` pour
//! chacune et envoie les octets des événements `Event::Send`.

#![no_std]
extern crate alloc;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

use rdp_pdu::{
    fastpath::{self, Input, PointerUpdate},
    gcc::{self, Channel, ClientCore, ClientData, channel_opts, early_caps},
    mcs::{self, DomainPdu},
    slowpath::{self, data_type, pdu_type},
    vc::{self, DvcPdu},
};

pub use rdp_pdu::Error;

/// Canaux dynamiques acceptés ; tout autre est refusé proprement.
pub const DVC_GRAPHICS: &str = "Microsoft::Windows::RDS::Graphics";
pub const DVC_DISPLAY_CONTROL: &str = "Microsoft::Windows::RDS::DisplayControl";
pub const CLIPRDR: &str = "cliprdr";
const DRDYNVC: &str = "drdynvc";
/// STATUS_NOT_SUPPORTED : refus de création d'un canal dynamique inconnu.
const DVC_REFUSED: i32 = 0xC000_00BBu32 as i32;
/// Canaux dynamiques ouverts à la fois : deux noms acceptés, et de quoi en recréer un avant la
/// fermeture de l'ancien. Chaque réassembleur peut garder un message entier (64 Mio au plus).
const MAX_DVCS: usize = 4;

#[derive(Debug, Clone)]
pub struct Config {
    pub width: u16,
    pub height: u16,
    pub keyboard_layout: u32,
    pub client_name: String,
    /// Protocole retenu à la négociation X.224 (faite par le serveur portique).
    pub selected_protocol: u32,
    pub username: String,
    pub domain: String,
    /// Accepte le canal de contrôle d'affichage (redimensionnement dynamique).
    pub display_control: bool,
}

#[derive(Debug, PartialEq)]
pub enum Event {
    /// Octets à envoyer au serveur, dans l'ordre.
    Send(Vec<u8>),
    /// Session active : taille du bureau imposée par le serveur.
    Connected {
        width: u16,
        height: u16,
    },
    /// Le serveur réactive la session (changement de taille sans EGFX).
    Deactivated,
    Pointer(PointerUpdate),
    /// Canal dynamique ouvert (graphique, contrôle d'affichage).
    DvcOpened {
        channel_id: u32,
        name: String,
    },
    DvcData {
        channel_id: u32,
        data: Vec<u8>,
    },
    DvcClosed {
        channel_id: u32,
    },
    /// Message complet du canal presse-papier (MS-RDPECLIP).
    Clipboard(Vec<u8>),
    /// Message d'erreur du serveur (Set Error Info) : la déconnexion suit en général.
    ServerError(String),
    /// Verrous clavier côté serveur (bits : 1 Arrêt défil, 2 Verr num, 4 Verr maj).
    KeyboardIndicators(u16),
    Disconnected(String),
    /// Diagnostic : PDU reçue mais non traitée (à journaliser côté appelant).
    Ignored(String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    ConnectResponse,
    AttachUser,
    Joining,
    License,
    DemandActive,
    Finalizing,
    Active,
    Closed,
}

pub struct Session {
    cfg: Config,
    state: State,
    user: u16,
    io_channel: u16,
    /// Canaux statiques : identifiant MCS → nom.
    channels: BTreeMap<u16, &'static str>,
    to_join: Vec<u16>,
    /// Canal dont on attend le Channel Join Confirm.
    joining: u16,
    /// Le serveur accepte qu'on saute les MCS Channel Join (MS-RDPBCGR 2.2.1.4.2) : un aller-retour de
    /// moins par canal, ce qui compte sur un lien lointain.
    skip_join: bool,
    share_id: u32,
    fastpath: fastpath::Reassembler,
    static_reassembly: BTreeMap<u16, vc::ChannelReassembler>,
    dvcs: BTreeMap<u32, (String, vc::DvcReassembler)>,
    desktop: (u16, u16),
}

const STATIC_CHANNELS: [&str; 2] = [CLIPRDR, DRDYNVC];

impl Session {
    pub fn new(cfg: Config) -> Self {
        let desktop = (cfg.width, cfg.height);
        Self {
            cfg,
            state: State::ConnectResponse,
            user: 0,
            io_channel: 0,
            channels: BTreeMap::new(),
            to_join: Vec::new(),
            joining: 0,
            skip_join: false,
            share_id: 0,
            fastpath: fastpath::Reassembler::default(),
            static_reassembly: BTreeMap::new(),
            dvcs: BTreeMap::new(),
            desktop,
        }
    }

    /// Premier message : MCS Connect Initial avec les blocs client.
    pub fn start(&self) -> Vec<u8> {
        let options = channel_opts::INITIALIZED | channel_opts::ENCRYPT_RDP | channel_opts::COMPRESS_RDP;
        let client = ClientData {
            core: ClientCore {
                version: gcc::RDP_VERSION_10_7,
                width: self.cfg.width,
                height: self.cfg.height,
                keyboard_layout: self.cfg.keyboard_layout,
                client_build: 1,
                client_name: self.cfg.client_name.clone(),
                early_capability_flags: early_caps::SUPPORT_ERRINFO_PDU
                    | early_caps::WANT_32BPP_SESSION
                    | early_caps::SUPPORT_STATUSINFO_PDU
                    | early_caps::STRONG_ASYMMETRIC_KEYS
                    | early_caps::VALID_CONNECTION_TYPE
                    | early_caps::SUPPORT_MONITOR_LAYOUT_PDU
                    | early_caps::SUPPORT_DYNVC_GFX_PROTOCOL
                    | early_caps::SUPPORT_SKIP_CHANNELJOIN,
                selected_protocol: self.cfg.selected_protocol,
            },
            channels: STATIC_CHANNELS
                .iter()
                .map(|name| Channel {
                    name,
                    options: if *name == CLIPRDR { options | channel_opts::SHOW_PROTOCOL } else { options },
                })
                .collect(),
        };
        mcs::connect_initial(&client)
    }

    pub fn is_active(&self) -> bool {
        self.state == State::Active
    }

    pub fn desktop_size(&self) -> (u16, u16) {
        self.desktop
    }

    /// Traite une trame complète (TPKT ou fast-path).
    pub fn feed(&mut self, frame: &[u8]) -> Result<Vec<Event>, Error> {
        let mut ev = Vec::new();
        if self.state == State::Closed {
            return Ok(ev);
        }
        if fastpath::is_fastpath(frame) {
            for (code, data) in self.fastpath.feed(frame)? {
                if let Some(p) = fastpath::pointer_update(code, &data)? {
                    ev.push(Event::Pointer(p));
                }
            }
            return Ok(ev);
        }
        match self.state {
            State::ConnectResponse => {
                let server = mcs::connect_response(frame)?;
                self.io_channel = server.io_channel;
                self.skip_join = server
                    .early_capability_flags
                    .is_some_and(|f| f & gcc::server_early_caps::SKIP_CHANNELJOIN_SUPPORTED != 0);
                for (name, id) in STATIC_CHANNELS.iter().zip(&server.channel_ids) {
                    self.channels.insert(*id, name);
                }
                ev.push(Event::Send(mcs::erect_domain_request()));
                ev.push(Event::Send(mcs::attach_user_request()));
                self.state = State::AttachUser;
            }
            State::AttachUser => {
                self.user = mcs::attach_user_confirm(frame)?;
                // MS-RDPBCGR 1.3.1.1 : avec SKIP_CHANNELJOIN accepté par le serveur, les canaux sont joints
                // d'office ; on passe directement aux informations du client.
                if !self.skip_join {
                    self.to_join = [self.user, self.io_channel]
                        .into_iter()
                        .chain(self.channels.keys().copied())
                        .collect();
                    self.to_join.reverse();
                }
                self.join_next(&mut ev);
            }
            State::Joining => {
                // T.125 : le confirm porte le canal joint ; un autre que celui demandé laisserait un
                // canal non joint sans qu'on le sache.
                if mcs::channel_join_confirm(frame)? != self.joining {
                    return Err(Error::Invalid("MCS : canal confirmé différent du canal demandé"));
                }
                self.join_next(&mut ev);
            }
            _ => self.domain_pdu(frame, &mut ev)?,
        }
        Ok(ev)
    }

    fn join_next(&mut self, ev: &mut Vec<Event>) {
        match self.to_join.pop() {
            Some(ch) => {
                self.joining = ch;
                ev.push(Event::Send(mcs::channel_join_request(self.user, ch)));
                self.state = State::Joining;
            }
            None => {
                let info = slowpath::client_info(
                    &self.cfg.domain,
                    &self.cfg.username,
                    slowpath::info_flags::MOUSE
                        | slowpath::info_flags::DISABLECTRLALTDEL
                        | slowpath::info_flags::UNICODE
                        | slowpath::info_flags::MAXIMIZESHELL
                        | slowpath::info_flags::LOGONNOTIFY
                        | slowpath::info_flags::ENABLEWINDOWSKEY
                        | slowpath::info_flags::LOGONERRORS
                        | slowpath::info_flags::NOAUDIOPLAYBACK,
                    slowpath::perf::ENABLE_FONT_SMOOTHING | slowpath::perf::ENABLE_DESKTOP_COMPOSITION,
                );
                ev.push(Event::Send(mcs::send_data_request(self.user, self.io_channel, &info)));
                self.state = State::License;
            }
        }
    }

    fn io(&self, payload: &[u8]) -> Event {
        Event::Send(mcs::send_data_request(self.user, self.io_channel, payload))
    }

    fn domain_pdu(&mut self, frame: &[u8], ev: &mut Vec<Event>) -> Result<(), Error> {
        let (channel, data) = match mcs::read_domain_pdu(frame)? {
            DomainPdu::SendDataIndication { channel, data } => (channel, data),
            DomainPdu::Disconnect { reason } => {
                self.state = State::Closed;
                ev.push(Event::Disconnected(alloc::format!(
                    "le serveur a fermé la connexion (raison MCS {reason})"
                )));
                return Ok(());
            }
            DomainPdu::Other(_) => return Ok(()),
        };
        if channel != self.io_channel {
            return self.static_channel(channel, data, ev);
        }
        match self.state {
            State::License => {
                // Seul « client valide » est attendu ; une vraie négociation de licence (serveur RDS)
                // n'est pas gérée.
                if !slowpath::license_is_valid_client(data)? {
                    return Err(Error::Invalid("le serveur exige une licence RDS (non géré)"));
                }
                self.state = State::DemandActive;
            }
            _ => self.share_control(data, ev)?,
        }
        Ok(())
    }

    fn share_control(&mut self, data: &[u8], ev: &mut Vec<Event>) -> Result<(), Error> {
        let sc = slowpath::read_share_control(data)?;
        match sc.pdu_type {
            pdu_type::DEMAND_ACTIVE => {
                let demand = slowpath::DemandActive::parse(sc.body)?;
                self.share_id = demand.share_id;
                if let Some(size) = demand.desktop_size() {
                    self.desktop = size;
                }
                let caps = slowpath::ClientCaps {
                    width: self.desktop.0,
                    height: self.desktop.1,
                    keyboard_layout: self.cfg.keyboard_layout,
                };
                let (confirm, _) = slowpath::confirm_active(self.share_id, self.user, &caps);
                ev.push(self.io(&confirm));
                for pdu in slowpath::finalization(self.share_id, self.user) {
                    ev.push(self.io(&pdu));
                }
                self.state = State::Finalizing;
            }
            pdu_type::DEACTIVATE_ALL => {
                self.state = State::DemandActive;
                ev.push(Event::Deactivated);
            }
            pdu_type::DATA => {
                let (kind, body) = slowpath::read_data_pdu(sc.body)?;
                self.data_pdu(kind, body, ev)?;
            }
            // MS-RDPBCGR 2.2.13.3.1 : redirection vers un autre hôte d'une ferme RDS, non gérée ;
            // mieux vaut le dire que laisser un écran noir.
            pdu_type::SERVER_REDIRECT => {
                return Err(Error::Invalid(
                    "redirection de ferme RDS non gérée : vise directement l'hôte de session",
                ));
            }
            _ => {}
        }
        Ok(())
    }

    fn data_pdu(&mut self, kind: u8, body: &[u8], ev: &mut Vec<Event>) -> Result<(), Error> {
        match kind {
            data_type::FONT_MAP if self.state == State::Finalizing => {
                self.state = State::Active;
                ev.push(Event::Connected { width: self.desktop.0, height: self.desktop.1 });
            }
            data_type::SET_ERROR_INFO => {
                let code = body.get(..4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(0);
                if let Some(text) = slowpath::error_info_text(code) {
                    ev.push(Event::ServerError(text));
                }
            }
            data_type::SET_KEYBOARD_INDICATORS => {
                if let Some(b) = body.get(2..4) {
                    ev.push(Event::KeyboardIndicators(u16::from_le_bytes([b[0], b[1]])));
                }
            }
            data_type::POINTER => {
                if let Some(p) = slow_pointer(body)? {
                    ev.push(Event::Pointer(p));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn static_channel(&mut self, channel: u16, data: &[u8], ev: &mut Vec<Event>) -> Result<(), Error> {
        let Some(name) = self.channels.get(&channel).copied() else { return Ok(()) };
        let Some(msg) = self.static_reassembly.entry(channel).or_default().feed(data)? else {
            return Ok(());
        };
        match name {
            CLIPRDR => ev.push(Event::Clipboard(msg)),
            DRDYNVC => self.drdynvc(&msg, ev)?,
            _ => {}
        }
        Ok(())
    }

    fn drdynvc(&mut self, msg: &[u8], ev: &mut Vec<Event>) -> Result<(), Error> {
        match vc::read_dvc(msg)? {
            DvcPdu::Capabilities { version } => {
                ev.push(Event::Ignored(alloc::format!("drdynvc : le serveur annonce la version {version}")));
                let out = self.static_send(DRDYNVC, &vc::dvc_capabilities_response());
                ev.extend(out.into_iter().map(Event::Send));
            }
            DvcPdu::Create { channel_id, name } => {
                let wanted =
                    name == DVC_GRAPHICS || (name == DVC_DISPLAY_CONTROL && self.cfg.display_control);
                let room = self.dvcs.contains_key(&channel_id) || self.dvcs.len() < MAX_DVCS;
                let accepted = wanted && room;
                let status = if accepted { 0 } else { DVC_REFUSED };
                let out = self.static_send(DRDYNVC, &vc::dvc_create_response(channel_id, status));
                ev.extend(out.into_iter().map(Event::Send));
                if accepted {
                    self.dvcs.insert(channel_id, (name.clone(), vc::DvcReassembler::default()));
                    ev.push(Event::DvcOpened { channel_id, name });
                }
            }
            DvcPdu::DataFirst { channel_id, total, data } => {
                if let Some((_, r)) = self.dvcs.get_mut(&channel_id)
                    && let Some(full) = r.first(total, data)?
                {
                    ev.push(Event::DvcData { channel_id, data: full });
                }
            }
            DvcPdu::Data { channel_id, data } => {
                if let Some((_, r)) = self.dvcs.get_mut(&channel_id)
                    && let Some(full) = r.data(data)?
                {
                    ev.push(Event::DvcData { channel_id, data: full });
                }
            }
            DvcPdu::Close { channel_id } => {
                if self.dvcs.remove(&channel_id).is_some() {
                    let out = self.static_send(DRDYNVC, &vc::dvc_close(channel_id));
                    ev.extend(out.into_iter().map(Event::Send));
                    ev.push(Event::DvcClosed { channel_id });
                }
            }
            DvcPdu::Other(cmd) => ev.push(Event::Ignored(alloc::format!(
                "drdynvc : commande 0x{cmd:x} ignorée ({} o)",
                msg.len()
            ))),
        }
        Ok(())
    }

    /// Trames à envoyer pour un message de canal statique (`cliprdr`, `drdynvc`).
    pub fn static_send(&self, name: &str, data: &[u8]) -> Vec<Vec<u8>> {
        let Some((&id, _)) = self.channels.iter().find(|(_, n)| **n == name) else { return Vec::new() };
        vc::chunks(data, name == CLIPRDR)
            .iter()
            .map(|chunk| mcs::send_data_request(self.user, id, chunk))
            .collect()
    }

    /// Trames à envoyer pour un message sur un canal dynamique ouvert.
    pub fn dvc_send(&self, channel_id: u32, data: &[u8]) -> Vec<Vec<u8>> {
        if !self.dvcs.contains_key(&channel_id) {
            return Vec::new();
        }
        vc::dvc_data(channel_id, data).iter().flat_map(|pdu| self.static_send(DRDYNVC, pdu)).collect()
    }

    pub fn dvc_name(&self, channel_id: u32) -> Option<&str> {
        self.dvcs.get(&channel_id).map(|(n, _)| n.as_str())
    }

    /// Trame d'entrées fast-path (vide tant que la session n'est pas active).
    pub fn input(&self, events: &[Input]) -> Vec<u8> {
        if self.state != State::Active || events.is_empty() {
            return Vec::new();
        }
        fastpath::input_frame(events)
    }

    /// Redemande l'écran entier (après reprise d'affichage). Vide tant que la session n'est pas
    /// active : l'utilisateur MCS et le partage ne sont pas encore connus.
    pub fn refresh(&self) -> Vec<u8> {
        if self.state != State::Active {
            return Vec::new();
        }
        mcs::send_data_request(
            self.user,
            self.io_channel,
            &slowpath::refresh_rect(self.share_id, self.user, self.desktop.0, self.desktop.1),
        )
    }

    /// Demande de fermeture propre (le serveur répond par une déconnexion). Vide tant que la
    /// session n'est pas active.
    pub fn shutdown(&mut self) -> Vec<u8> {
        if self.state != State::Active {
            return Vec::new();
        }
        mcs::send_data_request(
            self.user,
            self.io_channel,
            &slowpath::shutdown_request(self.share_id, self.user),
        )
    }
}

/// Curseur slow-path (TS_POINTER_PDU, 2.2.9.1.1.4) traduit en mise à jour fast-path.
fn slow_pointer(body: &[u8]) -> Result<Option<PointerUpdate>, Error> {
    if body.len() < 4 {
        return Err(Error::Truncated("Pointer PDU"));
    }
    let msg = u16::from_le_bytes([body[0], body[1]]);
    let data = &body[4..];
    let code = match msg {
        1 => {
            let kind = data.get(..4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(0);
            return Ok(Some(if kind == 0 { PointerUpdate::Hidden } else { PointerUpdate::Default }));
        }
        3 => fastpath::update_code::PTR_POSITION,
        6 => fastpath::update_code::COLOR,
        7 => fastpath::update_code::CACHED,
        8 => fastpath::update_code::POINTER,
        9 => fastpath::update_code::LARGE_POINTER,
        _ => return Ok(None),
    };
    fastpath::pointer_update(code, data)
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session").field("state", &self.state).field("desktop", &self.desktop).finish()
    }
}

/// Texte lisible d'une erreur de session.
pub fn describe(e: &Error) -> String {
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session::new(Config {
            width: 800,
            height: 600,
            keyboard_layout: 0x040C,
            client_name: "test".into(),
            selected_protocol: 0,
            username: "alice".into(),
            domain: String::new(),
            display_control: true,
        })
    }

    #[test]
    fn join_confirm_must_name_the_requested_channel() {
        // Channel Join Confirm (T.125) : en-tête, résultat 0, initiateur, canal demandé, canal joint.
        let confirm = |joined: u16| {
            rdp_pdu::x224::data(&[&[0x3E, 0, 0, 7, 0x03, 0xEC][..], &joined.to_be_bytes()].concat())
        };
        let mut s = session();
        s.state = State::Joining;
        s.user = 1007;
        s.joining = 1004;
        assert!(s.feed(&confirm(1005)).is_err(), "autre canal : refus");
        s.state = State::Joining;
        assert!(s.feed(&confirm(1004)).is_ok());
    }

    #[test]
    fn refresh_and_shutdown_wait_for_activation() {
        let mut s = session();
        assert!(s.refresh().is_empty());
        assert!(s.shutdown().is_empty());
    }

    #[test]
    fn open_dynamic_channels_are_capped() {
        let mut s = session();
        // DYNVC_CREATE_REQ (MS-RDPEDYC 2.2.2.1) : identifiant sur un octet, nom terminé par un nul.
        let create = |id: u8| [&[0x10, id], DVC_GRAPHICS.as_bytes(), &[0]].concat();
        let opened = |s: &mut Session, id: u8| {
            let mut ev = Vec::new();
            s.drdynvc(&create(id), &mut ev).unwrap();
            ev.iter().any(|e| matches!(e, Event::DvcOpened { .. }))
        };
        for id in 1..=MAX_DVCS as u8 {
            assert!(opened(&mut s, id));
        }
        assert!(!opened(&mut s, 9), "au-delà du plafond : refusé");
        assert!(opened(&mut s, 1), "recréation d'un canal ouvert : acceptée");
        s.drdynvc(&[0x40, 2], &mut Vec::new()).unwrap(); // DYNVC_CLOSE
        assert!(opened(&mut s, 9));
        assert_eq!(s.dvcs.len(), MAX_DVCS);
    }
}
