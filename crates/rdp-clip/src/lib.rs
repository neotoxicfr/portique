//! Presse-papier RDP côté client (MS-RDPECLIP), sans I/O : `receive` prend un message complet
//! du canal statique `cliprdr`, les octets à renvoyer sortent en `ClipEvent::Send`.
//!
//! Séquence (1.3) : le serveur envoie CB_CLIP_CAPS puis CB_MONITOR_READY ; le client répond par
//! ses capacités et sa Format List. Ensuite, chaque côté annonce ses formats (Format List,
//! acquittée par une Format List Response) et l'autre les demande à la demande (Format Data
//! Request / Response). Formats gérés : texte Unicode, « HTML Format », « PNG », CF_DIB.
//! Pas de fichiers (hors V1) : CB_STREAM_FILECLIP_ENABLED n'est jamais annoncé.

#![no_std]
extern crate alloc;

pub mod dib;
pub mod html;

use alloc::{string::String, vec::Vec};

pub use dib::{dib_to_rgba, rgba_to_dib};
pub use html::{cf_html_fragment, html_to_cf_html};

/// Plafond d'un message et d'une donnée échangée.
pub const MAX_DATA: usize = 32 << 20;
/// Plafond de largeur et de hauteur d'une image.
pub const MAX_DIM: usize = 16384;
/// Plafond d'entrées d'une Format List : un vrai presse-papier en propose quelques dizaines,
/// sans plafond 32 Mio d'entrées vides coûteraient des centaines de Mio.
const MAX_FORMATS: usize = 1024;

/// Types de message (2.2.1).
mod msg {
    pub const MONITOR_READY: u16 = 1;
    pub const FORMAT_LIST: u16 = 2;
    pub const FORMAT_LIST_RESPONSE: u16 = 3;
    pub const FORMAT_DATA_REQUEST: u16 = 4;
    pub const FORMAT_DATA_RESPONSE: u16 = 5;
    pub const CLIP_CAPS: u16 = 7;
    pub const FILECONTENTS_REQUEST: u16 = 8;
    pub const FILECONTENTS_RESPONSE: u16 = 9;
}

const RESPONSE_OK: u16 = 0x0001;
const RESPONSE_FAIL: u16 = 0x0002;
const ASCII_NAMES: u16 = 0x0004;

const CAPSTYPE_GENERAL: u16 = 1;
const CAPS_VERSION_2: u32 = 2;
const USE_LONG_FORMAT_NAMES: u32 = 0x0002;

/// Identifiants de format standard (et ceux qu'on attribue à nos formats enregistrés).
const CF_DIB: u32 = 8;
const CF_UNICODETEXT: u32 = 13;
const CF_DIBV5: u32 = 17;
const LOCAL_HTML: u32 = 0xC0F0;
const LOCAL_PNG: u32 = 0xC0F1;
const HTML_NAME: &str = "HTML Format";
const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
const PNG_NAME: &str = "PNG";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated(&'static str),
    Invalid(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated(what) => write!(f, "{what} tronqué"),
            Error::Invalid(what) => f.write_str(what),
        }
    }
}

impl core::error::Error for Error {}

pub(crate) fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

pub(crate) fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// UTF-16LE (arrêt au premier nul) → String, CRLF → LF ; paires invalides remplacées.
pub fn utf16_to_string(bytes: &[u8]) -> String {
    let units = bytes.as_chunks::<2>().0.iter().map(|&c| u16::from_le_bytes(c)).take_while(|&u| u != 0);
    let s: String = char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)).collect();
    if s.contains("\r\n") { s.replace("\r\n", "\n") } else { s }
}

/// String → UTF-16LE terminé par un nul, fins de ligne en CRLF (CF_UNICODETEXT).
pub fn string_to_utf16(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2 + 2);
    let mut prev_cr = false;
    for u in s.encode_utf16() {
        if u == u16::from(b'\n') && !prev_cr {
            out.extend_from_slice(&u16::from(b'\r').to_le_bytes());
        }
        prev_cr = u == u16::from(b'\r');
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipFormat {
    Text,
    Html,
    Png,
    Dib,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalData {
    Text(String),
    /// Fragment HTML (sans l'en-tête CF_HTML).
    Html(String),
    /// Octets PNG bruts.
    Png(Vec<u8>),
    /// Image RGBA, stride `width * 4`.
    Rgba {
        width: u32,
        height: u32,
        rgba: Vec<u8>,
    },
}

impl LocalData {
    fn format(&self) -> ClipFormat {
        match self {
            LocalData::Text(_) => ClipFormat::Text,
            LocalData::Html(_) => ClipFormat::Html,
            LocalData::Png(_) => ClipFormat::Png,
            LocalData::Rgba { .. } => ClipFormat::Dib,
        }
    }

    /// Octets à envoyer dans une Format Data Response.
    fn encode(&self) -> Option<Vec<u8>> {
        let data = match self {
            LocalData::Text(s) => string_to_utf16(s),
            LocalData::Html(f) => html_to_cf_html(f),
            LocalData::Png(p) => p.clone(),
            LocalData::Rgba { width, height, rgba } => rgba_to_dib(*width, *height, rgba).ok()?,
        };
        (data.len() <= MAX_DATA).then_some(data)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipEvent {
    /// Message cliprdr à envoyer (`Session::static_send("cliprdr", …)`).
    Send(Vec<u8>),
    /// Le serveur a du contenu dans ces formats : l'appelant le demande via `request`.
    RemoteChanged(Vec<ClipFormat>),
    /// Réponse à `request` ; `None` si le serveur a refusé, si les données sont illisibles ou
    /// si une Format List plus récente les a rendues caduques.
    RemoteData(Option<LocalData>),
}

/// Identifiant et nom local de chacun de nos formats.
fn local_id(f: ClipFormat) -> (u32, &'static str) {
    match f {
        ClipFormat::Text => (CF_UNICODETEXT, ""),
        ClipFormat::Html => (LOCAL_HTML, HTML_NAME),
        ClipFormat::Png => (LOCAL_PNG, PNG_NAME),
        ClipFormat::Dib => (CF_DIB, ""),
    }
}

fn pdu(msg_type: u16, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&msg_type.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

#[derive(Debug, Default)]
pub struct Clipboard {
    /// CB_CLIP_CAPS du serveur reçu (on n'envoie les nôtres qu'en réponse).
    server_caps: bool,
    /// Noms longs négociés (le serveur les annonce ; nous toujours).
    long_names: bool,
    /// Monitor Ready reçu : on peut annoncer nos formats.
    ready: bool,
    /// Formats annoncés par le serveur : (identifiant, nom).
    remote: Vec<(u32, String)>,
    /// Contenu local, servi à la demande.
    local: Vec<LocalData>,
    /// Format demandé au serveur, réponse attendue (une seule à la fois : pas d'identifiant).
    pending: Option<ClipFormat>,
    /// Une Format List est arrivée depuis la demande en vol : sa réponse sera écartée.
    stale: bool,
}

impl Clipboard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Traite un message complet reçu du serveur.
    pub fn receive(&mut self, msg: &[u8]) -> Result<Vec<ClipEvent>, Error> {
        let (Some(msg_type), Some(flags), Some(len)) = (le16(msg, 0), le16(msg, 2), le32(msg, 4)) else {
            // Peut-être la réponse attendue, mutilée : comme une réponse tronquée, elle termine la
            // demande en vol, sinon plus aucune demande ne partirait.
            if self.pending.take().is_some() {
                self.stale = false;
                return Ok(alloc::vec![ClipEvent::RemoteData(None)]);
            }
            return Err(Error::Truncated("en-tête cliprdr"));
        };
        let len = len as usize;
        // Octets au-delà de dataLen (remplissage de certains serveurs) ignorés.
        let body = if len > MAX_DATA { None } else { msg.get(8..8 + len) };
        let mut ev = Vec::new();
        if msg_type == msg::FORMAT_DATA_RESPONSE {
            // Réponse non sollicitée : ignorée. Tronquée, elle termine quand même la demande en
            // vol (une seule à la fois), sinon plus aucune demande ne partirait.
            if let Some(format) = self.pending.take() {
                let fresh = !core::mem::take(&mut self.stale);
                let data = body.filter(|_| fresh && flags & RESPONSE_OK != 0).and_then(|b| decode(format, b));
                ev.push(ClipEvent::RemoteData(data));
            }
            return Ok(ev);
        }
        if len > MAX_DATA {
            return Err(Error::Invalid("message cliprdr trop grand"));
        }
        let body = body.ok_or(Error::Truncated("message cliprdr"))?;
        match msg_type {
            msg::CLIP_CAPS => self.caps(body)?,
            msg::MONITOR_READY => {
                self.ready = true;
                if self.server_caps {
                    ev.push(ClipEvent::Send(self.client_caps()));
                }
                ev.push(ClipEvent::Send(self.format_list()));
            }
            msg::FORMAT_LIST => {
                // Liste inexploitable : CB_RESPONSE_FAIL (2.2.3.2), l'état précédent reste.
                let Ok(remote) = self.parse_format_list(body, flags & ASCII_NAMES != 0) else {
                    ev.push(ClipEvent::Send(pdu(msg::FORMAT_LIST_RESPONSE, RESPONSE_FAIL, &[])));
                    return Ok(ev);
                };
                self.remote = remote;
                // Le serveur possède désormais le presse-papier : notre contenu ne sera plus demandé.
                self.local.clear();
                self.stale = self.pending.is_some();
                ev.push(ClipEvent::Send(pdu(msg::FORMAT_LIST_RESPONSE, RESPONSE_OK, &[])));
                ev.push(ClipEvent::RemoteChanged(self.remote_formats()));
            }
            msg::FORMAT_DATA_REQUEST => {
                let id = le32(body, 0).ok_or(Error::Truncated("Format Data Request"))?;
                let data =
                    self.local.iter().find(|d| local_id(d.format()).0 == id).and_then(LocalData::encode);
                ev.push(ClipEvent::Send(match data {
                    Some(d) => pdu(msg::FORMAT_DATA_RESPONSE, RESPONSE_OK, &d),
                    None => pdu(msg::FORMAT_DATA_RESPONSE, RESPONSE_FAIL, &[]),
                }));
            }
            msg::FILECONTENTS_REQUEST => {
                // Jamais annoncé ; on refuse proprement (streamId repris, 2.2.5.4).
                let stream = le32(body, 0).ok_or(Error::Truncated("File Contents Request"))?;
                ev.push(ClipEvent::Send(pdu(
                    msg::FILECONTENTS_RESPONSE,
                    RESPONSE_FAIL,
                    &stream.to_le_bytes(),
                )));
            }
            // Format List Response, verrous, répertoire temporaire, types inconnus : rien à faire.
            _ => {}
        }
        Ok(ev)
    }

    /// Nouveau contenu local : Format List au serveur (dès que Monitor Ready est reçu).
    /// Texte → CF_UNICODETEXT ; HTML → « HTML Format » ; PNG → « PNG » ; RGBA → CF_DIB.
    /// Fournir le PNG et le RGBA d'une même image pour couvrir les deux familles d'applications.
    pub fn set_local(&mut self, data: Vec<LocalData>) -> Vec<ClipEvent> {
        self.local.clear();
        for d in data {
            // Un seul contenu par format : le premier l'emporte.
            if !self.local.iter().any(|l| l.format() == d.format()) {
                self.local.push(d);
            }
        }
        if self.ready { alloc::vec![ClipEvent::Send(self.format_list())] } else { Vec::new() }
    }

    /// Demande au serveur le premier format de `preferred` qu'il propose. Rien si aucun ne
    /// convient ou si une demande attend déjà sa réponse (la réponse ne porte pas d'identifiant :
    /// pas d'annulation possible, une réponse tardive serait prise pour la suivante).
    pub fn request(&mut self, preferred: &[ClipFormat]) -> Vec<ClipEvent> {
        if self.pending.is_some() {
            return Vec::new();
        }
        let Some((format, id)) = preferred.iter().find_map(|&f| Some((f, self.remote_id(f)?))) else {
            return Vec::new();
        };
        self.pending = Some(format);
        alloc::vec![ClipEvent::Send(pdu(msg::FORMAT_DATA_REQUEST, 0, &id.to_le_bytes()))]
    }

    /// Formats actuellement proposés par le serveur.
    pub fn remote_formats(&self) -> Vec<ClipFormat> {
        [ClipFormat::Text, ClipFormat::Html, ClipFormat::Png, ClipFormat::Dib]
            .into_iter()
            .filter(|&f| self.remote_id(f).is_some())
            .collect()
    }

    fn remote_id(&self, f: ClipFormat) -> Option<u32> {
        let by_id = |id| self.remote.iter().any(|(i, _)| *i == id).then_some(id);
        let by_name =
            |names: &[&str]| self.remote.iter().find(|(_, n)| names.contains(&n.as_str())).map(|(i, _)| *i);
        match f {
            ClipFormat::Text => by_id(CF_UNICODETEXT),
            ClipFormat::Html => by_name(&[HTML_NAME]),
            ClipFormat::Png => by_name(&[PNG_NAME, "image/png"]),
            ClipFormat::Dib => by_id(CF_DIB).or_else(|| by_id(CF_DIBV5)),
        }
    }

    /// CLIPRDR_CAPS (2.2.2.1) : l'état ne change que si toute la PDU est valide.
    fn caps(&mut self, body: &[u8]) -> Result<(), Error> {
        let count = le16(body, 0).ok_or(Error::Truncated("CB_CLIP_CAPS"))?;
        let mut long_names = self.long_names;
        let mut at = 4;
        for _ in 0..count {
            let (Some(kind), Some(len)) = (le16(body, at), le16(body, at + 2)) else {
                return Err(Error::Truncated("jeu de capacités cliprdr"));
            };
            let len = usize::from(len);
            if len < 4 {
                return Err(Error::Invalid("longueur de capacité cliprdr"));
            }
            let set = body.get(at..at + len).ok_or(Error::Truncated("jeu de capacités cliprdr"))?;
            if kind == CAPSTYPE_GENERAL {
                // CLIPRDR_GENERAL_CAPABILITY (2.2.2.1.1) : indicateurs dans les 12 octets du jeu.
                let flags = le32(set, 8).ok_or(Error::Truncated("capacité générale cliprdr"))?;
                long_names = flags & USE_LONG_FORMAT_NAMES != 0;
            }
            at += len;
        }
        self.server_caps = true;
        self.long_names = long_names;
        Ok(())
    }

    /// CLIPRDR_CAPS : version 2, noms longs ; ni fichiers ni verrous.
    fn client_caps(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(16);
        body.extend_from_slice(&1u16.to_le_bytes()); // cCapabilitiesSets
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&CAPSTYPE_GENERAL.to_le_bytes());
        body.extend_from_slice(&12u16.to_le_bytes());
        body.extend_from_slice(&CAPS_VERSION_2.to_le_bytes());
        body.extend_from_slice(&USE_LONG_FORMAT_NAMES.to_le_bytes());
        pdu(msg::CLIP_CAPS, 0, &body)
    }

    /// Format List de notre contenu local, noms longs ou courts selon la négociation.
    fn format_list(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for d in &self.local {
            let (id, name) = local_id(d.format());
            body.extend_from_slice(&id.to_le_bytes());
            if self.long_names {
                body.extend(name.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
            } else {
                // CLIPRDR_SHORT_FORMAT_NAME : 32 octets Unicode, nul compris.
                let mut short = [0u8; 32];
                for (slot, u) in short.as_chunks_mut::<2>().0.iter_mut().zip(name.encode_utf16().take(15)) {
                    slot.copy_from_slice(&u.to_le_bytes());
                }
                body.extend_from_slice(&short);
            }
        }
        pdu(msg::FORMAT_LIST, 0, &body)
    }

    fn parse_format_list(&self, body: &[u8], ascii: bool) -> Result<Vec<(u32, String)>, Error> {
        let mut out = Vec::new();
        if self.long_names {
            let mut rest = body;
            while !rest.is_empty() {
                let id = le32(rest, 0).ok_or(Error::Truncated("Format List"))?;
                let name = &rest[4..];
                let units =
                    name.as_chunks::<2>().0.iter().position(|c| c == &[0, 0]).unwrap_or(name.len() / 2);
                if out.len() == MAX_FORMATS {
                    return Err(Error::Invalid("Format List trop longue"));
                }
                out.push((id, utf16_to_string(&name[..units * 2])));
                rest = name.get(units * 2 + 2..).unwrap_or_default();
            }
        } else {
            if !body.len().is_multiple_of(36) {
                return Err(Error::Invalid("Format List (noms courts) mal alignée"));
            }
            if body.len() / 36 > MAX_FORMATS {
                return Err(Error::Invalid("Format List trop longue"));
            }
            for entry in body.as_chunks::<36>().0 {
                let id = le32(entry, 0).unwrap_or(0);
                let raw = &entry[4..];
                let name = if ascii {
                    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                    raw[..end].iter().map(|&b| char::from(b)).collect()
                } else {
                    utf16_to_string(raw)
                };
                out.push((id, name));
            }
        }
        Ok(out)
    }
}

/// Données du serveur → contenu local ; `None` si illisibles.
fn decode(format: ClipFormat, data: &[u8]) -> Option<LocalData> {
    Some(match format {
        ClipFormat::Text => LocalData::Text(utf16_to_string(data)),
        ClipFormat::Html => LocalData::Html(cf_html_fragment(data)),
        // Sans la signature PNG, l'image est illisible : l'appelant peut se rabattre sur le DIB.
        ClipFormat::Png => LocalData::Png(data.starts_with(PNG_SIGNATURE).then(|| data.to_vec())?),
        ClipFormat::Dib => {
            let (width, height, rgba) = dib_to_rgba(data).ok()?;
            LocalData::Rgba { width, height, rgba }
        }
    })
}

#[cfg(test)]
mod tests;
