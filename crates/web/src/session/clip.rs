//! Presse-papier du navigateur ↔ `rdp-clip` (texte, HTML, images).
//!
//! L'API Clipboard du navigateur est asynchrone et soumise au focus : on lit le presse-papier
//! local au retour du focus et juste avant un Ctrl+V transmis au PC ; on écrit ce que Windows a
//! copié dès qu'il l'annonce (et on réessaie au prochain geste si la page n'avait pas le focus).

use std::collections::VecDeque;

use futures::channel::oneshot;
use js_sys::{Array, Object, Reflect, Uint8Array};
use rdp_clip::{ClipFormat, LocalData};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Blob, CanvasRenderingContext2d, HtmlCanvasElement, ImageBitmap};

fn clipboard() -> Option<web_sys::Clipboard> {
    let nav = web_sys::window()?.navigator();
    // `navigator.clipboard` n'existe qu'en contexte sécurisé (HTTPS ou localhost).
    let c = Reflect::get(&nav, &"clipboard".into()).ok()?;
    (!c.is_undefined()).then(|| c.unchecked_into())
}

fn js_err(e: JsValue) -> String {
    e.dyn_ref::<js_sys::Error>().map(|e| String::from(e.message())).unwrap_or_else(|| format!("{e:?}"))
}

/// Ordre de demande des formats au serveur : une image en PNG, en DIB si le PNG échoue ; sinon
/// texte et HTML.
pub fn wanted(formats: &[ClipFormat]) -> Vec<ClipFormat> {
    let images: Vec<ClipFormat> =
        [ClipFormat::Png, ClipFormat::Dib].into_iter().filter(|f| formats.contains(f)).collect();
    if !images.is_empty() {
        return images;
    }
    [ClipFormat::Text, ClipFormat::Html].into_iter().filter(|f| formats.contains(f)).collect()
}

/// Récupération du contenu du PC, un format à la fois : cliprdr n'identifie pas les réponses, une
/// demande partie avant une nouvelle annonce doit être soldée (et sa réponse jetée) avant la suivante.
#[derive(Default)]
pub struct Fetch {
    /// Génération de l'annonce courante du PC.
    generation: u32,
    /// Formats encore à demander pour l'annonce courante.
    wanted: Vec<ClipFormat>,
    received: Vec<LocalData>,
    /// Génération de la demande en attente de réponse.
    in_flight: Option<u32>,
    /// Format de repli (DIB) écarté par un PNG reçu : demandé si le navigateur ne décode pas ce PNG.
    fallback: Vec<ClipFormat>,
}

impl Fetch {
    /// Le PC annonce un nouveau contenu. `request` envoie une demande et dit si elle est partie.
    /// Renvoie le contenu complet quand il n'y a plus rien à demander.
    pub fn changed(
        &mut self,
        formats: &[ClipFormat],
        request: impl FnMut(ClipFormat) -> bool,
    ) -> Option<Vec<LocalData>> {
        self.generation = self.generation.wrapping_add(1);
        self.wanted = wanted(formats);
        self.received.clear();
        self.fallback.clear();
        if self.in_flight.is_some() {
            return None;
        }
        self.next(request)
    }

    /// Réponse à la demande en attente ; celle d'une annonce dépassée est jetée.
    pub fn received(
        &mut self,
        data: Option<LocalData>,
        request: impl FnMut(ClipFormat) -> bool,
    ) -> Option<Vec<LocalData>> {
        let current = self.in_flight.take() == Some(self.generation);
        if current && let Some(d) = data {
            // Une image obtenue rend inutile le format de repli (gardé de côté pour un PNG).
            if matches!(d, LocalData::Png(_) | LocalData::Rgba { .. }) {
                let (images, rest) = std::mem::take(&mut self.wanted)
                    .into_iter()
                    .partition(|f| matches!(f, ClipFormat::Png | ClipFormat::Dib));
                self.wanted = rest;
                if matches!(d, LocalData::Png(_)) {
                    self.fallback = images;
                }
            }
            self.received.push(d);
        }
        self.next(request)
    }

    /// Copie locale publiée : le contenu du PC en cours de récupération est dépassé. La réponse en vol
    /// sera soldée (et jetée) à son arrivée ; plus rien n'est demandé, ni repli, pour cette annonce.
    pub fn local_published(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.wanted.clear();
        self.received.clear();
        self.fallback.clear();
    }

    /// Génération de l'annonce courante (à rendre à `png_unusable`).
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Le PNG livré pour l'annonce `generation` ne se décode pas dans le navigateur : demande le
    /// format de repli si cette annonce est toujours la courante. Renvoie le contenu complet.
    pub fn png_unusable(
        &mut self,
        generation: u32,
        request: impl FnMut(ClipFormat) -> bool,
    ) -> Option<Vec<LocalData>> {
        if generation != self.generation || self.in_flight.is_some() {
            return None;
        }
        self.wanted = std::mem::take(&mut self.fallback);
        self.received.clear();
        self.next(request)
    }

    fn next(&mut self, mut request: impl FnMut(ClipFormat) -> bool) -> Option<Vec<LocalData>> {
        while !self.wanted.is_empty() {
            let f = self.wanted.remove(0);
            if request(f) {
                self.in_flight = Some(self.generation);
                return None;
            }
        }
        let items = std::mem::take(&mut self.received);
        (!items.is_empty()).then_some(items)
    }
}

/// Verdict de Windows sur l'une de nos listes de formats (Format List Response).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ack {
    /// CB_RESPONSE_OK : notre contenu est celui du PC.
    Accepted,
    /// CB_RESPONSE_FAIL : il reste à réannoncer.
    Refused,
    /// Une liste plus récente est partie avant cette réponse : le contenu du PC est le sien.
    Replaced,
}

struct Announce {
    /// Empreinte annoncée. `None` : inconnue (liste de Monitor Ready) ou dépassée par une copie
    /// sur le PC ; une telle annonce n'est ni rejointe ni validée.
    fp: Option<u64>,
    at: f64,
    waiters: Vec<oneshot::Sender<Ack>>,
}

/// Durée de validité d'une annonce sans réponse (ms) : au-delà, on réannonce.
const ANNOUNCE_TTL_MS: f64 = 2000.0;

/// Relevé pris avant une lecture du presse-papier local (`Announces::mark`).
#[derive(Clone, Copy)]
pub struct Mark {
    remote_copies: u32,
    /// Numéro de départ de la lecture : la plus récente commencée l'emporte, quel que soit l'ordre de fin.
    seq: u64,
}

/// Suite à donner à une lecture locale terminée (`Announces::after_read`).
#[derive(Debug, PartialEq, Eq)]
pub enum AfterRead {
    /// Rien à annoncer ni à attendre.
    Done,
    /// Attendre l'accusé de la dernière liste en vol (`join`).
    Join,
    /// Dépassée par une lecture dont Windows a refusé le contenu : le PC n'est pas à jour, relire.
    Retry,
    /// Contenu à publier (`set_local`, puis `sent` si une liste part).
    Publish,
}

/// Nos listes de formats sans réponse, dans l'ordre d'envoi. Windows répond dans l'ordre : chaque
/// réponse solde la plus ancienne, et seules les attentes de celle-ci reçoivent son verdict.
#[derive(Default)]
pub struct Announces {
    pending: VecDeque<Announce>,
    /// Copies faites sur le PC : une lecture locale commencée avant la dernière est dépassée.
    remote_copies: u32,
    /// Lectures locales commencées (numéros de départ).
    started: u64,
    /// Numéro de départ de la plus récente lecture conclue (publiée, rejointe ou sans objet) : une
    /// lecture commencée avant elle est dépassée.
    published_seq: u64,
    /// Windows a refusé la dernière liste de cette lecture conclue (rien d'autre en vol depuis).
    refused: bool,
}

impl Announces {
    /// Liste envoyée : son empreinte si elle est connue, et l'attente de l'appelant.
    pub fn sent(&mut self, fp: Option<u64>, at: f64, waiter: Option<oneshot::Sender<Ack>>) {
        self.pending.push_back(Announce { fp, at, waiters: waiter.into_iter().collect() });
    }

    /// Dernière liste en vol, si son contenu est connu : (empreinte, instant d'envoi).
    pub fn latest(&self) -> Option<(u64, f64)> {
        self.pending.back().and_then(|a| Some((a.fp?, a.at)))
    }

    /// Attend la réponse de la dernière liste en vol (même contenu, voir `latest`).
    pub fn join(&mut self, waiter: oneshot::Sender<Ack>) {
        if let Some(a) = self.pending.back_mut() {
            a.waiters.push(waiter);
        }
    }

    /// Le PC a copié : nos listes en vol ne valident plus rien et ne se rejoignent plus ; leurs
    /// attentes recevront quand même leur propre verdict.
    pub fn remote_changed(&mut self) {
        self.remote_copies = self.remote_copies.wrapping_add(1);
        for a in &mut self.pending {
            a.fp = None;
        }
    }

    /// À relever avant une lecture locale, pour `after_read`.
    pub fn mark(&mut self) -> Mark {
        self.started += 1;
        Mark { remote_copies: self.remote_copies, seq: self.started }
    }

    /// Lecture locale commencée à `mark`, d'empreinte `fp` ; `common` : empreinte commune.
    /// `Publish` compte la publication : une lecture concurrente plus ancienne sera écartée.
    pub fn after_read(&mut self, mark: Mark, fp: u64, common: Option<u64>, now: f64) -> AfterRead {
        // Windows a copié pendant la lecture : son contenu est le plus récent, le nôtre ne doit
        // ni l'écraser ni invalider sa récupération.
        if self.remote_copies != mark.remote_copies {
            return AfterRead::Done;
        }
        // Une lecture commencée APRÈS celle-ci a déjà publié : ce contenu-ci est plus ancien. On
        // attend plutôt l'accusé de la publication récente, si elle est encore en vol. Une lecture
        // plus ancienne qui aurait publié entre-temps ne l'emporte pas sur celle-ci.
        // Accusé déjà reçu : un refus laisse le PC avec son ancien contenu, il faut relire.
        if self.published_seq > mark.seq {
            return match (self.pending.is_empty(), self.refused) {
                (false, _) => AfterRead::Join,
                (true, true) => AfterRead::Retry,
                (true, false) => AfterRead::Done,
            };
        }
        // Toute lecture qui conclut fait référence, pas seulement celle qui publie : une lecture plus
        // ancienne encore en cours (conversion d'image) ne doit pas réannoncer un contenu dépassé.
        self.published_seq = mark.seq;
        self.refused = false;
        match self.latest() {
            // Déjà annoncé, pas encore accepté (retour du focus juste avant un Ctrl+V) : même accusé.
            Some((a, at)) if a == fp && now - at < ANNOUNCE_TTL_MS => AfterRead::Join,
            None if common == Some(fp) => AfterRead::Done,
            _ => AfterRead::Publish,
        }
    }

    /// Réponse de Windows (`ok` : CB_RESPONSE_OK) à la plus ancienne liste en vol. Met à jour
    /// `common`, l'empreinte commune aux deux côtés : toute liste acceptée a remplacé le contenu
    /// du PC, il ne reste commun que si c'est la dernière et que son contenu est connu. Le verdict
    /// des attentes, lui, reste `Replaced` pour une liste suivie d'une autre. Un refus de la
    /// dernière, au contenu connu, efface aussi `common` : `set_local` a déjà remplacé le contenu
    /// servi, le PC garde ses formats d'avant mais recevrait le contenu refusé s'il les demandait.
    pub fn answered(&mut self, ok: bool, common: &mut Option<u64>) {
        let Some(a) = self.pending.pop_front() else { return };
        if self.pending.is_empty() {
            self.refused = !ok;
        }
        let verdict = match (self.pending.is_empty(), ok) {
            (false, _) => Ack::Replaced,
            (true, true) => Ack::Accepted,
            (true, false) => Ack::Refused,
        };
        if ok {
            *common = a.fp.filter(|_| verdict == Ack::Accepted);
        } else if verdict == Ack::Refused && a.fp.is_some() {
            *common = None;
        }
        for w in a.waiters {
            let _ = w.send(verdict);
        }
    }

    /// Session finie : les attentes sont abandonnées (leur récepteur voit l'annulation).
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}

/// Empreinte à tenir pour commune aux deux côtés après une lecture locale d'empreinte `fp`. Tant
/// qu'une copie du PC attend son écriture locale (`unwritten` : en cours, ou refusée faute de
/// focus), relire le contenu local d'avant (`local`, vu en dernier) n'est pas une nouvelle copie :
/// le republier écraserait la copie du PC. Un contenu local différent, lui, prend la main.
pub fn common_for_read(common: Option<u64>, unwritten: bool, local: Option<u64>, fp: u64) -> Option<u64> {
    if unwritten && local == Some(fp) { Some(fp) } else { common }
}

fn blob(bytes: &[u8], mime: &str) -> Result<Blob, String> {
    let parts = Array::of1(&Uint8Array::from(bytes));
    let opts = web_sys::BlobPropertyBag::new();
    opts.set_type(mime);
    Blob::new_with_u8_array_sequence_and_options(&parts, &opts).map_err(js_err)
}

async fn blob_bytes(b: &Blob) -> Result<Vec<u8>, String> {
    let buf = JsFuture::from(b.array_buffer()).await.map_err(js_err)?;
    Ok(Uint8Array::new(&buf).to_vec())
}

/// RGBA → PNG par un canevas temporaire.
async fn rgba_to_png(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<u8>, String> {
    let doc = web_sys::window().and_then(|w| w.document()).ok_or("pas de document")?;
    let c: HtmlCanvasElement = doc.create_element("canvas").map_err(js_err)?.unchecked_into();
    c.set_width(width);
    c.set_height(height);
    let ctx: CanvasRenderingContext2d =
        c.get_context("2d").map_err(js_err)?.ok_or("canevas indisponible")?.unchecked_into();
    let img =
        web_sys::ImageData::new_with_u8_clamped_array_and_sh(wasm_bindgen::Clamped(rgba), width, height)
            .map_err(js_err)?;
    ctx.put_image_data(&img, 0, 0).map_err(js_err)?;
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let cb = Closure::once_into_js(move |b: JsValue| {
            let _ = if b.is_null() {
                reject.call1(&JsValue::NULL, &"toBlob".into())
            } else {
                resolve.call1(&JsValue::NULL, &b)
            };
        });
        let _ = c.to_blob(cb.unchecked_ref());
    });
    let b: Blob = JsFuture::from(promise).await.map_err(js_err)?.unchecked_into();
    blob_bytes(&b).await
}

/// Le navigateur décode-t-il ce PNG ? Chromium refuse d'écrire une image qu'il ne décode pas, et
/// `rdp-clip` ne vérifie que la signature.
pub async fn png_decodes(png: &[u8]) -> bool {
    let (Ok(b), Some(window)) = (blob(png, "image/png"), web_sys::window()) else { return false };
    let Ok(p) = window.create_image_bitmap_with_blob(&b) else { return false };
    match JsFuture::from(p).await {
        Ok(bmp) => {
            bmp.unchecked_into::<ImageBitmap>().close();
            true
        }
        Err(_) => false,
    }
}

/// Image (PNG ou autre format lisible par le navigateur) → RGBA.
async fn image_to_rgba(b: &Blob) -> Result<(u32, u32, Vec<u8>), String> {
    let window = web_sys::window().ok_or("pas de fenêtre")?;
    let bmp: ImageBitmap = JsFuture::from(window.create_image_bitmap_with_blob(b).map_err(js_err)?)
        .await
        .map_err(js_err)?
        .unchecked_into();
    let (w, h) = (bmp.width(), bmp.height());
    if w == 0 || h == 0 || w as usize > rdp_clip::MAX_DIM || h as usize > rdp_clip::MAX_DIM {
        return Err("image vide ou trop grande".into());
    }
    let doc = window.document().ok_or("pas de document")?;
    let c: HtmlCanvasElement = doc.create_element("canvas").map_err(js_err)?.unchecked_into();
    c.set_width(w);
    c.set_height(h);
    let ctx: CanvasRenderingContext2d =
        c.get_context("2d").map_err(js_err)?.ok_or("canevas indisponible")?.unchecked_into();
    ctx.draw_image_with_image_bitmap(&bmp, 0.0, 0.0).map_err(js_err)?;
    let data = ctx.get_image_data(0, 0, w as i32, h as i32).map_err(js_err)?;
    Ok((w, h, data.data().0))
}

/// Écrit dans le presse-papier local ce que Windows a copié. `current` est relu juste avant
/// l'écriture : un contenu dépassé pendant la conversion n'écrase pas le plus récent.
pub async fn write_local(items: &[LocalData], current: &dyn Fn() -> bool) -> Result<(), String> {
    let cb = clipboard().ok_or("presse-papier indisponible (HTTPS requis)")?;
    let record = Object::new();
    for item in items {
        let (mime, b) = match item {
            LocalData::Text(t) => ("text/plain", blob(t.as_bytes(), "text/plain")?),
            LocalData::Html(h) => ("text/html", blob(h.as_bytes(), "text/html")?),
            LocalData::Png(p) => ("image/png", blob(p, "image/png")?),
            LocalData::Rgba { width, height, rgba } => {
                ("image/png", blob(&rgba_to_png(*width, *height, rgba).await?, "image/png")?)
            }
        };
        Reflect::set(&record, &mime.into(), &b).map_err(js_err)?;
    }
    let ctor = Reflect::get(&js_sys::global(), &"ClipboardItem".into()).map_err(js_err)?;
    let item =
        Reflect::construct(ctor.unchecked_ref::<js_sys::Function>(), &Array::of1(&record)).map_err(js_err)?;
    if !current() {
        return Ok(());
    }
    JsFuture::from(cb.write(&Array::of1(&item))).await.map_err(js_err)?;
    Ok(())
}

/// Lit le presse-papier local (texte, HTML, image). `None` si illisible ou refusé.
pub async fn read_local() -> Option<Vec<LocalData>> {
    let cb = clipboard()?;
    let mut out = Vec::new();
    match JsFuture::from(cb.read()).await {
        Ok(items) => {
            let items: Array = items.unchecked_into();
            for item in items.iter() {
                let item: web_sys::ClipboardItem = item.unchecked_into();
                let types: Vec<String> = item.types().iter().filter_map(|t| t.as_string()).collect();
                for t in &types {
                    let Ok(b) = JsFuture::from(item.get_type(t)).await else { continue };
                    let b: Blob = b.unchecked_into();
                    match t.as_str() {
                        "text/plain" => {
                            if let Ok(bytes) = blob_bytes(&b).await {
                                out.push(LocalData::Text(String::from_utf8_lossy(&bytes).into_owned()));
                            }
                        }
                        "text/html" => {
                            if let Ok(bytes) = blob_bytes(&b).await {
                                out.push(LocalData::Html(String::from_utf8_lossy(&bytes).into_owned()));
                            }
                        }
                        m if m.starts_with("image/") => {
                            if m == "image/png"
                                && let Ok(bytes) = blob_bytes(&b).await
                            {
                                out.push(LocalData::Png(bytes));
                            }
                            // Les applications Windows classiques lisent CF_DIB : on fournit les deux.
                            if let Ok((width, height, rgba)) = image_to_rgba(&b).await {
                                out.push(LocalData::Rgba { width, height, rgba });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        // read() refusé (Firefox, permission) : le texte seul reste souvent lisible.
        Err(_) => {
            let t = JsFuture::from(cb.read_text()).await.ok()?.as_string()?;
            out.push(LocalData::Text(t));
        }
    }
    Some(out)
}

/// Empreinte du contenu, pour ne pas renvoyer au PC ce qu'il a déjà. Type et longueur de chaque
/// élément en font partie (« ab » + « c » ≠ « a » + « bc »), et une image compte en entier.
pub fn fingerprint(items: &[LocalData]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    // FNV-1a par mots de 8 octets : une image de plusieurs Mo reste rapide à hacher. Le repli des
    // bits hauts sur les bas fait porter un écart du bit 63 sur les mots suivants : sans lui, il
    // y resterait seul et un second écart au même bit l'annulerait.
    let mut eat = |b: &[u8]| {
        let (words, rest) = b.as_chunks::<8>();
        for w in words {
            h = (h ^ u64::from_le_bytes(*w)).wrapping_mul(0x0100_0000_01b3);
            h ^= h >> 32;
        }
        for x in rest {
            h = (h ^ *x as u64).wrapping_mul(0x0100_0000_01b3);
        }
    };
    for i in items {
        let (tag, body): (u8, &[u8]) = match i {
            LocalData::Text(t) => (1, t.as_bytes()),
            LocalData::Html(t) => (2, t.as_bytes()),
            LocalData::Png(p) => (3, p),
            LocalData::Rgba { width, height, rgba } => {
                eat(&[&width.to_le_bytes()[..], &height.to_le_bytes()].concat());
                (4, rgba)
            }
        };
        eat(&[tag]);
        eat(&(body.len() as u64).to_le_bytes());
        eat(body);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_separates_items_and_whole_images() {
        let t = |s: &str| LocalData::Text(s.into());
        let html = |s: &str| LocalData::Html(s.into());
        assert_ne!(fingerprint(&[t("ab"), html("c")]), fingerprint(&[t("a"), html("bc")]));
        assert_ne!(fingerprint(&[t("ab")]), fingerprint(&[html("ab")]));
        let img = |last: u8, width: u32, height: u32| {
            let mut rgba = vec![0u8; 8192];
            rgba[8191] = last;
            LocalData::Rgba { width, height, rgba }
        };
        assert_ne!(
            fingerprint(&[img(0, 64, 32)]),
            fingerprint(&[img(1, 64, 32)]),
            "écart après 4 096 octets"
        );
        assert_ne!(fingerprint(&[img(0, 64, 32)]), fingerprint(&[img(0, 32, 64)]), "dimensions");
        assert_eq!(fingerprint(&[t("x"), img(7, 64, 32)]), fingerprint(&[t("x"), img(7, 64, 32)]));
        // 4×1 : seuls les bits forts des alphas 7 et 15 (bit 63 de chaque mot) diffèrent.
        let rgba = |flip: u8| {
            let mut rgba = vec![0x40u8; 16];
            rgba[7] ^= flip;
            rgba[15] ^= flip;
            LocalData::Rgba { width: 4, height: 1, rgba }
        };
        assert_ne!(fingerprint(&[rgba(0)]), fingerprint(&[rgba(0x80)]), "deux écarts au bit 63");
        assert_eq!(fingerprint(&[rgba(0x80)]), fingerprint(&[rgba(0x80)]));
    }

    #[test]
    fn each_announce_gets_only_its_own_verdict() {
        let wait = || oneshot::channel::<Ack>();
        let mut a = Announces::default();
        // Liste de Monitor Ready (contenu inconnu), puis A et B avant toute réponse.
        a.sent(None, 0.0, None);
        assert_eq!(a.latest(), None);
        let (ta, mut ra) = wait();
        a.sent(Some(1), 10.0, Some(ta));
        let (ta2, mut ra2) = wait();
        assert_eq!(a.latest(), Some((1, 10.0)));
        a.join(ta2);
        let (tb, mut rb) = wait();
        a.sent(Some(2), 20.0, Some(tb));
        // Monitor Ready, A refusée, B acceptée : A est remplacée, pas créditée du succès de B.
        let mut common = Some(9);
        a.answered(true, &mut common);
        assert_eq!(ra.try_recv(), Ok(None));
        assert_eq!(common, None, "liste acceptée au contenu inconnu");
        common = Some(9);
        a.answered(false, &mut common);
        assert_eq!(common, Some(9), "liste refusée : contenu du PC inchangé");
        assert_eq!(ra.try_recv(), Ok(Some(Ack::Replaced)));
        assert_eq!(ra2.try_recv(), Ok(Some(Ack::Replaced)), "attente jointe à A");
        assert_eq!(rb.try_recv(), Ok(None));
        a.answered(true, &mut common);
        assert_eq!(common, Some(2));
        assert_eq!(rb.try_recv(), Ok(Some(Ack::Accepted)));
        assert_eq!(a.latest(), None);
        // Seule en vol : son propre verdict, refus compris. Le contenu servi est déjà le refusé :
        // plus rien de commun, le réessai réannoncera même le contenu d'avant.
        let (tc, mut rc) = wait();
        a.sent(Some(3), 30.0, Some(tc));
        a.answered(false, &mut common);
        assert_eq!(rc.try_recv(), Ok(Some(Ack::Refused)));
        assert_eq!(common, None, "refus de la dernière liste connue");
        let m = a.mark();
        assert_eq!(a.after_read(m, 2, common, 35.0), AfterRead::Publish, "contenu d'avant réannoncé");
        a.sent(Some(2), 35.0, None);
        a.answered(true, &mut common);
        assert_eq!(common, Some(2));
        // A acceptée puis B refusée : le PC a pris A, le contenu commun d'avant n'est plus le sien.
        let (ta, mut ra) = wait();
        a.sent(Some(1), 31.0, Some(ta));
        let (tb, mut rb) = wait();
        a.sent(Some(2), 32.0, Some(tb));
        a.answered(true, &mut common);
        assert_eq!(ra.try_recv(), Ok(Some(Ack::Replaced)));
        assert_eq!(common, None, "empreinte commune invalidée");
        a.answered(false, &mut common);
        assert_eq!(rb.try_recv(), Ok(Some(Ack::Refused)));
        assert_eq!(common, None);
        // Copie sur le PC pendant l'attente : plus rien à rejoindre ni à valider, verdict remis.
        common = Some(9);
        let (td, mut rd) = wait();
        a.sent(Some(4), 40.0, Some(td));
        a.remote_changed();
        assert_eq!(a.latest(), None);
        a.answered(true, &mut common);
        assert_eq!(common, None, "acceptée, contenu inconnu");
        assert_eq!(rd.try_recv(), Ok(Some(Ack::Accepted)));
        // Réponse sans liste en vol : ignorée ; fin de session : attentes annulées.
        common = Some(9);
        a.answered(true, &mut common);
        assert_eq!(common, Some(9));
        let (te, mut re) = wait();
        a.sent(Some(5), 50.0, Some(te));
        a.clear();
        assert!(re.try_recv().is_err());
    }

    #[test]
    fn stale_local_reread_keeps_an_unwritten_remote_copy() {
        let (fa, fb, fc) = (1, 2, 3);
        let mut a = Announces::default();
        // A vu localement et commun ; Windows copie B, reçu (commun = B) mais pas écrit localement.
        a.remote_changed();
        let common = Some(fb);
        // Retour du focus : le presse-papier local contient toujours A, ce n'est pas une copie.
        let m = a.mark();
        assert_eq!(a.after_read(m, fa, common_for_read(common, true, Some(fa), fa), 0.0), AfterRead::Done);
        // Vraie copie locale C : elle prend la main sur B.
        let m = a.mark();
        assert_eq!(a.after_read(m, fc, common_for_read(common, true, Some(fa), fc), 0.0), AfterRead::Publish);
        // B écrit localement (vu en dernier) : relire A est une nouvelle copie.
        let m = a.mark();
        assert_eq!(
            a.after_read(m, fa, common_for_read(common, false, Some(fb), fa), 0.0),
            AfterRead::Publish
        );
        // Contenu local jamais vu : rien ne le distingue d'une copie, comme avant.
        assert_eq!(common_for_read(common, true, None, fa), common);
    }

    #[test]
    fn local_reads_overtaken_are_dropped() {
        let mut a = Announces::default();
        // Rien en vol, contenu commun identique : rien à faire ; différent : publié.
        let m = a.mark();
        assert_eq!(a.after_read(m, 1, Some(1), 0.0), AfterRead::Done);
        let m = a.mark();
        assert_eq!(a.after_read(m, 2, Some(1), 0.0), AfterRead::Publish);
        a.sent(Some(2), 0.0, None);
        // Même contenu encore en vol : on rejoint son accusé ; au-delà du délai : réannoncé.
        let m = a.mark();
        assert_eq!(a.after_read(m, 2, Some(1), 100.0), AfterRead::Join);
        let m = a.mark();
        assert_eq!(a.after_read(m, 2, Some(1), 2100.0), AfterRead::Publish);
        // Lecture A (retour du focus) commencée, puis lecture B (Ctrl+V) qui publie avant elle.
        let ma = a.mark();
        let mb = a.mark();
        assert_eq!(a.after_read(mb, 3, Some(1), 200.0), AfterRead::Publish);
        a.sent(Some(3), 200.0, None);
        // A se termine : dépassée, elle attend l'accusé de B au lieu de publier son contenu.
        assert_eq!(a.after_read(ma, 4, Some(1), 300.0), AfterRead::Join);
        assert_eq!(a.after_read(ma, 2, Some(1), 300.0), AfterRead::Join);
        // B déjà accusée : A n'a plus rien à attendre.
        let mut common = Some(1);
        a.answered(true, &mut common);
        a.answered(true, &mut common);
        assert_eq!(a.after_read(ma, 4, common, 400.0), AfterRead::Done);
        // B refusée avant la fin de A : A ne conclut pas à un succès, elle fait relire.
        let ma = a.mark();
        let mb = a.mark();
        assert_eq!(a.after_read(mb, 5, common, 410.0), AfterRead::Publish);
        a.sent(Some(5), 410.0, None);
        a.answered(false, &mut common);
        assert_eq!(a.after_read(ma, 4, common, 420.0), AfterRead::Retry);
        assert_eq!(a.after_read(ma, 4, common, 420.0), AfterRead::Retry, "rien n'a changé depuis");
        // Sans publication intermédiaire, la lecture se termine normalement.
        let m = a.mark();
        assert_eq!(a.after_read(m, 4, common, 500.0), AfterRead::Publish);
        a.sent(Some(4), 500.0, None);
        a.answered(true, &mut common);
        // Ordre inverse : A (plus ancienne) publie AVANT B ; B, plus récente, publie quand même.
        let ma = a.mark();
        let mb = a.mark();
        assert_eq!(a.after_read(ma, 6, common, 700.0), AfterRead::Publish);
        a.sent(Some(6), 700.0, None);
        assert_eq!(a.after_read(mb, 7, common, 750.0), AfterRead::Publish, "B reste prioritaire");
        a.sent(Some(7), 750.0, None);
        a.answered(true, &mut common);
        a.answered(true, &mut common);
        // Lecture récente sans objet (contenu déjà commun) : l'ancienne lecture A (image lente) ne
        // réannonce pas A par-dessus.
        let ma = a.mark();
        let mb = a.mark();
        assert_eq!(a.after_read(mb, 7, common, 800.0), AfterRead::Done);
        assert_eq!(a.after_read(ma, 8, common, 900.0), AfterRead::Done, "A dépassée par une lecture conclue");
        // Lecture récente qui rejoint un accusé en vol : A attend le même accusé au lieu de publier.
        let m = a.mark();
        assert_eq!(a.after_read(m, 9, common, 1000.0), AfterRead::Publish);
        a.sent(Some(9), 1000.0, None);
        let ma = a.mark();
        let mb = a.mark();
        assert_eq!(a.after_read(mb, 9, common, 1100.0), AfterRead::Join);
        assert_eq!(a.after_read(ma, 10, common, 1200.0), AfterRead::Join, "A ne publie pas");
        // Copie sur le PC pendant la lecture : écartée.
        let m = a.mark();
        a.remote_changed();
        assert_eq!(a.after_read(m, 5, common, 600.0), AfterRead::Done);
    }

    #[test]
    fn png_first_dib_only_as_fallback() {
        use ClipFormat::*;
        assert_eq!(wanted(&[Text, Dib, Png]), [Png, Dib]);
        assert_eq!(wanted(&[Text, Html]), [Text, Html]);
        let asked = std::cell::RefCell::new(Vec::new());
        let req = |x| {
            asked.borrow_mut().push(x);
            true
        };
        let mut f = Fetch::default();
        assert!(f.changed(&[Png, Dib], &req).is_none());
        // PNG refusé par le PC : on demande le DIB.
        assert!(f.received(None, &req).is_none());
        let rgba = LocalData::Rgba { width: 1, height: 1, rgba: vec![1, 2, 3, 4] };
        assert_eq!(f.received(Some(rgba.clone()), &req), Some(vec![rgba.clone()]));
        assert_eq!(*asked.borrow(), [Png, Dib]);
        // PNG obtenu : le DIB n'est pas demandé.
        asked.borrow_mut().clear();
        f.changed(&[Png, Dib], &req);
        let png = LocalData::Png(vec![0x89]);
        assert_eq!(f.received(Some(png.clone()), &req), Some(vec![png.clone()]));
        assert_eq!(*asked.borrow(), [Png]);
        // PNG illisible par le navigateur : le DIB est demandé, une fois, pour l'annonce courante.
        let g = f.generation();
        assert!(f.png_unusable(g, &req).is_none());
        assert_eq!(*asked.borrow(), [Png, Dib]);
        assert_eq!(f.received(Some(rgba.clone()), &req), Some(vec![rgba]));
        assert!(f.png_unusable(g, &req).is_none());
        assert_eq!(*asked.borrow(), [Png, Dib], "repli déjà consommé");
        // Annonce dépassée : rien n'est demandé.
        f.changed(&[Png, Dib], &req);
        f.received(Some(png), &req);
        f.changed(&[Text], &req);
        f.received(Some(LocalData::Text("t".into())), &req);
        asked.borrow_mut().clear();
        assert!(f.png_unusable(g + 1, &req).is_none());
        assert!(asked.borrow().is_empty());
    }

    #[test]
    fn local_copy_supersedes_a_fetch_in_flight() {
        use ClipFormat::*;
        let asked = std::cell::RefCell::new(Vec::new());
        let req = |x| {
            asked.borrow_mut().push(x);
            true
        };
        let mut f = Fetch::default();
        f.changed(&[Png, Dib], &req);
        let png = LocalData::Png(vec![0x89]);
        assert!(f.received(Some(png), &req).is_some());
        let g = f.generation();
        // PNG illisible : DIB demandé… puis l'utilisateur copie localement avant la réponse.
        assert!(f.png_unusable(g, &req).is_none());
        f.local_published();
        let rgba = LocalData::Rgba { width: 1, height: 1, rgba: vec![1, 2, 3, 4] };
        assert!(f.received(Some(rgba), &req).is_none(), "DIB en retard : jeté");
        assert!(f.png_unusable(g, &req).is_none(), "plus de repli pour l'ancienne annonce");
        assert_eq!(*asked.borrow(), [Png, Dib]);
    }

    #[test]
    fn answer_to_superseded_announce_is_dropped() {
        use ClipFormat::*;
        let asked = std::cell::RefCell::new(Vec::new());
        let req = |x| {
            asked.borrow_mut().push(x);
            true
        };
        let mut f = Fetch::default();
        assert!(f.changed(&[Text], &req).is_none());
        // Nouvelle annonce (image) pendant la demande de texte : rien ne part encore.
        assert!(f.changed(&[Png], &req).is_none());
        assert_eq!(*asked.borrow(), [Text]);
        // La réponse texte, dépassée, est jetée ; l'image est demandée.
        assert!(f.received(Some(LocalData::Text("A".into())), &req).is_none());
        assert_eq!(*asked.borrow(), [Text, Png]);
        let png = LocalData::Png(vec![1]);
        assert_eq!(f.received(Some(png.clone()), &req), Some(vec![png]));
        // Une demande refusée passe au format suivant.
        let only_html = |x| x == Html;
        let html = LocalData::Html("<b>b</b>".into());
        assert!(f.changed(&[Text, Html], only_html).is_none());
        assert_eq!(f.received(Some(html.clone()), only_html), Some(vec![html]));
    }
}
