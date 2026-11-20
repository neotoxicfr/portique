//! Décodage H.264 par WebCodecs (accéléré matériel quand le navigateur le peut).
//!
//! Le flux RDP est en Annex B, une image par appel. On lit le profil dans le SPS pour configurer
//! le décodeur, on attend l'image décodée, puis on copie ses plans (I420 ou NV12) pour que
//! `rdp-gfx` fasse la conversion BT.709 pleine plage elle-même (le navigateur supposerait la
//! plage limitée et délaverait les couleurs).
//!
//! Certains navigateurs (Firefox) ne rendent que des images RGB, converties avec l'espace BT.709
//! pleine plage imposé au décodeur. L'AVC420 s'affiche alors tel quel ; pour l'AVC444, la
//! sous-image principale est elle-même une image 4:2:0 complète : on l'affiche, et la sous-image
//! auxiliaire (détail de chroma) passe quand même par le décodeur pour garder ses références.
//! Si le décodeur échoue franchement, le navigateur est noté (par user-agent, une mise à jour
//! retente) et la session se rouvre sans H.264 (RemoteFX Progressive / ClearCodec).

use std::{cell::RefCell, rc::Rc};

use futures::channel::oneshot;
use js_sys::{Array, Uint8Array};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    EncodedVideoChunk, EncodedVideoChunkInit, EncodedVideoChunkType, HardwareAcceleration, PlaneLayout,
    VideoColorPrimaries, VideoColorSpaceInit, VideoDecoder, VideoDecoderConfig, VideoDecoderInit, VideoFrame,
    VideoMatrixCoefficients, VideoPixelFormat, VideoTransferCharacteristics,
};

pub use rdp_gfx::Avc;

/// Échec de décodage : passager (image clé attendue, image perdue) ou rédhibitoire pour ce
/// navigateur (format d'image inexploitable, décodeur en erreur).
#[derive(Debug)]
pub enum DecodeError {
    Transient(String),
    Unusable(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transient(e) | Self::Unusable(e) => f.write_str(e),
        }
    }
}

/// User-agent du navigateur dont le décodeur H.264 a échoué (H.264 désactivé pour lui).
const OFF_KEY: &str = "portique.h264-off";

fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok()?
}

fn user_agent() -> String {
    web_sys::window().and_then(|w| w.navigator().user_agent().ok()).unwrap_or_default()
}

/// Désactive le H.264 pour ce navigateur (cette version).
pub fn disable(reason: &str) {
    web_sys::console::warn_1(&format!("H.264 désactivé pour ce navigateur : {reason}").into());
    if let Some(s) = storage() {
        let _ = s.set_item(OFF_KEY, &user_agent());
    }
}

fn disabled() -> bool {
    let Some(s) = storage() else { return false };
    s.get_item(OFF_KEY).ok().flatten().is_some_and(|ua| ua == user_agent())
}

/// Image décodée : plans YUV (conversion faite par `rdp-gfx`) ou RGBA déjà converti.
pub enum Decoded {
    Yuv(Planes),
    Rgba { width: u32, height: u32, data: Vec<u8> },
}

/// Plans YUV420 copiés hors du GPU (u et v séparés, même pour une source NV12).
pub struct Planes {
    pub width: u32,
    pub height: u32,
    pub y: Vec<u8>,
    pub u: Vec<u8>,
    pub v: Vec<u8>,
    pub y_stride: u32,
    pub uv_stride: u32,
}

impl Planes {
    pub fn view(&self) -> rdp_gfx::Yuv420<'_> {
        rdp_gfx::Yuv420 {
            width: self.width,
            height: self.height,
            y: &self.y,
            u: &self.u,
            v: &self.v,
            y_stride: self.y_stride,
            uv_stride: self.uv_stride,
        }
    }
}

type Slot = Rc<RefCell<Option<oneshot::Sender<Result<VideoFrame, String>>>>>;

pub struct H264 {
    decoder: VideoDecoder,
    slot: Slot,
    codec: Option<String>,
    timestamp: i32,
    _output: Closure<dyn FnMut(VideoFrame)>,
    _error: Closure<dyn FnMut(JsValue)>,
}

/// Unités NAL d'un flux Annex B : (type, octets sans le code de début).
fn nal_units(data: &[u8]) -> Vec<(u8, &[u8])> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            starts.push(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }
    starts
        .iter()
        .enumerate()
        .filter_map(|(k, &s)| {
            let mut end = starts.get(k + 1).map_or(data.len(), |n| n - 3);
            // Code de début sur 4 octets : le zéro de tête appartient au suivant.
            if k + 1 < starts.len() && end > s && data[end - 1] == 0 {
                end -= 1;
            }
            (s < end).then(|| (data[s] & 0x1F, &data[s..end]))
        })
        .collect()
}

/// Chaîne de codec WebCodecs (« avc1.PPCCLL ») tirée du SPS.
fn codec_string(data: &[u8]) -> Option<String> {
    let (_, sps) = nal_units(data).into_iter().find(|(t, n)| *t == 7 && n.len() >= 4)?;
    Some(format!("avc1.{:02X}{:02X}{:02X}", sps[1], sps[2], sps[3]))
}

/// H.264 à annoncer au serveur : rien sans décodeur ni pour un navigateur dont le décodeur a échoué.
pub async fn support() -> Avc {
    if disabled() || !decoder_available().await {
        return Avc::Off;
    }
    Avc::Full
}

async fn decoder_available() -> bool {
    let Ok(ctor) = js_sys::Reflect::get(&js_sys::global(), &"VideoDecoder".into()) else { return false };
    if ctor.is_undefined() {
        return false;
    }
    let config = VideoDecoderConfig::new("avc1.640028");
    match JsFuture::from(VideoDecoder::is_config_supported(&config)).await {
        Ok(v) => {
            js_sys::Reflect::get(&v, &"supported".into()).ok().and_then(|s| s.as_bool()).unwrap_or(false)
        }
        Err(_) => false,
    }
}

impl H264 {
    pub fn new() -> Result<Self, String> {
        let slot: Slot = Rc::new(RefCell::new(None));
        let s = slot.clone();
        let output =
            Closure::<dyn FnMut(VideoFrame)>::new(move |frame: VideoFrame| match s.borrow_mut().take() {
                Some(tx) => {
                    let _ = tx.send(Ok(frame));
                }
                None => frame.close(),
            });
        let s = slot.clone();
        let error = Closure::<dyn FnMut(JsValue)>::new(move |e: JsValue| {
            let msg = e
                .dyn_ref::<js_sys::Error>()
                .map(|e| String::from(e.message()))
                .unwrap_or_else(|| "erreur du décodeur".into());
            if let Some(tx) = s.borrow_mut().take() {
                let _ = tx.send(Err(msg));
            }
        });
        let init = VideoDecoderInit::new(error.as_ref().unchecked_ref(), output.as_ref().unchecked_ref());
        let decoder = VideoDecoder::new(&init).map_err(|e| format!("{e:?}"))?;
        Ok(Self { decoder, slot, codec: None, timestamp: 0, _output: output, _error: error })
    }

    fn configure(&mut self, codec: &str) -> Result<(), String> {
        if self.decoder.state() == web_sys::CodecState::Closed {
            *self = Self::new()?;
        }
        let config = VideoDecoderConfig::new(codec);
        config.set_optimize_for_latency(true);
        config.set_hardware_acceleration(HardwareAcceleration::NoPreference);
        // Windows encode en BT.709 pleine plage (MS-RDPEGFX 3.3.8.3.1) ; le flux ne le dit pas
        // toujours. Sans effet sur les plans YUV copiés, mais juste pour une conversion RGB du
        // navigateur.
        let cs = VideoColorSpaceInit::new();
        cs.set_full_range(Some(true));
        cs.set_matrix(Some(VideoMatrixCoefficients::Bt709));
        cs.set_primaries(Some(VideoColorPrimaries::Bt709));
        cs.set_transfer(Some(VideoTransferCharacteristics::Bt709));
        config.set_color_space(&cs);
        self.decoder.configure(&config).map_err(|e| format!("configuration H.264 : {e:?}"))?;
        self.codec = Some(codec.to_owned());
        Ok(())
    }

    /// Décode une image Annex B et renvoie ses plans.
    pub async fn decode(&mut self, data: &[u8]) -> Result<Decoded, DecodeError> {
        let key = nal_units(data).iter().any(|(t, _)| *t == 5);
        if key
            && let Some(codec) = codec_string(data)
            && self.codec.as_deref() != Some(&codec)
        {
            self.configure(&codec).map_err(DecodeError::Unusable)?;
        }
        if self.codec.is_none() || self.decoder.state() != web_sys::CodecState::Configured {
            return Err(DecodeError::Transient("en attente d'une image clé".into()));
        }
        let (tx, rx) = oneshot::channel();
        *self.slot.borrow_mut() = Some(tx);
        let bytes = Uint8Array::from(data);
        let kind = if key { EncodedVideoChunkType::Key } else { EncodedVideoChunkType::Delta };
        self.timestamp = self.timestamp.wrapping_add(16_667);
        let init = EncodedVideoChunkInit::new(&bytes, self.timestamp, kind);
        let chunk = EncodedVideoChunk::new(&init).map_err(|e| DecodeError::Transient(format!("{e:?}")))?;
        if let Err(e) = self.decoder.decode(&chunk) {
            self.codec = None;
            return Err(DecodeError::Transient(format!("décodage refusé : {e:?}")));
        }
        // Un décodeur qui garde les images en tampon (attendant les suivantes) bloquerait tout le
        // pipeline EGFX, qui attend chaque image : au-delà du délai, il est déclaré inexploitable.
        let frame = match within(OUTPUT_TIMEOUT_MS, rx).await {
            Some(Ok(Ok(f))) => f,
            Some(Ok(Err(e))) => {
                self.codec = None;
                return Err(DecodeError::Unusable(e));
            }
            Some(Err(_)) => return Err(DecodeError::Transient("image perdue".into())),
            None => {
                return Err(DecodeError::Unusable(format!(
                    "aucune image rendue par le décodeur en {OUTPUT_TIMEOUT_MS} ms (images gardées en tampon)"
                )));
            }
        };
        let planes = within(OUTPUT_TIMEOUT_MS, copy_planes(&frame)).await;
        frame.close();
        planes
            .unwrap_or_else(|| Err(format!("copie de l'image bloquée plus de {OUTPUT_TIMEOUT_MS} ms")))
            .map_err(DecodeError::Unusable)
    }
}

/// Délai maximal entre l'envoi d'une image au décodeur et sa sortie (puis sa copie).
const OUTPUT_TIMEOUT_MS: i32 = 1500;

/// `fut`, ou `None` s'il n'aboutit pas en `ms` millisecondes.
async fn within<F: std::future::Future>(ms: i32, fut: F) -> Option<F::Output> {
    let timer = JsFuture::from(js_sys::Promise::new(&mut |resolve, _| {
        if let Some(w) = web_sys::window() {
            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        }
    }));
    match futures::future::select(std::pin::pin!(fut), timer).await {
        futures::future::Either::Left((v, _)) => Some(v),
        futures::future::Either::Right(_) => None,
    }
}

impl Drop for H264 {
    fn drop(&mut self) {
        let _ = self.decoder.close();
    }
}

async fn copy_planes(frame: &VideoFrame) -> Result<Decoded, String> {
    let rect = frame.visible_rect().ok_or("image sans zone visible")?;
    let (width, height) = (rect.width() as u32, rect.height() as u32);
    let format = frame.format().ok_or("format d'image inconnu")?;
    let size = frame.allocation_size().map_err(|e| format!("{e:?}"))?;
    let buf = Uint8Array::new_with_length(size);
    let layouts =
        JsFuture::from(frame.copy_to_with_u8_array(&buf)).await.map_err(|e| format!("copie : {e:?}"))?;
    let layouts: Array = layouts.unchecked_into();
    let plane = |i: u32| -> (u32, u32) {
        let l: PlaneLayout = layouts.get(i).unchecked_into();
        (l.get_offset(), l.get_stride())
    };
    let data = buf.to_vec();
    let (cw, ch) = (width.div_ceil(2), height.div_ceil(2));
    let slice = |off: u32, stride: u32, rows: u32| -> Result<Vec<u8>, String> {
        let end = off as usize + (stride * rows) as usize;
        data.get(off as usize..end).map(<[u8]>::to_vec).ok_or_else(|| "plan tronqué".into())
    };
    match format {
        VideoPixelFormat::I420 | VideoPixelFormat::I420a => {
            let ((yo, ys), (uo, us), (vo, vs)) = (plane(0), plane(1), plane(2));
            if us != vs {
                return Err("plans U et V de pas différents".into());
            }
            Ok(Decoded::Yuv(Planes {
                width,
                height,
                y: slice(yo, ys, height)?,
                u: slice(uo, us, ch)?,
                v: slice(vo, vs, ch)?,
                y_stride: ys,
                uv_stride: us,
            }))
        }
        VideoPixelFormat::Nv12 => {
            let ((yo, ys), (uvo, uvs)) = (plane(0), plane(1));
            let uv = slice(uvo, uvs, ch)?;
            let (mut u, mut v) = (vec![0u8; (cw * ch) as usize], vec![0u8; (cw * ch) as usize]);
            for row in 0..ch as usize {
                for col in 0..cw as usize {
                    let s = row * uvs as usize + col * 2;
                    u[row * cw as usize + col] = uv[s];
                    v[row * cw as usize + col] = uv[s + 1];
                }
            }
            Ok(Decoded::Yuv(Planes {
                width,
                height,
                y: slice(yo, ys, height)?,
                u,
                v,
                y_stride: ys,
                uv_stride: cw,
            }))
        }
        VideoPixelFormat::Rgba | VideoPixelFormat::Rgbx | VideoPixelFormat::Bgra | VideoPixelFormat::Bgrx => {
            let bgr = matches!(format, VideoPixelFormat::Bgra | VideoPixelFormat::Bgrx);
            let (o, stride) = plane(0);
            let src = slice(o, stride, height)?;
            let mut out = vec![0u8; (width * height * 4) as usize];
            for (row, dst) in out.chunks_exact_mut((width * 4) as usize).enumerate() {
                let line = &src[row * stride as usize..][..(width * 4) as usize];
                for (d, s) in dst.as_chunks_mut::<4>().0.iter_mut().zip(line.as_chunks::<4>().0) {
                    *d = if bgr { [s[2], s[1], s[0], 0xFF] } else { [s[0], s[1], s[2], 0xFF] };
                }
            }
            Ok(Decoded::Rgba { width, height, data: out })
        }
        other => Err(format!("format d'image non géré : {other:?}")),
    }
}
