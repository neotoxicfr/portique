//! Presse-papier du navigateur ↔ `rdp-clip` (texte, HTML, images).
//!
//! L'API Clipboard du navigateur est asynchrone et soumise au focus : on lit le presse-papier
//! local au retour du focus et juste avant un Ctrl+V transmis au PC ; on écrit ce que Windows a
//! copié dès qu'il l'annonce (et on réessaie au prochain geste si la page n'avait pas le focus).

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

/// Ordre de préférence des formats demandés au serveur.
pub fn wanted(formats: &[ClipFormat]) -> Vec<ClipFormat> {
    if formats.contains(&ClipFormat::Png) {
        return vec![ClipFormat::Png];
    }
    if formats.contains(&ClipFormat::Dib) {
        return vec![ClipFormat::Dib];
    }
    [ClipFormat::Text, ClipFormat::Html].into_iter().filter(|f| formats.contains(f)).collect()
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

/// Écrit dans le presse-papier local ce que Windows a copié.
pub async fn write_local(items: &[LocalData]) -> Result<(), String> {
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

/// Empreinte légère du contenu, pour ne pas renvoyer au PC ce qu'il a déjà.
pub fn fingerprint(items: &[LocalData]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |b: &[u8]| {
        for x in b {
            h = (h ^ *x as u64).wrapping_mul(0x0100_0000_01b3);
        }
    };
    for i in items {
        match i {
            LocalData::Text(t) => eat(t.as_bytes()),
            LocalData::Html(t) => eat(t.as_bytes()),
            LocalData::Png(p) => eat(p),
            LocalData::Rgba { rgba, .. } => eat(&rgba[..rgba.len().min(4096)]),
        }
    }
    h
}
