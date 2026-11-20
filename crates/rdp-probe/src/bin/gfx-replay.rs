//! Rejoue un enregistrement EGFX (`PORTIQUE_PROBE_DUMP`) dans `rdp-gfx`, écrit le PNG final et
//! liste les commandes qui touchent un point donné (diagnostic de rendu).
//!
//! Usage : gfx-replay <dump> <sortie.png> [x y]

use std::io::Read;

const USAGE: &str = "usage : gfx-replay <dump> <sortie.png> [x y]";

/// Pixel (x, y) d'une sortie RGBA `w`×`h`, s'il est dans l'image.
fn pixel(rgba: &[u8], w: u32, h: u32, x: u32, y: u32) -> Option<[u8; 4]> {
    if x >= w || y >= h {
        return None;
    }
    let o = (y as usize * w as usize + x as usize) * 4;
    rgba.get(o..o + 4)?.try_into().ok()
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(args.len() == 3 || args.len() == 5, USAGE);
    let mut raw = Vec::new();
    std::fs::File::open(&args[1])?.read_to_end(&mut raw)?;
    let probe: Option<(u32, u32)> = match &args[3..] {
        [x, y] => Some((
            x.parse().map_err(|_| anyhow::anyhow!("x invalide ; {USAGE}"))?,
            y.parse().map_err(|_| anyhow::anyhow!("y invalide ; {USAGE}"))?,
        )),
        _ => None,
    };
    let mut gfx = rdp_gfx::Gfx::new();
    let mut zgfx = rdp_codecs::zgfx::Zgfx::new();
    let (mut rest, mut n) = (&raw[..], 0u32);
    let mut last: Option<[u8; 3]> = None;
    // Enregistrements « longueur u32 LE + message » ; seule une fin pile entre deux est normale.
    while !rest.is_empty() {
        n += 1;
        let Some((prefix, body)) = rest.split_first_chunk::<4>() else {
            anyhow::bail!("enregistrement {n} : préfixe de longueur tronqué");
        };
        let len = u32::from_le_bytes(*prefix) as usize;
        anyhow::ensure!(len <= body.len(), "enregistrement {n} : {len} o annoncés, {} présents", body.len());
        let (msg, tail) = body.split_at(len);
        rest = tail;
        if let Some((px, py)) = probe {
            // Décompression parallèle pour journaliser les PDU qui couvrent le point.
            let mut pdus = Vec::new();
            zgfx.decompress(msg, &mut pdus).map_err(|e| anyhow::anyhow!("{e}"))?;
            let mut rest_pdus = &pdus[..];
            while rest_pdus.len() >= 8 {
                let l = u32::from_le_bytes(rest_pdus[4..8].try_into()?) as usize;
                // PDU isolée avant lecture : ses champs ne débordent pas sur la suivante.
                anyhow::ensure!((8..=rest_pdus.len()).contains(&l), "msg {n} : longueur de PDU {l} invalide");
                let (p, next) = rest_pdus.split_at(l);
                rest_pdus = next;
                let id = u16::from_le_bytes([p[0], p[1]]);
                // Lectures bornées : 0 au-delà de la PDU.
                let r = |o: usize| p.get(o..o + 2).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]) as u32);
                let r32 = |o: usize| p.get(o..o + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
                if id == 0x0001 && l >= 25 {
                    let (codec, x0, y0, x1, y1) = (r(10), r(13), r(15), r(17), r(19));
                    if (x0..x1).contains(&px) && (y0..y1).contains(&py) {
                        println!("msg {n} : WireToSurface1 codec 0x{codec:02x} ({x0},{y0})-({x1},{y1})");
                    }
                } else if id == 0x0002 {
                    println!("msg {n} : WireToSurface2 surface {} ctx {} ({} o)", r(8), r32(12), l);
                } else if id == 0x0004 {
                    // Rectangles au-delà de la PDU ignorés.
                    for k in 0..(r(14) as usize).min(l.saturating_sub(16) / 8) {
                        let b = 16 + k * 8;
                        let (x0, y0, x1, y1) = (r(b), r(b + 2), r(b + 4), r(b + 6));
                        if (x0..x1).contains(&px) && (y0..y1).contains(&py) {
                            println!("msg {n} : SolidFill BGRA {:?} ({x0},{y0})-({x1},{y1})", p.get(10..14));
                        }
                    }
                } else if id == 0x0007 {
                    for k in 0..(r(12) as usize).min(l.saturating_sub(14) / 4) {
                        let (x, y) = (r(14 + k * 4), r(16 + k * 4));
                        if (x..x + 64).contains(&px) && (y..y + 64).contains(&py) {
                            println!(
                                "msg {n} : CacheToSurface slot {} en ({x},{y}) (taille inconnue ici)",
                                r(8)
                            );
                        }
                    }
                } else if id == 0x0005 {
                    println!(
                        "msg {n} : SurfaceToSurface {} → {} ({},{})-({},{}) vers ({},{})",
                        r(8),
                        r(10),
                        r(12),
                        r(14),
                        r(16),
                        r(18),
                        r(22),
                        r(24)
                    );
                } else if id == 0x0009 {
                    let fmt = p.get(14).copied().unwrap_or(0);
                    println!("msg {n} : CreateSurface {} {}×{} fmt 0x{fmt:02x}", r(8), r(10), r(12));
                } else if id == 0x0006 || id == 0x000B || id == 0x000C {
                } else if id == 0x0003 {
                    println!("msg {n} : DeleteEncodingContext surface {} ctx {}", r(8), r32(10));
                }
            }
        }
        let mut outs: std::collections::VecDeque<_> =
            gfx.process(msg).map_err(|e| anyhow::anyhow!("msg {n} : {e}"))?.into();
        while let Some(o) = outs.pop_front() {
            if let rdp_gfx::Out::Avc420 { .. } | rdp_gfx::Out::Avc444 { .. } = o {
                outs.extend(gfx.skip_frame().map_err(|e| anyhow::anyhow!("{e}"))?);
            }
        }
        if let Some((px, py)) = probe {
            let (rgba, w, h) = gfx.output();
            if let Some([r, g, b, _]) = pixel(rgba, w, h, px, py) {
                let v = [r, g, b];
                if Some(v) != last {
                    println!("  après msg {n} : pixel = {v:?}");
                    last = Some(v);
                }
            }
        }
    }
    let (rgba, w, h) = gfx.output();
    if let Some((px, py)) = probe {
        match pixel(rgba, w, h, px, py) {
            Some(v) => println!("pixel ({px},{py}) = {v:?}"),
            None => println!("pixel ({px},{py}) hors de l'image {w}×{h}"),
        }
    }
    let mut enc = png::Encoder::new(std::io::BufWriter::new(std::fs::File::create(&args[2])?), w, h);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header()?.write_image_data(rgba)?;
    println!("{n} messages rejoués → {} ({w}×{h})", args[2]);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn pixel_checks_both_axes() {
        let rgba: Vec<u8> = (0..2 * 2 * 4).collect();
        assert_eq!(super::pixel(&rgba, 2, 2, 1, 1), Some([12, 13, 14, 15]), "dernier pixel");
        assert_eq!(super::pixel(&rgba, 2, 2, 2, 0), None, "hors de la ligne");
        assert_eq!(super::pixel(&rgba, 2, 2, 0, 2), None);
    }
}
