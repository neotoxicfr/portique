//! Rejoue un enregistrement EGFX (`PORTIQUE_PROBE_DUMP`) dans `rdp-gfx`, écrit le PNG final et
//! liste les commandes qui touchent un point donné (diagnostic de rendu).
//!
//! Usage : gfx-replay <dump> <sortie.png> [x y]

use std::io::Read;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(args.len() >= 3, "usage : gfx-replay <dump> <sortie.png> [x y]");
    let mut raw = Vec::new();
    std::fs::File::open(&args[1])?.read_to_end(&mut raw)?;
    let probe: Option<(u32, u32)> =
        (args.len() >= 5).then(|| (args[3].parse().unwrap(), args[4].parse().unwrap()));
    let mut gfx = rdp_gfx::Gfx::new();
    let mut zgfx = rdp_codecs::zgfx::Zgfx::new();
    let (mut rest, mut n) = (&raw[..], 0u32);
    let mut last: Option<[u8; 3]> = None;
    while rest.len() >= 4 {
        let len = u32::from_le_bytes(rest[..4].try_into()?) as usize;
        let msg = &rest[4..4 + len];
        rest = &rest[4 + len..];
        n += 1;
        if let Some((px, py)) = probe {
            // Décompression parallèle pour journaliser les PDU qui couvrent le point.
            let mut pdus = Vec::new();
            zgfx.decompress(msg, &mut pdus).map_err(|e| anyhow::anyhow!("{e}"))?;
            let mut p = &pdus[..];
            while p.len() >= 8 {
                let id = u16::from_le_bytes([p[0], p[1]]);
                let l = u32::from_le_bytes(p[4..8].try_into()?) as usize;
                if id == 0x0001 && l >= 25 {
                    let r = |o: usize| u16::from_le_bytes([p[o], p[o + 1]]) as u32;
                    let (codec, x0, y0, x1, y1) = (r(10), r(13), r(15), r(17), r(19));
                    if (x0..x1).contains(&px) && (y0..y1).contains(&py) {
                        println!("msg {n} : WireToSurface1 codec 0x{codec:02x} ({x0},{y0})-({x1},{y1})");
                    }
                } else if id == 0x0002 {
                    println!(
                        "msg {n} : WireToSurface2 surface {} ctx {} ({} o)",
                        u16::from_le_bytes([p[8], p[9]]),
                        u32::from_le_bytes(p[12..16].try_into()?),
                        l
                    );
                } else if id == 0x0004 {
                    let r = |o: usize| u16::from_le_bytes([p[o], p[o + 1]]) as u32;
                    for k in 0..r(14) as usize {
                        let b = 16 + k * 8;
                        let (x0, y0, x1, y1) = (r(b), r(b + 2), r(b + 4), r(b + 6));
                        if (x0..x1).contains(&px) && (y0..y1).contains(&py) {
                            println!("msg {n} : SolidFill BGRA {:?} ({x0},{y0})-({x1},{y1})", &p[10..14]);
                        }
                    }
                } else if id == 0x0007 {
                    let r = |o: usize| u16::from_le_bytes([p[o], p[o + 1]]) as u32;
                    for k in 0..r(12) as usize {
                        let (x, y) = (r(14 + k * 4), r(16 + k * 4));
                        if (x..x + 64).contains(&px) && (y..y + 64).contains(&py) {
                            println!(
                                "msg {n} : CacheToSurface slot {} en ({x},{y}) (taille inconnue ici)",
                                r(8)
                            );
                        }
                    }
                } else if id == 0x0005 {
                    let r = |o: usize| u16::from_le_bytes([p[o], p[o + 1]]) as u32;
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
                    let r = |o: usize| u16::from_le_bytes([p[o], p[o + 1]]) as u32;
                    println!("msg {n} : CreateSurface {} {}×{} fmt 0x{:02x}", r(8), r(10), r(12), p[14]);
                } else if id == 0x0006 || id == 0x000B || id == 0x000C {
                } else if id == 0x0003 {
                    println!(
                        "msg {n} : DeleteEncodingContext surface {} ctx {}",
                        u16::from_le_bytes([p[8], p[9]]),
                        u32::from_le_bytes(p[10..14].try_into()?)
                    );
                }
                p = &p[l..];
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
            let (rgba, w, _) = gfx.output();
            let o = ((py * w + px) * 4) as usize;
            if rgba.len() > o + 4 {
                let v = [rgba[o], rgba[o + 1], rgba[o + 2]];
                if Some(v) != last {
                    println!("  après msg {n} : pixel = {v:?}");
                    last = Some(v);
                }
            }
        }
    }
    let (rgba, w, h) = gfx.output();
    if let Some((px, py)) = probe {
        let o = ((py * w + px) * 4) as usize;
        println!("pixel ({px},{py}) = {:?}", &rgba[o..o + 4]);
    }
    let mut enc = png::Encoder::new(std::io::BufWriter::new(std::fs::File::create(&args[2])?), w, h);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header()?.write_image_data(rgba)?;
    println!("{n} messages rejoués → {} ({w}×{h})", args[2]);
    Ok(())
}
