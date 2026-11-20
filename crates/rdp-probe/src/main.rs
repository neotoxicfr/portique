//! Sonde RDP : connexion authentifiée (rdp-connect), session complète (rdp-session), rendu EGFX
//! (rdp-gfx) et capture PNG du bureau.
//!
//! Variables : PORTIQUE_PROBE_HOST, PORTIQUE_PROBE_PORT (3389), PORTIQUE_PROBE_USER,
//! PORTIQUE_PROBE_DOMAIN (vide), PORTIQUE_PROBE_PASSWORD ou PORTIQUE_PROBE_PASSWORD_FILE,
//! PORTIQUE_PROBE_SECONDS (8), PORTIQUE_PROBE_PNG (chemin de capture), PORTIQUE_PROBE_PIN (empreinte). Le mot de passe n'est
//! jamais affiché.

use std::time::Duration;

use anyhow::{Context, bail};
use rdp_auth::ntlm::Credentials;
use rdp_connect::{Target, read_frame};
use rdp_pdu::x224;
use rdp_session::{Config, Event, Session};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

fn env(name: &str) -> Option<String> {
    std::env::var(format!("PORTIQUE_PROBE_{name}")).ok().filter(|v| !v.is_empty())
}

fn password() -> anyhow::Result<String> {
    match (env("PASSWORD"), env("PASSWORD_FILE")) {
        (Some(_), Some(_)) => {
            bail!("PORTIQUE_PROBE_PASSWORD et PORTIQUE_PROBE_PASSWORD_FILE définis tous les deux")
        }
        (Some(p), None) => Ok(p),
        (None, Some(path)) => {
            let raw = std::fs::read_to_string(&path).with_context(|| format!("lecture de {path}"))?;
            Ok(raw.trim_end_matches(['\n', '\r']).to_owned())
        }
        (None, None) => bail!("PORTIQUE_PROBE_PASSWORD(_FILE) manquant"),
    }
}

async fn send<S: AsyncWrite + Unpin>(s: &mut S, data: &[u8]) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), s.write_all(data)).await.context("délai dépassé")??;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let host = env("HOST").context("PORTIQUE_PROBE_HOST manquant")?;
    let port: u16 = env("PORT").map(|p| p.parse()).transpose()?.unwrap_or(3389);
    let user = env("USER").context("PORTIQUE_PROBE_USER manquant")?;
    let domain = env("DOMAIN").unwrap_or_default();
    let target = Target {
        host: host.clone(),
        port,
        credentials: Credentials { username: user.clone(), domain, password: password()? },
    };
    println!("→ connexion à {host}:{port}");
    // PORTIQUE_PROBE_PIN : empreinte SHA-256 attendue ; sans elle, la sonde s'arrête avant NLA et
    // affiche l'empreinte à vérifier.
    let pin = env("PIN")
        .map(|h| {
            (0..h.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&h[i..i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()
        })
        .transpose()?
        .map(|v| {
            <[u8; 32]>::try_from(v).map_err(|_| anyhow::anyhow!("PORTIQUE_PROBE_PIN : 64 caractères hexa"))
        })
        .transpose()?;
    let mut c = rdp_connect::connect(&target, pin).await?;
    println!(
        "✓ NLA réussie pour {user} ({}, drapeaux 0x{:02x}), certificat SHA-256 {}",
        x224::protocol_name(c.selected_protocol),
        c.negotiation_flags,
        rdp_connect::hex(&c.cert_sha256)
    );
    run_session(&mut c.stream, &user, c.selected_protocol).await?;
    let _ = c.stream.shutdown().await;
    Ok(())
}

/// Session complète après NLA : séquence de connexion, EGFX rendu par `rdp-gfx` pendant
/// PORTIQUE_PROBE_SECONDS (8 par défaut), puis capture PNG du bureau dans PORTIQUE_PROBE_PNG.
async fn run_session<S: AsyncRead + AsyncWrite + Unpin>(
    tls: &mut S,
    user: &str,
    selected_protocol: u32,
) -> anyhow::Result<()> {
    let seconds: u64 = env("SECONDS").map(|s| s.parse()).transpose()?.unwrap_or(8);
    let mut session = Session::new(Config {
        width: 1920,
        height: 1080,
        keyboard_layout: 0x040C,
        client_name: "portique".into(),
        selected_protocol,
        username: user.into(),
        domain: String::new(),
        display_control: true,
    });
    send(tls, &session.start()).await?;
    let mut buf = Vec::new();
    let mut gfx = rdp_gfx::Gfx::new();
    let mut clip = rdp_clip::Clipboard::new();
    let clip_test = env("CLIPTEST").is_some();
    let mut clip_started = false;
    // PORTIQUE_PROBE_DUMP : enregistre les messages EGFX bruts (longueur u32 + octets) pour le rejeu
    // hors ligne (`gfx-replay`). Contient l'écran : à garder hors du dépôt.
    let mut dump = env("DUMP").map(std::fs::File::create).transpose()?.map(std::io::BufWriter::new);
    let mut ignored = std::collections::BTreeMap::<String, u32>::new();
    let (mut frames, mut avc) = (0u32, 0u32);
    let t0 = std::time::Instant::now();
    let mut deadline: Option<tokio::time::Instant> = None;
    'outer: loop {
        let frame = match deadline {
            Some(d) => match tokio::time::timeout_at(d, read_frame(tls, &mut buf, x224::frame_len)).await {
                Ok(f) => f?,
                Err(_) => break,
            },
            None => read_frame(tls, &mut buf, x224::frame_len).await?,
        };
        for ev in session.feed(&frame).map_err(|e| anyhow::anyhow!("session : {e}"))? {
            match ev {
                Event::Send(b) => send(tls, &b).await?,
                Event::Connected { width, height } => {
                    println!("✓ session active, bureau {width}×{height} ({} ms)", t0.elapsed().as_millis());
                    deadline = Some(tokio::time::Instant::now() + Duration::from_secs(seconds));
                }
                Event::DvcData { channel_id, data }
                    if session.dvc_name(channel_id) == Some(rdp_session::DVC_DISPLAY_CONTROL) =>
                {
                    println!("  DisplayControl : capacités reçues ({} o)", data.len());
                    if let Some(spec) = env("MONITORS") {
                        // « 1920x1080,1280x1024 » : écrans côte à côte, le premier principal.
                        let mons: Vec<(u32, u32)> = spec
                            .split(',')
                            .filter_map(|m| {
                                m.split_once('x').and_then(|(w, h)| Some((w.parse().ok()?, h.parse().ok()?)))
                            })
                            .collect();
                        let mut p = Vec::new();
                        p.extend_from_slice(&2u32.to_le_bytes());
                        p.extend_from_slice(&((16 + 40 * mons.len()) as u32).to_le_bytes());
                        p.extend_from_slice(&40u32.to_le_bytes());
                        p.extend_from_slice(&(mons.len() as u32).to_le_bytes());
                        let mut left = 0i32;
                        for (i, (w, h)) in mons.iter().enumerate() {
                            for v in
                                [if i == 0 { 1u32 } else { 0 }, left as u32, 0, *w, *h, 0, 0, 0, 100, 100]
                            {
                                p.extend_from_slice(&v.to_le_bytes());
                            }
                            left += *w as i32;
                        }
                        for f in session.dvc_send(channel_id, &p) {
                            send(tls, &f).await?;
                        }
                        println!("  → disposition envoyée : {mons:?}");
                    }
                }
                Event::DvcOpened { channel_id, name } => {
                    println!("  canal dynamique ouvert : {name} (#{channel_id})");
                    if name == rdp_session::DVC_GRAPHICS {
                        for f in session.dvc_send(channel_id, &rdp_gfx::caps_advertise(rdp_gfx::Avc::Full)) {
                            send(tls, &f).await?;
                        }
                    }
                }
                Event::DvcData { channel_id, data }
                    if session.dvc_name(channel_id) == Some(rdp_session::DVC_GRAPHICS) =>
                {
                    if let Some(f) = dump.as_mut() {
                        use std::io::Write;
                        f.write_all(&(data.len() as u32).to_le_bytes())?;
                        f.write_all(&data)?;
                    }
                    let mut queue: std::collections::VecDeque<rdp_gfx::Out> =
                        gfx.process(&data).map_err(|e| anyhow::anyhow!("{e}"))?.into();
                    while let Some(o) = queue.pop_front() {
                        match o {
                            rdp_gfx::Out::Send(m) => {
                                for f in session.dvc_send(channel_id, &m) {
                                    send(tls, &f).await?;
                                }
                            }
                            rdp_gfx::Out::Present { .. } => frames += 1,
                            rdp_gfx::Out::Reset { width, height, .. } => {
                                println!("  EGFX : sortie {width}×{height}")
                            }
                            rdp_gfx::Out::Avc420 { .. } | rdp_gfx::Out::Avc444 { .. } => {
                                // Pas de décodeur H.264 natif dans la sonde : image sautée.
                                avc += 1;
                                queue.extend(gfx.skip_frame().map_err(|e| anyhow::anyhow!("{e}"))?);
                            }
                            rdp_gfx::Out::Ignored(t) => {
                                *ignored.entry(t.split(" (").next().unwrap_or(&t).to_owned()).or_default() +=
                                    1
                            }
                        }
                    }
                }
                Event::ServerError(t) => {
                    println!("✗ erreur serveur : {t}");
                    break 'outer;
                }
                Event::Disconnected(t) => {
                    println!("✗ {t}");
                    break 'outer;
                }
                Event::Clipboard(msg) => {
                    let kind = u16::from_le_bytes([msg[0], msg[1]]);
                    println!("  {:>6} ms cliprdr ← type {kind} ({} o)", t0.elapsed().as_millis(), msg.len());
                    for ev in clip.receive(&msg).map_err(|e| anyhow::anyhow!("{e:?}"))? {
                        match ev {
                            rdp_clip::ClipEvent::Send(m) => {
                                println!(
                                    "  {:>6} ms cliprdr → type {}",
                                    t0.elapsed().as_millis(),
                                    u16::from_le_bytes([m[0], m[1]])
                                );
                                for f in session.static_send(rdp_session::CLIPRDR, &m) {
                                    send(tls, &f).await?;
                                }
                            }
                            rdp_clip::ClipEvent::RemoteChanged(f) => {
                                println!("  le PC propose {f:?}");
                                for ev in clip.request(&[rdp_clip::ClipFormat::Text]) {
                                    if let rdp_clip::ClipEvent::Send(m) = ev {
                                        for fr in session.static_send(rdp_session::CLIPRDR, &m) {
                                            send(tls, &fr).await?;
                                        }
                                    }
                                }
                            }
                            rdp_clip::ClipEvent::RemoteData(d) => println!("  données du PC : {d:?}"),
                        }
                    }
                    if env("DRAG").is_some() && !clip_started && kind == 1 {
                        clip_started = true;
                        // Win+R puis glisser la boîte Exécuter en cercles : du mouvement continu,
                        // pour voir si Windows passe des zones en H.264.
                        use rdp_pdu::fastpath::{Input, kbd, ptr};
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        let k = |code: u8, ext: bool, up: bool| Input::Scancode {
                            code,
                            flags: if ext { kbd::EXTENDED } else { 0 } | if up { kbd::RELEASE } else { 0 },
                        };
                        send(
                            tls,
                            &session.input(&[
                                k(0x5B, true, false),
                                k(0x13, false, false),
                                k(0x13, false, true),
                                k(0x5B, true, true),
                            ]),
                        )
                        .await?;
                        tokio::time::sleep(Duration::from_millis(1500)).await;
                        let (mut x, mut y) = (120u16, 830u16);
                        send(tls, &session.input(&[Input::Mouse { flags: ptr::MOVE, x, y }])).await?;
                        send(tls, &session.input(&[Input::Mouse { flags: ptr::BUTTON1 | ptr::DOWN, x, y }]))
                            .await?;
                        for i in 0..240u32 {
                            let a = i as f32 / 20.0;
                            x = (900.0 + 500.0 * a.cos()) as u16;
                            y = (500.0 + 300.0 * a.sin()) as u16;
                            send(tls, &session.input(&[Input::Mouse { flags: ptr::MOVE, x, y }])).await?;
                            tokio::time::sleep(Duration::from_millis(16)).await;
                            // Lecture opportuniste pour ne pas bloquer le serveur (accusés d'image).
                            while let Ok(Ok(f)) = tokio::time::timeout(
                                Duration::from_millis(1),
                                read_frame(tls, &mut buf, x224::frame_len),
                            )
                            .await
                            {
                                for ev in session.feed(&f).map_err(|e| anyhow::anyhow!("session : {e}"))? {
                                    if let Event::DvcData { channel_id, ref data } = ev
                                        && session.dvc_name(channel_id) == Some(rdp_session::DVC_GRAPHICS)
                                    {
                                        let mut q: std::collections::VecDeque<rdp_gfx::Out> =
                                            gfx.process(data).map_err(|e| anyhow::anyhow!("{e}"))?.into();
                                        while let Some(o) = q.pop_front() {
                                            match o {
                                                rdp_gfx::Out::Send(m) => {
                                                    for fr in session.dvc_send(channel_id, &m) {
                                                        send(tls, &fr).await?;
                                                    }
                                                }
                                                rdp_gfx::Out::Avc420 { .. } | rdp_gfx::Out::Avc444 { .. } => {
                                                    avc += 1;
                                                    q.extend(
                                                        gfx.skip_frame()
                                                            .map_err(|e| anyhow::anyhow!("{e}"))?,
                                                    );
                                                }
                                                rdp_gfx::Out::Present { .. } => frames += 1,
                                                _ => {}
                                            }
                                        }
                                    } else if let Event::Send(b) = ev {
                                        send(tls, &b).await?;
                                    }
                                }
                            }
                        }
                        send(tls, &session.input(&[Input::Mouse { flags: ptr::BUTTON1, x, y }])).await?;
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        send(tls, &session.input(&[k(0x01, false, false), k(0x01, false, true)])).await?;
                        println!("  glisser terminé : {frames} images, {avc} H.264");
                    }
                    if clip_test && !clip_started && kind == 1 {
                        clip_started = true;
                        // Win+R, « abc », Ctrl+A, Ctrl+C (scancodes), avec des pauses.
                        use rdp_pdu::fastpath::{Input, kbd};
                        let k = |code: u8, ext: bool, up: bool| Input::Scancode {
                            code,
                            flags: if ext { kbd::EXTENDED } else { 0 } | if up { kbd::RELEASE } else { 0 },
                        };
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        let steps: Vec<Vec<Input>> = vec![
                            vec![
                                k(0x5B, true, false),
                                k(0x13, false, false),
                                k(0x13, false, true),
                                k(0x5B, true, true),
                            ],
                            vec![
                                k(0x1E, false, false),
                                k(0x1E, false, true),
                                k(0x30, false, false),
                                k(0x30, false, true),
                                k(0x2E, false, false),
                                k(0x2E, false, true),
                            ],
                            vec![
                                k(0x1D, false, false),
                                k(0x1E, false, false),
                                k(0x1E, false, true),
                                k(0x1D, false, true),
                            ],
                            vec![
                                k(0x1D, false, false),
                                k(0x2E, false, false),
                                k(0x2E, false, true),
                                k(0x1D, false, true),
                            ],
                            vec![
                                k(0x1D, false, false),
                                k(0x1E, false, false),
                                k(0x1E, false, true),
                                k(0x1D, false, true),
                            ],
                            vec![
                                k(0x2C, false, false),
                                k(0x2C, false, true),
                                k(0x2C, false, false),
                                k(0x2C, false, true),
                                k(0x2C, false, false),
                                k(0x2C, false, true),
                            ],
                            vec![
                                k(0x2A, false, false),
                                k(0x52, true, false),
                                k(0x52, true, true),
                                k(0x2A, false, true),
                            ],
                        ];
                        for (i, step) in steps.iter().enumerate() {
                            send(tls, &session.input(step)).await?;
                            println!("  {:>6} ms → touches étape {i}", t0.elapsed().as_millis());
                            tokio::time::sleep(Duration::from_millis(1500)).await;
                        }
                    }
                }
                Event::Ignored(_) | Event::Pointer(_) | Event::DvcData { .. } => {}
                other => println!("  {other:?}"),
            }
        }
    }
    println!("  {frames} images rendues, {avc} images H.264 sautées en {seconds} s");
    for (k, n) in &ignored {
        println!("  ignoré ×{n} : {k}");
    }
    if clip_test {
        // Referme la boîte Exécuter (Échap) après la capture ci-dessous.
        use rdp_pdu::fastpath::{Input, kbd};
        let esc =
            [Input::Scancode { code: 0x01, flags: 0 }, Input::Scancode { code: 0x01, flags: kbd::RELEASE }];
        let _ = send(tls, &session.input(&esc)).await;
    }
    if let Some(path) = env("PNG") {
        let (rgba, w, h) = gfx.output();
        let file = std::fs::File::create(&path)?;
        let mut enc = png::Encoder::new(std::io::BufWriter::new(file), w, h);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        enc.write_header()?.write_image_data(rgba)?;
        println!("  capture : {path}");
    }
    Ok(())
}
