//! Sonde RDP : se connecte, négocie, chiffre en TLS, s'authentifie en NLA (CredSSP/NTLMv2)
//! puis échange les blocs MCS/GCC et affiche ce que le serveur annonce.
//!
//! Variables : YAWRDP_PROBE_HOST, YAWRDP_PROBE_PORT (3389), YAWRDP_PROBE_USER,
//! YAWRDP_PROBE_DOMAIN (vide), YAWRDP_PROBE_PASSWORD ou YAWRDP_PROBE_PASSWORD_FILE.
//! Le mot de passe n'est jamais affiché.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use rand::Rng;
use rdp_auth::{
    credssp::{self, CredSspClient, Step},
    ntlm::{Credentials, Randomness},
};
use rdp_pdu::x224::{self, protocol};
use rdp_session::{Config, Event, Session};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

const IO_TIMEOUT: Duration = Duration::from_secs(15);

fn env(name: &str) -> Option<String> {
    std::env::var(format!("YAWRDP_PROBE_{name}")).ok().filter(|v| !v.is_empty())
}

fn password() -> anyhow::Result<String> {
    match (env("PASSWORD"), env("PASSWORD_FILE")) {
        (Some(_), Some(_)) => {
            bail!("YAWRDP_PROBE_PASSWORD et YAWRDP_PROBE_PASSWORD_FILE définis tous les deux")
        }
        (Some(p), None) => Ok(p),
        (None, Some(path)) => {
            let raw = std::fs::read_to_string(&path).with_context(|| format!("lecture de {path}"))?;
            Ok(raw.trim_end_matches(['\n', '\r']).to_owned())
        }
        (None, None) => bail!("YAWRDP_PROBE_PASSWORD(_FILE) manquant"),
    }
}

/// Le certificat RDP est presque toujours auto-signé : on l'accepte ici et on affiche son
/// empreinte. Le produit final l'épinglera par connexion (confiance au premier usage).
#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(msg, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(msg, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Lit exactement une trame dont la longueur se déduit de l'en-tête.
async fn read_frame<S: AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
    len_of: fn(&[u8]) -> Option<usize>,
) -> anyhow::Result<Vec<u8>> {
    loop {
        if let Some(n) = len_of(buf) {
            anyhow::ensure!((2..1 << 20).contains(&n), "longueur de trame aberrante ({n})");
            if buf.len() >= n {
                return Ok(buf.drain(..n).collect());
            }
        }
        let mut chunk = [0u8; 8192];
        let got = timeout(IO_TIMEOUT, s.read(&mut chunk)).await.context("délai dépassé")??;
        anyhow::ensure!(got > 0, "connexion fermée par le serveur");
        buf.extend_from_slice(&chunk[..got]);
    }
}

async fn send<S: AsyncWrite + Unpin>(s: &mut S, data: &[u8]) -> anyhow::Result<()> {
    timeout(IO_TIMEOUT, s.write_all(data)).await.context("délai dépassé")??;
    Ok(())
}

fn filetime_now() -> u64 {
    let unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (unix.as_secs() + 11_644_473_600) * 10_000_000 + u64::from(unix.subsec_nanos() / 100)
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rng().fill_bytes(&mut b);
    b
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let host = env("HOST").context("YAWRDP_PROBE_HOST manquant")?;
    let port: u16 = env("PORT").map(|p| p.parse()).transpose()?.unwrap_or(3389);
    let user = env("USER").context("YAWRDP_PROBE_USER manquant")?;
    let domain = env("DOMAIN").unwrap_or_default();
    let creds = Credentials { username: user.clone(), domain, password: password()? };

    println!("→ connexion TCP à {host}:{port}");
    let mut tcp =
        timeout(IO_TIMEOUT, TcpStream::connect((host.as_str(), port))).await.context("délai TCP")??;
    tcp.set_nodelay(true)?;

    let requested = protocol::SSL | protocol::HYBRID | protocol::HYBRID_EX;
    send(&mut tcp, &x224::connection_request(Some(&user), requested)).await?;
    let mut buf = Vec::new();
    let cc = x224::connection_confirm(&read_frame(&mut tcp, &mut buf, x224::frame_len).await?)?;
    println!(
        "✓ négociation : {} (drapeaux 0x{:02x}{})",
        x224::protocol_name(cc.selected_protocol),
        cc.flags,
        if cc.flags & x224::neg_flags::DYNVC_GFX_PROTOCOL_SUPPORTED != 0 { ", EGFX supporté" } else { "" }
    );
    if cc.selected_protocol == protocol::RDP {
        bail!("le serveur ne propose que la sécurité RDP standard, refusée");
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    let name = ServerName::try_from(host.clone())?;
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await?;
    let (version, cert) = {
        let conn = tls.get_ref().1;
        let cert = conn.peer_certificates().and_then(|c| c.first()).context("aucun certificat")?.to_vec();
        (conn.protocol_version(), cert)
    };
    println!(
        "✓ TLS {:?}, certificat SHA-256 {}",
        version.context("version TLS")?,
        hex::encode(Sha256::digest(&cert))
    );

    if cc.selected_protocol & (protocol::HYBRID | protocol::HYBRID_EX) != 0 {
        let rand = Randomness {
            client_challenge: random(),
            exported_session_key: random(),
            now_filetime: filetime_now(),
        };
        let mut cssp = CredSspClient::new(creds, &cert, &host, rand, random())?;
        send(&mut tls, &cssp.start()?).await?;
        let mut buf = Vec::new();
        loop {
            let msg = read_frame(&mut tls, &mut buf, credssp::frame_len).await?;
            match cssp.step(&msg).map_err(|e| anyhow::anyhow!("NLA : {e}"))? {
                Step::Send(out) => send(&mut tls, &out).await?,
                Step::Finish(out) => {
                    send(&mut tls, &out).await?;
                    break;
                }
            }
        }
        if cc.selected_protocol == protocol::HYBRID_EX {
            let mut res = [0u8; 4];
            timeout(IO_TIMEOUT, tls.read_exact(&mut res)).await.context("délai")??;
            credssp::early_user_auth_result(&res).map_err(|e| anyhow::anyhow!("NLA : {e}"))?;
        }
        println!("✓ NLA réussie pour {user}");
    }

    run_session(&mut tls, &user, cc.selected_protocol).await?;
    let _ = tls.shutdown().await;
    Ok(())
}

/// Session complète après NLA : séquence de connexion, EGFX rendu par `rdp-gfx` pendant
/// YAWRDP_PROBE_SECONDS (8 par défaut), puis capture PNG du bureau dans YAWRDP_PROBE_PNG.
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
        client_name: "yawrdp".into(),
        selected_protocol,
        username: user.into(),
        domain: String::new(),
        display_control: true,
    });
    send(tls, &session.start()).await?;
    let mut buf = Vec::new();
    let mut gfx = rdp_gfx::Gfx::new();
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
                Event::DvcOpened { channel_id, name } => {
                    println!("  canal dynamique ouvert : {name} (#{channel_id})");
                    if name == rdp_session::DVC_GRAPHICS {
                        for f in session.dvc_send(channel_id, &rdp_gfx::caps_advertise(true)) {
                            send(tls, &f).await?;
                        }
                    }
                }
                Event::DvcData { channel_id, data }
                    if session.dvc_name(channel_id) == Some(rdp_session::DVC_GRAPHICS) =>
                {
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
                            rdp_gfx::Out::Reset { width, height } => {
                                println!("  EGFX : sortie {width}×{height}")
                            }
                            rdp_gfx::Out::Avc420 { .. } => {
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
                Event::Ignored(_) | Event::Pointer(_) | Event::Clipboard(_) | Event::DvcData { .. } => {}
                other => println!("  {other:?}"),
            }
        }
    }
    println!("  {frames} images rendues, {avc} images H.264 sautées en {seconds} s");
    for (k, n) in &ignored {
        println!("  ignoré ×{n} : {k}");
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
