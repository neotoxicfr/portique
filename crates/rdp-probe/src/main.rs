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
use rdp_pdu::{
    gcc::{self, Channel, ClientCore, ClientData, channel_opts, early_caps},
    mcs,
    x224::{self, protocol},
};
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
        let pubkey = credssp::subject_public_key(&cert)?;
        let rand = Randomness {
            client_challenge: random(),
            exported_session_key: random(),
            now_filetime: filetime_now(),
        };
        let mut cssp = CredSspClient::new(creds, pubkey, &host, rand, random());
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

    let client = ClientData {
        core: ClientCore {
            version: gcc::RDP_VERSION_10_7,
            width: 1920,
            height: 1080,
            keyboard_layout: 0x040C,
            client_build: 1,
            client_name: "yawrdp".into(),
            early_capability_flags: early_caps::SUPPORT_ERRINFO_PDU
                | early_caps::WANT_32BPP_SESSION
                | early_caps::SUPPORT_STATUSINFO_PDU
                | early_caps::STRONG_ASYMMETRIC_KEYS
                | early_caps::VALID_CONNECTION_TYPE
                | early_caps::SUPPORT_MONITOR_LAYOUT_PDU
                | early_caps::SUPPORT_DYNVC_GFX_PROTOCOL
                | early_caps::SUPPORT_HEARTBEAT_PDU,
            selected_protocol: cc.selected_protocol,
        },
        channels: vec![
            Channel {
                name: "cliprdr",
                options: channel_opts::INITIALIZED
                    | channel_opts::ENCRYPT_RDP
                    | channel_opts::COMPRESS_RDP
                    | channel_opts::SHOW_PROTOCOL,
            },
            Channel {
                name: "drdynvc",
                options: channel_opts::INITIALIZED | channel_opts::ENCRYPT_RDP | channel_opts::COMPRESS_RDP,
            },
        ],
    };
    send(&mut tls, &mcs::connect_initial(&client)).await?;
    let mut buf = Vec::new();
    let server = mcs::connect_response(&read_frame(&mut tls, &mut buf, x224::frame_len).await?)?;

    println!("✓ MCS Connect Response");
    println!("  version RDP du serveur : {} (0x{:08x})", gcc::version_name(server.version), server.version);
    if let Some(p) = server.client_requested_protocols {
        println!("  protocoles demandés (écho) : 0x{p:x}");
    }
    if let Some(f) = server.early_capability_flags {
        let mut caps = vec![];
        for (bit, name) in [
            (gcc::server_early_caps::EDGE_ACTIONS_SUPPORTED_V1, "edge actions v1"),
            (gcc::server_early_caps::DYNAMIC_DST_SUPPORTED, "heure d'été dynamique"),
            (gcc::server_early_caps::EDGE_ACTIONS_SUPPORTED_V2, "edge actions v2"),
            (gcc::server_early_caps::SKIP_CHANNELJOIN_SUPPORTED, "saut du Channel Join"),
        ] {
            if f & bit != 0 {
                caps.push(name);
            }
        }
        println!("  capacités précoces : 0x{f:x} [{}]", caps.join(", "));
    }
    println!(
        "  chiffrement RDP : méthode {} niveau {} (0/0 attendu sous TLS)",
        server.encryption_method, server.encryption_level
    );
    println!("  canal E/S : {}", server.io_channel);
    for (ch, id) in client.channels.iter().zip(&server.channel_ids) {
        println!("  canal {} → {id}", ch.name);
    }
    if let Some(m) = server.message_channel {
        println!("  canal de messages : {m}");
    }
    if let Some(m) = server.multitransport_flags {
        println!("  multitransport (UDP) : 0x{m:x}");
    }
    let _ = tls.shutdown().await;
    Ok(())
}
