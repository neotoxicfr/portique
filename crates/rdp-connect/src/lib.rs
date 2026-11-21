//! Ouverture d'une connexion RDP authentifiée, côté serveur portique : TCP, négociation X.224,
//! TLS avec épinglage du certificat, NLA (CredSSP/NTLMv2). Le flux TLS obtenu est ensuite
//! relayé tel quel au navigateur, qui reprend à MCS Connect Initial.
//!
//! L'empreinte du certificat est vérifiée AVANT CredSSP : un faux serveur ne reçoit jamais la
//! réponse NTLM (cassable hors ligne).

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rand::Rng;
use rdp_auth::{
    credssp::{self, CredSspClient, Step},
    ntlm::{Credentials, Randomness},
};
use rdp_pdu::x224::{self, protocol};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, timeout_at},
};
pub use tokio_rustls::client::TlsStream;

pub struct Target {
    pub host: String,
    pub port: u16,
    pub credentials: Credentials,
}

pub struct Connected {
    pub stream: TlsStream<TcpStream>,
    /// Protocole retenu, à recopier dans le bloc client MCS.
    pub selected_protocol: u32,
    /// Drapeaux de RDP_NEG_RSP (EGFX supporté…).
    pub negotiation_flags: u8,
    pub cert_sha256: [u8; 32],
    /// Durée de chaque phase, pour le journal : où passe le temps d'ouverture.
    pub timings: Timings,
}

/// Durées des phases de connexion, en millisecondes.
#[derive(Debug, Clone, Copy, Default)]
pub struct Timings {
    pub tcp: u32,
    pub x224: u32,
    pub tls: u32,
    pub nla: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("PC injoignable ({0})")]
    Unreachable(String),
    #[error("le PC ne répond pas (délai dépassé)")]
    Timeout,
    #[error("négociation RDP : {0}")]
    Negotiation(String),
    #[error("TLS : {0}")]
    Tls(String),
    #[error(
        "le certificat du PC a changé : empreinte attendue {expected}, reçue {got} (réinstallation, ou attaque ?)"
    )]
    CertificateMismatch { expected: String, got: String },
    /// Certificat jamais vu : la connexion s'arrête avant CredSSP, l'empreinte doit être approuvée.
    #[error("certificat du PC pas encore approuvé (empreinte {0})")]
    UntrustedCertificate(String),
    #[error("authentification Windows : {0}")]
    Auth(String),
    #[error("protocole : {0}")]
    Protocol(String),
}

impl From<std::io::Error> for ConnectError {
    fn from(e: std::io::Error) -> Self {
        ConnectError::Protocol(e.to_string())
    }
}

const STEP_TIMEOUT: Duration = Duration::from_secs(15);

/// Le certificat RDP est auto-signé : la confiance vient de l'épinglage (vérifié après coup),
/// pas d'une autorité. Les signatures de la poignée de main restent vérifiées.
#[derive(Debug)]
struct PinLater(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for PinLater {
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

/// Lit une trame dont la longueur se déduit de l'en-tête (`len_of`).
pub async fn read_frame<S: AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
    len_of: fn(&[u8]) -> Option<usize>,
) -> Result<Vec<u8>, ConnectError> {
    // Une échéance pour toute la trame : des lectures partielles ne réarment pas le délai.
    let deadline = tokio::time::Instant::now() + STEP_TIMEOUT;
    loop {
        if let Some(n) = len_of(buf) {
            if !(2..1 << 20).contains(&n) {
                return Err(ConnectError::Protocol(format!("longueur de trame aberrante ({n})")));
            }
            if buf.len() >= n {
                return Ok(buf.drain(..n).collect());
            }
        }
        let mut chunk = [0u8; 8192];
        let got = timeout_at(deadline, s.read(&mut chunk)).await.map_err(|_| ConnectError::Timeout)??;
        if got == 0 {
            return Err(ConnectError::Protocol("connexion fermée par le PC".into()));
        }
        buf.extend_from_slice(&chunk[..got]);
    }
}

async fn send<S: AsyncWrite + Unpin>(s: &mut S, data: &[u8]) -> Result<(), ConnectError> {
    // `flush` : TLS peut garder la fin du message en tampon alors que `write_all` a réussi, et le
    // PC attendrait la suite pendant qu'on attend sa réponse.
    timeout(STEP_TIMEOUT, async {
        s.write_all(data).await?;
        s.flush().await
    })
    .await
    .map_err(|_| ConnectError::Timeout)??;
    Ok(())
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rng().fill_bytes(&mut b);
    b
}

fn filetime_now() -> u64 {
    let unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (unix.as_secs() + 11_644_473_600) * 10_000_000 + u64::from(unix.subsec_nanos() / 100)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Connecte et authentifie. `pinned` : empreinte SHA-256 attendue du certificat. Sans empreinte,
/// la connexion s'arrête après TLS (`UntrustedCertificate`) : aucune réponse NTLM ne part vers
/// un serveur que personne n'a approuvé.
pub async fn connect(target: &Target, pinned: Option<[u8; 32]>) -> Result<Connected, ConnectError> {
    let mut t = std::time::Instant::now();
    let mut lap = || {
        let ms = t.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
        t = std::time::Instant::now();
        ms
    };
    let mut timings = Timings::default();
    let mut tcp = timeout(STEP_TIMEOUT, TcpStream::connect((target.host.as_str(), target.port)))
        .await
        .map_err(|_| ConnectError::Timeout)?
        .map_err(|e| ConnectError::Unreachable(e.to_string()))?;
    tcp.set_nodelay(true)?;
    timings.tcp = lap();

    let requested = protocol::SSL | protocol::HYBRID | protocol::HYBRID_EX;
    // Pas de cookie `mstshash` (facultatif, 2.2.1.1) : il partirait en clair, avant TLS, avec
    // le nom du compte Windows.
    send(&mut tcp, &x224::connection_request(None, requested)).await?;
    let mut buf = Vec::new();
    let cc = x224::connection_confirm(&read_frame(&mut tcp, &mut buf, x224::frame_len).await?)
        .map_err(|e| ConnectError::Negotiation(e.to_string()))?;
    if cc.selected_protocol & (protocol::HYBRID | protocol::HYBRID_EX) == 0 {
        return Err(ConnectError::Negotiation(format!(
            "le PC n'accepte pas NLA ({}) : exécute le script de préparation",
            x224::protocol_name(cc.selected_protocol)
        )));
    }
    timings.x224 = lap();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| ConnectError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinLater(provider)))
        .with_no_client_auth();
    let name = ServerName::try_from(target.host.clone()).map_err(|e| ConnectError::Tls(e.to_string()))?;
    let mut tls =
        timeout(STEP_TIMEOUT, tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp))
            .await
            .map_err(|_| ConnectError::Timeout)?
            .map_err(|e| ConnectError::Tls(e.to_string()))?;
    let cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or_else(|| ConnectError::Tls("aucun certificat".into()))?
        .to_vec();
    let cert_sha256: [u8; 32] = Sha256::digest(&cert).into();
    timings.tls = lap();
    match pinned {
        None => return Err(ConnectError::UntrustedCertificate(hex(&cert_sha256))),
        Some(expected) if expected != cert_sha256 => {
            return Err(ConnectError::CertificateMismatch {
                expected: hex(&expected),
                got: hex(&cert_sha256),
            });
        }
        Some(_) => {}
    }

    let rand = Randomness {
        client_challenge: random(),
        exported_session_key: random(),
        now_filetime: filetime_now(),
    };
    let mut cssp = CredSspClient::new(target.credentials.clone(), &cert, &target.host, rand, random())
        .map_err(|e| ConnectError::Auth(e.to_string()))?;
    send(&mut tls, &cssp.start().map_err(|e| ConnectError::Auth(e.to_string()))?).await?;
    let mut buf = Vec::new();
    loop {
        let msg = read_frame(&mut tls, &mut buf, credssp::frame_len).await?;
        match cssp.step(&msg).map_err(|e| ConnectError::Auth(e.to_string()))? {
            Step::Send(out) => send(&mut tls, &out).await?,
            Step::Finish(out) => {
                send(&mut tls, &out).await?;
                break;
            }
        }
    }
    if cc.selected_protocol == protocol::HYBRID_EX {
        let mut res = [0u8; 4];
        timeout(STEP_TIMEOUT, tls.read_exact(&mut res)).await.map_err(|_| ConnectError::Timeout)??;
        credssp::early_user_auth_result(&res).map_err(|e| ConnectError::Auth(e.to_string()))?;
    }
    timings.nla = lap();
    Ok(Connected {
        stream: tls,
        selected_protocol: cc.selected_protocol,
        negotiation_flags: cc.flags,
        cert_sha256,
        timings,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn frame_deadline_is_not_rearmed_by_partial_reads() {
        let (mut pc, mut us) = tokio::io::duplex(64);
        tokio::spawn(async move {
            for part in [&[0x03, 0x00, 0x00, 0x08][..], &[0, 0], &[0, 0]] {
                pc.write_all(part).await.unwrap();
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            pc
        });
        let mut buf = Vec::new();
        assert!(matches!(read_frame(&mut us, &mut buf, x224::frame_len).await, Err(ConnectError::Timeout)));
        // Trame déjà entière en tampon : rendue sans lecture.
        let mut buf = vec![0x03, 0x00, 0x00, 0x04, 0x03];
        assert_eq!(read_frame(&mut us, &mut buf, x224::frame_len).await.unwrap(), [3, 0, 0, 4]);
        assert_eq!(buf, [3]);
    }

    /// Flux qui ne transmet qu'au `flush`, comme TLS quand le socket est plein.
    #[derive(Default)]
    struct Buffered {
        pending: Vec<u8>,
        sent: Vec<u8>,
    }

    impl AsyncWrite for Buffered {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.pending.extend_from_slice(b);
            Poll::Ready(Ok(b.len()))
        }
        fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            let s = &mut *self;
            s.sent.append(&mut s.pending);
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn send_flushes() {
        let mut s = Buffered::default();
        send(&mut s, b"TSRequest").await.unwrap();
        assert_eq!(s.sent, b"TSRequest");
    }

    #[tokio::test]
    async fn connection_request_without_account_name() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Target {
            host: "127.0.0.1".into(),
            port: listener.local_addr().unwrap().port(),
            credentials: Credentials {
                username: "alice".into(),
                domain: String::new(),
                password: "x".into(),
            },
        };
        let client = tokio::spawn(async move { connect(&target, None).await.map(|_| ()) });
        let (mut pc, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let req = read_frame(&mut pc, &mut buf, x224::frame_len).await.unwrap();
        assert_eq!(
            req,
            x224::connection_request(None, protocol::SSL | protocol::HYBRID | protocol::HYBRID_EX)
        );
        drop(pc);
        assert!(client.await.unwrap().is_err());
    }
}
