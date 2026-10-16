use std::net::SocketAddr;

use anyhow::Context;
use tracing_subscriber::EnvFilter;
use yawrdp_server::{app, bootstrap_admin, build_state, config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `yawrdp healthcheck` : sonde de santé pour Docker (pas de curl dans l'image).
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return healthcheck().await;
    }
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into()))
        .init();

    let cfg = config::Config::from_env(&config::ProcessEnv)?;
    std::fs::create_dir_all(&cfg.data_dir).context("création du dossier de données")?;
    let db_url = format!("sqlite://{}", cfg.data_dir.join("yawrdp.db").display());
    let db = yawrdp_server::open_db(&db_url).await?;
    let listen = cfg.listen;
    let mode = cfg.auth_mode;
    let state = build_state(cfg, db)?;
    bootstrap_admin(&state).await?;
    // Proxys de confiance désignés par nom : résolus maintenant puis toutes les 30 s.
    state.cfg.proxy.refresh_trusted_hosts().await;
    let proxy = state.cfg.proxy.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            proxy.refresh_trusted_hosts().await;
        }
    });

    let listener =
        tokio::net::TcpListener::bind(listen).await.with_context(|| format!("écoute sur {listen}"))?;
    tracing::info!(%listen, ?mode, "yawrdp démarré");
    axum::serve(listener, app(state).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

/// Ctrl+C en local, SIGTERM sous `docker stop`.
async fn shutdown() {
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term => {}
    }
    tracing::info!("arrêt");
}

async fn healthcheck() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listen: SocketAddr =
        std::env::var("YAWRDP_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into()).parse()?;
    let target = SocketAddr::new(
        if listen.ip().is_unspecified() { std::net::Ipv4Addr::LOCALHOST.into() } else { listen.ip() },
        listen.port(),
    );
    let mut s =
        tokio::time::timeout(std::time::Duration::from_secs(3), tokio::net::TcpStream::connect(target))
            .await??;
    s.write_all(b"GET /api/info HTTP/1.0\r\nHost: localhost\r\n\r\n").await?;
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), s.read(&mut buf)).await??;
    anyhow::ensure!(
        buf[..n].starts_with(b"HTTP/1.0 200") || buf[..n].starts_with(b"HTTP/1.1 200"),
        "réponse inattendue"
    );
    Ok(())
}
