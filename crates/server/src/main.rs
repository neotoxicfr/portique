use std::net::SocketAddr;

use anyhow::Context;
use tracing_subscriber::EnvFilter;
use yawrdp_server::{app, bootstrap_admin, build_state, config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
