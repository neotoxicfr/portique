# syntax=docker/dockerfile:1
# portique : serveur (Rust) + front wasm (Leptos, trunk) dans une image Debian minimale.

FROM rust:1.100.0-slim-trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends perl make pkg-config \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add wasm32-unknown-unknown \
 && cargo install --locked trunk --version 0.21.14
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p portique-server \
 && cp target/release/portique /portique \
 && cd crates/web && trunk build --release --dist /web

FROM debian:trixie-slim
ARG VERSION=dev
LABEL org.opencontainers.image.title="Portique" \
      org.opencontainers.image.description="Client RDP web auto-hébergé (Rust + wasm)" \
      org.opencontainers.image.source="https://github.com/neotoxicfr/portique" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data portique \
 && install -d -o portique -g portique /data
COPY --from=build /portique /usr/local/bin/portique
COPY --from=build /web /app/web
USER portique
ENV PORTIQUE_DATA_DIR=/data PORTIQUE_STATIC_DIR=/app/web PORTIQUE_LISTEN=0.0.0.0:8080
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["portique", "healthcheck"]
ENTRYPOINT ["portique"]
