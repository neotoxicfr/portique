# syntax=docker/dockerfile:1
# portique : serveur (Rust) + front wasm (Leptos, trunk) dans une image Debian minimale.

FROM rust:1.100.0-slim-trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends perl make pkg-config curl openssl \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add wasm32-unknown-unknown \
 && cargo install --locked trunk --version 0.22.2
# wasm-opt (binaryen) dans une couche en cache, empreinte vérifiée : sans lui, trunk retélécharge à chaque build
# l'archive de 103 Mo en moins de 30 s, ce qu'un lien lent ne tient pas. Même version que celle de trunk 0.22.2.
RUN arch=$(uname -m) \
 && case "$arch" in \
      x86_64) sum=b5bf1f0eaf17c63ee588ff7a5954dc8f6ce2c26989051c66f24dfe9ece3e46db ;; \
      aarch64) sum=ba991f677edd9a21d2bc96c0144bc8ac5b112d4d98a3eb266e075e22e557df2a ;; \
      *) echo "architecture non prise en charge : $arch" >&2; exit 1 ;; \
    esac \
 && f=binaryen-version_131-$arch-linux.tar.gz \
 && curl -fsSL --retry 5 -o "/tmp/$f" "https://github.com/WebAssembly/binaryen/releases/download/version_131/$f" \
 && echo "$sum  /tmp/$f" | sha256sum -c - \
 && tar -xzf "/tmp/$f" -C /usr/local/bin --strip-components=2 binaryen-version_131/bin/wasm-opt \
 && rm "/tmp/$f" && wasm-opt --version
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p portique-server \
 && cp target/release/portique /portique \
 && ./scripts/vendor-xterm.sh && cd crates/web && trunk build --release --dist /web

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
