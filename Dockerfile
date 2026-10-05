FROM docker.io/library/rust:1.90.0-bookworm AS builder

WORKDIR /src
COPY . .
RUN cargo build --locked --release -p kerosene-node --features production

FROM docker.io/library/debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/kerosene-node /usr/local/bin/kerosene-node

USER 1000:1000
EXPOSE 8800
ENTRYPOINT ["/usr/local/bin/kerosene-node"]
