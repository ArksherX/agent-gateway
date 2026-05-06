FROM rust:1-bookworm AS builder

WORKDIR /src
COPY . .
RUN cargo build --release --bin agent_gateway

FROM debian:bookworm-slim

COPY --from=builder /src/target/release/agent_gateway /usr/local/bin/agent_gateway

ENTRYPOINT ["agent_gateway"]
