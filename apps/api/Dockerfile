# ── Stage 1: dependency cache ────────────────────────────────────────────────
# Copy only manifest files first so Docker can cache the compiled dependency
# layer independently of source changes.
FROM rust:1.94-bookworm AS deps

WORKDIR /usr/src/api

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./

# Create a minimal stub so `cargo build --release` can resolve and compile all
# dependencies without the real source.  The stub is overwritten in the next stage.
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo 'pub fn _stub() {}' > src/lib.rs \
    && cargo build --release \
    && rm -rf src target/release/iam-api target/release/deps/iam_api*

# ── Stage 2: full build ───────────────────────────────────────────────────────
FROM deps AS builder

COPY src ./src
COPY migrations ./migrations

# Touch the lib/main entry points so Cargo recognises them as changed.
RUN touch src/main.rs src/lib.rs \
    && cargo build --release

# ── Stage 3: minimal runtime image ───────────────────────────────────────────
FROM debian:bookworm-slim AS runner

WORKDIR /usr/local/bin

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/*

# SQLx migrations are embedded at compile time via sqlx::migrate!(), so only
# the binary is needed at runtime.
COPY --from=builder /usr/src/api/target/release/iam-api ./iam-api

EXPOSE 8080

CMD ["iam-api"]
