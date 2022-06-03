FROM rust:1.59 as builder
WORKDIR /app
COPY . /app
RUN cargo build --release

# We do not need the Rust toolchain to run the binary!
FROM debian:buster-slim AS runtime
RUN apt-get update \
    && apt-get install -y ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

ARG APP=/app

ENV TZ=Etc/UTC \
    APP_USER=appuser

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

RUN chown -R $APP_USER:$APP_USER ${APP}
USER $APP_USER
WORKDIR ${APP}

EXPOSE 8080

COPY --from=builder /app/target/release/sso-rs /usr/local/bin
COPY --from=builder /app/manifest.yaml /app/

CMD ["sso-rs", "/app/manifest.yaml"]