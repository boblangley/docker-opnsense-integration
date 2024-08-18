FROM rust:alpine as builder

RUN apk add --no-cache musl-dev

WORKDIR /usr/src/app

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && echo "fn main() {}" > src/main.rs

RUN cargo build --release

COPY src ./src

RUN cargo build --release

FROM alpine:latest

RUN apk add --no-cache ca-certificates

RUN mkdir -p /certs

COPY --from=builder /usr/src/app/target/release/myapp /usr/local/bin/myapp

ENV CERT_PATH=/certs/root.pem
ENV KEY_PATH=/certs/intermediate.pem

EXPOSE 8080

CMD ["myapp"]