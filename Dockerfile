# FROM ubuntu:latest
# RUN apt-get update && apt-get install -y libacl1-dev rust-all

FROM rust:latest as builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN apt-get update && apt-get install -y libacl1-dev
RUN cargo fetch


# FROM debian:buster-slim
# COPY --from=builder /usr/local/cargo/bin/chowner-rs /usr/local/bin/chowner-rs
# CMD ["chowner-rs"]
