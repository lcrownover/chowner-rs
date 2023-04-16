FROM lukemathwalker/cargo-chef:latest-rust-slim-bullseye AS chef
WORKDIR app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --recipe-path recipe.json
# COPY . .
RUN apt-get update && apt-get install -y libacl1-dev
RUN cargo build
