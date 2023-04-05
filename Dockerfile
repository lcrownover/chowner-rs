FROM ubuntu:latest
RUN apt-get update && apt-get install -y libacl1-dev rust-all
