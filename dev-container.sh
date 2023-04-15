#!/bin/bash

docker build . -t chowner-rs
# docker run -it -w /app -v .:/app chowner-rs /bin/sh -c 'cargo build; bash'
# docker run -it -w /app -v .:/app chowner-rs bash
docker run -it -w /app chowner-rs:latest bash
