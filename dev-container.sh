#!/bin/bash

docker build . -t chowner-rs:dev
docker run -it -w /app -v .:/app chowner-rs:dev /bin/sh -c 'cargo build; bash'
