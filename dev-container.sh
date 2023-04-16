#!/bin/bash

docker build . -t chowner-rs
docker run -it -w /app -v $(pwd):/app chowner-rs bash
