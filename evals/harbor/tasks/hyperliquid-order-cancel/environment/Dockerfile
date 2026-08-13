FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       bash ca-certificates coreutils curl jq python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
