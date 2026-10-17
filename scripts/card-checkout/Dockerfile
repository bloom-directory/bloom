FROM archlinux:base@sha256:4e77cf2ea5f410e6f8be5abf93ccf17ce2436e87a138c167208356711a405dbd
RUN pacman -Syu --noconfirm python jq chromium nodejs
# Each test/session keeps its own state. No user home or NFS mount is included.
WORKDIR /fixture
