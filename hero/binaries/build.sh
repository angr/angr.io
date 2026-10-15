#!/usr/bin/env bash
#
# Build the Go and Rust ports of fauxware with a pinned-ish toolchain from
# nixpkgs, so the committed binaries (and the addresses the demos show) are
# reproducible. The C fauxware is the canonical one from angr/binaries and is
# not rebuilt here.
#
#   hero/binaries/build.sh          # needs nix (flakes enabled)
#
# Re-run the generators afterwards (`npm run gen:force`) — function addresses
# move whenever a binary changes.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

nix shell nixpkgs#go nixpkgs#rustc nixpkgs#gcc nixpkgs#patchelf -c bash -euo pipefail -c '
  # Go: static, optimized, DWARF stripped (symbols kept — angr needs them).
  (cd go && CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags=-w -o fauxware fauxware.go)
  # Rust: a plain debug build (calls stay calls, which reads best decompiled),
  # then point it at the system dynamic loader instead of the nix store one.
  (cd rust \
    && rustc --edition 2021 -C opt-level=0 -C debuginfo=0 -C panic=abort -o fauxware fauxware.rs \
    && patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 --remove-rpath fauxware)
'
ls -la go/fauxware rust/fauxware
