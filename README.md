# What is ExProto?

ExProto is a fast and flexible MTProto proxy server for everyone, written in
Rust. It works as a transparent relay between Telegram clients and Telegram
datacenters, wrapping MTProto traffic in fake TLS to get past DPI and
censorship systems.

This README is just a fast *quick start* document. See `exproto.yaml` for
the full configuration reference.

# Building

ExProto requires Rust 1.75+ and Cargo. It is as simple as:

    cargo build --release

The binary will be at `target/release/exproto`.

To cross-compile for Linux or ARM:

    cargo build --release --target x86_64-unknown-linux-gnu
    cargo build --release --target aarch64-unknown-linux-gnu

# Running

To generate a new secret:

    exproto secret

To run with a secret on port 443:

    exproto run -S <hex-secret> -H 443

To run with a configuration file:

    exproto run -c exproto.yaml

To generate `tg://proxy` links for sharing:

    exproto links -c exproto.yaml

To validate a configuration file without starting:

    exproto check -c exproto.yaml

# Configuration

ExProto uses YAML configuration. All sections are optional with sensible
defaults.

```yaml
server:
  bind: 0.0.0.0
  port: 443

tls:
  domain: www.google.com

  handshake:
    fragment: true

  stream:
    max_record_size: 16640
    record_jitter: 0.03

  fallback:
    hosts:
      - "google.com:443"
      - "cloudflare.com:443"
    timeout: 5000

secrets:
  - name: main
    secret: "00112233445566778899aabbccddeeff"
```

See `exproto.yaml` for the full reference with all available options including
per-secret upstream routing, connection limits, SOCKS5 support, healthchecks,
and ad-tags.
