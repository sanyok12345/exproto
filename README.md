# ExProto

MTProto proxy for Telegram. Single binary, zero config, runs anywhere.

Wraps MTProto traffic in fake TLS to bypass DPI and censorship. Download,
run, share the link.

## Quick Start

```bash
# 1. Download (linux amd64, see Releases for other platforms)
curl -Lo exproto https://github.com/sanyok12345/exproto/releases/latest/download/exproto-linux-amd64
chmod +x exproto

# 2. Run
./exproto run -H 443

# That's it. ExProto generates a secret, binds port 443, and prints
# a ready-to-share tg://proxy link to stdout.
```

No config files. No Docker. No dependencies. One binary does everything.

## Options

Override anything from the command line:

```bash
# Custom secret + port
./exproto run -S 9a17d3fddaf04683933007b5c155ed4a -H 8443

# Multiple secrets
./exproto run -S <secret1> -S <secret2> -H 443

# Custom TLS domain for SNI camouflage
./exproto run -S <secret> -H 443 --tls-domain ya.ru
```

Generate and manage secrets:

```bash
./exproto secret          # generate a new random secret
./exproto links -S <hex>  # print tg:// sharing links
./exproto check -c cfg.yaml  # validate config without starting
```

## Configuration File

For advanced setups, use YAML. All fields are optional with sensible defaults.

```yaml
server:
  bind: 0.0.0.0
  port: 443

tls:
  domain: www.google.com
  handshake:
    fragment: true
  fallback:
    hosts:
      - "google.com:443"
    timeout: 5000

secrets:
  - name: main
    secret: "9a17d3fddaf04683933007b5c155ed4a"
```

```bash
./exproto run -c exproto.yaml
```

See `exproto.yaml` for the full reference including per-secret upstream
routing, connection limits, SOCKS5, worker pools, healthchecks, and ad-tags.

