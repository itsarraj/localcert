# localcert

Local dev TLS certs, zero OpenSSL — a `mkcert` alternative in pure Rust.
Go's `mkcert` is the standard for "trusted HTTPS on localhost in 10
seconds"; there's no canonical Rust equivalent, despite `rcgen` (pure-Rust
cert generation, no OpenSSL/native dependency at all) being a mature
building block for exactly this.

## Installation

```sh
cargo install --path .
```

## Usage

```bash
localcert init                              # once: generates the local CA
localcert install                           # prints (never runs) the OS-specific trust command
localcert cert myapp.test localhost 127.0.0.1
# -> myapp.test+2.pem, myapp.test+2-key.pem  (mkcert's own naming convention)
```

Point your dev server's TLS config at the two files it just wrote. Any
client that trusts the CA from `localcert init` (i.e., ran the command
`localcert install` prints) will accept the certificate without a browser
warning.

`localcert install` never escalates privileges or runs a command for
you — trusting a root CA system-wide is exactly the kind of action that
should require reading the command first, not a tool silently `sudo`-ing
on your behalf.

## Status: built and verified with a real TLS handshake, not just "generates a cert-shaped file"

- **7 unit tests** (`cargo test --lib`): a generated CA's PEM round-trips
  through its own parser; `load_ca` (what a second `localcert cert`
  invocation uses to reload the CA from disk) reconstructs a key that
  matches the original; hostname vs. IP SAN classification; the
  `mkcert`-matching output-filename convention (`localhost+2.pem` for
  three names); rejecting an empty name list.
- **3 real TLS handshake tests** (`tests/tls_handshake.rs`) — this is the
  test that actually proves the tool works, not just that it produces
  PEM-shaped text: a genuine `rustls` server and `rustls` client, over a
  real loopback TCP socket, doing a real handshake and real X.509 chain
  validation:
  - a client that trusts the generated CA **completes the handshake** and
    reads the server's message through the encrypted channel;
  - a client trusting a *different*, unrelated generated CA **fails** the
    same handshake (the negative control — proves the cert isn't
    accidentally trusted by everyone);
  - a client connecting with a hostname **not** in the cert's SAN list
    fails verification even while trusting the right CA (proves SAN
    checking is actually enforced, not just present in the cert).
- **CLI smoke-tested for real**: `init` → `init` again (correctly refused,
  since overwriting the CA would invalidate every cert already issued from
  it) → `cert myapp.test localhost 127.0.0.1` → confirmed the output
  filename (`myapp.test+2.pem`) and, via `openssl x509 -noout -subject
  -issuer -ext subjectAltName`, that the real issued certificate has the
  right subject, the right issuer DN, and all three SANs with the correct
  types (`DNS:myapp.test, DNS:localhost, IP Address:127.0.0.1`) — and that
  `install` only ever prints instructions, confirmed by reading its actual
  output, never executes anything.
- **Validity window explicitly set**, not left at `rcgen`'s own default
  (which is an essentially unbounded 1975–4096 range — harmless for a
  private CA no browser applies public-CA policy to, but not what a human
  expects to see in `openssl x509 -dates`): 10 years for the CA, 2 years
  for leaf certs, both starting a day in the past as clock-skew buffer.

**Not done / deliberately deferred**: `localcert uninstall` (removing the
CA from the OS/Firefox trust store) — v1 only adds trust, matching
`mkcert`'s own asymmetry here (uninstalling a manually-added root CA is
inherently more consequential than adding one, and deserves its own
explicit confirmation step rather than being bundled in this pass);
Firefox's own `nss`-based store isn't touched automatically (the `install`
instructions mention it, but don't attempt it, since it requires locating
a per-profile `cert9.db` — real, but more moving parts than a v1 needs).
