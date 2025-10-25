# zopp

Own your secrets. Stay secure. Empower developers.
zopp is the open-source, self-hostable, CLI-first secrets manager that keeps your secrets safe and your workflow fast.

---

## Status

[![Lint](https://github.com/vieiralucas/zopp/actions/workflows/lint.yml/badge.svg)](https://github.com/vieiralucas/zopp/actions/workflows/lint.yml)
[![Build](https://github.com/vieiralucas/zopp/actions/workflows/build.yml/badge.svg)](https://github.com/vieiralucas/zopp/actions/workflows/build.yml)
[![Test](https://github.com/vieiralucas/zopp/actions/workflows/test.yml/badge.svg)](https://github.com/vieiralucas/zopp/actions/workflows/test.yml)
[![Security Audit](https://github.com/vieiralucas/zopp/actions/workflows/audit.yml/badge.svg)](https://github.com/vieiralucas/zopp/actions/workflows/audit.yml)


---

## Why zopp?

- **Open-source**: transparent code, community-driven, contributions encouraged.
- **Self-hostable**: your secrets, your infra — deploy where you trust.
- **Local-first**: works fully offline; no vendor lock-in.
- **Safe**: passphrase → Argon2id; per-environment keys; AEAD for secret values.
- **Developer-focused**: import/export `.env`, inject into processes, zero boilerplate.

---

## Build

```bash
# from repo root
cargo build --workspace --release
```
