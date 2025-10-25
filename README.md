# zopp

Own your secrets. Stay secure. Empower developers.
zopp is the open-source, self-hostable, CLI-first secrets manager that keeps your secrets safe and your workflow fast.

---

## Status

[![Lint](https://github.com/vieiralucas/zopp/actions/workflows/lint.yaml/badge.svg)](https://github.com/vieiralucas/zopp/actions/workflows/lint.yaml)
[![Build](https://github.com/vieiralucas/zopp/actions/workflows/build.yaml/badge.svg)](https://github.com/vieiralucas/zopp/actions/workflows/build.yaml)
[![Test](https://github.com/vieiralucas/zopp/actions/workflows/test.yaml/badge.svg)](https://github.com/vieiralucas/zopp/actions/workflows/test.yaml)
[![Security Audit](https://github.com/vieiralucas/zopp/actions/workflows/audit.yaml/badge.svg)](https://github.com/vieiralucas/zopp/actions/workflows/audit.yaml)


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
