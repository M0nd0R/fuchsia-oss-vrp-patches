# Fuchsia OSS VRP — separate fix patches (non-duplicates)

Tracking repo for **one merged PR per finding**. Skipped VRP duplicates:

- Heap OOB **WRITE** in `brcmf_if_eapol_req` / EapolTx
- Heap OOB **Read** in brcmfmac SAE AUTH handler

## Merged PRs (this repo)

| Finding | PR | Patch path |
|---------|----|------------|
| Assoc IE uncapped lengths | [#1](https://github.com/M0nd0R/fuchsia-oss-vrp-patches/pull/1) | `findings/assoc-ies-oob/` |
| SSID TLV walk OOB | [#2](https://github.com/M0nd0R/fuchsia-oss-vrp-patches/pull/2) | `findings/ssid-ie-oob/` |
| Escan BSS ie_offset/length | [#3](https://github.com/M0nd0R/fuchsia-oss-vrp-patches/pull/3) | `findings/escan-ie-oob/` |
| SaeFrameTx stack VLA | [#4](https://github.com/M0nd0R/fuchsia-oss-vrp-patches/pull/4) | `findings/sae-frametx-stack-vla/` |
| QMI short Ethernet TX | [#5](https://github.com/M0nd0R/fuchsia-oss-vrp-patches/pull/5) | `findings/qmi-short-frame/` |
| KGSL + Magma ExecResource bounds | [#6](https://github.com/M0nd0R/fuchsia-oss-vrp-patches/pull/6) | `findings/kgsl-exec-oob/` |
| FastRPC VmoArgument bounds | [#7](https://github.com/M0nd0R/fuchsia-oss-vrp-patches/pull/7) | `findings/fastrpc-vmo-oob/` |

## Upstream merge (required by Google OSS VRP)

Fuchsia does **not** merge GitHub PRs. Official path:

1. Apply `findings/<name>/patch/0001-*.patch` on fuchsia @ `main`
2. `git push origin HEAD:refs/for/main` to [fuchsia-review.googlesource.com](https://fuchsia-review.googlesource.com)
3. Get Code-Review +2 / CQ; reply on the VRP report with the **merged Gerrit CL** URL

Cookie / SSO for googlesource is required for Gerrit upload (not available in this environment).
