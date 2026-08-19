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


## Upstream Gerrit CLs

| Finding | CL |
|---------|----|
| assoc-ies-oob | https://fuchsia-review.googlesource.com/c/fuchsia/+/1769953 |
| ssid-ie-oob | https://fuchsia-review.googlesource.com/c/fuchsia/+/1766637 |
| escan-ie-oob | https://fuchsia-review.googlesource.com/c/fuchsia/+/1766638 |
| sae-frametx-stack-vla | https://fuchsia-review.googlesource.com/c/fuchsia/+/1769954 |
| qmi-short-frame | https://fuchsia-review.googlesource.com/c/fuchsia/+/1769557 |
| kgsl-exec-oob | https://fuchsia-review.googlesource.com/c/fuchsia/+/1769973 |
| fastrpc-vmo-oob | https://fuchsia-review.googlesource.com/c/fuchsia/+/1769993 |
