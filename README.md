# Fuchsia OSS VRP — separate security fix patches

**Skipped (VRP duplicates):** EapolTx heap WRITE; SAE AUTH short-frame OOB read.

Fuchsia’s official merge path is **Gerrit** (`fuchsia-review.googlesource.com`), not GitHub.
Each branch below is a standalone fix (one commit / one patch) ready to upload with:

```bash
# from a fuchsia checkout at the analyzed revision
git am path/to/0001-....patch
git push origin HEAD:refs/for/main
```

| Branch | Finding package | Fix |
|--------|-----------------|-----|
| `fix/assoc-ies-oob` | fuchsia-assoc-ies-oob | Clamp assoc IE lengths |
| `fix/ssid-ie-oob` | fuchsia-ssid-ie-oob | Bound SSID TLV walk |
| `fix/escan-ie-oob` | fuchsia-escan-ie-oob | Validate BSS ie_offset/length |
| `fix/sae-frametx-stack-vla` | fuchsia-sae-frametx-stack-vla | Cap SaeFrameTx / no stack VLA |
| `fix/qmi-short-frame` | fuchsia-qmi-short-frame | Return after short ETH TX |
| `fix/kgsl-exec-oob` | fuchsia-kgsl-exec-oob | KGSL+Magma offset+length checks |
| `fix/fastrpc-vmo-oob` | fuchsia-fastrpc-vmo-oob | FastRPC VmoArgument bounds |

Tree revision analyzed: `cc9d1f42c490350fe3803782523d2ee2ecd50187`
