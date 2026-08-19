# Per-finding VRP reply (paste separately on each closed report)

Skip replies for the two duplicates (EapolTx WRITE, SAE AUTH read).

---

## Template (fill Gerrit CL when merged upstream)

```
Hi — thank you for the review. A committed fix for this issue is available.

Merged patch artifact (separate PR for this finding only):
<PR_URL>

Unified diff against fuchsia (apply with git am):
https://github.com/M0nd0R/fuchsia-oss-vrp-patches/blob/main/findings/<NAME>/patch/<PATCH_FILE>

I am also uploading this change to fuchsia-review.googlesource.com. I will reply again with the merged Gerrit CL URL once CQ lands it on fuchsia main.

Please reopen / reconsider once the upstream merge is confirmed. Thank you.
```

---

## Ready replies (GitHub PR already merged)

### Assoc IE lengths (`fuchsia-assoc-ies-oob`)
PR: https://github.com/M0nd0R/fuchsia-oss-vrp-patches/pull/1  
Patch: https://github.com/M0nd0R/fuchsia-oss-vrp-patches/blob/main/findings/assoc-ies-oob/patch/0001-brcmfmac-Clamp-assoc-IE-lengths-before-alloc_and_cop.patch

### SSID TLV (`fuchsia-ssid-ie-oob`)
PR: https://github.com/M0nd0R/fuchsia-oss-vrp-patches/pull/2  
Patch: https://github.com/M0nd0R/fuchsia-oss-vrp-patches/blob/main/findings/ssid-ie-oob/patch/0001-brcmfmac-Bound-TLV-walk-in-brcmf_find_ssid_in_ies.patch

### Escan IE (`fuchsia-escan-ie-oob`)
PR: https://github.com/M0nd0R/fuchsia-oss-vrp-patches/pull/3  
Patch: https://github.com/M0nd0R/fuchsia-oss-vrp-patches/blob/main/findings/escan-ie-oob/patch/0001-brcmfmac-Validate-BSS-ie_offset-ie_length-in-inform_.patch

### SaeFrameTx VLA (`fuchsia-sae-frametx-stack-vla`)
PR: https://github.com/M0nd0R/fuchsia-oss-vrp-patches/pull/4  
Patch: https://github.com/M0nd0R/fuchsia-oss-vrp-patches/blob/main/findings/sae-frametx-stack-vla/patch/0001-brcmfmac-Cap-SaeFrameTx-payload-and-avoid-stack-VLA.patch

### QMI short frame (`fuchsia-qmi-short-frame`)
PR: https://github.com/M0nd0R/fuchsia-oss-vrp-patches/pull/5  
Patch: https://github.com/M0nd0R/fuchsia-oss-vrp-patches/blob/main/findings/qmi-short-frame/patch/0001-qmi-usb-transport-Return-after-short-Ethernet-TX-fra.patch

### KGSL / Magma (`fuchsia-kgsl-exec-oob`)
PR: https://github.com/M0nd0R/fuchsia-oss-vrp-patches/pull/6  
Patch: https://github.com/M0nd0R/fuchsia-oss-vrp-patches/blob/main/findings/kgsl-exec-oob/patch/0001-kgsl-magma-Validate-ExecResource-offset-length-again.patch

### FastRPC VMO (`fuchsia-fastrpc-vmo-oob`)
PR: https://github.com/M0nd0R/fuchsia-oss-vrp-patches/pull/7  
Patch: https://github.com/M0nd0R/fuchsia-oss-vrp-patches/blob/main/findings/fastrpc-vmo-oob/patch/0001-fastrpc-Reject-mapped-VmoArgument-ranges-past-VMO-si.patch
