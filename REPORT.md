# Security Advisory: Heap Out-of-Bounds Read in Fuchsia `brcmf_get_assoc_ies`

| Field | Value |
|---|---|
| **Title** | Heap OOB read in `brcmf_get_assoc_ies` via uncapped `assoc_info` lengths |
| **Component** | `brcmfmac` (Broadcom FullMAC WLAN driver) |
| **Tree** | `fuchsia.googlesource.com/fuchsia` |
| **Analyzed revision** | `cc9d1f42c490350fe3803782523d2ee2ecd50187` |
| **Primary sink** | `cfg80211.cc` `brcmf_get_assoc_ies` ~5769–5825 |
| **Attacker model** | Firmware-influenced `req_len`/`resp_len` on connect/roam success (SDIO/SIM). Linux documented USB URB case in CVE-2023-53213 |
| **Impact class** | Heap buffer over-read; multi-megabyte allocation DoS; possible ASLR/info leak companion for RCE chains |
| **Severity** | **High** |
| **CVSS 3.1 (estimated)** | **7.1** (USB/local class); `AV:A` if AP→firmware length inflation proven |
| **Linux relation** | **Same sink as CVE-2023-53213** — Fuchsia still missing the length clamp |
| **Report date** | 2026-08-18 |
| **Status** | OBSERVED missing check; ASan-confirmed host PoC |

## 1. Executive summary

`brcmf_get_assoc_ies` reads `req_len` / `resp_len` from the firmware `assoc_info` iovar and passes those values to `brcmu_alloc_and_copy(cfg->extra_buf, len)` **without** ensuring `len <= WL_EXTRA_BUF_MAX` (2048). Each IE iovar fill uses at most `WL_ASSOC_INFO_MAX` (512). Oversized lengths cause a **heap OOB read** (Linux KASAN showed ~3 MB reads) and can attempt huge allocations.

Linux fixed this in CVE-2023-53213:

```c
if (req_len > WL_EXTRA_BUF_MAX || resp_len > WL_EXTRA_BUF_MAX)
  return -EINVAL;
```

That check is **absent** in this Fuchsia revision.

## 2. Severity: High

| Factor | Assessment |
|---|---|
| Attack vector | Firmware path (SDIO/SIM on Fuchsia; USB on Linux) |
| Privileges | None on host; requires malicious/buggy firmware lengths |
| Integrity | None (read + alloc) |
| Confidentiality / Availability | Heap disclosure; OOM / crash |

**Why not Critical:** No write/RCE at this sink alone. Useful as an **info-leak companion** to the EapolTx Critical WRITE (`fuchsia-eapol-tx-oob/`).

## 3. Affected code

**Constants** (`cfg80211.h`): `WL_ASSOC_INFO_MAX = 512`, `WL_EXTRA_BUF_MAX = 2048`.

**Sink** (`cfg80211.cc` ~5785–5815):

```cpp
req_len = assoc_info->req_len;
resp_len = assoc_info->resp_len;
// MISSING: if (req_len > WL_EXTRA_BUF_MAX || resp_len > WL_EXTRA_BUF_MAX) return error;
conn_info->req_ie = brcmu_alloc_and_copy(cfg->extra_buf, conn_info->req_ie_len);
```

**Callers:** connect success (~6730), roam done (~5978).

## 4. PoC

```
poc/poc_brcmf_get_assoc_ies_oob.cpp
poc/run.sh
evidence/run.out
```

ASan: `READ of size 3014656` past 2048-byte region (matches Linux KASAN scale).

```bash
cd poc && ./run.sh
```

## 5. Fix

Reject lengths `> WL_EXTRA_BUF_MAX`; optionally copy at most `WL_ASSOC_INFO_MAX`.

## 6. Evidence labels

| Claim | Label |
|---|---|
| Missing clamp before copy | OBSERVED |
| ASan OOB on oversized req_len | OBSERVED (host mirror) |
| CVE-2023-53213 equivalence | OBSERVED |
| Evil AP alone inflates SDIO lengths | INFERRED |
