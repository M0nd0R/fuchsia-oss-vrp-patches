# Security Advisory: Heap Out-of-Bounds Read in Fuchsia `brcmf_inform_single_bss`

| Field | Value |
|---|---|
| **Title** | Heap OOB read via unchecked `ie_offset` / `ie_length` in scan BSS info |
| **Component** | `brcmfmac` |
| **Tree** | `fuchsia.googlesource.com/fuchsia` |
| **Analyzed revision** | `cc9d1f42c490350fe3803782523d2ee2ecd50187` |
| **Primary sink** | `cfg80211.cc` `brcmf_inform_single_bss` ~3317–3329 |
| **Attacker model** | Unauthenticated adjacent AP / malicious firmware scan results |
| **Impact class** | Heap over-read into SME scan-result FIDL path; possible ASLR leak companion |
| **Severity** | **High** |
| **CVSS 3.1 (estimated)** | **7.5** `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H` |
| **Report date** | 2026-08-18 |
| **Status** | OBSERVED missing bounds; ASan host PoC |

## 1. Executive summary

Scan results call `brcmf_inform_single_bss`, which sets:

```cpp
notify_ie = (uint8_t*)bi + bi->ie_offset;
notify_ielen = bi->ie_length;
```

and forwards them via `brcmf_return_scan_result` → FIDL `FromExternal` **without** verifying:

```text
ie_offset + ie_length <= bi->length
```

(or that the IE range stays inside the escan event buffer).

The escan handler validates `buflen` / `bi->length` consistency but **not** IE offset/length. Linux wireless patches proposed the same class of check.

Contrast: firmware-initiated roam BSS copy path (~5942) **does** bound-check against `WL_EXTRA_BUF_MAX`.

## 2. Severity: High

Unauthenticated adjacent reach into heap OOB read with disclosure to SME. Not Critical (read-only).

## 3. Reach

1. Victim scans (or background scan).
2. Attacker AP / buggy FW returns BSS info with inflated `ie_offset`/`ie_length` inside an otherwise length-consistent `bi`.
3. Driver reads past the BSS allocation when packaging IEs for SME.

## 4. PoC

```
poc/poc_inform_single_bss_ie_oob.cpp
evidence/asan_oob.out
```

```bash
cd poc && make && ./poc_inform_single_bss_ie_oob clean
./poc_inform_single_bss_ie_oob oob
```

## 5. Fix

In `brcmf_cfg80211_escan_handler` (preferred) or `brcmf_inform_single_bss`:

```cpp
if (bi->ie_offset > bi->length ||
    bi->ie_length > bi->length - bi->ie_offset) {
  /* reject */
}
```

## 6. Evidence labels

| Claim | Label |
|---|---|
| No ie_offset+ie_length vs bi->length check | OBSERVED |
| Roam path has analogous check; scan path does not | OBSERVED |
| ASan OOB on malicious offset/length | OBSERVED (host mirror) |
| Real AP/FW can set those fields freely | INFERRED |
