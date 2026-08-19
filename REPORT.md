# Security Advisory: Heap Out-of-Bounds Read in Fuchsia `brcmf_find_ssid_in_ies`

| Field | Value |
|---|---|
| **Title** | Truncated IE OOB read in `brcmf_find_ssid_in_ies` |
| **Component** | `brcmfmac` (Broadcom FullMAC WLAN driver) |
| **Tree** | `fuchsia.googlesource.com/fuchsia` |
| **Analyzed revision** | `cc9d1f42c490350fe3803782523d2ee2ecd50187` |
| **Primary sink** | `src/connectivity/wlan/drivers/third_party/broadcom/brcmfmac/cfg80211.cc` ~2138–2153 |
| **Attacker model** | Malformed IE blob from SME `selected_bss().ies` (connect/roam) or firmware BSS IE buffer (`brcmf_bss_info_le_ie_buffer_well_formed` / roam/scan helpers) |
| **Impact class** | Heap / buffer over-read (1+ bytes; up to ~255 on SSID branch with size underflow) |
| **Severity** | **Medium** (prefer) / **High** if firmware truncated-IE path is production-proven |
| **CVSS 3.1 (estimated)** | **5.9** `AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (adjacent, parsing quirk) |
| **Report date** | 2026-08-18 |
| **Status** | OBSERVED missing bounds; ASan-style host PoC |

---

## 1. Executive summary

`brcmf_find_ssid_in_ies` walks an 802.11 Information Element buffer with:

```cpp
while (offset < ie_len) {
  uint8_t type = ie[offset];
  uint8_t length = ie[offset + TLV_LEN_OFF];  // reads ie[offset+1]
  ...
  offset += length + TLV_HDR_LEN;
}
```

The loop condition only requires `offset < ie_len`. When the remaining length is **1 byte**, the type byte is in-bounds but **`ie[offset + 1]` is out of bounds**.

On the SSID branch, if `offset + TLV_HDR_LEN > ie_len`, then:

```cpp
size_t ssid_len = std::min<size_t>(length, ie_len - (offset + TLV_HDR_LEN));
```

underflows `size_t`, and the subsequent `std::vector` construction can read up to `kMaxSsidByteLen` (32) bytes past the buffer (still capped by `min` with length ≤ 255 before the second min — typically ≤ 32 after the SSID cap).

This is a classic truncated-TLV parser bug: **OBSERVED OOB READ**, not a write/RCE sink by itself. Useful as a small info-leak / crash companion next to Critical EapolTx WRITE.

---

## 2. Severity assessment

| Factor | Assessment |
|---|---|
| Memory corruption type | **READ** |
| Controllability | Attacker influences IE contents/length via AP/firmware/SME BSS description |
| Integrity | None |
| Confidentiality | Limited adjacent heap bytes |
| Availability | Possible crash under ASan / hardened allocators |

**Why not Critical:** No controllable WRITE. Rate **Medium** unless a concrete production path delivers `ie_len == 1` (or truncated TLV) from air/firmware without earlier rejection.

---

## 3. Affected code (file:line)

**Sink** — `cfg80211.cc` ~2138–2153:

```cpp
std::vector<uint8_t> brcmf_find_ssid_in_ies(const uint8_t* ie, size_t ie_len) {
  std::vector<uint8_t> ssid;
  size_t offset = 0;
  while (offset < ie_len) {
    uint8_t type = ie[offset];
    uint8_t length = ie[offset + TLV_LEN_OFF];
    if (type == WLAN_IE_TYPE_SSID) {
      size_t ssid_len = std::min<size_t>(length, ie_len - (offset + TLV_HDR_LEN));
      ssid_len = std::min<size_t>(ssid_len, fuchsia_wlan_ieee80211::kMaxSsidByteLen);
      auto start = ie + offset + TLV_HDR_LEN;
      ssid = std::vector<uint8_t>(start, start + ssid_len);
      break;
    }
    offset += length + TLV_HDR_LEN;
  }
  return ssid;
}
```

**Call sites (same file):** connect/roam paths using `selected_bss()->ies()` / `req->selected_bss().ies` (~2340, ~4136, ~6172, ~6252), SoftAP/BSS helpers (~3273, ~7519).

---

## 4. Attack model and reachability

1. **SME-supplied IEs on Connect/Roam:** Policy/SME builds `selected_bss` from scan results. If a truncated IE blob reaches the driver (malicious AP IE list that survives upper layers, or a bug in IE stitching), connect/roam invokes this parser.
2. **Firmware BSS IE buffer:** Helpers that pass firmware-provided IE pointers/lengths into `brcmf_find_ssid_in_ies` inherit firmware length trust.

**OBSERVED:** Parser has no `offset + 1 < ie_len` (or `offset + TLV_HDR_LEN + length <= ie_len`) check.  
**INFERRED:** Evil AP can produce truncated IEs; whether Fuchsia’s scan/SME path preserves exact truncation is environment-dependent.

---

## 5. Proof of concept

```
poc/poc_find_ssid_oob.cpp
poc/poc_find_ssid_oob          # prebuilt host binary
```

```bash
cd poc
./poc_find_ssid_oob clean   # OK
./poc_find_ssid_oob trunc   # OOB read of ie[1] on 1-byte buffer
```

Host mirror matches the driver loop. Under ASan, `trunc` mode reports heap-buffer-overflow READ.

---

## 6. Suggested fix

```cpp
while (offset + TLV_HDR_LEN <= ie_len) {
  uint8_t type = ie[offset];
  uint8_t length = ie[offset + TLV_LEN_OFF];
  if (offset + TLV_HDR_LEN + length > ie_len) {
    break;  // truncated IE — stop
  }
  ...
  offset += length + TLV_HDR_LEN;
}
```

Prefer a shared TLV walker already used elsewhere in the tree.

---

## 7. Evidence labels

| Claim | Label |
|---|---|
| Missing `offset+1 < ie_len` before length byte read | **OBSERVED** |
| Possible `size_t` underflow on SSID branch | **OBSERVED** |
| Host PoC OOB on truncated buffer | **OBSERVED** |
| Production air path delivers truncated `ie_len` unchanged | **INFERRED** |
| WRITE / RCE at this sink | **NOT SHOWN** |

---

## 8. Related findings

- Critical WRITE: EapolTx (`fuchsia-eapol-tx-oob/`)
- High scan IE OOB: `brcmf_inform_single_bss` (`fuchsia-escan-ie-oob/`)
- High assoc IE OOB: `brcmf_get_assoc_ies` (`fuchsia-assoc-ies-oob/`)
