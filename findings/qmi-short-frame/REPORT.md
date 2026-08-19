# Security Advisory: QMI USB Ethernet Short-Frame Missing Return → `size_t` Underflow

| Field | Value |
|---|---|
| **Title** | Missing early return after short Ethernet frame check in `qmi-usb-transport` |
| **Component** | `src/connectivity/telephony/drivers/qmi-usb-transport` |
| **Tree** | `fuchsia.googlesource.com/fuchsia` |
| **Analyzed revision** | `cc9d1f42c490350fe3803782523d2ee2ecd50187` |
| **Primary sink** | `qmi-usb-transport.cc` `Device::EthernetImplQueueTx` ~350–390 |
| **Attacker model** | Ethernet client (typically netstack / telephony stack) submitting undersized `ethernet_netbuf_t` |
| **Impact class** | `size_t` underflow → enormous `eth_payload_len`; OOB **read** of ethertype / ARP path; potential bad USB TX length if later checks fail open |
| **Severity** | **High** (memory-safety defect); not Critical — **WRITE not demonstrated** |
| **CVSS 3.1 (estimated)** | **7.0** `AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H` |
| **Report date** | 2026-08-18 |
| **Status** | OBSERVED missing return + underflow; host logic PoC |

---

## 1. Executive summary

`EthernetImplQueueTx` detects frames shorter than `kEthFrameHdrSize`, logs an error, increments a drop counter — then **continues execution**:

```cpp
if (length < kEthFrameHdrSize) {
  zxlogf(ERROR, "qmi-usb-transport: tx eth frame too short (length: %zx) ", length);
  eth_tx_stats_.eth_dropped_cnt += 1;
  // MISSING: complete_txn(...); return;
}
size_t eth_payload_len = length - kEthFrameHdrSize;  // underflows when length < hdr
```

Unsigned underflow makes `eth_payload_len` huge (`SIZE_MAX - (hdr - length - 1)`). The code then reads `EthFrameHdr` from `netbuf->data_buffer` (which may be shorter than a full header — **OOB read** of ethertype) and branches into ARP/IPv4 handling.

ARP path compares `eth_payload_len < kArpSize` (true for underflow? No — underflow is huge, so check **passes**) and may interpret truncated buffer as ARP — further OOB reads. IPv4 path has `length > kEthMtu || length == 0` checks that often reject before `SendLocked`, limiting write impact.

---

## 2. Severity: High (not Critical)

| Factor | Assessment |
|---|---|
| Bug class | Missing return + unsigned underflow |
| Reach | Local EthernetImpl client (privileged relative to modem driver; not Wi-Fi adjacent) |
| Confidentiality | OOB read of heap near netbuf |
| Integrity / RCE | **NOT SHOWN** — IPv4 length gates and ARP parsing usually fail safely; no proven controllable WRITE |

Do **not** file as Critical without a demonstrated write or USB DMA corruption path.

---

## 3. Affected code (file:line)

**File:** `src/connectivity/telephony/drivers/qmi-usb-transport/qmi-usb-transport.cc` ~350–390

```cpp
size_t length = netbuf->data_size;

if (length < kEthFrameHdrSize) {
  zxlogf(ERROR, "qmi-usb-transport: tx eth frame too short (length: %zx) ", length);
  eth_tx_stats_.eth_dropped_cnt += 1;
}
size_t eth_payload_len = length - kEthFrameHdrSize;

const EthFrameHdr* eth_hdr = reinterpret_cast<const EthFrameHdr*>(netbuf->data_buffer);
switch (betoh16(eth_hdr->ethertype)) {
  case kEthertypeArp: {
    if (eth_payload_len < kArpSize) { ... return; }
    auto eth_arp = reinterpret_cast<const EthArpFrame*>(netbuf->data_buffer);
    ...
  }
  case kEthertypeIpv4: {
    if (length > kEthMtu || length == 0) {
      complete_txn(txn, ZX_ERR_INVALID_ARGS);
      return;
    }
    status = SendLocked(eth_ip->eth_payload, eth_payload_len);
    ...
  }
}
```

---

## 4. Attack model and reachability

1. A Fuchsia component with the QMI ethernet client interface queues a TX netbuf with `data_size` in `{0, …, kEthFrameHdrSize-1}`.
2. Driver logs “too short” but does not abort.
3. Underflowed `eth_payload_len` and truncated header parse follow.

**Typical peer:** netstack / telephony — not an unauthenticated remote attacker. Still a real driver memory-safety bug for VRP / hardening.

---

## 5. Proof of concept

```
poc/poc_qmi_short_frame.cpp
evidence/underflow.out
```

```bash
cd poc && c++ -O0 -g -fsanitize=address -o poc_qmi_short_frame poc_qmi_short_frame.cpp
./poc_qmi_short_frame
```

Demonstrates: short length → underflowed payload length → out-of-bounds ethertype/ARP field reads on a 1-byte buffer (ASan READ).

---

## 6. Suggested fix

```cpp
if (length < kEthFrameHdrSize) {
  zxlogf(ERROR, "...");
  eth_tx_stats_.eth_dropped_cnt += 1;
  complete_txn(/*txn if available*/, ZX_ERR_INVALID_ARGS);  // or invoke completion_cb
  return;
}
```

Also reject before any dereference of `EthFrameHdr`.

---

## 7. Evidence labels

| Claim | Label |
|---|---|
| Short-frame branch lacks return | **OBSERVED** |
| `size_t` underflow of `eth_payload_len` | **OBSERVED** |
| Subsequent header/ARP OOB read on short buffer | **OBSERVED** (host PoC) |
| Controllable heap WRITE / RCE | **NOT SHOWN** |

---

## 8. Related

Critical driver RCE remains EapolTx WRITE (`fuchsia-eapol-tx-oob/`). This QMI bug is a separate telephony-driver memory-safety issue.
