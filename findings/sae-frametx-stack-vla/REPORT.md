# Security Advisory: SaeFrameTx Unbounded Stack VLA from FIDL `sae_fields:MAX`

| Field | Value |
|---|---|
| **Title** | `brcmf_if_sae_frame_tx` allocates a stack VLA sized to attacker-controlled FIDL `sae_fields` (up to channel MAX ~64KiB) |
| **Component** | brcmfmac Fullmac `SaeFrameTx` |
| **Tree** | `fuchsia.googlesource.com/fuchsia` |
| **Analyzed revision** | `cc9d1f42c490350fe3803782523d2ee2ecd50187` |
| **Primary sink** | `cfg80211.cc` `brcmf_if_sae_frame_tx` ~6296–6368 |
| **Attacker model** | Fullmac peer (SME / wlan stack) supplying `SaeFrame.sae_fields` |
| **Impact class** | Large stack allocation + controlled `memcpy` onto stack; stack exhaustion / clash risk; iovar later capped at `BRCMF_DCMD_MAXLEN` (8192) so **heap WRITE not shown** |
| **Severity** | **High** (memory-safety / DoS); not Critical without proven stack-clash RCE on driver stack (default Zircon stack **256KiB**) |
| **Report date** | 2026-08-18 |
| **Status** | OBSERVED unbounded VLA; RCE **not** claimed |
| **Not a duplicate of** | EapolTx heap WRITE Critical |

---

## 1. Sink

```cpp
uint32_t frame_size =
    sizeof(wlan::MgmtFrameHeader) + sizeof(wlan::Authentication) + frame->sae_fields().size();
uint32_t cmd_buf_len = sizeof(assoc_mgr_cmd_t) + frame_size;
uint8_t cmd_buf[cmd_buf_len];  // GNU/Clang VLA on stack
...
memcpy(sae_frame->sae_payload, frame->sae_fields().data(), frame->sae_fields().size());
err = brcmf_fil_iovar_data_set(ifp, "assoc_mgr_cmd", cmd_buf, cmd_buf_len, &fw_err);
```

FIDL: `sae_fields vector<uint8>:MAX` → up to `ZX_CHANNEL_MAX_MSG_BYTES` (65536).

`brcmf_create_iovar` refuses payloads that do not fit `proto_buf` (8192) **after** the VLA and memcpy already ran.

---

## 2. Why not Critical

- Default driver/user stack is **256KiB** (`ZIRCON_DEFAULT_STACK_SIZE`); a ~64KiB VLA alone does not reliably smash the stack.
- No proven controllable overwrite of a return address / fn pointer (unlike EapolTx heap PoC).
- Rate **High** for unbounded stack use + fail-late iovar check; escalate if a shallow dispatcher stack or stack-clash technique is demonstrated.

---

## 3. Fix

Cap `sae_fields().size()` before any stack allocation (e.g. max SAE payload ≤ 1024 or ≤ `BRCMF_DCMD_MAXLEN - headers`), allocate with `std::vector`/`malloc`, or reject early with `ZX_ERR_INVALID_ARGS`.

---

## 4. PoC

```
poc/poc_sae_frametx_vla.cpp
evidence/vla_size.out
```
