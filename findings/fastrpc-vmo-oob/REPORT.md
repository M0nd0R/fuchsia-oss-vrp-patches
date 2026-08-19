# Security Advisory: Unprivileged FastRPC Mapped VMO `offset+length` Passed Without Bounds Check

| Field | Value |
|---|---|
| **Title** | Starnix FastRPC builds `VmoArgument{offset,length}` from attacker `remote_buf` without checking VMO size |
| **Component** | Starnix FastRPC (`adsprpc-smd-secure`) → `fuchsia.hardware.qualcomm.fastrpc` (external DSP driver) |
| **Tree** | `fuchsia.googlesource.com/fuchsia` |
| **Analyzed revision** | `cc9d1f42c490350fe3803782523d2ee2ecd50187` |
| **Primary sink** | `src/starnix/modules/fastrpc/fastrpc.rs` ~670–715 (`get_payload_info`) |
| **Attacker model** | **Unprivileged** Starnix/Android process; `DeviceOps::open` has **no** capability gate |
| **Impact class** | DSP / IOMMU DMA out-of-bounds **WRITE** (and/or READ) of mapped VMO pages **if** the SecureFastRpc driver honors oversized `length` |
| **Severity** | **Critical** (unpriv local → memory corruption class); DSP-side corruption **INFERRED** (server=`external`, not in OSS tree) |
| **CVSS 3.1 (estimated)** | **8.4** `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` with confirmed DMA; **7.8** if treated as High until device proof |
| **Report date** | 2026-08-18 |
| **Status** | OBSERVED missing Starnix bounds + unpriv reach; DMA WRITE **INFERRED** |
| **Not a duplicate of** | `fuchsia-eapol-tx-oob` (WLAN Fullmac heap WRITE) or `fuchsia-kgsl-exec-oob` (GPU Magma path) — **different IPC, different device node** |

---

## 1. Executive summary

Starnix’s FastRPC compatibility layer exposes `/dev`-style node `adsprpc-smd-secure` to ordinary apps. On `FASTRPC_IOCTL_INVOKE` / `INVOKE_FD`, when a `remote_buf` is backed by a mapped DMA-buf VMO, Starnix constructs:

```text
fidl VmoArgument { vmo, offset: <mm_offset>, length: buf.len }
```

**without** verifying:

```text
offset.checked_add(length) <= vmo.get_size()
```

`buf.len` and the user pointer are fully attacker-controlled. The VMO handle and this pair are sent to `SecureFastRpc` / `RemoteDomain::Invoke` (hardware driver **not** in this OSS tree).

If the DSP/SMMU path DMAs `length` bytes at `offset` into the shared VMO, an oversized `length` is a classic **out-of-bounds DMA WRITE** into adjacent physical memory — the same impact class as historical Android FastRPC / ION bugs (local privilege escalation / RCE into shared system memory).

This is **independent** of the already-reported EapolTx Critical (duplicate for VRP) and of the KGSL→Magma High finding: different device, different protocol, same missing-bounds pattern.

---

## 2. Why Critical (with honest caveats)

| Criterion | Assessment |
|---|---|
| Reach | **OBSERVED** — `FastRPCDevice::open` returns `FastRPCFile` with no capability check |
| Controllable `offset` / `length` | **OBSERVED** — `linux_uapi::remote_buf.{pv,len}` from ioctl |
| Missing Starnix VMO size check | **OBSERVED** |
| Actual DSP DMA OOB WRITE | **INFERRED** — `server=external`; confirm on device or with vendor driver source |
| Contrast: non-mapped path | Host `zx::Vmo::write` fails closed on OOB; **mapped** path skips host copy and trusts DSP |

Google OSS VRP: file as **Critical** when device PoC or vendor driver shows no `offset+length` clamp; otherwise ship as **High** with Critical escalation criteria (same bar as `fuchsia-kgsl-exec-oob`).

---

## 3. Affected code (file:line)

### 3.1 Unprivileged open — `fastrpc.rs` ~939–952

```rust
impl DeviceOps for FastRPCDevice {
    fn open(...) -> Result<Box<dyn FileOps>, Errno> {
        Ok(Box::new(FastRPCFile::new(
            current_task.thread_group_key.clone(),
            self.device.clone(),
            self.cached_capabilities.clone(),
        )))
    }
}
```

Registered as `adsprpc-smd-secure` in `fastrpc_device_init`.

### 3.2 Missing bounds — `get_payload_info` ~670–715

```rust
let (entry, offset) = if is_mapped {
    let (offset, vmo) = Self::get_mapped_memory_and_offset(...)?;
    (
        frpc::ArgumentEntry::VmoArgument(frpc::VmoArgument {
            vmo,
            offset,
            length: buf.len,  // NOT checked against vmo.get_size()
        }),
        offset,
    )
} else {
    ...
};
```

`get_mapped_memory_and_offset` only confirms the user VA maps to the DMA-buf VMO with R/W; it does **not** clamp `buf.len`.

### 3.3 FIDL surface — `sdk/fidl/fuchsia.hardware.qualcomm.fastrpc/fastrpc.fidl`

```fidl
type VmoArgument = resource struct {
    vmo zx.Handle:VMO;
    offset uint64;
    length uint64;
};
```

No protocol-level max; validation is the driver’s responsibility. Starnix is the last OSS gate before the external server.

---

## 4. Attack model

1. Unprivileged app opens `adsprpc-smd-secure`, completes `FASTRPC_IOCTL_INIT` / session setup available on the product image.
2. Allocates a small DMA-buf VMO via the FastRPC-linked `system` heap, maps it.
3. Issues `INVOKE` with `remote_buf.len = VMO_size + N` (or `offset` near end + large `len`).
4. Starnix forwards oversized `VmoArgument` to SecureFastRpc.
5. DSP DMA writes past the VMO → corrupt adjacent pages / IOMMU-mapped memory → local LPE / RCE.

---

## 5. Proof of concept

Host-side logic PoC (no DSP required) demonstrating that Starnix would emit an unchecked pair:

```
poc/poc_fastrpc_vmo_bounds.cpp
evidence/missing_bounds.out
```

Shows: for VMO size `S`, attacker length `S+0x1000` is accepted by the same arithmetic Starnix uses (no `offset+length <= size` check).

---

## 6. Suggested fix

Before constructing `VmoArgument`:

```rust
let vmo_size = vmo.get_size().map_err(...)?;
let end = offset.checked_add(buf.len).ok_or_else(|| errno!(EOVERFLOW))?;
if end > vmo_size {
    return error!(EINVAL);
}
```

Apply the same check for non-mapped `Argument` against the payload VMO size (defense in depth; `zx::Vmo::write` already fails, but fail earlier).

Mirror Magma’s `MapBuffer` / `BufferRangeOp` pattern in `magma_system_connection.cc`.

---

## 7. Related findings (do not conflate)

| Package | Relationship |
|---|---|
| `fuchsia-eapol-tx-oob` | **Different** — WLAN Fullmac heap WRITE; **VRP duplicate** — do not refile |
| `fuchsia-kgsl-exec-oob` | Same *class* (missing `offset+length`), different device (KGSL/Magma) |
| This package | FastRPC / DSP path |

---

## 8. Disclosure notes

- Prefer device confirmation (ASan/KASAN on vendor FastRPC driver, or IOMMU fault logs) before claiming production RCE.
- Do not claim remote/unauthenticated air attack — this is **local unprivileged**.
