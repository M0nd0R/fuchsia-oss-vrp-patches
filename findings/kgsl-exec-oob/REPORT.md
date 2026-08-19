# Security Advisory: Unprivileged KGSL `GPU_COMMAND` Missing `offset+size` Bounds → Magma ExecResource

| Field | Value |
|---|---|
| **Title** | Starnix KGSL passes attacker `offset`/`size` into Magma without buffer-range validation |
| **Component** | Starnix KGSL (`/dev/kgsl-3d0`) → Magma system context → Adreno MSD |
| **Tree** | `fuchsia.googlesource.com/fuchsia` |
| **Analyzed revision** | `cc9d1f42c490350fe3803782523d2ee2ecd50187` |
| **Primary sink** | `src/starnix/modules/kgsl/file.rs` ~600–620 (`to_exec_resources`) |
| **Secondary sink** | `src/graphics/magma/lib/magma_service/sys_driver/magma_system_context.cc` ~20–55 |
| **Attacker model** | **Unprivileged** Android/Starnix process with access to `/dev/kgsl-3d0` (DeviceOps `open` has **no** capability gate) |
| **Impact class** | GPU DMA out-of-bounds **WRITE** / RCE **if** Adreno MSD honors oversized `ExecResource.length` (MSD not in this OSS tree) |
| **Severity** | **High** (proven missing checks + unpriv reach); escalate to **Critical** when MSD/DMA corruption is confirmed on device |
| **CVSS 3.1 (estimated)** | **7.8** `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (unpriv local); **8.8+** with confirmed GPU DMA write |
| **Report date** | 2026-08-18 |
| **Status** | OBSERVED missing bounds on Starnix + Magma; RCE via GPU DMA **INFERRED** (closed MSD) |

---

## 1. Executive summary

Starnix’s KGSL compatibility layer lets ordinary apps open `/dev/kgsl-3d0` and submit `GPU_COMMAND` ioctls. When building Magma execution resources, the code:

1. Locates a GPU object only by checking `gpuaddr ∈ [base, base + size)`.
2. Sets Magma fields to:

```text
offset = (obj.gpuaddr - gpuobj.gpuaddr) + obj.offset
length = obj.size
```

**without** ensuring `offset + length <= gpuobj.size` (or Magma buffer size).

Magma’s `MagmaSystemContext::ExecuteCommandBuffers` validates buffer handles and **command** `start_offset`, but **does not** validate each resource’s `offset + length` against the buffer size before calling the MSD.

If the Qualcomm Adreno MSD maps or DMAs using those lengths blindly, this is a classic **GPU memory OOB WRITE** — the same class as historical KGSL/GPU driver escapes (local privilege escalation / RCE into GPU or shared system memory).

---

## 2. Why this is High / Critical-adjacent

| Criterion | Assessment |
|---|---|
| Reach | **OBSERVED** unprivileged open + ioctl |
| Missing Starnix bounds | **OBSERVED** |
| Missing Magma resource length check | **OBSERVED** |
| Controllable length/offset | **OBSERVED** (`obj.offset`, `obj.size`) |
| Actual GPU DMA corruption / RCE | **INFERRED** — Adreno MSD binaries are not in this open tree |

Google OSS VRP: ship as **High** with clear Critical escalation criteria (device PoC showing OOB DMA or MSD source confirming no check).

---

## 3. Affected code (file:line)

### 3.1 Starnix KGSL — `file.rs` ~600–620

```rust
let gpuobj = gpuobjs
    .values()
    .find(|o| obj.gpuaddr >= o.gpuaddr && obj.gpuaddr < o.gpuaddr + o.size)
    ...;
Ok(kgsl_libmagma::ExecResource {
    buffer: gpuobj.buffer.clone(),
    offset: (obj.gpuaddr - gpuobj.gpuaddr) + obj.offset,
    length: obj.size,  // NOT checked against remaining buffer size
})
```

Only membership of `gpuaddr` in the object is checked. `obj.offset` and `obj.size` are attacker-controlled command-object fields.

### 3.2 Magma system context — `magma_system_context.cc` ~20–55

Validates:

- resource buffer handle exists
- command buffer resource index
- `command_buffer.start_offset < buffer.size()`

Does **not** validate `resources[i].offset + resources[i].length <= buffer.size()`.

### 3.3 Open path — no capability

`KgslDeviceBuilder::open` → `KgslFile::new_file` with no `CAP_*` / policy check (`init.rs` / `file.rs`). Any process that can open the device node can submit commands.

---

## 4. Attack model

1. Unprivileged Starnix/Android app opens `/dev/kgsl-3d0`.
2. Allocates a small GPU buffer via existing KGSL alloc ioctls.
3. Submits `GPU_COMMAND` with a `kgsl_command_object` whose `gpuaddr` falls inside the buffer but `offset`/`size` extend **past** the end (or use a large `size` with small mapped buffer).
4. Starnix forwards oversized `ExecResource` to Magma → MSD.
5. If MSD programs GPU with that range → DMA read/write outside the BO → memory corruption / info leak / RCE depending on IOMMU and MSD implementation.

---

## 5. Proof / reproduction notes

This package is **logic + static evidence** (MSD not available for host ASan).

**Minimum device PoC (researcher-owned hardware):**

1. Open kgsl; allocate 4 KiB BO.
2. Submit GPU_COMMAND with `size = 0x100000` (or `offset` near end + large size).
3. Observe: ioctl success vs reject; GPU hang; KASAN/IOMMU fault; corruption of adjacent BO.

**Fix verification:** After patch, step 2 must return `EINVAL` in Starnix before Magma.

---

## 6. Suggested fix

**Starnix (required):**

```rust
let base_off = obj.gpuaddr - gpuobj.gpuaddr;
let offset = base_off.checked_add(obj.offset).ok_or(errno!(EINVAL))?;
let end = offset.checked_add(obj.size).ok_or(errno!(EINVAL))?;
if end > gpuobj.size {
    return error!(EINVAL);
}
```

**Magma (defense in depth):** In `ExecuteCommandBuffers`, for every resource:

```cpp
if (resource.offset > buf->size() ||
    resource.length > buf->size() - resource.offset) {
  return MAGMA_STATUS_INVALID_ARGS;
}
```

---

## 7. Evidence labels

| Claim | Label |
|---|---|
| Unprivileged kgsl device open | **OBSERVED** |
| Missing `offset+size ≤ buffer` in Starnix | **OBSERVED** |
| Magma skips resource range check | **OBSERVED** |
| Adreno MSD performs unchecked DMA | **INFERRED** (binary MSD) |
| End-to-end RCE on production device | **NOT SHOWN** in this tree |

---

## 8. Relation to Critical EapolTx RCE

EapolTx (`fuchsia-eapol-tx-oob/`) is a **proven** driver heap WRITE → control-flow hijack PoC (Fullmac reach). KGSL is the strongest **unprivileged local** path toward Critical if device confirmation lands — complementary, not duplicate.
