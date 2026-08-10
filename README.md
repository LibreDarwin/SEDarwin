# SEDarwin

A research kext that registers a policy with the kernel's TrustedBSD MAC
framework (the "Security Extensions" KPI) and logs what the framework asks of
it. It is not a product, not a sandbox, and it enforces nothing: every hook
returns the kernel's default answer (`MAC_DENY`/`MAC_PERMIT` path is just
logging + default), which is exactly what a framework-onboarding kext should
do.

**Do not install this on a machine you care about.** It is a development aid,
built against one specific kernel (see "ABI compatibility" below).

## What it demonstrates

- A **c-style kext** with no dependency on the private `libkext`/`libkern`
  libraries: `_start`/`_stop` come from `libkmod.a` and route through
  `_realmain`/`_antimain` to the policy's `mac_policy_register()` /
  `mac_policy_unregister()`.
- A **hand-declared ABI** for the private MAC framework (`mac_policy_ops`,
  `mac_policy_conf`, `mac_policy_register()`) — the public SDK ships none of
  it. The layout is documented, offset-verified against the running kernel,
  and guarded by `_Static_assert`s so a kernel bump fails the build instead of
  corrupting memory.
- **20+ MAC policy hooks** across vnode, file, proc, socket, pty and exec
  operations, tracing the parameters the framework passes in (subject proc,
  uid, lookup component, prot, flags, csflags, ...) through kernel `printf`,
  behind a runtime gate that is off by default. Hooks never walk a vnode back
  to a path: `vn_getpath()` from inside a check hook re-locks the vnode the
  caller already holds and freezes the machine.
- A **synthetic Mach-O loader selftest** (`sebsd_macho_selftest`) that runs at
  policy init time to exercise the in-memory Mach-O parsing code.

## Requirements

- macOS 26.x, arm64 (built and validated on macOS 26.5.2 / Darwin 25.5.0 /
  xnu-12377.121.10, `kernel.release.t8142`).
- Xcode command line tools (kernel SDK, `libkmod.a`, `codesign`, `kextutil`).
- A kernel that still allows third-party kexts to load (kernel developer mode:
  boot in verbose/dev mode or use `kextutil -d`, and disable SIP kext
  restrictions) — modern macOS does not load unsigned/third-party kexts
  otherwise.

## Build

```sh
make            # builds into out/ (kext + dSYM)
make debug      # alias; debug is the default
make release    # same output, release-style flags
make clean      # no sudo needed; all artifacts are user-owned
```

The kext builds against the **public kernel SDK only** — there is no vendored
xnu header tree. The single hand-declared interface is
`include/sedarwin/sebsd_mac.h`, which exists because the MAC KPI is private and
the SDK ships none of it. Where a type is kernel-private but only ever held as a
pointer (`struct fileglob`, `struct tty`, `struct attrlist`) it is
forward-declared; where a private struct's contents were needed, the policy uses
the public accessor instead (`proc_find_ident()` rather than reaching into
`struct proc_ident`).

The build is split into `lib/libkern-bsd` (userspace-style helpers compiled
with the kernel SDK, e.g. `malloc`, `sbuf`) and `kext/` (the policy itself).
The top-level `Makefile` orchestrates both and moves the bundle into `out/`.

Static validation without loading anything:

```sh
kextutil -q -n -t out/sedarwin.kext   # exit 0 => bundle + linkage OK
```

## Install / uninstall

`make install` only **copies** the already-built bundle into
`/Library/Extensions` (it never compiles, so nothing is built as root). It also
installs the boot-time loader described below:

```sh
make && sudo make install            # kext + loader; leaves it DISARMED
# System Settings > Privacy & Security -> allow the signing developer
sudo reboot                          # required: the auxKC is rebuilt at boot
sudo make load                       # deliberate, interactive load
make status                          # installed / armed / loaded / hooks / trace
```

Load a new build **interactively** (`sudo make load`) rather than by arming the
boot daemon. If the build wedges the machine, a power cycle comes back to a
working system, because the daemon is still disarmed and will not retry it. Only
once a build has proven itself is it worth arming:

```sh
sudo touch /var/db/sedarwin.enabled  # now it loads at every boot
```

**Every rebuild needs that whole cycle again.** A recompiled kext has a new
cdhash, so the standing approval no longer covers it, and the auxiliary kernel
collection that the load draws from is only rebuilt at boot. `sudo make load`
exists for the case where the installed bundle is already approved and staged
and you just want it in the running kernel; it cannot shortcut a rebuild.

### Something has to actually load it

Installing into `/Library/Extensions` is **not** enough, and neither is being
prelinked into the auxiliary kernel collection. The auxKC only *maps* the kext;
its `_start` never runs until something asks kernelmanagement to load it.

This was verified the hard way on macOS 26.5.2: with the bundle installed and
confirmed present in the booted auxKC (`_PrelinkExecutableLoadAddr` and all),
the policy still never registered across a full boot — no `sysctl sedarwin`, no
log lines, nothing. The `IOResources`/`IOBSD` `IOKitPersonalities` entry does
not change that; the sibling procfs/sysfs kexts carry the identical personality
and are likewise loaded by a LaunchDaemon at boot, not by IOKit matching.

So `make install` also installs:

- `/usr/local/sbin/sedarwin-load` — loads the kext (`kmutil load -p`), polls
  until it shows up, and confirms the policy registered by checking that the
  `sedarwin.trace` sysctl exists.
- `/Library/LaunchDaemons/com.beako.sedarwin.plist` — runs that script once at
  boot (`RunAtLoad`), logging to `/var/log/sedarwin-load.log`.

Auto-load is gated behind the arm flag `/var/db/sedarwin.enabled`, absent by
default, so a fault in kernel code cannot boot-loop the machine. The gate
matters more here than for the filesystem siblings: once this policy registers,
its hooks sit on every open/exec/signal/connect on the system. `sudo make load`
runs the same script the daemon runs, so an interactive test exercises exactly
the boot path.

The kext is a `MPC_LOADTIME_FLAG_NOTLATE`-free, late-loading policy, so it
registers after the kernel's own policies (SIP, sandbox, seatbelt). The kext
must still be dev-mode signed/admitted — see Requirements.

### Hook groups: bisecting without rebuilding

The policy registers with **no check hooks installed** — only the lifecycle
slots, which fire once each from the register path. Everything else is opt-in
at runtime:

```sh
sysctl sedarwin.hooks            # 0 on a fresh load
sudo sysctl sedarwin.hooks=1     # + vnode_check_open only
sudo sysctl sedarwin.hooks=0     # back to inert
```

The mask does not persist across a load — a fresh load is always back to 0.

**Validated set: `0x1fffef`.** All twenty hooks other than the quarantined
`vnode_check_lookup` have been enabled simultaneously on macOS 26.5.2 /
xnu-12377.121.10 (arm64e) and run without incident:

```sh
sudo sysctl sedarwin.hooks=0x1fffef   # everything except the unsafe bit
```

One bit per **hook**, not per group — when a group wedges the machine the next
question is always *which* hook, and answering it must not cost a rebuild:

| bit | hook | | bit | hook |
|-----|------|-|-----|------|
| 0x000001 | vnode_check_open | | 0x000800 | file_check_library_validation |
| 0x000002 | vnode_check_create | | 0x001000 | proc_check_signal |
| 0x000004 | vnode_check_unlink | | 0x002000 | proc_check_fork |
| 0x000008 | vnode_check_rename | | 0x004000 | proc_notify_exit |
| 0x000010 | vnode_check_lookup | | 0x008000 | socket_check_connect |
| 0x000020 | vnode_check_readlink | | 0x010000 | socket_check_create |
| 0x000040 | vnode_check_getattr | | 0x020000 | socket_check_listen |
| 0x000080 | vnode_check_setattrlist | | 0x040000 | pty_notify_grant |
| 0x000100 | vnode_label_associate_extattr | | 0x080000 | vnode_check_exec |
| 0x000200 | vnode_label_copy | | 0x100000 | proc_notify_exec_complete |
| 0x000400 | file_check_mmap | | | |

So `sedarwin.hooks=1` is now **only** `vnode_check_open`, not the whole vnode
group. Bisect a bad group by halving: `0x0f`, then `0x03`, then `0x01`.

#### `vnode_check_lookup` (0x10) is known bad

Installing that one slot wedges the machine — hard hang, no panic, no log —
**even though the hook body does nothing** when tracing is off. It is gated
behind a second key so a stray `0xff` cannot take the box down:

```sh
sudo sysctl sedarwin.unsafe=1    # required first
sudo sysctl sedarwin.hooks=0x10  # EPERM without the above
```

Established by bisection on macOS 26.5.2 / xnu-12377.121.10:

| mask | hooks | result |
|------|-------|--------|
| `0x01` | open | survives |
| `0xae` | create, unlink, rename, readlink, setattrlist | survives |
| `0x40` | getattr | survives |
| `0xff` | all eight | **freeze** |

Every hook but `0x10` is exonerated, so `mpo_vnode_check_lookup` is the one.

Since our body is empty, the fault is in what the *kernel* does because the slot
is non-NULL: per dispatch it resolves the vnode's label and runs it through a
zone-pointer validator whose failure path is `panic`. `vnode_check_lookup` fires
on every component of every path resolution, reaching that machinery far more
often than anything else.

##### Where it is dispatched from

Disassembling the running kernel shows this hook is called from
`cache_lookup_path()` in `vfs_cache.c` — the name cache fast path — with the
name-cache rw lock held shared:

```
ldr  w8, [x22, #0x4]      ; cnp->cn_flags
tbnz w8, #0xb, skip       ; bit 11 = DONOTAUTH -> skip the check
bl   mac_vnode_check_lookup
cbnz w0, error            ; error path calls name_cache_unlock()
```

That is a different regime from every other vnode hook this policy installs.
The others fire once per *operation*, with no name-cache lock. This one fires
once per path *component*, on every lookup on the system, with a global VFS
lock held. The dispatch code itself is byte-for-byte the same shape as
`vnode_check_open`'s — same loop, same label resolve — so the difference is
the calling context, not the dispatch.

##### The fuse

A wedged kernel cannot be read, so the hook now counts its dispatches and
uninstalls itself after `sedarwin.lookup_fuse` of them (0 = no limit). That
allows a bounded number of real dispatches and then a look at the result:

```sh
sudo sysctl sedarwin.lookup_fuse=1     # allow exactly one dispatch
sudo sysctl sedarwin.unsafe=1
sudo sysctl sedarwin.hooks=0x10        # arms it; it disarms itself
sysctl sedarwin.lookup_count           # how many landed
sysctl sedarwin.hooks                  # bit 0x10 gone once the fuse blew
```

Raising the fuse until it breaks brackets the mechanism.

Results so far:

| fuse | outcome |
|------|---------|
| 1 | survives — `lookup_count` reads 1, the bit clears, machine stays up |
| 32 | **freeze** |
| 1000 | **freeze** — dies before the fuse can blow |

A single dispatch is harmless, which retires every hypothesis that would fail
deterministically on dispatch #1: a bad slot, a wrong signature, a PAC
mismatch, a NULL-label panic in the resolver.

The 1000 result is the more informative one. Every path resolution on the
system comes through this hook, from every core, so 1000 dispatches is a few
tens of milliseconds — the machine died well before the fuse could fire. That
speed rules out a slow leak: 1000 allocations against a `MAC.Labels` zone
already holding ~16000 elements is nothing. Whatever this is, it goes wrong
almost immediately once the hook is live at system-wide rates.

A fuse of 32 is enough. Thirty-two dispatches take microseconds, and the hook
body at that point is *a single relaxed atomic add* — no locks, no allocation,
no logging, not even a read of the trace flag. An atomic increment executed
thirty-two times cannot wedge a machine.

**So the fault is not in this policy's code.** It is in what the kernel does
because the slot is non-NULL, and it needs the slot to stay non-NULL across more
than one dispatch. Roughly one lookup in ≤32 is enough to trigger it, so
whatever the condition is, it is common rather than exotic.

##### What has been ruled out

- **The ABI.** Slot offset, struct layout and arm64e PAC discriminator all
  verified against the KDK's DWARF and the running kernel's dispatch code.
- **Anything deterministic on entry.** A fuse of 1 survives, so the hook is not
  faulting when called.
- **Our hook body.** It is one atomic add.
- **A leak.** The machine dies within tens of milliseconds; 32 allocations
  against a `MAC.Labels` zone holding ~15000 elements is nothing.
- **Lazy label allocation.** The label resolver returns NULL harmlessly for an
  unlabeled vnode — it neither allocates nor panics, and only a *corrupt*
  (non-NULL, failing zone validation) label reaches its `panic` call. This is
  the common case, not an edge case: the system carries 153365 vnodes and only
  4308 labels, so ~97% of dispatches hand the policy a NULL `dlabel`.

##### What is left

The distinguishing property remains the caller: this is the only hook this
policy installs that is dispatched from inside the name cache, holding the
name-cache rw lock shared, once per path component.

Pinning it down further means observing a kernel that is already wedged, which
needs a second machine and KDP (`boot-args` `debug=0x144 -v`, `kdp_match_name`,
`kmutil` remote). That is the right tool for this and the point at which
guessing stops being cheap: every wrong hypothesis from here costs a reboot,
and the ones that were cheap to test are now exhausted.

Clearing the slot from inside a dispatch of it is safe: the framework has
already loaded the pointer for that call, and a CPU racing the store reads
either the old pointer or NULL, both of which it handles.

A remaining hypothesis — **unproven** — is lazy label allocation. A late-loaded
policy means vnodes predating it carry no label; a lookup hook may force the
framework to allocate one from inside path resolution, under the caller's VFS
locks. An allocation that needs to reclaim re-enters VFS, which re-enters
lookup. That would deadlock exactly like this, and silently. This policy
registers with `mpc_field_off = NULL` — no label slot of its own.

This works because the framework never copies the ops vector: it keeps the
pointer handed to `mac_policy_register()` and re-reads the slot on every
dispatch, treating NULL as "no opinion". Filling or clearing a slot on a live
policy therefore takes effect immediately.

That property is what makes this kext debuggable at all. A rebuilt kext has a
new cdhash, so testing one costs a re-approval **and** a reboot; flipping this
mask costs a `sysctl` write. Enable one group, exercise the machine, and if it
survives, move to the next.

### Diagnostics

Lifecycle messages (register/init/destroy) are always emitted; per-event traces
are **off by default** behind a runtime gate, because the check hooks fire on
every open/exec/signal/connect on the system:

The policy's output reaches the unified log, so this is the reliable way to read
it (`dmesg` needs root and only shows the tail of the kernel buffer):

```sh
log show --last 5m --predicate 'eventMessage CONTAINS "SEDarwin"' --style compact
log stream --predicate 'eventMessage CONTAINS "SEDarwin"'
```

Successful registration also produces the framework's own line, which is worth
knowing because it comes from the kernel rather than from this policy:

```
kernel: Security policy loaded: SEDarwin Security Extension (com.beako.security.sedarwin)
```

With the trace gate off, the hooks do nothing but test a flag and return — no
formatting, and in particular no `proc_name()`, which resolves a pid through
`proc_find()` and takes `proc_list_lock`. MAC hooks fire from contexts that may
already hold that lock (signal delivery, process exit), so every per-event hook
returns behind `sebsd_tracing()` before touching anything.

#### Turning tracing on is not free

```sh
sudo sysctl sedarwin.trace=1
sudo sysctl sedarwin.trace=0
```

**Do not enable tracing with a wide hook mask.** The gate is what makes the wide
mask survivable. Turn it on with `hooks=0x1fffef` and every `open`, `getattr`,
`mmap`, `fork`, `exit`, `exec` and socket operation on the system takes a kernel
`printf` — serialized, tens of thousands per second. That is its own way to make
the machine unusable, and it would look like a hook fault rather than what it is.

Trace narrowly. Pick the low-frequency hooks first and widen only as needed:

| mask | hooks | rate |
|------|-------|------|
| `0x40000` | pty grant | very low |
| `0x180000` | exec check + complete | low |
| `0x7000` | signal, fork, exit | moderate |
| `0x38000` | socket connect/create/listen | moderate |
| `0x400` | mmap | high |
| `0x1` / `0x40` | open / getattr | very high — expect a flood |

## Layout

```
include/sedarwin/   sebsd_mac.h - hand-written MAC framework ABI (offsets verified)
                    sebsd.h     - shared policy constants (names, flags, version)
kext/               the policy kext sources
                    main.c     - kmod entry, policy conf, ops wiring
                    vnode.c    - vnode check hooks
                    file.c     - mmap / library-validation hooks
                    proc.c     - signal / fork / exit hooks
                    net.c      - socket connect / create / listen hooks
                    tty.c      - pty grant notification
                    spawn.c    - exec-related hooks
                    MachO.c    - in-memory Mach-O parser + load-time selftest
lib/libkern-bsd/    malloc/sbuf helpers compiled against the kernel SDK.
                    Built, but NOT linked into the kext - the policy references
                    nothing from it; it is here for the userland side.
tools/              sedarwin-load            - boot-time loader script
                    com.beako.sedarwin.plist - LaunchDaemon that runs it
Makefile            top-level orchestrator (build/install/load/uninstall/clean)
Makefile.inc        variables; single source of truth: VERSION
```

## ABI compatibility

The MAC KPI is private and changes between xnu versions. This kext pins the
ABI to the kernel it was verified against (macOS 26.5.2, build 25F84, xnu
12377.121.10):

- `mac_policy_ops` is exactly **335 slots / 2680 bytes**; a short struct would
  be read out of bounds by the framework's slot dispatch. The struct is
  zero-initialized and unimplemented slots are typed `mpo_hook_t *` to hold
  the size while only spelling out implemented hooks.
- Field offsets for `mac_policy_conf` and the `mpo_policy_init` /
  `mpo_policy_initbsd` slots were recovered from a disassembly of
  `_mac_policy_register` in the running kernel and are documented in
  `include/sedarwin/sebsd_mac.h`.
- `_Static_assert(sizeof(struct mac_policy_ops) == 2680)` fails the build if
  the ABI assumption ever breaks.

On a different kernel, re-verify the offsets before using this as a base.

### Verifying the ABI against the kernel

The claims above are checkable, and were checked, against the matching Kernel
Debug Kit (`/Library/Developer/KDKs/KDK_26.5.2_25F84.kdk`) rather than by
inspection. The release kernel ships a dSYM with full DWARF, so the real
struct is readable:

```sh
DS=/Library/Developer/KDKs/KDK_26.5.2_25F84.kdk/System/Library/Kernels/kernel.release.t8142.dSYM/Contents/Resources/DWARF/kernel.release.t8142
dwarfdump --name=mac_policy_ops "$DS"        # DW_AT_byte_size (0x0a78) = 2680
```

Dumping the members with `DW_AT_data_member_location` gives all 335 slot
offsets, which can be diffed against the struct in `sebsd_mac.h` — the order
matches exactly, and every hook this policy installs lands on the slot the
kernel expects.

There is a second, easily-missed requirement on arm64e: the kernel dispatches
hooks through an **authenticated** branch.

```
ldr   x8,  [x23, #0x20]    ; mpc_ops
ldr   x26, [x8, #0x858]    ; mpo_vnode_check_open
mov   x17, #0x1586         ; type discriminator
blraa x26, x17
```

So a slot must hold a pointer signed with key IA and that slot's discriminator,
or the call fails authentication. The compiler emits the correct `pacia` when
the pointer is stored **through the typed struct member** — which is why
`sebsd_install_hooks()` assigns members directly and never memcpy's or casts
through a generic pointer type. Scanning the kernel for `mpc_ops`-based
dispatches yields 286 slots with their discriminators; all of this policy's
hooks match.

## Versioning

The kext/Info.plist and kmod version read from the repo's `VERSION` file via
`Makefile.inc` — bump that file, not the plist.

Copyright (C) 2022-2026 Sunneva N. Mariu. All rights reserved.
