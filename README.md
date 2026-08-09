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
sudo touch /var/db/sedarwin.enabled  # arm the boot loader
sudo reboot
make status                          # installed / armed / loaded / trace
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

### Diagnostics

Lifecycle messages (register/init/destroy) are always emitted; per-event traces
are **off by default** behind a runtime gate, because the check hooks fire on
every open/exec/signal/connect on the system:

```sh
sudo dmesg | grep sedarwin
sudo sysctl sedarwin.trace=1   # enable per-event traces
sudo sysctl sedarwin.trace=0   # back off
```

With the gate off, the hooks do nothing but test a flag and return — no
formatting, and in particular no `proc_name()`, which resolves a pid through
`proc_find()` and takes `proc_list_lock`. MAC hooks fire from contexts that may
already hold that lock (signal delivery, process exit), so every per-event hook
returns behind `sebsd_tracing()` before touching anything.

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
lib/libkern-bsd/    malloc/sbuf helpers compiled against the kernel SDK
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

## Versioning

The kext/Info.plist and kmod version read from the repo's `VERSION` file via
`Makefile.inc` — bump that file, not the plist.

Copyright (C) 2022-2026 Sunneva N. Mariu. All rights reserved.
