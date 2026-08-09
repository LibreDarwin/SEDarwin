/*-
 * SEDarwin policy kext - shared policy metadata and module-wide declarations.
 *
 * The policy name is com.beako.security.sedarwin (inside the com.beako.security
 * bundle domain) and it registers with the kernel's TrustedBSD MAC framework
 * as a late-loading extension policy.
 */

#ifndef _SEBSD_SEBSD_H_
#define _SEBSD_SEBSD_H_

#define SEBSD_POLICY_NAME       "com.beako.security.sedarwin"
#define SEBSD_POLICY_FULLNAME   "SEDarwin Security Extension"
#define SEBSD_POLICY_VERSION    "0.0.1"

#define SEBSD_LOADTIME_FLAGS    0
#define SEBSD_LABELNAMES        NULL
#define SEBSD_LABELNAME_COUNT   0

/*
 * Hook groups, selectable at runtime through `sysctl sedarwin.hooks`.
 *
 * The policy registers with NO check hooks installed - only the lifecycle
 * slots (init/initbsd/destroy). Everything else is opt-in at runtime.
 *
 * This exists because the framework does not copy the ops vector: it keeps the
 * pointer the policy handed to mac_policy_register() and re-reads the
 * individual slot on every dispatch, treating NULL as "this policy has no
 * opinion". So a slot can be filled or cleared while the policy is live and it
 * takes effect immediately - which makes it possible to bisect a misbehaving
 * hook group WITHOUT rebuilding the kext. That matters a great deal here: a
 * rebuilt kext has a new cdhash, so testing one costs a re-approval and a
 * reboot, while flipping this mask costs a sysctl write.
 *
 * Start at 0, add one group, exercise the machine, repeat.
 */
#define SEBSD_HOOK_VNODE_CHECK  0x0001  /* open/create/unlink/rename/lookup... */
#define SEBSD_HOOK_VNODE_LABEL  0x0002  /* label_associate_extattr, label_copy */
#define SEBSD_HOOK_FILE         0x0004  /* mmap, library validation           */
#define SEBSD_HOOK_PROC         0x0008  /* signal, fork, exit                 */
#define SEBSD_HOOK_SOCKET       0x0010  /* connect, create, listen            */
#define SEBSD_HOOK_PTY          0x0020  /* pty grant                          */
#define SEBSD_HOOK_EXEC         0x0040  /* vnode_check_exec, exec_complete    */

#define SEBSD_HOOK_ALL          (SEBSD_HOOK_VNODE_CHECK | SEBSD_HOOK_VNODE_LABEL | \
                                 SEBSD_HOOK_FILE | SEBSD_HOOK_PROC | \
                                 SEBSD_HOOK_SOCKET | SEBSD_HOOK_PTY | \
                                 SEBSD_HOOK_EXEC)

/* Installed at registration time. Deliberately none. */
#define SEBSD_HOOK_DEFAULT      0

#endif /* _SEBSD_SEBSD_H_ */
