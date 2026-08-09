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
/*
 * One bit per hook, not per group: when a group wedges the machine, the next
 * question is always *which* hook, and answering it must not cost a rebuild.
 */
#define SEBSD_HOOK_VNODE_OPEN        0x00000001
#define SEBSD_HOOK_VNODE_CREATE      0x00000002
#define SEBSD_HOOK_VNODE_UNLINK      0x00000004
#define SEBSD_HOOK_VNODE_RENAME      0x00000008
#define SEBSD_HOOK_VNODE_LOOKUP      0x00000010
#define SEBSD_HOOK_VNODE_READLINK    0x00000020
#define SEBSD_HOOK_VNODE_GETATTR     0x00000040
#define SEBSD_HOOK_VNODE_SETATTRLIST 0x00000080
#define SEBSD_HOOK_VNODE_LBL_EXTATTR 0x00000100
#define SEBSD_HOOK_VNODE_LBL_COPY    0x00000200
#define SEBSD_HOOK_FILE_MMAP         0x00000400
#define SEBSD_HOOK_FILE_LIBVAL       0x00000800
#define SEBSD_HOOK_PROC_SIGNAL       0x00001000
#define SEBSD_HOOK_PROC_FORK         0x00002000
#define SEBSD_HOOK_PROC_EXIT         0x00004000
#define SEBSD_HOOK_SOCKET_CONNECT    0x00008000
#define SEBSD_HOOK_SOCKET_CREATE     0x00010000
#define SEBSD_HOOK_SOCKET_LISTEN     0x00020000
#define SEBSD_HOOK_PTY_GRANT         0x00040000
#define SEBSD_HOOK_EXEC_CHECK        0x00080000
#define SEBSD_HOOK_EXEC_COMPLETE     0x00100000

/* Convenience groupings (see README for the bisection procedure). */
#define SEBSD_HOOK_VNODE_CHECK  (SEBSD_HOOK_VNODE_OPEN | SEBSD_HOOK_VNODE_CREATE | \
                                 SEBSD_HOOK_VNODE_UNLINK | SEBSD_HOOK_VNODE_RENAME | \
                                 SEBSD_HOOK_VNODE_LOOKUP | SEBSD_HOOK_VNODE_READLINK | \
                                 SEBSD_HOOK_VNODE_GETATTR | SEBSD_HOOK_VNODE_SETATTRLIST)
#define SEBSD_HOOK_VNODE_LABEL  (SEBSD_HOOK_VNODE_LBL_EXTATTR | SEBSD_HOOK_VNODE_LBL_COPY)
#define SEBSD_HOOK_FILE         (SEBSD_HOOK_FILE_MMAP | SEBSD_HOOK_FILE_LIBVAL)
#define SEBSD_HOOK_PROC         (SEBSD_HOOK_PROC_SIGNAL | SEBSD_HOOK_PROC_FORK | \
                                 SEBSD_HOOK_PROC_EXIT)
#define SEBSD_HOOK_SOCKET       (SEBSD_HOOK_SOCKET_CONNECT | SEBSD_HOOK_SOCKET_CREATE | \
                                 SEBSD_HOOK_SOCKET_LISTEN)
#define SEBSD_HOOK_PTY          SEBSD_HOOK_PTY_GRANT
#define SEBSD_HOOK_EXEC         (SEBSD_HOOK_EXEC_CHECK | SEBSD_HOOK_EXEC_COMPLETE)

#define SEBSD_HOOK_ALL          (SEBSD_HOOK_VNODE_CHECK | SEBSD_HOOK_VNODE_LABEL | \
                                 SEBSD_HOOK_FILE | SEBSD_HOOK_PROC | \
                                 SEBSD_HOOK_SOCKET | SEBSD_HOOK_PTY | \
                                 SEBSD_HOOK_EXEC)

/* Installed at registration time. Deliberately none. */
#define SEBSD_HOOK_DEFAULT      0

#endif /* _SEBSD_SEBSD_H_ */
