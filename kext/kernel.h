/*-
 * SEDarwin policy kext - internal umbrella header.
 *
 * Every kext translation unit includes this first.
 *
 * Everything here comes from the PUBLIC kernel SDK (Kernel.framework) plus this
 * project's own headers. The one unavoidable exception is sebsd_mac.h, which
 * hand-declares the MAC framework ABI because that KPI is private and the SDK
 * ships none of it.
 *
 * This used to include a stack of kernel-private headers vendored from the xnu
 * source (sys/proc_internal.h, sys/vnode_internal.h, sys/user.h, ...). Those
 * are gone. They are not merely redundant: the vendored copies come from a
 * different xnu build than the running kernel, so any struct laid out from them
 * is a guess, and pulling in one internal header dragged in most of the osfmk
 * lock/zalloc/waitq chain behind it. Where a definition really is private, the
 * policy now either uses the public accessor (proc_find_ident() rather than
 * reaching into struct proc_ident) or forward-declares the type because it only
 * ever holds a pointer to it.
 *
 * Logging is plain kernel printf() with a module tag; there is no syslog in
 * the kernel, so the policy does not attempt openlog()/syslog().
 */

#ifndef _SEBSD_KERNEL_H_
#define _SEBSD_KERNEL_H_

#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/kernel_types.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <libkern/libkern.h>
#include <kern/cs_blobs.h>

#include <sedarwin/sebsd.h>
#include <sedarwin/sebsd_mac.h>

/*
 * Types the hooks only ever take a pointer to (struct fileglob, tty, attrlist)
 * are forward-declared in sebsd_mac.h, which has to see them before it declares
 * the hook typedefs.
 */

/*
 * Hook implementations, grouped by subsystem. main.c wires them into
 * struct mac_policy_ops. Declared here so every module can reference them.
 */

void    sebsd_policy_init(struct mac_policy_conf *mpc);
void    sebsd_policy_initbsd(struct mac_policy_conf *mpc);
void    sebsd_policy_destroy(struct mac_policy_conf *mpc);

int     sebsd_vnode_check_open(kauth_cred_t cred, struct vnode *vp,
            struct label *label, int acc_mode);
int     sebsd_vnode_check_create(kauth_cred_t cred, struct vnode *dvp,
            struct label *dlabel, struct componentname *cnp,
            struct vnode_attr *vap);
int     sebsd_vnode_check_unlink(kauth_cred_t cred, struct vnode *dvp,
            struct label *dlabel, struct vnode *vp, struct label *label,
            struct componentname *cnp);
int     sebsd_vnode_check_rename(kauth_cred_t cred, struct vnode *fdvp,
            struct label *fdlabel, struct vnode *fvp, struct label *flabel,
            struct componentname *fcnp, struct vnode *tdvp,
            struct label *tdlabel, struct vnode *tvp, struct label *tlabel,
            struct componentname *tcnp);
int     sebsd_vnode_check_lookup(kauth_cred_t cred, struct vnode *dvp,
            struct label *dlabel, struct componentname *cnp);

int     sebsd_vnode_check_readlink(kauth_cred_t cred, struct vnode *vp,
            struct label *label);
int     sebsd_vnode_check_getattr(kauth_cred_t active_cred,
            kauth_cred_t file_cred, struct vnode *vp, struct label *vlabel,
            struct vnode_attr *va);
int     sebsd_vnode_check_setattrlist(kauth_cred_t cred, struct vnode *vp,
            struct label *vlabel, struct attrlist *alist);
int     sebsd_vnode_label_associate_extattr(struct mount *mp,
            struct label *mntlabel, struct vnode *vp, struct label *vlabel);
void    sebsd_vnode_label_copy(struct label *src, struct label *dest);

/*
 * Instrumentation for the quarantined lookup hook (see vnode.c). The counter
 * and fuse are exported through sysctl by main.c, which also owns the ops
 * vector and so provides the "uninstall myself" call.
 */
extern unsigned int sebsd_lookup_count;
extern int          sebsd_lookup_fuse;
void    sebsd_hooks_blow_lookup_fuse(void);

int     sebsd_file_check_mmap(kauth_cred_t cred, struct fileglob *fg,
            struct label *label, int prot, int flags, uint64_t file_pos,
            int *maxprot);
int     sebsd_file_check_library_validation(struct proc *p,
            struct fileglob *fg, off_t slice_offset, user_long_t error_message,
            size_t error_message_size);

int     sebsd_proc_check_signal(kauth_cred_t cred, proc_ident_t instigator,
            proc_ident_t target, int signum);
int     sebsd_proc_check_fork(kauth_cred_t cred, struct proc *proc);
void    sebsd_proc_notify_exit(struct proc *proc);

/* Process execution (spawn/exec) and code-signing observation. */
int     sebsd_spawn_check_exec(kauth_cred_t cred, struct vnode *vp,
            struct vnode *scriptvp, struct label *vnodelabel,
            struct label *scriptlabel, struct label *execlabel,
            struct componentname *cnp, u_int *csflags, void *macpolicyattr,
            size_t macpolicyattrlen);
void    sebsd_spawn_notify_exec_complete(struct proc *p);

/* In-memory Mach-O header inspection (thin/fat, CPU, LC_CODE_SIGNATURE). */
struct sebsd_macho_info {
	int     m_cputype;
	int     m_cpusubtype;
	int     m_ncmds;
	int     m_fat;          /* 1 if a fat binary was detected */
	int     m_codesign;     /* 1 if LC_CODE_SIGNATURE present */
};
int     sebsd_macho_info(const void *data, size_t len,
            struct sebsd_macho_info *info);
void    sebsd_macho_selftest(void);

int     sebsd_socket_check_connect(kauth_cred_t cred, socket_t so,
            struct label *socklabel, struct sockaddr *addr);
int     sebsd_socket_check_create(kauth_cred_t cred, int domain, int type,
            int protocol);
int     sebsd_socket_check_listen(kauth_cred_t cred, socket_t so,
            struct label *socklabel);

void    sebsd_pty_notify_grant(proc_t p, struct tty *tp, dev_t dev,
            struct label *label);

/*
 * Logging. Kernel printf() is the only sink; every message carries the
 * SEBSD_TAG prefix so kextstat/dmesg/streams of the console are greppable.
 *
 * There are two levels:
 *   sebsd_log()          - lifecycle events only (register/init/destroy),
 *                          always emitted, once per load at most.
 *   sebsd_log_debug()    - per-event traces (open/exec/signal/connect/...).
 *                          These sit on hot kernel paths (every open() and
 *                          exec() on the system), so they are gated behind the
 *                          runtime `sebsd_trace_enabled` flag (sysctl
 *                          sedarwin.trace), OFF by default. Do not print or do
 *                          VFS work unconditionally in a per-event hook.
 */
#define SEBSD_TAG "SEDarwin"

#ifndef SEBSD_LOGGING
#define SEBSD_LOGGING 1
#endif

/* Runtime gate for per-event trace lines; set via `sysctl sedarwin.trace`. */
extern int sebsd_trace_enabled;

#if SEBSD_LOGGING
#define sebsd_log(fmt, ...) \
    printf(SEBSD_TAG ": " fmt "\n", ##__VA_ARGS__)
#define sebsd_log_debug(fmt, ...) \
    do { \
        if (__builtin_expect(sebsd_trace_enabled, 0)) { \
            printf(SEBSD_TAG ": debug: " fmt "\n", ##__VA_ARGS__); \
        } \
    } while (0)
#else
#define sebsd_log(fmt, ...) do {} while (0)
#define sebsd_log_debug(fmt, ...) do {} while (0)
#endif

/*
 * Trace gate. Every per-event hook must test this FIRST and return immediately
 * when it is off, before gathering any subject identification. Formatting the
 * arguments is not free, and proc_name() in particular is not merely slow (see
 * sebsd_proc_name()) - leaving it on the unconditional path would put a lock
 * acquisition on every open()/exec()/signal/connect on the system even with
 * tracing disabled, which is the opposite of what the gate is for.
 */
static inline int
sebsd_tracing(void)
{
	return __builtin_expect(sebsd_trace_enabled != 0, 0) != 0;
}

/*
 * Cheap subject identification for trace lines: the running process's pid and
 * name.
 *
 * proc_selfname() reads p_comm straight off current_proc() and takes no locks.
 * proc_name(pid) does NOT: it resolves the pid through proc_find(), which takes
 * proc_list_lock. MAC hooks fire from contexts that may already hold it (signal
 * delivery, proc exit), so the current-process helper must never go that route.
 */
static inline int
sebsd_cur_pid(void)
{
	return proc_pid(current_proc());
}

static inline void
sebsd_cur_name(char *buf, size_t len)
{
	proc_selfname(buf, (int)len);
}

/*
 * Name of some OTHER process, by pid. This one does go through proc_find() and
 * therefore takes proc_list_lock - only ever call it from behind
 * sebsd_tracing(), i.e. when an operator has explicitly asked for traces.
 */
static inline void
sebsd_proc_name(int pid, char *buf, size_t len)
{
	proc_name(pid, buf, (int)len);
}

/*
 * Cap for name buffers in trace lines. Deliberately far below NAME_MAX: these
 * buffers land on the KERNEL stack (16K, and MAC hooks fire deep inside VFS
 * recursion), so a NAME_MAX+1 buffer per hook is not affordable - a rename
 * hook alone would carry half a kilobyte. Trace output is diagnostic, so
 * truncating a long component is the right trade. Note the build sets
 * -fno-stack-check -fno-stack-protector, so an overflow here would not trap;
 * it would silently corrupt whatever lies below the stack.
 */
#define SEBSD_TRACE_NAME_MAX    64

/*
 * Copy a lookup component into a caller buffer, NUL-terminating it. cn_nameptr
 * is not guaranteed NUL-terminated; cn_namelen is authoritative.
 */
static inline void
sebsd_cnp_name(struct componentname *cnp, char *buf, size_t len)
{
	size_t n;

	if (cnp == NULL || cnp->cn_nameptr == NULL) {
		strlcpy(buf, "<none>", len);
		return;
	}
	n = (size_t)cnp->cn_namelen;
	if (n >= len) {
		n = len - 1;
	}
	memcpy(buf, cnp->cn_nameptr, n);
	buf[n] = '\0';
}

#endif /* _SEBSD_KERNEL_H_ */
