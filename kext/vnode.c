/*-
 * SEDarwin policy kext - vnode access-control hooks.
 *
 * M0 stage: these are observational. Every hook grants access (returns 0)
 * after logging; none of them denies yet. The enforcement logic (which paths,
 * which callers, what to do) lives in userland / later milestones, keyed off
 * the trace this module emits.
 *
 * Hooks here must not walk the vnode back to a path: check hooks fire with the
 * vnode already locked (open/exec paths), and vn_getpath() from inside one
 * re-locks the same vnode and deadlocks the machine - no panic, just a hard
 * freeze. The trace is limited to pid/name/type/op; recovering paths is a
 * userland problem.
 *
 * Every hook is split in two: a tiny entry point that tests the trace gate and
 * returns, and a noinline helper holding the character buffers. These hooks sit
 * on the KERNEL stack inside VFS recursion, and the compiler reserves a
 * function's whole frame on entry - so buffers declared in the entry point
 * would be paid for on every open/lookup/getattr on the system even with
 * tracing off. Keeping them in the helper keeps the hot path's frame minimal.
 */

#include "kernel.h"

static void __attribute__((noinline))
sebsd_trace_open(kauth_cred_t cred, int acc_mode)
{
	char pname[MAXCOMLEN + 1];

	sebsd_cur_name(pname, sizeof(pname));
	sebsd_log_debug("vnode open: %s pid=%d uid=%d mode=0x%x", pname,
	    sebsd_cur_pid(), kauth_cred_getuid(cred), acc_mode);
}

int
sebsd_vnode_check_open(kauth_cred_t cred, struct vnode *vp,
    struct label *label, int acc_mode)
{
	(void)vp;
	(void)label;
	if (sebsd_tracing()) {
		sebsd_trace_open(cred, acc_mode);
	}
	return 0;
}

static void __attribute__((noinline))
sebsd_trace_component(const char *op, kauth_cred_t cred,
    struct componentname *cnp)
{
	char pname[MAXCOMLEN + 1];
	char name[SEBSD_TRACE_NAME_MAX];

	sebsd_cur_name(pname, sizeof(pname));
	sebsd_cnp_name(cnp, name, sizeof(name));
	sebsd_log_debug("vnode %s: %s pid=%d name=%s uid=%d", op, pname,
	    sebsd_cur_pid(), name, kauth_cred_getuid(cred));
}

int
sebsd_vnode_check_create(kauth_cred_t cred, struct vnode *dvp,
    struct label *dlabel, struct componentname *cnp, struct vnode_attr *vap)
{
	(void)dvp;
	(void)dlabel;
	(void)vap;
	if (sebsd_tracing()) {
		sebsd_trace_component("create", cred, cnp);
	}
	return 0;
}

int
sebsd_vnode_check_unlink(kauth_cred_t cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label,
    struct componentname *cnp)
{
	(void)dvp;
	(void)dlabel;
	(void)vp;
	(void)label;
	if (sebsd_tracing()) {
		sebsd_trace_component("unlink", cred, cnp);
	}
	return 0;
}

static void __attribute__((noinline))
sebsd_trace_rename(kauth_cred_t cred, struct componentname *fcnp,
    struct componentname *tcnp)
{
	char pname[MAXCOMLEN + 1];
	char from[SEBSD_TRACE_NAME_MAX];
	char to[SEBSD_TRACE_NAME_MAX];

	sebsd_cur_name(pname, sizeof(pname));
	sebsd_cnp_name(fcnp, from, sizeof(from));
	sebsd_cnp_name(tcnp, to, sizeof(to));
	sebsd_log_debug("vnode rename: %s pid=%d %s -> %s uid=%d", pname,
	    sebsd_cur_pid(), from, to, kauth_cred_getuid(cred));
}

int
sebsd_vnode_check_rename(kauth_cred_t cred, struct vnode *fdvp,
    struct label *fdlabel, struct vnode *fvp, struct label *flabel,
    struct componentname *fcnp, struct vnode *tdvp, struct label *tdlabel,
    struct vnode *tvp, struct label *tlabel, struct componentname *tcnp)
{
	(void)fdvp;
	(void)fdlabel;
	(void)fvp;
	(void)flabel;
	(void)tdvp;
	(void)tdlabel;
	(void)tvp;
	(void)tlabel;
	if (sebsd_tracing()) {
		sebsd_trace_rename(cred, fcnp, tcnp);
	}
	return 0;
}

/*
 * KNOWN BAD - installing this slot wedges the machine, even though the body
 * below does nothing at all. See the SEBSD_HOOK_UNSAFE note in sebsd.h for the
 * bisection that established it. The bit is gated behind
 * `sysctl sedarwin.unsafe=1`; do not install it casually.
 *
 * WHERE IT IS CALLED FROM. Unlike every other vnode hook this policy installs,
 * this one is dispatched from cache_lookup_path() in vfs_cache.c - the name
 * cache fast path - with the name-cache rw lock held shared. In the running
 * kernel the call site reads:
 *
 *      ldr  w8, [x22, #0x4]      ; cnp->cn_flags
 *      tbnz w8, #0xb, skip       ; bit 11 = DONOTAUTH -> skip the check
 *      bl   mac_vnode_check_lookup
 *      cbnz w0, error            ; error path does name_cache_unlock()
 *
 * So it fires once per path COMPONENT, on every lookup on the system, with a
 * global VFS lock held. That is a different regime from the other hooks, which
 * fire per operation with no name-cache lock.
 *
 * THE FUSE. Because a wedged kernel cannot be read, this hook counts its own
 * dispatches and uninstalls itself once it has seen `sedarwin.lookup_fuse` of
 * them (0 = no limit). That makes it possible to let the hook run a bounded
 * number of times and then look at what happened, instead of guessing:
 *
 *      sysctl sedarwin.lookup_fuse=1    # allow exactly one dispatch
 *      sysctl sedarwin.unsafe=1
 *      sysctl sedarwin.hooks=0x10
 *      sysctl sedarwin.lookup_count     # how many actually landed
 *
 * If the machine survives a fuse of 1 but dies at some larger N, the fault is
 * cumulative - a leak or unbounded growth - rather than something wrong with
 * the very first call. Raising N until it breaks brackets the mechanism.
 *
 * Clearing our own slot from inside a dispatch of it is safe: the framework has
 * already loaded the pointer for this call, and any CPU racing the store reads
 * either the old pointer or NULL, both of which it handles.
 */
unsigned int sebsd_lookup_count;

/*
 * Default fuse. Small and non-zero on purpose: arming this hook at system-wide
 * lookup rates wedges the machine in milliseconds, far too fast for any fuse
 * large enough to be interesting. 0 means "no limit" and is a deliberate act.
 *
 * The count is deliberately GLOBAL and unconditional - it bounds how long the
 * slot stays non-NULL, which is the only thing that actually limits exposure.
 * An earlier version gated the counter behind a pid filter so the hook would
 * only "engage" for one process; that was backwards. The kernel dispatches for
 * every lookup regardless of what the body does, so counting only one process's
 * dispatches left the slot installed until that process happened to do N
 * lookups - extending the window rather than narrowing it. The filter is gone.
 */
int sebsd_lookup_fuse = 16;

/*
 * Reentrancy detection.
 *
 * The remaining explanation for the wedge is that having this slot installed
 * leads, directly or indirectly, back into path resolution on the SAME thread
 * while it already holds the name-cache rw lock. That deadlocks, silently, and
 * would explain every observation: harmless for one dispatch (the fuse pulls
 * the slot before anything can re-enter), fatal once the slot survives past the
 * first call, and independent of anything the hook body does.
 *
 * So detect it rather than infer it. `owner` holds the thread currently inside
 * the hook; seeing our own thread there on entry means we have been re-entered.
 * On that path we set a flag, pull the slot immediately and return WITHOUT
 * recursing further - which turns a fatal hang into a fact that can be read
 * back afterwards with `sysctl sedarwin.lookup_recursed`.
 *
 * The owner store races across cores, but only in the direction of false
 * NEGATIVES: another thread can overwrite the slot and hide a genuine
 * reentry. A false positive would require reading our own thread pointer when
 * we are not nested, which cannot happen - thread pointers are unique and the
 * slot is cleared on the way out. So a set flag is evidence; a clear flag is
 * merely the absence of it.
 *
 * `maxdepth` separates the two ways depth can exceed 1: with `recursed` set it
 * is reentrancy on one thread, without it, it is simply several cores in the
 * hook at once.
 */
unsigned long sebsd_lookup_owner;
unsigned int  sebsd_lookup_depth;
unsigned int  sebsd_lookup_maxdepth;
unsigned int  sebsd_lookup_recursed;

int
sebsd_vnode_check_lookup(kauth_cred_t cred, struct vnode *dvp,
    struct label *dlabel, struct componentname *cnp)
{
	unsigned long self = (unsigned long)current_thread();
	unsigned int n, d;

	(void)dvp;
	(void)dlabel;
	(void)cred;
	(void)cnp;

	if (__atomic_load_n(&sebsd_lookup_owner, __ATOMIC_RELAXED) == self) {
		sebsd_lookup_recursed = 1;
		sebsd_hooks_blow_lookup_fuse();
		return 0;
	}
	__atomic_store_n(&sebsd_lookup_owner, self, __ATOMIC_RELAXED);

	d = __atomic_add_fetch(&sebsd_lookup_depth, 1, __ATOMIC_RELAXED);
	if (d > sebsd_lookup_maxdepth) {
		sebsd_lookup_maxdepth = d;
	}

	n = __atomic_add_fetch(&sebsd_lookup_count, 1, __ATOMIC_RELAXED);
	if (sebsd_lookup_fuse > 0 && n >= (unsigned int)sebsd_lookup_fuse) {
		sebsd_hooks_blow_lookup_fuse();
	}

	__atomic_sub_fetch(&sebsd_lookup_depth, 1, __ATOMIC_RELAXED);
	__atomic_store_n(&sebsd_lookup_owner, 0, __ATOMIC_RELAXED);
	return 0;
}

int
sebsd_vnode_check_readlink(kauth_cred_t cred, struct vnode *vp,
    struct label *label)
{
	(void)vp;
	(void)label;
	(void)cred;
	return 0;
}

int
sebsd_vnode_check_getattr(kauth_cred_t active_cred, kauth_cred_t file_cred,
    struct vnode *vp, struct label *vlabel, struct vnode_attr *va)
{
	(void)active_cred;
	(void)file_cred;
	(void)vp;
	(void)vlabel;
	(void)va;
	return 0;
}

int
sebsd_vnode_check_setattrlist(kauth_cred_t cred, struct vnode *vp,
    struct label *vlabel, struct attrlist *alist)
{
	(void)cred;
	(void)vp;
	(void)vlabel;
	(void)alist;
	return 0;
}

int
sebsd_vnode_label_associate_extattr(struct mount *mp, struct label *mntlabel,
    struct vnode *vp, struct label *vlabel)
{
	(void)mp;
	(void)mntlabel;
	(void)vp;
	(void)vlabel;
	return 0;
}

void
sebsd_vnode_label_copy(struct label *src, struct label *dest)
{
	(void)src;
	(void)dest;
}
