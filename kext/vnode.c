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
 * bisection that established it and the leading hypothesis. The bit is gated
 * behind `sysctl sedarwin.unsafe=1`; do not install it casually.
 */
int
sebsd_vnode_check_lookup(kauth_cred_t cred, struct vnode *dvp,
    struct label *dlabel, struct componentname *cnp)
{
	(void)dvp;
	(void)dlabel;
	(void)cred;
	(void)cnp;
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
