/*-
 * SEDarwin policy kext - process execution hooks.
 *
 * mpo_vnode_check_exec is the last MAC gate before a binary starts. For M0 the
 * hook is observational: it logs the signature-verification state the kernel
 * has already computed (csflags), which is the interesting security datum
 * (ad-hoc vs signed, valid vs invalid, hardened runtime, etc.), and grants
 * execution.
 *
 * The kernel hands the executing image's vnode to this hook; reading the file
 * back out of it to parse the Mach-O header (see MachO.c) is deliberately NOT
 * done in the exec path - it would re-enter the VFS under the exec path's
 * locks. sebsd_macho_info() is exercised against an in-memory image at load
 * time instead, and is ready for a lock-free reader in a later milestone.
 */

#include "kernel.h"

static const char *
sebsd_csflag_bits(u_int flags, char *buf, size_t len)
{
	int first = 1;
	char *p = buf;
	size_t left = len;

	*p = '\0';
#define CSFLAG_BIT(mask, name)                                                \
	do {                                                                    \
		if ((flags & (mask)) != 0) {                                    \
			if (!first) {                                           \
				if (left > 1) {                                 \
					*p++ = ',';                             \
					left--;                                 \
				}                                               \
			}                                                       \
			if (left > 1) {                                         \
				*p++ = (name);                                 \
				left--;                                         \
			}                                                       \
			first = 0;                                              \
		}                                                               \
	} while (0)

	CSFLAG_BIT(CS_VALID, 'V');
	CSFLAG_BIT(CS_ADHOC, 'A');
	CSFLAG_BIT(CS_SIGNED, 'S');
	CSFLAG_BIT(CS_HARD, 'H');
	CSFLAG_BIT(CS_KILL, 'K');
	CSFLAG_BIT(CS_RUNTIME, 'R');
	CSFLAG_BIT(CS_RESTRICT, 'T');
	CSFLAG_BIT(CS_DEBUGGED, 'D');
	CSFLAG_BIT(CS_PLATFORM_BINARY, 'P');
	CSFLAG_BIT(CS_INSTALLER, 'I');
	*p = '\0';

#undef CSFLAG_BIT

	return buf;
}

/* Buffers live here, not in the hook: see the note at the top of vnode.c. */
static void __attribute__((noinline))
sebsd_trace_exec(kauth_cred_t cred, u_int flags)
{
	char pname[MAXCOMLEN + 1];
	char sig[32];

	sebsd_cur_name(pname, sizeof(pname));
	sebsd_csflag_bits(flags, sig, sizeof(sig));
	sebsd_log_debug("exec: %s pid=%d uid=%d cs=0x%x(%s)", pname,
	    sebsd_cur_pid(), kauth_cred_getuid(cred), flags, sig);
}

int
sebsd_spawn_check_exec(kauth_cred_t cred, struct vnode *vp,
    struct vnode *scriptvp, struct label *vnodelabel,
    struct label *scriptlabel, struct label *execlabel,
    struct componentname *cnp, u_int *csflags, void *macpolicyattr,
    size_t macpolicyattrlen)
{
	(void)vp;
	(void)scriptvp;
	(void)vnodelabel;
	(void)scriptlabel;
	(void)execlabel;
	(void)cnp;
	(void)macpolicyattr;
	(void)macpolicyattrlen;

	if (sebsd_tracing()) {
		sebsd_trace_exec(cred, csflags != NULL ? *csflags : 0);
	}
	return 0;
}

void
sebsd_spawn_notify_exec_complete(struct proc *p)
{
	char pname[MAXCOMLEN + 1];

	(void)p;
	if (!sebsd_tracing()) {
		return;
	}
	sebsd_cur_name(pname, sizeof(pname));
	sebsd_log_debug("exec complete: %s pid=%d", pname, sebsd_cur_pid());
}
