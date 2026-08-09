/*-
 * SEDarwin policy kext - module entry point.
 *
 * The policy registers with the kernel's TrustedBSD MAC framework via the
 * hand-declared ABI in include/sedarwin/sebsd_mac.h. That header exists
 * because the MAC KPI is private: Kernel.framework ships neither the struct
 * nor the register/unregister entry points, and the ops vector must be a full
 * 335-slot (2680 byte) object - the framework keeps the pointer and reads
 * individual slots while scanning the policy list, so a short struct would be
 * read out of bounds.
 *
 * The mpc_ops pointer is not copied at registration time, which is also why
 * the ops vector lives in .data (writable, so the runtime flag set by
 * mac_policy_register() lands in the module's own copy) and is never
 * deallocated.
 *
 * Registration is unconditional and late-loading (MPC_LOADTIME_FLAG_NOTLATE is
 * deliberately not set): the kext is installed into /Library/Extensions, so it
 * is loaded after the kernel's core policies (SIP, sandbox, seatbelt) have
 * already registered.
 */

#include "kernel.h"
#include <mach/kmod.h>
#include <mach/mach_types.h>

/*
 * Kext entry points. libkmod.a's _start/_stop call _realmain/_antimain, which
 * are the module's actual register/unregister hooks. KMOD_EXPLICIT_DECL
 * instantiates the global kmod_info that kextd uses to find this kext; the
 * name token (com.beako.security.sedarwin) is stringified by the macro.
 */
extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);

kern_return_t sebsd_mac_policy_register(kmod_info_t *ki, void *data);
kern_return_t sebsd_mac_policy_unregister(kmod_info_t *ki, void *data);

KMOD_EXPLICIT_DECL(com.beako.security.sedarwin, KEXTBUILD_S, _start, _stop)

__private_extern__ kmod_start_func_t *_realmain = sebsd_mac_policy_register;
__private_extern__ kmod_stop_func_t *_antimain = sebsd_mac_policy_unregister;

struct mac_policy_ops sebsd_ops;

struct mac_policy_conf sebsd_policy_conf = {
	.mpc_name           = SEBSD_POLICY_NAME,
	.mpc_fullname       = SEBSD_POLICY_FULLNAME,
	.mpc_labelnames     = SEBSD_LABELNAMES,
	.mpc_labelname_count= SEBSD_LABELNAME_COUNT,
	.mpc_ops            = &sebsd_ops,
	.mpc_loadtime_flags = SEBSD_LOADTIME_FLAGS,
	.mpc_field_off      = NULL,
	.mpc_runtime_flags  = 0,
	.mpc_data           = NULL,
};

/*
 * mac_policy_register() hands back an index into the framework's policy list,
 * and 0 is a perfectly legal one - so the handle cannot double as its own
 * "am I registered?" flag. Keep that state explicitly.
 */
static mac_policy_handle_t sebsd_handle;
static int sebsd_registered;

/*
 * Runtime gate for per-event trace lines (sysctl sedarwin.trace), OFF by
 * default. The check hooks fire on every open/exec/signal/connect on the
 * system; tracing unconditionally would flood the console log and add lock
 * contention to hot kernel paths. Enable when needed:
 *     sysctl sedarwin.trace=1
 */
int sebsd_trace_enabled = 0;

/*
 * Which hook groups are currently installed (sysctl sedarwin.hooks). Starts at
 * SEBSD_HOOK_DEFAULT - no check hooks at all - so a fresh load puts nothing on
 * any system call path until an operator asks for it. See sebsd_install_hooks().
 */
static int sebsd_hooks_enabled = SEBSD_HOOK_DEFAULT;

/* Defined below; the sysctl handler needs it before its definition. */
static void sebsd_install_hooks(struct mac_policy_ops *ops, int mask);

/*
 * The oids are built by hand rather than with the SYSCTL_* macros. Under
 * XNU_KERNEL_PRIVATE (which this kext compiles with) those macros expand to an
 * in-kernel STARTUP auto-registration referencing sysctl_register_oid_early()
 * - an internal symbol NOT exported to kexts, so the kext fails to bind and
 * never loads. Constructing the sysctl_oid structs directly and registering
 * them through the KPI sysctl_register_oid() avoids that symbol entirely;
 * omitting CTLFLAG_PERMANENT lets us remove them at unload. (Same fix as the
 * mSL-SysFS / procfs siblings.)
 */
static struct sysctl_oid_list sebsd_sysctl_children;

static struct sysctl_oid sebsd_sysctl_node = {
	.oid_parent  = &sysctl__children,
	.oid_number  = OID_AUTO,
	.oid_kind    = CTLTYPE_NODE | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_OID2,
	.oid_arg1    = &sebsd_sysctl_children,
	.oid_arg2    = 0,
	.oid_name    = "sedarwin",
	.oid_handler = NULL,
	.oid_fmt     = "N",
	.oid_descr   = "SEDarwin security policy",
	.oid_version = SYSCTL_OID_VERSION,
};

static struct sysctl_oid sebsd_sysctl_trace = {
	.oid_parent  = &sebsd_sysctl_children,
	.oid_number  = OID_AUTO,
	.oid_kind    = CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_OID2,
	.oid_arg1    = &sebsd_trace_enabled,
	.oid_arg2    = 0,
	.oid_name    = "trace",
	.oid_handler = sysctl_handle_int,
	.oid_fmt     = "I",
	.oid_descr   = "emit per-event trace lines",
	.oid_version = SYSCTL_OID_VERSION,
};

/*
 * Writing sedarwin.hooks installs or removes hook groups on the live policy.
 * Reject unknown bits rather than silently ignoring them, so a typo does not
 * look like it worked.
 */
static int
sebsd_sysctl_hooks_handler(struct sysctl_oid *oidp, void *arg1, int arg2,
    struct sysctl_req *req)
{
	int value = sebsd_hooks_enabled;
	int error;

	(void)arg1;
	(void)arg2;

	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == 0) {
		return error;   /* read, or a failed write */
	}
	if ((value & ~SEBSD_HOOK_ALL) != 0) {
		return EINVAL;
	}

	sebsd_hooks_enabled = value;
	sebsd_install_hooks(&sebsd_ops, value);
	sebsd_log("hooks now 0x%x", value);
	return 0;
}

static struct sysctl_oid sebsd_sysctl_hooks = {
	.oid_parent  = &sebsd_sysctl_children,
	.oid_number  = OID_AUTO,
	.oid_kind    = CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_OID2,
	.oid_arg1    = &sebsd_hooks_enabled,
	.oid_arg2    = 0,
	.oid_name    = "hooks",
	.oid_handler = sebsd_sysctl_hooks_handler,
	.oid_fmt     = "I",
	.oid_descr   = "installed hook groups (bitmask; 0 = none)",
	.oid_version = SYSCTL_OID_VERSION,
};

static void
sebsd_sysctl_register(void)
{
	sysctl_register_oid(&sebsd_sysctl_node);   /* parent first */
	sysctl_register_oid(&sebsd_sysctl_trace);
	sysctl_register_oid(&sebsd_sysctl_hooks);
}

static void
sebsd_sysctl_unregister(void)
{
	sysctl_unregister_oid(&sebsd_sysctl_hooks);
	sysctl_unregister_oid(&sebsd_sysctl_trace);
	sysctl_unregister_oid(&sebsd_sysctl_node);
}

/*
 * Lifecycle slots. These are the only hooks installed at registration time:
 * they fire once each, from the register/unregister path itself, and cannot be
 * reached by ordinary system activity.
 *
 * Assignment, not C99 designated initializers, so a stray field rename breaks
 * the build loudly rather than silently shifting every later hook.
 */
static void
sebsd_install_lifecycle(struct mac_policy_ops *ops)
{
	ops->mpo_policy_init                     = sebsd_policy_init;
	ops->mpo_policy_initbsd                  = sebsd_policy_initbsd;
	ops->mpo_policy_destroy                  = sebsd_policy_destroy;
}

/*
 * Install (or remove) the per-event hooks named by `mask`.
 *
 * The framework does not copy the ops vector - it keeps the pointer passed to
 * mac_policy_register() and re-reads the slot on every dispatch, treating NULL
 * as "no opinion". So filling or clearing a slot on a live policy takes effect
 * immediately, and a group can be enabled or disabled without reloading the
 * kext. Each slot is a single naturally-aligned pointer store; a dispatch
 * racing the store sees either the old pointer or the new one, both valid.
 *
 * Writing through the typed struct member (rather than memcpy or a cast) is
 * what gets the pointer signed with the right arm64e discriminator for that
 * slot - the kernel dispatches with `blraa`, so an unsigned or wrongly-signed
 * pointer would fail authentication.
 */
static void
sebsd_install_hooks(struct mac_policy_ops *ops, int mask)
{
	ops->mpo_vnode_check_open                = (mask & SEBSD_HOOK_VNODE_CHECK) ? sebsd_vnode_check_open : NULL;
	ops->mpo_vnode_check_create              = (mask & SEBSD_HOOK_VNODE_CHECK) ? sebsd_vnode_check_create : NULL;
	ops->mpo_vnode_check_unlink              = (mask & SEBSD_HOOK_VNODE_CHECK) ? sebsd_vnode_check_unlink : NULL;
	ops->mpo_vnode_check_rename              = (mask & SEBSD_HOOK_VNODE_CHECK) ? sebsd_vnode_check_rename : NULL;
	ops->mpo_vnode_check_lookup              = (mask & SEBSD_HOOK_VNODE_CHECK) ? sebsd_vnode_check_lookup : NULL;
	ops->mpo_vnode_check_readlink            = (mask & SEBSD_HOOK_VNODE_CHECK) ? sebsd_vnode_check_readlink : NULL;
	ops->mpo_vnode_check_getattr             = (mask & SEBSD_HOOK_VNODE_CHECK) ? sebsd_vnode_check_getattr : NULL;
	ops->mpo_vnode_check_setattrlist         = (mask & SEBSD_HOOK_VNODE_CHECK) ? sebsd_vnode_check_setattrlist : NULL;

	ops->mpo_vnode_label_associate_extattr   = (mask & SEBSD_HOOK_VNODE_LABEL) ? sebsd_vnode_label_associate_extattr : NULL;
	ops->mpo_vnode_label_copy                = (mask & SEBSD_HOOK_VNODE_LABEL) ? sebsd_vnode_label_copy : NULL;

	ops->mpo_file_check_mmap                 = (mask & SEBSD_HOOK_FILE) ? sebsd_file_check_mmap : NULL;
	ops->mpo_file_check_library_validation   = (mask & SEBSD_HOOK_FILE) ? sebsd_file_check_library_validation : NULL;

	ops->mpo_proc_check_signal               = (mask & SEBSD_HOOK_PROC) ? sebsd_proc_check_signal : NULL;
	ops->mpo_proc_check_fork                 = (mask & SEBSD_HOOK_PROC) ? sebsd_proc_check_fork : NULL;
	ops->mpo_proc_notify_exit                = (mask & SEBSD_HOOK_PROC) ? sebsd_proc_notify_exit : NULL;

	ops->mpo_socket_check_connect            = (mask & SEBSD_HOOK_SOCKET) ? sebsd_socket_check_connect : NULL;
	ops->mpo_socket_check_create             = (mask & SEBSD_HOOK_SOCKET) ? sebsd_socket_check_create : NULL;
	ops->mpo_socket_check_listen             = (mask & SEBSD_HOOK_SOCKET) ? sebsd_socket_check_listen : NULL;

	ops->mpo_pty_notify_grant                = (mask & SEBSD_HOOK_PTY) ? sebsd_pty_notify_grant : NULL;

	ops->mpo_vnode_check_exec                = (mask & SEBSD_HOOK_EXEC) ? sebsd_spawn_check_exec : NULL;
	ops->mpo_proc_notify_exec_complete       = (mask & SEBSD_HOOK_EXEC) ? sebsd_spawn_notify_exec_complete : NULL;
}

void
sebsd_policy_init(struct mac_policy_conf *mpc)
{
	sebsd_log("policy init: %s", mpc->mpc_fullname);
}

void
sebsd_policy_initbsd(struct mac_policy_conf *mpc)
{
	sebsd_log("policy initbsd: %s v%s registered, ops=%p (%u slots, %lu bytes)",
	    mpc->mpc_name, SEBSD_POLICY_VERSION, (void *)mpc->mpc_ops,
	    MAC_POLICY_OPS_SLOTS, (unsigned long)sizeof(struct mac_policy_ops));

	/*
	 * Exercise the in-memory Mach-O parser against a synthetic image so the
	 * code is proven at load time (see MachO.c for why the exec path does
	 * not read binaries itself).
	 */
	sebsd_macho_selftest();
}

void
sebsd_policy_destroy(struct mac_policy_conf *mpc)
{
	sebsd_log("policy destroy: %s", mpc->mpc_name);
}

kern_return_t
sebsd_mac_policy_register(kmod_info_t *ki, void *data)
{
	int error;

	(void)ki;
	(void)data;

	sebsd_install_lifecycle(&sebsd_ops);
	sebsd_install_hooks(&sebsd_ops, sebsd_hooks_enabled);
	sebsd_sysctl_register();

	error = mac_policy_register(&sebsd_policy_conf, &sebsd_handle, NULL);
	if (error != 0) {
		/*
		 * Returning failure from _start makes the kernel unload the
		 * module, freeing the memory these oids live in. Leaving them
		 * linked into sysctl__children would leave the global tree
		 * pointing at freed pages - the next `sysctl -a` walks it and
		 * takes the machine down. Undo the registration before failing.
		 */
		sebsd_sysctl_unregister();
		printf(SEBSD_TAG ": mac_policy_register failed: %d\n", error);
		return KERN_FAILURE;
	}

	sebsd_registered = 1;
	sebsd_log("registered with MAC framework (handle %u), hooks=0x%x",
	    sebsd_handle, sebsd_hooks_enabled);
	if (sebsd_hooks_enabled == 0) {
		sebsd_log("no check hooks installed; enable groups with "
		    "`sysctl sedarwin.hooks=<mask>`");
	}
	return KERN_SUCCESS;
}

kern_return_t
sebsd_mac_policy_unregister(kmod_info_t *ki, void *data)
{
	int error;

	(void)ki;
	(void)data;

	if (!sebsd_registered) {
		return KERN_SUCCESS;
	}

	/*
	 * Clear the per-event slots before asking the framework to drop the
	 * policy: from here on a dispatch that is already in flight reads NULL
	 * and skips us, which narrows the window in which the framework can
	 * enter this module while it is being torn down. The lifecycle slots
	 * stay - mac_policy_unregister() still calls mpo_policy_destroy().
	 */
	sebsd_install_hooks(&sebsd_ops, 0);

	error = mac_policy_unregister(sebsd_handle);
	if (error != 0) {
		/*
		 * The policy is still live, so the module stays loaded - leave
		 * the sysctls registered to match.
		 */
		printf(SEBSD_TAG ": mac_policy_unregister failed: %d\n", error);
		return KERN_FAILURE;
	}

	sebsd_registered = 0;
	sebsd_sysctl_unregister();
	sebsd_log("unregistered from MAC framework");
	return KERN_SUCCESS;
}
