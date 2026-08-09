/*-
 * Hand-written, kernel-side-only MAC framework ABI for the SEDarwin policy kext.
 *
 * The macOS MAC framework (the TrustedBSD "Security Extensions" KPI) is a
 * private kernel interface: the public Kernel.framework SDK exposes neither
 * struct label, nor mac_policy_ops, nor mac_policy_register()/unregister().
 * The layout below is hand-declared and validated against the RELEASE kernel
 * of macOS 26.5.2 (25F84) / Darwin 25.5.0 / xnu-12377.121.10, running on this
 * machine (kernel.release.t8142), by disassembling _mac_policy_register:
 *
 *   mac_policy_conf field offsets recovered from live code:
 *     mpc_name@0x00  mpc_fullname@0x08  mpc_labelnames@0x10
 *     mpc_labelname_count@0x18  mpc_ops@0x20  mpc_loadtime_flags@0x28
 *     mpc_field_off@0x30  mpc_runtime_flags@0x38  mpc_list@0x40  mpc_data@0x48
 *
 *   mac_policy_ops is 335 pointer slots (2680 bytes). The kernel never copies
 *   it - it keeps the pointer the policy passes to mac_policy_register() and
 *   reads individual hooks while scanning the policy list - so the kext MUST
 *   supply a full-size, zeroed struct; a short one would be read out of bounds
 *   (e.g. mpo_vnode_check_open at 0x858, mpo_vnode_label_associate_extattr at
 *   0x8f0) on the next framework dispatch. mpo_policy_init@0x398 and
 *   mpo_policy_initbsd@0x3a0 were confirmed against the register-time loads
 *   `ldr x8, [x8, #0x398]` / `ldr x8, [x8, #0x3a0]`.
 *
 * The field ORDER matches security/mac_policy.h from xnu-12377.1.9
 * (MAC_POLICY_OPS_VERSION 91). Unimplemented slots are typed mpo_hook_t * so
 * the struct stays exactly 2680 bytes while we only spell out the hooks we
 * implement.
 */

#ifndef _SEDARWIN_SEBSD_MAC_H_
#define _SEDARWIN_SEBSD_MAC_H_

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

/*
 * A generic function pointer for the ops-vector slots we do not (yet)
 * implement. All pointer slots are the same size on this ABI, so the layout is
 * identical regardless of the per-hook signature.
 */
typedef void mpo_hook_t(void);

/*
 * Opaque kernel types referenced by the hooks we do implement. Only the ones
 * we need are declared; more can be added as hooks are ported.
 */
struct mac_policy_conf;

/* Handle into the kernel policy list, returned by mac_policy_register(). */
typedef unsigned int mac_policy_handle_t;

/* Policy list node, referenced (not embedded) by the conf below. */
struct mac_policy_list_element {
	struct mac_policy_list_element *next;
	struct mac_policy_list_element *prev;
};

/*
 * Policy registration descriptor (see mac_policy_register()). Must be a
 * writable object: the kernel ORs MPC_RUNTIME_FLAG_REGISTERED into
 * mpc_runtime_flags at registration time.
 */
struct mac_policy_conf {
	const char                       *mpc_name;            /* 0x00 */
	const char                       *mpc_fullname;        /* 0x08 */
	const char                      **mpc_labelnames;      /* 0x10 */
	unsigned int                      mpc_labelname_count; /* 0x18 */
	struct mac_policy_ops            *mpc_ops;             /* 0x20 */
	int                               mpc_loadtime_flags;  /* 0x28 */
	int                              *mpc_field_off;       /* 0x30 */
	int                               mpc_runtime_flags;   /* 0x38 */
	struct mac_policy_list_element   *mpc_list;            /* 0x40 */
	void                             *mpc_data;            /* 0x48 */
};

/* Policy lifecycle hooks, given their real signatures. */
/*
 * Per-hook function-pointer typedefs, with the exact signatures from
 * xnu-12377.1.9 security/mac_policy.h. Only the hooks this module
 * implements get a real type; everything else stays mpo_hook_t * so the
 * struct is exactly 2680 bytes. Slots with a real type are checked by the
 * compiler when main.c assigns the implementations.
 *
 * NOTE: this header is kernel-side only and must be included AFTER the
 * kernel headers (it is, via kext/kernel.h), because these signatures
 * reference kauth_cred_t, struct vnode, struct label, proc_ident_t,
 * socket_t, proc_t and friends.
 */
  typedef int (*mpo_file_check_library_validation_t)(struct proc *p, struct fileglob *fg, off_t slice_offset, user_long_t error_message, size_t error_message_size);
  typedef int (*mpo_file_check_mmap_t)(kauth_cred_t cred, struct fileglob *fg, struct label *label, int prot, int flags, uint64_t file_pos, int *maxprot);
  typedef void (*mpo_policy_destroy_t)(struct mac_policy_conf *mpc);
  typedef void (*mpo_policy_init_t)(struct mac_policy_conf *mpc);
  typedef void (*mpo_policy_initbsd_t)(struct mac_policy_conf *mpc);
  typedef int (*mpo_proc_check_fork_t)(kauth_cred_t cred, struct proc *proc);
  typedef int (*mpo_proc_check_signal_t)(kauth_cred_t cred, proc_ident_t instigator, proc_ident_t target, int signum);
  typedef void (*mpo_proc_notify_exec_complete_t)(struct proc *p);
  typedef void (*mpo_proc_notify_exit_t)(struct proc *proc);
  typedef void (*mpo_pty_notify_grant_t)(proc_t p, struct tty *tp, dev_t dev, struct label *label);
  typedef int (*mpo_socket_check_connect_t)(kauth_cred_t cred, socket_t so, struct label *socklabel, struct sockaddr *addr);
  typedef int (*mpo_socket_check_create_t)(kauth_cred_t cred, int domain, int type, int protocol);
  typedef int (*mpo_socket_check_listen_t)(kauth_cred_t cred, socket_t so, struct label *socklabel);
  typedef int (*mpo_vnode_check_create_t)(kauth_cred_t cred, struct vnode *dvp, struct label *dlabel, struct componentname *cnp, struct vnode_attr *vap);
  typedef int (*mpo_vnode_check_exec_t)(kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel, struct label *scriptlabel, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen);
  typedef int (*mpo_vnode_check_getattr_t)(kauth_cred_t active_cred, kauth_cred_t file_cred, struct vnode *vp, struct label *vlabel, struct vnode_attr *va);
  typedef int (*mpo_vnode_check_lookup_t)(kauth_cred_t cred, struct vnode *dvp, struct label *dlabel, struct componentname *cnp);
  typedef int (*mpo_vnode_check_open_t)(kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode);
  typedef int (*mpo_vnode_check_readlink_t)(kauth_cred_t cred, struct vnode *vp, struct label *label);
  typedef int (*mpo_vnode_check_rename_t)(kauth_cred_t cred, struct vnode *fdvp, struct label *fdlabel, struct vnode *fvp, struct label *flabel, struct componentname *fcnp, struct vnode *tdvp, struct label *tdlabel, struct vnode *tvp, struct label *tlabel, struct componentname *tcnp);
  typedef int (*mpo_vnode_check_setattrlist_t)(kauth_cred_t cred, struct vnode *vp, struct label *vlabel, struct attrlist *alist);
  typedef int (*mpo_vnode_check_unlink_t)(kauth_cred_t cred, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, struct componentname *cnp);
  typedef int (*mpo_vnode_label_associate_extattr_t)(struct mount *mp, struct label *mntlabel, struct vnode *vp, struct label *vlabel);
  typedef void (*mpo_vnode_label_copy_t)(struct label *src, struct label *dest);

/*
 * Policy operations vector: 335 slots, 2680 bytes, in mac_policy.h order.
 * Register-time kernel reads: mpo_policy_init@0x398, mpo_policy_initbsd@0x3a0,
 * mpo_policy_destroy@0x390 (on unregister).
 */
struct mac_policy_ops {
	mpo_hook_t *mpo_audit_check_postselect;
	mpo_hook_t *mpo_audit_check_preselect;
	mpo_hook_t *mpo_graft_check_graft;
	mpo_hook_t *mpo_graft_check_ungraft;
	mpo_hook_t *mpo_graft_notify_graft;
	mpo_hook_t *mpo_graft_notify_ungraft;
	mpo_hook_t *mpo_cred_check_label_update_execve;
	mpo_hook_t *mpo_cred_check_label_update;
	mpo_hook_t *mpo_cred_check_visible;
	mpo_hook_t *mpo_cred_label_associate_fork;
	mpo_hook_t *mpo_cred_label_associate_kernel;
	mpo_hook_t *mpo_cred_label_associate;
	mpo_hook_t *mpo_cred_label_associate_user;
	mpo_hook_t *mpo_cred_label_destroy;
	mpo_hook_t *mpo_cred_label_externalize_audit;
	mpo_hook_t *mpo_cred_label_externalize;
	mpo_hook_t *mpo_cred_label_init;
	mpo_hook_t *mpo_cred_label_internalize;
	mpo_hook_t *mpo_cred_label_update_execve;
	mpo_hook_t *mpo_cred_label_update;
	mpo_hook_t *mpo_devfs_label_associate_device;
	mpo_hook_t *mpo_devfs_label_associate_directory;
	mpo_hook_t *mpo_devfs_label_copy;
	mpo_hook_t *mpo_devfs_label_destroy;
	mpo_hook_t *mpo_devfs_label_init;
	mpo_hook_t *mpo_devfs_label_update;
	mpo_hook_t *mpo_file_check_change_offset;
	mpo_hook_t *mpo_file_check_create;
	mpo_hook_t *mpo_file_check_dup;
	mpo_hook_t *mpo_file_check_fcntl;
	mpo_hook_t *mpo_file_check_get_offset;
	mpo_hook_t *mpo_file_check_get;
	mpo_hook_t *mpo_file_check_inherit;
	mpo_hook_t *mpo_file_check_ioctl;
	mpo_hook_t *mpo_file_check_lock;
	mpo_hook_t *mpo_file_check_mmap_downgrade;
	mpo_file_check_mmap_t mpo_file_check_mmap;
	mpo_hook_t *mpo_file_check_receive;
	mpo_hook_t *mpo_file_check_set;
	mpo_hook_t *mpo_file_label_init;
	mpo_hook_t *mpo_file_label_destroy;
	mpo_hook_t *mpo_file_label_associate;
	mpo_hook_t *mpo_file_notify_close;
	mpo_hook_t *mpo_proc_check_launch_constraints;
	mpo_hook_t *mpo_proc_notify_service_port_derive;
	mpo_hook_t *mpo_proc_check_set_task_exception_port;
	mpo_hook_t *mpo_proc_check_set_thread_exception_port;
	mpo_hook_t *mpo_reserved08;
	mpo_hook_t *mpo_reserved09;
	mpo_hook_t *mpo_reserved10;
	mpo_hook_t *mpo_reserved11;
	mpo_hook_t *mpo_reserved12;
	mpo_hook_t *mpo_reserved13;
	mpo_hook_t *mpo_reserved14;
	mpo_hook_t *mpo_reserved15;
	mpo_hook_t *mpo_reserved16;
	mpo_hook_t *mpo_reserved17;
	mpo_hook_t *mpo_reserved18;
	mpo_hook_t *mpo_reserved19;
	mpo_hook_t *mpo_reserved20;
	mpo_hook_t *mpo_reserved21;
	mpo_hook_t *mpo_reserved22;
	mpo_hook_t *mpo_necp_check_open;
	mpo_hook_t *mpo_necp_check_client_action;
	mpo_file_check_library_validation_t mpo_file_check_library_validation;
	mpo_hook_t *mpo_vnode_notify_setacl;
	mpo_hook_t *mpo_vnode_notify_setattrlist;
	mpo_hook_t *mpo_vnode_notify_setextattr;
	mpo_hook_t *mpo_vnode_notify_setflags;
	mpo_hook_t *mpo_vnode_notify_setmode;
	mpo_hook_t *mpo_vnode_notify_setowner;
	mpo_hook_t *mpo_vnode_notify_setutimes;
	mpo_hook_t *mpo_vnode_notify_truncate;
	mpo_hook_t *mpo_vnode_check_getattrlistbulk;
	mpo_hook_t *mpo_proc_check_get_task_special_port;
	mpo_hook_t *mpo_proc_check_set_task_special_port;
	mpo_hook_t *mpo_vnode_notify_swap;
	mpo_hook_t *mpo_vnode_notify_unlink;
	mpo_hook_t *mpo_vnode_check_swap;
	mpo_hook_t *mpo_vnode_check_dataprotect_set;
	mpo_hook_t *mpo_mount_check_remount_with_flags;
	mpo_hook_t *mpo_mount_notify_mount;
	mpo_hook_t *mpo_vnode_check_copyfile;
	mpo_hook_t *mpo_mount_check_quotactl;
	mpo_hook_t *mpo_mount_check_fsctl;
	mpo_hook_t *mpo_mount_check_getattr;
	mpo_hook_t *mpo_mount_check_label_update;
	mpo_hook_t *mpo_mount_check_mount;
	mpo_hook_t *mpo_mount_check_remount;
	mpo_hook_t *mpo_mount_check_setattr;
	mpo_hook_t *mpo_mount_check_stat;
	mpo_hook_t *mpo_mount_check_umount;
	mpo_hook_t *mpo_mount_label_associate;
	mpo_hook_t *mpo_mount_label_destroy;
	mpo_hook_t *mpo_mount_label_externalize;
	mpo_hook_t *mpo_mount_label_init;
	mpo_hook_t *mpo_mount_label_internalize;
	mpo_hook_t *mpo_proc_check_expose_task_with_flavor;
	mpo_hook_t *mpo_proc_check_get_task_with_flavor;
	mpo_hook_t *mpo_proc_check_task_id_token_get_task;
	mpo_hook_t *mpo_pipe_check_ioctl;
	mpo_hook_t *mpo_pipe_check_kqfilter;
	mpo_hook_t *mpo_reserved41;
	mpo_hook_t *mpo_pipe_check_read;
	mpo_hook_t *mpo_pipe_check_select;
	mpo_hook_t *mpo_pipe_check_stat;
	mpo_hook_t *mpo_pipe_check_write;
	mpo_hook_t *mpo_pipe_label_associate;
	mpo_hook_t *mpo_reserved42;
	mpo_hook_t *mpo_pipe_label_destroy;
	mpo_hook_t *mpo_reserved43;
	mpo_hook_t *mpo_pipe_label_init;
	mpo_hook_t *mpo_reserved44;
	mpo_hook_t *mpo_proc_check_syscall_mac;
	mpo_policy_destroy_t mpo_policy_destroy;
	mpo_policy_init_t mpo_policy_init;
	mpo_policy_initbsd_t mpo_policy_initbsd;
	mpo_hook_t *mpo_policy_syscall;
	mpo_hook_t *mpo_system_check_sysctlbyname;
	mpo_hook_t *mpo_proc_check_inherit_ipc_ports;
	mpo_vnode_check_rename_t mpo_vnode_check_rename;
	mpo_hook_t *mpo_kext_check_query;
	mpo_proc_notify_exec_complete_t mpo_proc_notify_exec_complete;
	mpo_hook_t *mpo_proc_notify_cs_invalidated;
	mpo_hook_t *mpo_proc_check_syscall_unix;
	mpo_hook_t *mpo_reserved45;
	mpo_hook_t *mpo_proc_check_set_host_special_port;
	mpo_hook_t *mpo_proc_check_set_host_exception_port;
	mpo_hook_t *mpo_exc_action_check_exception_send;
	mpo_hook_t *mpo_exc_action_label_associate;
	mpo_hook_t *mpo_exc_action_label_populate;
	mpo_hook_t *mpo_exc_action_label_destroy;
	mpo_hook_t *mpo_exc_action_label_init;
	mpo_hook_t *mpo_exc_action_label_update;
	mpo_hook_t *mpo_vnode_check_trigger_resolve;
	mpo_hook_t *mpo_mount_check_mount_late;
	mpo_hook_t *mpo_mount_check_snapshot_mount;
	mpo_hook_t *mpo_vnode_notify_reclaim;
	mpo_hook_t *mpo_skywalk_flow_check_connect;
	mpo_hook_t *mpo_skywalk_flow_check_listen;
	mpo_hook_t *mpo_posixsem_check_create;
	mpo_hook_t *mpo_posixsem_check_open;
	mpo_hook_t *mpo_posixsem_check_post;
	mpo_hook_t *mpo_posixsem_check_unlink;
	mpo_hook_t *mpo_posixsem_check_wait;
	mpo_hook_t *mpo_posixsem_label_associate;
	mpo_hook_t *mpo_posixsem_label_destroy;
	mpo_hook_t *mpo_posixsem_label_init;
	mpo_hook_t *mpo_posixshm_check_create;
	mpo_hook_t *mpo_posixshm_check_mmap;
	mpo_hook_t *mpo_posixshm_check_open;
	mpo_hook_t *mpo_posixshm_check_stat;
	mpo_hook_t *mpo_posixshm_check_truncate;
	mpo_hook_t *mpo_posixshm_check_unlink;
	mpo_hook_t *mpo_posixshm_label_associate;
	mpo_hook_t *mpo_posixshm_label_destroy;
	mpo_hook_t *mpo_posixshm_label_init;
	mpo_hook_t *mpo_proc_check_debug;
	mpo_proc_check_fork_t mpo_proc_check_fork;
	mpo_hook_t *mpo_reserved61;
	mpo_hook_t *mpo_reserved62;
	mpo_hook_t *mpo_proc_check_getaudit;
	mpo_hook_t *mpo_proc_check_getauid;
	mpo_hook_t *mpo_reserved63;
	mpo_hook_t *mpo_proc_check_mprotect;
	mpo_hook_t *mpo_proc_check_sched;
	mpo_hook_t *mpo_proc_check_setaudit;
	mpo_hook_t *mpo_proc_check_setauid;
	mpo_hook_t *mpo_proc_check_iopolicysys;
	mpo_proc_check_signal_t mpo_proc_check_signal;
	mpo_hook_t *mpo_proc_check_wait;
	mpo_hook_t *mpo_proc_check_dump_core;
	mpo_hook_t *mpo_proc_check_remote_thread_create;
	mpo_hook_t *mpo_socket_check_accept;
	mpo_hook_t *mpo_socket_check_accepted;
	mpo_hook_t *mpo_socket_check_bind;
	mpo_socket_check_connect_t mpo_socket_check_connect;
	mpo_socket_check_create_t mpo_socket_check_create;
	mpo_hook_t *mpo_reserved46;
	mpo_hook_t *mpo_reserved47;
	mpo_hook_t *mpo_reserved48;
	mpo_socket_check_listen_t mpo_socket_check_listen;
	mpo_hook_t *mpo_socket_check_receive;
	mpo_hook_t *mpo_socket_check_received;
	mpo_hook_t *mpo_reserved49;
	mpo_hook_t *mpo_socket_check_send;
	mpo_hook_t *mpo_socket_check_stat;
	mpo_hook_t *mpo_socket_check_setsockopt;
	mpo_hook_t *mpo_socket_check_getsockopt;
	mpo_hook_t *mpo_proc_check_get_movable_control_port;
	mpo_hook_t *mpo_proc_check_dyld_process_info_notify_register;
	mpo_hook_t *mpo_proc_check_setuid;
	mpo_hook_t *mpo_proc_check_seteuid;
	mpo_hook_t *mpo_proc_check_setreuid;
	mpo_hook_t *mpo_proc_check_setgid;
	mpo_hook_t *mpo_proc_check_setegid;
	mpo_hook_t *mpo_proc_check_setregid;
	mpo_hook_t *mpo_proc_check_settid;
	mpo_hook_t *mpo_proc_check_memorystatus_control;
	mpo_hook_t *mpo_reserved60;
	mpo_hook_t *mpo_thread_telemetry;
	mpo_hook_t *mpo_iokit_check_open_service;
	mpo_hook_t *mpo_system_check_acct;
	mpo_hook_t *mpo_system_check_audit;
	mpo_hook_t *mpo_system_check_auditctl;
	mpo_hook_t *mpo_system_check_auditon;
	mpo_hook_t *mpo_system_check_host_priv;
	mpo_hook_t *mpo_system_check_nfsd;
	mpo_hook_t *mpo_system_check_reboot;
	mpo_hook_t *mpo_system_check_settime;
	mpo_hook_t *mpo_system_check_swapoff;
	mpo_hook_t *mpo_system_check_swapon;
	mpo_hook_t *mpo_socket_check_ioctl;
	mpo_hook_t *mpo_sysvmsg_label_associate;
	mpo_hook_t *mpo_sysvmsg_label_destroy;
	mpo_hook_t *mpo_sysvmsg_label_init;
	mpo_hook_t *mpo_sysvmsg_label_recycle;
	mpo_hook_t *mpo_sysvmsq_check_enqueue;
	mpo_hook_t *mpo_sysvmsq_check_msgrcv;
	mpo_hook_t *mpo_sysvmsq_check_msgrmid;
	mpo_hook_t *mpo_sysvmsq_check_msqctl;
	mpo_hook_t *mpo_sysvmsq_check_msqget;
	mpo_hook_t *mpo_sysvmsq_check_msqrcv;
	mpo_hook_t *mpo_sysvmsq_check_msqsnd;
	mpo_hook_t *mpo_sysvmsq_label_associate;
	mpo_hook_t *mpo_sysvmsq_label_destroy;
	mpo_hook_t *mpo_sysvmsq_label_init;
	mpo_hook_t *mpo_sysvmsq_label_recycle;
	mpo_hook_t *mpo_sysvsem_check_semctl;
	mpo_hook_t *mpo_sysvsem_check_semget;
	mpo_hook_t *mpo_sysvsem_check_semop;
	mpo_hook_t *mpo_sysvsem_label_associate;
	mpo_hook_t *mpo_sysvsem_label_destroy;
	mpo_hook_t *mpo_sysvsem_label_init;
	mpo_hook_t *mpo_sysvsem_label_recycle;
	mpo_hook_t *mpo_sysvshm_check_shmat;
	mpo_hook_t *mpo_sysvshm_check_shmctl;
	mpo_hook_t *mpo_sysvshm_check_shmdt;
	mpo_hook_t *mpo_sysvshm_check_shmget;
	mpo_hook_t *mpo_sysvshm_label_associate;
	mpo_hook_t *mpo_sysvshm_label_destroy;
	mpo_hook_t *mpo_sysvshm_label_init;
	mpo_hook_t *mpo_sysvshm_label_recycle;
	mpo_proc_notify_exit_t mpo_proc_notify_exit;
	mpo_hook_t *mpo_mount_check_snapshot_revert;
	mpo_vnode_check_getattr_t mpo_vnode_check_getattr;
	mpo_hook_t *mpo_mount_check_snapshot_create;
	mpo_hook_t *mpo_mount_check_snapshot_delete;
	mpo_hook_t *mpo_vnode_check_clone;
	mpo_hook_t *mpo_proc_check_get_cs_info;
	mpo_hook_t *mpo_proc_check_set_cs_info;
	mpo_hook_t *mpo_iokit_check_hid_control;
	mpo_hook_t *mpo_vnode_check_access;
	mpo_hook_t *mpo_vnode_check_chdir;
	mpo_hook_t *mpo_vnode_check_chroot;
	mpo_vnode_check_create_t mpo_vnode_check_create;
	mpo_hook_t *mpo_vnode_check_deleteextattr;
	mpo_hook_t *mpo_vnode_check_exchangedata;
	mpo_vnode_check_exec_t mpo_vnode_check_exec;
	mpo_hook_t *mpo_vnode_check_getattrlist;
	mpo_hook_t *mpo_vnode_check_getextattr;
	mpo_hook_t *mpo_vnode_check_ioctl;
	mpo_hook_t *mpo_vnode_check_kqfilter;
	mpo_hook_t *mpo_vnode_check_label_update;
	mpo_hook_t *mpo_vnode_check_link;
	mpo_hook_t *mpo_vnode_check_listextattr;
	mpo_vnode_check_lookup_t mpo_vnode_check_lookup;
	mpo_vnode_check_open_t mpo_vnode_check_open;
	mpo_hook_t *mpo_vnode_check_read;
	mpo_hook_t *mpo_vnode_check_readdir;
	mpo_vnode_check_readlink_t mpo_vnode_check_readlink;
	mpo_hook_t *mpo_vnode_check_rename_from;
	mpo_hook_t *mpo_vnode_check_rename_to;
	mpo_hook_t *mpo_vnode_check_revoke;
	mpo_hook_t *mpo_vnode_check_select;
	mpo_vnode_check_setattrlist_t mpo_vnode_check_setattrlist;
	mpo_hook_t *mpo_vnode_check_setextattr;
	mpo_hook_t *mpo_vnode_check_setflags;
	mpo_hook_t *mpo_vnode_check_setmode;
	mpo_hook_t *mpo_vnode_check_setowner;
	mpo_hook_t *mpo_vnode_check_setutimes;
	mpo_hook_t *mpo_vnode_check_stat;
	mpo_hook_t *mpo_vnode_check_truncate;
	mpo_vnode_check_unlink_t mpo_vnode_check_unlink;
	mpo_hook_t *mpo_vnode_check_write;
	mpo_hook_t *mpo_vnode_label_associate_devfs;
	mpo_vnode_label_associate_extattr_t mpo_vnode_label_associate_extattr;
	mpo_hook_t *mpo_vnode_label_associate_file;
	mpo_hook_t *mpo_vnode_label_associate_pipe;
	mpo_hook_t *mpo_vnode_label_associate_posixsem;
	mpo_hook_t *mpo_vnode_label_associate_posixshm;
	mpo_hook_t *mpo_vnode_label_associate_singlelabel;
	mpo_hook_t *mpo_vnode_label_associate_socket;
	mpo_vnode_label_copy_t mpo_vnode_label_copy;
	mpo_hook_t *mpo_vnode_label_destroy;
	mpo_hook_t *mpo_vnode_label_externalize_audit;
	mpo_hook_t *mpo_vnode_label_externalize;
	mpo_hook_t *mpo_vnode_label_init;
	mpo_hook_t *mpo_vnode_label_internalize;
	mpo_hook_t *mpo_vnode_label_recycle;
	mpo_hook_t *mpo_vnode_label_store;
	mpo_hook_t *mpo_vnode_label_update_extattr;
	mpo_hook_t *mpo_vnode_label_update;
	mpo_hook_t *mpo_vnode_notify_create;
	mpo_hook_t *mpo_vnode_check_signature;
	mpo_hook_t *mpo_vnode_check_uipc_bind;
	mpo_hook_t *mpo_vnode_check_uipc_connect;
	mpo_hook_t *mpo_proc_check_run_cs_invalid;
	mpo_hook_t *mpo_proc_check_suspend_resume;
	mpo_hook_t *mpo_thread_userret;
	mpo_hook_t *mpo_iokit_check_set_properties;
	mpo_hook_t *mpo_vnode_check_supplemental_signature;
	mpo_hook_t *mpo_vnode_check_searchfs;
	mpo_hook_t *mpo_priv_check;
	mpo_hook_t *mpo_priv_grant;
	mpo_hook_t *mpo_proc_check_map_anon;
	mpo_hook_t *mpo_vnode_check_fsgetpath;
	mpo_hook_t *mpo_iokit_check_open;
	mpo_hook_t *mpo_proc_check_ledger;
	mpo_hook_t *mpo_vnode_notify_rename;
	mpo_hook_t *mpo_vnode_check_setacl;
	mpo_hook_t *mpo_vnode_notify_deleteextattr;
	mpo_hook_t *mpo_system_check_kas_info;
	mpo_hook_t *mpo_vnode_check_lookup_preflight;
	mpo_hook_t *mpo_vnode_notify_open;
	mpo_hook_t *mpo_system_check_info;
	mpo_pty_notify_grant_t mpo_pty_notify_grant;
	mpo_hook_t *mpo_pty_notify_close;
	mpo_hook_t *mpo_vnode_find_sigs;
	mpo_hook_t *mpo_kext_check_load;
	mpo_hook_t *mpo_kext_check_unload;
	mpo_hook_t *mpo_proc_check_proc_info;
	mpo_hook_t *mpo_vnode_notify_link;
	mpo_hook_t *mpo_iokit_check_filter_properties;
	mpo_hook_t *mpo_iokit_check_get_property;
};

/* Number of pointer slots in struct mac_policy_ops on this ABI (2680 bytes). */
#define MAC_POLICY_OPS_SLOTS            335

/* mpc_loadtime_flags values (security/mac_policy.h). 0 = default late load. */
#define MPC_LOADTIME_FLAG_NOTLATE       0x00000001
#define MPC_LOADTIME_FLAG_UNLOADOK      0x00000002
#define MPC_LOADTIME_FLAG_LABELMBUFS    0x00000004

/* mpc_runtime_flags values. */
#define MPC_RUNTIME_FLAG_REGISTERED     0x00000001

/* Maximum number of managed label namespaces a policy may declare. */
#define MAC_MAX_MANAGED_NAMESPACES      4

/*
 * Export the entry points. mac_policy_register() takes the conf, a pointer to
 * receive the handle, and an optional module-data blob (NULL for us);
 * mac_policy_unregister() takes the handle. Both are exported by the macOS
 * kernel (config/MACFramework.exports).
 */
int mac_policy_register(struct mac_policy_conf *mpc, mac_policy_handle_t *handlep, void *arg);
int mac_policy_unregister(mac_policy_handle_t handle);

/* Layout guards: these must hold on the running kernel or the ABI is wrong. */
_Static_assert(sizeof(struct mac_policy_conf) == 80, "mac_policy_conf size");
_Static_assert(offsetof(struct mac_policy_conf, mpc_fullname) == 0x08, "mpc_fullname");
_Static_assert(offsetof(struct mac_policy_conf, mpc_labelname_count) == 0x18, "mpc_labelname_count");
_Static_assert(offsetof(struct mac_policy_conf, mpc_ops) == 0x20, "mpc_ops");
_Static_assert(offsetof(struct mac_policy_conf, mpc_loadtime_flags) == 0x28, "mpc_loadtime_flags");
_Static_assert(sizeof(struct mac_policy_ops) == 2680, "mac_policy_ops size");
_Static_assert(offsetof(struct mac_policy_ops, mpo_policy_destroy) == 0x390, "mpo_policy_destroy");
_Static_assert(offsetof(struct mac_policy_ops, mpo_policy_init) == 0x398, "mpo_policy_init");
_Static_assert(offsetof(struct mac_policy_ops, mpo_policy_initbsd) == 0x3a0, "mpo_policy_initbsd");

__END_DECLS

#endif /* _SEDARWIN_SEBSD_MAC_H_ */
