/*-
 * SEDarwin policy kext - file-level access-control hooks.
 *
 * mpo_file_check_library_validation is a gate the kernel consults when dyld
 * loads a library under library validation (CS_REQUIRE_LV). Returning anything
 * but 0 here would block libraries in hardened processes, so M0 returns 0 and
 * only traces. mpo_file_check_mmap observes executable mappings.
 */

#include "kernel.h"

int
sebsd_file_check_mmap(kauth_cred_t cred, struct fileglob *fg,
    struct label *label, int prot, int flags, uint64_t file_pos, int *maxprot)
{
	char pname[MAXCOMLEN + 1];

	(void)fg;
	(void)label;
	(void)flags;
	(void)file_pos;
	(void)maxprot;

	if (!sebsd_tracing()) {
		return 0;
	}
	sebsd_cur_name(pname, sizeof(pname));
	sebsd_log_debug("mmap: %s pid=%d prot=0x%x uid=%d", pname,
	    sebsd_cur_pid(), prot, kauth_cred_getuid(cred));
	return 0;
}

int
sebsd_file_check_library_validation(struct proc *p, struct fileglob *fg,
    off_t slice_offset, user_long_t error_message, size_t error_message_size)
{
	char pname[MAXCOMLEN + 1];

	(void)fg;
	(void)slice_offset;
	(void)error_message;
	(void)error_message_size;

	if (!sebsd_tracing()) {
		return 0;
	}
	sebsd_proc_name(proc_pid(p), pname, sizeof(pname));
	sebsd_log_debug("library validation: %s pid=%d", pname, proc_pid(p));
	return 0;
}
