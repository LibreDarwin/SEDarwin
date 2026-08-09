/*-
 * SEDarwin policy kext - process access-control hooks.
 *
 * M0 stage: observational. Signal delivery to another process is the 
 * interesting primitive for later milestones (job-control policy, "who may
 * signal whom"); fork/exit give the process-lifecycle trace.
 *
 * proc_ident_t is a fixed-size snapshot of a process identity (pid + version
 * token) that stays valid without holding a proc reference, which is why the
 * kernel passes it to the signal check rather than struct proc *.
 */

#include "kernel.h"

/*
 * Resolve a proc_ident_t to a name. This goes through proc_find() (see
 * sebsd_proc_name()) and therefore takes proc_list_lock, so it must only be
 * reached from behind sebsd_tracing() - signal delivery can run with that lock
 * already held.
 */
static void
sebsd_ident_name(proc_ident_t ident, char *buf, size_t len)
{
	if (ident == NULL) {
		strlcpy(buf, "<kernel>", len);
		return;
	}
	sebsd_proc_name(ident->p_pid, buf, len);
}

int
sebsd_proc_check_signal(kauth_cred_t cred, proc_ident_t instigator,
    proc_ident_t target, int signum)
{
	char iname[MAXCOMLEN + 1];
	char tname[MAXCOMLEN + 1];

	if (!sebsd_tracing()) {
		return 0;
	}
	if (signum != SIGKILL && signum != SIGSEGV && signum != SIGBUS &&
	    signum != SIGILL && signum != SIGABRT && signum != SIGTERM) {
		return 0;
	}

	sebsd_ident_name(instigator, iname, sizeof(iname));
	sebsd_ident_name(target, tname, sizeof(tname));
	sebsd_log_debug("signal: %s(%d) -> %s(%d) sig=%d uid=%d", iname,
	    instigator != NULL ? instigator->p_pid : 0, tname,
	    target != NULL ? target->p_pid : 0, signum,
	    kauth_cred_getuid(cred));
	return 0;
}

int
sebsd_proc_check_fork(kauth_cred_t cred, struct proc *proc)
{
	char pname[MAXCOMLEN + 1];

	if (!sebsd_tracing()) {
		return 0;
	}
	sebsd_cur_name(pname, sizeof(pname));
	sebsd_log_debug("fork: %s pid=%d ppid=%d uid=%d", pname,
	    proc_pid(proc), proc_pid(current_proc()), kauth_cred_getuid(cred));
	return 0;
}

void
sebsd_proc_notify_exit(struct proc *proc)
{
	char pname[MAXCOMLEN + 1];

	if (!sebsd_tracing()) {
		return;
	}
	sebsd_proc_name(proc_pid(proc), pname, sizeof(pname));
	sebsd_log_debug("exit: %s pid=%d", pname, proc_pid(proc));
}
