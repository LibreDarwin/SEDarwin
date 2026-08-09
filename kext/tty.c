/*-
 * SEDarwin policy kext - pty allocation observation.
 *
 * The classic mpo_tty_* hooks no longer exist in xnu-12377's MAC framework
 * (removed with the tty-level enforcement); the only remaining tty-facing
 * entry points are the pty notify hooks. mpo_pty_notify_grant fires when a
 * pty master is opened, i.e. whenever a terminal/session (typically a shell)
 * is created - a useful signal for later milestones.
 */

#include "kernel.h"

void
sebsd_pty_notify_grant(proc_t p, struct tty *tp, dev_t dev,
    struct label *label)
{
	char pname[MAXCOMLEN + 1];

	(void)tp;
	(void)label;

	if (!sebsd_tracing()) {
		return;
	}
	sebsd_proc_name(proc_pid(p), pname, sizeof(pname));
	sebsd_log_debug("pty grant: %s pid=%d dev=%d,%d", pname,
	    proc_pid(p), major(dev), minor(dev));
}
