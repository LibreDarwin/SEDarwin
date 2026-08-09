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

#endif /* _SEBSD_SEBSD_H_ */
