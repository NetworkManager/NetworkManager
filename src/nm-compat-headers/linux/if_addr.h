/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_COMPAT_HEADER_LINUX_IF_ADDR_H__
#define __NM_COMPAT_HEADER_LINUX_IF_ADDR_H__

#include <linux/if_addr.h>

#ifndef IFA_F_MANAGETEMPADDR
#define IFA_F_MANAGETEMPADDR 0x100
#endif

#ifndef IFA_F_NOPREFIXROUTE
#define IFA_F_NOPREFIXROUTE 0x200
#endif

#endif /* __NM_COMPAT_HEADER_LINUX_IF_ADDR_H__ */
