/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_LINUX_COMPAT_H__
#define __NM_LINUX_COMPAT_H__

/* We have copies of linux UAPI headers in `src/linux-headers` which
 * should be preferred over the headers on the system. However, these
 * newer headers might be incompatible with the installed UAPI headers.
 *
 * This nm-linux-compat.h header tries to solve that and apply the necessary
 * workarounds.
 *
 * Unlike most NetworkManager headers, this header needs to be included
 * *before* most system headers. */

#include <linux/const.h>

#ifndef __KERNEL_DIV_ROUND_UP
#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) -1) / (d))
#endif

#include "linux-headers/ethtool.h"
#include "linux-headers/nl802154.h"
#include "linux-headers/nl80211-vnd-intel.h"
#include "linux-headers/mptcp.h"

#endif /* __NM_LINUX_COMPAT_H__ */
