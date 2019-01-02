/* This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2014 - 2018 Red Hat, Inc.
 */

#ifndef __NM_SD_ADAPT_CORE_H__
#define __NM_SD_ADAPT_CORE_H__

#include "nm-default.h"

#include <stdbool.h>
#include <sys/resource.h>
#include <time.h>

#include "systemd/sd-adapt-shared/nm-sd-adapt-shared.h"

#ifndef HAVE_SYS_AUXV_H
#define HAVE_SYS_AUXV_H 0
#endif

/*****************************************************************************
 * The remainder of the header is only enabled when building the systemd code
 * itself.
 *****************************************************************************/

#if (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_SYSTEMD

#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <elf.h>
#ifdef HAVE_SYS_AUXV_H
#include <sys/auxv.h>
#endif
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

#include <net/if_arp.h>

/* Missing in Linux 3.2.0, in Ubuntu 12.04 */
#ifndef BPF_XOR
#define BPF_XOR 0xa0
#endif

#ifndef ETHERTYPE_LLDP
#define ETHERTYPE_LLDP 0x88cc
#endif

#ifndef HAVE_SECURE_GETENV
#  ifdef HAVE___SECURE_GETENV
#    define secure_getenv __secure_getenv
#  else
#    error neither secure_getenv nor __secure_getenv is available
#  endif
#endif

/*****************************************************************************/

static inline int
sd_notify (int unset_environment, const char *state)
{
	return 0;
}

/* Can't include both net/if.h and linux/if.h; so have to define this here */
#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ IF_NAMESIZE
#endif

#ifndef MAX_HANDLE_SZ
#define MAX_HANDLE_SZ 128
#endif

#include "sd-id128.h"
#include "sparse-endian.h"
#include "async.h"
#include "util.h"

#endif /* (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_SYSTEMD */

#endif /* __NM_SD_ADAPT_CORE_H__ */

