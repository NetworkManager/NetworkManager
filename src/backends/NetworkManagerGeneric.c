/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2004 - 2012 Red Hat, Inc.
 * (C) Copyright 2006 Timothee Lecomte <timothee.lecomte@ens.fr>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <arpa/inet.h>
#include <string.h>

#include "NetworkManagerGeneric.h"
#include "nm-system.h"
#include "NetworkManagerUtils.h"
#include "nm-logging.h"
#include "nm-netlink-compat.h"
#include "nm-netlink-monitor.h"
#include "nm-netlink-utils.h"

/* Because of a bug in libnl, rtnl.h should be included before route.h */
#include <netlink/route/rtnl.h>

#include <netlink/route/addr.h>
#include <netlink/netlink.h>

