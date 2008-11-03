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
 * Copyright (C) 2004 - 2008 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef NETWORK_MANAGER_POLICY_H
#define NETWORK_MANAGER_POLICY_H

#include "NetworkManager.h"
#include "nm-manager.h"
#include "nm-vpn-manager.h"
#include "nm-device.h"
#include "nm-activation-request.h"

typedef struct NMPolicy NMPolicy;

NMPolicy *nm_policy_new (NMManager *manager, NMVPNManager *vpn_manager);
void nm_policy_destroy (NMPolicy *policy);

#endif /* NETWORK_MANAGER_POLICY_H */
