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
 * Copyright (C) 2004 - 2010 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_POLICY_H__
#define __NETWORKMANAGER_POLICY_H__

#include "nm-default.h"

#define NM_TYPE_POLICY            (nm_policy_get_type ())
#define NM_POLICY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_POLICY, NMPolicy))
#define NM_POLICY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_POLICY, NMPolicyClass))
#define NM_IS_POLICY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_POLICY))
#define NM_IS_POLICY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_POLICY))
#define NM_POLICY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_POLICY, NMPolicyClass))

#define NM_POLICY_DEFAULT_IP4_DEVICE "default-ip4-device"
#define NM_POLICY_DEFAULT_IP6_DEVICE "default-ip6-device"
#define NM_POLICY_ACTIVATING_IP4_DEVICE "activating-ip4-device"
#define NM_POLICY_ACTIVATING_IP6_DEVICE "activating-ip6-device"

struct _NMPolicy {
	GObject parent;
};

typedef struct {
	GObjectClass parent;

} NMPolicyClass;

GType nm_policy_get_type (void);

NMPolicy *nm_policy_new (NMManager *manager, NMSettings *settings);

NMDevice *nm_policy_get_default_ip4_device (NMPolicy *policy);
NMDevice *nm_policy_get_default_ip6_device (NMPolicy *policy);
NMDevice *nm_policy_get_activating_ip4_device (NMPolicy *policy);
NMDevice *nm_policy_get_activating_ip6_device (NMPolicy *policy);

#endif /* __NETWORKMANAGER_POLICY_H__ */
