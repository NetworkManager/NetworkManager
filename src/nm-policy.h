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

#define NM_TYPE_POLICY            (nm_policy_get_type ())
#define NM_POLICY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_POLICY, NMPolicy))
#define NM_POLICY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_POLICY, NMPolicyClass))
#define NM_IS_POLICY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_POLICY))
#define NM_IS_POLICY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_POLICY))
#define NM_POLICY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_POLICY, NMPolicyClass))

#define NM_POLICY_MANAGER               "manager"
#define NM_POLICY_SETTINGS              "settings"
#define NM_POLICY_DEFAULT_IP4_AC        "default-ip4-ac"
#define NM_POLICY_DEFAULT_IP6_AC        "default-ip6-ac"
#define NM_POLICY_ACTIVATING_IP4_AC     "activating-ip4-ac"
#define NM_POLICY_ACTIVATING_IP6_AC     "activating-ip6-ac"

typedef struct _NMPolicyClass NMPolicyClass;

GType nm_policy_get_type (void);

NMPolicy *nm_policy_new (NMManager *manager, NMSettings *settings);

NMActiveConnection *nm_policy_get_default_ip4_ac (NMPolicy *policy);
NMActiveConnection *nm_policy_get_default_ip6_ac (NMPolicy *policy);
NMActiveConnection *nm_policy_get_activating_ip4_ac (NMPolicy *policy);
NMActiveConnection *nm_policy_get_activating_ip6_ac (NMPolicy *policy);

/**
 * NMPolicyHostnameMode
 * @NM_POLICY_HOSTNAME_MODE_NONE: never update the transient hostname.
 * @NM_POLICY_HOSTNAME_MODE_DHCP: only hostname from DHCP hostname
 *   options are eligible to be set as transient hostname.
 * @NM_POLICY_HOSTNAME_MODE_FULL: NM will try to update the hostname looking
 *   to current static hostname, DHCP options, reverse IP lookup and externally
 *   set hostnames.
 *
 * NMPolicy's hostname update policy
 */
typedef enum {
	NM_POLICY_HOSTNAME_MODE_NONE,
	NM_POLICY_HOSTNAME_MODE_DHCP,
	NM_POLICY_HOSTNAME_MODE_FULL,
} NMPolicyHostnameMode;

#endif /* __NETWORKMANAGER_POLICY_H__ */
