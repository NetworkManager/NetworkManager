/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
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
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SETTING_VPN_H
#define NM_SETTING_VPN_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_VPN            (nm_setting_vpn_get_type ())
#define NM_SETTING_VPN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_VPN, NMSettingVPN))
#define NM_SETTING_VPN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_VPN, NMSettingVPNClass))
#define NM_IS_SETTING_VPN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_VPN))
#define NM_IS_SETTING_VPN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_VPN))
#define NM_SETTING_VPN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_VPN, NMSettingVPNClass))

#define NM_SETTING_VPN_SETTING_NAME "vpn"

typedef enum
{
	NM_SETTING_VPN_ERROR_UNKNOWN = 0,
	NM_SETTING_VPN_ERROR_INVALID_PROPERTY,
	NM_SETTING_VPN_ERROR_MISSING_PROPERTY,
} NMSettingVpnError;

#define NM_TYPE_SETTING_VPN_ERROR (nm_setting_vpn_error_get_type ()) 
GType nm_setting_vpn_error_get_type (void);

#define NM_SETTING_VPN_ERROR nm_setting_vpn_error_quark ()
GQuark nm_setting_vpn_error_quark (void);

#define NM_SETTING_VPN_SERVICE_TYPE "service-type"
#define NM_SETTING_VPN_USER_NAME    "user-name"
#define NM_SETTING_VPN_DATA         "data"

typedef struct {
	NMSetting parent;

	char *service_type;

	/* username of the user requesting this connection, thus
	 * it's really only valid for user connections, and it also
	 * should never be saved out to persistent config.
	 */
	char *user_name;

	/* The hash table is created at setting object
	 * init time and should not be replaced.  It is
	 * a char * -> char * mapping, and both the key
	 * and value are owned by the hash table, and should
	 * be allocated with functions whose value can be
	 * freed with g_free()
	 */
	GHashTable *data;
} NMSettingVPN;

typedef struct {
	NMSettingClass parent;
} NMSettingVPNClass;

GType nm_setting_vpn_get_type (void);

NMSetting *nm_setting_vpn_new (void);

G_END_DECLS

#endif /* NM_SETTING_VPN_H */
