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

#ifndef NM_CONNECTION_H
#define NM_CONNECTION_H

#include <glib.h>
#include <glib-object.h>
#include <nm-setting.h>

#include <nm-setting-8021x.h>
#include <nm-setting-bluetooth.h>
#include <nm-setting-cdma.h>
#include <nm-setting-connection.h>
#include <nm-setting-gsm.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-olpc-mesh.h>
#include <nm-setting-ppp.h>
#include <nm-setting-pppoe.h>
#include <nm-setting-vpn.h>
#include <nm-setting-wimax.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>

G_BEGIN_DECLS

#define NM_TYPE_CONNECTION            (nm_connection_get_type ())
#define NM_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONNECTION, NMConnection))
#define NM_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_CONNECTION, NMConnectionClass))
#define NM_IS_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONNECTION))
#define NM_IS_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_CONNECTION))
#define NM_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_CONNECTION, NMConnectionClass))


/**
 * NMConnectionError:
 * @NM_CONNECTION_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_CONNECTION_ERROR_CONNECTION_SETTING_NOT_FOUND: the #NMConnection object
 *   did not contain the required #NMSettingConnection object, which must be
 *   present for all connections
 * @NM_CONNECTION_ERROR_CONNECTION_TYPE_INVALID: the 'type' property of the
 *   'connection' setting did not point to a valid connection base type; ie
 *   it was not a hardware-related setting like #NMSettingWired or
 *   #NMSettingWireless.
 *
 * Describes errors that may result from operations involving a #NMConnection.
 *
 **/
typedef enum
{
	NM_CONNECTION_ERROR_UNKNOWN = 0,
	NM_CONNECTION_ERROR_CONNECTION_SETTING_NOT_FOUND,
	NM_CONNECTION_ERROR_CONNECTION_TYPE_INVALID
} NMConnectionError;

#define NM_TYPE_CONNECTION_ERROR (nm_connection_error_get_type ()) 
GType nm_connection_error_get_type (void);

#define NM_CONNECTION_ERROR nm_connection_error_quark ()
GQuark nm_connection_error_quark (void);

#define NM_CONNECTION_PATH "path"

/**
 * NMConnection:
 *
 * The NMConnection struct contains only private data.
 * It should only be accessed through the functions described below.
 */
typedef struct {
	GObject parent;
} NMConnection;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*secrets_updated) (NMConnection *connection, const char * setting);
} NMConnectionClass;

GType nm_connection_get_type (void);

NMConnection *nm_connection_new           (void);

NMConnection *nm_connection_new_from_hash (GHashTable *hash, GError **error);

NMConnection *nm_connection_duplicate     (NMConnection *connection);

NMSetting    *nm_connection_create_setting (const char *name);

void          nm_connection_add_setting   (NMConnection *connection,
                                           NMSetting    *setting);

void          nm_connection_remove_setting (NMConnection *connection,
                                            GType         setting_type);

NMSetting    *nm_connection_get_setting   (NMConnection *connection,
                                           GType         setting_type);

NMSetting    *nm_connection_get_setting_by_name (NMConnection *connection,
                                                 const char   *name);

gboolean      nm_connection_replace_settings (NMConnection *connection,
                                              GHashTable *new_settings,
                                              GError **error);

gboolean      nm_connection_compare       (NMConnection *a,
                                           NMConnection *b,
                                           NMSettingCompareFlags flags);

gboolean      nm_connection_diff          (NMConnection *a,
                                           NMConnection *b,
                                           NMSettingCompareFlags flags,
                                           GHashTable **out_settings);

gboolean      nm_connection_verify        (NMConnection *connection, GError **error);

const char *  nm_connection_need_secrets  (NMConnection *connection,
                                           GPtrArray **hints);

void          nm_connection_clear_secrets (NMConnection *connection);

gboolean      nm_connection_update_secrets (NMConnection *connection,
                                            const char *setting_name,
                                            GHashTable *setting_secrets,
                                            GError **error);

void          nm_connection_set_path      (NMConnection *connection,
                                           const char *path);

const char *  nm_connection_get_path      (NMConnection *connection);

void          nm_connection_for_each_setting_value (NMConnection *connection,
                                                    NMSettingValueIterFn func,
                                                    gpointer user_data);

GHashTable   *nm_connection_to_hash       (NMConnection *connection,
                                           NMSettingHashFlags flags);

void          nm_connection_dump          (NMConnection *connection);

GType         nm_connection_lookup_setting_type (const char *name);

GType         nm_connection_lookup_setting_type_by_quark (GQuark error_quark);

/* Helpers */
const char *  nm_connection_get_uuid      (NMConnection *connection);

const char *  nm_connection_get_id        (NMConnection *connection);

NMSetting8021x *           nm_connection_get_setting_802_1x            (NMConnection *connection);
NMSettingBluetooth *       nm_connection_get_setting_bluetooth         (NMConnection *connection);
NMSettingCdma *            nm_connection_get_setting_cdma              (NMConnection *connection);
NMSettingConnection *      nm_connection_get_setting_connection        (NMConnection *connection);
NMSettingGsm *             nm_connection_get_setting_gsm               (NMConnection *connection);
NMSettingIP4Config *       nm_connection_get_setting_ip4_config        (NMConnection *connection);
NMSettingIP6Config *       nm_connection_get_setting_ip6_config        (NMConnection *connection);
NMSettingOlpcMesh *        nm_connection_get_setting_olpc_mesh         (NMConnection *connection);
NMSettingPPP *             nm_connection_get_setting_ppp               (NMConnection *connection);
NMSettingPPPOE *           nm_connection_get_setting_pppoe             (NMConnection *connection);
NMSettingVPN *             nm_connection_get_setting_vpn               (NMConnection *connection);
NMSettingWimax *           nm_connection_get_setting_wimax             (NMConnection *connection);
NMSettingWired *           nm_connection_get_setting_wired             (NMConnection *connection);
NMSettingWireless *        nm_connection_get_setting_wireless          (NMConnection *connection);
NMSettingWirelessSecurity *nm_connection_get_setting_wireless_security (NMConnection *connection);

G_END_DECLS

#endif /* NM_CONNECTION_H */
