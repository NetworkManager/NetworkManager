/* nmcli - command-line tool to control NetworkManager
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
 * Copyright 2010 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "connections.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/ether.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <fcntl.h>

#include "nm-client-utils.h"
#include "nm-vpn-helpers.h"
#include "nm-meta-setting-access.h"
#include "nm-secret-agent-simple.h"

#include "utils.h"
#include "common.h"
#include "settings.h"
#include "devices.h"
#include "polkit-agent.h"

typedef enum {
	PROPERTY_INF_FLAG_NONE                      = 0x0,
	PROPERTY_INF_FLAG_DISABLED                  = 0x1, /* Don't ask due to runtime decision. */
	PROPERTY_INF_FLAG_ENABLED                   = 0x2, /* Override NM_META_PROPERTY_INF_FLAG_DONT_ASK due to runtime decision. */
	PROPERTY_INF_FLAG_ALL                       = 0x3,
} PropertyInfFlags;

typedef char *(*CompEntryFunc) (const char *, int);

typedef struct _OptionInfo OptionInfo;
struct _OptionInfo {
	const NMMetaSettingInfoEditor *setting_info;
	const char *property;
	const char *option;
	gboolean (*check_and_set)(NmCli *nmc, NMConnection *connection, const OptionInfo *option, const char *value, GError **error);
	CompEntryFunc generator_func;
};

/* define some prompts for connection editor */
#define EDITOR_PROMPT_SETTING  _("Setting name? ")
#define EDITOR_PROMPT_PROPERTY _("Property name? ")
#define EDITOR_PROMPT_CON_TYPE _("Enter connection type: ")

/* define some other prompts */

#define PROMPT_CONNECTION  _("Connection (name, UUID, or path): ")
#define PROMPT_VPN_CONNECTION  _("VPN connection (name, UUID, or path): ")
#define PROMPT_CONNECTIONS _("Connection(s) (name, UUID, or path): ")
#define PROMPT_ACTIVE_CONNECTIONS _("Connection(s) (name, UUID, path or apath): ")

#define BASE_PROMPT "nmcli> "

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (active_connection_state_to_string, NMActiveConnectionState,
	NM_UTILS_LOOKUP_DEFAULT (N_("unknown")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_ACTIVATING,   N_("activating")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_ACTIVATED,    N_("activated")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_DEACTIVATING, N_("deactivating")),
	NM_UTILS_LOOKUP_ITEM (NM_ACTIVE_CONNECTION_STATE_DEACTIVATED,  N_("deactivated")),
	NM_UTILS_LOOKUP_ITEM_IGNORE (NM_ACTIVE_CONNECTION_STATE_UNKNOWN),
)

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (vpn_connection_state_to_string, NMVpnConnectionState,
	NM_UTILS_LOOKUP_DEFAULT (N_("unknown")),
	NM_UTILS_LOOKUP_ITEM (NM_VPN_CONNECTION_STATE_PREPARE,       N_("VPN connecting (prepare)")),
	NM_UTILS_LOOKUP_ITEM (NM_VPN_CONNECTION_STATE_NEED_AUTH,     N_("VPN connecting (need authentication)")),
	NM_UTILS_LOOKUP_ITEM (NM_VPN_CONNECTION_STATE_CONNECT,       N_("VPN connecting")),
	NM_UTILS_LOOKUP_ITEM (NM_VPN_CONNECTION_STATE_IP_CONFIG_GET, N_("VPN connecting (getting IP configuration)")),
	NM_UTILS_LOOKUP_ITEM (NM_VPN_CONNECTION_STATE_ACTIVATED,     N_("VPN connected")),
	NM_UTILS_LOOKUP_ITEM (NM_VPN_CONNECTION_STATE_FAILED,        N_("VPN connection failed")),
	NM_UTILS_LOOKUP_ITEM (NM_VPN_CONNECTION_STATE_DISCONNECTED,  N_("VPN disconnected")),
	NM_UTILS_LOOKUP_ITEM_IGNORE (NM_VPN_CONNECTION_STATE_UNKNOWN),
)

/* Essentially a version of nm_setting_connection_get_connection_type() that
 * prefers an alias instead of the settings name when in pretty print mode.
 * That is so that we print "wifi" instead of "802-11-wireless" in "nmcli c". */
static const char *
connection_type_to_display (const char *type, NMMetaAccessorGetType get_type)
{
	const NMMetaSettingInfoEditor *editor;
	int i;

	nm_assert (NM_IN_SET (get_type, NM_META_ACCESSOR_GET_TYPE_PRETTY, NM_META_ACCESSOR_GET_TYPE_PARSABLE));

	if (!type)
		return NULL;

	if (get_type != NM_META_ACCESSOR_GET_TYPE_PRETTY)
		return type;

	for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++) {
		editor = &nm_meta_setting_infos_editor[i];
		if (nm_streq (type, editor->general->setting_name))
			return editor->alias ?: type;
	}
	return type;
}

static int
active_connection_get_state_ord (NMActiveConnection *active)
{
	/* returns an integer related to @active's state, that can be used for sorting
	 * active connections based on their activation state. */
	if (!active)
		return -2;

	switch (nm_active_connection_get_state (active)) {
	case NM_ACTIVE_CONNECTION_STATE_UNKNOWN:      return 0;
	case NM_ACTIVE_CONNECTION_STATE_DEACTIVATED:  return 1;
	case NM_ACTIVE_CONNECTION_STATE_DEACTIVATING: return 2;
	case NM_ACTIVE_CONNECTION_STATE_ACTIVATING:   return 3;
	case NM_ACTIVE_CONNECTION_STATE_ACTIVATED:    return 4;
	}
	return -1;
}

int
nmc_active_connection_cmp (NMActiveConnection *ac_a, NMActiveConnection *ac_b)
{
	NMSettingIPConfig *s_ip;
	NMRemoteConnection *conn;
	NMIPConfig *da_ip;
	NMIPConfig *db_ip;
	int da_num_addrs;
	int db_num_addrs;
	int cmp = 0;

	/* Non-active sort last. */
	NM_CMP_SELF (ac_a, ac_b);
	NM_CMP_DIRECT (active_connection_get_state_ord (ac_b),
	               active_connection_get_state_ord (ac_a));

	/* Shared connections (likely hotspots) go on the top if possible */
	conn = nm_active_connection_get_connection (ac_a);
	s_ip = conn ? nm_connection_get_setting_ip6_config (NM_CONNECTION (conn)) : NULL;
	if (s_ip && strcmp (nm_setting_ip_config_get_method (s_ip), NM_SETTING_IP6_CONFIG_METHOD_SHARED) == 0)
		cmp++;
	conn = nm_active_connection_get_connection (ac_b);
	s_ip = conn ? nm_connection_get_setting_ip6_config (NM_CONNECTION (conn)) : NULL;
	if (s_ip && strcmp (nm_setting_ip_config_get_method (s_ip), NM_SETTING_IP6_CONFIG_METHOD_SHARED) == 0)
		cmp--;
	NM_CMP_RETURN (cmp);

	conn = nm_active_connection_get_connection (ac_a);
	s_ip = conn ? nm_connection_get_setting_ip4_config (NM_CONNECTION (conn)) : NULL;
	if (s_ip && strcmp (nm_setting_ip_config_get_method (s_ip), NM_SETTING_IP4_CONFIG_METHOD_SHARED) == 0)
		cmp++;
	conn = nm_active_connection_get_connection (ac_b);
	s_ip = conn ? nm_connection_get_setting_ip4_config (NM_CONNECTION (conn)) : NULL;
	if (s_ip && strcmp (nm_setting_ip_config_get_method (s_ip), NM_SETTING_IP4_CONFIG_METHOD_SHARED) == 0)
		cmp--;
	NM_CMP_RETURN (cmp);

	/* VPNs go next */
	NM_CMP_DIRECT (!!nm_active_connection_get_vpn (ac_a),
	               !!nm_active_connection_get_vpn (ac_b));

	/* Default devices are prioritized */
	NM_CMP_DIRECT (nm_active_connection_get_default (ac_a),
	               nm_active_connection_get_default (ac_b));

	/* Default IPv6 devices are prioritized */
	NM_CMP_DIRECT (nm_active_connection_get_default6 (ac_a),
	               nm_active_connection_get_default6 (ac_b));

	/* Sort by number of addresses. */
	da_ip = nm_active_connection_get_ip4_config (ac_a);
	da_num_addrs = da_ip ? nm_ip_config_get_addresses (da_ip)->len : 0;
	db_ip = nm_active_connection_get_ip4_config (ac_b);
	db_num_addrs = db_ip ? nm_ip_config_get_addresses (db_ip)->len : 0;

	da_ip = nm_active_connection_get_ip6_config (ac_a);
	da_num_addrs += da_ip ? nm_ip_config_get_addresses (da_ip)->len : 0;
	db_ip = nm_active_connection_get_ip6_config (ac_b);
	db_num_addrs += db_ip ? nm_ip_config_get_addresses (db_ip)->len : 0;

	NM_CMP_DIRECT (da_num_addrs, db_num_addrs);

	return 0;
}

static char *
get_ac_device_string (NMActiveConnection *active)
{
	GString *dev_str;
	const GPtrArray *devices;
	int i;

	if (!active)
		return NULL;

	/* Get devices of the active connection */
	dev_str = g_string_new (NULL);
	devices = nm_active_connection_get_devices (active);
	for (i = 0; i < devices->len; i++) {
		NMDevice *device = g_ptr_array_index (devices, i);
		const char *dev_iface = nm_device_get_iface (device);

		if (dev_iface) {
			g_string_append (dev_str, dev_iface);
			g_string_append_c (dev_str, ',');
		}
	}
	if (dev_str->len > 0)
		g_string_truncate (dev_str, dev_str->len - 1);  /* Cut off last ',' */

	return g_string_free (dev_str, FALSE);
}

/*****************************************************************************/

/* FIXME: The same or similar code for VPN info appears also in nm-applet (applet-dialogs.c),
 * and in gnome-control-center as well. It could probably be shared somehow. */

static const char *
get_vpn_connection_type (NMConnection *connection)
{
	NMSettingVpn *s_vpn;
	const char *type, *p;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn)
		return NULL;

	/* The service type is in form of "org.freedesktop.NetworkManager.vpnc".
	 * Extract end part after last dot, e.g. "vpnc"
	 */
	type = nm_setting_vpn_get_service_type (nm_connection_get_setting_vpn (connection));
	if (!type)
		return NULL;
	p = strrchr (type, '.');
	return p ? p + 1 : type;
}

/* VPN parameters can be found at:
 * http://git.gnome.org/browse/network-manager-openvpn/tree/src/nm-openvpn-service.h
 * http://git.gnome.org/browse/network-manager-vpnc/tree/src/nm-vpnc-service.h
 * http://git.gnome.org/browse/network-manager-pptp/tree/src/nm-pptp-service.h
 * http://git.gnome.org/browse/network-manager-openconnect/tree/src/nm-openconnect-service.h
 * http://git.gnome.org/browse/network-manager-openswan/tree/src/nm-openswan-service.h
 * See also 'properties' directory in these plugins.
 */
static const char *
find_vpn_gateway_key (const char *vpn_type)
{
	if (vpn_type) {
		if (nm_streq (vpn_type, "openvpn"))     return "remote";
		if (nm_streq (vpn_type, "vpnc"))        return "IPSec gateway";
		if (nm_streq (vpn_type, "pptp"))        return "gateway";
		if (nm_streq (vpn_type, "openconnect")) return "gateway";
		if (nm_streq (vpn_type, "openswan"))    return "right";
		if (nm_streq (vpn_type, "libreswan"))   return "right";
		if (nm_streq (vpn_type, "ssh"))         return "remote";
		if (nm_streq (vpn_type, "l2tp"))        return "gateway";
	}
	return NULL;
}

static const char *
find_vpn_username_key (const char *vpn_type)
{
	if (vpn_type) {
		if (nm_streq (vpn_type, "openvpn"))     return "username";
		if (nm_streq (vpn_type, "vpnc"))        return "Xauth username";
		if (nm_streq (vpn_type, "pptp"))        return "user";
		if (nm_streq (vpn_type, "openconnect")) return "username";
		if (nm_streq (vpn_type, "openswan"))    return "leftxauthusername";
		if (nm_streq (vpn_type, "libreswan"))   return "leftxauthusername";
		if (nm_streq (vpn_type, "l2tp"))        return "user";
	}
	return NULL;
}

enum VpnDataItem {
	VPN_DATA_ITEM_GATEWAY,
	VPN_DATA_ITEM_USERNAME
};

static const char *
get_vpn_data_item (NMConnection *connection, enum VpnDataItem vpn_data_item)
{
	const char *type;
	const char *key = NULL;

	type = get_vpn_connection_type (connection);

	switch (vpn_data_item) {
	case VPN_DATA_ITEM_GATEWAY:
		key = find_vpn_gateway_key (type);
		break;
	case VPN_DATA_ITEM_USERNAME:
		key = find_vpn_username_key (type);
		break;
	default:
		break;
	}

	if (!key)
		return NULL;
	return nm_setting_vpn_get_data_item (nm_connection_get_setting_vpn (connection), key);
}

/*****************************************************************************/

typedef struct {
	NMConnection *connection;
	NMActiveConnection *primary_active;
	GPtrArray *all_active;
	bool show_active_fields;
} MetagenConShowRowData;

static MetagenConShowRowData *
_metagen_con_show_row_data_new_for_connection (NMRemoteConnection *connection, gboolean show_active_fields)
{
	MetagenConShowRowData *row_data;

	row_data = g_slice_new0 (MetagenConShowRowData);
	row_data->connection = g_object_ref (NM_CONNECTION (connection));
	row_data->show_active_fields = show_active_fields;
	return row_data;
}

static MetagenConShowRowData *
_metagen_con_show_row_data_new_for_active_connection (NMRemoteConnection *connection, NMActiveConnection *active, gboolean show_active_fields)
{
	MetagenConShowRowData *row_data;

	row_data = g_slice_new0 (MetagenConShowRowData);
	if (connection)
		row_data->connection = g_object_ref (NM_CONNECTION (connection));
	row_data->primary_active = g_object_ref (active);
	row_data->show_active_fields = show_active_fields;
	return row_data;
}

static void
_metagen_con_show_row_data_add_active_connection (MetagenConShowRowData *row_data, NMActiveConnection *active)
{
	if (!row_data->primary_active) {
		row_data->primary_active = g_object_ref (active);
		return;
	}
	if (!row_data->all_active) {
		row_data->all_active = g_ptr_array_new_with_free_func (g_object_unref);
		g_ptr_array_add (row_data->all_active, g_object_ref (row_data->primary_active));
	}
	g_ptr_array_add (row_data->all_active, g_object_ref (active));
}

static void
_metagen_con_show_row_data_init_primary_active (MetagenConShowRowData *row_data)
{
	NMActiveConnection *ac, *best_ac;
	guint i;

	if (!row_data->all_active)
		return;

	best_ac = row_data->all_active->pdata[0];
	for (i = 1; i < row_data->all_active->len; i++) {
		ac = row_data->all_active->pdata[i];

		if (active_connection_get_state_ord (ac) > active_connection_get_state_ord (best_ac))
			best_ac = ac;
	}

	if (row_data->primary_active != best_ac) {
		g_object_unref (row_data->primary_active);
		row_data->primary_active = g_object_ref (best_ac);
	}
	g_clear_pointer (&row_data->all_active, g_ptr_array_unref);
}

static void
_metagen_con_show_row_data_destroy (gpointer data)
{
	MetagenConShowRowData *row_data = data;

	if (!row_data)
		return;

	g_clear_object (&row_data->connection);
	g_clear_object (&row_data->primary_active);
	g_clear_pointer (&row_data->all_active, g_ptr_array_unref);
	g_slice_free (MetagenConShowRowData, row_data);
}

static const char *
_con_show_fcn_get_id (NMConnection *c, NMActiveConnection *ac)
{
	NMSettingConnection *s_con = NULL;
	const char *s;

	if (c)
		s_con = nm_connection_get_setting_connection (c);

	s = s_con ? nm_setting_connection_get_id (s_con) : NULL;
	if (!s && ac) {
		/* note that if we have no s_con, that usually means that the user has no permissions
		 * to see the connection. We still fall to get the ID from the active-connection,
		 * which exposes it despite the user having no permissions.
		 *
		 * That might be unexpected, because the user is shown an ID, which he later
		 * is unable to resolve in other operations. */
		s = nm_active_connection_get_id (ac);
	}
	return s;
}

static const char *
_con_show_fcn_get_type (NMConnection *c, NMActiveConnection *ac, NMMetaAccessorGetType get_type)
{
	NMSettingConnection *s_con = NULL;
	const char *s;

	if (c)
		s_con = nm_connection_get_setting_connection (c);

	s = s_con ? nm_setting_connection_get_connection_type (s_con) : NULL;
	if (!s && ac) {
		/* see _con_show_fcn_get_id() for why we fallback to get the value
		 * from @ac. */
		s = nm_active_connection_get_connection_type (ac);
	}
	return connection_type_to_display (s, get_type);
}

static gconstpointer
_metagen_con_show_get_fcn (NMC_META_GENERIC_INFO_GET_FCN_ARGS)
{
	const MetagenConShowRowData *row_data = target;
	NMConnection *c = row_data->connection;
	NMActiveConnection *ac = row_data->primary_active;
	NMSettingConnection *s_con = NULL;
	const char *s;
	char *s_mut;

	NMC_HANDLE_COLOR (  ac
	                  ? nmc_active_connection_state_to_color (nm_active_connection_get_state (ac))
	                  : NM_META_COLOR_CONNECTION_UNKNOWN);

	if (c)
		s_con = nm_connection_get_setting_connection (c);

	if (!row_data->show_active_fields) {
		/* we are not supposed to show any fields of the active connection.
		 * We only tracked the primary_active to get the coloring right.
		 * From now on, there is no active connection. */
		ac = NULL;

		/* in this mode, we expect that we are called only with connections that
		 * have a [connection] setting and a UUID. Otherwise, the connection is
		 * effectively invisible to the user, and should be hidden.
		 *
		 * But in that case, we expect that the caller pre-filtered this row out.
		 * So assert(). */
		nm_assert (s_con);
		nm_assert (nm_setting_connection_get_uuid (s_con));
	}

	nm_assert (NM_IN_SET (get_type, NM_META_ACCESSOR_GET_TYPE_PRETTY, NM_META_ACCESSOR_GET_TYPE_PARSABLE));

	switch (info->info_type) {
	case NMC_GENERIC_INFO_TYPE_CON_SHOW_NAME:
		return _con_show_fcn_get_id (c, ac);
	case NMC_GENERIC_INFO_TYPE_CON_SHOW_UUID:
		s = s_con ? nm_setting_connection_get_uuid (s_con) : NULL;
		if (!s && ac) {
			/* see _con_show_fcn_get_id() for why we fallback to get the value
			 * from @ac. */
			s = nm_active_connection_get_uuid (ac);
		}
		return s;
	case NMC_GENERIC_INFO_TYPE_CON_SHOW_TYPE:
		return _con_show_fcn_get_type (c, ac, get_type);
	case NMC_GENERIC_INFO_TYPE_CON_SHOW_TIMESTAMP:
	case NMC_GENERIC_INFO_TYPE_CON_SHOW_TIMESTAMP_REAL:
		if (!s_con)
			return NULL;
		{
			guint64 timestamp;
			time_t timestamp_real;

			timestamp = nm_setting_connection_get_timestamp (s_con);

			if (info->info_type == NMC_GENERIC_INFO_TYPE_CON_SHOW_TIMESTAMP)
				return (*out_to_free = g_strdup_printf ("%" G_GUINT64_FORMAT, timestamp));
			else {
				if (!timestamp) {
					if (get_type == NM_META_ACCESSOR_GET_TYPE_PRETTY)
						return _("never");
					return "never";
				}
				timestamp_real = timestamp;
				s_mut = g_malloc0 (128);
				strftime (s_mut, 64, "%c", localtime (&timestamp_real));
				return (*out_to_free = s_mut);
			}
		}
	case NMC_GENERIC_INFO_TYPE_CON_SHOW_AUTOCONNECT:
		if (!s_con)
			return NULL;
		return nmc_meta_generic_get_bool (nm_setting_connection_get_autoconnect (s_con), get_type);
	case NMC_GENERIC_INFO_TYPE_CON_SHOW_AUTOCONNECT_PRIORITY:
		if (!s_con)
			return NULL;
		return (*out_to_free = g_strdup_printf ("%d", nm_setting_connection_get_autoconnect_priority (s_con)));
	case NMC_GENERIC_INFO_TYPE_CON_SHOW_READONLY:
		if (!s_con)
			return NULL;
		return nmc_meta_generic_get_bool (nm_setting_connection_get_read_only (s_con), get_type);
	case NMC_GENERIC_INFO_TYPE_CON_SHOW_DBUS_PATH:
		if (!c)
			return NULL;
		return nm_connection_get_path (c);
	case NMC_GENERIC_INFO_TYPE_CON_SHOW_ACTIVE:
		return nmc_meta_generic_get_bool (!!ac, get_type);
	case NMC_GENERIC_INFO_TYPE_CON_SHOW_DEVICE:
		if (ac)
			return (*out_to_free = get_ac_device_string (ac));
		return NULL;
	case NMC_GENERIC_INFO_TYPE_CON_SHOW_STATE:
		return nmc_meta_generic_get_str_i18n (ac
		                                        ? active_connection_state_to_string (nm_active_connection_get_state (ac))
		                                        : NULL,
		                                      get_type);
	case NMC_GENERIC_INFO_TYPE_CON_SHOW_ACTIVE_PATH:
		if (ac)
			return nm_object_get_path (NM_OBJECT (ac));
		return NULL;
	case NMC_GENERIC_INFO_TYPE_CON_SHOW_SLAVE:
		if (!s_con)
			return NULL;
		return nm_setting_connection_get_slave_type (s_con);
	case NMC_GENERIC_INFO_TYPE_CON_SHOW_FILENAME:
		if (!NM_IS_REMOTE_CONNECTION (c))
			return NULL;
		return nm_remote_connection_get_filename (NM_REMOTE_CONNECTION (c));
	default:
		break;
	}

	g_return_val_if_reached (NULL);
}

const NmcMetaGenericInfo *const metagen_con_show[_NMC_GENERIC_INFO_TYPE_CON_SHOW_NUM + 1] = {
#define _METAGEN_CON_SHOW(type, name) \
	[type] = NMC_META_GENERIC(name, .info_type = type, .get_fcn = _metagen_con_show_get_fcn)
	_METAGEN_CON_SHOW (NMC_GENERIC_INFO_TYPE_CON_SHOW_NAME,                 "NAME"),
	_METAGEN_CON_SHOW (NMC_GENERIC_INFO_TYPE_CON_SHOW_UUID,                 "UUID"),
	_METAGEN_CON_SHOW (NMC_GENERIC_INFO_TYPE_CON_SHOW_TYPE,                 "TYPE"),
	_METAGEN_CON_SHOW (NMC_GENERIC_INFO_TYPE_CON_SHOW_TIMESTAMP,            "TIMESTAMP"),
	_METAGEN_CON_SHOW (NMC_GENERIC_INFO_TYPE_CON_SHOW_TIMESTAMP_REAL,       "TIMESTAMP-REAL"),
	_METAGEN_CON_SHOW (NMC_GENERIC_INFO_TYPE_CON_SHOW_AUTOCONNECT,          "AUTOCONNECT"),
	_METAGEN_CON_SHOW (NMC_GENERIC_INFO_TYPE_CON_SHOW_AUTOCONNECT_PRIORITY, "AUTOCONNECT-PRIORITY"),
	_METAGEN_CON_SHOW (NMC_GENERIC_INFO_TYPE_CON_SHOW_READONLY,             "READONLY"),
	_METAGEN_CON_SHOW (NMC_GENERIC_INFO_TYPE_CON_SHOW_DBUS_PATH,            "DBUS-PATH"),
	_METAGEN_CON_SHOW (NMC_GENERIC_INFO_TYPE_CON_SHOW_ACTIVE,               "ACTIVE"),
	_METAGEN_CON_SHOW (NMC_GENERIC_INFO_TYPE_CON_SHOW_DEVICE,               "DEVICE"),
	_METAGEN_CON_SHOW (NMC_GENERIC_INFO_TYPE_CON_SHOW_STATE,                "STATE"),
	_METAGEN_CON_SHOW (NMC_GENERIC_INFO_TYPE_CON_SHOW_ACTIVE_PATH,          "ACTIVE-PATH"),
	_METAGEN_CON_SHOW (NMC_GENERIC_INFO_TYPE_CON_SHOW_SLAVE,                "SLAVE"),
	_METAGEN_CON_SHOW (NMC_GENERIC_INFO_TYPE_CON_SHOW_FILENAME,             "FILENAME"),
};
#define NMC_FIELDS_CON_SHOW_COMMON  "NAME,UUID,TYPE,DEVICE"

/*****************************************************************************/

static gconstpointer
_metagen_con_active_general_get_fcn (NMC_META_GENERIC_INFO_GET_FCN_ARGS)
{
	NMActiveConnection *ac = target;
	NMConnection *c;
	NMSettingConnection *s_con = NULL;
	NMDevice *dev;
	guint i;
	const char *s;

	NMC_HANDLE_COLOR (NM_META_COLOR_NONE);

	nm_assert (NM_IN_SET (get_type, NM_META_ACCESSOR_GET_TYPE_PRETTY, NM_META_ACCESSOR_GET_TYPE_PARSABLE));

	c = NM_CONNECTION (nm_active_connection_get_connection (ac));
	if (c)
		s_con = nm_connection_get_setting_connection (c);

	switch (info->info_type) {
	case NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_NAME:
		return nm_active_connection_get_id (ac);
	case NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_UUID:
		return nm_active_connection_get_uuid (ac);
	case NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_DEVICES:
		{
			GString *str = NULL;
			const GPtrArray *devices;

			s = NULL;
			devices = nm_active_connection_get_devices (ac);
			if (devices) {
				for (i = 0; i < devices->len; i++) {
					NMDevice *device = devices->pdata[i];
					const char *iface;

					iface = nm_device_get_iface (device);
					if (!iface)
						continue;
					if (!s) {
						s = iface;
						continue;
					}
					if (!str)
						str = g_string_new (s);
					g_string_append_c (str, ',');
					g_string_append (str, iface);
				}
			}
			if (str)
				return (*out_to_free = g_string_free (str, FALSE));
			return s;
		}
	case NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_STATE:
		return nmc_meta_generic_get_str_i18n (active_connection_state_to_string (nm_active_connection_get_state (ac)),
		                                      get_type);
	case NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_DEFAULT:
		return nmc_meta_generic_get_bool (nm_active_connection_get_default (ac), get_type);
	case NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_DEFAULT6:
		return nmc_meta_generic_get_bool (nm_active_connection_get_default6 (ac), get_type);
	case NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_SPEC_OBJECT:
		return nm_active_connection_get_specific_object_path (ac);
	case NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_VPN:
		return nmc_meta_generic_get_bool (NM_IS_VPN_CONNECTION (ac), get_type);
	case NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_DBUS_PATH:
		return nm_object_get_path (NM_OBJECT (ac));
	case NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_CON_PATH:
		return c ? nm_connection_get_path (c) : NULL;
	case NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_ZONE:
		/* this is really ugly, because the zone is not a property of the active-connection,
		 * but the settings-connection profile. There is no guarantee, that they agree. */
		return s_con ? nm_setting_connection_get_zone (s_con) : NULL;
	case NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_MASTER_PATH:
		dev = nm_active_connection_get_master (ac);
		return dev ? nm_object_get_path (NM_OBJECT (dev)) : NULL;
	default:
		break;
	}

	g_return_val_if_reached (NULL);
}

const NmcMetaGenericInfo *const metagen_con_active_general[_NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_NUM + 1] = {
#define _METAGEN_CON_ACTIVE_GENERAL(type, name) \
	[type] = NMC_META_GENERIC(name, .info_type = type, .get_fcn = _metagen_con_active_general_get_fcn)
	_METAGEN_CON_ACTIVE_GENERAL (NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_NAME,        "NAME"),
	_METAGEN_CON_ACTIVE_GENERAL (NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_UUID,        "UUID"),
	_METAGEN_CON_ACTIVE_GENERAL (NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_DEVICES,     "DEVICES"),
	_METAGEN_CON_ACTIVE_GENERAL (NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_STATE,       "STATE"),
	_METAGEN_CON_ACTIVE_GENERAL (NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_DEFAULT,     "DEFAULT"),
	_METAGEN_CON_ACTIVE_GENERAL (NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_DEFAULT6,    "DEFAULT6"),
	_METAGEN_CON_ACTIVE_GENERAL (NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_SPEC_OBJECT, "SPEC-OBJECT"),
	_METAGEN_CON_ACTIVE_GENERAL (NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_VPN,         "VPN"),
	_METAGEN_CON_ACTIVE_GENERAL (NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_DBUS_PATH,   "DBUS-PATH"),
	_METAGEN_CON_ACTIVE_GENERAL (NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_CON_PATH,    "CON-PATH"),
	_METAGEN_CON_ACTIVE_GENERAL (NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_ZONE,        "ZONE"),
	_METAGEN_CON_ACTIVE_GENERAL (NMC_GENERIC_INFO_TYPE_CON_ACTIVE_GENERAL_MASTER_PATH, "MASTER-PATH"),
};

/*****************************************************************************/

static gconstpointer
_metagen_con_active_vpn_get_fcn (NMC_META_GENERIC_INFO_GET_FCN_ARGS)
{
	NMActiveConnection *ac = target;
	NMConnection *c;
	NMSettingVpn *s_vpn = NULL;
	NMVpnConnectionState vpn_state;
	guint i;
	const char *s;
	char **arr = NULL;

	nm_assert (NM_IS_VPN_CONNECTION (ac));

	NMC_HANDLE_COLOR (NM_META_COLOR_NONE);

	nm_assert (NM_IN_SET (get_type, NM_META_ACCESSOR_GET_TYPE_PRETTY, NM_META_ACCESSOR_GET_TYPE_PARSABLE));

	c = NM_CONNECTION (nm_active_connection_get_connection (ac));
	if (c)
		s_vpn = nm_connection_get_setting_vpn (c);

	switch (info->info_type) {
	case NMC_GENERIC_INFO_TYPE_CON_VPN_TYPE:
		return c ? get_vpn_connection_type (c) : NULL;
	case NMC_GENERIC_INFO_TYPE_CON_VPN_USERNAME:
		if (   s_vpn
		    && (s = nm_setting_vpn_get_user_name (s_vpn)))
			return s;
		return c ? get_vpn_data_item (c, VPN_DATA_ITEM_USERNAME) : NULL;
	case NMC_GENERIC_INFO_TYPE_CON_VPN_GATEWAY:
		return c ? get_vpn_data_item (c, VPN_DATA_ITEM_GATEWAY) : NULL;
	case NMC_GENERIC_INFO_TYPE_CON_VPN_BANNER:
		s = nm_vpn_connection_get_banner (NM_VPN_CONNECTION (ac));
		if (s)
			return (*out_to_free = g_strescape (s, ""));
		return NULL;
	case NMC_GENERIC_INFO_TYPE_CON_VPN_VPN_STATE:
		vpn_state = nm_vpn_connection_get_vpn_state (NM_VPN_CONNECTION (ac));
		return (*out_to_free = nmc_meta_generic_get_enum_with_detail (NMC_META_GENERIC_GET_ENUM_TYPE_DASH,
		                                                              vpn_state,
		                                                              vpn_connection_state_to_string (vpn_state),
		                                                              get_type));
	case NMC_GENERIC_INFO_TYPE_CON_VPN_CFG:
		if (!NM_FLAGS_HAS (get_flags, NM_META_ACCESSOR_GET_FLAGS_ACCEPT_STRV))
			return NULL;
		if (s_vpn) {
			gs_free char **arr2 = NULL;
			guint n;

			arr2 = (char **) nm_setting_vpn_get_data_keys (s_vpn, &n);
			if (!n)
				goto arr_out;

			nm_assert (arr2 && !arr2[n]);
			for (i = 0; i < n; i++) {
				const char *k = arr2[i];
				const char *v;

				nm_assert (k);
				v = nm_setting_vpn_get_data_item (s_vpn, k);
				/* update the arr array in-place. Previously it contained
				 * the constant keys, now it contains the strdup'ed output text. */
				arr2[i] = g_strdup_printf ("%s = %s", k, v);
			}

			arr = g_steal_pointer (&arr2);
		}
		goto arr_out;
	default:
		break;
	}

	g_return_val_if_reached (NULL);

arr_out:
	NM_SET_OUT (out_is_default, !arr || !arr[0]);
	*out_flags |= NM_META_ACCESSOR_GET_OUT_FLAGS_STRV;
	*out_to_free = arr;
	return arr;
}

const NmcMetaGenericInfo *const metagen_con_active_vpn[_NMC_GENERIC_INFO_TYPE_CON_ACTIVE_VPN_NUM + 1] = {
#define _METAGEN_CON_ACTIVE_VPN(type, name) \
	[type] = NMC_META_GENERIC(name, .info_type = type, .get_fcn = _metagen_con_active_vpn_get_fcn)
	_METAGEN_CON_ACTIVE_VPN (NMC_GENERIC_INFO_TYPE_CON_VPN_TYPE,      "TYPE"),
	_METAGEN_CON_ACTIVE_VPN (NMC_GENERIC_INFO_TYPE_CON_VPN_USERNAME,  "USERNAME"),
	_METAGEN_CON_ACTIVE_VPN (NMC_GENERIC_INFO_TYPE_CON_VPN_GATEWAY,   "GATEWAY"),
	_METAGEN_CON_ACTIVE_VPN (NMC_GENERIC_INFO_TYPE_CON_VPN_BANNER,    "BANNER"),
	_METAGEN_CON_ACTIVE_VPN (NMC_GENERIC_INFO_TYPE_CON_VPN_VPN_STATE, "VPN-STATE"),
	_METAGEN_CON_ACTIVE_VPN (NMC_GENERIC_INFO_TYPE_CON_VPN_CFG,       "CFG"),
};

/*****************************************************************************/

#define NMC_FIELDS_SETTINGS_NAMES_ALL    NM_SETTING_CONNECTION_SETTING_NAME","\
                                         NM_SETTING_MATCH_SETTING_NAME","\
                                         NM_SETTING_WIRED_SETTING_NAME","\
                                         NM_SETTING_802_1X_SETTING_NAME","\
                                         NM_SETTING_WIRELESS_SETTING_NAME","\
                                         NM_SETTING_WIRELESS_SECURITY_SETTING_NAME","\
                                         NM_SETTING_IP4_CONFIG_SETTING_NAME","\
                                         NM_SETTING_IP6_CONFIG_SETTING_NAME","\
                                         NM_SETTING_SERIAL_SETTING_NAME","\
                                         NM_SETTING_WIFI_P2P_SETTING_NAME","\
                                         NM_SETTING_PPP_SETTING_NAME","\
                                         NM_SETTING_PPPOE_SETTING_NAME","\
                                         NM_SETTING_ADSL_SETTING_NAME","\
                                         NM_SETTING_GSM_SETTING_NAME","\
                                         NM_SETTING_CDMA_SETTING_NAME","\
                                         NM_SETTING_BLUETOOTH_SETTING_NAME","\
                                         NM_SETTING_OLPC_MESH_SETTING_NAME","\
                                         NM_SETTING_VPN_SETTING_NAME","\
                                         NM_SETTING_INFINIBAND_SETTING_NAME","\
                                         NM_SETTING_BOND_SETTING_NAME","\
                                         NM_SETTING_VLAN_SETTING_NAME","\
                                         NM_SETTING_BRIDGE_SETTING_NAME","\
                                         NM_SETTING_BRIDGE_PORT_SETTING_NAME","\
                                         NM_SETTING_TEAM_SETTING_NAME","\
                                         NM_SETTING_TEAM_PORT_SETTING_NAME"," \
                                         NM_SETTING_OVS_BRIDGE_SETTING_NAME","\
                                         NM_SETTING_OVS_INTERFACE_SETTING_NAME","\
                                         NM_SETTING_OVS_PATCH_SETTING_NAME","\
                                         NM_SETTING_OVS_PORT_SETTING_NAME","\
                                         NM_SETTING_DCB_SETTING_NAME"," \
                                         NM_SETTING_TUN_SETTING_NAME"," \
                                         NM_SETTING_IP_TUNNEL_SETTING_NAME"," \
                                         NM_SETTING_MACSEC_SETTING_NAME"," \
                                         NM_SETTING_MACVLAN_SETTING_NAME"," \
                                         NM_SETTING_VXLAN_SETTING_NAME"," \
                                         NM_SETTING_WPAN_SETTING_NAME","\
                                         NM_SETTING_6LOWPAN_SETTING_NAME","\
                                         NM_SETTING_WIREGUARD_SETTING_NAME","\
                                         NM_SETTING_PROXY_SETTING_NAME"," \
                                         NM_SETTING_TC_CONFIG_SETTING_NAME"," \
                                         NM_SETTING_SRIOV_SETTING_NAME"," \
                                         NM_SETTING_ETHTOOL_SETTING_NAME
                                         // NM_SETTING_DUMMY_SETTING_NAME
                                         // NM_SETTING_WIMAX_SETTING_NAME

const NmcMetaGenericInfo *const nmc_fields_con_active_details_groups[] = {
	NMC_META_GENERIC_WITH_NESTED ("GENERAL", metagen_con_active_general),                /* 0 */
	NMC_META_GENERIC_WITH_NESTED ("IP4",     metagen_ip4_config),                        /* 1 */
	NMC_META_GENERIC_WITH_NESTED ("DHCP4",   metagen_dhcp_config),                       /* 2 */
	NMC_META_GENERIC_WITH_NESTED ("IP6",     metagen_ip6_config),                        /* 3 */
	NMC_META_GENERIC_WITH_NESTED ("DHCP6",   metagen_dhcp_config),                       /* 4 */
	NMC_META_GENERIC_WITH_NESTED ("VPN",     metagen_con_active_vpn),                    /* 5 */
	NULL,
};

/* Pseudo group names for 'connection show <con>' */
/* e.g.: nmcli -f profile con show my-eth0 */
/* e.g.: nmcli -f active con show my-eth0 */
#define CON_SHOW_DETAIL_GROUP_PROFILE "profile"
#define CON_SHOW_DETAIL_GROUP_ACTIVE  "active"

static guint progress_id = 0;  /* ID of event source for displaying progress */

/* for readline TAB completion in editor */
typedef struct {
	NmCli *nmc;
	char *con_type;
	NMConnection *connection;
	NMSetting *setting;
	const char *property;
	char **words;
} TabCompletionInfo;

static TabCompletionInfo nmc_tab_completion;

/*****************************************************************************/

static void
usage (void)
{
	g_printerr (_("Usage: nmcli connection { COMMAND | help }\n\n"
	              "COMMAND := { show | up | down | add | modify | clone | edit | delete | monitor | reload | load | import | export }\n\n"
	              "  show [--active] [--order <order spec>]\n"
	              "  show [--active] [id | uuid | path | apath] <ID> ...\n\n"
	              "  up [[id | uuid | path] <ID>] [ifname <ifname>] [ap <BSSID>] [passwd-file <file with passwords>]\n\n"
	              "  down [id | uuid | path | apath] <ID> ...\n\n"
	              "  add COMMON_OPTIONS TYPE_SPECIFIC_OPTIONS SLAVE_OPTIONS IP_OPTIONS [-- ([+|-]<setting>.<property> <value>)+]\n\n"
	              "  modify [--temporary] [id | uuid | path] <ID> ([+|-]<setting>.<property> <value>)+\n\n"
	              "  clone [--temporary] [id | uuid | path ] <ID> <new name>\n\n"
	              "  edit [id | uuid | path] <ID>\n"
	              "  edit [type <new_con_type>] [con-name <new_con_name>]\n\n"
	              "  delete [id | uuid | path] <ID>\n\n"
	              "  monitor [id | uuid | path] <ID> ...\n\n"
	              "  reload\n\n"
	              "  load <filename> [ <filename>... ]\n\n"
	              "  import [--temporary] type <type> file <file to import>\n\n"
	              "  export [id | uuid | path] <ID> [<output file>]\n\n"));
}

static void
usage_connection_show (void)
{
	g_printerr (_("Usage: nmcli connection show { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [--active] [--order <order spec>]\n"
	              "\n"
	              "List in-memory and on-disk connection profiles, some of which may also be\n"
	              "active if a device is using that connection profile. Without a parameter, all\n"
	              "profiles are listed. When --active option is specified, only the active\n"
	              "profiles are shown. --order allows custom connection ordering (see manual page).\n"
	              "\n"
	              "ARGUMENTS := [--active] [id | uuid | path | apath] <ID> ...\n"
	              "\n"
	              "Show details for specified connections. By default, both static configuration\n"
	              "and active connection data are displayed. It is possible to filter the output\n"
	              "using global '--fields' option. Refer to the manual page for more information.\n"
	              "When --active option is specified, only the active profiles are taken into\n"
	              "account. Use global --show-secrets option to reveal associated secrets as well.\n"));
}

static void
usage_connection_up (void)
{
	g_printerr (_("Usage: nmcli connection up { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [id | uuid | path] <ID> [ifname <ifname>] [ap <BSSID>] [nsp <name>] [passwd-file <file with passwords>]\n"
	              "\n"
	              "Activate a connection on a device. The profile to activate is identified by its\n"
	              "name, UUID or D-Bus path.\n"
	              "\n"
	              "ARGUMENTS := ifname <ifname> [ap <BSSID>] [nsp <name>] [passwd-file <file with passwords>]\n"
	              "\n"
	              "Activate a device with a connection. The connection profile is selected\n"
	              "automatically by NetworkManager.\n"
	              "\n"
	              "ifname      - specifies the device to active the connection on\n"
	              "ap          - specifies AP to connect to (only valid for Wi-Fi)\n"
	              "nsp         - specifies NSP to connect to (only valid for WiMAX)\n"
	              "passwd-file - file with password(s) required to activate the connection\n\n"));
}

static void
usage_connection_down (void)
{
	g_printerr (_("Usage: nmcli connection down { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [id | uuid | path | apath] <ID> ...\n"
	              "\n"
	              "Deactivate a connection from a device (without preventing the device from\n"
	              "further auto-activation). The profile to deactivate is identified by its name,\n"
	              "UUID or D-Bus path.\n\n"));
}

static void
usage_connection_add (void)
{
	g_printerr (_("Usage: nmcli connection add { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := COMMON_OPTIONS TYPE_SPECIFIC_OPTIONS SLAVE_OPTIONS IP_OPTIONS [-- ([+|-]<setting>.<property> <value>)+]\n\n"
	              "  COMMON_OPTIONS:\n"
	              "                  type <type>\n"
	              "                  ifname <interface name> | \"*\"\n"
	              "                  [con-name <connection name>]\n"
	              "                  [autoconnect yes|no]\n"
	              "                  [save yes|no]\n"
	              "                  [master <master (ifname, or connection UUID or name)>]\n"
	              "                  [slave-type <master connection type>]\n\n"
	              "  TYPE_SPECIFIC_OPTIONS:\n"
	              "    ethernet:     [mac <MAC address>]\n"
	              "                  [cloned-mac <cloned MAC address>]\n"
	              "                  [mtu <MTU>]\n\n"
	              "    wifi:         ssid <SSID>\n"
	              "                  [mac <MAC address>]\n"
	              "                  [cloned-mac <cloned MAC address>]\n"
	              "                  [mtu <MTU>]\n"
	              "                  [mode infrastructure|ap|adhoc]\n\n"
	              "    wimax:        [mac <MAC address>]\n"
	              "                  [nsp <NSP>]\n\n"
	              "    pppoe:        username <PPPoE username>\n"
	              "                  [password <PPPoE password>]\n"
	              "                  [service <PPPoE service name>]\n"
	              "                  [mtu <MTU>]\n"
	              "                  [mac <MAC address>]\n\n"
	              "    gsm:          apn <APN>\n"
	              "                  [user <username>]\n"
	              "                  [password <password>]\n\n"
	              "    cdma:         [user <username>]\n"
	              "                  [password <password>]\n\n"
	              "    infiniband:   [mac <MAC address>]\n"
	              "                  [mtu <MTU>]\n"
	              "                  [transport-mode datagram | connected]\n"
	              "                  [parent <ifname>]\n"
	              "                  [p-key <IPoIB P_Key>]\n\n"
	              "    bluetooth:    [addr <bluetooth address>]\n"
	              "                  [bt-type panu|nap|dun-gsm|dun-cdma]\n\n"
	              "    vlan:         dev <parent device (connection UUID, ifname, or MAC)>\n"
	              "                  id <VLAN ID>\n"
	              "                  [flags <VLAN flags>]\n"
	              "                  [ingress <ingress priority mapping>]\n"
	              "                  [egress <egress priority mapping>]\n"
	              "                  [mtu <MTU>]\n\n"
	              "    bond:         [mode balance-rr (0) | active-backup (1) | balance-xor (2) | broadcast (3) |\n"
	              "                        802.3ad    (4) | balance-tlb   (5) | balance-alb (6)]\n"
	              "                  [primary <ifname>]\n"
	              "                  [miimon <num>]\n"
	              "                  [downdelay <num>]\n"
	              "                  [updelay <num>]\n"
	              "                  [arp-interval <num>]\n"
	              "                  [arp-ip-target <num>]\n"
	              "                  [lacp-rate slow (0) | fast (1)]\n\n"
	              "    bond-slave:   master <master (ifname, or connection UUID or name)>\n\n"
	              "    team:         [config <file>|<raw JSON data>]\n\n"
	              "    team-slave:   master <master (ifname, or connection UUID or name)>\n"
	              "                  [config <file>|<raw JSON data>]\n\n"
	              "    bridge:       [stp yes|no]\n"
	              "                  [priority <num>]\n"
	              "                  [forward-delay <2-30>]\n"
	              "                  [hello-time <1-10>]\n"
	              "                  [max-age <6-40>]\n"
	              "                  [ageing-time <0-1000000>]\n"
	              "                  [multicast-snooping yes|no]\n"
	              "                  [mac <MAC address>]\n\n"
	              "    bridge-slave: master <master (ifname, or connection UUID or name)>\n"
	              "                  [priority <0-63>]\n"
	              "                  [path-cost <1-65535>]\n"
	              "                  [hairpin yes|no]\n\n"
	              "    vpn:          vpn-type vpnc|openvpn|pptp|openconnect|openswan|libreswan|ssh|l2tp|iodine|...\n"
	              "                  [user <username>]\n\n"
	              "    olpc-mesh:    ssid <SSID>\n"
	              "                  [channel <1-13>]\n"
	              "                  [dhcp-anycast <MAC address>]\n\n"
	              "    adsl:         username <username>\n"
	              "                  protocol pppoa|pppoe|ipoatm\n"
	              "                  [password <password>]\n"
	              "                  [encapsulation vcmux|llc]\n\n"
	              "    tun:          mode tun|tap\n"
	              "                  [owner <UID>]\n"
	              "                  [group <GID>]\n"
	              "                  [pi yes|no]\n"
	              "                  [vnet-hdr yes|no]\n"
	              "                  [multi-queue yes|no]\n\n"
	              "    ip-tunnel:    mode ipip|gre|sit|isatap|vti|ip6ip6|ipip6|ip6gre|vti6\n"
	              "                  remote <remote endpoint IP>\n"
	              "                  [local <local endpoint IP>]\n"
	              "                  [dev <parent device (ifname or connection UUID)>]\n\n"
	              "    macsec:       dev <parent device (connection UUID, ifname, or MAC)>\n"
	              "                  mode <psk|eap>\n"
	              "                  [cak <key> ckn <key>]\n"
	              "                  [encrypt yes|no]\n"
	              "                  [port 1-65534]\n\n\n"
	              "    macvlan:      dev <parent device (connection UUID, ifname, or MAC)>\n"
	              "                  mode vepa|bridge|private|passthru|source\n"
	              "                  [tap yes|no]\n\n"
	              "    vxlan:        id <VXLAN ID>\n"
	              "                  remote <IP of multicast group or remote address>\n"
	              "                  [local <source IP>]\n"
	              "                  [dev <parent device (ifname or connection UUID)>]\n"
	              "                  [source-port-min <0-65535>]\n"
	              "                  [source-port-max <0-65535>]\n"
	              "                  [destination-port <0-65535>]\n\n"
	              "    wpan:         [short-addr <0x0000-0xffff>]\n"
	              "                  [pan-id <0x0000-0xffff>]\n"
	              "                  [page <default|0-31>]\n"
	              "                  [channel <default|0-26>]\n"
	              "                  [mac <MAC address>]\n\n"
	              "    6lowpan:      dev <parent device (connection UUID, ifname, or MAC)>\n"
	              "    dummy:\n\n"
	              "  SLAVE_OPTIONS:\n"
	              "    bridge:       [priority <0-63>]\n"
	              "                  [path-cost <1-65535>]\n"
	              "                  [hairpin yes|no]\n\n"
	              "    team:         [config <file>|<raw JSON data>]\n\n"
	              "  IP_OPTIONS:\n"
	              "                  [ip4 <IPv4 address>] [gw4 <IPv4 gateway>]\n"
	              "                  [ip6 <IPv6 address>] [gw6 <IPv6 gateway>]\n\n"));
}

static void
usage_connection_modify (void)
{
	g_printerr (_("Usage: nmcli connection modify { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [id | uuid | path] <ID> ([+|-]<setting>.<property> <value>)+\n"
	              "\n"
	              "Modify one or more properties of the connection profile.\n"
	              "The profile is identified by its name, UUID or D-Bus path. For multi-valued\n"
	              "properties you can use optional '+' or '-' prefix to the property name.\n"
	              "The '+' sign allows appending items instead of overwriting the whole value.\n"
	              "The '-' sign allows removing selected items instead of the whole value.\n"
	              "\n"
	              "Examples:\n"
	              "nmcli con mod home-wifi wifi.ssid rakosnicek\n"
	              "nmcli con mod em1-1 ipv4.method manual ipv4.addr \"192.168.1.2/24, 10.10.1.5/8\"\n"
	              "nmcli con mod em1-1 +ipv4.dns 8.8.4.4\n"
	              "nmcli con mod em1-1 -ipv4.dns 1\n"
	              "nmcli con mod em1-1 -ipv6.addr \"abbe::cafe/56\"\n"
	              "nmcli con mod bond0 +bond.options mii=500\n"
	              "nmcli con mod bond0 -bond.options downdelay\n\n"));
}

static void
usage_connection_clone (void)
{
	g_printerr (_("Usage: nmcli connection clone { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [--temporary] [id | uuid | path] <ID> <new name>\n"
	              "\n"
	              "Clone an existing connection profile. The newly created connection will be\n"
	              "the exact copy of the <ID>, except the uuid property (will be generated) and\n"
	              "id (provided as <new name> argument).\n\n"));
}

static void
usage_connection_edit (void)
{
	g_printerr (_("Usage: nmcli connection edit { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [id | uuid | path] <ID>\n"
	              "\n"
	              "Edit an existing connection profile in an interactive editor.\n"
	              "The profile is identified by its name, UUID or D-Bus path\n"
	              "\n"
	              "ARGUMENTS := [type <new connection type>] [con-name <new connection name>]\n"
	              "\n"
	              "Add a new connection profile in an interactive editor.\n\n"));
}

static void
usage_connection_delete (void)
{
	g_printerr (_("Usage: nmcli connection delete { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [id | uuid | path] <ID>\n"
	              "\n"
	              "Delete a connection profile.\n"
	              "The profile is identified by its name, UUID or D-Bus path.\n\n"));
}

static void
usage_connection_monitor (void)
{
	g_printerr (_("Usage: nmcli connection monitor { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [id | uuid | path] <ID> ...\n"
	              "\n"
	              "Monitor connection profile activity.\n"
	              "This command prints a line whenever the specified connection changes.\n"
	              "Monitors all connection profiles in case none is specified.\n\n"));
}

static void
usage_connection_reload (void)
{
	g_printerr (_("Usage: nmcli connection reload { help }\n"
	              "\n"
	              "Reload all connection files from disk.\n\n"));
}

static void
usage_connection_load (void)
{
	g_printerr (_("Usage: nmcli connection load { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := <filename> [<filename>...]\n"
	              "\n"
	              "Load/reload one or more connection files from disk. Use this after manually\n"
	              "editing a connection file to ensure that NetworkManager is aware of its latest\n"
	              "state.\n\n"));
}

static void
usage_connection_import (void)
{
	g_printerr (_("Usage: nmcli connection import { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [--temporary] type <type> file <file to import>\n"
	              "\n"
	              "Import an external/foreign configuration as a NetworkManager connection profile.\n"
	              "The type of the input file is specified by type option.\n"
	              "Only VPN configurations are supported at the moment. The configuration\n"
	              "is imported by NetworkManager VPN plugins.\n\n"));
}

static void
usage_connection_export (void)
{
	g_printerr (_("Usage: nmcli connection export { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [id | uuid | path] <ID> [<output file>]\n"
	              "\n"
	              "Export a connection. Only VPN connections are supported at the moment.\n"
	              "The data are directed to standard output or to a file if a name is given.\n\n"));
}

static void
quit (void)
{
	if (nm_clear_g_source (&progress_id))
		nmc_terminal_erase_line ();
	g_main_loop_quit (loop);
}

static char *
construct_header_name (const char *base, const char *spec)
{
	if (spec == NULL)
		return g_strdup (base);

	return g_strdup_printf ("%s (%s)", base, spec);
}

static int
get_ac_for_connection_cmp (gconstpointer pa, gconstpointer pb)
{
	NMActiveConnection *ac_a = *((NMActiveConnection *const*) pa);
	NMActiveConnection *ac_b = *((NMActiveConnection *const*) pb);

	NM_CMP_RETURN (nmc_active_connection_cmp (ac_a, ac_b));
	NM_CMP_DIRECT_STRCMP0 (nm_active_connection_get_id (ac_a),
	                       nm_active_connection_get_id (ac_b));
	NM_CMP_DIRECT_STRCMP0 (nm_active_connection_get_connection_type (ac_a),
	                       nm_active_connection_get_connection_type (ac_b));
	NM_CMP_DIRECT_STRCMP0 (nm_object_get_path (NM_OBJECT (ac_a)),
	                       nm_object_get_path (NM_OBJECT (ac_b)));

	g_return_val_if_reached (0);
}

static NMActiveConnection *
get_ac_for_connection (const GPtrArray *active_cons, NMConnection *connection, GPtrArray **out_result)
{
	guint i;
	NMActiveConnection *best_candidate = NULL;
	GPtrArray *result = out_result ? *out_result : NULL;

	for (i = 0; i < active_cons->len; i++) {
		NMActiveConnection *candidate = g_ptr_array_index (active_cons, i);
		NMRemoteConnection *con;

		con = nm_active_connection_get_connection (candidate);
		if (NM_CONNECTION (con) != connection)
			continue;

		if (!out_result)
			return candidate;
		if (!result)
			result = g_ptr_array_new_with_free_func (g_object_unref);
		g_ptr_array_add (result, g_object_ref (candidate));
	}

	if (result) {
		g_ptr_array_sort (result, get_ac_for_connection_cmp);
		best_candidate = result->pdata[0];
	}

	NM_SET_OUT (out_result, result);
	return best_candidate;
}

typedef struct {
	GMainLoop *loop;
	NMConnection *local;
	const char *setting_name;
} GetSecretsData;

static void
got_secrets (GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	NMRemoteConnection *remote = NM_REMOTE_CONNECTION (source_object);
	GetSecretsData *data = user_data;
	GVariant *secrets;
	GError *error = NULL;

	secrets = nm_remote_connection_get_secrets_finish (remote, res, NULL);
	if (secrets) {
		if (!nm_connection_update_secrets (data->local, NULL, secrets, &error) && error) {
			g_printerr (_("Error updating secrets for %s: %s\n"),
			            data->setting_name, error->message);
			g_clear_error (&error);
		}
		g_variant_unref (secrets);
	}

	g_main_loop_quit (data->loop);
}

/* Put secrets into local connection. */
static void
update_secrets_in_connection (NMRemoteConnection *remote, NMConnection *local)
{
	GetSecretsData data = { 0, };
	GType setting_type;
	int i;

	data.local = local;
	data.loop = g_main_loop_new (NULL, FALSE);

	for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++) {
		setting_type = nm_meta_setting_infos[i].get_setting_gtype();
		if (!nm_connection_get_setting (NM_CONNECTION (remote), setting_type))
			continue;
		if (!nm_meta_setting_info_editor_has_secrets (nm_meta_setting_info_editor_find_by_gtype (setting_type)))
			continue;
		data.setting_name = nm_meta_setting_infos[i].setting_name;
		nm_remote_connection_get_secrets_async (remote,
		                                        nm_meta_setting_infos[i].setting_name,
		                                        NULL,
		                                        got_secrets,
		                                        &data);
		g_main_loop_run (data.loop);
	}

	g_main_loop_unref (data.loop);
}

static gboolean
nmc_connection_profile_details (NMConnection *connection, NmCli *nmc)
{
	GError *error = NULL;
	GArray *print_settings_array;
	GPtrArray *prop_array = NULL;
	int i;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_SETTINGS_NAMES_ALL;
	char *fields_common = NMC_FIELDS_SETTINGS_NAMES_ALL;
	const char *base_hdr = _("Connection profile details");
	gboolean was_output = FALSE;

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	print_settings_array = parse_output_fields (fields_str, (const NMMetaAbstractInfo *const*) nm_meta_setting_infos_editor_p (),
	                                            TRUE, &prop_array, &error);
	if (error) {
		g_string_printf (nmc->return_text, _("Error: 'connection show': %s"), error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}
	g_assert (print_settings_array);

	/* Main header */
	{
		gs_free char *header_name = NULL;
		gs_free NmcOutputField *row = NULL;
		gs_unref_array GArray *out_indices = NULL;

		header_name = construct_header_name (base_hdr, nm_connection_get_id (connection));
		out_indices = parse_output_fields (NMC_FIELDS_SETTINGS_NAMES_ALL,
		                                   (const NMMetaAbstractInfo *const*) nm_meta_setting_infos_editor_p (),
		                                   FALSE, NULL, NULL);

		row = g_new0 (NmcOutputField, _NM_META_SETTING_TYPE_NUM + 1);
		for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++)
			row[i].info = (const NMMetaAbstractInfo *) &nm_meta_setting_infos_editor[i];

		print_required_fields (&nmc->nmc_config, NMC_OF_FLAG_MAIN_HEADER_ONLY,
		                       out_indices, header_name,
		                       0, row);
	}

	/* Loop through the required settings and print them. */
	for (i = 0; i < print_settings_array->len; i++) {
		NMSetting *setting;
		int section_idx = g_array_index (print_settings_array, int, i);
		const char *prop_name = (const char *) g_ptr_array_index (prop_array, i);

		if (   NM_IN_SET (nmc->nmc_config.print_output, NMC_PRINT_NORMAL, NMC_PRINT_PRETTY)
		    && !nmc->nmc_config.multiline_output
		    && was_output)
			g_print ("\n"); /* Empty line */

		was_output = FALSE;

		setting = nm_connection_get_setting_by_name (connection, nm_meta_setting_infos_editor[section_idx].general->setting_name);
		if (setting) {
			setting_details (&nmc->nmc_config, setting, prop_name);
			was_output = TRUE;
		}
	}

	g_array_free (print_settings_array, TRUE);
	if (prop_array)
		g_ptr_array_free (prop_array, TRUE);

	return TRUE;
}

NMMetaColor
nmc_active_connection_state_to_color (NMActiveConnectionState state)
{
	if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATING)
		return NM_META_COLOR_CONNECTION_ACTIVATING;
	else if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED)
		return NM_META_COLOR_CONNECTION_ACTIVATED;
	else if (state > NM_ACTIVE_CONNECTION_STATE_ACTIVATED)
		return NM_META_COLOR_CONNECTION_DISCONNECTING;
	else
		return NM_META_COLOR_CONNECTION_UNKNOWN;
}

static gboolean
nmc_active_connection_details (NMActiveConnection *acon, NmCli *nmc)
{
	GError *error = NULL;
	GArray *print_groups;
	GPtrArray *group_fields = NULL;
	int i;
	const char *fields_str = NULL;
	const char *base_hdr = _("Activate connection details");
	gboolean was_output = FALSE;

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0) {
	} else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0) {
	} else
		fields_str = nmc->required_fields;

	print_groups = parse_output_fields (fields_str, (const NMMetaAbstractInfo *const*) nmc_fields_con_active_details_groups, TRUE, &group_fields, &error);
	if (error) {
		g_string_printf (nmc->return_text, _("Error: 'connection show': %s"), error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}
	g_assert (print_groups);

	/* Main header */
	{
		gs_free char *header_name = NULL;
		gs_free NmcOutputField *row = NULL;
		gs_unref_array GArray *out_indices = NULL;

		header_name = construct_header_name (base_hdr, nm_active_connection_get_uuid (acon));
		out_indices = parse_output_fields (NULL,
		                                   (const NMMetaAbstractInfo *const*) nmc_fields_con_active_details_groups,
		                                   FALSE, NULL, NULL);

		row = g_new0 (NmcOutputField, G_N_ELEMENTS (nmc_fields_con_active_details_groups) + 1);
		for (i = 0; nmc_fields_con_active_details_groups[i]; i++)
			row[i].info = (const NMMetaAbstractInfo *) nmc_fields_con_active_details_groups[i];

		print_required_fields (&nmc->nmc_config, NMC_OF_FLAG_MAIN_HEADER_ONLY,
		                       out_indices, header_name,
		                       0, row);
	}

	/* Loop through the groups and print them. */
	for (i = 0; i < print_groups->len; i++) {
		int group_idx = g_array_index (print_groups, int, i);
		char *group_fld = (char *) g_ptr_array_index (group_fields, i);

		if (   NM_IN_SET (nmc->nmc_config.print_output, NMC_PRINT_NORMAL, NMC_PRINT_PRETTY)
		    && !nmc->nmc_config.multiline_output
		    && was_output)
			g_print ("\n");

		was_output = FALSE;

		if (nmc_fields_con_active_details_groups[group_idx]->nested == metagen_con_active_general) {
			gs_free char *f = NULL;

			if (group_fld)
				f = g_strdup_printf ("GENERAL.%s", group_fld);

			nmc_print (&nmc->nmc_config,
			           (gpointer[]) { acon, NULL },
			           NULL,
			           NULL,
			           NMC_META_GENERIC_GROUP ("GENERAL", metagen_con_active_general, N_("GROUP")),
			           f,
			           NULL);
			was_output = TRUE;
			continue;
		}

		/* IP4 */
		if (strcasecmp (nmc_fields_con_active_details_groups[group_idx]->name,  nmc_fields_con_active_details_groups[1]->name) == 0) {
			gboolean b1 = FALSE;
			NMIPConfig *cfg4 = nm_active_connection_get_ip4_config (acon);

			b1 = print_ip_config (cfg4, AF_INET, &nmc->nmc_config, group_fld);
			was_output = was_output || b1;
		}

		/* DHCP4 */
		if (strcasecmp (nmc_fields_con_active_details_groups[group_idx]->name,  nmc_fields_con_active_details_groups[2]->name) == 0) {
			gboolean b1 = FALSE;
			NMDhcpConfig *dhcp4 = nm_active_connection_get_dhcp4_config (acon);

			b1 = print_dhcp_config (dhcp4, AF_INET, &nmc->nmc_config, group_fld);
			was_output = was_output || b1;
		}

		/* IP6 */
		if (strcasecmp (nmc_fields_con_active_details_groups[group_idx]->name,  nmc_fields_con_active_details_groups[3]->name) == 0) {
			gboolean b1 = FALSE;
			NMIPConfig *cfg6 = nm_active_connection_get_ip6_config (acon);

			b1 = print_ip_config (cfg6, AF_INET6, &nmc->nmc_config, group_fld);
			was_output = was_output || b1;
		}

		/* DHCP6 */
		if (strcasecmp (nmc_fields_con_active_details_groups[group_idx]->name,  nmc_fields_con_active_details_groups[4]->name) == 0) {
			gboolean b1 = FALSE;
			NMDhcpConfig *dhcp6 = nm_active_connection_get_dhcp6_config (acon);

			b1 = print_dhcp_config (dhcp6, AF_INET6, &nmc->nmc_config, group_fld);
			was_output = was_output || b1;
		}

		if (nmc_fields_con_active_details_groups[group_idx]->nested == metagen_con_active_vpn) {
			if (NM_IS_VPN_CONNECTION (acon)) {
				nmc_print (&nmc->nmc_config,
				           (gpointer[]) { acon, NULL },
				           NULL,
				           NULL,
				           NMC_META_GENERIC_GROUP ("VPN", metagen_con_active_vpn, N_("NAME")),
				           group_fld,
				           NULL);
				was_output = TRUE;
			}
			continue;
		}
	}

	g_array_free (print_groups, TRUE);
	if (group_fields)
		g_ptr_array_free (group_fields, TRUE);

	return TRUE;
}

static gboolean
split_required_fields_for_con_show (const char *input,
                                    char **profile_flds,
                                    char **active_flds,
                                    GError **error)
{
	gs_free const char **fields = NULL;
	const char *const*iter;
	nm_auto_free_gstring GString *str1 = NULL;
	nm_auto_free_gstring GString *str2 = NULL;
	gboolean group_profile = FALSE;
	gboolean group_active = FALSE;
	gboolean do_free;

	if (!input) {
		*profile_flds = NULL;
		*active_flds = NULL;
		return TRUE;
	}

	str1 = g_string_new (NULL);
	str2 = g_string_new (NULL);

	fields = nm_utils_strsplit_set_with_empty (input, ",");
	for (iter = fields; iter && *iter; iter++) {
		char *s_mutable = (char *) (*iter);
		char *dot;
		gboolean is_all;
		gboolean is_common;
		gboolean found;
		int i;

		g_strstrip (s_mutable);
		dot = strchr (s_mutable, '.');
		if (dot)
			*dot = '\0';

		is_all = !dot && strcasecmp (s_mutable, "all") == 0;
		is_common = !dot && strcasecmp (s_mutable, "common") == 0;

		found = FALSE;
		for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++) {
			if (   is_all || is_common
			    || !strcasecmp (s_mutable, nm_meta_setting_infos[i].setting_name)) {
				if (dot)
					*dot = '.';
				g_string_append (str1, s_mutable);
				g_string_append_c (str1, ',');
				found = TRUE;
				break;
			}
		}
		if (found)
			continue;

		for (i = 0; nmc_fields_con_active_details_groups[i]; i++) {
			if (   is_all || is_common
			    || !strcasecmp (s_mutable, nmc_fields_con_active_details_groups[i]->name)) {
				if (dot)
					*dot = '.';
				g_string_append (str2, s_mutable);
				g_string_append_c (str2, ',');
				found = TRUE;
				break;
			}
		}
		if (!found) {
			if (dot)
				*dot = '.';
			if (!strcasecmp (s_mutable, CON_SHOW_DETAIL_GROUP_PROFILE))
				group_profile = TRUE;
			else if (!strcasecmp (s_mutable, CON_SHOW_DETAIL_GROUP_ACTIVE))
				group_active = TRUE;
			else {
				gs_free char *allowed1 = nm_meta_abstract_infos_get_names_str ((const NMMetaAbstractInfo *const*) nm_meta_setting_infos_editor_p (), NULL);
				gs_free char *allowed2 = nm_meta_abstract_infos_get_names_str ((const NMMetaAbstractInfo *const*) nmc_fields_con_active_details_groups, NULL);

				g_set_error (error, NMCLI_ERROR, 0, _("invalid field '%s'; allowed fields: %s and %s, or %s,%s"),
				             s_mutable, allowed1, allowed2, CON_SHOW_DETAIL_GROUP_PROFILE, CON_SHOW_DETAIL_GROUP_ACTIVE);
				return FALSE;
			}
		}
	}

	/* Handle pseudo groups: profile, active */
	if (group_profile) {
		if (str1->len > 0) {
			g_set_error (error, NMCLI_ERROR, 0, _("'%s' has to be alone"),
			             CON_SHOW_DETAIL_GROUP_PROFILE);
			return FALSE;
		}
		g_string_assign (str1, "all,");
	}
	if (group_active) {
		if (str2->len > 0) {
			g_set_error (error, NMCLI_ERROR, 0, _("'%s' has to be alone"),
			             CON_SHOW_DETAIL_GROUP_ACTIVE);
			return FALSE;
		}
		g_string_assign (str2, "all,");
	}

	if (str1->len > 0)
		g_string_truncate (str1, str1->len - 1);
	if (str2->len > 0)
		g_string_truncate (str2, str2->len - 1);

	do_free = (str1->len == 0);
	*profile_flds = g_string_free (g_steal_pointer (&str1), do_free);
	do_free = (str2->len == 0);
	*active_flds = g_string_free (g_steal_pointer (&str2), do_free);
	return TRUE;
}

typedef enum {
	NMC_SORT_ACTIVE     =  1,
	NMC_SORT_ACTIVE_INV = -1,
	NMC_SORT_NAME       =  2,
	NMC_SORT_NAME_INV   = -2,
	NMC_SORT_TYPE       =  3,
	NMC_SORT_TYPE_INV   = -3,
	NMC_SORT_PATH       =  4,
	NMC_SORT_PATH_INV   = -4,
} NmcSortOrder;

typedef struct {
	NmCli *nmc;
	const GArray *order;
	gboolean show_active_fields;
} ConShowSortInfo;

static int
con_show_get_items_cmp (gconstpointer pa, gconstpointer pb, gpointer user_data)
{
	const ConShowSortInfo *sort_info = user_data;
	const MetagenConShowRowData *row_data_a = *((const MetagenConShowRowData *const*) pa);
	const MetagenConShowRowData *row_data_b = *((const MetagenConShowRowData *const*) pb);
	NMConnection *c_a = row_data_a->connection;
	NMConnection *c_b = row_data_b->connection;
	NMActiveConnection *ac_a = row_data_a->primary_active;
	NMActiveConnection *ac_b = row_data_b->primary_active;
	NMActiveConnection *ac_a_effective = sort_info->show_active_fields ? ac_a : NULL;
	NMActiveConnection *ac_b_effective = sort_info->show_active_fields ? ac_b : NULL;

	/* first sort active-connections which are invisible, i.e. that have no connection */
	if (!c_a && c_b)
		return -1;
	if (!c_b && c_a)
		return 1;

	/* we have two connections... */
	if (c_a && c_b && c_a != c_b) {
		const NmcSortOrder *order_arr;
		guint i, order_len;
		NMMetaAccessorGetType get_type = nmc_print_output_to_accessor_get_type (sort_info->nmc->nmc_config.print_output);

		if (sort_info->order) {
			order_arr = &g_array_index (sort_info->order, NmcSortOrder, 0);
			order_len = sort_info->order->len;
		} else {
			static const NmcSortOrder def[] = { NMC_SORT_ACTIVE, NMC_SORT_NAME, NMC_SORT_PATH };

			/* Note: the default order does not consider whether a column is shown.
			 *       That means, the selection of the output fields, does not affect the
			 *       order (although there could be an argument that it should). */
			order_arr = def;
			order_len = G_N_ELEMENTS (def);
		}

		for (i = 0; i < order_len; i++) {
			NmcSortOrder item = order_arr[i];

			switch (item) {

			case NMC_SORT_ACTIVE:
				NM_CMP_RETURN (nmc_active_connection_cmp (ac_b, ac_a));
				break;
			case NMC_SORT_ACTIVE_INV:
				NM_CMP_RETURN (nmc_active_connection_cmp (ac_a, ac_b));
				break;

			case NMC_SORT_TYPE:
				NM_CMP_DIRECT_STRCMP0 (_con_show_fcn_get_type (c_a, ac_a_effective, get_type),
				                       _con_show_fcn_get_type (c_b, ac_b_effective, get_type));
				break;
			case NMC_SORT_TYPE_INV:
				NM_CMP_DIRECT_STRCMP0 (_con_show_fcn_get_type (c_b, ac_b_effective, get_type),
				                       _con_show_fcn_get_type (c_a, ac_a_effective, get_type));
				break;

			case NMC_SORT_NAME:
				NM_CMP_RETURN (nm_utf8_collate0 (_con_show_fcn_get_id (c_a, ac_a_effective),
				                                 _con_show_fcn_get_id (c_b, ac_b_effective)));
				break;
			case NMC_SORT_NAME_INV:
				NM_CMP_RETURN (nm_utf8_collate0 (_con_show_fcn_get_id (c_b, ac_b_effective),
				                                 _con_show_fcn_get_id (c_a, ac_a_effective)));
				break;

			case NMC_SORT_PATH:
				NM_CMP_RETURN (nm_utils_dbus_path_cmp (nm_connection_get_path (c_a), nm_connection_get_path (c_b)));
				break;

			case NMC_SORT_PATH_INV:
				NM_CMP_RETURN (nm_utils_dbus_path_cmp (nm_connection_get_path (c_b), nm_connection_get_path (c_a)));
				break;

			default:
				nm_assert_not_reached ();
				break;
			}
		}

		NM_CMP_DIRECT_STRCMP0 (nm_connection_get_uuid (c_a),
		                       nm_connection_get_uuid (c_b));
		NM_CMP_DIRECT_STRCMP0 (nm_connection_get_path (c_a),
		                       nm_connection_get_path (c_b));
	}

	NM_CMP_DIRECT_STRCMP0 (nm_object_get_path (NM_OBJECT (ac_a)),
	                       nm_object_get_path (NM_OBJECT (ac_b)));

	g_return_val_if_reached (0);
}

static GPtrArray *
con_show_get_items (NmCli *nmc, gboolean active_only, gboolean show_active_fields, GArray *order)
{
	gs_unref_hashtable GHashTable *row_hash = NULL;
	GHashTableIter hiter;
	GPtrArray *result;
	const GPtrArray *arr;
	NMRemoteConnection *c;
	MetagenConShowRowData *row_data;
	guint i;
	const ConShowSortInfo sort_info = {
		.nmc = nmc,
		.order = order,
		.show_active_fields = show_active_fields,
	};

	row_hash = g_hash_table_new (nm_direct_hash, NULL);

	arr = nm_client_get_connections (nmc->client);
	for (i = 0; i < arr->len; i++) {
		/* Note: libnm will not expose connection that are invisible
		 * to the user but currently inactive.
		 *
		 * That differs from get-active-connection(). If an invisible connection
		 * is active, we can get its NMActiveConnection. We can even obtain
		 * the corresponding NMRemoteConnection (although, of course it has
		 * no visible settings).
		 *
		 * I think this inconsistency is a bug in libnm. Anyway, the result is,
		 * that we print invisible connections if they are active, but otherwise
		 * we exclude them. */
		c = arr->pdata[i];
		g_hash_table_insert (row_hash,
		                     c,
		                     _metagen_con_show_row_data_new_for_connection (c,
		                                                                    show_active_fields));
	}

	arr = nm_client_get_active_connections (nmc->client);
	for (i = 0; i < arr->len; i++) {
		NMActiveConnection *ac = arr->pdata[i];

		c = nm_active_connection_get_connection (ac);
		if (!show_active_fields && !c) {
			/* the active connection has no connection, and we don't show
			 * any active fields. Skip this row. */
			continue;
		}

		row_data =   c
		           ? g_hash_table_lookup (row_hash, c)
		           : NULL;

		if (show_active_fields || !c) {
			/* the active connection either has no connection (in which we create a
			 * connection-less row), or we are interested in showing each active
			 * connection in its own row. Add a row. */
			if (row_data) {
				/* we create a rowdata for this connection earlier. We drop it, because this
				 * connection is tracked via the rowdata of the active connection. */
				g_hash_table_remove (row_hash, c);
				_metagen_con_show_row_data_destroy (row_data);
			}
			row_data = _metagen_con_show_row_data_new_for_active_connection (c, ac, show_active_fields);
			g_hash_table_insert (row_hash, ac, row_data);
			continue;
		}

		/* we add the active connection to the row for the referenced
		 * connection. We need to group them this way, to print the proper
		 * color (activated or not) based on primary_active. */
		if (!row_data) {
			/* this is unexpected. The active connection references a connection that
			 * seemingly no longer exists. It's a bug in libnm. Add a row nonetheless. */
			row_data = _metagen_con_show_row_data_new_for_connection (c, show_active_fields);
			g_hash_table_insert (row_hash, c, row_data);
		}
		_metagen_con_show_row_data_add_active_connection (row_data, ac);
	}

	result = g_ptr_array_new_with_free_func (_metagen_con_show_row_data_destroy);

	g_hash_table_iter_init (&hiter, row_hash);
	while (g_hash_table_iter_next (&hiter, NULL, (gpointer *) &row_data)) {
		if (   active_only
		    && !row_data->primary_active) {
			/* We only print connections that are active. Skip this row. */
			_metagen_con_show_row_data_destroy (row_data);
			continue;
		}
		if (!show_active_fields) {
			NMSettingConnection *s_con;

			nm_assert (NM_IS_REMOTE_CONNECTION (row_data->connection));
			s_con = nm_connection_get_setting_connection (row_data->connection);
			if (   !s_con
			    || !nm_setting_connection_get_uuid (s_con)) {
				/* we are in a mode, where we only print rows for connection.
				 * For that we require that all rows are visible to the user,
				 * meaning: the have a [connection] setting and a UUID.
				 *
				 * Otherwise, this connection is likely invisible to the user.
				 * Skip it. */
				_metagen_con_show_row_data_destroy (row_data);
				continue;
			}
			_metagen_con_show_row_data_init_primary_active (row_data);
		} else
			nm_assert (!row_data->all_active);
		g_ptr_array_add (result, row_data);
	}

	g_ptr_array_sort_with_data (result, con_show_get_items_cmp, (gpointer) &sort_info);
	return result;
}

static GArray *
parse_preferred_connection_order (const char *order, GError **error)
{
	gs_free const char **strv = NULL;
	const char *const*iter;
	const char *str;
	GArray *order_arr;
	NmcSortOrder val;
	gboolean inverse, unique;
	int i;

	strv = nm_utils_strsplit_set (order, ":");
	if (!strv) {
		g_set_error (error, NMCLI_ERROR, 0,
		             _("incorrect string '%s' of '--order' option"), order);
		return NULL;
	}

	order_arr = g_array_sized_new (FALSE, FALSE, sizeof (NmcSortOrder), 4);
	for (iter = strv; iter && *iter; iter++) {
		str = *iter;
		inverse = FALSE;
		if (str[0] == '-')
			inverse = TRUE;
		if (str[0] == '+' || str[0] == '-')
			str++;

		if (matches (str, "active"))
			val = inverse ? NMC_SORT_ACTIVE_INV : NMC_SORT_ACTIVE;
		else if (matches (str, "name"))
			val = inverse ? NMC_SORT_NAME_INV : NMC_SORT_NAME;
		else if (matches (str, "type"))
			val = inverse ? NMC_SORT_TYPE_INV : NMC_SORT_TYPE;
		else if (matches (str, "path"))
			val = inverse ? NMC_SORT_PATH_INV : NMC_SORT_PATH;
		else {
			g_array_unref (order_arr);
			order_arr = NULL;
			g_set_error (error, NMCLI_ERROR, 0,
			             _("incorrect item '%s' in '--order' option"), *iter);
			break;
		}
		/* Check for duplicates and ignore them. */
		unique = TRUE;
		for (i = 0; i < order_arr->len; i++) {
			if (abs (g_array_index (order_arr, NmcSortOrder, i)) - abs (val) == 0) {
				unique = FALSE;
				break;
			}
		}

		/* Value is ok and unique, add it to the array */
		if (unique)
			g_array_append_val (order_arr, val);
	}

	return order_arr;
}

static NMConnection *
get_connection (NmCli *nmc,
                int *argc,
                char ***argv,
                const char **out_selector,
                const char **out_value,
                GPtrArray **out_result,
                GError **error)
{
	const GPtrArray *connections;
	NMConnection *connection = NULL;
	const char *selector = NULL;

	NM_SET_OUT (out_selector, NULL);
	NM_SET_OUT (out_value, NULL);

	if (*argc == 0) {
		g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		                     _("No connection specified"));
		return NULL;
	}

	if (*argc == 1 && nmc->complete)
		nmc_complete_strings (**argv, "id", "uuid", "path", "filename", NULL);

	if (NM_IN_STRSET (**argv, "id", "uuid", "path", "filename")) {
		if (*argc == 1) {
			if (!nmc->complete) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("%s argument is missing"), selector);
				return NULL;
			}
		} else {
			selector = **argv;
			(*argv)++;
			(*argc)--;
		}
	}

	NM_SET_OUT (out_selector, selector);
	NM_SET_OUT (out_value, **argv);

	connections = nm_client_get_connections (nmc->client);
	connection = nmc_find_connection (connections, selector, **argv, out_result,
	                                  *argc == 1 && nmc->complete);
	if (!connection) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_NOT_FOUND,
		             _("unknown connection '%s'"), **argv);
	}

	next_arg (nmc, argc, argv, NULL);
	return connection;
}

static NMCResultCode
do_connections_show (NmCli *nmc, int argc, char **argv)
{
	gs_free_error GError *err = NULL;
	gs_free char *profile_flds = NULL;
	gs_free char *active_flds = NULL;
	gboolean active_only = FALSE;
	gs_unref_array GArray *order = NULL;
	guint i;
	int option;

	/* check connection show options [--active] [--order <order spec>] */
	while ((option = next_arg (nmc, &argc, &argv, "--active", "--order", NULL)) > 0) {
		switch (option) {
		case 1: /* --active */
			active_only = TRUE;
			break;
		case 2: /* --order */
			argc--;
			argv++;
			if (!argc) {
				g_set_error_literal (&err, NMCLI_ERROR, 0,
				                     _("'--order' argument is missing"));
				goto finish;
			}
			order = parse_preferred_connection_order (*argv, &err);
			if (err)
				goto finish;
			break;
		default:
			g_assert_not_reached();
			break;
		}
	}

	if (argc == 0) {
		const char *fields_str = NULL;
		gs_unref_ptrarray GPtrArray *items = NULL;
		gs_free NMMetaSelectionResultList *selection = NULL;
		gboolean show_active_fields = TRUE;

		if (nmc->complete)
			goto finish;

		if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
			fields_str = NMC_FIELDS_CON_SHOW_COMMON;
		else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0) {
		} else
			fields_str = nmc->required_fields;

		/* determine whether the user wants to see any fields that are related to active-connections
		 * (e.g. the apath, the current state, or the device where the profile is active).
		 *
		 * If that's the case, then we will show one line for each active connection. In case
		 * a profile has multiple active connections, it will be listed multiple times.
		 * If that's not the case, we filter out these duplicate lines. */
		selection = nm_meta_selection_create_parse_list ((const NMMetaAbstractInfo *const*) metagen_con_show,
		                                                 fields_str,
		                                                 FALSE,
		                                                 NULL);
		if (selection && selection->num > 0) {
			show_active_fields = FALSE;
			for (i = 0; i < selection->num; i++) {
				const NmcMetaGenericInfo *info = (const NmcMetaGenericInfo *) selection->items[i].info;

				if (NM_IN_SET (info->info_type, NMC_GENERIC_INFO_TYPE_CON_SHOW_DEVICE,
				                                NMC_GENERIC_INFO_TYPE_CON_SHOW_STATE,
				                                NMC_GENERIC_INFO_TYPE_CON_SHOW_ACTIVE_PATH)) {
					show_active_fields = TRUE;
					break;
				}
			}
		}

		nm_cli_spawn_pager (nmc);

		items = con_show_get_items (nmc, active_only, show_active_fields, order);
		g_ptr_array_add (items, NULL);
		if (!nmc_print (&nmc->nmc_config,
		                items->pdata,
		                NULL,
		                active_only
		                  ? _("NetworkManager active profiles")
		                  : _("NetworkManager connection profiles"),
		                (const NMMetaAbstractInfo *const*) metagen_con_show,
		                fields_str,
		                &err))
			goto finish;
	} else {
		gboolean new_line = FALSE;
		gboolean without_fields = (nmc->required_fields == NULL);
		const GPtrArray *active_cons = nm_client_get_active_connections (nmc->client);

		/* multiline mode is default for 'connection show <ID>' */
		if (!nmc->mode_specified)
			nmc->nmc_config_mutable.multiline_output = TRUE;

		/* Split required fields into the settings and active ones. */
		if (!split_required_fields_for_con_show (nmc->required_fields, &profile_flds, &active_flds, &err))
			goto finish;

		nm_clear_g_free (&nmc->required_fields);

		/* Before printing the connections check if we have a "--show-secret"
		 * option after the connection ids */
		if (!nmc->nmc_config.show_secrets && !nmc->complete) {
			int argc_cp = argc;
			char **argv_cp = argv;

			do {
				if (NM_IN_STRSET (*argv_cp, "id", "uuid", "path", "filename", "apath")) {
					argc_cp--;
					argv_cp++;
				}
			} while (next_arg (nmc, &argc_cp, &argv_cp, NULL) != -1);
		}

		while (argc > 0) {
			const GPtrArray *connections;
			gboolean res;
			NMConnection *con;
			gs_unref_object NMActiveConnection *explicit_acon = NULL;
			const char *selector = NULL;
			gs_unref_ptrarray GPtrArray *found_cons = NULL;
			gboolean explicit_acon_handled = FALSE;
			guint i_found_cons;

			if (argc == 1 && nmc->complete)
				nmc_complete_strings (*argv, "id", "uuid", "path", "filename", "apath", NULL);

			if (NM_IN_STRSET (*argv, "id", "uuid", "path", "filename", "apath")) {
				selector = *argv;
				argc--;
				argv++;
				if (!argc) {
					g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					goto finish;
				}
			}

			/* Try to find connection by id, uuid or path first */
			connections = nm_client_get_connections (nmc->client);
			con = nmc_find_connection (connections, selector, *argv, &found_cons,
			                           argc == 1 && nmc->complete);
			if (   !con
			    && NM_IN_STRSET (selector, NULL, "apath")) {
				/* Try apath too */
				explicit_acon = nmc_find_active_connection (active_cons, "apath", *argv, NULL,
				                                            argc == 1 && nmc->complete);
				if (explicit_acon) {
					if (   !selector
					    && !nm_streq0 (*argv, nm_object_get_path (NM_OBJECT (explicit_acon)))) {
						/* we matched the apath based on the last component alone (note the full D-Bus path).
						 * That is how nmc_find_active_connection() works, if you pass in a selector.
						 * Reject it. */
						explicit_acon = NULL;
					}
					nm_g_object_ref (explicit_acon);
				}
			}

			if (!con && !explicit_acon) {
				g_string_printf (nmc->return_text, _("Error: %s - no such connection profile."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
				goto finish;
			}

			/* Print connection details:
			 * Usually we have both static and active connection.
			 * But when a connection is private to a user, another user
			 * may see only the active connection.
			 */

			if (nmc->complete) {
				next_arg (nmc, &argc, &argv, NULL);
				continue;
			}

			explicit_acon_handled = FALSE;
			i_found_cons = 0;
			for (;;) {
				gs_unref_ptrarray GPtrArray *found_acons = NULL;

				if (explicit_acon) {
					if (explicit_acon_handled)
						break;
					explicit_acon_handled = TRUE;
					/* the user referenced an "apath". In this case, we can only have at most one connection
					 * and one apath. */
					con = NM_CONNECTION (nm_active_connection_get_connection (explicit_acon));
				} else {
					if (i_found_cons >= found_cons->len)
						break;
					con = found_cons->pdata[i_found_cons++];
					get_ac_for_connection (active_cons, con, &found_acons);
				}

				if (active_only && !explicit_acon && !found_acons) {
					/* this connection is not interesting, we only print active ones. */
					continue;
				}

				nm_assert (explicit_acon || con);

				if (new_line)
					g_print ("\n");
				new_line = TRUE;

				if (without_fields || profile_flds) {
					if (con) {
						nmc->required_fields = profile_flds;
						if (nmc->nmc_config.show_secrets)
							update_secrets_in_connection (NM_REMOTE_CONNECTION (con), con);
						res = nmc_connection_profile_details (con, nmc);
						nmc->required_fields = NULL;
						if (!res)
							goto finish;
					}
				}

				if (without_fields || active_flds) {
					guint l = explicit_acon ? 1 : (found_acons ? found_acons->len : 0);

					for (i = 0; i < l; i++) {
						NMActiveConnection *acon;

						if (i > 0) {
							/* if there are multiple active connections, separate them with newline.
							 * that is a bit odd, because we already separate connections with newlines,
							 * and commonly don't separate the connection from the first active connection. */
							g_print ("\n");
						}

						if (explicit_acon)
							acon = explicit_acon;
						else
							acon = found_acons->pdata[i];

						nmc->required_fields = active_flds;
						res = nmc_active_connection_details (acon, nmc);
						nmc->required_fields = NULL;
						if (!res)
							goto finish;
					}
				}
			}

			next_arg (nmc, &argc, &argv, NULL);
		}
	}

finish:
	if (err) {
		g_string_printf (nmc->return_text, _("Error: %s."), err->message);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
	}
	return nmc->return_value;
}

static NMActiveConnection *
get_default_active_connection (NmCli *nmc, NMDevice **device)
{
	NMActiveConnection *default_ac = NULL;
	NMDevice *non_default_device = NULL;
	NMActiveConnection *non_default_ac = NULL;
	const GPtrArray *connections;
	int i;

	g_return_val_if_fail (nmc, NULL);
	g_return_val_if_fail (device, NULL);
	g_return_val_if_fail (*device == NULL, NULL);

	connections = nm_client_get_active_connections (nmc->client);
	for (i = 0; i < connections->len; i++) {
		NMActiveConnection *candidate = g_ptr_array_index (connections, i);
		const GPtrArray *devices;

		devices = nm_active_connection_get_devices (candidate);
		if (!devices->len)
			continue;

		if (nm_active_connection_get_default (candidate)) {
			if (!default_ac) {
				*device = g_ptr_array_index (devices, 0);
				default_ac = candidate;
			}
		} else {
			if (!non_default_ac) {
				non_default_device = g_ptr_array_index (devices, 0);
				non_default_ac = candidate;
			}
		}
	}

	/* Prefer the default connection if one exists, otherwise return the first
	 * non-default connection.
	 */
	if (!default_ac && non_default_ac) {
		default_ac = non_default_ac;
		*device = non_default_device;
	}
	return default_ac;
}

/* Find a device to activate the connection on.
 * IN:  connection:  connection to activate
 *      iface:       device interface name to use (optional)
 *      ap:          access point to use (optional; valid just for 802-11-wireless)
 *      nsp:         Network Service Provider to use (option; valid only for wimax)
 * OUT: device:      found device
 *      spec_object: specific_object path of NMAccessPoint
 * RETURNS: TRUE when a device is found, FALSE otherwise.
 */
static gboolean
find_device_for_connection (NmCli *nmc,
                            NMConnection *connection,
                            const char *iface,
                            const char *ap,
                            const char *nsp,
                            NMDevice **device,
                            const char **spec_object,
                            GError **error)
{
	NMSettingConnection *s_con;
	const char *con_type;
	int i, j;

	g_return_val_if_fail (nmc, FALSE);
	g_return_val_if_fail (iface || ap || nsp, FALSE);
	g_return_val_if_fail (device && *device == NULL, FALSE);
	g_return_val_if_fail (spec_object && *spec_object == NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	con_type = nm_setting_connection_get_connection_type (s_con);

	if (strcmp (con_type, NM_SETTING_VPN_SETTING_NAME) == 0) {
		/* VPN connections */
		NMActiveConnection *active = NULL;
		if (iface) {
			*device = nm_client_get_device_by_iface (nmc->client, iface);
			if (*device)
				active = nm_device_get_active_connection (*device);

			if (!active) {
				g_set_error (error, NMCLI_ERROR, 0, _("no active connection on device '%s'"), iface);
				return FALSE;
			}
			*spec_object = nm_object_get_path (NM_OBJECT (active));
			return TRUE;
		} else {
			active = get_default_active_connection (nmc, device);
			if (!active) {
				g_set_error_literal (error, NMCLI_ERROR, 0, _("no active connection or device"));
				return FALSE;
			}
			*spec_object = nm_object_get_path (NM_OBJECT (active));
			return TRUE;
		}
	} else {
		/* Other connections */
		NMDevice *found_device = NULL;
		const GPtrArray *devices = nm_client_get_devices (nmc->client);

		for (i = 0; i < devices->len && !found_device; i++) {
			NMDevice *dev = g_ptr_array_index (devices, i);

			if (iface) {
				const char *dev_iface = nm_device_get_iface (dev);
				if (!nm_streq0 (dev_iface, iface))
					continue;

				if (!nm_device_connection_compatible (dev, connection, error)) {
					g_prefix_error (error, _("device '%s' not compatible with connection '%s': "),
					                iface, nm_setting_connection_get_id (s_con));
					return FALSE;
				}

			} else {
				if (!nm_device_connection_compatible (dev, connection, NULL))
					continue;
			}

			found_device = dev;
			if (   ap
			    && nm_streq (con_type, NM_SETTING_WIRELESS_SETTING_NAME)
			    && NM_IS_DEVICE_WIFI (dev)) {
				gs_free char *bssid_up = g_ascii_strup (ap, -1);
				const GPtrArray *aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (dev));
				found_device = NULL;  /* Mark as not found; set to the device again later, only if AP matches */

				for (j = 0; j < aps->len; j++) {
					NMAccessPoint *candidate_ap = g_ptr_array_index (aps, j);
					const char *candidate_bssid = nm_access_point_get_bssid (candidate_ap);

					if (nm_streq0 (bssid_up, candidate_bssid)) {
						found_device = dev;
						*spec_object = nm_object_get_path (NM_OBJECT (candidate_ap));
						break;
					}
				}
			}
		}

		if (!found_device) {
			if (iface) {
				g_set_error (error, NMCLI_ERROR, 0, _("device '%s' not compatible with connection '%s'"),
				             iface, nm_setting_connection_get_id (s_con));
			} else {
				g_set_error (error, NMCLI_ERROR, 0, _("no device found for connection '%s'"),
				             nm_setting_connection_get_id (s_con));
			}
			return FALSE;
		}

		*device = found_device;
		return TRUE;
	}
}

typedef struct {
	NmCli *nmc;
	NMDevice *device;
	NMActiveConnection *active;
} ActivateConnectionInfo;

static void
active_connection_hint (GString *return_text,
                        NMActiveConnection *active,
                        NMDevice *device)
{
	NMRemoteConnection *connection;
	nm_auto_free_gstring GString *hint = NULL;
	const GPtrArray *devices;
	guint i;

	if (!active)
		return;

	if (!nm_streq (NM_CONFIG_DEFAULT_LOGGING_BACKEND, "journal"))
		return;

	connection = nm_active_connection_get_connection (active);
	g_return_if_fail (connection);

	hint = g_string_new ("journalctl -xe ");
	g_string_append_printf (hint, "NM_CONNECTION=%s",
	                        nm_connection_get_uuid (NM_CONNECTION (connection)));

	if (device)
		g_string_append_printf (hint, " + NM_DEVICE=%s", nm_device_get_iface (device));
	else {
		devices = nm_active_connection_get_devices (active);
		for (i = 0; i < devices->len; i++) {
			g_string_append_printf (hint, " + NM_DEVICE=%s",
			                        nm_device_get_iface (NM_DEVICE (g_ptr_array_index (devices, i))));
		}
	}

	g_string_append (return_text, "\n");
	g_string_append_printf (return_text, _("Hint: use '%s' to get more details."), hint->str);
}

static void activate_connection_info_finish (ActivateConnectionInfo *info);

static void
check_activated (ActivateConnectionInfo *info)
{
	NMActiveConnectionState ac_state;
	NmCli *nmc = info->nmc;
	const char *reason = NULL;

	ac_state = nmc_activation_get_effective_state (info->active, info->device, &reason);
	switch (ac_state) {
	case NM_ACTIVE_CONNECTION_STATE_ACTIVATED:
		if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY)
			nmc_terminal_erase_line ();
		if (reason) {
			g_print (_("Connection successfully activated (%s) (D-Bus active path: %s)\n"),
			         reason,
			         nm_object_get_path (NM_OBJECT (info->active)));
		} else {
			g_print (_("Connection successfully activated (D-Bus active path: %s)\n"),
			         nm_object_get_path (NM_OBJECT (info->active)));
		}
		activate_connection_info_finish (info);
		break;
	case NM_ACTIVE_CONNECTION_STATE_DEACTIVATED:
		nm_assert (reason);
		g_string_printf (nmc->return_text, _("Error: Connection activation failed: %s"),
		                 reason);
		active_connection_hint (nmc->return_text, info->active, info->device);
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		activate_connection_info_finish (info);
		break;
	case NM_ACTIVE_CONNECTION_STATE_ACTIVATING:
		if (nmc->secret_agent) {
			NMRemoteConnection *connection = nm_active_connection_get_connection (info->active);

			nm_secret_agent_simple_enable (nmc->secret_agent,
			                               nm_connection_get_path (NM_CONNECTION (connection)));
		}
		break;
	default:
		break;
	}
}

static void
device_state_cb (NMDevice *device, GParamSpec *pspec, ActivateConnectionInfo *info)
{
	check_activated (info);
}

static void
active_connection_state_cb (NMActiveConnection *active,
                            NMActiveConnectionState state,
                            NMActiveConnectionStateReason reason,
                            ActivateConnectionInfo *info)
{
	check_activated (info);
}

static void
set_nmc_error_timeout (NmCli *nmc)
{
	g_string_printf (nmc->return_text, _("Error: Timeout expired (%d seconds)"), nmc->timeout);
	nmc->return_value = NMC_RESULT_ERROR_TIMEOUT_EXPIRED;
}

static gboolean
activate_connection_timeout_cb (gpointer user_data)
{
	ActivateConnectionInfo *info = user_data;

	/* Time expired -> exit nmcli */
	set_nmc_error_timeout (info->nmc);
	activate_connection_info_finish (info);
	return FALSE;
}

static gboolean
progress_cb (gpointer user_data)
{
	const char *str = (const char *) user_data;

	nmc_terminal_show_progress (str);

	return TRUE;
}

static gboolean
progress_active_connection_cb (gpointer user_data)
{
	NMActiveConnection *active = user_data;
	const char *str;
	NMDevice *device;
	NMActiveConnectionState ac_state;
	const GPtrArray *ac_devs;

	ac_state = nm_active_connection_get_state (active);

	if (ac_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATING) {
		/* If the connection is activating, the device state
		 * is more interesting. */
		ac_devs = nm_active_connection_get_devices (active);
		device = ac_devs->len > 0 ? g_ptr_array_index (ac_devs, 0) : NULL;
	} else {
		device = NULL;
	}

	str =   device
	      ? gettext (nmc_device_state_to_string (nm_device_get_state (device)))
	      : active_connection_state_to_string (ac_state);

	nmc_terminal_show_progress (str);

	return TRUE;
}

static void
activate_connection_info_finish (ActivateConnectionInfo *info)
{
	if (info->device) {
		g_signal_handlers_disconnect_by_func (info->device, G_CALLBACK (device_state_cb), info);
		g_object_unref (info->device);
	}

	if (info->active) {
		g_signal_handlers_disconnect_by_func (info->active, G_CALLBACK (active_connection_state_cb), info);
		g_object_unref (info->active);
	}

	g_free (info);
	quit ();
}

static void
activate_connection_cb (GObject *client, GAsyncResult *result, gpointer user_data)
{
	ActivateConnectionInfo *info = (ActivateConnectionInfo *) user_data;
	NmCli *nmc = info->nmc;
	NMDevice *device = info->device;
	NMActiveConnection *active;
	NMActiveConnectionState state;
	const GPtrArray *ac_devs;
	GError *error = NULL;

	info->active = active = nm_client_activate_connection_finish (NM_CLIENT (client), result, &error);

	if (error) {
		g_string_printf (nmc->return_text, _("Error: Connection activation failed: %s"),
		                 error->message);
		g_error_free (error);
		active_connection_hint (nmc->return_text, info->active, info->device);
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		activate_connection_info_finish (info);
	} else {
		state = nm_active_connection_get_state (active);
		if (!device && !nm_active_connection_get_vpn (active)) {
			/* device could be NULL for virtual devices. Fill it here. */
			ac_devs = nm_active_connection_get_devices (active);
			device = ac_devs->len > 0 ? g_ptr_array_index (ac_devs, 0) : NULL;
			if (device)
				info->device = g_object_ref (device);
		}

		if (nmc->nowait_flag || state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
			/* User doesn't want to wait or already activated */
			if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
				if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY)
					nmc_terminal_erase_line ();
				g_print (_("Connection successfully activated (D-Bus active path: %s)\n"),
				         nm_object_get_path (NM_OBJECT (active)));
			}
			activate_connection_info_finish (info);
		} else {
			/* Monitor the active connection and device (if available) states */
			g_signal_connect (active, "state-changed", G_CALLBACK (active_connection_state_cb), info);
			if (device)
				g_signal_connect (device, "notify::" NM_DEVICE_STATE, G_CALLBACK (device_state_cb), info);
			/* Both active_connection_state_cb () and device_state_cb () will just
			 * call check_activated (info). So, just call it once directly after
			 * connecting on both the signals of the objects and skip the call to
			 * the callbacks.
			 */
			check_activated (info);

			/* Start progress indication showing VPN states */
			if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY) {
				if (progress_id)
					g_source_remove (progress_id);
				progress_id = g_timeout_add (120, progress_active_connection_cb, active);
			}

			/* Start timer not to loop forever when signals are not emitted */
			g_timeout_add_seconds (nmc->timeout, activate_connection_timeout_cb, info);
		}
	}
}

/**
 * parse_passwords:
 * @passwd_file: file with passwords to parse
 * @error: location to store error, or %NULL
 *
 * Parse passwords given in @passwd_file and insert them into a hash table.
 * Example of @passwd_file contents:
 *   wifi.psk:tajne heslo
 *   802-1x.password:krakonos
 *   802-11-wireless-security:leap-password:my leap password
 *
 * Returns: hash table with parsed passwords, or %NULL on an error
 */
static GHashTable *
parse_passwords (const char *passwd_file, GError **error)
{
	gs_unref_hashtable GHashTable *pwds_hash = NULL;
	gs_free char *contents = NULL;
	gsize len = 0;
	GError *local_err = NULL;
	gs_free const char **strv = NULL;
	const char *const*iter;
	char *pwd_spec, *pwd, *prop;
	const char *setting;

	pwds_hash = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_free);

	if (!passwd_file)
		return g_steal_pointer (&pwds_hash);

	/* Read the passwords file */
	if (!g_file_get_contents (passwd_file, &contents, &len, &local_err)) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("failed to read passwd-file '%s': %s"),
		             passwd_file, local_err->message);
		g_error_free (local_err);
		return NULL;
	}

	strv = nm_utils_strsplit_set (contents, "\r\n");
	for (iter = strv; *iter; iter++) {
		gs_free char *iter_s = g_strdup (*iter);

		pwd = strchr (iter_s, ':');
		if (!pwd) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("missing colon in 'password' entry '%s'"), *iter);
			return NULL;
		}
		*(pwd++) = '\0';

		prop = strchr (iter_s, '.');
		if (!prop) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("missing dot in 'password' entry '%s'"), *iter);
			return NULL;
		}
		*(prop++) = '\0';

		setting = iter_s;
		while (g_ascii_isspace (*setting))
			setting++;
		/* Accept wifi-sec or wifi instead of cumbersome '802-11-wireless-security' */
		if (!strcmp (setting, "wifi-sec") || !strcmp (setting, "wifi"))
			setting = NM_SETTING_WIRELESS_SECURITY_SETTING_NAME;
		if (nm_setting_lookup_type (setting) == G_TYPE_INVALID) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("invalid setting name in 'password' entry '%s'"), setting);
			return NULL;
		}

		if (   nm_streq (setting, "vpn")
		    && g_str_has_prefix (prop, "secret.")) {
			/* in 1.12.0, we wrongly required the VPN secrets to be named
			 * "vpn.secret". It should be "vpn.secrets". Work around it
			 * (rh#1628833). */
			pwd_spec = g_strdup_printf ("vpn.secrets.%s", &prop[NM_STRLEN ("secret.")]);
		} else
			pwd_spec = g_strdup_printf ("%s.%s", setting, prop);

		g_hash_table_insert (pwds_hash, pwd_spec, g_strdup (pwd));
	}
	return g_steal_pointer (&pwds_hash);
}

static gboolean
nmc_activate_connection (NmCli *nmc,
                         NMConnection *connection,
                         const char *ifname,
                         const char *ap,
                         const char *nsp,
                         const char *pwds,
                         GAsyncReadyCallback callback,
                         GError **error)
{
	ActivateConnectionInfo *info;

	GHashTable *pwds_hash;
	NMDevice *device = NULL;
	const char *spec_object = NULL;
	gboolean device_found;
	GError *local = NULL;

	g_return_val_if_fail (nmc, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (connection && (ifname || ap || nsp)) {
		device_found = find_device_for_connection (nmc, connection, ifname, ap, nsp, &device, &spec_object, &local);

		/* Virtual connection may not have their interfaces created yet */
		if (!device_found && !nm_connection_is_virtual (connection)) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_CON_ACTIVATION,
			             "%s", local->message);
			g_clear_error (&local);
			return FALSE;
		}
		g_clear_error (&local);
	} else if (ifname) {
		device = nm_client_get_device_by_iface (nmc->client, ifname);
		if (!device) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_NOT_FOUND,
			             _("unknown device '%s'."), ifname);
			return FALSE;
		}
	} else if (!connection) {
		g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_NOT_FOUND,
		                     _("neither a valid connection nor device given"));
		return FALSE;
	}

	/* Parse passwords given in passwords file */
	pwds_hash = parse_passwords (pwds, &local);
	if (local) {
		g_propagate_error (error, local);
		return FALSE;
	}
	if (nmc->pwds_hash)
		g_hash_table_destroy (nmc->pwds_hash);
	nmc->pwds_hash = pwds_hash;

	nmc->secret_agent = nm_secret_agent_simple_new ("nmcli-connect");
	if (nmc->secret_agent) {
		g_signal_connect (nmc->secret_agent,
		                  NM_SECRET_AGENT_SIMPLE_REQUEST_SECRETS,
		                  G_CALLBACK (nmc_secrets_requested),
		                  nmc);
	}

	info = g_malloc0 (sizeof (ActivateConnectionInfo));
	info->nmc = nmc;
	if (device)
		info->device = g_object_ref (device);

	nm_client_activate_connection_async (nmc->client,
	                                     connection,
	                                     device,
	                                     spec_object,
	                                     NULL,
	                                     callback,
	                                     info);
	return TRUE;
}

static NMCResultCode
do_connection_up (NmCli *nmc, int argc, char **argv)
{
	NMConnection *connection = NULL;
	const char *ifname = NULL;
	const char *ap = NULL;
	const char *nsp = NULL;
	const char *pwds = NULL;
	gs_free_error GError *error = NULL;
	char **arg_arr = NULL;
	int arg_num;
	char ***argv_ptr;
	int *argc_ptr;

	/*
	 * Set default timeout for connection activation.
	 * Activation can take quite a long time, use 90 seconds.
	 */
	if (nmc->timeout == -1)
		nmc->timeout = 90;

	next_arg (nmc, &argc, &argv, NULL);
	argv_ptr = &argv;
	argc_ptr = &argc;

	if (argc == 0 && nmc->ask) {
		gs_free char *line = NULL;

		/* nmc_do_cmd() should not call this with argc=0. */
		g_assert (!nmc->complete);

		line = nmc_readline (&nmc->nmc_config,
		                     PROMPT_CONNECTION);
		nmc_string_to_arg_array (line, NULL, TRUE, &arg_arr, &arg_num);
		argv_ptr = &arg_arr;
		argc_ptr = &arg_num;
	}

	if (argc > 0 && strcmp (*argv, "ifname") != 0) {
		connection = get_connection (nmc, argc_ptr, argv_ptr, NULL, NULL, NULL, &error);
		if (!connection) {
			g_string_printf (nmc->return_text, _("Error: %s."), error->message);
			return error->code;
		}
	}

	while (argc > 0) {
		if (argc == 1 && nmc->complete)
			nmc_complete_strings (*argv, "ifname", "ap", "passwd-file", NULL);

		if (strcmp (*argv, "ifname") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}

			ifname = *argv;
			if (argc == 1 && nmc->complete)
				nmc_complete_device (nmc->client, ifname, ap != NULL);
		}
		else if (strcmp (*argv, "ap") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}

			ap = *argv;
			if (argc == 1 && nmc->complete)
				nmc_complete_bssid (nmc->client, ifname, ap);
		}
		else if (strcmp (*argv, "passwd-file") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}

			if (argc == 1 && nmc->complete)
				nmc->return_value = NMC_RESULT_COMPLETE_FILE;

			pwds = *argv;
		}
		else if (!nmc->complete) {
			g_printerr (_("Unknown parameter: %s\n"), *argv);
		}

		next_arg (nmc, &argc, &argv, NULL);
	}

	if (nmc->complete)
		return nmc->return_value;

	/* Use nowait_flag instead of should_wait because exiting has to be postponed till
	 * active_connection_state_cb() is called. That gives NM time to check our permissions
	 * and we can follow activation progress.
	 */
	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait++;

	if (!nmc_activate_connection (nmc, connection, ifname, ap, nsp, pwds, activate_connection_cb, &error)) {
		g_string_printf (nmc->return_text, _("Error: %s."),
		                 error->message);
		nmc->should_wait--;
		return error->code;
	}

	/* Start progress indication */
	if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY)
		progress_id = g_timeout_add (120, progress_cb, _("preparing"));

	return nmc->return_value;
}

/*****************************************************************************/

typedef struct {
	NmCli *nmc;
	/* a list of object that is relevant for the callback. The object
	 * type differs, and depends on the type of callback. */
	GPtrArray *obj_list;
	guint timeout_id;
	GCancellable *cancellable;
} ConnectionCbInfo;

static void connection_removed_cb (NMClient *client, NMConnection *connection, ConnectionCbInfo *info);

static void down_active_connection_state_cb (NMActiveConnection *active,
                                             GParamSpec *pspec,
                                             ConnectionCbInfo *info);

static void
connection_cb_info_obj_list_destroy (ConnectionCbInfo *info, gpointer obj)
{
	nm_assert (info);
	nm_assert (info->obj_list);
	nm_assert (G_IS_OBJECT (obj));

	g_signal_handlers_disconnect_by_func (obj, down_active_connection_state_cb, info);
	g_object_unref (obj);
}

static gssize
connection_cb_info_obj_list_idx (ConnectionCbInfo *info, gpointer obj)
{
	guint i;

	nm_assert (info);
	nm_assert (info->obj_list);
	nm_assert (G_IS_OBJECT (obj));

	for (i = 0; i < info->obj_list->len; i++) {
		if (info->obj_list->pdata[i] == obj)
			return i;
	}
	return -1;
}

static gpointer
connection_cb_info_obj_list_has (ConnectionCbInfo *info, gpointer obj)
{
	gssize idx;

	idx = connection_cb_info_obj_list_idx (info, obj);
	if (idx >= 0)
		return info->obj_list->pdata[idx];
	return NULL;
}

static gpointer
connection_cb_info_obj_list_steal (ConnectionCbInfo *info, gpointer obj)
{
	gssize idx;

	idx = connection_cb_info_obj_list_idx (info, obj);
	if (idx >= 0) {
		g_ptr_array_remove_index (info->obj_list, idx);
		return obj;
	}
	return NULL;
}

static void
connection_cb_info_finish (ConnectionCbInfo *info, gpointer obj)
{
	if (obj) {
		obj = connection_cb_info_obj_list_steal (info, obj);
		if (obj)
			connection_cb_info_obj_list_destroy (info, obj);
	} else {
		while (info->obj_list->len > 0) {
			obj = info->obj_list->pdata[info->obj_list->len - 1];
			g_ptr_array_remove_index (info->obj_list, info->obj_list->len - 1);
			connection_cb_info_obj_list_destroy (info, obj);
		}
	}

	if (info->obj_list->len > 0)
		return;

	nm_clear_g_source (&info->timeout_id);
	nm_clear_g_cancellable (&info->cancellable);
	g_ptr_array_free (info->obj_list, TRUE);

	g_signal_handlers_disconnect_by_func (info->nmc->client, connection_removed_cb, info);

	g_slice_free (ConnectionCbInfo, info);

	quit ();
}

/*****************************************************************************/

static void
connection_removed_cb (NMClient *client, NMConnection *connection, ConnectionCbInfo *info)
{
	if (!connection_cb_info_obj_list_has (info, connection))
		return;
	g_print (_("Connection '%s' (%s) successfully deleted.\n"),
	         nm_connection_get_id (connection),
	         nm_connection_get_uuid (connection));
	connection_cb_info_finish (info, connection);
}

static void
down_active_connection_state_cb (NMActiveConnection *active,
                                 GParamSpec *pspec,
                                 ConnectionCbInfo *info)
{
	if (nm_active_connection_get_state (active) < NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
		return;

	if (info->nmc->nmc_config.print_output == NMC_PRINT_PRETTY)
		nmc_terminal_erase_line ();
	g_print (_("Connection '%s' successfully deactivated (D-Bus active path: %s)\n"),
	         nm_active_connection_get_id (active), nm_object_get_path (NM_OBJECT (active)));

	g_signal_handlers_disconnect_by_func (G_OBJECT (active),
	                                      down_active_connection_state_cb,
	                                      info);
	connection_cb_info_finish (info, active);
}

static gboolean
connection_op_timeout_cb (gpointer user_data)
{
	ConnectionCbInfo *info = user_data;

	set_nmc_error_timeout (info->nmc);
	connection_cb_info_finish (info, NULL);
	return G_SOURCE_REMOVE;
}

static NMCResultCode
do_connection_down (NmCli *nmc, int argc, char **argv)
{
	NMActiveConnection *active;
	ConnectionCbInfo *info = NULL;
	const GPtrArray *active_cons;
	gs_strfreev char **arg_arr = NULL;
	char **arg_ptr;
	int arg_num;
	guint i;
	gs_unref_ptrarray GPtrArray *found_active_cons = NULL;

	if (nmc->timeout == -1)
		nmc->timeout = 10;

	next_arg (nmc, &argc, &argv, NULL);
	arg_ptr = argv;
	arg_num = argc;

	if (argc == 0) {
		/* nmc_do_cmd() should not call this with argc=0. */
		g_assert (!nmc->complete);

		if (nmc->ask) {
			gs_free char *line = NULL;

			line = nmc_readline (&nmc->nmc_config,
			                     PROMPT_ACTIVE_CONNECTIONS);
			nmc_string_to_arg_array (line, NULL, TRUE, &arg_arr, &arg_num);
			arg_ptr = arg_arr;
		}
		if (arg_num == 0) {
			g_string_printf (nmc->return_text, _("Error: No connection specified."));
			NMC_RETURN (nmc, NMC_RESULT_ERROR_USER_INPUT);
		}
	}

	/* Get active connections */
	active_cons = nm_client_get_active_connections (nmc->client);
	while (arg_num > 0) {
		const char *selector = NULL;

		if (arg_num == 1 && nmc->complete)
			nmc_complete_strings (*arg_ptr, "id", "uuid", "path",  "filename", "apath", NULL);

		if (NM_IN_STRSET (*arg_ptr, "id", "uuid", "path",  "filename", "apath")) {
			selector = *arg_ptr;
			arg_num--;
			arg_ptr++;
			if (!arg_num) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), selector);
				NMC_RETURN (nmc, NMC_RESULT_ERROR_USER_INPUT);
			}
		}

		active = nmc_find_active_connection (active_cons,
		                                     selector,
		                                     *arg_ptr,
		                                     &found_active_cons,
		                                     arg_num == 1 && nmc->complete);
		if (!active) {
			if (!nmc->complete)
				g_printerr (_("Error: '%s' is not an active connection.\n"), *arg_ptr);
			g_string_printf (nmc->return_text, _("Error: not all active connections found."));
			nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
		}

		next_arg (nmc->ask ? NULL : nmc, &arg_num, &arg_ptr, NULL);
	}

	if (!found_active_cons) {
		g_string_printf (nmc->return_text, _("Error: no active connection provided."));
		NMC_RETURN (nmc, NMC_RESULT_ERROR_NOT_FOUND);
	}
	nm_assert (found_active_cons->len > 0);

	if (nmc->complete)
		return nmc->return_value;

	if (nmc->timeout > 0) {
		nmc->should_wait++;

		info = g_slice_new0 (ConnectionCbInfo);
		info->nmc = nmc;
		info->obj_list = g_ptr_array_sized_new (found_active_cons->len);
		for (i = 0; i < found_active_cons->len; i++) {
			active = found_active_cons->pdata[i];
			g_ptr_array_add (info->obj_list, g_object_ref (active));
			g_signal_connect (active,
			                  "notify::" NM_ACTIVE_CONNECTION_STATE,
			                  G_CALLBACK (down_active_connection_state_cb),
			                  info);
		}
		info->timeout_id = g_timeout_add_seconds (nmc->timeout, connection_op_timeout_cb, info);
	}

	for (i = 0; i < found_active_cons->len; i++) {
		GError *error = NULL;

		active = found_active_cons->pdata[i];

		if (!nm_client_deactivate_connection (nmc->client, active, NULL, &error)) {
			g_print (_("Connection '%s' deactivation failed: %s\n"),
			         nm_active_connection_get_id (active), error->message);
			g_clear_error (&error);

			if (info) {
				g_signal_handlers_disconnect_by_func (active,
				                                      down_active_connection_state_cb,
				                                      info);
				connection_cb_info_finish (info, active);
			}
		}
	}

	return nmc->return_value;
}

/*****************************************************************************/

/*
 * Return the most appropriate name for the connection of a type 'name' possibly with given 'slave_type'
 * if exists, else return the 'name'. The returned string must not be freed.
 */
static const char *
get_name_alias_toplevel (const char *name, const char *slave_type)
{
	const NMMetaSettingInfoEditor *setting_info;

	if (slave_type) {
		const char *slave_name;

		if (nm_meta_setting_info_valid_parts_for_slave_type (slave_type, &slave_name))
			return slave_name ?: name;
		return name;
	}

	setting_info = nm_meta_setting_info_editor_find_by_name (name, FALSE);
	if (setting_info)
		return setting_info->alias ?: setting_info->general->setting_name;

	return name;
}

/*
 * Construct a string with names and aliases from the arrays formatted as:
 * "name (alias), name, name (alias), name, name"
 *
 * Returns: string; the caller is responsible for freeing it.
 */
static char *
get_valid_options_string (const NMMetaSettingValidPartItem *const*array, const NMMetaSettingValidPartItem *const*array_slv)
{
	const NMMetaSettingValidPartItem *const*iter = array;
	GString *str;
	int i;

	str = g_string_sized_new (150);

	for (i = 0; i < 2; i++, iter = array_slv) {
		for (; iter && *iter; iter++) {
			const NMMetaSettingInfoEditor *setting_info = (*iter)->setting_info;

			if (str->len)
				g_string_append (str, ", ");
			if (setting_info->alias)
				g_string_append_printf (str, "%s (%s)", setting_info->general->setting_name, setting_info->alias);
			else
				g_string_append (str, setting_info->general->setting_name);
		}
	}
	return g_string_free (str, FALSE);
}

static char *
get_valid_options_string_toplevel (void)
{
	GString *str;
	int i;

	str = g_string_sized_new (150);
	for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++) {
		const NMMetaSettingInfoEditor *setting_info = &nm_meta_setting_infos_editor[i];

		if (!setting_info->valid_parts)
			continue;

		if (str->len)
			g_string_append (str, ", ");
		if (setting_info->alias)
			g_string_append_printf (str, "%s (%s)", setting_info->general->setting_name, setting_info->alias);
		else
			g_string_append (str, setting_info->general->setting_name);
	}

	if (str->len)
		g_string_append (str, ", ");
	g_string_append (str, "bond-slave, bridge-slave, team-slave");

	return g_string_free (str, FALSE);
}

static const NMMetaSettingValidPartItem *const*
get_valid_settings_array (const char *con_type)
{
	const NMMetaSettingInfoEditor *setting_info;

	/* No connection type yet? Return settings for a generic connection
	 * (just the "connection" setting), which always makes sense. */
	if (!con_type)
		return nm_meta_setting_info_valid_parts_default;

	setting_info = nm_meta_setting_info_editor_find_by_name (con_type, FALSE);
	if (setting_info)
		return setting_info->valid_parts ?: NM_PTRARRAY_EMPTY (const NMMetaSettingValidPartItem *);
	return NULL;
}

/* get_valid_properties_string:
 * @array: base properties for the current connection type
 * @array_slv: slave properties (or ipv4/ipv6 ones) for the current connection type
 * @modifier: to prepend to each element of the returned list
 * @prefix: only properties matching the prefix will be returned
 * @postfix: required prefix on the property args; if a empty string is passed, is
 *           assumed that the @prefix is a shortcut, so it should not be completed
 *           but left as is (and an additional check for shortcut ambiguity is performed)
 *
 * Returns a list of properties compatible with the current connection type
 * for the shell autocompletion functionality.
 *
 * Returns: list of property.arg elements
 */
static char *
get_valid_properties_string (const NMMetaSettingValidPartItem *const*array,
                             const NMMetaSettingValidPartItem *const*array_slv,
                             char modifier,
                             const char *prefix,
                             const char *postfix)
{
	const NMMetaSettingValidPartItem *const*iter = array;
	const char *prop_name = NULL;
	GString *str;
	int i, j;
	gboolean full_match = FALSE;

	g_return_val_if_fail (prefix, NULL);

	str = g_string_sized_new (1024);

	for (i = 0; i < 2; i++, iter = array_slv) {
		for (; !full_match && iter && *iter; iter++) {
			const NMMetaSettingInfoEditor *setting_info = (*iter)->setting_info;

			if (   !(g_str_has_prefix (setting_info->general->setting_name, prefix))
			    && (   !setting_info->alias
			        || !g_str_has_prefix (setting_info->alias, prefix))) {
				continue;
			}

			/* If postix (so prefix is terminated by a dot), check
			 * that prefix is not ambiguous */
			if (postfix) {
				/* If we have a perfect match, no need to look for others
				 * prefix and no check on ambiguity should be performed.
				 * Moreover, erase previous matches from output string */
				if (   nm_streq (prefix, setting_info->general->setting_name)
				    || nm_streq0 (prefix, setting_info->alias)) {
					g_string_erase (str, 0, -1);
					full_match = TRUE;
				} else if (prop_name)
					return g_string_free (str, TRUE);
				prop_name = prefix;
			} else
				prop_name = setting_info->general->setting_name;

			/* Search the array with the arguments of the current property */
			for (j = 0; j < setting_info->properties_num; j++) {
				char *new;
				const char *arg_name;

				arg_name = setting_info->properties[j]->property_name;

				/* If required, expand the alias too */
				if (!postfix && setting_info->alias) {
					if (modifier)
						g_string_append_c (str, modifier);
					new = g_strdup_printf ("%s.%s\n",
					                       setting_info->alias,
					                       arg_name);
					g_string_append (str, new);
					g_free (new);
				}

				if (postfix && !g_str_has_prefix (arg_name, postfix))
					continue;

				if (modifier)
					g_string_append_c (str, modifier);
				new = g_strdup_printf ("%s.%s\n",
				                       prop_name,
				                       arg_name);
				g_string_append (str, new);
				g_free (new);
			}
		}
	}
	return g_string_free (str, FALSE);
}

/*
 * Check if 'val' is valid string in either array->name or array->alias for
 * both array parameters (array & array_slv).
 * It accepts shorter string provided they are not ambiguous.
 * 'val' == NULL doesn't hurt.
 *
 * Returns: pointer to array->name string or NULL on failure.
 * The returned string must not be freed.
 */
static const char *
check_valid_name (const char *val, const NMMetaSettingValidPartItem *const*array, const NMMetaSettingValidPartItem *const*array_slv, GError **error)
{
	const NMMetaSettingValidPartItem *const*iter;
	gs_unref_ptrarray GPtrArray *tmp_arr = NULL;
	const char *str;
	GError *tmp_err = NULL;
	int i;

	g_return_val_if_fail (array, NULL);

	/* Create a temporary array that can be used in nmc_string_is_valid() */
	tmp_arr = g_ptr_array_sized_new (32);
	iter = array;
	for (i = 0; i < 2; i++, iter = array_slv) {
		for (; iter && *iter; iter++) {
			const NMMetaSettingInfoEditor *setting_info = (*iter)->setting_info;

			g_ptr_array_add (tmp_arr, (gpointer) setting_info->general->setting_name);
			if (setting_info->alias)
				g_ptr_array_add (tmp_arr, (gpointer) setting_info->alias);
		}
	}
	g_ptr_array_add (tmp_arr, (gpointer) NULL);

	/* Check string validity */
	str = nmc_string_is_valid (val, (const char **) tmp_arr->pdata, &tmp_err);
	if (!str) {
		if (tmp_err->code == 1)
			g_propagate_error (error, tmp_err);
		else {
			/* We want to handle aliases, so construct own error message */
			gs_free char *err_str = NULL;

			err_str = get_valid_options_string (array, array_slv);
			g_set_error (error, 1, 0, _("'%s' not among [%s]"), val, err_str);
			g_clear_error (&tmp_err);
		}
		return NULL;
	}

	/* Return a pointer to the found string in passed 'array' */
	iter = array;
	for (i = 0; i < 2; i++, iter = array_slv) {
		for (; iter && *iter; iter++) {
			const NMMetaSettingInfoEditor *setting_info = (*iter)->setting_info;

			if (   nm_streq (setting_info->general->setting_name, str)
			    || nm_streq0 (setting_info->alias, str)) {
				return setting_info->general->setting_name;
			}
		}
	}

	/* We should not really come here */
	g_set_error (error, 1, 0, _("Unknown error"));
	return NULL;
}

static const char *
check_valid_name_toplevel (const char *val, const char **slave_type, GError **error)
{
	gs_unref_ptrarray GPtrArray *tmp_arr = NULL;
	const char *str;
	GError *tmp_err = NULL;
	int i;
	const NMMetaSettingInfoEditor *setting_info;

	NM_SET_OUT (slave_type, NULL);

	/* Create a temporary array that can be used in nmc_string_is_valid() */
	tmp_arr = g_ptr_array_sized_new (32);
	for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++) {
		setting_info = &nm_meta_setting_infos_editor[i];
		g_ptr_array_add (tmp_arr, (gpointer) setting_info->general->setting_name);
		if (setting_info->alias)
			g_ptr_array_add (tmp_arr, (gpointer) setting_info->alias);
	}
	g_ptr_array_add (tmp_arr, "bond-slave");
	g_ptr_array_add (tmp_arr, "bridge-slave");
	g_ptr_array_add (tmp_arr, "team-slave");
	g_ptr_array_add (tmp_arr, (gpointer) NULL);

	/* Check string validity */
	str = nmc_string_is_valid (val, (const char **) tmp_arr->pdata, &tmp_err);
	if (!str) {
		if (tmp_err->code == 1)
			g_propagate_error (error, tmp_err);
		else {
			/* We want to handle aliases, so construct own error message */
			char *err_str = get_valid_options_string_toplevel ();

			g_set_error (error, 1, 0, _("'%s' not among [%s]"), val, err_str);
			g_free (err_str);
			g_clear_error (&tmp_err);
		}
		return NULL;
	}

	if (nm_streq (str, "bond-slave")) {
		NM_SET_OUT (slave_type, NM_SETTING_BOND_SETTING_NAME);
		return NM_SETTING_WIRED_SETTING_NAME;
	} else if (nm_streq (str, "bridge-slave")) {
		NM_SET_OUT (slave_type, NM_SETTING_BRIDGE_SETTING_NAME);
		return NM_SETTING_WIRED_SETTING_NAME;
	} else if (nm_streq (str, "team-slave")) {
		NM_SET_OUT (slave_type, NM_SETTING_TEAM_SETTING_NAME);
		return NM_SETTING_WIRED_SETTING_NAME;
	}

	setting_info = nm_meta_setting_info_editor_find_by_name (str, TRUE);
	if (setting_info)
		return setting_info->general->setting_name;

	/* We should not really come here */
	g_set_error (error, 1, 0, _("Unknown error"));
	return NULL;
}

static gboolean
is_setting_mandatory (NMConnection *connection, NMSetting *setting)
{
	NMSettingConnection *s_con;
	const char *c_type;
	const NMMetaSettingValidPartItem *const*item;
	const char *name;
	const char *s_type;
	guint i;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	c_type = nm_setting_connection_get_connection_type (s_con);
	s_type = nm_setting_connection_get_slave_type (s_con);

	name = nm_setting_get_name (setting);

	for (i = 0; i < 2; i++) {
		if (i == 0)
			item = get_valid_settings_array (c_type);
		else
			item = nm_meta_setting_info_valid_parts_for_slave_type (s_type, NULL);
		for (; item && *item; item++) {
			if (!strcmp (name, (*item)->setting_info->general->setting_name))
				return (*item)->mandatory;
		}
	}

	return FALSE;
}

/*****************************************************************************/

static const char *
_strip_master_prefix (const char *master, const char *(**func)(NMConnection *))
{
	if (!master)
		return NULL;

	if (g_str_has_prefix (master, "ifname/")) {
		master = master + strlen ("ifname/");
		if (func)
			*func = nm_connection_get_interface_name;
	} else if (g_str_has_prefix (master, "uuid/")) {
		master = master + strlen ("uuid/");
		if (func)
			*func = nm_connection_get_uuid;
	} else if (g_str_has_prefix (master, "id/")) {
		master = master + strlen ("id/");
		if (func)
			 *func = nm_connection_get_id;
	}
	return master;
}

/* normalized_master_for_slave:
 * @connections: list af all connections
 * @master: UUID, ifname or ID of the master connection
 * @type: virtual connection type (bond, team, bridge, ...) or %NULL
 * @out_type: type of the connection that matched
 *
 * Check whether master is a valid interface name, UUID or ID of some connection,
 * possibly of a specified @type.
 * First UUID and ifname are checked. If they don't match, ID is checked
 * and replaced by UUID on a match.
 *
 * Returns: identifier of master connection if found, %NULL otherwise
 */
static const char *
normalized_master_for_slave (const GPtrArray *connections,
                             const char *master,
                             const char *type,
                             const char **out_type)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	const char *con_type = NULL, *id, *uuid, *ifname;
	int i;
	const char *found_by_id = NULL;
	const char *out_type_by_id = NULL;
	const char *out_master = NULL;
	const char *(*func) (NMConnection *) = NULL;

	if (!master)
		return NULL;

	master = _strip_master_prefix (master, &func);
	for (i = 0; i < connections->len; i++) {
		connection = NM_CONNECTION (connections->pdata[i]);
		s_con = nm_connection_get_setting_connection (connection);
		g_assert (s_con);
		con_type = nm_setting_connection_get_connection_type (s_con);
		if (type && g_strcmp0 (con_type, type) != 0)
			continue;
		if (func) {
			/* There was a prefix; only compare to that type. */
			if (g_strcmp0 (master, func (connection)) == 0) {
				if (out_type)
					*out_type = con_type;
				if (func == nm_connection_get_id)
					out_master = nm_connection_get_uuid (connection);
				else
					out_master = master;
				break;
			}
		} else {
			id = nm_connection_get_id (connection);
			uuid = nm_connection_get_uuid (connection);
			ifname = nm_connection_get_interface_name (connection);
			if (   g_strcmp0 (master, uuid) == 0
			    || g_strcmp0 (master, ifname) == 0) {
				out_master = master;
				if (out_type)
					*out_type = con_type;
				break;
			}
			if (!found_by_id && g_strcmp0 (master, id) == 0) {
				out_type_by_id = con_type;
				found_by_id = uuid;
			}
		}
	}

	if (!out_master) {
		out_master = found_by_id;
		if (out_type)
			*out_type = out_type_by_id;
	}

	if (!out_master) {
		g_print (_("Warning: master='%s' doesn't refer to any existing profile.\n"), master);
		out_master = master;
		if (out_type)
			*out_type = type;
	}

	return out_master;
}

#define WORD_YES "yes"
#define WORD_NO  "no"
static const char *
prompt_yes_no (gboolean default_yes, char *delim)
{
	static char prompt[128] = { 0 };

	if (!delim)
		delim = "";

	snprintf (prompt, sizeof (prompt), "(%s/%s) [%s]%s ",
	          WORD_YES, WORD_NO,
	          default_yes ? WORD_YES : WORD_NO, delim);

	return prompt;
}

static NMSetting *
is_setting_valid (NMConnection *connection, const NMMetaSettingValidPartItem *const*valid_settings_main, const NMMetaSettingValidPartItem *const*valid_settings_slave, char *setting)
{
	const char *setting_name;

	if (!(setting_name = check_valid_name (setting, valid_settings_main, valid_settings_slave, NULL)))
		return NULL;
	return nm_connection_get_setting_by_name (connection, setting_name);
}

static char *
is_property_valid (NMSetting *setting, const char *property, GError **error)
{
	char **valid_props = NULL;
	const char *prop_name;
	char *ret;

	valid_props = nmc_setting_get_valid_properties (setting);
	prop_name = nmc_string_is_valid (property, (const char **) valid_props, error);
	ret = g_strdup (prop_name);
	g_strfreev (valid_props);
	return ret;
}

static char *
unique_master_iface_ifname (const GPtrArray *connections,
                            const char *try_name)
{
	NMConnection *connection;
	char *new_name;
	unsigned num = 1;
	int i = 0;
	const char *ifname = NULL;

	new_name = g_strdup (try_name);
	while (i < connections->len) {
		connection = NM_CONNECTION (connections->pdata[i]);
		ifname = nm_connection_get_interface_name (connection);
		if (g_strcmp0 (new_name, ifname) == 0) {
			g_free (new_name);
			new_name = g_strdup_printf ("%s%d", try_name, num++);
			i = 0;
		} else
			i++;
	}
	return new_name;
}

static void
set_default_interface_name (NmCli *nmc, NMSettingConnection *s_con)
{
	const GPtrArray *connections;
	char *ifname = NULL;
	const char *con_type = nm_setting_connection_get_connection_type (s_con);

	if (nm_setting_connection_get_interface_name (s_con))
		return;

	connections = nm_client_get_connections (nmc->client);

	/* Set a sensible bond/team/bridge interface name by default */
	if (g_strcmp0 (con_type, NM_SETTING_BOND_SETTING_NAME) == 0)
		ifname = unique_master_iface_ifname (connections, "nm-bond");
	else if (g_strcmp0 (con_type, NM_SETTING_TEAM_SETTING_NAME) == 0)
		ifname = unique_master_iface_ifname (connections, "nm-team");
	else if (g_strcmp0 (con_type, NM_SETTING_BRIDGE_SETTING_NAME) == 0)
		ifname = unique_master_iface_ifname (connections, "nm-bridge");
	else
		return;

	g_object_set (s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, ifname, NULL);
	g_free (ifname);
}

/*****************************************************************************/

static PropertyInfFlags
_dynamic_options_set (const NMMetaAbstractInfo *abstract_info,
                      PropertyInfFlags mask, PropertyInfFlags set)
{
	static GHashTable *cache = NULL;
	gpointer p;
	PropertyInfFlags v, v2;

	if (G_UNLIKELY (!cache))
		cache = g_hash_table_new (nm_direct_hash, NULL);

	if (g_hash_table_lookup_extended (cache, (gpointer) abstract_info, NULL, &p))
		v = GPOINTER_TO_UINT (p);
	else
		v = 0;

	v2 = (v & ~mask) | (mask & set);
	if (v != v2)
		g_hash_table_insert (cache, (gpointer) abstract_info, GUINT_TO_POINTER (v2));

	return v2;
}

static PropertyInfFlags
_dynamic_options_get (const NMMetaAbstractInfo *abstract_info)
{
	return _dynamic_options_set (abstract_info, 0, 0);
}

/*****************************************************************************/

static gboolean
_meta_property_needs_bond_hack (const NMMetaPropertyInfo *property_info)
{
	/* hack: the bond property data is handled special and not generically.
	 * Eventually, get rid of explicitly checking whether we handle a bond. */
	if (!property_info)
		g_return_val_if_reached (FALSE);
	return    property_info->property_typ_data
	       && property_info->property_typ_data->nested == &nm_meta_property_typ_data_bond;

}

static char **
_meta_abstract_complete (const NMMetaAbstractInfo *abstract_info, const char *text)
{
	const char *const*values;
	char **values_to_free = NULL;
	const NMMetaOperationContext ctx = {
		.connection = nmc_tab_completion.connection,
	};

	values = nm_meta_abstract_info_complete (abstract_info,
	                                         nmc_meta_environment,
	                                         nmc_meta_environment_arg,
	                                         &ctx,
	                                         text,
	                                         &values_to_free);
	if (values)
		return values_to_free ?: g_strdupv ((char **) values);
	return NULL;
}

static char *
_meta_abstract_generator (const char *text, int state)
{
	if (nmc_tab_completion.words) {
		return nmc_rl_gen_func_basic (text,
		                              state,
		                              (const char *const *) nmc_tab_completion.words);
	}

	return NULL;
}

static void
_meta_abstract_get (const NMMetaAbstractInfo *abstract_info,
                    const NMMetaSettingInfoEditor **out_setting_info,
                    const char **out_setting_name,
                    const char **out_property_name,
                    const char **out_option,
                    NMMetaPropertyInfFlags *out_inf_flags,
                    const char **out_prompt,
                    const char **out_def_hint)
{
	const NMMetaPropertyInfo *info = (const NMMetaPropertyInfo *) abstract_info;

	NM_SET_OUT (out_option, info->property_alias);
	NM_SET_OUT (out_setting_info, info->setting_info);
	NM_SET_OUT (out_setting_name, info->setting_info->general->setting_name);
	NM_SET_OUT (out_property_name, info->property_name);
	NM_SET_OUT (out_option, info->property_alias);
	NM_SET_OUT (out_inf_flags, info->inf_flags);
	NM_SET_OUT (out_prompt, info->prompt);
	NM_SET_OUT (out_def_hint, info->def_hint);
}

static const OptionInfo *_meta_abstract_get_option_info (const NMMetaAbstractInfo *abstract_info);

/*
 * Mark options in option_info as relevant.
 * The questionnaire (for --ask) will ask for them.
 */
static void
enable_options (const char *setting_name, const char *property, const char * const *opts)
{
	const NMMetaPropertyInfo *property_info;

	property_info = nm_meta_property_info_find_by_name (setting_name, property);

	if (!property_info)
		g_return_if_reached ();

	if (_meta_property_needs_bond_hack (property_info)) {
		guint i;

		for (i = 0; i < nm_meta_property_typ_data_bond.nested_len; i++) {
			const NMMetaNestedPropertyInfo *bi = &nm_meta_property_typ_data_bond.nested[i];

			if (   bi->base.inf_flags & NM_META_PROPERTY_INF_FLAG_DONT_ASK
			    && bi->base.property_alias
			    && g_strv_contains (opts, bi->base.property_alias))
				_dynamic_options_set ((const NMMetaAbstractInfo *) bi, PROPERTY_INF_FLAG_ENABLED, PROPERTY_INF_FLAG_ENABLED);
		}
		return;
	}

	if (!property_info->is_cli_option)
		g_return_if_reached ();

	if (   property_info->inf_flags & NM_META_PROPERTY_INF_FLAG_DONT_ASK
	    && property_info->property_alias
	    && g_strv_contains (opts, property_info->property_alias))
		_dynamic_options_set ((const NMMetaAbstractInfo *) property_info, PROPERTY_INF_FLAG_ENABLED, PROPERTY_INF_FLAG_ENABLED);
}

/*
 * Mark options in option_info as irrelevant (because we learned they make no sense
 * or they have been set via different means).
 * The questionnaire (for --ask) will not ask for them.
 */
static void
disable_options (const char *setting_name, const char *property)
{
	const NMMetaPropertyInfo *property_infos_local[2];
	const NMMetaPropertyInfo *const*property_infos;
	guint p;

	if (property) {
		const NMMetaPropertyInfo *pi;

		pi = nm_meta_property_info_find_by_name (setting_name, property);
		if (!pi)
			g_return_if_reached ();
		if (   !_meta_property_needs_bond_hack (pi)
		    && !pi->is_cli_option)
			return;
		property_infos_local[0] = pi;
		property_infos_local[1] = NULL;
		property_infos = property_infos_local;
	} else {
		const NMMetaSettingInfoEditor *setting_info;

		setting_info = nm_meta_setting_info_editor_find_by_name (setting_name, FALSE);
		if (!setting_info)
			g_return_if_reached ();
		property_infos = setting_info->properties;
		if (!property_infos)
			return;
	}

	for (p = 0; property_infos[p]; p++) {
		const NMMetaPropertyInfo *property_info = property_infos[p];

		if (_meta_property_needs_bond_hack (property_info)) {
			guint i;

			for (i = 0; i < nm_meta_property_typ_data_bond.nested_len; i++) {
				const NMMetaNestedPropertyInfo *bi = &nm_meta_property_typ_data_bond.nested[i];

				_dynamic_options_set ((const NMMetaAbstractInfo *) bi, PROPERTY_INF_FLAG_DISABLED, PROPERTY_INF_FLAG_DISABLED);
			}
			nm_assert (p == 0 && !property_infos[1]);
		} else {
			if (property_info->is_cli_option)
				_dynamic_options_set ((const NMMetaAbstractInfo *) property_info, PROPERTY_INF_FLAG_DISABLED, PROPERTY_INF_FLAG_DISABLED);
		}
	}
}

/*
 * Reset marks done with enable_options() and disable_options().
 * Ensures correct operation in case more than one connection is added in a single
 * nmcli session.
 */
static void
reset_options (void)
{
	NMMetaSettingType s;

	for (s = 0; s < _NM_META_SETTING_TYPE_NUM; s++) {
		const NMMetaPropertyInfo *const*property_infos;
		guint p;

		property_infos = nm_meta_setting_infos_editor[s].properties;
		if (!property_infos)
			continue;
		for (p = 0; property_infos[p]; p++) {
			const NMMetaPropertyInfo *property_info = property_infos[p];

			if (_meta_property_needs_bond_hack (property_info)) {
				guint i;

				for (i = 0; i < nm_meta_property_typ_data_bond.nested_len; i++) {
					const NMMetaNestedPropertyInfo *bi = &nm_meta_property_typ_data_bond.nested[i];

					_dynamic_options_set ((const NMMetaAbstractInfo *) bi, PROPERTY_INF_FLAG_ALL, 0);
				}
			} else {
				if (property_info->is_cli_option)
					_dynamic_options_set ((const NMMetaAbstractInfo *) property_info, PROPERTY_INF_FLAG_ALL, 0);
			}
		}
	}
}

static gboolean
set_property (NMClient *client,
              NMConnection *connection,
              const char *setting_name,
              const char *property,
              const char *value,
              char modifier,
              GError **error)
{
	gs_free char *property_name = NULL;
	gs_free_error GError *local = NULL;
	NMSetting *setting;

	nm_assert (setting_name && setting_name[0]);
	nm_assert (NM_IN_SET (modifier, '\0', '+', '-'));

	setting = nm_connection_get_setting_by_name (connection, setting_name);
	if (!setting) {
		setting = nm_meta_setting_info_editor_new_setting (nm_meta_setting_info_editor_find_by_name (setting_name, FALSE),
		                                                   NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI);
		nm_connection_add_setting (connection, setting);
	}

	property_name = is_property_valid (setting, property, &local);
	if (!property_name) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: invalid property '%s': %s."),
		             property, local->message);
		return FALSE;
	}

	if (!nmc_setting_set_property (client,
	                               setting,
	                               property_name,
	                               (  (modifier == '-' && !value)
	                                ? '\0'
	                                : modifier),
	                               value,
	                               &local)) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: failed to %s %s.%s: %s."),
		             (  modifier != '-'
		              ? "modify"
		              : "remove a value from"),
		             setting_name,
		             property,
		             local->message);
		return FALSE;
	}

	/* Don't ask for this property in interactive mode. */
	disable_options (setting_name, property_name);

	return TRUE;
}

static gboolean
set_option (NmCli *nmc, NMConnection *connection, const NMMetaAbstractInfo *abstract_info, const char *value, GError **error)
{
	const char *setting_name, *property_name, *option_name;
	NMMetaPropertyInfFlags inf_flags;
	const OptionInfo *option;

	option = _meta_abstract_get_option_info (abstract_info);

	_dynamic_options_set (abstract_info, PROPERTY_INF_FLAG_DISABLED, PROPERTY_INF_FLAG_DISABLED);

	_meta_abstract_get (abstract_info, NULL, &setting_name, &property_name, &option_name, &inf_flags, NULL, NULL);
	if (option && option->check_and_set) {
		return option->check_and_set (nmc, connection, option, value, error);
	} else if (value) {
		return set_property (nmc->client, connection, setting_name, property_name,
		                     value, inf_flags & NM_META_PROPERTY_INF_FLAG_MULTI ? '+' : '\0', error);
	} else if (inf_flags & NM_META_PROPERTY_INF_FLAG_REQD) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
	                     _("Error: '%s' is mandatory."), option_name);
		return FALSE;
	}

	return TRUE;
}

/*
 * Return relevant NameItem[] tables for given connection (based on connection type
 * and slave type.
 */
static gboolean
con_settings (NMConnection *connection, const NMMetaSettingValidPartItem *const**type_settings, const NMMetaSettingValidPartItem *const**slv_settings, GError **error)
{
	const char *con_type;
	NMSettingConnection *s_con;

	g_return_val_if_fail (type_settings, FALSE);
	g_return_val_if_fail (slv_settings, FALSE);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	con_type = nm_setting_connection_get_slave_type (s_con);
	*slv_settings = nm_meta_setting_info_valid_parts_for_slave_type (con_type, NULL);
	if (!*slv_settings) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: invalid slave type; %s."), con_type);
		return FALSE;
	}

	con_type = nm_setting_connection_get_connection_type (s_con);
	*type_settings = get_valid_settings_array (con_type);
	if (!*type_settings) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: invalid connection type; %s."), con_type);
		return FALSE;
	}

	return TRUE;
}

/*
 * Make sure all required settings are in place (should be called when
 * it's possible that a type is already set).
 */
static void
ensure_settings (NMConnection *connection, const NMMetaSettingValidPartItem *const*item)
{
	NMSetting *setting;

	for (; item && *item; item++) {
		if (!(*item)->mandatory)
			continue;
		if (nm_connection_get_setting_by_name (connection, (*item)->setting_info->general->setting_name))
			continue;
		setting = nm_meta_setting_info_editor_new_setting ((*item)->setting_info,
		                                                   NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI);
		nm_connection_add_setting (connection, setting);
	}
}

/*****************************************************************************/

static char *
gen_func_bool_values_l10n (const char *text, int state)
{
	const char *words[] = { WORD_YES, WORD_NO, NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_func_bt_type (const char *text, int state)
{
	const char *words[] = { "panu", "nap", "dun-gsm", "dun-cdma", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_func_bond_mode (const char *text, int state)
{
	const char *words[] = { "balance-rr", "active-backup", "balance-xor", "broadcast",
	                        "802.3ad", "balance-tlb", "balance-alb", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}
static char *
gen_func_bond_mon_mode (const char *text, int state)
{
	const char *words[] = { "miimon", "arp", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}
static char *
gen_func_bond_lacp_rate (const char *text, int state)
{
	const char *words[] = { "slow", "fast", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

/*****************************************************************************/

static gboolean
set_connection_type (NmCli *nmc, NMConnection *con, const OptionInfo *option, const char *value, GError **error)
{
	const NMMetaSettingValidPartItem *const*type_settings;
	const NMMetaSettingValidPartItem *const*slv_settings;
	GError *local = NULL;
	const char *master[] = { "master", NULL };
	const char *slave_type = NULL;

	value = check_valid_name_toplevel (value, &slave_type, &local);
	if (!value) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: bad connection type: %s"), local->message);
		g_clear_error (&local);
		return FALSE;
	}

	if (slave_type) {
		if (!set_property (nmc->client, con, NM_SETTING_CONNECTION_SETTING_NAME,
		                   NM_SETTING_CONNECTION_SLAVE_TYPE, slave_type,
		                   '\0', error)) {
			return FALSE;
		}
		enable_options (NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_MASTER, master);
	}

	/* ifname is mandatory for all connection types except virtual ones (bond, team, bridge, vlan) */
	if (   (strcmp (value, NM_SETTING_BOND_SETTING_NAME) == 0)
	    || (strcmp (value, NM_SETTING_TEAM_SETTING_NAME) == 0)
	    || (strcmp (value, NM_SETTING_BRIDGE_SETTING_NAME) == 0)
	    || (strcmp (value, NM_SETTING_VLAN_SETTING_NAME) == 0)) {
		disable_options (NM_SETTING_CONNECTION_SETTING_NAME,
		                 NM_SETTING_CONNECTION_INTERFACE_NAME);
	}

	if (!set_property (nmc->client, con, option->setting_info->general->setting_name, option->property, value, '\0', error))
		return FALSE;

	if (!con_settings (con, &type_settings, &slv_settings, error))
		return FALSE;

	ensure_settings (con, slv_settings);
	ensure_settings (con, type_settings);

	return TRUE;
}

static gboolean
set_connection_iface (NmCli *nmc, NMConnection *con, const OptionInfo *option, const char *value, GError **error)
{
	GError *tmp_error = NULL;

	if (value) {
		/* Special value of '*' means no specific interface name */
		if (strcmp (value, "*") == 0)
			value = NULL;
		else if (!nm_utils_is_valid_iface_name (value, &tmp_error)) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("Error: '%s': %s"), value, tmp_error->message);
			g_error_free (tmp_error);
			return FALSE;
		}
	}

	return set_property (nmc->client, con, option->setting_info->general->setting_name, option->property, value, '\0', error);
}

static gboolean
set_connection_master (NmCli *nmc, NMConnection *con, const OptionInfo *option, const char *value, GError **error)
{
	const GPtrArray *connections;
	NMSettingConnection *s_con;
	const char *slave_type;

	s_con = nm_connection_get_setting_connection (con);
	g_return_val_if_fail (s_con, FALSE);

	if (!value) {
		g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("Error: master is required"));
		return FALSE;
	}

	slave_type = nm_setting_connection_get_slave_type (s_con);
	connections = nm_client_get_connections (nmc->client);
	value = normalized_master_for_slave (connections, value, slave_type, &slave_type);

	if (!set_property (nmc->client, con, NM_SETTING_CONNECTION_SETTING_NAME,
	                   NM_SETTING_CONNECTION_SLAVE_TYPE, slave_type,
	                   '\0', error)) {
		return FALSE;
	}

	return set_property (nmc->client, con, option->setting_info->general->setting_name, option->property, value, '\0', error);
}

static gboolean
set_bond_option (NmCli *nmc, NMConnection *con, const OptionInfo *option, const char *value, GError **error)
{
	NMSettingBond *s_bond;
	gboolean success;

	s_bond = nm_connection_get_setting_bond (con);
	g_return_val_if_fail (s_bond, FALSE);

	if (!value)
		return TRUE;

	if (strcmp (option->option, "mode") == 0) {
		value = nmc_bond_validate_mode (value, error);
		if (!value)
			return FALSE;

		if (g_strcmp0 (value, "active-backup") == 0) {
			const char *primary[] = { "primary", NULL };
			enable_options (NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS, primary);
		}

		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MODE, value);
	} else if (strcmp (option->option, "primary") == 0)
		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_PRIMARY, value);
	else if (strcmp (option->option, "miimon") == 0)
		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MIIMON, value);
	else if (strcmp (option->option, "downdelay") == 0)
		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY, value);
	else if (strcmp (option->option, "updelay") == 0)
		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_UPDELAY, value);
	else if (strcmp (option->option, "arp-interval") == 0)
		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL, value);
	else if (strcmp (option->option, "arp-ip-target") == 0)
		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_IP_TARGET, value);
	else if (strcmp (option->option, "lacp-rate") == 0)
		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_LACP_RATE, value);
	else
		g_return_val_if_reached (FALSE);

	if (!success) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: error adding bond option '%s=%s'."),
		             option->option, value);
	}

	return success;
}

static gboolean
set_bond_monitoring_mode (NmCli *nmc, NMConnection *con, const OptionInfo *option, const char *value, GError **error)
{
	NMSettingBond *s_bond;
	gs_free char *monitor_mode = NULL;
	const char *miimon_opts[] = { "miimon", "downdelay", "updelay", NULL };
	const char *arp_opts[] = { "arp-interval", "arp-ip-target", NULL };

	s_bond = nm_connection_get_setting_bond (con);
	g_return_val_if_fail (s_bond, FALSE);

	if (value) {
		monitor_mode = g_strdup (value);
		g_strstrip (monitor_mode);
	} else {
		monitor_mode = g_strdup (NM_META_TEXT_WORD_MIIMON);
	}

	if (matches (monitor_mode, NM_META_TEXT_WORD_MIIMON))
		enable_options (NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS, miimon_opts);
	else if (matches (monitor_mode, NM_META_TEXT_WORD_ARP))
		enable_options (NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS, arp_opts);
	else {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: '%s' is not a valid monitoring mode; use '%s' or '%s'.\n"),
		             monitor_mode, NM_META_TEXT_WORD_MIIMON, NM_META_TEXT_WORD_ARP);
		return FALSE;
	}

	return TRUE;
}

static gboolean
set_bluetooth_type (NmCli *nmc, NMConnection *con, const OptionInfo *option, const char *value, GError **error)
{
	NMSetting *setting;

	if (!value)
		return TRUE;

	/* 'dun' type requires adding 'gsm' or 'cdma' setting */
	if (   !strcmp (value, NM_SETTING_BLUETOOTH_TYPE_DUN)
	    || !strcmp (value, NM_SETTING_BLUETOOTH_TYPE_DUN"-gsm")) {
		value = NM_SETTING_BLUETOOTH_TYPE_DUN;
		setting = nm_meta_setting_info_editor_new_setting (&nm_meta_setting_infos_editor[NM_META_SETTING_TYPE_GSM],
		                                                   NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI);
		nm_connection_add_setting (con, setting);
	} else if (!strcmp (value, NM_SETTING_BLUETOOTH_TYPE_DUN"-cdma")) {
		value = NM_SETTING_BLUETOOTH_TYPE_DUN;
		setting = nm_setting_cdma_new ();
		nm_connection_add_setting (con, setting);
	} else if (!strcmp (value, NM_SETTING_BLUETOOTH_TYPE_PANU) || !strcmp (value, NM_SETTING_BLUETOOTH_TYPE_NAP)) {
		/* no op */
	} else {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: 'bt-type': '%s' not valid; use [%s, %s, %s (%s), %s]."),
		             value, NM_SETTING_BLUETOOTH_TYPE_PANU, NM_SETTING_BLUETOOTH_TYPE_NAP,
		             NM_SETTING_BLUETOOTH_TYPE_DUN, NM_SETTING_BLUETOOTH_TYPE_DUN"-gsm",
		             NM_SETTING_BLUETOOTH_TYPE_DUN"-cdma");
		return FALSE;
	}

	return set_property (nmc->client, con, option->setting_info->general->setting_name, option->property, value, '\0', error);
}

static gboolean
set_ip4_address (NmCli *nmc, NMConnection *con, const OptionInfo *option, const char *value, GError **error)
{
	NMSettingIPConfig *s_ip4;

	if (!value)
		return TRUE;

	s_ip4 = nm_connection_get_setting_ip4_config (con);
	if (!s_ip4) {
		s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
		nm_connection_add_setting (con, NM_SETTING (s_ip4));
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
		              NULL);
	}
	return set_property (nmc->client, con, option->setting_info->general->setting_name, option->property, value,
	                     '+', error);
}

static gboolean
set_ip6_address (NmCli *nmc, NMConnection *con, const OptionInfo *option, const char *value, GError **error)
{
	NMSettingIPConfig *s_ip6;

	if (!value)
		return TRUE;

	s_ip6 = nm_connection_get_setting_ip6_config (con);
	if (!s_ip6) {
		s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
		nm_connection_add_setting (con, NM_SETTING (s_ip6));
		g_object_set (s_ip6,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
		              NULL);
	}
	return set_property (nmc->client, con, option->setting_info->general->setting_name, option->property, value,
	                     '+', error);
}

/*****************************************************************************/

static const OptionInfo *
_meta_abstract_get_option_info (const NMMetaAbstractInfo *abstract_info)
{
	static const OptionInfo option_info[] = {
#define OPTION_INFO(name, property_name_, property_alias_, check_and_set_, generator_func_) \
		{ \
			.setting_info =        &nm_meta_setting_infos_editor[NM_META_SETTING_TYPE_##name], \
			.property =            property_name_, \
			.option =              property_alias_, \
			.check_and_set =       check_and_set_, \
			.generator_func =      generator_func_, \
		}
		OPTION_INFO (CONNECTION,   NM_SETTING_CONNECTION_TYPE,                  "type",               set_connection_type,       NULL),
		OPTION_INFO (CONNECTION,   NM_SETTING_CONNECTION_INTERFACE_NAME,        "ifname",             set_connection_iface,      NULL),
		OPTION_INFO (CONNECTION,   NM_SETTING_CONNECTION_MASTER,                "master",             set_connection_master,     NULL),
		OPTION_INFO (BLUETOOTH,    NM_SETTING_BLUETOOTH_TYPE,                   "bt-type",            set_bluetooth_type,        gen_func_bt_type),
		OPTION_INFO (BOND,         NM_SETTING_BOND_OPTIONS,                     "mode",               set_bond_option,           gen_func_bond_mode),
		OPTION_INFO (BOND,         NM_SETTING_BOND_OPTIONS,                     "primary",            set_bond_option,           nmc_rl_gen_func_ifnames),
		OPTION_INFO (BOND,         NM_SETTING_BOND_OPTIONS,                     NULL,                 set_bond_monitoring_mode,  gen_func_bond_mon_mode),
		OPTION_INFO (BOND,         NM_SETTING_BOND_OPTIONS,                     "miimon",             set_bond_option,           NULL),
		OPTION_INFO (BOND,         NM_SETTING_BOND_OPTIONS,                     "downdelay",          set_bond_option,           NULL),
		OPTION_INFO (BOND,         NM_SETTING_BOND_OPTIONS,                     "updelay",            set_bond_option,           NULL),
		OPTION_INFO (BOND,         NM_SETTING_BOND_OPTIONS,                     "arp-interval",       set_bond_option,           NULL),
		OPTION_INFO (BOND,         NM_SETTING_BOND_OPTIONS,                     "arp-ip-target",      set_bond_option,           NULL),
		OPTION_INFO (BOND,         NM_SETTING_BOND_OPTIONS,                     "lacp-rate",          set_bond_option,           gen_func_bond_lacp_rate),
		OPTION_INFO (IP4_CONFIG,   NM_SETTING_IP_CONFIG_ADDRESSES,              "ip4",                set_ip4_address,           NULL),
		OPTION_INFO (IP6_CONFIG,   NM_SETTING_IP_CONFIG_ADDRESSES,              "ip6",                set_ip6_address,           NULL),
		{ 0 },
	};
	const char *property_name, *option;
	const NMMetaSettingInfoEditor *setting_info;
	const OptionInfo *candidate;

	_meta_abstract_get (abstract_info, &setting_info, NULL, &property_name, &option, NULL, NULL, NULL);

	for (candidate = option_info; candidate->setting_info; candidate++) {
		if (   candidate->setting_info == setting_info
		    && nm_streq0 (candidate->property, property_name)
		    && nm_streq0 (candidate->option, option)) {
			return candidate;
		}
	}
	return NULL;
}

static gboolean
option_relevant (NMConnection *connection, const NMMetaAbstractInfo *abstract_info)
{
	const char *setting_name;
	NMMetaPropertyInfFlags inf_flags;

	_meta_abstract_get (abstract_info, NULL, &setting_name, NULL, NULL, &inf_flags, NULL, NULL);

	if (   (inf_flags & NM_META_PROPERTY_INF_FLAG_DONT_ASK)
	    && !(_dynamic_options_get (abstract_info) & PROPERTY_INF_FLAG_ENABLED))
		return FALSE;
	if (_dynamic_options_get (abstract_info) & PROPERTY_INF_FLAG_DISABLED)
		return FALSE;
	if (!nm_connection_get_setting_by_name (connection, setting_name))
		return FALSE;
	return TRUE;
}

/*****************************************************************************/

static void
complete_property_name (NmCli *nmc, NMConnection *connection,
                        char modifier,
                        const char *prefix,
                        const char *postfix)
{
	NMSettingConnection *s_con;
	const NMMetaSettingValidPartItem *const*valid_settings_main;
	const NMMetaSettingValidPartItem *const*valid_settings_slave;
	const char *connection_type = NULL;
	const char *slave_type = NULL;
	gs_free char *word_list = NULL;
	NMMetaSettingType s;

	connection_type = nm_connection_get_connection_type (connection);
	s_con = nm_connection_get_setting_connection (connection);
	if (s_con)
		slave_type = nm_setting_connection_get_slave_type (s_con);
	valid_settings_main = get_valid_settings_array (connection_type);
	valid_settings_slave = nm_meta_setting_info_valid_parts_for_slave_type (slave_type, NULL);

	word_list = get_valid_properties_string (valid_settings_main, valid_settings_slave, modifier, prefix, postfix);
	if (word_list)
		g_print ("%s", word_list);

	if (modifier != '\0')
		return;

	for (s = 0; s < _NM_META_SETTING_TYPE_NUM; s++) {
		const NMMetaPropertyInfo *const*property_infos;
		guint p;

		if (!nm_connection_get_setting_by_name (connection, nm_meta_setting_infos_editor[s].general->setting_name))
			continue;

		property_infos = nm_meta_setting_infos_editor[s].properties;
		if (!property_infos)
			continue;
		for (p = 0; property_infos[p]; p++) {
			const NMMetaPropertyInfo *property_info = property_infos[p];

			if (_meta_property_needs_bond_hack (property_info)) {
				guint i;

				for (i = 0; i < nm_meta_property_typ_data_bond.nested_len; i++) {
					const NMMetaNestedPropertyInfo *bi = &nm_meta_property_typ_data_bond.nested[i];

					if (   !bi->base.property_alias
					    || !g_str_has_prefix (bi->base.property_alias, prefix))
						continue;
					g_print ("%s\n", bi->base.property_alias);
				}
			} else {
				if (!property_info->is_cli_option)
					continue;
				if (   !property_info->property_alias
				    || !g_str_has_prefix (property_info->property_alias, prefix))
					continue;
				g_print ("%s\n", property_info->property_alias);
			}
		}
	}
}

static void
run_rl_generator (rl_compentry_func_t *generator_func, const char *prefix)
{
	int state = 0;
	char *str;

	while ((str = generator_func (prefix, state))) {
		g_print ("%s\n", str);
		g_free (str);
		if (state == 0)
			state = 1;
	}
}

static gboolean
complete_option (const NMMetaAbstractInfo *abstract_info, const char *prefix, NMConnection *context_connection)
{
	const OptionInfo *candidate;
	const char *const*values;
	gs_strfreev char **values_to_free = NULL;
	const NMMetaOperationContext ctx = {
		.connection = context_connection,
	};

	values = nm_meta_abstract_info_complete (abstract_info,
	                                         nmc_meta_environment,
	                                         nmc_meta_environment_arg,
	                                         &ctx,
	                                         prefix,
	                                         &values_to_free);
	if (values) {
		for (; values[0]; values++)
			g_print ("%s\n", values[0]);
		return TRUE;
	}

	candidate = _meta_abstract_get_option_info (abstract_info);
	if (candidate && candidate->generator_func) {
		run_rl_generator (candidate->generator_func, prefix);
		return TRUE;
	}

	return FALSE;
}

static void
complete_property (const char *setting_name, const char *property, const char *prefix, NMConnection *connection)
{
	const NMMetaPropertyInfo *property_info;

	property_info = nm_meta_property_info_find_by_name (setting_name, property);
	if (property_info) {
		if (complete_option ((const NMMetaAbstractInfo *) property_info, prefix, connection))
			return;
	}

	if (   strcmp (setting_name, NM_SETTING_BLUETOOTH_SETTING_NAME) == 0
	         && strcmp (property, NM_SETTING_BLUETOOTH_TYPE) == 0)
		run_rl_generator (gen_func_bt_type, prefix);
}

/*****************************************************************************/

static gboolean
get_value (const char **value, int *argc, char ***argv, const char *option, GError **error)
{
	if (!**argv) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: value for '%s' is missing."), option);
		return FALSE;
	}

	/* Empty string will reset the value to default */
	if (**argv[0] == '\0')
		*value = NULL;
	else
		*value = *argv[0];

	(*argc)--;
	(*argv)++;
	return TRUE;
}

gboolean
nmc_read_connection_properties (NmCli *nmc,
                                NMConnection *connection,
                                int *argc,
                                char ***argv,
                                GError **error)
{
	const char *option;
	const char *value = NULL;
	GError *local = NULL;

	/* First check if we have a slave-type, as this would mean we will not
	 * have ip properties but possibly others, slave-type specific.
	 */
	/* Go through arguments and set properties */
	do {
		const NMMetaAbstractInfo *chosen = NULL;
		gs_strfreev char **strv = NULL;
		const NMMetaSettingValidPartItem *const*type_settings;
		const NMMetaSettingValidPartItem *const*slv_settings;
		char modifier = '\0';

		if (!con_settings (connection, &type_settings, &slv_settings, error))
			return FALSE;

		ensure_settings (connection, slv_settings);
		ensure_settings (connection, type_settings);

		option = **argv;
		if (!option) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: <setting>.<property> argument is missing."));
			return FALSE;
		}

		if (option[0] == '+' || option[0] == '-')
			modifier = *option;

		strv = g_strsplit (option, ".", 2);
		if (g_strv_length (strv) == 2) {
			/* This seems like a <setting>.<property> (such as "connection.id" or "bond.mode"),
			 * optionally prefixed with "+| or "-". */
			char *setting = strv[0];
			const char *setting_name;

			if (modifier)
				setting++;

			if (*argc == 1 && nmc->complete)
				complete_property_name (nmc, connection, modifier, setting, strv[1]);

			setting_name = check_valid_name (setting, type_settings, slv_settings, &local);
			if (!setting_name) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: invalid or not allowed setting '%s': %s."),
				             setting, local->message);
				g_clear_error (&local);
				return FALSE;
			}

			(*argc)--;
			(*argv)++;
			if (!get_value (&value, argc, argv, option, error))
				return FALSE;

			if (!*argc && nmc->complete)
				complete_property (setting, strv[1], value ?: "", connection);

			if (!set_property (nmc->client, connection, setting_name, strv[1], value, modifier, error))
				return FALSE;
		} else {
			NMMetaSettingType s;
			const char *chosen_setting_name = NULL;
			const char *chosen_option = NULL;

			/* Let's see if this is an property alias (such as "id", "mode", "type" or "con-name")*/
			for (s = 0; s < _NM_META_SETTING_TYPE_NUM; s++) {
				const NMMetaPropertyInfo *const*property_infos;
				guint p;

				if (!check_valid_name (nm_meta_setting_infos[s].setting_name,
				                       type_settings, slv_settings, NULL))
					continue;

				property_infos = nm_meta_setting_infos_editor[s].properties;
				if (!property_infos)
					continue;
				for (p = 0; property_infos[p]; p++) {
					const NMMetaPropertyInfo *property_info = property_infos[p];

					if (_meta_property_needs_bond_hack (property_info)) {
						guint i;

						for (i = 0; i < nm_meta_property_typ_data_bond.nested_len; i++) {
							const NMMetaNestedPropertyInfo *bi = &nm_meta_property_typ_data_bond.nested[i];

							if (!nm_streq0 (bi->base.property_alias, option))
								continue;
							if (chosen) {
								g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
								             _("Error: '%s' is ambiguous (%s.%s or %s.%s)."), option,
								             chosen_setting_name, chosen_option,
								             nm_meta_setting_infos[s].setting_name, option);
								return FALSE;
							}
							chosen_setting_name = nm_meta_setting_infos[s].setting_name;
							chosen_option = option;
							chosen = (const NMMetaAbstractInfo *) bi;
						}
					} else {
						if (!property_info->is_cli_option)
							continue;
						if (!nm_streq0 (property_info->property_alias, option))
							continue;
						if (chosen) {
							g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
							             _("Error: '%s' is ambiguous (%s.%s or %s.%s)."), option,
							             chosen_setting_name, chosen_option,
							             nm_meta_setting_infos[s].setting_name, option);
							return FALSE;
						}
						chosen_setting_name = nm_meta_setting_infos[s].setting_name;
						chosen_option = option;
						chosen = (const NMMetaAbstractInfo *) property_info;
					}
				}
			}

			if (!chosen) {
				if (modifier)
					option++;
				if (*argc == 1 && nmc->complete)
					complete_property_name (nmc, connection, modifier, option, NULL);
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: invalid <setting>.<property> '%s'."), option);
				return FALSE;
			}

			if (*argc == 1 && nmc->complete)
				complete_property_name (nmc, connection, modifier, option, NULL);

			(*argc)--;
			(*argv)++;
			if (!get_value (&value, argc, argv, option, error))
				return FALSE;

			if (!*argc && nmc->complete)
				complete_option (chosen, value ?: "", connection);

			if (!set_option (nmc, connection, chosen, value, error))
				return FALSE;
		}

	} while (*argc);

	return TRUE;
}

typedef struct {
	NmCli *nmc;
	char *con_name;
} AddConnectionInfo;

static void
add_connection_cb (GObject *client,
                   GAsyncResult *result,
                   gpointer user_data)
{
	AddConnectionInfo *info = (AddConnectionInfo *) user_data;
	NmCli *nmc = info->nmc;
	NMRemoteConnection *connection;
	GError *error = NULL;
	const GPtrArray *connections;
	guint i, found;

	connection = nm_client_add_connection_finish (NM_CLIENT (client), result, &error);
	if (error) {
		g_string_printf (nmc->return_text,
		                 _("Error: Failed to add '%s' connection: %s"),
		                 info->con_name, error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
	} else {
		connections = nm_client_get_connections (nmc->client);
		if (connections) {
			found = 0;
			for (i = 0; i < connections->len; i++) {
				NMConnection *candidate = NM_CONNECTION (connections->pdata[i]);

				if ((NMConnection *) connection == candidate)
					continue;
				if (nm_streq0 (nm_connection_get_id (candidate), info->con_name))
					found++;
			}
			if (found > 0) {
				g_printerr (g_dngettext (GETTEXT_PACKAGE,
				                         "Warning: There is another connection with the name '%1$s'. Reference the connection by its uuid '%2$s'\n",
				                         "Warning: There are %3$u other connections with the name '%1$s'. Reference the connection by its uuid '%2$s'\n",
				                         found),
				            info->con_name,
				            nm_connection_get_uuid (NM_CONNECTION (connection)),
				            found);
			}
		}

		g_print (_("Connection '%s' (%s) successfully added.\n"),
		         nm_connection_get_id (NM_CONNECTION (connection)),
		         nm_connection_get_uuid (NM_CONNECTION (connection)));
		g_object_unref (connection);
	}

	g_free (info->con_name);
	g_free (info);
	quit ();
}

static void
add_new_connection (gboolean persistent,
                    NMClient *client,
                    NMConnection *connection,
                    GAsyncReadyCallback callback,
                    gpointer user_data)
{
	nm_client_add_connection_async (client, connection, persistent,
	                                NULL, callback, user_data);
}

static void
update_connection (gboolean persistent,
                   NMRemoteConnection *connection,
                   GAsyncReadyCallback callback,
                   gpointer user_data)
{
	nm_remote_connection_commit_changes_async (connection, persistent,
	                                           NULL, callback, user_data);
}

static gboolean
is_single_word (const char* line)
{
	size_t n1, n2, n3;

	n1 = strspn  (line,    " \t");
	n2 = strcspn (line+n1, " \t\0") + n1;
	n3 = strspn  (line+n2, " \t");

	if (n3 == 0)
		return TRUE;
	else
		return FALSE;
}

static char **
nmcli_con_add_tab_completion (const char *text, int start, int end)
{
	NMMetaSettingType s;
	char **match_array = NULL;
	rl_compentry_func_t *generator_func = NULL;
	gs_free char *no = g_strdup_printf ("[%s]: ", _("no"));
	gs_free char *yes = g_strdup_printf ("[%s]: ", _("yes"));
	const NMMetaAbstractInfo *info;

	/* Disable readline's default filename completion */
	rl_attempted_completion_over = 1;

	/* Restore standard append character to space */
	rl_completion_append_character = '\x00';

	if (!is_single_word (rl_line_buffer))
		return NULL;

	for (s = 0; s < _NM_META_SETTING_TYPE_NUM; s++) {
		const NMMetaPropertyInfo *const*property_infos;
		guint p;

		property_infos = nm_meta_setting_infos_editor[s].properties;
		if (!property_infos)
			continue;
		for (p = 0; property_infos[p]; p++) {
			const NMMetaPropertyInfo *property_info = property_infos[p];

			if (_meta_property_needs_bond_hack (property_info)) {
				guint i;

				for (i = 0; i < nm_meta_property_typ_data_bond.nested_len; i++) {
					const NMMetaNestedPropertyInfo *bi = &nm_meta_property_typ_data_bond.nested[i];

					if (   bi->base.prompt
					    && g_str_has_prefix (rl_prompt, bi->base.prompt)) {
						goto next;
					}
				}
			} else {
				if (   property_info->prompt
				    && g_str_has_prefix (rl_prompt, property_info->prompt)) {
					info = (const NMMetaAbstractInfo *) property_info;
					nmc_tab_completion.words = _meta_abstract_complete (info, text);
					if (nmc_tab_completion.words) {
						match_array = rl_completion_matches (text, _meta_abstract_generator);
						nm_clear_pointer (&nmc_tab_completion.words, g_strfreev);
					}
					return match_array;
				}
			}
		}
	}

next:
	if (g_str_has_prefix (rl_prompt, NM_META_TEXT_PROMPT_BT_TYPE))
		generator_func = gen_func_bt_type;
	else if (g_str_has_prefix (rl_prompt, NM_META_TEXT_PROMPT_BOND_MODE))
		generator_func = gen_func_bond_mode;
	else if (g_str_has_prefix (rl_prompt, NM_META_TEXT_PROMPT_BOND_MON_MODE))
		generator_func = gen_func_bond_mon_mode;
	else if (   g_str_has_suffix (rl_prompt, yes)
	         || g_str_has_suffix (rl_prompt, no))
		generator_func = gen_func_bool_values_l10n;

	if (generator_func)
		match_array = rl_completion_matches (text, generator_func);

	return match_array;
}

static void
ask_option (NmCli *nmc, NMConnection *connection, const NMMetaAbstractInfo *abstract_info)
{
	char *value;
	GError *error = NULL;
	gs_free char *prompt = NULL;
	gboolean multi;
	const char *opt_prompt, *opt_def_hint;
	NMMetaPropertyInfFlags inf_flags;

	_meta_abstract_get (abstract_info, NULL, NULL, NULL, NULL, &inf_flags, &opt_prompt, &opt_def_hint);
	prompt = g_strjoin ("",
	                    gettext (opt_prompt),
	                    opt_def_hint ? " " : "",
	                    opt_def_hint ?: "",
	                    ": ",
	                    NULL);

	multi = NM_FLAGS_HAS (inf_flags, NM_META_PROPERTY_INF_FLAG_MULTI);

	if (multi)
		g_print (_("You can specify this option more than once. Press <Enter> when you're done.\n"));

again:
	value = nmc_readline (&nmc->nmc_config,
	                      "%s",
	                      prompt);
	if (multi && !value)
		return;

	if (!set_option (nmc, connection, abstract_info, value, &error)) {
		g_printerr ("%s\n", error->message);
		g_clear_error (&error);
		goto again;
	}

	if (multi && value)
		goto again;
}

static NMMetaSettingType
connection_get_base_meta_setting_type (NMConnection *connection)
{
	const char *connection_type;
	NMSetting *base_setting;
	const NMMetaSettingInfoEditor *editor;

	connection_type = nm_connection_get_connection_type (connection);
	nm_assert (connection_type);
	base_setting = nm_connection_get_setting_by_name (connection, connection_type);
	nm_assert (base_setting);
	editor = nm_meta_setting_info_editor_find_by_setting (base_setting);
	nm_assert (editor);

	return editor - nm_meta_setting_infos_editor;
}

static void
questionnaire_mandatory_ask_setting (NmCli *nmc, NMConnection *connection, NMMetaSettingType type)
{
	const NMMetaSettingInfoEditor *editor;
	const NMMetaPropertyInfo *property_info;
	guint p;

	editor = &nm_meta_setting_infos_editor[type];
	if (!editor->properties)
		return;

	for (p = 0; editor->properties[p]; p++) {
		property_info = editor->properties[p];

		if (_meta_property_needs_bond_hack (property_info)) {
			guint i;

			for (i = 0; i < nm_meta_property_typ_data_bond.nested_len; i++) {
				const NMMetaNestedPropertyInfo *bi = &nm_meta_property_typ_data_bond.nested[i];

				if (!option_relevant (connection, (const NMMetaAbstractInfo *) bi))
					continue;
				if (   (bi->base.inf_flags & NM_META_PROPERTY_INF_FLAG_REQD)
				    || (_dynamic_options_get ((const NMMetaAbstractInfo *) bi) & PROPERTY_INF_FLAG_ENABLED))
					ask_option (nmc, connection, (const NMMetaAbstractInfo *) bi);
			}
		} else {
			if (!property_info->is_cli_option)
				continue;

			if (!option_relevant (connection, (const NMMetaAbstractInfo *) property_info))
				continue;
			if (   (property_info->inf_flags & NM_META_PROPERTY_INF_FLAG_REQD)
			    || (_dynamic_options_get ((const NMMetaAbstractInfo *) property_info) & PROPERTY_INF_FLAG_ENABLED))
				ask_option (nmc, connection, (const NMMetaAbstractInfo *) property_info);
		}
	}
}

static void
questionnaire_mandatory (NmCli *nmc, NMConnection *connection)
{
	NMMetaSettingType s, base;

	/* First ask connection properties */
	questionnaire_mandatory_ask_setting (nmc, connection, NM_META_SETTING_TYPE_CONNECTION);

	/* Ask properties of the base setting */
	base = connection_get_base_meta_setting_type (connection);
	questionnaire_mandatory_ask_setting (nmc, connection, base);

	/* Remaining settings */
	for (s = 0; s < _NM_META_SETTING_TYPE_NUM; s++) {
		if (!NM_IN_SET (s, NM_META_SETTING_TYPE_CONNECTION, base))
			questionnaire_mandatory_ask_setting (nmc, connection, s);
	}
}

static gboolean
want_provide_opt_args (const NmcConfig *nmc_config,
                       const char *type,
                       guint num)
{
	gs_free char *answer = NULL;

	/* Ask for optional arguments. */
	g_print (ngettext ("There is %d optional setting for %s.\n",
	                   "There are %d optional settings for %s.\n",
	                   num),
	         (int) num,
	         type);
	answer = nmc_readline (nmc_config,
	                       ngettext ("Do you want to provide it? %s",
	                                 "Do you want to provide them? %s",
	                                 num),
	                       prompt_yes_no (TRUE, NULL));
	nm_strstrip (answer);
	return !answer || matches (answer, WORD_YES);
}

static gboolean
questionnaire_one_optional (NmCli *nmc, NMConnection *connection)
{
	NMMetaSettingType base;
	gs_unref_ptrarray GPtrArray *infos = NULL;
	guint i, j;
	gboolean already_confirmed = FALSE;
	NMMetaSettingType s_asking = NM_META_SETTING_TYPE_UNKNOWN;
	NMMetaSettingType settings[_NM_META_SETTING_TYPE_NUM];

	base = connection_get_base_meta_setting_type (connection);

	i = 0;
	settings[i++] = NM_META_SETTING_TYPE_CONNECTION;
	settings[i++] = base;
	for (j = 0; j < _NM_META_SETTING_TYPE_NUM; j++) {
		if (!NM_IN_SET (j, NM_META_SETTING_TYPE_CONNECTION, base))
			settings[i++] = j;
	}

	infos = g_ptr_array_new ();

	/* Find first setting with relevant options and count them. */
again:
	for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++) {
		const NMMetaPropertyInfo *const*property_infos;
		guint p;

		if (   s_asking != NM_META_SETTING_TYPE_UNKNOWN
		    && settings[i] != s_asking)
			continue;

		property_infos = nm_meta_setting_infos_editor[settings[i]].properties;
		if (!property_infos)
			continue;
		for (p = 0; property_infos[p]; p++) {
			const NMMetaPropertyInfo *property_info = property_infos[p];

			if (_meta_property_needs_bond_hack (property_info)) {
				for (j = 0; j < nm_meta_property_typ_data_bond.nested_len; j++) {
					const NMMetaNestedPropertyInfo *bi = &nm_meta_property_typ_data_bond.nested[j];

					if (!option_relevant (connection, (const NMMetaAbstractInfo *) bi))
						continue;
					g_ptr_array_add (infos, (gpointer) bi);
				}
			} else {
				if (!property_info->is_cli_option)
					continue;
				if (!option_relevant (connection, (const NMMetaAbstractInfo *) property_info))
					continue;
				g_ptr_array_add (infos, (gpointer) property_info);
			}
		}
		if (infos->len) {
			s_asking = settings[i];
			break;
		}
	}

	if (infos->len) {
		const NMMetaSettingInfoEditor *setting_info = NULL;

		_meta_abstract_get (infos->pdata[0], &setting_info, NULL, NULL, NULL, NULL, NULL, NULL);

		/* Now ask for the settings. */
		if (   already_confirmed
		    || want_provide_opt_args (&nmc->nmc_config,
		                              _(setting_info->pretty_name),
		                              infos->len)) {
			ask_option (nmc, connection, infos->pdata[0]);
			already_confirmed = TRUE;
			/* asking for an option may enable other options. Create the list again. */
			g_ptr_array_set_size (infos, 0);
			goto again;
		}
	}

	if (s_asking == NM_META_SETTING_TYPE_UNKNOWN)
		return FALSE;

	/* Make sure we won't ask again. */
	disable_options (nm_meta_setting_infos[s_asking].setting_name, NULL);
	return TRUE;
}

static NMCResultCode
do_connection_add (NmCli *nmc, int argc, char **argv)
{
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	gs_free_error GError *error = NULL;
	AddConnectionInfo *info = NULL;
	gboolean save_bool = TRUE;
	gboolean seen_dash_dash = FALSE;
	NMMetaSettingType s;

	next_arg (nmc, &argc, &argv, NULL);

	rl_attempted_completion_function = nmcli_con_add_tab_completion;

	nmc->return_value = NMC_RESULT_SUCCESS;

	connection = nm_simple_connection_new ();

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

read_properties:
	g_clear_error (&error);
	/* Get the arguments from the command line if any */
	if (argc && !nmc_read_connection_properties (nmc, connection, &argc, &argv, &error)) {
		if (g_strcmp0 (*argv, "--") == 0 && !seen_dash_dash) {
			/* This is for compatibility with older nmcli that required
			 * options and properties to be separated with "--" */
			seen_dash_dash = TRUE;
			next_arg (nmc, &argc, &argv, NULL);
			goto read_properties;
		} else if (g_strcmp0 (*argv, "save") == 0) {
			/* It would be better if "save" was a separate argument and not
			 * mixed with properties, but there's not much we can do about it now. */
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text,
				                 _("Error: value for '%s' argument is required."),
				                "save");
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
			g_clear_error (&error);
			if (!nmc_string_to_bool (*argv, &save_bool, &error)) {
				g_string_printf (nmc->return_text, _("Error: 'save': %s."),
				                 error->message);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
			next_arg (nmc, &argc, &argv, NULL);
			goto read_properties;
		}

		g_string_assign (nmc->return_text, error->message);
		nmc->return_value = error->code;
		goto finish;
	}

	if (nmc->complete)
		goto finish;

	/* Now ask user for the rest of the mandatory options. */
	if (nmc->ask)
		questionnaire_mandatory (nmc, connection);

	/* Traditionally, we didn't ask for these options for ethernet slaves. They don't
	 * make much sense, since these are likely to be set by the master anyway. */
	if (nm_setting_connection_get_slave_type (s_con)) {
		disable_options (NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_MTU);
		disable_options (NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_MAC_ADDRESS);
		disable_options (NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_CLONED_MAC_ADDRESS);
	}

	/* Connection id is special in that it's required but we don't insist
	 * on getting it from the user -- we just make up something sensible. */
	if (!nm_setting_connection_get_id (s_con)) {
		const char *ifname = nm_setting_connection_get_interface_name (s_con);
		const char *type = nm_setting_connection_get_connection_type (s_con);
		const char *slave_type = nm_setting_connection_get_slave_type (s_con);
		char *try_name, *default_name;

		/* If only bother when there's a type, which is not guaranteed at this point.
		 * Otherwise the validation will fail anyway. */
		if (type) {
			const GPtrArray *connections;

			connections = nm_client_get_connections (nmc->client);
			try_name = ifname
			           ? g_strdup_printf ("%s-%s", get_name_alias_toplevel (type, slave_type), ifname)
			           : g_strdup (get_name_alias_toplevel (type, slave_type));
			default_name = nmc_unique_connection_name (connections, try_name);
			g_free (try_name);
			g_object_set (s_con, NM_SETTING_CONNECTION_ID, default_name, NULL);
			g_free (default_name);
		}
	}

	/* For some software connection types we generate the interface name for the user. */
	set_default_interface_name (nmc, s_con);

	/* Now see if there's something optional that needs to be asked for.
	 * Keep asking until there's no more things to ask for. */
	do {
		/* This ensures all settings that make sense are present. */
		nm_connection_normalize (connection, NULL, NULL, NULL);
	} while (nmc->ask && questionnaire_one_optional (nmc, connection));

	/* Mandatory settings. No good reason to check this other than guarding the user
	 * from doing something that's not likely to make sense (such as missing ifname
	 * on a bond/bridge/team, etc.). Added just to preserve traditional behavior, it
	 * perhaps is a good idea to just remove this. */
	for (s = 0; s < _NM_META_SETTING_TYPE_NUM; s++) {
		const NMMetaPropertyInfo *const*property_infos;
		guint p;

		property_infos = nm_meta_setting_infos_editor[s].properties;
		if (!property_infos)
			continue;
		for (p = 0; property_infos[p]; p++) {
			const NMMetaPropertyInfo *property_info = property_infos[p];

			if (_meta_property_needs_bond_hack (property_info)) {
				guint i;

				for (i = 0; i < nm_meta_property_typ_data_bond.nested_len; i++) {
					const NMMetaNestedPropertyInfo *bi = &nm_meta_property_typ_data_bond.nested[i];

					if (!option_relevant (connection, (const NMMetaAbstractInfo *) bi))
						continue;
					if (bi->base.inf_flags & NM_META_PROPERTY_INF_FLAG_REQD) {
						g_string_printf (nmc->return_text, _("Error: '%s' argument is required."), bi->base.property_alias);
						nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
						goto finish;
					}
				}
			} else {
				if (!property_info->is_cli_option)
					continue;
				if (!option_relevant (connection, (const NMMetaAbstractInfo *) property_info))
					continue;
				if (property_info->inf_flags & NM_META_PROPERTY_INF_FLAG_REQD) {
					g_string_printf (nmc->return_text, _("Error: '%s' argument is required."), property_info->property_alias);
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					goto finish;
				}
			}
		}
	}

	nmc->should_wait++;

	info = g_malloc0 (sizeof (AddConnectionInfo));
	info->nmc = nmc;
	info->con_name = g_strdup (nm_connection_get_id (connection));

	/* Tell the settings service to add the new connection */
	add_new_connection (save_bool,
	                    nmc->client,
	                    connection,
	                    add_connection_cb,
	                    info);

finish:
	reset_options ();
	return nmc->return_value;
}

/*****************************************************************************/
/* Functions for readline TAB completion in editor */

static void
uuid_display_hook (char **array, int len, int max_len)
{
	const GPtrArray *connections;
	NMConnection *con;
	int i, max = 0;
	char *tmp;
	const char *id;
	for (i = 1; i <= len; i++) {
		connections = nm_client_get_connections (nmc_tab_completion.nmc->client);
		con = nmc_find_connection (connections, "uuid", array[i], NULL, FALSE);
		id = con ? nm_connection_get_id (con) : NULL;
		if (id) {
			tmp = g_strdup_printf ("%s (%s)", array[i], id);
			g_free (array[i]);
			array[i] = tmp;
			if (max < strlen (id))
				max = strlen (id);
		}
	}
	rl_display_match_list (array, len, max_len + max + 3);
	rl_forced_update_display ();
}

static char *
gen_nmcli_cmds_menu (const char *text, int state)
{
	const char *words[] = { "goto", "set", "remove", "describe", "print", "verify",
	                        "save", "activate", "back", "help", "quit", "nmcli",
	                        NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_nmcli_cmds_submenu (const char *text, int state)
{
	const char *words[] = { "set", "add", "change", "remove", "describe",
	                        "print", "back", "help", "quit",
	                        NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_cmd_nmcli (const char *text, int state)
{
	const char *words[] = { "status-line", "save-confirmation", "show-secrets", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_func_bool_values (const char *text, int state)
{
	const char *words[] = { "yes", "no", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_cmd_verify0 (const char *text, int state)
{
	const char *words[] = { "all", "fix", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_cmd_print0 (const char *text, int state)
{
	static char **words = NULL;
	char *ret = NULL;

	if (!state) {
		GVariant *settings;
		GVariantIter iter;
		const char *setting_name;
		int i = 0;

		settings = nm_connection_to_dbus (nmc_tab_completion.connection, NM_CONNECTION_SERIALIZE_NO_SECRETS);
		words = g_new (char *, g_variant_n_children (settings) + 2);
		g_variant_iter_init (&iter, settings);
		while (g_variant_iter_next (&iter, "{&s@a{sv}}", &setting_name, NULL))
			words [i++] = g_strdup (setting_name);
		words[i++] = g_strdup ("all");
		words[i] = NULL;
		g_variant_unref (settings);
	}

	if (words) {
		ret = nmc_rl_gen_func_basic (text, state, (const char **) words);
		if (ret == NULL) {
			g_strfreev (words);
			words = NULL;
		}
	}
	return ret;
}

static char *
gen_cmd_print2 (const char *text, int state)
{
	const char *words[] = { "setting", "connection", "all", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_cmd_save (const char *text, int state)
{
	const char *words[] = { "persistent", "temporary", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static rl_compentry_func_t *
gen_connection_types (const char *text)
{
	gs_free char **values = NULL;
	const NMMetaSettingInfoEditor *editor;
	GPtrArray *array;
	int i;

	array = g_ptr_array_new ();

	for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++) {
		editor = &nm_meta_setting_infos_editor[i];
		if (!editor->valid_parts)
			continue;
		g_ptr_array_add (array, (gpointer) nm_meta_setting_infos[i].setting_name);
		if (editor->alias)
			g_ptr_array_add (array, (gpointer) editor->alias);
	}

	g_ptr_array_add (array, "bond-slave");
	g_ptr_array_add (array, "bridge-slave");
	g_ptr_array_add (array, "team-slave");
	g_ptr_array_add (array, NULL);

	values = (char **) g_ptr_array_free (array, FALSE);

	return nmc_rl_compentry_func_wrap ((const char *const*) values);
}

static char *
gen_setting_names (const char *text, int state)
{
	static int list_idx, len, is_slv;
	const char *s_name, *a_name;
	const NMMetaSettingValidPartItem *const*valid_settings_arr;
	NMSettingConnection *s_con;
	const char *s_type = NULL;

	if (!state) {
		list_idx = 0;
		len = strlen (text);
		is_slv = 0;
	}

	if (!is_slv) {
		valid_settings_arr = get_valid_settings_array (nmc_tab_completion.con_type);
		if (list_idx >= NM_PTRARRAY_LEN (valid_settings_arr))
			return NULL;
		for (; valid_settings_arr[list_idx];) {
			const NMMetaSettingInfoEditor *setting_info = valid_settings_arr[list_idx]->setting_info;

			a_name = setting_info->alias;
			s_name = setting_info->general->setting_name;
			list_idx++;
			if (len == 0 && a_name)
				return g_strdup_printf ("%s (%s)", s_name, a_name);
			if (a_name && !strncmp (text, a_name, len))
				return g_strdup (a_name);
			if (s_name && !strncmp (text, s_name, len))
				return g_strdup (s_name);
		}

		/* Let's give a try to parameters related to slave type */
		list_idx = 0;
		is_slv = 1;
	}

	/* is_slv */
	s_con = nm_connection_get_setting_connection (nmc_tab_completion.connection);
	if (s_con)
		s_type = nm_setting_connection_get_slave_type (s_con);
	valid_settings_arr = nm_meta_setting_info_valid_parts_for_slave_type (s_type, NULL);

	if (list_idx < NM_PTRARRAY_LEN (valid_settings_arr)) {
		while (valid_settings_arr[list_idx]) {
			const NMMetaSettingInfoEditor *setting_info = valid_settings_arr[list_idx]->setting_info;

			a_name = setting_info->alias;
			s_name = setting_info->general->setting_name;
			list_idx++;
			if (len == 0 && a_name)
				return g_strdup_printf ("%s (%s)", s_name, a_name);
			if (a_name && !strncmp (text, a_name, len))
				return g_strdup (a_name);
			if (s_name && !strncmp (text, s_name, len))
				return g_strdup (s_name);
		}
	}

	return NULL;
}

static char *
gen_property_names (const char *text, int state)
{
	NMSetting *setting = NULL;
	char **valid_props = NULL;
	char *ret = NULL;
	const char *line = rl_line_buffer;
	const char *setting_name;
	char **strv = NULL;
	const NMMetaSettingValidPartItem *const*valid_settings_main;
	const NMMetaSettingValidPartItem *const*valid_settings_slave;
	const char *p1;
	const char *slv_type;

	/* Try to get the setting from 'line' - setting_name.property */
	p1 = strchr (line, '.');
	if (p1) {
		while (p1 > line && !g_ascii_isspace (*p1))
			p1--;

		strv = g_strsplit (p1 + 1, ".", 2);

		valid_settings_main = get_valid_settings_array (nmc_tab_completion.con_type);

		/* Support autocompletion of slave-connection parameters
		 * guessing the slave type from the setting name already
		 * typed (or autocompleted) */
		if (nm_streq0 (strv[0], NM_SETTING_TEAM_PORT_SETTING_NAME))
			slv_type = NM_SETTING_TEAM_SETTING_NAME;
		else if (nm_streq0 (strv[0], NM_SETTING_BRIDGE_PORT_SETTING_NAME))
			slv_type = NM_SETTING_BRIDGE_SETTING_NAME;
		else
			slv_type = NULL;
		valid_settings_slave = nm_meta_setting_info_valid_parts_for_slave_type (slv_type, NULL);

		setting_name = check_valid_name (strv[0],
		                                 valid_settings_main,
		                                 valid_settings_slave,
		                                 NULL);
		if (setting_name) {
			setting = nm_meta_setting_info_editor_new_setting (nm_meta_setting_info_editor_find_by_name (setting_name, FALSE),
			                                                   NM_META_ACCESSOR_SETTING_INIT_TYPE_DEFAULT);
		}
	}

	if (!setting) {
		/* Else take the current setting, if any */
		setting = nmc_tab_completion.setting ? g_object_ref (nmc_tab_completion.setting) : NULL;
	}

	if (setting) {
		valid_props = nmc_setting_get_valid_properties (setting);
		ret = nmc_rl_gen_func_basic (text, state, (const char **) valid_props);
	}

	g_strfreev (strv);
	g_strfreev (valid_props);
	if (setting)
		g_object_unref (setting);
	return ret;
}

static char *
gen_compat_devices (const char *text, int state)
{
	int i, j = 0;
	const GPtrArray *devices;
	const char **compatible_devices;
	char *ret;

	devices = nm_client_get_devices (nmc_tab_completion.nmc->client);
	if (devices->len == 0)
		return NULL;

	compatible_devices = g_new (const char *, devices->len + 1);
	for (i = 0; i < devices->len; i++) {
		NMDevice *dev = g_ptr_array_index (devices, i);
		const char *ifname = nm_device_get_iface (dev);
		NMDevice *device = NULL;
		const char *spec_object = NULL;

		if (find_device_for_connection (nmc_tab_completion.nmc, nmc_tab_completion.connection,
		                                ifname, NULL, NULL, &device, &spec_object, NULL)) {
			compatible_devices[j++] = ifname;
		}
	}
	compatible_devices[j] = NULL;

	ret = nmc_rl_gen_func_basic (text, state, compatible_devices);

	g_free (compatible_devices);
	return ret;
}

static const char **
_create_vpn_array (const GPtrArray *connections, gboolean uuid)
{
	int c, idx = 0;
	const char **array;

	if (connections->len < 1)
		return NULL;

	array = g_new (const char *, connections->len + 1);
	for (c = 0; c < connections->len; c++) {
		NMConnection *connection = NM_CONNECTION (connections->pdata[c]);
		const char *type = nm_connection_get_connection_type (connection);

		if (g_strcmp0 (type, NM_SETTING_VPN_SETTING_NAME) == 0)
			array[idx++] = uuid ? nm_connection_get_uuid (connection) : nm_connection_get_id (connection);
	}
	array[idx] = NULL;
	return array;
}

static char *
gen_vpn_uuids (const char *text, int state)
{
	const GPtrArray *connections;
	const char **uuids;
	char *ret;

	connections = nm_client_get_connections (nm_cli.client);
	if (connections->len < 1)
		return NULL;

	uuids = _create_vpn_array (connections, TRUE);
	ret = nmc_rl_gen_func_basic (text, state, uuids);
	g_free (uuids);
	return ret;
}

static char *
gen_vpn_ids (const char *text, int state)
{
	const GPtrArray *connections;
	const char **ids;
	char *ret;

	connections = nm_client_get_connections (nm_cli.client);
	if (connections->len < 1)
		return NULL;

	ids = _create_vpn_array (connections, FALSE);
	ret = nmc_rl_gen_func_basic (text, state, ids);
	g_free (ids);
	return ret;
}

static rl_compentry_func_t *
get_gen_func_cmd_nmcli (const char *str)
{
	if (!str)
		return NULL;
	if (matches (str, "status-line"))
		return gen_func_bool_values;
	if (matches (str, "save-confirmation"))
		return gen_func_bool_values;
	if (matches (str, "show-secrets"))
		return gen_func_bool_values;
	return NULL;
}

/*
 * Helper function parsing line for completion.
 * IN:
 *   line : the whole line to be parsed
 *   end  : the position of cursor in the line
 *   cmd  : command to match
 * OUT:
 *   cw_num    : is set to the word number being completed (1, 2, 3, 4).
 *   prev_word : returns the previous word (so that we have some context).
 *
 * Returns TRUE when the first word of the 'line' matches 'cmd'.
 *
 * Examples:
 * line="rem"              cmd="remove"   -> TRUE  cw_num=1
 * line="set con"          cmd="set"      -> TRUE  cw_num=2
 * line="go ipv4.method"   cmd="goto"     -> TRUE  cw_num=2
 * line="  des eth.mtu "   cmd="describe" -> TRUE  cw_num=3
 * line=" bla ipv4.method" cmd="goto"     -> FALSE
 */
static gboolean
should_complete_cmd (const char *line, int end, const char *cmd,
                     int *cw_num, char **prev_word)
{
	char *tmp;
	const char *word1, *word2, *word3;
	size_t n1, n2, n3, n4, n5, n6;
	gboolean word1_done, word2_done, word3_done;
	gboolean ret = FALSE;

	if (!line)
		return FALSE;

	tmp = g_strdup (line);

	n1 = strspn  (tmp,    " \t");
	n2 = strcspn (tmp+n1, " \t\0") + n1;
	n3 = strspn  (tmp+n2, " \t")   + n2;
	n4 = strcspn (tmp+n3, " \t\0") + n3;
	n5 = strspn  (tmp+n4, " \t")   + n4;
	n6 = strcspn (tmp+n5, " \t\0") + n5;

	word1_done = end > n2;
	word2_done = end > n4;
	word3_done = end > n6;
	tmp[n2] = tmp[n4] = tmp[n6] = '\0';

	word1 = tmp[n1] ? tmp + n1 : NULL;
	word2 = tmp[n3] ? tmp + n3 : NULL;
	word3 = tmp[n5] ? tmp + n5 : NULL;

	if (!word1_done) {
		if (cw_num)
			*cw_num = 1;
		if (prev_word)
			*prev_word = NULL;
	} else if (!word2_done) {
		if (cw_num)
			*cw_num = 2;
		if (prev_word)
			*prev_word = g_strdup (word1);
	} else if (!word3_done) {
		if (cw_num)
			*cw_num = 3;
		if (prev_word)
			*prev_word = g_strdup (word2);
	} else {
		if (cw_num)
			*cw_num = 4;
		if (prev_word)
			*prev_word = g_strdup (word3);
	}

	if (word1 && matches (word1, cmd))
		ret = TRUE;

	g_free (tmp);
	return ret;
}

/*
 * extract_setting_and_property:
 * prompt: (in) (allow-none): prompt string, or NULL
 * line: (in) (allow-none): line, or NULL
 * setting: (out) (transfer full) (array zero-terminated=1):
 *   return location for setting name
 * property: (out) (transfer full) (array zero-terminated=1):
 *   return location for property name
 *
 * Extract setting and property names from prompt and/or line.
 */
static void
extract_setting_and_property (const char *prompt, const char *line,
                              char **setting, char **property)
{
	char *prop = NULL;
	char *sett = NULL;

	if (prompt) {
		/* prompt looks like this:
		  "nmcli 802-1x>" or "nmcli 802-1x.pac-file>" */
		const char *p1, *p2, *dot;
		size_t num1, num2;
		p1 = strchr (prompt, ' ');
		if (p1) {
			dot = strchr (++p1, '.');
			if (dot) {
				p2 = dot + 1;
				num1 = strcspn (p1, ".");
				num2 = strcspn (p2, ">");
				sett = num1 > 0 ? g_strndup (p1, num1) : NULL;
				prop = num2 > 0 ? g_strndup (p2, num2) : NULL;
			} else {
				num1 = strcspn (p1, ">");
				sett = num1 > 0 ? g_strndup (p1, num1) : NULL;
			}
		}
	}

	if (line) {
		/* line looks like this:
		  " set 802-1x.pac-file ..." or " set pac-file ..." */
		const char *p1, *p2, *dot;
		size_t n1, n2, n3, n4;
		size_t num1, num2, len;
		n1 = strspn  (line,    " \t");         /* white-space */
		n2 = strcspn (line+n1, " \t\0") + n1;  /* command */
		n3 = strspn  (line+n2, " \t")   + n2;  /* white-space */
		n4 = strcspn (line+n3, " \t\0") + n3;  /* setting/property */
		p1 = line + n3;
		len = n4 - n3;

		dot = strchr (p1, '.');
		if (dot && dot < p1 + len) {
			p2 = dot + 1;
			num1 = strcspn (p1, ".");
			num2 = len > num1 + 1 ? len - num1 - 1 : 0;
			sett = num1 > 0 ? g_strndup (p1, num1) : sett;
			prop = num2 > 0 ? g_strndup (p2, num2) : prop;
		} else {
			if (!prop)
				prop = len > 0 ? g_strndup (p1, len) : NULL;
		}
	}

	if (setting)
		*setting = sett;
	else
		g_free (sett);
	if (property)
		*property = prop;
	else
		g_free (prop);
}

static void
get_setting_and_property (const char *prompt, const char *line,
                          NMSetting **setting_out, char**property_out)
{
	const NMMetaSettingValidPartItem *const*valid_settings_main;
	const NMMetaSettingValidPartItem *const*valid_settings_slave;
	const char *setting_name;
	NMSetting *setting = NULL;
	char *property = NULL;
	char *sett = NULL, *prop = NULL;
	NMSettingConnection *s_con;
	const char *s_type = NULL;

	extract_setting_and_property (prompt, line, &sett, &prop);
	if (sett) {
		/* Is this too much (and useless?) effort for an unlikely case? */
		s_con = nm_connection_get_setting_connection (nmc_tab_completion.connection);
		if (s_con)
			s_type = nm_setting_connection_get_slave_type (s_con);

		valid_settings_main = get_valid_settings_array (nmc_tab_completion.con_type);
		valid_settings_slave = nm_meta_setting_info_valid_parts_for_slave_type (s_type, NULL);

		setting_name = check_valid_name (sett, valid_settings_main,
		                                 valid_settings_slave,  NULL);
		setting = nm_meta_setting_info_editor_new_setting (nm_meta_setting_info_editor_find_by_name (setting_name, FALSE),
		                                                   NM_META_ACCESSOR_SETTING_INIT_TYPE_DEFAULT);
	} else
		setting = nmc_tab_completion.setting ? g_object_ref (nmc_tab_completion.setting) : NULL;

	if (setting && prop)
		property = is_property_valid (setting, prop, NULL);
	else
		property = g_strdup (nmc_tab_completion.property);

	*setting_out = setting;
	*property_out = property;

	g_free (sett);
	g_free (prop);
}

static gboolean
_get_and_check_property (const char *prompt,
                         const char *line,
                         const char **array,
                         const char **array_multi,
                         gboolean *multi)
{
	char *prop;
	gboolean found = FALSE;

	extract_setting_and_property (prompt, line, NULL, &prop);
	if (prop) {
		if (array)
			found = !!nmc_string_is_valid (prop, array, NULL);
		if (array_multi && multi)
			*multi = !!nmc_string_is_valid (prop, array_multi, NULL);
		g_free (prop);
	}
	return found;
}

static gboolean
should_complete_files (const char *prompt, const char *line)
{
	const char *file_properties[] = {
		/* '802-1x' properties */
		"ca-cert",
		"ca-path",
		"client-cert",
		"pac-file",
		"phase2-ca-cert",
		"phase2-ca-path",
		"phase2-client-cert",
		"private-key",
		"phase2-private-key",
		/* 'team' and 'team-port' properties */
		"config",
		/* 'proxy' properties */
		"pac-script",
		NULL
	};
	return _get_and_check_property (prompt, line, file_properties, NULL, NULL);
}

static gboolean
should_complete_vpn_uuids (const char *prompt, const char *line)
{
	const char *uuid_properties[] = {
		/* 'connection' properties */
		"secondaries",
		NULL
	};
	return _get_and_check_property (prompt, line, uuid_properties, NULL, NULL);
}

static const char *const*
get_allowed_property_values (char ***out_to_free)
{
	gs_unref_object NMSetting *setting = NULL;
	gs_free char *property = NULL;
	const char *const*avals = NULL;

	get_setting_and_property (rl_prompt, rl_line_buffer, &setting, &property);
	if (setting && property)
		avals = nmc_setting_get_property_allowed_values (setting, property, out_to_free);
	return avals;
}

static gboolean
should_complete_property_values (const char *prompt, const char *line, gboolean *multi)
{
	gs_strfreev char **to_free = NULL;

	/* properties allowing multiple values */
	const char *multi_props[] = {
		/* '802-1x' properties */
		NM_SETTING_802_1X_EAP,
		/* '802-11-wireless-security' properties */
		NM_SETTING_WIRELESS_SECURITY_PROTO,
		NM_SETTING_WIRELESS_SECURITY_PAIRWISE,
		NM_SETTING_WIRELESS_SECURITY_GROUP,
		/* 'bond' properties */
		NM_SETTING_BOND_OPTIONS,
		/* 'ethernet' properties */
		NM_SETTING_WIRED_S390_OPTIONS,
		NULL
	};
	_get_and_check_property (prompt, line, NULL, multi_props, multi);
	return !!get_allowed_property_values (&to_free);
}

static gboolean
_setting_property_is_boolean (NMSetting *setting, const char *property_name)
{
	GParamSpec *pspec;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (property_name, FALSE);

	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), property_name);
	if (pspec && pspec->value_type == G_TYPE_BOOLEAN)
		return TRUE;
	return FALSE;
}

static gboolean
should_complete_boolean (const char *prompt, const char *line)
{
	NMSetting *setting;
	char *property;
	gboolean is_boolean = FALSE;

	get_setting_and_property (prompt, line, &setting, &property);
	if (setting && property)
		is_boolean = _setting_property_is_boolean (setting, property);

	if (setting)
		g_object_unref (setting);
	g_free (property);

	return is_boolean;
}

static char *
gen_property_values (const char *text, int state)
{
	gs_strfreev char **to_free = NULL;
	const char *const*avals;

	avals = get_allowed_property_values (&to_free);
	if (!avals)
		return NULL;
	return nmc_rl_gen_func_basic (text, state, avals);
}

/* from readline */
extern int rl_complete_with_tilde_expansion;

/*
 * Attempt to complete on the contents of TEXT.  START and END show the
 * region of TEXT that contains the word to complete.  We can use the
 * entire line in case we want to do some simple parsing.  Return the
 * array of matches, or NULL if there aren't any.
 */
static char **
nmcli_editor_tab_completion (const char *text, int start, int end)
{
	char **match_array = NULL;
	const char *line = rl_line_buffer;
	rl_compentry_func_t *generator_func = NULL;
	char *prompt_tmp;
	char *word = NULL;
	size_t n1;
	int num;

	/* Restore standard append character to space */
	rl_completion_append_character = ' ';

	/* Restore standard function for displaying matches */
	rl_completion_display_matches_hook = NULL;

	/* Disable default filename completion */
	rl_attempted_completion_over = 1;

	/* Enable tilde expansion when filenames are completed */
	rl_complete_with_tilde_expansion = 1;

	/* Filter out possible ANSI color escape sequences */
	prompt_tmp = nmc_filter_out_colors ((const char *) rl_prompt);

	/* Find the first non-space character */
	n1 = strspn (line, " \t");

	/* Choose the right generator function */
	if (strcmp (prompt_tmp, EDITOR_PROMPT_CON_TYPE) == 0)
		generator_func = gen_connection_types (text);
	else if (strcmp (prompt_tmp, EDITOR_PROMPT_SETTING) == 0)
		generator_func = gen_setting_names;
	else if (strcmp (prompt_tmp, EDITOR_PROMPT_PROPERTY) == 0)
		generator_func = gen_property_names;
	else if (   g_str_has_suffix (rl_prompt, prompt_yes_no (TRUE, NULL))
	         || g_str_has_suffix (rl_prompt, prompt_yes_no (FALSE, NULL)))
		generator_func = gen_func_bool_values_l10n;
	else if (g_str_has_prefix (prompt_tmp, "nmcli")) {
		if (!strchr (prompt_tmp, '.')) {
			int level = g_str_has_prefix (prompt_tmp, "nmcli>") ? 0 : 1;
			const char *dot = strchr (line, '.');
			gboolean multi;

			/* Main menu  - level 0,1 */
			if (start == n1)
				generator_func = gen_nmcli_cmds_menu;
			else {
				if (should_complete_cmd (line, end, "goto", &num, NULL) && num <= 2) {
					if (level == 0 && (!dot || dot >= line + end))
						generator_func = gen_setting_names;
					else
						generator_func = gen_property_names;
				} else if (should_complete_cmd (line, end, "set", &num, NULL)) {
					if (num < 3) {
						if (level == 0 && (!dot || dot >= line + end)) {
							generator_func = gen_setting_names;
							rl_completion_append_character = '.';
						} else
							generator_func = gen_property_names;
					} else if (num >= 3) {
						if (num == 3 && should_complete_files (NULL, line))
							rl_attempted_completion_over = 0;
						else if (should_complete_vpn_uuids (NULL, line)) {
							rl_completion_display_matches_hook = uuid_display_hook;
							generator_func = gen_vpn_uuids;
						} else if (   should_complete_property_values (NULL, line, &multi)
							   && (num == 3 || multi)) {
							generator_func = gen_property_values;
						} else if (should_complete_boolean (NULL, line) && num == 3)
							generator_func = gen_func_bool_values;
					}
				} else if (  (   should_complete_cmd (line, end, "remove", &num, NULL)
				              || should_complete_cmd (line, end, "describe", &num, NULL))
				           && num <= 2) {
					if (level == 0 && (!dot || dot >= line + end)) {
						generator_func = gen_setting_names;
						rl_completion_append_character = '.';
					} else
						generator_func = gen_property_names;
				} else if (should_complete_cmd (line, end, "nmcli", &num, &word)) {
					if (num < 3)
						generator_func = gen_cmd_nmcli;
					else if (num == 3)
						generator_func = get_gen_func_cmd_nmcli (word);
				} else if (should_complete_cmd (line, end, "print", &num, NULL) && num <= 2) {
					if (level == 0 && (!dot || dot >= line + end))
						generator_func = gen_cmd_print0;
					else
						generator_func = gen_property_names;
				} else if (should_complete_cmd (line, end, "verify", &num, NULL) && num <= 2) {
					generator_func = gen_cmd_verify0;
				} else if (should_complete_cmd (line, end, "activate", &num, NULL) && num <= 2) {
					generator_func = gen_compat_devices;
				} else if (should_complete_cmd (line, end, "save", &num, NULL) && num <= 2) {
					generator_func = gen_cmd_save;
				} else if (should_complete_cmd (line, end, "help", &num, NULL) && num <= 2)
					generator_func = gen_nmcli_cmds_menu;
			}
		} else {
			/* Submenu - level 2 */
			if (start == n1)
				generator_func = gen_nmcli_cmds_submenu;
			else {
				gboolean multi;

				if (   should_complete_cmd (line, end, "add", &num, NULL)
				    || should_complete_cmd (line, end, "set", &num, NULL)) {
					if (num <= 2 && should_complete_files (prompt_tmp, line))
						rl_attempted_completion_over = 0;
					else if (should_complete_vpn_uuids (prompt_tmp, line)) {
						rl_completion_display_matches_hook = uuid_display_hook;
						generator_func = gen_vpn_uuids;
					} else if (   should_complete_property_values (prompt_tmp, NULL, &multi)
						   && (num <= 2 || multi)) {
						generator_func = gen_property_values;
					} else if (should_complete_boolean (prompt_tmp, NULL) && num <= 2)
						generator_func = gen_func_bool_values;
				}
				if (should_complete_cmd (line, end, "print", &num, NULL) && num <= 2)
					generator_func = gen_cmd_print2;
				else if (should_complete_cmd (line, end, "help", &num, NULL) && num <= 2)
					generator_func = gen_nmcli_cmds_submenu;
			}
		}
	}

	if (generator_func)
		match_array = rl_completion_matches (text, generator_func);

	g_free (prompt_tmp);
	g_free (word);
	return match_array;
}

#define NMCLI_EDITOR_HISTORY ".nmcli-history"

static void
load_history_cmds (const char *uuid)
{
	GKeyFile *kf;
	char *filename;
	char **keys;
	char *line;
	size_t i;
	GError *err = NULL;

	filename = g_build_filename (g_get_home_dir (), NMCLI_EDITOR_HISTORY, NULL);
	kf = g_key_file_new ();
	if (!g_key_file_load_from_file (kf, filename, G_KEY_FILE_KEEP_COMMENTS, &err)) {
		if (g_error_matches (err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE))
			g_print ("Warning: %s parse error: %s\n", filename, err->message);
		g_key_file_free (kf);
		g_free (filename);
		return;
	}
	keys = g_key_file_get_keys (kf, uuid, NULL, NULL);
	for (i = 0; keys && keys[i]; i++) {
		line = g_key_file_get_string (kf, uuid, keys[i], NULL);
		if (line && *line)
			add_history (line);
		g_free (line);
	}
	g_strfreev (keys);
	g_key_file_free (kf);
	g_free (filename);
}

static void
save_history_cmds (const char *uuid)
{
	HIST_ENTRY **hist = NULL;
	GKeyFile *kf;
	char *filename;
	size_t i;
	char *key;
	char *data;
	gsize len = 0;
	GError *err = NULL;

	hist = history_list ();
	if (hist) {
		filename = g_build_filename (g_get_home_dir (), NMCLI_EDITOR_HISTORY, NULL);
		kf = g_key_file_new ();
		if (!g_key_file_load_from_file (kf, filename, G_KEY_FILE_KEEP_COMMENTS, &err)) {
			if (   !g_error_matches (err, G_FILE_ERROR, G_FILE_ERROR_NOENT)
			    && !g_error_matches (err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND)) {
				g_print ("Warning: %s parse error: %s\n", filename, err->message);
				g_key_file_free (kf);
				g_free (filename);
				g_clear_error (&err);
				return;
			}
			g_clear_error (&err);
		}

		/* Remove previous history group and save new history entries */
		g_key_file_remove_group (kf, uuid, NULL);
		for (i = 0; hist[i]; i++)
		{
			key = g_strdup_printf ("%zd", i);
			g_key_file_set_string (kf, uuid, key, hist[i]->line);
			g_free (key);
		}

		/* Write history to file */
		data = g_key_file_to_data (kf, &len, NULL);
		if (data) {
			g_file_set_contents (filename, data, len, NULL);
			g_free (data);
		}
		g_key_file_free (kf);
		g_free (filename);
	}
}

/*****************************************************************************/

static void
editor_show_connection (NMConnection *connection, NmCli *nmc)
{
	nmc->nmc_config_mutable.print_output = NMC_PRINT_PRETTY;
	nmc->nmc_config_mutable.multiline_output = TRUE;
	nmc->nmc_config_mutable.escape_values = 0;

	nmc_connection_profile_details (connection, nmc);
}

static void
editor_show_setting (NMSetting *setting, NmCli *nmc)
{
	g_print (_("['%s' setting values]\n"),
	         nm_setting_get_name (setting));

	nmc->nmc_config_mutable.print_output = NMC_PRINT_NORMAL;
	nmc->nmc_config_mutable.multiline_output = TRUE;
	nmc->nmc_config_mutable.escape_values = 0;

	setting_details (&nmc->nmc_config, setting, NULL);
}

typedef enum {
	NMC_EDITOR_MAIN_CMD_UNKNOWN = 0,
	NMC_EDITOR_MAIN_CMD_GOTO,
	NMC_EDITOR_MAIN_CMD_REMOVE,
	NMC_EDITOR_MAIN_CMD_SET,
	NMC_EDITOR_MAIN_CMD_DESCRIBE,
	NMC_EDITOR_MAIN_CMD_PRINT,
	NMC_EDITOR_MAIN_CMD_VERIFY,
	NMC_EDITOR_MAIN_CMD_SAVE,
	NMC_EDITOR_MAIN_CMD_ACTIVATE,
	NMC_EDITOR_MAIN_CMD_BACK,
	NMC_EDITOR_MAIN_CMD_HELP,
	NMC_EDITOR_MAIN_CMD_NMCLI,
	NMC_EDITOR_MAIN_CMD_QUIT,
} NmcEditorMainCmd;

static void
_split_cmd (const char *cmd, char **out_arg0, const char **out_argr)
{
	gs_free char *arg0 = NULL;
	const char *argr = NULL;
	gsize l;

	NM_SET_OUT (out_arg0, NULL);
	NM_SET_OUT (out_argr, NULL);

	if (!cmd)
		return;
	while (nm_utils_is_separator (cmd[0]))
		cmd++;
	if (!cmd[0])
		return;

	l = strcspn (cmd, " \t");
	arg0 = g_strndup (cmd, l);
	cmd += l;
	if (cmd[0]) {
		while (nm_utils_is_separator (cmd[0]))
			cmd++;
		if (cmd[0])
			argr = cmd;
	}

	NM_SET_OUT (out_arg0, g_steal_pointer (&arg0));
	NM_SET_OUT (out_argr, argr);
}

static NmcEditorMainCmd
parse_editor_main_cmd (const char *cmd, char **cmd_arg)
{
	NmcEditorMainCmd editor_cmd = NMC_EDITOR_MAIN_CMD_UNKNOWN;
	gs_free char *cmd_arg0 = NULL;
	const char *cmd_argr;

	_split_cmd (cmd, &cmd_arg0, &cmd_argr);
	if (!cmd_arg0)
		goto fail;

	if (matches (cmd_arg0, "goto"))
		editor_cmd = NMC_EDITOR_MAIN_CMD_GOTO;
	else if (matches (cmd_arg0, "remove"))
		editor_cmd = NMC_EDITOR_MAIN_CMD_REMOVE;
	else if (matches (cmd_arg0, "set"))
		editor_cmd = NMC_EDITOR_MAIN_CMD_SET;
	else if (matches (cmd_arg0, "describe"))
		editor_cmd = NMC_EDITOR_MAIN_CMD_DESCRIBE;
	else if (matches (cmd_arg0, "print"))
		editor_cmd = NMC_EDITOR_MAIN_CMD_PRINT;
	else if (matches (cmd_arg0, "verify"))
		editor_cmd = NMC_EDITOR_MAIN_CMD_VERIFY;
	else if (matches (cmd_arg0, "save"))
		editor_cmd = NMC_EDITOR_MAIN_CMD_SAVE;
	else if (matches (cmd_arg0, "activate"))
		editor_cmd = NMC_EDITOR_MAIN_CMD_ACTIVATE;
	else if (matches (cmd_arg0, "back"))
		editor_cmd = NMC_EDITOR_MAIN_CMD_BACK;
	else if (matches (cmd_arg0, "help") || strcmp (cmd_arg0, "?") == 0)
		editor_cmd = NMC_EDITOR_MAIN_CMD_HELP;
	else if (matches (cmd_arg0, "quit"))
		editor_cmd = NMC_EDITOR_MAIN_CMD_QUIT;
	else if (matches (cmd_arg0, "nmcli"))
		editor_cmd = NMC_EDITOR_MAIN_CMD_NMCLI;
	else
		goto fail;

	NM_SET_OUT (cmd_arg, g_strdup (cmd_argr));
	return editor_cmd;
fail:
	NM_SET_OUT (cmd_arg, NULL);
	return NMC_EDITOR_MAIN_CMD_UNKNOWN;
}

static void
editor_main_usage (void)
{
	g_print ("------------------------------------------------------------------------------\n");
	/* TRANSLATORS: do not translate command names and keywords before ::
	 *              However, you should translate terms enclosed in <>.
	 */
	g_print (_("---[ Main menu ]---\n"
	           "goto     [<setting> | <prop>]        :: go to a setting or property\n"
	           "remove   <setting>[.<prop>] | <prop> :: remove setting or reset property value\n"
	           "set      [<setting>.<prop> <value>]  :: set property value\n"
	           "describe [<setting>.<prop>]          :: describe property\n"
	           "print    [all | <setting>[.<prop>]]  :: print the connection\n"
	           "verify   [all | fix]                 :: verify the connection\n"
	           "save     [persistent|temporary]      :: save the connection\n"
	           "activate [<ifname>] [/<ap>|<nsp>]    :: activate the connection\n"
	           "back                                 :: go one level up (back)\n"
	           "help/?   [<command>]                 :: print this help\n"
	           "nmcli    <conf-option> <value>       :: nmcli configuration\n"
	           "quit                                 :: exit nmcli\n"));
	g_print ("------------------------------------------------------------------------------\n");
}

static void
editor_main_help (const char *command)
{
	if (!command)
		editor_main_usage ();
	else {
		/* detailed command descriptions */
		NmcEditorMainCmd cmd = parse_editor_main_cmd (command, NULL);

		switch (cmd) {
		case NMC_EDITOR_MAIN_CMD_GOTO:
			g_print (_("goto <setting>[.<prop>] | <prop>  :: enter setting/property for editing\n\n"
			           "This command enters into a setting or property for editing it.\n\n"
			           "Examples: nmcli> goto connection\n"
			           "          nmcli connection> goto secondaries\n"
			           "          nmcli> goto ipv4.addresses\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_REMOVE:
			g_print (_("remove <setting>[.<prop>]  :: remove setting or reset property value\n\n"
			           "This command removes an entire setting from the connection, or if a property\n"
			           "is given, resets that property to the default value.\n\n"
			           "Examples: nmcli> remove wifi-sec\n"
			           "          nmcli> remove eth.mtu\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_SET:
			g_print (_("set [<setting>.<prop> <value>]  :: set property value\n\n"
			           "This command sets property value.\n\n"
			           "Example: nmcli> set con.id My connection\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_DESCRIBE:
			g_print (_("describe [<setting>.<prop>]  :: describe property\n\n"
			           "Shows property description. You can consult nm-settings(5) "
			           "manual page to see all NM settings and properties.\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_PRINT:
			g_print (_("print [all]  :: print setting or connection values\n\n"
			           "Shows current property or the whole connection.\n\n"
			           "Example: nmcli ipv4> print all\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_VERIFY:
			g_print (_("verify [all | fix]  :: verify setting or connection validity\n\n"
			           "Verifies whether the setting or connection is valid and can be saved later.\n"
			           "It indicates invalid values on error. Some errors may be fixed automatically\n"
			           "by 'fix' option.\n\n"
			           "Examples: nmcli> verify\n"
			           "          nmcli> verify fix\n"
			           "          nmcli bond> verify\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_SAVE:
			g_print (_("save [persistent|temporary]  :: save the connection\n\n"
			           "Sends the connection profile to NetworkManager that either will save it\n"
			           "persistently, or will only keep it in memory. 'save' without an argument\n"
			           "means 'save persistent'.\n"
			           "Note that once you save the profile persistently those settings are saved\n"
			           "across reboot or restart. Subsequent changes can also be temporary or\n"
			           "persistent, but any temporary changes will not persist across reboot or\n"
			           "restart. If you want to fully remove the persistent connection, the connection\n"
			           "profile must be deleted.\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_ACTIVATE:
			g_print (_("activate [<ifname>] [/<ap>|<nsp>]  :: activate the connection\n\n"
			           "Activates the connection.\n\n"
			           "Available options:\n"
			           "<ifname>    - device the connection will be activated on\n"
			           "/<ap>|<nsp> - AP (Wi-Fi) or NSP (WiMAX) (prepend with / when <ifname> is not specified)\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_BACK:
			g_print (_("back  :: go to upper menu level\n\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_HELP:
			g_print (_("help/? [<command>]  :: help for the nmcli commands\n\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_NMCLI:
			g_print (_("nmcli [<conf-option> <value>]  :: nmcli configuration\n\n"
			           "Configures nmcli. The following options are available:\n"
			           "status-line yes | no          [default: no]\n"
			           "save-confirmation yes | no    [default: yes]\n"
			           "show-secrets yes | no         [default: no]\n"
			           "prompt-color <color> | <0-8>  [default: 0]\n"
			           "%s"  /* color table description */
			           "\n"
			           "Examples: nmcli> nmcli status-line yes\n"
			           "          nmcli> nmcli save-confirmation no\n"
			           "          nmcli> nmcli prompt-color 3\n"),
			           "  0 = normal\n"
			           "  1 = \33[30mblack\33[0m\n"
			           "  2 = \33[31mred\33[0m\n"
			           "  3 = \33[32mgreen\33[0m\n"
			           "  4 = \33[33myellow\33[0m\n"
			           "  5 = \33[34mblue\33[0m\n"
			           "  6 = \33[35mmagenta\33[0m\n"
			           "  7 = \33[36mcyan\33[0m\n"
			           "  8 = \33[37mwhite\33[0m\n");
			break;
		case NMC_EDITOR_MAIN_CMD_QUIT:
			g_print (_("quit  :: exit nmcli\n\n"
			           "This command exits nmcli. When the connection being edited "
			           "is not saved, the user is asked to confirm the action.\n"));
			break;
		default:
			g_print (_("Unknown command: '%s'\n"), command);
			break;
		}
	}
}

typedef enum {
	NMC_EDITOR_SUB_CMD_UNKNOWN = 0,
	NMC_EDITOR_SUB_CMD_SET,
	NMC_EDITOR_SUB_CMD_ADD,
	NMC_EDITOR_SUB_CMD_CHANGE,
	NMC_EDITOR_SUB_CMD_REMOVE,
	NMC_EDITOR_SUB_CMD_DESCRIBE,
	NMC_EDITOR_SUB_CMD_PRINT,
	NMC_EDITOR_SUB_CMD_BACK,
	NMC_EDITOR_SUB_CMD_HELP,
	NMC_EDITOR_SUB_CMD_QUIT
} NmcEditorSubCmd;

static NmcEditorSubCmd
parse_editor_sub_cmd (const char *cmd, char **cmd_arg)
{
	NmcEditorSubCmd editor_cmd = NMC_EDITOR_SUB_CMD_UNKNOWN;
	gs_free char *cmd_arg0 = NULL;
	const char *cmd_argr;

	_split_cmd (cmd, &cmd_arg0, &cmd_argr);
	if (!cmd_arg0)
		goto fail;

	if (matches (cmd_arg0, "set"))
		editor_cmd = NMC_EDITOR_SUB_CMD_SET;
	else if (matches (cmd_arg0, "add"))
		editor_cmd = NMC_EDITOR_SUB_CMD_ADD;
	else if (matches (cmd_arg0, "change"))
		editor_cmd = NMC_EDITOR_SUB_CMD_CHANGE;
	else if (matches (cmd_arg0, "remove"))
		editor_cmd = NMC_EDITOR_SUB_CMD_REMOVE;
	else if (matches (cmd_arg0, "describe"))
		editor_cmd = NMC_EDITOR_SUB_CMD_DESCRIBE;
	else if (matches (cmd_arg0, "print"))
		editor_cmd = NMC_EDITOR_SUB_CMD_PRINT;
	else if (matches (cmd_arg0, "back"))
		editor_cmd = NMC_EDITOR_SUB_CMD_BACK;
	else if (matches (cmd_arg0, "help") || strcmp (cmd_arg0, "?") == 0)
		editor_cmd = NMC_EDITOR_SUB_CMD_HELP;
	else if (matches (cmd_arg0, "quit"))
		editor_cmd = NMC_EDITOR_SUB_CMD_QUIT;
	else
		goto fail;

	NM_SET_OUT (cmd_arg, g_strdup (cmd_argr));
	return editor_cmd;
fail:
	NM_SET_OUT (cmd_arg, NULL);
	return NMC_EDITOR_SUB_CMD_UNKNOWN;
}

static void
editor_sub_help (void)
{
	g_print ("------------------------------------------------------------------------------\n");
	/* TRANSLATORS: do not translate command names and keywords before ::
	 *              However, you should translate terms enclosed in <>.
	 */
	g_print (_("---[ Property menu ]---\n"
	           "set      [<value>]               :: set new value\n"
	           "add      [<value>]               :: add new option to the property\n"
	           "change                           :: change current value\n"
	           "remove   [<index> | <option>]    :: delete the value\n"
	           "describe                         :: describe property\n"
	           "print    [setting | connection]  :: print property (setting/connection) value(s)\n"
	           "back                             :: go to upper level\n"
	           "help/?   [<command>]             :: print this help or command description\n"
	           "quit                             :: exit nmcli\n"));
	g_print ("------------------------------------------------------------------------------\n");
}

static void
editor_sub_usage (const char *command)
{

	if (!command)
		editor_sub_help ();
	else {
		/* detailed command descriptions */
		NmcEditorSubCmd cmdsub = parse_editor_sub_cmd (command, NULL);

		switch (cmdsub) {
		case NMC_EDITOR_SUB_CMD_SET:
			g_print (_("set [<value>]  :: set new value\n\n"
			           "This command sets provided <value> to this property\n"));
			break;
		case NMC_EDITOR_SUB_CMD_ADD:
			g_print (_("add [<value>]  :: append new value to the property\n\n"
			           "This command adds provided <value> to this property, if "
			           "the property is of a container type. For single-valued "
			           "properties the property value is replaced (same as 'set').\n"));
			break;
		case NMC_EDITOR_SUB_CMD_CHANGE:
			g_print (_("change  :: change current value\n\n"
			           "Displays current value and allows editing it.\n"));
			break;
		case NMC_EDITOR_SUB_CMD_REMOVE:
			g_print (_("remove [<value>|<index>|<option name>]  :: delete the value\n\n"
			           "Removes the property value. For single-valued properties, this sets the\n"
			           "property back to its default value. For container-type properties, this removes\n"
			           "all the values of that property, or you can specify an argument to remove just\n"
			           "a single item or option. The argument is either a value or index of the item to\n"
			           "remove, or an option name (for properties with named options).\n\n"
			           "Examples: nmcli ipv4.dns> remove 8.8.8.8\n"
			           "          nmcli ipv4.dns> remove 2\n"
			           "          nmcli bond.options> remove downdelay\n\n"));
			break;
		case NMC_EDITOR_SUB_CMD_DESCRIBE:
			g_print (_("describe  :: describe property\n\n"
			           "Shows property description. You can consult nm-settings(5) "
			           "manual page to see all NM settings and properties.\n"));
			break;
		case NMC_EDITOR_SUB_CMD_PRINT:
			g_print (_("print [property|setting|connection]  :: print property (setting, connection) value(s)\n\n"
			           "Shows property value. Providing an argument you can also display "
			           "values for the whole setting or connection.\n"));
			break;
		case NMC_EDITOR_SUB_CMD_BACK:
			g_print (_("back  :: go to upper menu level\n\n"));
			break;
		case NMC_EDITOR_SUB_CMD_HELP:
			g_print (_("help/? [<command>]  :: help for nmcli commands\n\n"));
			break;
		case NMC_EDITOR_SUB_CMD_QUIT:
			g_print (_("quit  :: exit nmcli\n\n"
			           "This command exits nmcli. When the connection being edited "
			           "is not saved, the user is asked to confirm the action.\n"));
			break;
		default:
			g_print (_("Unknown command: '%s'\n"), command);
			break;
		}
	}
}

/*****************************************************************************/

typedef struct {
	NMDevice *device;
	NMActiveConnection *ac;
	guint monitor_id;
	NmCli *nmc;
} MonitorACInfo;

static gboolean nmc_editor_cb_called;
static GError *nmc_editor_error;
static MonitorACInfo *nmc_editor_monitor_ac;

static void
editor_connection_changed_cb (NMConnection *connection, gboolean *changed)
{
	*changed = TRUE;
}

/*
 * Store 'error' to shared 'nmc_editor_error' and monitoring info to
 * 'nmc_editor_monitor_ac' and signal the condition so that
 * the 'editor-thread' thread could process that.
 */
static void
set_info_and_signal_editor_thread (GError *error, MonitorACInfo *monitor_ac_info)
{
	nmc_editor_cb_called = TRUE;
	nmc_editor_error = error ? g_error_copy (error) : NULL;
	nmc_editor_monitor_ac = monitor_ac_info;
}

static void
add_connection_editor_cb (GObject *client,
                          GAsyncResult *result,
                          gpointer user_data)
{
	NMRemoteConnection *connection;
	GError *error = NULL;

	connection = nm_client_add_connection_finish (NM_CLIENT (client), result, &error);
	set_info_and_signal_editor_thread (error, NULL);

	g_clear_object (&connection);
	g_clear_error (&error);
}

static void
update_connection_editor_cb (GObject *connection,
                             GAsyncResult *result,
                             gpointer user_data)
{
	GError *error = NULL;

	nm_remote_connection_commit_changes_finish (NM_REMOTE_CONNECTION (connection),
	                                            result, &error);
	set_info_and_signal_editor_thread (error, NULL);
	g_clear_error (&error);
}

static gboolean
progress_activation_editor_cb (gpointer user_data)
{
	MonitorACInfo *info = (MonitorACInfo *) user_data;
	NMDevice *device = info->device;
	NMActiveConnection *ac = info->ac;
	NMActiveConnectionState ac_state;
	NMDeviceState dev_state;

	if (!device || !ac)
		goto finish;

	ac_state = nm_active_connection_get_state (ac);
	dev_state = nm_device_get_state (device);

	nmc_terminal_show_progress (gettext (nmc_device_state_to_string (dev_state)));

	if (   ac_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED
	    || dev_state == NM_DEVICE_STATE_ACTIVATED) {
		nmc_terminal_erase_line ();
		g_print (_("Connection successfully activated (D-Bus active path: %s)\n"),
		         nm_object_get_path (NM_OBJECT (ac)));
		goto finish;
	} else if (   ac_state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED
	           || dev_state == NM_DEVICE_STATE_FAILED) {
		nmc_terminal_erase_line ();
		g_print (_("Error: Connection activation failed.\n"));
		goto finish;
	}

	if (info->nmc->secret_agent) {
		NMRemoteConnection *connection;

		connection = nm_active_connection_get_connection (ac);
		nm_secret_agent_simple_enable (info->nmc->secret_agent,
		                               nm_object_get_path (NM_OBJECT (connection)));
	}

	return G_SOURCE_CONTINUE;

finish:
	nm_g_object_unref (device);
	nm_g_object_unref (ac);
	info->monitor_id = 0;
	return G_SOURCE_REMOVE;
}

static void
activate_connection_editor_cb (GObject *client,
                               GAsyncResult *result,
                               gpointer user_data)
{
	ActivateConnectionInfo *info = (ActivateConnectionInfo *) user_data;
	NMDevice *device = info->device;
	const GPtrArray *ac_devs;
	MonitorACInfo *monitor_ac_info = NULL;
	NMActiveConnection *active;
	GError *error = NULL;

	active = nm_client_activate_connection_finish (NM_CLIENT (client), result, &error);

	if (!error) {
		if (!device) {
			ac_devs = nm_active_connection_get_devices (active);
			device = ac_devs->len > 0 ? g_ptr_array_index (ac_devs, 0) : NULL;
		}
		if (device) {
			monitor_ac_info = g_malloc0 (sizeof (MonitorACInfo));
			monitor_ac_info->device = g_object_ref (device);
			monitor_ac_info->ac = active;
			monitor_ac_info->monitor_id = g_timeout_add (120, progress_activation_editor_cb, monitor_ac_info);
			monitor_ac_info->nmc = info->nmc;
		} else
			g_object_unref (active);
	}

	nm_g_object_unref (info->device);
	g_free (info);

	set_info_and_signal_editor_thread (error, monitor_ac_info);
	g_clear_error (&error);
}

/*****************************************************************************/

static void
print_property_description (NMSetting *setting, const char *prop_name)
{
	char *desc;

	desc = nmc_setting_get_property_desc (setting, prop_name);
	if (desc) {
		g_print ("\n=== [%s] ===\n%s\n", prop_name, desc);
		g_free (desc);
	}
}

static void
print_setting_description (NMSetting *setting)
{
	/* Show description of all properties */
	char **all_props;
	int i;

	all_props = nmc_setting_get_valid_properties (setting);
	g_print (("<<< %s >>>\n"), nm_setting_get_name (setting));
	for (i = 0; all_props && all_props[i]; i++)
		print_property_description (setting, all_props[i]);
	g_strfreev (all_props);
}

static gboolean
connection_remove_setting (NMConnection *connection, NMSetting *setting)
{
	gboolean mandatory;

	g_return_val_if_fail (setting, FALSE);

	mandatory = is_setting_mandatory (connection, setting);
	if (!mandatory) {
		nm_connection_remove_setting (connection, G_OBJECT_TYPE (setting));
		return TRUE;
	}
	g_print (_("Error: setting '%s' is mandatory and cannot be removed.\n"),
	         nm_setting_get_name (setting));
	return FALSE;
}

static void
editor_show_status_line (NMConnection *connection, gboolean dirty, gboolean temp)
{
	NMSettingConnection *s_con;
	const char *con_type, *con_id, *con_uuid;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	con_type = nm_setting_connection_get_connection_type (s_con);
	con_id = nm_connection_get_id (connection);
	con_uuid = nm_connection_get_uuid (connection);

	/* TRANSLATORS: status line in nmcli connection editor */
	g_print (_("[ Type: %s | Name: %s | UUID: %s | Dirty: %s | Temp: %s ]\n"),
	         con_type, con_id, con_uuid,
	         dirty ? _("yes") : _("no"),
	         temp ? _("yes") : _("no"));
}

static gboolean
refresh_remote_connection (GWeakRef *weak, NMRemoteConnection **remote)
{
	gboolean previous;

	g_return_val_if_fail (remote, FALSE);

	previous = (*remote != NULL);
	if (*remote)
		g_object_unref (*remote);
	*remote = g_weak_ref_get (weak);

	return (previous && !*remote);
}

static gboolean
is_connection_dirty (NMConnection *connection, NMRemoteConnection *remote)
{
	return !nm_connection_compare (connection,
	                               remote ? NM_CONNECTION (remote) : NULL,
	                               NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS |
	                               NM_SETTING_COMPARE_FLAG_IGNORE_TIMESTAMP);
}

static gboolean
confirm_quit (const NmcConfig *nmc_config)
{
	gs_free char *answer = NULL;

	answer = nmc_readline (nmc_config,
	                       _("The connection is not saved. "
	                         "Do you really want to quit? %s"),
	                       prompt_yes_no (FALSE, NULL));
	nm_strstrip (answer);
	return (answer && matches (answer, WORD_YES));
}

/*
 * Submenu for detailed property editing
 * Return: TRUE - continue;  FALSE - should quit
 */
static gboolean
property_edit_submenu (NmCli *nmc,
                       NMConnection *connection,
                       NMRemoteConnection **rem_con,
                       GWeakRef *rem_con_weak,
                       NMSetting *curr_setting,
                       const char *prop_name)
{
	NmcEditorSubCmd cmdsub;
	gboolean set_result;
	GError *tmp_err = NULL;
	gs_free char *prompt = NULL;
	gboolean temp_changes;

	/* Set global variable for use in TAB completion */
	nmc_tab_completion.property = prop_name;

	prompt = nmc_colorize (&nmc->nmc_config, NM_META_COLOR_PROMPT, "nmcli %s.%s> ",
	                       nm_setting_get_name (curr_setting), prop_name);

	for (;;) {
		gs_free char *cmd_property_user = NULL;
		gs_free char *cmd_property_arg = NULL;
		gs_free char *prop_val_user = NULL;
		gboolean removed;
		gboolean dirty;

		/* Get the remote connection again, it may have disappeared */
		removed = refresh_remote_connection (rem_con_weak, rem_con);
		if (removed) {
			g_print (_("The connection profile has been removed from another client. "
			           "You may type 'save' in the main menu to restore it.\n"));
		}

		/* Connection is dirty? (not saved or differs from the saved) */
		dirty = is_connection_dirty (connection, *rem_con);
		temp_changes = *rem_con ? nm_remote_connection_get_unsaved (*rem_con) : TRUE;
		if (nmc->editor_status_line)
			editor_show_status_line (connection, dirty, temp_changes);

		cmd_property_user = nmc_readline (&nmc->nmc_config,
		                                  "%s",
		                                  prompt);
		if (!cmd_property_user || !*cmd_property_user)
			continue;
		g_strstrip (cmd_property_user);
		cmdsub = parse_editor_sub_cmd (cmd_property_user, &cmd_property_arg);

		switch (cmdsub) {
		case NMC_EDITOR_SUB_CMD_SET:
		case NMC_EDITOR_SUB_CMD_ADD:
			/* list, arrays,...: SET replaces the whole property value
			 *                   ADD adds the new value(s)
			 * single values:  : both SET and ADD sets the new value
			 */
			if (!cmd_property_arg) {
				gs_strfreev char **to_free = NULL;
				const char *const*avals;

				avals = nmc_setting_get_property_allowed_values (curr_setting, prop_name, &to_free);
				if (avals) {
					gs_free char *avals_str = NULL;

					avals_str = nmc_util_strv_for_display (avals, FALSE);
					g_print (_("Allowed values for '%s' property: %s\n"),
					         prop_name, avals_str);
				}
				prop_val_user = nmc_readline (&nmc->nmc_config,
				                              _("Enter '%s' value: "),
				                              prop_name);
			} else
				prop_val_user = g_strdup (cmd_property_arg);

			set_result = nmc_setting_set_property (nmc->client,
			                                       curr_setting,
			                                       prop_name,
			                                         (cmdsub == NMC_EDITOR_SUB_CMD_SET)
			                                       ? '\0'
			                                       : '+',
			                                       prop_val_user,
			                                       &tmp_err);
			if (!set_result) {
				g_print (_("Error: failed to set '%s' property: %s\n"), prop_name, tmp_err->message);
				g_clear_error (&tmp_err);
			}
			break;

		case NMC_EDITOR_SUB_CMD_CHANGE:
			rl_startup_hook = nmc_rl_set_deftext;
			nmc_rl_pre_input_deftext = nmc_setting_get_property_parsable (curr_setting, prop_name, NULL);
			prop_val_user = nmc_readline (&nmc->nmc_config,
			                              _("Edit '%s' value: "),
			                              prop_name);

			if (!nmc_setting_set_property (nmc->client, curr_setting, prop_name, '\0', prop_val_user, &tmp_err)) {
				g_print (_("Error: failed to set '%s' property: %s\n"), prop_name, tmp_err->message);
				g_clear_error (&tmp_err);
			}
			break;

		case NMC_EDITOR_SUB_CMD_REMOVE:
			if (!nmc_setting_set_property (nmc->client,
			                               curr_setting,
			                               prop_name,
			                               (  cmd_property_arg
			                                ? '-'
			                                : '\0'),
			                               cmd_property_arg,
			                               &tmp_err)) {
				g_print (_("Error: %s\n"), tmp_err->message);
				g_clear_error (&tmp_err);
			}
			break;

		case NMC_EDITOR_SUB_CMD_DESCRIBE:
			/* Show property description */
			print_property_description (curr_setting, prop_name);
			break;

		case NMC_EDITOR_SUB_CMD_PRINT:
			/* Print current connection settings/properties */
			if (cmd_property_arg) {
				if (matches (cmd_property_arg, "setting"))
					editor_show_setting (curr_setting, nmc);
				else if (   matches (cmd_property_arg, "connection")
				         || matches (cmd_property_arg, "all"))
					editor_show_connection (connection, nmc);
				else
					g_print (_("Unknown command argument: '%s'\n"), cmd_property_arg);
			} else {
				char *prop_val =  nmc_setting_get_property (curr_setting, prop_name, NULL);
				g_print ("%s: %s\n", prop_name, prop_val);
				g_free (prop_val);
			}
			break;

		case NMC_EDITOR_SUB_CMD_BACK:
			/* Set global variable for use in TAB completion */
			nmc_tab_completion.property = NULL;
			return TRUE;

		case NMC_EDITOR_SUB_CMD_HELP:
			editor_sub_usage (cmd_property_arg);
			break;

		case NMC_EDITOR_SUB_CMD_QUIT:
			if (is_connection_dirty (connection, *rem_con)) {
				if (confirm_quit (&nmc->nmc_config))
					return FALSE;
			} else
				return FALSE;
			break;

		case NMC_EDITOR_SUB_CMD_UNKNOWN:
		default:
			g_print (_("Unknown command: '%s'\n"), cmd_property_user);
			break;
		}
	}
}

/*
 * Split 'str' in the following format:  [[[setting.]property] [value]]
 * and return the components in 'setting', 'property' and 'value'
 * Use g_free() to deallocate the returned strings.
 */
static void
split_editor_main_cmd_args (const char *str, char **setting, char **property, char **value)
{
	gs_free char *cmd_arg0 = NULL;
	const char *cmd_argr;
	const char *s;

	NM_SET_OUT (setting, NULL);
	NM_SET_OUT (property, NULL);
	NM_SET_OUT (value, NULL);

	_split_cmd (str, &cmd_arg0, &cmd_argr);
	if (!cmd_arg0)
		return;

	NM_SET_OUT (value, g_strdup (cmd_argr));
	s = strchr (cmd_arg0, '.');
	if (s && s > cmd_arg0) {
		NM_SET_OUT (setting, g_strndup (cmd_arg0, s - cmd_arg0));
		NM_SET_OUT (property, g_strdup (&s[1]));
	} else {
		NM_SET_OUT (property, g_steal_pointer (&cmd_arg0));
	}
}

static NMSetting *
create_setting_by_name (const char *name, const NMMetaSettingValidPartItem *const*valid_settings_main, const NMMetaSettingValidPartItem *const*valid_settings_slave)
{
	const char *setting_name;
	NMSetting *setting = NULL;

	/* Get a valid setting name */
	setting_name = check_valid_name (name, valid_settings_main, valid_settings_slave, NULL);

	if (setting_name) {
		setting = nm_meta_setting_info_editor_new_setting (nm_meta_setting_info_editor_find_by_name (setting_name, FALSE),
		                                                   NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI);
	}
	return setting;
}

static const char *
ask_check_setting (const NmcConfig *nmc_config,
                   const char *arg,
                   const NMMetaSettingValidPartItem *const*valid_settings_main,
                   const NMMetaSettingValidPartItem *const*valid_settings_slave,
                   const char *valid_settings_str)
{
	char *setting_name_user;
	const char *setting_name;
	GError *err = NULL;

	if (!arg) {
		g_print (_("Available settings: %s\n"), valid_settings_str);
		setting_name_user = nmc_readline (nmc_config,
		                                  EDITOR_PROMPT_SETTING);
	} else
		setting_name_user = g_strdup (arg);

	nm_strstrip (setting_name_user);

	if (!(setting_name = check_valid_name (setting_name_user,
	                                       valid_settings_main,
	                                       valid_settings_slave,
	                                       &err))) {
		g_print (_("Error: invalid setting name; %s\n"), err->message);
		g_clear_error (&err);
	}
	g_free (setting_name_user);
	return setting_name;
}

static const char *
ask_check_property (const NmcConfig *nmc_config,
                    const char *arg,
                    const char **valid_props,
                    const char *valid_props_str)
{
	char *prop_name_user;
	const char *prop_name;
	GError *tmp_err = NULL;

	if (!arg) {
		g_print (_("Available properties: %s\n"), valid_props_str);
		prop_name_user = nmc_readline (nmc_config,
		                               EDITOR_PROMPT_PROPERTY);
		nm_strstrip (prop_name_user);
	} else
		prop_name_user = g_strdup (arg);

	if (!(prop_name = nmc_string_is_valid (prop_name_user, valid_props, &tmp_err))) {
		g_print (_("Error: property %s\n"), tmp_err->message);
		g_clear_error (&tmp_err);
	}
	g_free (prop_name_user);
	return prop_name;
}

/* Copy timestamp from src do dst */
static void
update_connection_timestamp (NMConnection *src, NMConnection *dst)
{
	NMSettingConnection *s_con_src, *s_con_dst;

	s_con_src = nm_connection_get_setting_connection (src);
	s_con_dst = nm_connection_get_setting_connection (dst);
	if (s_con_src && s_con_dst) {
		guint64 timestamp = nm_setting_connection_get_timestamp (s_con_src);
		g_object_set (s_con_dst, NM_SETTING_CONNECTION_TIMESTAMP, timestamp, NULL);
	}
}

static gboolean
confirm_connection_saving (const NmcConfig *nmc_config,
                           NMConnection *local,
                           NMConnection *remote)
{
	NMSettingConnection *s_con_loc, *s_con_rem;
	gboolean ac_local, ac_remote;
	gboolean confirmed = TRUE;

	s_con_loc = nm_connection_get_setting_connection (local);
	g_assert (s_con_loc);
	ac_local = nm_setting_connection_get_autoconnect (s_con_loc);

	if (remote) {
		s_con_rem = nm_connection_get_setting_connection (remote);
		g_assert (s_con_rem);
		ac_remote = nm_setting_connection_get_autoconnect (s_con_rem);
	} else
		ac_remote = FALSE;

	if (ac_local && !ac_remote) {
		gs_free char *answer = NULL;

		answer = nmc_readline (nmc_config,
		                       _("Saving the connection with 'autoconnect=yes'. "
		                         "That might result in an immediate activation of the connection.\n"
		                         "Do you still want to save? %s"),
		                       prompt_yes_no (TRUE, NULL));
		nm_strstrip (answer);
		confirmed = (!answer || matches (answer, WORD_YES));
	}
	return confirmed;
}

typedef struct {
	guint level;
	char *main_prompt;
	NMSetting *curr_setting;
	char **valid_props;
	char *valid_props_str;
} NmcEditorMenuContext;

static void
menu_switch_to_level0 (const NmcConfig *nmc_config,
                       NmcEditorMenuContext *menu_ctx,
                       const char *prompt)
{
	menu_ctx->level = 0;
	g_free (menu_ctx->main_prompt);
	menu_ctx->main_prompt = nmc_colorize (nmc_config, NM_META_COLOR_PROMPT, "%s", prompt);
	menu_ctx->curr_setting = NULL;
	g_strfreev (menu_ctx->valid_props);
	menu_ctx->valid_props = NULL;
	g_free (menu_ctx->valid_props_str);
	menu_ctx->valid_props_str = NULL;
}

static void
menu_switch_to_level1 (const NmcConfig *nmc_config,
                       NmcEditorMenuContext *menu_ctx,
                       NMSetting *setting,
                       const char *setting_name)
{
	menu_ctx->level = 1;
	g_free (menu_ctx->main_prompt);
	menu_ctx->main_prompt = nmc_colorize (nmc_config, NM_META_COLOR_PROMPT, "nmcli %s> ", setting_name);
	menu_ctx->curr_setting = setting;
	g_strfreev (menu_ctx->valid_props);
	menu_ctx->valid_props = nmc_setting_get_valid_properties (menu_ctx->curr_setting);
	g_free (menu_ctx->valid_props_str);
	menu_ctx->valid_props_str = g_strjoinv (", ", menu_ctx->valid_props);
}

static gboolean
editor_save_timeout (gpointer user_data)
{
	gboolean *timeout = user_data;

	*timeout = TRUE;

	return G_SOURCE_REMOVE;
}

static gboolean
editor_menu_main (NmCli *nmc, NMConnection *connection, const char *connection_type)
{
	gs_unref_object NMRemoteConnection *rem_con = NULL;
	NMSettingConnection *s_con;
	NMRemoteConnection *con_tmp;
	GWeakRef weak = { { NULL } };
	gboolean removed;
	NmcEditorMainCmd cmd;
	gboolean cmd_loop = TRUE;
	const NMMetaSettingValidPartItem *const*valid_settings_main;
	const NMMetaSettingValidPartItem *const*valid_settings_slave;
	gs_free char *valid_settings_str = NULL;
	const char *s_type = NULL;
	AddConnectionInfo *info = NULL;
	gboolean temp_changes;
	GError *err1 = NULL;
	NmcEditorMenuContext menu_ctx = { 0 };

	s_con = nm_connection_get_setting_connection (connection);
	if (s_con)
		s_type = nm_setting_connection_get_slave_type (s_con);

	valid_settings_main = get_valid_settings_array (connection_type);
	valid_settings_slave = nm_meta_setting_info_valid_parts_for_slave_type (s_type, NULL);

	valid_settings_str = get_valid_options_string (valid_settings_main, valid_settings_slave);
	g_print (_("You may edit the following settings: %s\n"), valid_settings_str);

	menu_ctx.main_prompt = nmc_colorize (&nmc->nmc_config, NM_META_COLOR_PROMPT, BASE_PROMPT);

	/* Get remote connection */
	con_tmp = nm_client_get_connection_by_uuid (nmc->client,
	                                            nm_connection_get_uuid (connection));
	g_weak_ref_init (&weak, con_tmp);
	rem_con = g_weak_ref_get (&weak);

	while (cmd_loop) {
		gs_free char *cmd_user = NULL;
		gs_free char *cmd_arg = NULL;
		gs_free char *cmd_arg_s = NULL;
		gs_free char *cmd_arg_p = NULL;
		gs_free char *cmd_arg_v = NULL;
		gboolean dirty;

		/* Connection is dirty? (not saved or differs from the saved) */
		dirty = is_connection_dirty (connection, rem_con);
		temp_changes = rem_con ? nm_remote_connection_get_unsaved (rem_con) : TRUE;
		if (nmc->editor_status_line)
			editor_show_status_line (connection, dirty, temp_changes);

		cmd_user = nmc_readline (&nmc->nmc_config,
		                         "%s",
		                         menu_ctx.main_prompt);

		/* Get the remote connection again, it may have disappeared */
		removed = refresh_remote_connection (&weak, &rem_con);
		if (removed) {
			g_print (_("The connection profile has been removed from another client. "
			           "You may type 'save' to restore it.\n"));
		}

		if (!cmd_user || !*cmd_user)
			continue;

		g_strstrip (cmd_user);

		cmd = parse_editor_main_cmd (cmd_user, &cmd_arg);

		split_editor_main_cmd_args (cmd_arg, &cmd_arg_s, &cmd_arg_p, &cmd_arg_v);
		switch (cmd) {
		case NMC_EDITOR_MAIN_CMD_SET:
			/* Set property value */
			if (!cmd_arg) {
				if (menu_ctx.level == 1) {
					gs_strfreev char **avals_to_free = NULL;
					gs_free char *prop_val_user = NULL;
					const char *prop_name;
					const char *const*avals;
					GError *tmp_err = NULL;

					prop_name = ask_check_property (&nmc->nmc_config,
					                                cmd_arg,
					                                (const char **) menu_ctx.valid_props,
					                                menu_ctx.valid_props_str);
					if (!prop_name)
						break;

					avals = nmc_setting_get_property_allowed_values (menu_ctx.curr_setting, prop_name, &avals_to_free);
					if (avals) {
						gs_free char *avals_str = NULL;

						avals_str = nmc_util_strv_for_display (avals, FALSE);
						g_print (_("Allowed values for '%s' property: %s\n"),
						         prop_name, avals_str);
					}
					prop_val_user = nmc_readline (&nmc->nmc_config,
					                              _("Enter '%s' value: "),
					                              prop_name);

					if (!nmc_setting_set_property (nmc->client, menu_ctx.curr_setting, prop_name, '+', prop_val_user, &tmp_err)) {
						g_print (_("Error: failed to set '%s' property: %s\n"), prop_name, tmp_err->message);
						g_clear_error (&tmp_err);
					}
				} else {
					g_print (_("Error: no setting selected; valid are [%s]\n"), valid_settings_str);
					g_print (_("use 'goto <setting>' first, or 'set <setting>.<property>'\n"));
				}
			} else {
				gs_free char *prop_name = NULL;
				gs_unref_object NMSetting *ss_created = NULL;
				NMSetting *ss = NULL;
				GError *tmp_err = NULL;

				if (cmd_arg_s) {
					/* setting provided as "setting.property" */
					ss = is_setting_valid (connection, valid_settings_main, valid_settings_slave, cmd_arg_s);
					if (!ss) {
						ss_created = create_setting_by_name (cmd_arg_s, valid_settings_main, valid_settings_slave);
						ss = ss_created;
						if (!ss) {
							g_print (_("Error: invalid setting argument '%s'; valid are [%s]\n"),
							         cmd_arg_s, valid_settings_str);
							break;
						}
					}
				} else {
					if (menu_ctx.curr_setting)
						ss = menu_ctx.curr_setting;
					else {
						g_print (_("Error: missing setting for '%s' property\n"), cmd_arg_p);
						break;
					}
				}

				prop_name = is_property_valid (ss, cmd_arg_p, &tmp_err);
				if (!prop_name) {
					g_print (_("Error: invalid property: %s\n"), tmp_err->message);
					g_clear_error (&tmp_err);
					break;
				}

				/* Ask for value */
				if (!cmd_arg_v) {
					gs_strfreev char **avals_to_free = NULL;
					const char *const*avals;

					avals = nmc_setting_get_property_allowed_values (ss, prop_name, &avals_to_free);
					if (avals) {
						gs_free char *avals_str = NULL;

						avals_str = nmc_util_strv_for_display (avals, FALSE);
						g_print (_("Allowed values for '%s' property: %s\n"),
						         prop_name, avals_str);
					}
					cmd_arg_v = nmc_readline (&nmc->nmc_config,
					                          _("Enter '%s' value: "),
					                          prop_name);
				}

				/* setting a value in edit mode "appends". That seems unexpected behavior. */
				if (!nmc_setting_set_property (nmc->client,
				                               ss,
				                               prop_name,
				                               cmd_arg_v ? '+' : '\0',
				                               cmd_arg_v,
				                               &tmp_err)) {
					g_print (_("Error: failed to set '%s' property: %s\n"),
					         prop_name, tmp_err->message);
					g_clear_error (&tmp_err);
				}

				if (ss_created)
					nm_connection_add_setting (connection, g_steal_pointer (&ss_created));
			}
			break;

		case NMC_EDITOR_MAIN_CMD_GOTO:
			/* cmd_arg_s != NULL means 'setting.property' argument */
			if (menu_ctx.level == 0 || cmd_arg_s) {
				/* in top level - no setting selected yet */
				const char *setting_name;
				NMSetting *setting;
				const char *user_arg = cmd_arg_s ?: cmd_arg_p;

				setting_name = ask_check_setting (&nmc->nmc_config,
				                                  user_arg,
				                                  valid_settings_main,
				                                  valid_settings_slave,
				                                  valid_settings_str);
				if (!setting_name)
					break;

				setting = nm_connection_get_setting_by_name (connection, setting_name);
				if (!setting) {
					const NMMetaSettingInfoEditor *setting_info;

					setting_info = nm_meta_setting_info_editor_find_by_name (setting_name, FALSE);
					if (!setting_info) {
						g_print (_("Error: unknown setting '%s'\n"), setting_name);
						break;
					}

					setting = nm_meta_setting_info_editor_new_setting (setting_info,
					                                                   NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI);

					if (NM_IS_SETTING_WIRELESS (setting))
						nmc_setting_wireless_connect_handlers (NM_SETTING_WIRELESS (setting));
					else if (NM_IS_SETTING_IP4_CONFIG (setting))
						nmc_setting_ip4_connect_handlers (NM_SETTING_IP_CONFIG (setting));
					else if (NM_IS_SETTING_IP6_CONFIG (setting))
						nmc_setting_ip6_connect_handlers (NM_SETTING_IP_CONFIG (setting));
					else if (NM_IS_SETTING_PROXY (setting))
						nmc_setting_proxy_connect_handlers (NM_SETTING_PROXY (setting));

					nm_connection_add_setting (connection, setting);
				}
				/* Set global variable for use in TAB completion */
				nmc_tab_completion.setting = setting;

				/* Switch to level 1 */
				menu_switch_to_level1 (&nmc->nmc_config, &menu_ctx, setting, setting_name);

				if (!cmd_arg_s) {
					g_print (_("You may edit the following properties: %s\n"), menu_ctx.valid_props_str);
					break;
				}
			}
			if (menu_ctx.level == 1 || cmd_arg_s) {
				/* level 1 - setting selected */
				const char *prop_name;

				prop_name = ask_check_property (&nmc->nmc_config,
				                                cmd_arg_p,
				                                (const char **) menu_ctx.valid_props,
				                                menu_ctx.valid_props_str);
				if (!prop_name)
					break;

				/* submenu - level 2 - editing properties */
				cmd_loop = property_edit_submenu (nmc,
				                                  connection,
				                                  &rem_con,
				                                  &weak,
				                                  menu_ctx.curr_setting,
				                                  prop_name);
			}
			break;

		case NMC_EDITOR_MAIN_CMD_REMOVE:
			/* Remove setting from connection, or delete value of a property */
			if (!cmd_arg) {
				if (menu_ctx.level == 1) {
					GError *tmp_err = NULL;
					const char *prop_name;

					prop_name = ask_check_property (&nmc->nmc_config,
					                                cmd_arg,
					                                (const char **) menu_ctx.valid_props,
					                                menu_ctx.valid_props_str);
					if (!prop_name)
						break;

					if (!nmc_setting_set_property (nmc->client, menu_ctx.curr_setting, prop_name, '\0', NULL, &tmp_err)) {
						g_print (_("Error: failed to remove value of '%s': %s\n"), prop_name,
						         tmp_err->message);
						g_clear_error (&tmp_err);
					}
				} else
					g_print (_("Error: no argument given; valid are [%s]\n"), valid_settings_str);
			} else {
				NMSetting *ss = NULL;
				gboolean descr_all;
				char *user_s;

				/* cmd_arg_s != NULL means argument is "setting.property" */
				descr_all = !cmd_arg_s && !menu_ctx.curr_setting;
				user_s = descr_all ? cmd_arg_p : cmd_arg_s;
				if (user_s) {
					ss = is_setting_valid (connection,
					                       valid_settings_main,
					                       valid_settings_slave,
					                       user_s);
					if (!ss) {
						if (check_valid_name (user_s,
						                      valid_settings_main,
						                      valid_settings_slave,
						                      NULL)) {
							g_print (_("Setting '%s' is not present in the connection.\n"),
							         user_s);
						} else {
							g_print (_("Error: invalid setting argument '%s'; valid are [%s]\n"),
							         user_s, valid_settings_str);
						}
						break;
					}
				} else
					ss = menu_ctx.curr_setting;

				if (descr_all) {
					/* Remove setting from the connection */
					connection_remove_setting (connection, ss);
					if (ss == menu_ctx.curr_setting) {
						/* If we removed the setting we are in, go up */
						menu_switch_to_level0 (&nmc->nmc_config, &menu_ctx, BASE_PROMPT);
						nmc_tab_completion.setting = NULL;  /* for TAB completion */
					}
				} else {
					gs_free char *prop_name = NULL;
					GError *tmp_err = NULL;

					prop_name = is_property_valid (ss, cmd_arg_p, &tmp_err);
					if (prop_name) {
						if (!nmc_setting_set_property (nmc->client, ss, prop_name, '\0', NULL, &tmp_err)) {
							g_print (_("Error: failed to remove value of '%s': %s\n"), prop_name,
							         tmp_err->message);
							g_clear_error (&tmp_err);
						}
					} else {
						/* If the string is not a property, try it as a setting */
						NMSetting *s_tmp;
						s_tmp = is_setting_valid (connection,
						                          valid_settings_main,
						                          valid_settings_slave,
						                          cmd_arg_p);
						if (s_tmp) {
							/* Remove setting from the connection */
							connection_remove_setting (connection, s_tmp);
							/* coverity[copy_paste_error] - suppress Coverity COPY_PASTE_ERROR defect */
							if (ss == menu_ctx.curr_setting) {
								/* If we removed the setting we are in, go up */
								menu_switch_to_level0 (&nmc->nmc_config, &menu_ctx, BASE_PROMPT);
								nmc_tab_completion.setting = NULL;  /* for TAB completion */
							}
						} else
							g_print (_("Error: %s properties, nor it is a setting name.\n"),
							         tmp_err->message);
						g_clear_error (&tmp_err);
					}
				}
			}
			break;

		case NMC_EDITOR_MAIN_CMD_DESCRIBE:
			/* Print property description */
			if (!cmd_arg) {
				if (menu_ctx.level == 1) {
					const char *prop_name;

					prop_name = ask_check_property (&nmc->nmc_config,
					                                cmd_arg,
					                                (const char **) menu_ctx.valid_props,
					                                menu_ctx.valid_props_str);
					if (!prop_name)
						break;

					/* Show property description */
					print_property_description (menu_ctx.curr_setting, prop_name);
				} else {
					g_print (_("Error: no setting selected; valid are [%s]\n"), valid_settings_str);
					g_print (_("use 'goto <setting>' first, or 'describe <setting>.<property>'\n"));
				}
			} else {
				gs_unref_object NMSetting *ss_free = NULL;
				NMSetting *ss = NULL;
				gboolean descr_all;
				char *user_s;

				/* cmd_arg_s != NULL means argument is "setting.property" */
				descr_all = !cmd_arg_s && !menu_ctx.curr_setting;
				user_s = descr_all ? cmd_arg_p : cmd_arg_s;
				if (user_s) {
					ss = is_setting_valid (connection,
					                       valid_settings_main,
					                       valid_settings_slave,
					                       user_s);
					if (!ss) {
						ss = create_setting_by_name (user_s,
						                             valid_settings_main,
						                             valid_settings_slave);
						if (!ss) {
							g_print (_("Error: invalid setting argument '%s'; valid are [%s]\n"),
							         user_s, valid_settings_str);
							break;
						}
						ss_free = ss;
					}
				} else
					ss = menu_ctx.curr_setting;

				if (!ss) {
					g_print (_("Error: no setting selected; valid are [%s]\n"), valid_settings_str);
					g_print (_("use 'goto <setting>' first, or 'describe <setting>.<property>'\n"));
				} else if (descr_all) {
					/* Show description for all properties */
					print_setting_description (ss);
				} else {
					GError *tmp_err = NULL;
					gs_free char *prop_name = NULL;

					prop_name = is_property_valid (ss, cmd_arg_p, &tmp_err);
					if (prop_name) {
						/* Show property description */
						print_property_description (ss, prop_name);
					} else {
						/* If the string is not a property, try it as a setting */
						NMSetting *s_tmp;

						s_tmp = is_setting_valid (connection,
						                          valid_settings_main,
						                          valid_settings_slave,
						                          cmd_arg_p);
						if (s_tmp)
							print_setting_description (s_tmp);
						else
							g_print (_("Error: invalid property: %s, "
							           "neither a valid setting name.\n"),
							         tmp_err->message);
						g_clear_error (&tmp_err);
					}
				}
			}
			break;

		case NMC_EDITOR_MAIN_CMD_PRINT:
			/* Print current connection settings/properties */
			if (cmd_arg) {
				if (nm_streq (cmd_arg, "all"))
					editor_show_connection (connection, nmc);
				else {
					NMSetting *ss = NULL;
					gboolean whole_setting;
					char *user_s;

					/* cmd_arg_s != NULL means argument is "setting.property" */
					whole_setting = !cmd_arg_s && !menu_ctx.curr_setting;
					user_s = whole_setting ? cmd_arg_p : cmd_arg_s;
					if (user_s) {
						const char *s_name;

						s_name = check_valid_name (user_s,
						                           valid_settings_main,
						                           valid_settings_slave,
						                           NULL);
						if (!s_name) {
							g_print (_("Error: unknown setting: '%s'\n"), user_s);
							break;
						}
						ss = nm_connection_get_setting_by_name (connection, s_name);
						if (!ss) {
							g_print (_("Error: '%s' setting not present in the connection\n"), s_name);
							break;
						}
					} else
						ss = menu_ctx.curr_setting;

					if (whole_setting) {
						/* Print the whole setting */
						editor_show_setting (ss, nmc);
					} else {
						gs_free char *prop_name = NULL;
						GError *err = NULL;

						prop_name = is_property_valid (ss, cmd_arg_p, &err);
						if (prop_name) {
							/* Print one property */
							gs_free char *prop_val = NULL;

							prop_val = nmc_setting_get_property (ss, prop_name, NULL);
							g_print ("%s.%s: %s\n", nm_setting_get_name (ss),prop_name , prop_val);
						} else {
							/* If the string is not a property, try it as a setting */
							NMSetting *s_tmp;
							s_tmp = is_setting_valid (connection,
							                          valid_settings_main,
							                          valid_settings_slave,
							                          cmd_arg_p);
							if (s_tmp) {
								/* Print the whole setting */
								editor_show_setting (s_tmp, nmc);
							} else
								g_print (_("Error: invalid property: %s%s\n"),
								         err->message,
								         cmd_arg_s ? "" : _(", neither a valid setting name"));
							g_clear_error (&err);
						}
					}
				}
			} else {
				if (menu_ctx.curr_setting)
					editor_show_setting (menu_ctx.curr_setting, nmc);
				else
					editor_show_connection (connection, nmc);
			}
			break;

		case NMC_EDITOR_MAIN_CMD_VERIFY:
			/* Verify current setting or the whole connection */
			if (cmd_arg && strcmp (cmd_arg, "all") && strcmp (cmd_arg, "fix")) {
				g_print (_("Invalid verify option: %s\n"), cmd_arg);
				break;
			}

			if (   menu_ctx.curr_setting
			    && (!cmd_arg || strcmp (cmd_arg, "all") != 0)) {
				GError *tmp_err = NULL;
				(void) nm_setting_verify (menu_ctx.curr_setting, NULL, &tmp_err);
				g_print (_("Verify setting '%s': %s\n"),
				         nm_setting_get_name (menu_ctx.curr_setting),
				         tmp_err ? tmp_err->message : "OK");
				g_clear_error (&tmp_err);
			} else {
				GError *tmp_err = NULL;
				gboolean valid, modified;
				gboolean fixed = TRUE;

				valid = nm_connection_verify (connection, &tmp_err);
				if (!valid && (g_strcmp0 (cmd_arg, "fix") == 0)) {
					/* Try to fix normalizable errors */
					g_clear_error (&tmp_err);
					fixed = nm_connection_normalize (connection, NULL, &modified, &tmp_err);
				}
				g_print (_("Verify connection: %s\n"),
				         tmp_err ? tmp_err->message : "OK");
				if (!fixed)
					g_print (_("The error cannot be fixed automatically.\n"));
				g_clear_error (&tmp_err);
			}
			break;

		case NMC_EDITOR_MAIN_CMD_SAVE:
			/* Save the connection */
			if (nm_connection_verify (connection, &err1)) {
				gboolean persistent = TRUE;
				gboolean connection_changed;
				nm_auto_unref_gsource GSource *source = NULL;
				gboolean timeout = FALSE;
				gulong handler_id = 0;

				/* parse argument */
				if (cmd_arg) {
					if (matches (cmd_arg, "temporary"))
						persistent = FALSE;
					else if (matches (cmd_arg, "persistent"))
						persistent = TRUE;
					else {
						g_print (_("Error: invalid argument '%s'\n"), cmd_arg);
						break;
					}
				}

				/* Ask for save confirmation if the connection changes to autoconnect=yes */
				if (nmc->editor_save_confirmation) {
					if (!confirm_connection_saving (&nmc->nmc_config,
					                                connection,
					                                NM_CONNECTION (rem_con)))
						break;
				}

				if (!rem_con) {
					/* Tell the settings service to add the new connection */
					info = g_malloc0 (sizeof (AddConnectionInfo));
					info->nmc = nmc;
					info->con_name = g_strdup (nm_connection_get_id (connection));
					add_new_connection (persistent,
					                    nmc->client,
					                    connection,
					                    add_connection_editor_cb,
					                    info);
					connection_changed = TRUE;
				} else {
					/* Save/update already saved (existing) connection */
					nm_connection_replace_settings_from_connection (NM_CONNECTION (rem_con),
					                                                connection);
					update_connection (persistent, rem_con, update_connection_editor_cb, NULL);

					handler_id = g_signal_connect (rem_con,
					                               NM_CONNECTION_CHANGED,
					                               G_CALLBACK (editor_connection_changed_cb),
					                               &connection_changed);
					connection_changed = FALSE;
				}

				source = g_timeout_source_new (10 * NM_UTILS_MSEC_PER_SECOND);
				g_source_set_callback (source, editor_save_timeout, &timeout, NULL);
				g_source_attach (source, g_main_loop_get_context (loop));

				while (!nmc_editor_cb_called && !timeout)
					g_main_context_iteration (NULL, TRUE);

				while (!connection_changed && !timeout)
					g_main_context_iteration (NULL, TRUE);

				if (handler_id)
					g_signal_handler_disconnect (rem_con, handler_id);
				g_source_destroy (source);

				if (nmc_editor_error) {
					g_print (_("Error: Failed to save '%s' (%s) connection: %s\n"),
					         nm_connection_get_id (connection),
					         nm_connection_get_uuid (connection),
					         nmc_editor_error->message);
					g_error_free (nmc_editor_error);
				} else if (timeout) {
					g_print (_("Error: Timeout saving '%s' (%s) connection\n"),
					         nm_connection_get_id (connection),
					         nm_connection_get_uuid (connection));
				} else {
					g_print (!rem_con ?
					         _("Connection '%s' (%s) successfully saved.\n") :
					         _("Connection '%s' (%s) successfully updated.\n"),
					         nm_connection_get_id (connection),
					         nm_connection_get_uuid (connection));

					con_tmp = nm_client_get_connection_by_uuid (nmc->client,
					                                            nm_connection_get_uuid (connection));
					g_weak_ref_set (&weak, con_tmp);
					refresh_remote_connection (&weak, &rem_con);

					/* Replace local connection with the remote one to be sure they are equal.
					 * This mitigates problems with plugins not preserving some properties or
					 * adding ipv{4,6} settings when not present.
					 */
					if (con_tmp) {
						gs_free char *s_name = NULL;

						if (menu_ctx.curr_setting)
							s_name = g_strdup (nm_setting_get_name (menu_ctx.curr_setting));

						/* Update settings and secrets in the local connection */
						nm_connection_replace_settings_from_connection (connection,
						                                                NM_CONNECTION (con_tmp));
						update_secrets_in_connection (con_tmp, connection);

						/* Also update setting for menu context and TAB-completion */
						menu_ctx.curr_setting = s_name ? nm_connection_get_setting_by_name (connection, s_name) : NULL;
						nmc_tab_completion.setting = menu_ctx.curr_setting;
					}
				}

				nmc_editor_cb_called = FALSE;
				nmc_editor_error = NULL;
			} else {
				g_print (_("Error: connection verification failed: %s\n"),
				         err1 ? err1->message : _("(unknown error)"));
				g_print (_("You may try running 'verify fix' to fix errors.\n"));
			}

			g_clear_error (&err1);
			break;

		case NMC_EDITOR_MAIN_CMD_ACTIVATE:
			{
			GError *tmp_err = NULL;
			const char *ifname = cmd_arg_p;
			const char *ap_nsp = cmd_arg_v;

			/* When only AP/NSP is specified it is prepended with '/' */
			if (!cmd_arg_v) {
				if (ifname && ifname[0] == '/') {
					ap_nsp = ifname + 1;
					ifname = NULL;
				}
			} else
				ap_nsp = ap_nsp && ap_nsp[0] == '/' ? ap_nsp + 1 : ap_nsp;

			if (is_connection_dirty (connection, rem_con)) {
				g_print (_("Error: connection is not saved. Type 'save' first.\n"));
				break;
			}
			if (!nm_connection_verify (NM_CONNECTION (rem_con), &tmp_err)) {
				g_print (_("Error: connection is not valid: %s\n"), tmp_err->message);
				g_clear_error (&tmp_err);
				break;
			}

			nmc->nowait_flag = FALSE;
			nmc->should_wait++;
			nmc->nmc_config_mutable.print_output = NMC_PRINT_PRETTY;
			if (!nmc_activate_connection (nmc, NM_CONNECTION (rem_con), ifname, ap_nsp, ap_nsp, NULL,
			                              activate_connection_editor_cb, &tmp_err)) {
				g_print (_("Error: Cannot activate connection: %s.\n"), tmp_err->message);
				g_clear_error (&tmp_err);
				break;
			}

			while (!nmc_editor_cb_called)
				g_main_context_iteration (NULL, TRUE);

			if (nmc_editor_error) {
				g_print (_("Error: Failed to activate '%s' (%s) connection: %s\n"),
				         nm_connection_get_id (connection),
				         nm_connection_get_uuid (connection),
				         nmc_editor_error->message);
				g_error_free (nmc_editor_error);
			} else {
				nmc_readline (&nmc->nmc_config,
				              _("Monitoring connection activation (press any key to continue)\n"));
			}

			if (nmc_editor_monitor_ac) {
				if (nmc_editor_monitor_ac->monitor_id)
					g_source_remove (nmc_editor_monitor_ac->monitor_id);
				g_free (nmc_editor_monitor_ac);
			}
			nmc_editor_cb_called = FALSE;
			nmc_editor_error = NULL;
			nmc_editor_monitor_ac = NULL;

			/* Update timestamp in local connection */
			update_connection_timestamp (NM_CONNECTION (rem_con), connection);

			}
			break;

		case NMC_EDITOR_MAIN_CMD_BACK:
			/* Go back (up) an the menu */
			if (menu_ctx.level == 1) {
				menu_switch_to_level0 (&nmc->nmc_config, &menu_ctx, BASE_PROMPT);
				nmc_tab_completion.setting = NULL;  /* for TAB completion */
			}
			break;

		case NMC_EDITOR_MAIN_CMD_HELP:
			/* Print command help */
			editor_main_help (cmd_arg);
			break;

		case NMC_EDITOR_MAIN_CMD_NMCLI:
			if (cmd_arg_p && matches (cmd_arg_p, "status-line")) {
				GError *tmp_err = NULL;
				gboolean bb;
				if (!nmc_string_to_bool (cmd_arg_v ? g_strstrip (cmd_arg_v) : "", &bb, &tmp_err)) {
					g_print (_("Error: status-line: %s\n"), tmp_err->message);
					g_clear_error (&tmp_err);
				} else
					nmc->editor_status_line = bb;
			} else if (cmd_arg_p && matches (cmd_arg_p, "save-confirmation")) {
				GError *tmp_err = NULL;
				gboolean bb;
				if (!nmc_string_to_bool (cmd_arg_v ? g_strstrip (cmd_arg_v) : "", &bb, &tmp_err)) {
					g_print (_("Error: save-confirmation: %s\n"), tmp_err->message);
					g_clear_error (&tmp_err);
				} else
					nmc->editor_save_confirmation = bb;
			} else if (cmd_arg_p && matches (cmd_arg_p, "show-secrets")) {
				GError *tmp_err = NULL;
				gboolean bb;
				if (!nmc_string_to_bool (cmd_arg_v ? g_strstrip (cmd_arg_v) : "", &bb, &tmp_err)) {
					g_print (_("Error: show-secrets: %s\n"), tmp_err->message);
					g_clear_error (&tmp_err);
				} else
					nmc->nmc_config_mutable.show_secrets = bb;
			} else if (cmd_arg_p && matches (cmd_arg_p, "prompt-color")) {
				g_debug ("Ignoring erroneous --prompt-color argument. Use terminal-colors.d(5) to set the prompt color.\n");
			} else if (!cmd_arg_p) {
				g_print (_("Current nmcli configuration:\n"));
				g_print ("status-line: %s\n"
				         "save-confirmation: %s\n"
				         "show-secrets: %s\n",
				         nmc->editor_status_line ? "yes" : "no",
				         nmc->editor_save_confirmation ? "yes" : "no",
				         nmc->nmc_config.show_secrets ? "yes" : "no");
			} else
				g_print (_("Invalid configuration option '%s'; allowed [%s]\n"),
				         cmd_arg_v ?: "", "status-line, save-confirmation, show-secrets");

			break;

		case NMC_EDITOR_MAIN_CMD_QUIT:
			if (is_connection_dirty (connection, rem_con)) {
				if (confirm_quit (&nmc->nmc_config))
					cmd_loop = FALSE;  /* quit command loop */
			} else
				cmd_loop = FALSE;  /* quit command loop */
			break;

		case NMC_EDITOR_MAIN_CMD_UNKNOWN:
		default:
			g_print (_("Unknown command: '%s'\n"), cmd_user);
			break;
		}
	}

	g_free (menu_ctx.main_prompt);
	g_strfreev (menu_ctx.valid_props);
	g_free (menu_ctx.valid_props_str);
	g_weak_ref_clear (&weak);

	quit ();

	/* Save history file */
	save_history_cmds (nm_connection_get_uuid (connection));

	return TRUE;
}

static const char *
get_ethernet_device_name (NmCli *nmc)
{
	const GPtrArray *devices;
	int i;

	devices = nm_client_get_devices (nmc->client);
	for (i = 0; i < devices->len; i++) {
		NMDevice *dev = g_ptr_array_index (devices, i);
		if (NM_IS_DEVICE_ETHERNET (dev))
			return nm_device_get_iface (dev);
	}
	return NULL;
}

static void
editor_init_new_connection (NmCli *nmc, NMConnection *connection, const char *slave_type)
{
	NMSetting *setting, *base_setting;
	NMSettingConnection *s_con;
	const char *con_type;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	con_type = nm_setting_connection_get_connection_type (s_con);

	/* Initialize new connection according to its type using sensible defaults. */

	nmc_setting_connection_connect_handlers (s_con, connection);

	if (slave_type) {
		const char *dev_ifname = get_ethernet_device_name (nmc);

		/* For bond/team/bridge slaves add 'wired' setting */
		setting = nm_setting_wired_new ();
		nm_connection_add_setting (connection, setting);

		g_object_set (s_con,
		              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
		              NM_SETTING_CONNECTION_MASTER, dev_ifname ?: "eth0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, slave_type,
		              NULL);
	} else {
		const NMMetaSettingInfoEditor *setting_info;

		/* Add a "base" setting to the connection by default */
		setting_info = nm_meta_setting_info_editor_find_by_name (con_type, FALSE);
		if (!setting_info)
			return;
		base_setting = nm_meta_setting_info_editor_new_setting (setting_info,
		                                                        NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI);
		nm_connection_add_setting (connection, base_setting);

		set_default_interface_name (nmc, s_con);

		/* Set sensible initial VLAN values */
		if (g_strcmp0 (con_type, NM_SETTING_VLAN_SETTING_NAME) == 0) {
			const char *dev_ifname = get_ethernet_device_name (nmc);

			g_object_set (NM_SETTING_VLAN (base_setting),
			              NM_SETTING_VLAN_PARENT, dev_ifname ?: "eth0",
			              NULL);
		}

		setting = nm_meta_setting_info_editor_new_setting (&nm_meta_setting_infos_editor[NM_META_SETTING_TYPE_IP4_CONFIG],
		                                                   NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI);
		nm_connection_add_setting (connection, setting);

		setting = nm_meta_setting_info_editor_new_setting (&nm_meta_setting_infos_editor[NM_META_SETTING_TYPE_IP6_CONFIG],
		                                                   NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI);
		nm_connection_add_setting (connection, setting);

		setting = nm_meta_setting_info_editor_new_setting (&nm_meta_setting_infos_editor[NM_META_SETTING_TYPE_PROXY],
		                                                   NM_META_ACCESSOR_SETTING_INIT_TYPE_CLI);
		nm_connection_add_setting (connection, setting);
	}
}

static void
editor_init_existing_connection (NMConnection *connection)
{
	NMSettingIPConfig *s_ip4, *s_ip6;
	NMSettingProxy *s_proxy;
	NMSettingWireless *s_wireless;
	NMSettingConnection *s_con;

	/* FIXME: this approach of connecting handlers to do something is fundamentally
	 * flawed. See the comment in nmc_setting_ip6_connect_handlers(). */

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	s_proxy = nm_connection_get_setting_proxy (connection);
	s_wireless = nm_connection_get_setting_wireless (connection);
	s_con = nm_connection_get_setting_connection (connection);

	if (s_ip4)
		nmc_setting_ip4_connect_handlers (s_ip4);
	if (s_ip6)
		nmc_setting_ip6_connect_handlers (s_ip6);
	if (s_proxy)
		nmc_setting_proxy_connect_handlers (s_proxy);
	if (s_wireless)
		nmc_setting_wireless_connect_handlers (s_wireless);
	if (s_con)
		nmc_setting_connection_connect_handlers (s_con, connection);
}

static void
nmc_complete_connection_type (const char *prefix)
{
	guint i;

	for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++) {
		const NMMetaSettingInfoEditor *setting_info = &nm_meta_setting_infos_editor[i];

		if (!*prefix || matches (prefix, setting_info->general->setting_name))
			g_print ("%s\n", setting_info->general->setting_name);
		if (   setting_info->alias
		    && (!*prefix || matches (prefix, setting_info->alias)))
			g_print ("%s\n", setting_info->alias);
	}
}

static NMCResultCode
do_connection_edit (NmCli *nmc, int argc, char **argv)
{
	const GPtrArray *connections;
	gs_unref_object NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	const char *connection_type;
	const char *type = NULL;
	const char *con_name = NULL;
	const char *con = NULL;
	const char *con_id = NULL;
	const char *con_uuid = NULL;
	const char *con_path = NULL;
	const char *con_filename = NULL;
	const char *selector = NULL;
	gs_free_error GError *error = NULL;
	GError *err1 = NULL;
	nmc_arg_t exp_args[] = { { "type",     TRUE, &type,     FALSE },
	                         { "con-name", TRUE, &con_name, FALSE },
	                         { "id",       TRUE, &con_id,   FALSE },
	                         { "uuid",     TRUE, &con_uuid, FALSE },
	                         { "path",     TRUE, &con_path, FALSE },
	                         { "filename", TRUE, &con_filename, FALSE },
	                         { NULL } };

	next_arg (nmc, &argc, &argv, NULL);
	if (argc == 1 && nmc->complete)
		nmc_complete_strings (*argv, "type", "con-name", "id", "uuid", "path",  "filename", NULL);

	nmc->return_value = NMC_RESULT_SUCCESS;

	if (argc == 1)
		con = *argv;
	else {
		if (!nmc_parse_args (exp_args, TRUE, &argc, &argv, &error)) {
			g_string_assign (nmc->return_text, error->message);
			NMC_RETURN (nmc, error->code);
		}
	}

	/* Setup some readline completion stuff */
	/* Set a pointer to an alternative function to create matches */
	rl_attempted_completion_function = nmcli_editor_tab_completion;
	/* Use ' ' and '.' as word break characters */
	rl_completer_word_break_characters = ". ";

	connections = nm_client_get_connections (nmc->client);

	if (!con) {
		if (con_id && !con_uuid && !con_path && !con_filename) {
			con = con_id;
			selector = "id";
		} else if (con_uuid && !con_id && !con_path && !con_filename) {
			con = con_uuid;
			selector = "uuid";
		} else if (con_path && !con_id && !con_uuid && !con_filename) {
			con = con_path;
			selector = "path";
		} else if (con_filename && !con_path && !con_id && !con_uuid) {
			con = con_filename;
			selector = "filename";
		} else if (!con_path && !con_id && !con_uuid && !con_filename) {
			/* no-op */
		} else {
			g_string_printf (nmc->return_text,
			                 _("Error: only one of 'id', 'filename', uuid, or 'path' can be provided."));
			NMC_RETURN (nmc, NMC_RESULT_ERROR_USER_INPUT);
		}
	}

	if (con) {
		/* Existing connection */
		NMConnection *found_con;

		found_con = nmc_find_connection (connections, selector, con, NULL, nmc->complete);
		if (nmc->complete)
			return nmc->return_value;

		if (!found_con) {
			g_string_printf (nmc->return_text, _("Error: Unknown connection '%s'."), con);
			NMC_RETURN (nmc, NMC_RESULT_ERROR_NOT_FOUND);
		}

		/* Duplicate the connection and use that so that we need not
		 * differentiate existing vs. new later
		 */
		connection = nm_simple_connection_new_clone (found_con);

		/* Merge secrets into the connection */
		update_secrets_in_connection (NM_REMOTE_CONNECTION (found_con), connection);

		s_con = nm_connection_get_setting_connection (connection);
		connection_type = nm_setting_connection_get_connection_type (s_con);

		if (type)
			g_print (_("Warning: editing existing connection '%s'; 'type' argument is ignored\n"),
			         nm_connection_get_id (connection));
		if (con_name)
			g_print (_("Warning: editing existing connection '%s'; 'con-name' argument is ignored\n"),
			         nm_connection_get_id (connection));

		/* Load previously saved history commands for the connection */
		load_history_cmds (nm_connection_get_uuid (connection));

		editor_init_existing_connection (connection);
	} else {
		const char *slave_type = NULL;
		gs_free char *uuid = NULL;
		gs_free char *default_name = NULL;
		gs_free char *tmp_str = NULL;

		/* New connection */
		if (nmc->complete) {
			if (type && argc == 0)
				nmc_complete_connection_type (type);
			return nmc->return_value;
		}

		connection_type = check_valid_name_toplevel (type, &slave_type, &err1);
		tmp_str = get_valid_options_string_toplevel ();

		while (!connection_type) {
			gs_free char *type_ask = NULL;

			if (!type)
				g_print (_("Valid connection types: %s\n"), tmp_str);
			else
				g_print (_("Error: invalid connection type; %s\n"), err1->message);
			g_clear_error (&err1);

			type_ask = nmc_readline (&nmc->nmc_config,
			                         EDITOR_PROMPT_CON_TYPE);
			type = type_ask = nm_strstrip (type_ask);
			connection_type = check_valid_name_toplevel (type_ask, &slave_type, &err1);
		}
		nm_clear_g_free (&tmp_str);

		connection = nm_simple_connection_new ();

		s_con = (NMSettingConnection *) nm_setting_connection_new ();
		uuid = nm_utils_uuid_generate ();
		if (con_name)
			default_name = g_strdup (con_name);
		else {
			default_name = nmc_unique_connection_name (connections,
			                                           get_name_alias_toplevel (connection_type, NULL));
		}

		g_object_set (s_con,
		              NM_SETTING_CONNECTION_ID, default_name,
		              NM_SETTING_CONNECTION_UUID, uuid,
		              NM_SETTING_CONNECTION_TYPE, connection_type,
		              NULL);
		nm_connection_add_setting (connection, NM_SETTING (s_con));

		/* Initialize the new connection so that it is valid from the start */
		editor_init_new_connection (nmc, connection, slave_type);
	}

	/* nmcli runs the editor */
	nmc->nmc_config_mutable.in_editor = TRUE;

	g_print ("\n");
	g_print (_("===| nmcli interactive connection editor |==="));
	g_print ("\n\n");
	if (con)
		g_print (_("Editing existing '%s' connection: '%s'"), connection_type, con);
	else
		g_print (_("Adding a new '%s' connection"), connection_type);
	g_print ("\n\n");
	g_print (_("Type 'help' or '?' for available commands."));
	g_print ("\n");
	g_print (_("Type 'print' to show all the connection properties."));
	g_print ("\n");
	g_print (_("Type 'describe [<setting>.<prop>]' for detailed property description."));
	g_print ("\n\n");

	nmc_tab_completion.nmc = nmc;
	nmc_tab_completion.con_type = g_strdup (connection_type);
	nmc_tab_completion.connection = connection;

	/* Run menu loop */
	editor_menu_main (nmc, connection, connection_type);

	nmc_tab_completion.nmc = NULL;
	nm_clear_g_free (&nmc_tab_completion.con_type);
	nmc_tab_completion.connection = NULL;

	return nmc->return_value;
}

static void
modify_connection_cb (GObject *connection,
                      GAsyncResult *result,
                      gpointer user_data)
{
	NmCli *nmc = user_data;
	gs_free_error GError *error = NULL;

	if (!nm_remote_connection_commit_changes_finish (NM_REMOTE_CONNECTION (connection),
	                                                 result, &error)) {
		g_string_printf (nmc->return_text,
		                 _("Error: Failed to modify connection '%s': %s"),
		                 nm_connection_get_id (NM_CONNECTION (connection)),
		                 error->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
	} else {
		if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY) {
			g_print (_("Connection '%s' (%s) successfully modified.\n"),
			         nm_connection_get_id (NM_CONNECTION (connection)),
			         nm_connection_get_uuid (NM_CONNECTION (connection)));
		}
	}
	quit ();
}

static NMCResultCode
do_connection_modify (NmCli *nmc,
                      int argc,
                      char **argv)
{
	NMConnection *connection = NULL;
	NMRemoteConnection *rc = NULL;
	gs_free_error GError *error = NULL;
	gboolean temporary = FALSE;

	if (next_arg (nmc, &argc, &argv, "--temporary", NULL) > 0) {
		temporary = TRUE;
		next_arg (nmc, &argc, &argv, NULL);
	}

	connection = get_connection (nmc, &argc, &argv, NULL, NULL, NULL, &error);
	if (!connection) {
		g_string_printf (nmc->return_text, _("Error: %s."), error->message);
		NMC_RETURN (nmc, error->code);
	}

	rc = nm_client_get_connection_by_uuid (nmc->client,
	                                       nm_connection_get_uuid (connection));
	if (!rc) {
		g_string_printf (nmc->return_text, _("Error: Unknown connection '%s'."),
		                 nm_connection_get_uuid (connection));
		NMC_RETURN (nmc, NMC_RESULT_ERROR_NOT_FOUND);
	}

	if (!nmc_read_connection_properties (nmc, NM_CONNECTION (rc), &argc, &argv, &error)) {
		g_string_assign (nmc->return_text, error->message);
		NMC_RETURN (nmc, error->code);
	}

	if (nmc->complete)
		return nmc->return_value;

	update_connection (!temporary, rc, modify_connection_cb, nmc);
	nmc->should_wait++;

	return nmc->return_value;
}

typedef struct {
	NmCli *nmc;
	char *orig_id;
	char *orig_uuid;
	char *con_id;
} CloneConnectionInfo;

static void
clone_connection_cb (GObject *client,
                     GAsyncResult *result,
                     gpointer user_data)
{
	CloneConnectionInfo *info = (CloneConnectionInfo *) user_data;
	NmCli *nmc = info->nmc;
	NMRemoteConnection *connection;
	GError *error = NULL;

	connection = nm_client_add_connection_finish (NM_CLIENT (client), result, &error);
	if (error) {
		g_string_printf (nmc->return_text,
		                 _("Error: Failed to add '%s' connection: %s"),
		                 info->con_id, error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
	} else {
		g_print (_("%s (%s) cloned as %s (%s).\n"),
		         info->orig_id,
		         info->orig_uuid,
		         nm_connection_get_id (NM_CONNECTION (connection)),
		         nm_connection_get_uuid (NM_CONNECTION (connection)));
		g_object_unref (connection);
	}

	g_free (info->con_id);
	g_free (info->orig_id);
	g_free (info->orig_uuid);
	g_slice_free (CloneConnectionInfo, info);
	quit ();
}

static NMCResultCode
do_connection_clone (NmCli *nmc, int argc, char **argv)
{
	NMConnection *connection = NULL;
	gs_unref_object NMConnection *new_connection = NULL;
	NMSettingConnection *s_con;
	CloneConnectionInfo *info;
	const char *new_name;
	gs_free char *new_name_ask = NULL;
	char *uuid;
	gboolean temporary = FALSE;
	char **arg_arr = NULL;
	int arg_num;
	char ***argv_ptr;
	int *argc_ptr;
	GError *error = NULL;

	if (next_arg (nmc, &argc, &argv, "--temporary", NULL) > 0) {
		temporary = TRUE;
		next_arg (nmc, &argc, &argv, NULL);
	}

	argv_ptr = &argv;
	argc_ptr = &argc;

	if (argc == 0 && nmc->ask) {
		gs_free char *line = NULL;

		/* nmc_do_cmd() should not call this with argc=0. */
		g_assert (!nmc->complete);

		line = nmc_readline (&nmc->nmc_config,
		                     PROMPT_CONNECTION);
		nmc_string_to_arg_array (line, NULL, TRUE, &arg_arr, &arg_num);
		argv_ptr = &arg_arr;
		argc_ptr = &arg_num;
	}

	connection = get_connection (nmc, argc_ptr, argv_ptr, NULL, NULL, NULL, &error);
	if (!connection) {
		g_string_printf (nmc->return_text, _("Error: %s."), error->message);
		NMC_RETURN (nmc, error->code);
	}

	if (nmc->complete)
		return nmc->return_value;

	if (argv[0])
		new_name = *argv;
	else if (nmc->ask) {
		new_name = new_name_ask = nmc_readline (&nmc->nmc_config,
		                                        _("New connection name: "));
	} else {
		g_string_printf (nmc->return_text, _("Error: <new name> argument is missing."));
		NMC_RETURN (nmc, NMC_RESULT_ERROR_USER_INPUT);
	}

	if (next_arg (nmc->ask ? NULL : nmc, argc_ptr, argv_ptr, NULL) == 0) {
		g_string_printf (nmc->return_text, _("Error: unknown extra argument: '%s'."), *argv);
		NMC_RETURN (nmc, NMC_RESULT_ERROR_USER_INPUT);
	}

	/* Copy the connection */
	new_connection = nm_simple_connection_new_clone (connection);

	s_con = nm_connection_get_setting_connection (new_connection);
	g_assert (s_con);
	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, new_name,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NULL);
	g_free (uuid);

	/* Merge secrets into the new connection */
	update_secrets_in_connection (NM_REMOTE_CONNECTION (connection), new_connection);

	info = g_slice_new0 (CloneConnectionInfo);
	info->nmc = nmc;
	info->orig_id = g_strdup (nm_connection_get_id (connection));
	info->orig_uuid = g_strdup (nm_connection_get_uuid (connection));
	info->con_id = g_strdup (nm_connection_get_id (new_connection));

	/* Add the new cloned connection to NetworkManager */
	add_new_connection (!temporary,
	                    nmc->client,
	                    new_connection,
	                    clone_connection_cb,
	                    info);

	nmc->should_wait++;
	return nmc->return_value;
}

static void
delete_cb (GObject *con, GAsyncResult *result, gpointer user_data)
{
	ConnectionCbInfo *info = (ConnectionCbInfo *) user_data;
	GError *error = NULL;

	if (!nm_remote_connection_delete_finish (NM_REMOTE_CONNECTION (con), result, &error)) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			return;
		g_string_printf (info->nmc->return_text, _("Error: not all connections deleted."));
		g_printerr (_("Error: Connection deletion failed: %s\n"),
		            error->message);
		g_error_free (error);
		info->nmc->return_value = NMC_RESULT_ERROR_CON_DEL;
		connection_cb_info_finish (info, con);
	} else {
		if (info->nmc->nowait_flag)
			connection_cb_info_finish (info, con);
	}
}

static NMCResultCode
do_connection_delete (NmCli *nmc, int argc, char **argv)
{
	NMConnection *connection;
	ConnectionCbInfo *info = NULL;
	gs_strfreev char **arg_arr = NULL;
	char **arg_ptr;
	guint i;
	int arg_num;
	nm_auto_free_gstring GString *invalid_cons = NULL;
	gs_unref_ptrarray GPtrArray *found_cons = NULL;
	GError *error = NULL;

	if (nmc->timeout == -1)
		nmc->timeout = 10;

	next_arg (nmc, &argc, &argv, NULL);
	arg_ptr = argv;
	arg_num = argc;

	if (argc == 0) {
		if (nmc->ask) {
			gs_free char *line = NULL;

			/* nmc_do_cmd() should not call this with argc=0. */
			g_assert (!nmc->complete);

			line = nmc_readline (&nmc->nmc_config,
			                     PROMPT_CONNECTIONS);
			nmc_string_to_arg_array (line, NULL, TRUE, &arg_arr, &arg_num);
			arg_ptr = arg_arr;
		}
		if (arg_num == 0) {
			g_string_printf (nmc->return_text, _("Error: No connection specified."));
			nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
			goto finish;
		}
	}

	while (arg_num > 0) {
		const char *cur_selector, *cur_value;

		connection = get_connection (nmc, &arg_num, &arg_ptr, &cur_selector, &cur_value, &found_cons, &error);
		if (!connection) {
			if (!nmc->complete)
				g_printerr (_("Error: %s.\n"), error->message);
			g_string_printf (nmc->return_text, _("Error: not all connections found."));
			nmc->return_value = error->code;
			g_clear_error (&error);

			if (nmc->return_value != NMC_RESULT_ERROR_NOT_FOUND)
				goto finish;

			if (!invalid_cons)
				invalid_cons = g_string_new (NULL);
			if (cur_selector)
				g_string_append_printf (invalid_cons, "%s '%s', ", cur_selector, cur_value);
			else
				g_string_append_printf (invalid_cons, "'%s', ", cur_value);
		}
	}

	if (!found_cons) {
		if (!invalid_cons) {
			g_string_printf (nmc->return_text, _("Error: No connection specified."));
			nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
		}
		goto finish;
	}

	if (nmc->complete)
		goto finish;

	info = g_slice_new0 (ConnectionCbInfo);
	info->nmc = nmc;
	info->obj_list = g_ptr_array_sized_new (found_cons->len);
	for (i = 0; i < found_cons->len; i++) {
		connection = found_cons->pdata[i];
		g_ptr_array_add (info->obj_list, g_object_ref (connection));
	}
	info->timeout_id = g_timeout_add_seconds (nmc->timeout, connection_op_timeout_cb, info);
	info->cancellable = g_cancellable_new ();

	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait++;

	g_signal_connect (nmc->client, NM_CLIENT_CONNECTION_REMOVED,
	                  G_CALLBACK (connection_removed_cb), info);

	for (i = 0; i < found_cons->len; i++) {
		nm_remote_connection_delete_async (NM_REMOTE_CONNECTION (found_cons->pdata[i]),
		                                   info->cancellable, delete_cb, info);
	}

finish:
	if (invalid_cons) {
		g_string_truncate (invalid_cons, invalid_cons->len-2);  /* truncate trailing ", " */
		g_string_printf (nmc->return_text, _("Error: cannot delete unknown connection(s): %s."),
		                 invalid_cons->str);
		nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
	}
	return nmc->return_value;
}

static void
connection_changed (NMConnection *connection, NmCli *nmc)
{
	g_print (_("%s: connection profile changed\n"), nm_connection_get_id (connection));
}

static void
connection_watch (NmCli *nmc, NMConnection *connection)
{
	nmc->should_wait++;
	g_signal_connect (connection, NM_CONNECTION_CHANGED, G_CALLBACK (connection_changed), nmc);
}

static void
connection_unwatch (NmCli *nmc, NMConnection *connection)
{
	if (g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (connection_changed), nmc))
		nmc->should_wait--;

	/* Terminate if all the watched connections disappeared. */
	if (!nmc->should_wait)
		quit ();
}

static void
connection_added (NMClient *client, NMRemoteConnection *con, NmCli *nmc)
{
	NMConnection *connection = NM_CONNECTION (con);

	g_print (_("%s: connection profile created\n"), nm_connection_get_id (connection));
	connection_watch (nmc, connection);
}

static void
connection_removed (NMClient *client, NMRemoteConnection *con, NmCli *nmc)
{
	NMConnection *connection = NM_CONNECTION (con);

	g_print (_("%s: connection profile removed\n"), nm_connection_get_id (connection));
	connection_unwatch (nmc, connection);
}

static NMCResultCode
do_connection_monitor (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;
	guint i;
	gs_unref_ptrarray GPtrArray *found_cons = NULL;
	const GPtrArray *connections = NULL;

	next_arg (nmc, &argc, &argv, NULL);
	if (argc == 0) {
		/* No connections specified. Monitor all. */

		/* nmc_do_cmd() should not call this with argc=0. */
		g_assert (!nmc->complete);

		connections = nm_client_get_connections (nmc->client);
	} else {
		while (argc > 0) {
			if (!get_connection (nmc, &argc, &argv, NULL, NULL, &found_cons, &error)) {
				if (!nmc->complete)
					g_printerr (_("Error: %s.\n"), error->message);
				g_string_printf (nmc->return_text, _("Error: not all connections found."));
				return error->code;
			}

			if (nmc->complete)
				continue;

			connections = found_cons;
		}
	}

	for (i = 0; i < connections->len; i++)
		connection_watch (nmc, connections->pdata[i]);

	if (argc == 0) {
		/* We'll watch the connection additions too, never exit. */
		nmc->should_wait++;
		g_signal_connect (nmc->client, NM_CLIENT_CONNECTION_ADDED, G_CALLBACK (connection_added), nmc);
	}

	if (nmc->complete)
		return nmc->return_value;
	g_signal_connect (nmc->client, NM_CLIENT_CONNECTION_REMOVED, G_CALLBACK (connection_removed), nmc);

	return NMC_RESULT_SUCCESS;
}

static NMCResultCode
do_connection_reload (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;

	next_arg (nmc, &argc, &argv, NULL);
	if (nmc->complete)
		return nmc->return_value;

	if (!nm_client_reload_connections (nmc->client, NULL, &error)) {
		g_string_printf (nmc->return_text, _("Error: failed to reload connections: %s."),
		                 nmc_error_get_simple_message (error));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		g_clear_error (&error);
	}

	return nmc->return_value;
}

static NMCResultCode
do_connection_load (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;
	char **filenames, **failures = NULL;
	int i;

	next_arg (nmc, &argc, &argv, NULL);
	if (argc == 0) {
		g_string_printf (nmc->return_text, _("Error: No connection specified."));
		return NMC_RESULT_ERROR_USER_INPUT;
	}

	if (nmc->complete)
		return NMC_RESULT_COMPLETE_FILE;

	filenames = g_new (char *, argc + 1);
	for (i = 0; i < argc; i++)
		filenames[i] = argv[i];
	filenames[i] = NULL;

	nm_client_load_connections (nmc->client, filenames, &failures, NULL, &error);
	g_free (filenames);
	if (error) {
		g_string_printf (nmc->return_text, _("Error: failed to load connection: %s."),
		                 nmc_error_get_simple_message (error));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		g_error_free (error);
	}

	if (failures) {
		for (i = 0; failures[i]; i++)
			g_printerr (_("Could not load file '%s'\n"), failures[i]);
		g_strfreev (failures);
	}

	return nmc->return_value;
}

#define PROMPT_IMPORT_FILE N_("File to import: ")

static NMCResultCode
do_connection_import (NmCli *nmc, int argc, char **argv)
{
	gs_free_error GError *error = NULL;
	const char *type = NULL, *filename = NULL;
	gs_free char *type_ask = NULL;
	gs_free char *filename_ask = NULL;
	AddConnectionInfo *info;
	gs_unref_object NMConnection *connection = NULL;
	NMVpnEditorPlugin *plugin;
	gs_free char *service_type = NULL;
	gboolean temporary = FALSE;

	/* Check --temporary */
	if (next_arg (nmc, &argc, &argv, "--temporary", NULL) > 0) {
		temporary = TRUE;
		next_arg (nmc, &argc, &argv, NULL);
	}

	if (argc == 0) {
		/* nmc_do_cmd() should not call this with argc=0. */
		g_assert (!nmc->complete);

		if (nmc->ask) {
			type_ask = nmc_readline (&nmc->nmc_config,
			                         "%s: ",
			                         gettext (NM_META_TEXT_PROMPT_VPN_TYPE));
			type = nm_strstrip (type_ask);
			filename_ask = nmc_readline (&nmc->nmc_config,
			                             gettext (PROMPT_IMPORT_FILE));
			filename = nm_strstrip (filename_ask);
		} else {
			g_string_printf (nmc->return_text, _("Error: No arguments provided."));
			NMC_RETURN (nmc, NMC_RESULT_ERROR_USER_INPUT);
		}
	}

	while (argc > 0) {
		if (argc == 1 && nmc->complete) {
			nmc_complete_strings (*argv,
			                      type ? NULL : "type",
			                      filename ? NULL : "file");
		}

		if (strcmp (*argv, "type") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				NMC_RETURN (nmc, NMC_RESULT_ERROR_USER_INPUT);
			}

			if (   argc == 1
			    && nmc->complete) {
				nmc_complete_strings (*argv, "wireguard");
				complete_option ((const NMMetaAbstractInfo *) nm_meta_property_info_vpn_service_type,
				                 *argv,
				                 NULL);
			}

			if (!type)
				type = *argv;
			else
				g_printerr (_("Warning: 'type' already specified, ignoring extra one.\n"));

		} else if (strcmp (*argv, "file") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				NMC_RETURN (nmc, NMC_RESULT_ERROR_USER_INPUT);
			}
			if (argc == 1 && nmc->complete)
				nmc->return_value = NMC_RESULT_COMPLETE_FILE;
			if (!filename)
				filename = *argv;
			else
				g_printerr (_("Warning: 'file' already specified, ignoring extra one.\n"));
		} else {
			g_string_printf (nmc->return_text, _("Unknown parameter: %s"), *argv);
			NMC_RETURN (nmc, NMC_RESULT_ERROR_USER_INPUT);
		}

		next_arg (nmc, &argc, &argv, NULL);
	}

	if (nmc->complete)
		return nmc->return_value;

	if (!type) {
		g_string_printf (nmc->return_text, _("Error: 'type' argument is required."));
		NMC_RETURN (nmc, NMC_RESULT_ERROR_USER_INPUT);
	}
	if (!filename) {
		g_string_printf (nmc->return_text, _("Error: 'file' argument is required."));
		NMC_RETURN (nmc, NMC_RESULT_ERROR_USER_INPUT);
	}

	if (nm_streq (type, "wireguard"))
		connection = nm_vpn_wireguard_import (filename, &error);
	else {
		service_type = nm_vpn_plugin_info_list_find_service_type (nm_vpn_get_plugin_infos (), type);
		if (!service_type) {
			g_string_printf (nmc->return_text, _("Error: failed to find VPN plugin for %s."), type);
			NMC_RETURN (nmc, NMC_RESULT_ERROR_UNKNOWN);
		}

		/* Import VPN configuration */
		plugin = nm_vpn_get_editor_plugin (service_type, &error);
		if (!plugin) {
			g_string_printf (nmc->return_text, _("Error: failed to load VPN plugin: %s."),
			                 error->message);
			NMC_RETURN (nmc, NMC_RESULT_ERROR_UNKNOWN);
		}

		connection = nm_vpn_editor_plugin_import (plugin, filename, &error);
	}

	if (!connection) {
		g_string_printf (nmc->return_text, _("Error: failed to import '%s': %s."),
		                 filename, error->message);
		NMC_RETURN (nmc, NMC_RESULT_ERROR_UNKNOWN);
	}

	info = g_malloc0 (sizeof (AddConnectionInfo));
	info->nmc = nmc;
	info->con_name = g_strdup (nm_connection_get_id (connection));

	/* Add the new imported connection to NetworkManager */
	add_new_connection (!temporary,
	                    nmc->client,
	                    connection,
	                    add_connection_cb,
	                    info);

	nmc->should_wait++;
	return nmc->return_value;
}

static NMCResultCode
do_connection_export (NmCli *nmc, int argc, char **argv)
{
	NMConnection *connection = NULL;
	const char *out_name = NULL;
	gs_free char *out_name_ask = NULL;
	const char *path = NULL;
	const char *type = NULL;
	NMVpnEditorPlugin *plugin;
	gs_free_error GError *error = NULL;
	char tmpfile[] = "/tmp/nmcli-export-temp-XXXXXX";
	char **arg_arr = NULL;
	int arg_num;
	char ***argv_ptr;
	int *argc_ptr;

	next_arg (nmc, &argc, &argv, NULL);
	argv_ptr = &argv;
	argc_ptr = &argc;

	if (argc == 0 && nmc->ask) {
		gs_free char *line = NULL;

		/* nmc_do_cmd() should not call this with argc=0. */
		g_assert (!nmc->complete);

		line = nmc_readline (&nmc->nmc_config,
		                     PROMPT_VPN_CONNECTION);
		nmc_string_to_arg_array (line, NULL, TRUE, &arg_arr, &arg_num);
		argv_ptr = &arg_arr;
		argc_ptr = &arg_num;
	}

	connection = get_connection (nmc, argc_ptr, argv_ptr, NULL, NULL, NULL, &error);
	if (!connection) {
		g_string_printf (nmc->return_text, _("Error: %s."), error->message);
		nmc->return_value = error->code;
		goto finish;
	}

	if (nmc->complete)
		return nmc->return_value;

	out_name = *argv;

	if (next_arg (nmc->ask ? NULL : nmc, argc_ptr, argv_ptr, NULL) == 0) {
		g_string_printf (nmc->return_text, _("Error: unknown extra argument: '%s'."), *argv);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}

	if (!out_name && nmc->ask) {
		out_name = out_name_ask = nmc_readline (&nmc->nmc_config,
		                                        _("Output file name: "));
	}

	type = nm_connection_get_connection_type (connection);
	if (g_strcmp0 (type, NM_SETTING_VPN_SETTING_NAME) != 0) {
		g_string_printf (nmc->return_text, _("Error: the connection is not VPN."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}
	type = nm_setting_vpn_get_service_type (nm_connection_get_setting_vpn (connection));

	/* Export VPN configuration */
	plugin = nm_vpn_get_editor_plugin (type, &error);
	if (!plugin) {
		g_string_printf (nmc->return_text, _("Error: failed to load VPN plugin: %s."),
		                 error->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto finish;
	}

	if (out_name)
		path = out_name;
	else {
		nm_auto_close int fd = -1;

		fd = g_mkstemp_full (tmpfile, O_RDWR | O_CLOEXEC, 0600);
		if (fd == -1) {
			g_string_printf (nmc->return_text, _("Error: failed to create temporary file %s."), tmpfile);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto finish;
		}
		path = tmpfile;
	}

	if (!nm_vpn_editor_plugin_export (plugin, path, connection, &error)) {
		g_string_printf (nmc->return_text, _("Error: failed to export '%s': %s."),
		                 nm_connection_get_id (connection), error->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto finish;
	}

	/* No output file -> copy data to stdout */
	if (!out_name) {
		gs_free char *contents = NULL;
		gsize len = 0;

		if (!g_file_get_contents (path, &contents, &len, &error)) {
			g_string_printf (nmc->return_text, _("Error: failed to read temporary file '%s': %s."),
			                 path, error->message);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto finish;
		}
		g_print ("%s", contents);
	}

finish:
	if (!out_name && path)
		unlink (path);
	return nmc->return_value;
}

static char *
gen_func_connection_names (const char *text, int state)
{
	int i;
	const GPtrArray *connections;
	const char **connection_names;
	char *ret;

	connections = nm_client_get_connections (nm_cli.client);
	if (connections->len == 0)
		return NULL;

	connection_names = g_new (const char *, connections->len + 1);
	for (i = 0; i < connections->len; i++)
		connection_names[i] = nm_connection_get_id (NM_CONNECTION (connections->pdata[i]));
	connection_names[i] = NULL;

	ret = nmc_rl_gen_func_basic (text, state, connection_names);

	g_free (connection_names);
	return ret;
}

static char *
gen_func_active_connection_names (const char *text, int state)
{
	int i;
	const GPtrArray *acs;
	const char **connections;
	char *ret;

	if (!nm_cli.client)
		return NULL;

	acs = nm_client_get_active_connections (nm_cli.client);
	if (!acs || acs->len == 0)
		return NULL;

	connections = g_new (const char *, acs->len + 1);
	for (i = 0; i < acs->len; i++)
		connections[i] = nm_active_connection_get_id (acs->pdata[i]);
	connections[i] = NULL;

	ret = nmc_rl_gen_func_basic (text, state, connections);

	g_free (connections);
	return ret;
}

static char **
nmcli_con_tab_completion (const char *text, int start, int end)
{
	char **match_array = NULL;
	rl_compentry_func_t *generator_func = NULL;
	const NMMetaAbstractInfo *info;

	/* Disable readline's default filename completion */
	rl_attempted_completion_over = 1;

	if (g_strcmp0 (rl_prompt, PROMPT_CONNECTION) == 0) {
		/* Disable appending space after completion */
		rl_completion_append_character = '\0';

		if (!is_single_word (rl_line_buffer))
			return NULL;

		generator_func = gen_func_connection_names;
	} else if (g_strcmp0 (rl_prompt, PROMPT_CONNECTIONS) == 0) {
		generator_func = gen_func_connection_names;
	} else if (g_strcmp0 (rl_prompt, PROMPT_ACTIVE_CONNECTIONS) == 0) {
		generator_func = gen_func_active_connection_names;
	} else if (rl_prompt && g_str_has_prefix (rl_prompt, NM_META_TEXT_PROMPT_VPN_TYPE)) {
		info = (const NMMetaAbstractInfo *) nm_meta_property_info_vpn_service_type;
		nmc_tab_completion.words = _meta_abstract_complete (info, text);
		generator_func = _meta_abstract_generator;
	} else if (g_strcmp0 (rl_prompt, PROMPT_IMPORT_FILE) == 0) {
		rl_attempted_completion_over = 0;
		rl_complete_with_tilde_expansion = 1;
	} else if (g_strcmp0 (rl_prompt, PROMPT_VPN_CONNECTION) == 0) {
		generator_func = gen_vpn_ids;
	}

	if (generator_func)
		match_array = rl_completion_matches (text, generator_func);

	g_clear_pointer (&nmc_tab_completion.words, g_strfreev);
	return match_array;
}

static const NMCCommand connection_cmds[] = {
	{ "show",     do_connections_show,      usage_connection_show,     TRUE,   TRUE },
	{ "up",       do_connection_up,         usage_connection_up,       TRUE,   TRUE },
	{ "down",     do_connection_down,       usage_connection_down,     TRUE,   TRUE },
	{ "add",      do_connection_add,        usage_connection_add,      TRUE,   TRUE },
	{ "edit",     do_connection_edit,       usage_connection_edit,     TRUE,   TRUE },
	{ "delete",   do_connection_delete,     usage_connection_delete,   TRUE,   TRUE },
	{ "reload",   do_connection_reload,     usage_connection_reload,   TRUE,   TRUE },
	{ "load",     do_connection_load,       usage_connection_load,     TRUE,   TRUE },
	{ "modify",   do_connection_modify,     usage_connection_modify,   TRUE,   TRUE },
	{ "clone",    do_connection_clone,      usage_connection_clone,    TRUE,   TRUE },
	{ "import",   do_connection_import,     usage_connection_import,   TRUE,   TRUE },
	{ "export",   do_connection_export,     usage_connection_export,   TRUE,   TRUE },
	{ "monitor",  do_connection_monitor,    usage_connection_monitor,  TRUE,   TRUE },
	{ NULL,       do_connections_show,      usage,                     TRUE,   TRUE },
};

/* Entry point function for connections-related commands: 'nmcli connection' */
NMCResultCode
do_connections (NmCli *nmc, int argc, char **argv)
{
	next_arg (nmc, &argc, &argv, NULL);

	/* Register polkit agent */
	nmc_start_polkit_agent_start_try (nmc);

	/* Set completion function for 'nmcli con' */
	rl_attempted_completion_function = nmcli_con_tab_completion;

	nmc_do_cmd (nmc, connection_cmds, *argv, argc, argv);

	return nmc->return_value;
}

void
monitor_connections (NmCli *nmc)
{
	do_connection_monitor (nmc, 0, NULL);
}
