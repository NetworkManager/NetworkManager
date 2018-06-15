/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * Copyright 2008 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nms-ifcfg-rh-reader.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "nm-connection.h"
#include "nm-dbus-interface.h"
#include "nm-setting-connection.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-vlan.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-8021x.h"
#include "nm-setting-bond.h"
#include "nm-setting-team.h"
#include "nm-setting-team-port.h"
#include "nm-setting-bridge.h"
#include "nm-setting-bridge-port.h"
#include "nm-setting-dcb.h"
#include "nm-setting-user.h"
#include "nm-setting-proxy.h"
#include "nm-setting-generic.h"
#include "nm-core-internal.h"
#include "nm-utils.h"

#include "platform/nm-platform.h"
#include "NetworkManagerUtils.h"

#include "nms-ifcfg-rh-common.h"
#include "nms-ifcfg-rh-utils.h"
#include "shvar.h"

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_SETTINGS
#define _NMLOG_PREFIX_NAME "ifcfg-rh"
#define _NMLOG(level, ...) \
    G_STMT_START { \
        nm_log ((level), (_NMLOG_DOMAIN), NULL, NULL, \
                "%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                _NMLOG_PREFIX_NAME": " \
                _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

#define PARSE_WARNING(...) _LOGW ("%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__), "    " _NM_UTILS_MACRO_REST(__VA_ARGS__))

/*****************************************************************************/

static void
check_if_bond_slave (shvarFile *ifcfg,
                     NMSettingConnection *s_con)
{
	gs_free char *value = NULL;
	const char *v;
	const char *master;

	v = svGetValueStr (ifcfg, "MASTER_UUID", &value);
	if (!v)
		v = svGetValueStr (ifcfg, "MASTER", &value);

	if (v) {
		master = nm_setting_connection_get_master (s_con);
		if (master) {
			PARSE_WARNING ("Already configured as slave of %s. Ignoring MASTER{_UUID}=\"%s\"",
			               master, v);
			return;
		}

		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, v,
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BOND_SETTING_NAME,
		              NULL);
	}

	/* We should be checking for SLAVE=yes as well, but NM used to not set that,
	 * so for backward-compatibility, we don't check.
	 */
}

static void
check_if_team_slave (shvarFile *ifcfg,
                     NMSettingConnection *s_con)
{
	gs_free char *value = NULL;
	const char *v;
	const char *master;

	v = svGetValueStr (ifcfg, "TEAM_MASTER_UUID", &value);
	if (!v)
		v = svGetValueStr (ifcfg, "TEAM_MASTER", &value);
	if (!v)
		return;

	master = nm_setting_connection_get_master (s_con);
	if (master) {
		PARSE_WARNING ("Already configured as slave of %s. Ignoring TEAM_MASTER{_UUID}=\"%s\"",
		               master, v);
		return;
	}

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_MASTER, v,
	              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_TEAM_SETTING_NAME,
	              NULL);
}

static char *
make_connection_name (shvarFile *ifcfg,
                      const char *ifcfg_name,
                      const char *suggested,
                      const char *prefix)
{
	char *full_name = NULL, *name;

	/* If the ifcfg file already has a NAME, always use that */
	name = svGetValueStr_cp (ifcfg, "NAME");
	if (name)
		return name;

	/* Otherwise construct a new NAME */
	if (!prefix)
		prefix = "System";

	/* For cosmetic reasons, if the suggested name is the same as
	 * the ifcfg files name, don't use it.  Mainly for wifi so that
	 * the SSID is shown in the connection ID instead of just "wlan0".
	 */
	if (suggested && strcmp (ifcfg_name, suggested))
		full_name = g_strdup_printf ("%s %s (%s)", prefix, suggested, ifcfg_name);
	else
		full_name = g_strdup_printf ("%s %s", prefix, ifcfg_name);

	return full_name;
}

static NMSetting *
make_connection_setting (const char *file,
                         shvarFile *ifcfg,
                         const char *type,
                         const char *suggested,
                         const char *prefix)
{
	NMSettingConnection *s_con;
	NMSettingConnectionLldp lldp;
	const char *ifcfg_name = NULL;
	char *new_id;
	const char *uuid;
	gs_free char *uuid_free = NULL;
	gs_free char *value = NULL;
	const char *v;
	gs_free char *stable_id = NULL;
	const char *const *iter;
	int vint64, i_val;

	ifcfg_name = utils_get_ifcfg_name (file, TRUE);
	if (!ifcfg_name)
		return NULL;

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());

	new_id = make_connection_name (ifcfg, ifcfg_name, suggested, prefix);
	g_object_set (s_con, NM_SETTING_CONNECTION_ID, new_id, NULL);
	g_free (new_id);

	/* Try for a UUID key before falling back to hashing the file name */
	uuid = svGetValueStr (ifcfg, "UUID", &uuid_free);
	if (!uuid) {
		uuid_free = nm_utils_uuid_generate_from_string (svFileGetName (ifcfg), -1, NM_UTILS_UUID_TYPE_LEGACY, NULL);
		uuid = uuid_free;
	}

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_TYPE, type,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_STABLE_ID, svGetValue (ifcfg, "STABLE_ID", &stable_id),
	              NULL);

	v = svGetValueStr (ifcfg, "DEVICE", &value);
	if (v) {
		GError *error = NULL;

		if (nm_utils_is_valid_iface_name (v, &error)) {
			g_object_set (s_con,
			              NM_SETTING_CONNECTION_INTERFACE_NAME, v,
			              NULL);
		} else {
			PARSE_WARNING ("invalid DEVICE name '%s': %s", v, error->message);
			g_error_free (error);
		}
	}

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "LLDP", &value);
	if (nm_streq0 (v, "rx"))
		lldp = NM_SETTING_CONNECTION_LLDP_ENABLE_RX;
	else
		lldp = svParseBoolean (v, NM_SETTING_CONNECTION_LLDP_DEFAULT);

	/* Missing ONBOOT is treated as "ONBOOT=true" by the old network service */
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_AUTOCONNECT,
	              svGetValueBoolean (ifcfg, "ONBOOT", TRUE),
	              NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY,
	              (gint) svGetValueInt64 (ifcfg, "AUTOCONNECT_PRIORITY", 10,
	                                      NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_MIN,
	                                      NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_MAX,
	                                      NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_DEFAULT),
	              NM_SETTING_CONNECTION_AUTOCONNECT_RETRIES,
	              (gint) svGetValueInt64 (ifcfg, "AUTOCONNECT_RETRIES", 10,
	                                      -1, G_MAXINT32, -1),
	              NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES,
	              svGetValueBoolean (ifcfg, "AUTOCONNECT_SLAVES", NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_DEFAULT),
	              NM_SETTING_CONNECTION_LLDP, lldp,
	              NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "USERS", &value);
	if (v) {
		gs_free const char **items = NULL;

		items = nm_utils_strsplit_set (v, " ");
		for (iter = items; iter && *iter; iter++) {
			if (!nm_setting_connection_add_permission (s_con, "user", *iter, NULL))
				PARSE_WARNING ("invalid USERS item '%s'", *iter);
		}
	}

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "ZONE", &value);
	g_object_set (s_con, NM_SETTING_CONNECTION_ZONE, v, NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "SECONDARY_UUIDS", &value);
	if (v) {
		gs_free const char **items = NULL;

		items = nm_utils_strsplit_set (v, " \t");
		for (iter = items; iter && *iter; iter++) {
			if (!nm_setting_connection_add_secondary (s_con, *iter))
				PARSE_WARNING ("secondary connection UUID '%s' already added", *iter);
		}
	}

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "BRIDGE_UUID", &value);
	if (!v)
		v = svGetValueStr (ifcfg, "BRIDGE", &value);
	if (v) {
		const char *old_value;

		if ((old_value = nm_setting_connection_get_master (s_con))) {
			PARSE_WARNING ("Already configured as slave of %s. Ignoring BRIDGE=\"%s\"",
			               old_value, v);
		} else {
			g_object_set (s_con, NM_SETTING_CONNECTION_MASTER, v, NULL);
			g_object_set (s_con, NM_SETTING_CONNECTION_SLAVE_TYPE,
			              NM_SETTING_BRIDGE_SETTING_NAME, NULL);
		}
	}

	check_if_bond_slave (ifcfg, s_con);
	check_if_team_slave (ifcfg, s_con);

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "OVS_PORT_UUID", &value);
	if (!v)
		v = svGetValueStr (ifcfg, "OVS_PORT", &value);
	if (v) {
		const char *old_value;

		if ((old_value = nm_setting_connection_get_master (s_con))) {
			PARSE_WARNING ("Already configured as slave of %s. Ignoring OVS_PORT=\"%s\"",
			               old_value, v);
		} else {
			g_object_set (s_con, NM_SETTING_CONNECTION_MASTER, v, NULL);
			g_object_set (s_con, NM_SETTING_CONNECTION_SLAVE_TYPE,
			              NM_SETTING_OVS_PORT_SETTING_NAME, NULL);
		}
	}

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "GATEWAY_PING_TIMEOUT", &value);
	if (v) {
		gint64 tmp;

		tmp = _nm_utils_ascii_str_to_int64 (v, 10, 0, G_MAXINT32 - 1, -1);
		if (tmp >= 0) {
			if (tmp > 600) {
				tmp = 600;
				PARSE_WARNING ("invalid GATEWAY_PING_TIMEOUT time");
			}
			g_object_set (s_con, NM_SETTING_CONNECTION_GATEWAY_PING_TIMEOUT, (guint) tmp, NULL);
		} else
			PARSE_WARNING ("invalid GATEWAY_PING_TIMEOUT time");
	}

	switch (svGetValueBoolean (ifcfg, "CONNECTION_METERED", -1)) {
	case TRUE:
		g_object_set (s_con, NM_SETTING_CONNECTION_METERED, NM_METERED_YES, NULL);
		break;
	case FALSE:
		g_object_set (s_con, NM_SETTING_CONNECTION_METERED, NM_METERED_NO, NULL);
		break;
	}

	vint64 = svGetValueInt64 (ifcfg, "AUTH_RETRIES", 10, -1, G_MAXINT32, -1);
	g_object_set (s_con, NM_SETTING_CONNECTION_AUTH_RETRIES, (gint) vint64, NULL);

	i_val = NM_SETTING_CONNECTION_MDNS_DEFAULT;
	if (!svGetValueEnum (ifcfg, "MDNS",
	                     nm_setting_connection_mdns_get_type (),
	                     &i_val, NULL))
		PARSE_WARNING ("invalid MDNS setting");
	g_object_set (s_con, NM_SETTING_CONNECTION_MDNS, i_val, NULL);

	return NM_SETTING (s_con);
}

/* Returns TRUE on missing address or valid address */
static gboolean
read_ip4_address (shvarFile *ifcfg,
                  const char *tag,
                  gboolean *out_has_key,
                  guint32 *out_addr,
                  GError **error)
{
	gs_free char *value_to_free = NULL;
	const char *value;
	guint32 a;

	nm_assert (ifcfg);
	nm_assert (tag);
	nm_assert (!error || !*error);

	value = svGetValueStr (ifcfg, tag, &value_to_free);
	if (!value) {
		NM_SET_OUT (out_has_key, FALSE);
		NM_SET_OUT (out_addr, 0);
		return TRUE;
	}

	if (inet_pton (AF_INET, value, &a) != 1) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Invalid %s IP4 address '%s'", tag, value);
		return FALSE;
	}

	NM_SET_OUT (out_has_key, TRUE);
	NM_SET_OUT (out_addr, a);
	return TRUE;
}

static gboolean
is_any_ip4_address_defined (shvarFile *ifcfg, int *idx)
{
	int i, ignore, *ret_idx;

	ret_idx = idx ?: &ignore;

	for (i = -1; i <= 2; i++) {
		gs_free char *value = NULL;
		char tag[256];

		if (svGetValueStr (ifcfg, numbered_tag (tag, "IPADDR", i), &value)) {
			*ret_idx = i;
			return TRUE;
		}

		if (svGetValueStr (ifcfg, numbered_tag (tag, "PREFIX", i), &value)) {
			*ret_idx = i;
			return TRUE;
		}

		if (svGetValueStr (ifcfg, numbered_tag (tag, "NETMASK", i), &value)) {
			*ret_idx = i;
			return TRUE;
		}
	}
	return FALSE;
}

/* Returns TRUE on missing address or valid address */
static gboolean
read_full_ip4_address (shvarFile *ifcfg,
                       gint32 which,
                       NMIPAddress *base_addr,
                       NMIPAddress **out_address,
                       char **out_gateway,
                       GError **error)
{
	char tag[256];
	char prefix_tag[256];
	guint32 ipaddr;
	gs_free char *value = NULL;
	const char *v;
	int prefix = 0;
	gboolean has_key;
	guint32 a;
	char inet_buf[NM_UTILS_INET_ADDRSTRLEN];

	g_return_val_if_fail (which >= -1, FALSE);
	g_return_val_if_fail (ifcfg != NULL, FALSE);
	g_return_val_if_fail (out_address != NULL, FALSE);
	g_return_val_if_fail (*out_address == NULL, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	/* IP address */
	if (!read_ip4_address (ifcfg,
	                       numbered_tag (tag, "IPADDR", which),
	                       &has_key, &ipaddr, error))
		return FALSE;
	if (!has_key) {
		if (!base_addr)
			return TRUE;
		nm_ip_address_get_address_binary (base_addr, &ipaddr);
	}

	/* Gateway */
	if (out_gateway && !*out_gateway) {
		if (!read_ip4_address (ifcfg,
		                       numbered_tag (tag, "GATEWAY", which),
		                       &has_key, &a, error))
			return FALSE;
		if (has_key)
			*out_gateway = g_strdup (nm_utils_inet4_ntop (a, inet_buf));
	}

	/* Prefix */
	numbered_tag (prefix_tag, "PREFIX", which);
	v = svGetValueStr (ifcfg, prefix_tag, &value);
	if (v) {
		prefix = _nm_utils_ascii_str_to_int64 (v, 10, 0, 32, -1);
		if (prefix < 0) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid IP4 prefix '%s'", v);
			return FALSE;
		}
	} else {
		/* Fall back to NETMASK if no PREFIX was specified */
		if (!read_ip4_address (ifcfg,
		                       numbered_tag (tag, "NETMASK", which),
		                       &has_key, &a, error))
			return FALSE;
		if (has_key)
			prefix = nm_utils_ip4_netmask_to_prefix (a);
		else {
			if (base_addr)
				prefix = nm_ip_address_get_prefix (base_addr);
			else {
				/* Try to autodetermine the prefix for the address' class */
				prefix = _nm_utils_ip4_get_default_prefix (ipaddr);
				PARSE_WARNING ("missing %s, assuming %s/%d", prefix_tag, nm_utils_inet4_ntop (ipaddr, inet_buf), prefix);
			}
		}
	}

	*out_address = nm_ip_address_new_binary (AF_INET, &ipaddr, prefix, error);
	if (*out_address)
		return TRUE;

	return FALSE;
}

/*****************************************************************************/

static gboolean
parse_route_line_is_comment (const char *line)
{
	/* we obtained the line from a legacy route file. Here we skip
	 * empty lines and comments.
	 *
	 * initscripts compares: "$line" =~ '^[[:space:]]*(\#.*)?$'
	 */
	while (nm_utils_is_separator (line[0]))
		line++;
	if (NM_IN_SET (line[0], '\0', '#'))
		return TRUE;
	return FALSE;
}

/*****************************************************************************/

typedef struct {
	const char *key;

	/* the element is not available in this case. */
	bool disabled:1;

	/* whether the element is to be ignored. Ignord is different from
	 * "disabled", because we still parse the option, but don't use it. */
	bool ignore:1;

	bool int_base_16:1;

	/* whether the command line option was found, and @v is
	 * initialized. */
	bool has:1;

	/* the type, one of PARSE_LINE_TYPE_* */
	char type;

	union {
		guint8 uint8;
		guint32 uint32;
		struct {
			guint32 uint32;
			bool lock:1;
		} uint32_with_lock;
		struct {
			NMIPAddr addr;
			guint8 plen;
			bool has_plen:1;
		} addr;
	} v;

} ParseLineInfo;

enum {
	/* route attributes */
	PARSE_LINE_ATTR_ROUTE_TABLE,
	PARSE_LINE_ATTR_ROUTE_SRC,
	PARSE_LINE_ATTR_ROUTE_FROM,
	PARSE_LINE_ATTR_ROUTE_TOS,
	PARSE_LINE_ATTR_ROUTE_ONLINK,
	PARSE_LINE_ATTR_ROUTE_WINDOW,
	PARSE_LINE_ATTR_ROUTE_CWND,
	PARSE_LINE_ATTR_ROUTE_INITCWND,
	PARSE_LINE_ATTR_ROUTE_INITRWND,
	PARSE_LINE_ATTR_ROUTE_MTU,

	/* iproute2 arguments that only matter when parsing the file. */
	PARSE_LINE_ATTR_ROUTE_TO,
	PARSE_LINE_ATTR_ROUTE_VIA,
	PARSE_LINE_ATTR_ROUTE_METRIC,

	/* iproute2 parameters that are well known and that we silently ignore. */
	PARSE_LINE_ATTR_ROUTE_DEV,
};

#define PARSE_LINE_TYPE_UINT8             '8'
#define PARSE_LINE_TYPE_UINT32            'u'
#define PARSE_LINE_TYPE_UINT32_WITH_LOCK  'l'
#define PARSE_LINE_TYPE_ADDR              'a'
#define PARSE_LINE_TYPE_ADDR_WITH_PREFIX  'p'
#define PARSE_LINE_TYPE_IFNAME            'i'
#define PARSE_LINE_TYPE_FLAG              'f'

/**
 * parse_route_line:
 * @line: the line to parse. This is either a line from the route-* or route6-* file,
 *   or the numbered OPTIONS setting.
 * @addr_family: the address family.
 * @options_route: (in-out): when line is from the OPTIONS setting, this is a pre-created
 *   route object that is completed with the settings from options. Otherwise,
 *   it shall point to %NULL and a new route is created and returned.
 * @out_route: (out): (transfer-full): (allow-none): the parsed %NMIPRoute instance.
 *   In case a @options_route is passed in, it returns the input route that was modified
 *   in-place. But the caller must unref the returned route in either case.
 * @error: the failure description.
 *
 * Parsing the route options line has two modes: one for the numbered OPTIONS
 * setting, and one for initscript's handle_ip_file(), which takes the lines
 * and passes them to `ip route add`. The modes are similar, but certain properties
 * are not allowed for OPTIONS.
 * The mode is differenciated by having an @options_route argument.
 *
 * Returns: returns a negative errno on failure. On success, it returns 0
 *   and @out_route.
 */
static int
parse_route_line (const char *line,
                  int addr_family,
                  NMIPRoute *options_route,
                  NMIPRoute **out_route,
                  GError **error)
{
	nm_auto_ip_route_unref NMIPRoute *route = NULL;
	gs_free const char **words_free = NULL;
	const char *const*words;
	const char *s;
	gsize i_words;
	guint i;
	char buf1[256];
	char buf2[256];
	ParseLineInfo infos[] = {
		[PARSE_LINE_ATTR_ROUTE_TABLE]     = { .key = NM_IP_ROUTE_ATTRIBUTE_TABLE,
		                                      .type = PARSE_LINE_TYPE_UINT32, },
		[PARSE_LINE_ATTR_ROUTE_SRC]       = { .key = NM_IP_ROUTE_ATTRIBUTE_SRC,
		                                      .type = PARSE_LINE_TYPE_ADDR, },
		[PARSE_LINE_ATTR_ROUTE_FROM]      = { .key = NM_IP_ROUTE_ATTRIBUTE_FROM,
		                                      .type = PARSE_LINE_TYPE_ADDR_WITH_PREFIX,
		                                      .disabled = (addr_family != AF_INET6), },
		[PARSE_LINE_ATTR_ROUTE_TOS]       = { .key = NM_IP_ROUTE_ATTRIBUTE_TOS,
		                                      .type = PARSE_LINE_TYPE_UINT8,
		                                      .int_base_16 = TRUE,
		                                      .ignore = (addr_family != AF_INET), },
		[PARSE_LINE_ATTR_ROUTE_ONLINK]    = { .key = NM_IP_ROUTE_ATTRIBUTE_ONLINK,
		                                      .type = PARSE_LINE_TYPE_FLAG,
		                                      .ignore = (addr_family != AF_INET), },
		[PARSE_LINE_ATTR_ROUTE_WINDOW]    = { .key = NM_IP_ROUTE_ATTRIBUTE_WINDOW,
		                                      .type = PARSE_LINE_TYPE_UINT32_WITH_LOCK, },
		[PARSE_LINE_ATTR_ROUTE_CWND]      = { .key = NM_IP_ROUTE_ATTRIBUTE_CWND,
		                                      .type = PARSE_LINE_TYPE_UINT32_WITH_LOCK, },
		[PARSE_LINE_ATTR_ROUTE_INITCWND]  = { .key = NM_IP_ROUTE_ATTRIBUTE_INITCWND,
		                                      .type = PARSE_LINE_TYPE_UINT32_WITH_LOCK, },
		[PARSE_LINE_ATTR_ROUTE_INITRWND]  = { .key = NM_IP_ROUTE_ATTRIBUTE_INITRWND,
		                                      .type = PARSE_LINE_TYPE_UINT32_WITH_LOCK, },
		[PARSE_LINE_ATTR_ROUTE_MTU]       = { .key = NM_IP_ROUTE_ATTRIBUTE_MTU,
		                                      .type = PARSE_LINE_TYPE_UINT32_WITH_LOCK, },

		[PARSE_LINE_ATTR_ROUTE_TO]        = { .key = "to",
		                                      .type = PARSE_LINE_TYPE_ADDR_WITH_PREFIX,
		                                      .disabled = (options_route != NULL), },
		[PARSE_LINE_ATTR_ROUTE_VIA]       = { .key = "via",
		                                      .type = PARSE_LINE_TYPE_ADDR,
		                                      .disabled = (options_route != NULL), },
		[PARSE_LINE_ATTR_ROUTE_METRIC]    = { .key = "metric",
		                                      .type = PARSE_LINE_TYPE_UINT32,
		                                      .disabled = (options_route != NULL), },

		[PARSE_LINE_ATTR_ROUTE_DEV]       = { .key = "dev",
		                                      .type = PARSE_LINE_TYPE_IFNAME,
		                                      .ignore = TRUE,
		                                      .disabled = (options_route != NULL), },
	};

	nm_assert (line);
	nm_assert (NM_IN_SET (addr_family, AF_INET, AF_INET6));
	nm_assert (!options_route || nm_ip_route_get_family (options_route) == addr_family);

	/* initscripts read the legacy route file line-by-line and
	 * use it as `ip route add $line`, thus doing split+glob.
	 * Splitting on IFS (which we consider '<space><tab><newline>')
	 * and globbing (which we obviously don't do).
	 *
	 * I think it's a mess, because it doesn't support escaping or
	 * quoting. In fact, it can only encode benign values.
	 *
	 * We also use the same form for the numbered OPTIONS
	 * variable. I think it's bad not to support any form of
	 * escaping. But do that for now.
	 *
	 * Maybe later we want to support some form of quotation here.
	 * Which of course, would be incompatible with initscripts.
	 */
	words_free = nm_utils_strsplit_set (line, " \t\n");

	words = words_free ?: NM_PTRARRAY_EMPTY (const char *);

	for (i_words = 0; words[i_words]; ) {
		const gsize i_words0 = i_words;
		const char *const w = words[i_words0];
		ParseLineInfo *info;
		gboolean unqualified_addr = FALSE;

		for (i = 0; i < G_N_ELEMENTS (infos); i++) {
			info = &infos[i];

			if (info->disabled)
				continue;

			if (!nm_streq (w, info->key))
				continue;

			if (info->has) {
				/* iproute2 for most arguments allows specifying them multiple times.
				 * Let's not do that. */
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				             "Duplicate option \"%s\"", w);
				return -EINVAL;
			}

			info->has = TRUE;
			switch (info->type) {
			case PARSE_LINE_TYPE_UINT8:
				i_words++;
				goto parse_line_type_uint8;
			case PARSE_LINE_TYPE_UINT32:
				i_words++;
				goto parse_line_type_uint32;
			case PARSE_LINE_TYPE_UINT32_WITH_LOCK:
				i_words++;
				goto parse_line_type_uint32_with_lock;
			case PARSE_LINE_TYPE_ADDR:
				i_words++;
				goto parse_line_type_addr;
			case PARSE_LINE_TYPE_ADDR_WITH_PREFIX:
				i_words++;
				goto parse_line_type_addr_with_prefix;
			case PARSE_LINE_TYPE_IFNAME:
				i_words++;
				goto parse_line_type_ifname;
			case PARSE_LINE_TYPE_FLAG:
				i_words++;
				goto next;
			default:
				nm_assert_not_reached ();
			}
		}

		/* "to" is also accepted unqualified... (once) */
		info = &infos[PARSE_LINE_ATTR_ROUTE_TO];
		if (!info->has && !info->disabled) {
			unqualified_addr = TRUE;
			info->has = TRUE;
			goto parse_line_type_addr;
		}

		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Unrecognized argument (\"to\" is duplicate or \"%s\" is garbage)", w);
		return -EINVAL;

parse_line_type_uint8:
		s = words[i_words];
		if (!s)
			goto err_word_missing_argument;
		info->v.uint8 = _nm_utils_ascii_str_to_int64 (s,
		                                              info->int_base_16 ? 16 : 10,
		                                              0,
		                                              G_MAXUINT8,
		                                              0);;
		if (errno) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Argument for \"%s\" is not a valid number", w);
			return -EINVAL;
		}
		i_words++;
		goto next;

parse_line_type_uint32:
parse_line_type_uint32_with_lock:
		s = words[i_words];
		if (!s)
			goto err_word_missing_argument;
		if (info->type == PARSE_LINE_TYPE_UINT32_WITH_LOCK) {
			if (nm_streq (s, "lock")) {
				s = words[++i_words];
				if (!s)
					goto err_word_missing_argument;
				info->v.uint32_with_lock.lock = TRUE;
			} else
				info->v.uint32_with_lock.lock = FALSE;
			info->v.uint32_with_lock.uint32 = _nm_utils_ascii_str_to_int64 (s, 10, 0, G_MAXUINT32, 0);;
		} else {
			info->v.uint32 = _nm_utils_ascii_str_to_int64 (s, 10, 0, G_MAXUINT32, 0);
		}
		if (errno) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Argument for \"%s\" is not a valid number", w);
			return -EINVAL;
		}
		i_words++;
		goto next;

parse_line_type_ifname:
		s = words[i_words];
		if (!s)
			goto err_word_missing_argument;
		i_words++;
		goto next;

parse_line_type_addr:
parse_line_type_addr_with_prefix:
		s = words[i_words];
		if (!s)
			goto err_word_missing_argument;
		{
			int prefix = -1;

			if (info->type == PARSE_LINE_TYPE_ADDR) {
				if (!nm_utils_parse_inaddr_bin (addr_family,
				                                s,
				                                &info->v.addr.addr)) {
					if (   info == &infos[PARSE_LINE_ATTR_ROUTE_VIA]
					    && nm_streq (s, "(null)")) {
						/* Due to a bug, would older versions of NM write "via (null)"
						 * (rh#1452648). Workaround that, and accept it.*/
						memset (&info->v.addr.addr, 0, sizeof (info->v.addr.addr));
					} else {
						if (unqualified_addr) {
							g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
							             "Unrecognized argument (inet prefix is expected rather then \"%s\")", w);
							return -EINVAL;
						} else {
							g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
							             "Argument for \"%s\" is not a valid IPv%c address", w,
							             addr_family == AF_INET ? '4' : '6');
						}
						return -EINVAL;
					}
				}
			} else {
				nm_assert (info->type == PARSE_LINE_TYPE_ADDR_WITH_PREFIX);
				if (   info == &infos[PARSE_LINE_ATTR_ROUTE_TO]
				    && nm_streq (s, "default")) {
					memset (&info->v.addr.addr, 0, sizeof (info->v.addr.addr));
					prefix = 0;
				} else if (!nm_utils_parse_inaddr_prefix_bin (addr_family,
				                                              s,
				                                              &info->v.addr.addr,
				                                              &prefix)) {
					g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
					             "Argument for \"%s\" is not ADDR/PREFIX format", w);
					return -EINVAL;
				}
			}
			if (prefix == -1)
				info->v.addr.has_plen = FALSE;
			else {
				info->v.addr.has_plen = TRUE;
				info->v.addr.plen = prefix;
			}
		}
		i_words++;
		goto next;

err_word_missing_argument:
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Missing argument for \"%s\"", w);
		return -EINVAL;
next:
		;
	}

	if (options_route) {
		route = options_route;
		nm_ip_route_ref (route);
	} else {
		ParseLineInfo *info_to = &infos[PARSE_LINE_ATTR_ROUTE_TO];
		ParseLineInfo *info_via = &infos[PARSE_LINE_ATTR_ROUTE_VIA];
		ParseLineInfo *info_metric = &infos[PARSE_LINE_ATTR_ROUTE_METRIC];
		guint prefix;

		if (!info_to->has) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Missing destination prefix");
			return -EINVAL;
		}

		prefix =   info_to->v.addr.has_plen
		         ? info_to->v.addr.plen
		         : (addr_family == AF_INET ? 32 : 128);

		if (   (   (addr_family == AF_INET  && !info_to->v.addr.addr.addr4)
		        || (addr_family == AF_INET6 && IN6_IS_ADDR_UNSPECIFIED (&info_to->v.addr.addr.addr6)))
		    && prefix == 0) {
			/* we ignore default routes by returning -ERANGE. */
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Ignore manual default route");
			return -ERANGE;
		}

		route = nm_ip_route_new_binary (addr_family,
		                                &info_to->v.addr.addr,
		                                prefix,
		                                info_via->has ? &info_via->v.addr.addr : NULL,
		                                info_metric->has ? (gint64) info_metric->v.uint32 : (gint64) -1,
		                                error);
		info_to->has = FALSE;
		info_via->has = FALSE;
		info_metric->has = FALSE;
		if (!route)
			return -EINVAL;
	}

	for (i = 0; i < G_N_ELEMENTS (infos); i++) {
		ParseLineInfo *info = &infos[i];

		if (!info->has)
			continue;
		if (info->ignore || info->disabled)
			continue;
		switch (info->type) {
		case PARSE_LINE_TYPE_UINT8:
			nm_ip_route_set_attribute (route,
			                           info->key,
			                           g_variant_new_byte (info->v.uint8));
			break;
		case PARSE_LINE_TYPE_UINT32:
			nm_ip_route_set_attribute (route,
			                           info->key,
			                           g_variant_new_uint32 (info->v.uint32));
			break;
		case PARSE_LINE_TYPE_UINT32_WITH_LOCK:
			if (info->v.uint32_with_lock.lock) {
				nm_ip_route_set_attribute (route,
				                           nm_sprintf_buf (buf1, "lock-%s", info->key),
				                           g_variant_new_boolean (TRUE));
			}
			nm_ip_route_set_attribute (route,
			                           info->key,
			                           g_variant_new_uint32 (info->v.uint32_with_lock.uint32));
			break;
		case PARSE_LINE_TYPE_ADDR:
		case PARSE_LINE_TYPE_ADDR_WITH_PREFIX:
			nm_ip_route_set_attribute (route,
			                           info->key,
			                           g_variant_new_printf ("%s%s",
			                                                 inet_ntop (addr_family, &info->v.addr.addr, buf1, sizeof (buf1)),
			                                                 info->v.addr.has_plen
			                                                    ? nm_sprintf_buf (buf2, "/%u", (unsigned) info->v.addr.plen)
			                                                    : ""));
			break;
		case PARSE_LINE_TYPE_FLAG:
			/* NOTE: the flag (for "onlink") only allows to explictly set "TRUE".
			 * There is no way to express an explicit "FALSE" setting
			 * of this attribute, hence, the file format cannot encode
			 * that configuration. */
			nm_ip_route_set_attribute (route,
			                           info->key,
			                           g_variant_new_boolean (TRUE));
			break;
		default:
			nm_assert_not_reached ();
			break;
		}
	}

	nm_assert (_nm_ip_route_attribute_validate_all (route));

	NM_SET_OUT (out_route, g_steal_pointer (&route));
	return 0;
}

/* Returns TRUE on missing route or valid route */
static gboolean
read_one_ip4_route (shvarFile *ifcfg,
                    guint32 which,
                    NMIPRoute **out_route,
                    GError **error)
{
	char tag[256];
	char netmask_tag[256];
	guint32 dest;
	guint32 next_hop;
	guint32 netmask;
	gboolean has_key;
	const char *v;
	gs_free char *value = NULL;
	gint64 prefix, metric;
	char inet_buf[NM_UTILS_INET_ADDRSTRLEN];

	g_return_val_if_fail (ifcfg != NULL, FALSE);
	g_return_val_if_fail (out_route && !*out_route, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	/* Destination */
	if (!read_ip4_address (ifcfg,
	                       numbered_tag (tag, "ADDRESS", which),
	                       &has_key, &dest, error))
		return FALSE;
	if (!has_key) {
		/* missing route = success */
		*out_route = NULL;
		return TRUE;
	}

	/* Next hop */
	if (!read_ip4_address (ifcfg,
	                       numbered_tag (tag, "GATEWAY", which),
	                       NULL, &next_hop, error))
		return FALSE;
	/* We don't make distinction between missing GATEWAY IP and 0.0.0.0 */

	/* Prefix */
	if (!read_ip4_address (ifcfg,
	                       numbered_tag (netmask_tag, "NETMASK", which),
	                       &has_key, &netmask, error))
		return FALSE;
	if (has_key) {
		prefix = nm_utils_ip4_netmask_to_prefix (netmask);
		if (prefix == 0 || netmask != _nm_utils_ip4_prefix_to_netmask (prefix)) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid IP4 netmask '%s' \"%s\"", netmask_tag, nm_utils_inet4_ntop (netmask, inet_buf));
			return FALSE;
		}
	} else {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Missing IP4 route element '%s'", netmask_tag);
		return FALSE;
	}

	/* Metric */
	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, numbered_tag (tag, "METRIC", which), &value);
	if (v) {
		metric = _nm_utils_ascii_str_to_int64 (v, 10, 0, G_MAXUINT32, -1);
		if (metric < 0) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid IP4 route metric '%s'", v);
			return FALSE;
		}
	} else
		metric = -1;

	*out_route = nm_ip_route_new_binary (AF_INET, &dest, prefix, &next_hop, metric, error);
	if (!*out_route)
		return FALSE;

	/* Options */
	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, numbered_tag (tag, "OPTIONS", which), &value);
	if (v) {
		if (parse_route_line (v, AF_INET, *out_route, NULL, error) < 0) {
			g_clear_pointer (out_route, nm_ip_route_unref);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
read_route_file (int addr_family,
                 const char *filename,
                 NMSettingIPConfig *s_ip,
                 GError **error)
{
	gs_free char *contents = NULL;
	char *contents_rest = NULL;
	const char *line;
	gsize len = 0;
	gsize line_num;

	g_return_val_if_fail (filename, FALSE);
	g_return_val_if_fail (   (addr_family == AF_INET  && NM_IS_SETTING_IP4_CONFIG (s_ip))
	                      || (addr_family == AF_INET6 && NM_IS_SETTING_IP6_CONFIG (s_ip)), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	if (   !g_file_get_contents (filename, &contents, &len, NULL)
	    || !len) {
		return TRUE;  /* missing/empty = success */
	}

	line_num = 0;
	for (line = strtok_r (contents, "\n", &contents_rest);
	     line;
	     line = strtok_r (NULL, "\n", &contents_rest)) {
		nm_auto_ip_route_unref NMIPRoute *route = NULL;
		gs_free_error GError *local = NULL;
		int e;

		line_num++;

		if (parse_route_line_is_comment (line))
			continue;

		e = parse_route_line (line, addr_family, NULL, &route, &local);

		if (e < 0) {
			if (e == -ERANGE)
				PARSE_WARNING ("ignoring manual default route: '%s' (%s)", line, filename);
			else {
				/* we accept all unrecognized lines, because otherwise we would reject the
				 * entire connection. */
				PARSE_WARNING ("ignoring invalid route at \"%s\" (%s:%lu): %s", line, filename, (long unsigned) line_num, local->message);
			}
			continue;
		}

		if (!nm_setting_ip_config_add_route (s_ip, route))
			PARSE_WARNING ("duplicate IPv%c route", addr_family == AF_INET ? '4' : '6');
	}

	return TRUE;
}

static void
parse_dns_options (NMSettingIPConfig *ip_config, const char *value)
{
	gs_free const char **options = NULL;
	const char *const *item;

	g_return_if_fail (ip_config);

	if (!value)
		return;

	if (!nm_setting_ip_config_has_dns_options (ip_config))
		nm_setting_ip_config_clear_dns_options (ip_config, TRUE);

	options = nm_utils_strsplit_set (value, " ");
	if (options) {
		for (item = options; *item; item++) {
			if (!nm_setting_ip_config_add_dns_option (ip_config, *item))
				PARSE_WARNING ("can't add DNS option '%s'", *item);
		}
	}
}

static gboolean
parse_full_ip6_address (shvarFile *ifcfg,
                        const char *addr_str,
                        int i,
                        NMIPAddress **out_address,
                        GError **error)
{
	char **list;
	char *ip_val, *prefix_val;
	int prefix;
	gboolean success = FALSE;

	g_return_val_if_fail (addr_str != NULL, FALSE);
	g_return_val_if_fail (out_address != NULL, FALSE);
	g_return_val_if_fail (*out_address == NULL, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	/* Split the address and prefix */
	list = g_strsplit_set (addr_str, "/", 2);
	if (g_strv_length (list) < 1) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Invalid IP6 address '%s'", addr_str);
		goto error;
	}

	ip_val = list[0];

	prefix_val = list[1];
	if (prefix_val) {
		prefix = _nm_utils_ascii_str_to_int64 (prefix_val, 10, 0, 128, -1);
		if (prefix < 0) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid IP6 prefix '%s'", prefix_val);
			goto error;
		}
	} else {
		/* Missing prefix is treated as prefix of 64 */
		prefix = 64;
	}

	*out_address = nm_ip_address_new (AF_INET6, ip_val, prefix, error);
	if (*out_address)
		success = TRUE;

error:
	g_strfreev (list);
	return success;
}

static NMSetting *
make_user_setting (shvarFile *ifcfg)
{
	gboolean has_user_data = FALSE;
	gs_unref_object NMSettingUser *s_user = NULL;
	gs_unref_hashtable GHashTable *keys = NULL;
	GHashTableIter iter;
	const char *key;
	nm_auto_free_gstring GString *str = NULL;

	keys = svGetKeys (ifcfg);
	if (!keys)
		return NULL;

	g_hash_table_iter_init (&iter, keys);
	while (g_hash_table_iter_next (&iter, (gpointer *) &key, NULL)) {
		const char *value;
		gs_free char *value_to_free = NULL;

		if (!g_str_has_prefix (key, "NM_USER_"))
			continue;

		value = svGetValue (ifcfg, key, &value_to_free);

		if (!value)
			continue;

		if (!str)
			str = g_string_sized_new (100);
		else
			g_string_set_size (str, 0);

		if (!nms_ifcfg_rh_utils_user_key_decode (key + NM_STRLEN ("NM_USER_"), str))
			continue;

		if (!s_user)
			s_user = NM_SETTING_USER (nm_setting_user_new ());

		if (nm_setting_user_set_data (s_user, str->str,
		                              value, NULL))
			has_user_data = TRUE;
	}

	return has_user_data
	       ? g_steal_pointer (&s_user)
	       : NULL;
}

static NMSetting *
make_proxy_setting (shvarFile *ifcfg)
{
	NMSettingProxy *s_proxy = NULL;
	gs_free char *value = NULL;
	const char *v;
	NMSettingProxyMethod method;

	v = svGetValueStr (ifcfg, "PROXY_METHOD", &value);
	if (!v)
		return NULL;

	if (!g_ascii_strcasecmp (v, "auto"))
		method = NM_SETTING_PROXY_METHOD_AUTO;
	else
		method = NM_SETTING_PROXY_METHOD_NONE;

	s_proxy = (NMSettingProxy *) nm_setting_proxy_new ();

	switch (method) {
	case NM_SETTING_PROXY_METHOD_AUTO:
		g_object_set (s_proxy,
		              NM_SETTING_PROXY_METHOD, (int) NM_SETTING_PROXY_METHOD_AUTO,
		              NULL);

		nm_clear_g_free (&value);
		v = svGetValueStr (ifcfg, "PAC_URL", &value);
		if (v)
			g_object_set (s_proxy, NM_SETTING_PROXY_PAC_URL, v, NULL);

		nm_clear_g_free (&value);
		v = svGetValueStr (ifcfg, "PAC_SCRIPT", &value);
		if (v)
			g_object_set (s_proxy, NM_SETTING_PROXY_PAC_SCRIPT, v, NULL);

		break;
	case NM_SETTING_PROXY_METHOD_NONE:
		g_object_set (s_proxy,
		              NM_SETTING_PROXY_METHOD, (int) NM_SETTING_PROXY_METHOD_NONE,
		              NULL);
		break;
	}

	if (svGetValueBoolean (ifcfg, "BROWSER_ONLY", FALSE))
		g_object_set (s_proxy, NM_SETTING_PROXY_BROWSER_ONLY, TRUE, NULL);

	return NM_SETTING (s_proxy);
}

static NMSetting *
make_ip4_setting (shvarFile *ifcfg,
                  shvarFile *network_ifcfg,
                  gboolean routes_read,
                  gboolean *out_has_defroute,
                  GError **error)
{
	gs_unref_object NMSettingIPConfig *s_ip4 = NULL;
	gs_free char *route_path = NULL;
	gs_free char *value = NULL;
	const char *v;
	char *method;
	gs_free char *dns_options_free = NULL;
	const char *dns_options = NULL;
	gs_free char *gateway = NULL;
	int i;
	guint32 a;
	gboolean has_key;
	shvarFile *route_ifcfg;
	gboolean never_default;
	gint64 timeout;
	gint priority;
	char inet_buf[NM_UTILS_INET_ADDRSTRLEN];
	const char *const *item;
	guint32 route_table;

	nm_assert (out_has_defroute && !*out_has_defroute);

	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();

	/* First check if DEFROUTE is set for this device; DEFROUTE has the
	 * opposite meaning from never-default. The default if DEFROUTE is not
	 * specified is DEFROUTE=yes which means that this connection can be used
	 * as a default route
	 */
	i = svGetValueBoolean (ifcfg, "DEFROUTE", -1);
	if (i == -1)
		never_default = FALSE;
	else {
		never_default = !i;
		*out_has_defroute = TRUE;
	}

	/* Then check if GATEWAYDEV; it's global and overrides DEFROUTE */
	if (network_ifcfg) {
		gs_free char *gatewaydev_value = NULL;
		const char *gatewaydev;

		/* Get the connection ifcfg device name and the global gateway device */
		v = svGetValueStr (ifcfg, "DEVICE", &value);
		gatewaydev = svGetValueStr (network_ifcfg, "GATEWAYDEV", &gatewaydev_value);
		dns_options = svGetValue (network_ifcfg, "RES_OPTIONS", &dns_options_free);

		/* If there was a global gateway device specified, then only connections
		 * for that device can be the default connection.
		 */
		if (gatewaydev && v)
			never_default = !!strcmp (v, gatewaydev);

		nm_clear_g_free (&value);
	}

	v = svGetValueStr (ifcfg, "BOOTPROTO", &value);

	if (!v || !*v || !g_ascii_strcasecmp (v, "none")) {
		if (is_any_ip4_address_defined (ifcfg, NULL))
			method = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;
		else
			method = NM_SETTING_IP4_CONFIG_METHOD_DISABLED;
	} else if (!g_ascii_strcasecmp (v, "bootp") || !g_ascii_strcasecmp (v, "dhcp")) {
		method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;
	} else if (!g_ascii_strcasecmp (v, "static")) {
		if (is_any_ip4_address_defined (ifcfg, NULL))
			method = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;
		else
			method = NM_SETTING_IP4_CONFIG_METHOD_DISABLED;
	} else if (!g_ascii_strcasecmp (v, "autoip")) {
		method = NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL;
	} else if (!g_ascii_strcasecmp (v, "shared")) {
		method = NM_SETTING_IP4_CONFIG_METHOD_SHARED;
	} else {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Unknown BOOTPROTO '%s'", v);
		return NULL;
	}

	/* the route table (policy routing) is ignored if we don't handle routes. */
	route_table = svGetValueInt64 (ifcfg, "IPV4_ROUTE_TABLE", 10,
	                               0, G_MAXUINT32, 0);
	if (   route_table != 0
	    && !routes_read) {
		PARSE_WARNING ("'rule-' or 'rule6-' files are present; Policy routing (IPV4_ROUTE_TABLE) is ignored");
		route_table = 0;
	}

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, method,
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, !svGetValueBoolean (ifcfg, "PEERDNS", TRUE),
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, !svGetValueBoolean (ifcfg, "PEERROUTES", TRUE),
	              NM_SETTING_IP_CONFIG_NEVER_DEFAULT, never_default,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, !svGetValueBoolean (ifcfg, "IPV4_FAILURE_FATAL", FALSE),
	              NM_SETTING_IP_CONFIG_ROUTE_METRIC, svGetValueInt64 (ifcfg, "IPV4_ROUTE_METRIC", 10,
	                                                                  -1, G_MAXUINT32, -1),
	              NM_SETTING_IP_CONFIG_ROUTE_TABLE, (guint) route_table,
	              NULL);

	if (nm_streq (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED))
		return g_steal_pointer (&s_ip4);

	/* Handle DHCP settings */
	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "DHCP_HOSTNAME", &value);
	if (v)
		g_object_set (s_ip4, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, v, NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "DHCP_FQDN", &value);
	if (v) {
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, NULL,
		              NM_SETTING_IP4_CONFIG_DHCP_FQDN, v,
		              NULL);
	}

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, svGetValueBoolean (ifcfg, "DHCP_SEND_HOSTNAME", TRUE),
	              NM_SETTING_IP_CONFIG_DHCP_TIMEOUT, svGetValueInt64 (ifcfg, "IPV4_DHCP_TIMEOUT", 10, 0, G_MAXINT32, 0),
	              NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "DHCP_CLIENT_ID", &value);
	if (v)
		g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID, v, NULL);

	/* Read static IP addresses.
	 * Read them even for AUTO method - in this case the addresses are
	 * added to the automatic ones. Note that this is not currently supported by
	 * the legacy 'network' service (ifup-eth).
	 */
	for (i = -1;; i++) {
		NMIPAddress *addr = NULL;

		/* gateway will only be set if still unset. Hence, we don't leak gateway
		 * here by calling read_full_ip4_address() repeatedly */
		if (!read_full_ip4_address (ifcfg, i, NULL, &addr, &gateway, error))
			return NULL;

		if (!addr) {
			/* The first mandatory variable is 2-indexed (IPADDR2)
			 * Variables IPADDR, IPADDR0 and IPADDR1 are optional */
			if (i > 1)
				break;
			continue;
		}

		if (!nm_setting_ip_config_add_address (s_ip4, addr))
			PARSE_WARNING ("duplicate IP4 address");
		nm_ip_address_unref (addr);
	}

	/* Gateway */
	if (!gateway) {
		if (network_ifcfg) {
			gboolean read_success;

			read_success = read_ip4_address (network_ifcfg, "GATEWAY", &has_key, &a, error);
			if (!read_success)
				return NULL;
			if (has_key) {
				if (nm_setting_ip_config_get_num_addresses (s_ip4) == 0) {
					gs_free char *f = g_path_get_basename (svFileGetName (ifcfg));
					PARSE_WARNING ("ignoring GATEWAY (/etc/sysconfig/network) for %s "
					               "because the connection has no static addresses", f);
				} else
					gateway = g_strdup (nm_utils_inet4_ntop (a, inet_buf));
			}
		}
	}
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_GATEWAY, gateway, NULL);

	if (gateway && never_default)
		PARSE_WARNING ("GATEWAY will be ignored when DEFROUTE is disabled");

	/* We used to skip saving a lot of unused properties for the ipv4 shared method.
	 * We want now to persist them but... unfortunately loading DNS or DOMAIN options
	 * would cause a fail in the ipv4 verify() function. As we don't want any regression
	 * in the unlikely event that someone has a working ifcfg file for an IPv4 shared ip
	 * connection with a crafted "DNS" entry... don't load it. So we will avoid failing
	 * the connection) */
	if (!nm_streq (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED)) {
		/* DNS servers
		 * Pick up just IPv4 addresses (IPv6 addresses are taken by make_ip6_setting())
		 */
		for (i = 1; i <= 10; i++) {
			char tag[256];

			numbered_tag (tag, "DNS", i);
			nm_clear_g_free (&value);
			v = svGetValueStr (ifcfg, tag, &value);
			if (v) {
				if (nm_utils_ipaddr_valid (AF_INET, v)) {
					if (!nm_setting_ip_config_add_dns (s_ip4, v))
						PARSE_WARNING ("duplicate DNS server %s", tag);
				} else if (nm_utils_ipaddr_valid (AF_INET6, v)) {
					/* Ignore IPv6 addresses */
				} else {
					PARSE_WARNING ("invalid DNS server address %s", v);
					return NULL;
				}
			}
		}

		/* DNS searches */
		nm_clear_g_free (&value);
		v = svGetValueStr (ifcfg, "DOMAIN", &value);
		if (v) {
			gs_free const char **searches = NULL;

			searches = nm_utils_strsplit_set (v, " ");
			if (searches) {
				for (item = searches; *item; item++) {
					if (!nm_setting_ip_config_add_dns_search (s_ip4, *item))
						PARSE_WARNING ("duplicate DNS domain '%s'", *item);
				}
			}
		}
	}

	/* DNS options */
	nm_clear_g_free (&value);
	parse_dns_options (s_ip4, svGetValue (ifcfg, "RES_OPTIONS", &value));
	parse_dns_options (s_ip4, dns_options);

	/* DNS priority */
	priority = svGetValueInt64 (ifcfg, "IPV4_DNS_PRIORITY", 10, G_MININT32, G_MAXINT32, 0);
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_DNS_PRIORITY,
	              priority,
	              NULL);

	/* Static routes  - route-<name> file */
	route_path = utils_get_route_path (svFileGetName (ifcfg));

	if (!routes_read) {
		/* NOP */
	} else if (utils_has_route_file_new_syntax (route_path)) {
		/* Parse route file in new syntax */
		route_ifcfg = utils_get_route_ifcfg (svFileGetName (ifcfg), FALSE);
		if (route_ifcfg) {
			for (i = 0;; i++) {
				NMIPRoute *route = NULL;

				if (!read_one_ip4_route (route_ifcfg, i, &route, error)) {
					svCloseFile (route_ifcfg);
					return NULL;
				}

				if (!route)
					break;

				if (!nm_setting_ip_config_add_route (s_ip4, route))
					PARSE_WARNING ("duplicate IP4 route");
				nm_ip_route_unref (route);
			}
			svCloseFile (route_ifcfg);
		}
	} else {
		if (!read_route_file (AF_INET, route_path, s_ip4, error))
			return NULL;
	}

	/* Legacy value NM used for a while but is incorrect (rh #459370) */
	if (   !nm_streq (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED)
	    && !nm_setting_ip_config_get_num_dns_searches (s_ip4)) {
		nm_clear_g_free (&value);
		v = svGetValueStr (ifcfg, "SEARCH", &value);
		if (v) {
			gs_free const char **searches = NULL;

			searches = nm_utils_strsplit_set (v, " ");
			if (searches) {
				for (item = searches; *item; item++) {
					if (!nm_setting_ip_config_add_dns_search (s_ip4, *item))
						PARSE_WARNING ("duplicate DNS search '%s'", *item);
				}
			}
		}
	}

	timeout = svGetValueInt64 (ifcfg, "ACD_TIMEOUT", 10, -1, NM_SETTING_IP_CONFIG_DAD_TIMEOUT_MAX, -2);
	if (timeout == -2) {
		timeout = svGetValueInt64 (ifcfg, "ARPING_WAIT", 10, -1,
		                           NM_SETTING_IP_CONFIG_DAD_TIMEOUT_MAX / 1000, -1);
		if (timeout > 0)
			timeout *= 1000;
	}
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_DAD_TIMEOUT, (gint) timeout, NULL);

	return g_steal_pointer (&s_ip4);
}

static void
read_aliases (NMSettingIPConfig *s_ip4, gboolean read_defroute, const char *filename)
{
	GDir *dir;
	char *dirname, *base;
	NMIPAddress *base_addr = NULL;
	GError *err = NULL;

	g_return_if_fail (s_ip4 != NULL);
	g_return_if_fail (filename != NULL);

	if (nm_setting_ip_config_get_num_addresses (s_ip4) > 0)
		base_addr = nm_setting_ip_config_get_address (s_ip4, 0);

	dirname = g_path_get_dirname (filename);
	g_return_if_fail (dirname != NULL);
	base = g_path_get_basename (filename);
	g_return_if_fail (base != NULL);

	dir = g_dir_open (dirname, 0, &err);
	if (dir) {
		const char *item;
		NMIPAddress *addr;
		gboolean ok;

		while ((item = g_dir_read_name (dir))) {
			nm_auto_shvar_file_close shvarFile *parsed = NULL;
			gs_free char *gateway = NULL;
			gs_free char *device_value = NULL;
			gs_free char *full_path = NULL;
			const char *device;
			const char *p;

			if (!utils_is_ifcfg_alias_file (item, base))
				continue;

			full_path = g_build_filename (dirname, item, NULL);

			p = strchr (item, ':');
			g_assert (p != NULL); /* we know this is true from utils_is_ifcfg_alias_file() */
			for (p++; *p; p++) {
				if (!g_ascii_isalnum (*p) && *p != '_')
					break;
			}
			if (*p) {
				PARSE_WARNING ("ignoring alias file '%s' with invalid name", full_path);
				continue;
			}

			parsed = svOpenFile (full_path, &err);
			if (!parsed) {
				PARSE_WARNING ("couldn't parse alias file '%s': %s", full_path, err->message);
				g_clear_error (&err);
				continue;
			}

			device = svGetValueStr (parsed, "DEVICE", &device_value);
			if (!device) {
				PARSE_WARNING ("alias file '%s' has no DEVICE", full_path);
				continue;
			}
			/* We know that item starts with IFCFG_TAG from utils_is_ifcfg_alias_file() */
			if (strcmp (device, item + strlen (IFCFG_TAG)) != 0) {
				PARSE_WARNING ("alias file '%s' has invalid DEVICE (%s) for filename",
				               full_path, device);
				continue;
			}

			addr = NULL;
			ok = read_full_ip4_address (parsed, -1, base_addr, &addr,
			                            read_defroute ? &gateway : NULL,
			                            &err);
			if (ok) {
				nm_ip_address_set_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL, g_variant_new_string (device));
				if (!nm_setting_ip_config_add_address (s_ip4, addr))
					PARSE_WARNING ("duplicate IP4 address in alias file %s", item);
				if (nm_streq0 (nm_setting_ip_config_get_method (s_ip4), NM_SETTING_IP4_CONFIG_METHOD_DISABLED))
					g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL, NULL);
				if (read_defroute) {
					int i;

					if (gateway) {
						g_object_set (s_ip4, NM_SETTING_IP_CONFIG_GATEWAY, gateway, NULL);
						read_defroute = FALSE;
					}
					i = svGetValueBoolean (parsed, "DEFROUTE", -1);
					if (i != -1) {
						g_object_set (s_ip4,
						              NM_SETTING_IP_CONFIG_NEVER_DEFAULT, (gboolean) !i,
						              NULL);
						read_defroute = FALSE;
					}
				}
			} else {
				PARSE_WARNING ("error reading IP4 address from alias file '%s': %s",
				               full_path, err ? err->message : "no address");
				g_clear_error (&err);
			}
			nm_ip_address_unref (addr);
		}

		g_dir_close (dir);
	} else {
		PARSE_WARNING ("can not read directory '%s': %s", dirname, err->message);
		g_error_free (err);
	}

	g_free (base);
	g_free (dirname);
}

static NMSetting *
make_ip6_setting (shvarFile *ifcfg,
                  shvarFile *network_ifcfg,
                  gboolean routes_read,
                  GError **error)
{
	NMSettingIPConfig *s_ip6 = NULL;
	const char *v;
	gs_free char *value = NULL;
	char *route6_path = NULL;
	gboolean ipv6init, ipv6forwarding, dhcp6 = FALSE;
	char *method = NM_SETTING_IP6_CONFIG_METHOD_MANUAL;
	const char *ipv6addr, *ipv6addr_secondaries;
	gs_free char *ipv6addr_to_free = NULL;
	gs_free char *ipv6addr_secondaries_to_free = NULL;
	gs_free const char **list = NULL;
	const char *const *iter;
	guint32 i;
	int i_val;
	GError *local = NULL;
	gint priority;
	gboolean never_default = FALSE;
	gboolean ip6_privacy = FALSE, ip6_privacy_prefer_public_ip;
	NMSettingIP6ConfigPrivacy ip6_privacy_val;
	guint32 route_table;

	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();

	/* First check if IPV6_DEFROUTE is set for this device; IPV6_DEFROUTE has the
	 * opposite meaning from never-default. The default if IPV6_DEFROUTE is not
	 * specified is IPV6_DEFROUTE=yes which means that this connection can be used
	 * as a default route
	 */
	never_default = !svGetValueBoolean (ifcfg, "IPV6_DEFROUTE", TRUE);

	/* Then check if IPV6_DEFAULTGW or IPV6_DEFAULTDEV is specified;
	 * they are global and override IPV6_DEFROUTE
	 * When both are set, the device specified in IPV6_DEFAULTGW takes preference.
	 */
	if (network_ifcfg) {
		const char *ipv6_defaultgw, *ipv6_defaultdev;
		gs_free char *ipv6_defaultgw_to_free = NULL;
		gs_free char *ipv6_defaultdev_to_free = NULL;
		const char *default_dev = NULL;

		/* Get the connection ifcfg device name and the global default route device */
		nm_clear_g_free (&value);
		v = svGetValueStr (ifcfg, "DEVICE", &value);
		ipv6_defaultgw = svGetValueStr (network_ifcfg, "IPV6_DEFAULTGW", &ipv6_defaultgw_to_free);
		ipv6_defaultdev = svGetValueStr (network_ifcfg, "IPV6_DEFAULTDEV", &ipv6_defaultdev_to_free);

		if (ipv6_defaultgw) {
			default_dev = strchr (ipv6_defaultgw, '%');
			if (default_dev)
				default_dev++;
		}
		if (!default_dev)
			default_dev = ipv6_defaultdev;

		/* If there was a global default route device specified, then only connections
		 * for that device can be the default connection.
		 */
		if (default_dev && v)
			never_default = !!strcmp (v, default_dev);
	}

	/* Find out method property */
	/* Is IPV6 enabled? Set method to "ignored", when not enabled */
	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "IPV6INIT", &value);
	ipv6init = svGetValueBoolean (ifcfg, "IPV6INIT", FALSE);
	if (!v) {
		if (network_ifcfg)
			ipv6init = svGetValueBoolean (network_ifcfg, "IPV6INIT", FALSE);
	}

	if (!ipv6init)
		method = NM_SETTING_IP6_CONFIG_METHOD_IGNORE;  /* IPv6 is disabled */
	else {
		ipv6forwarding = svGetValueBoolean (ifcfg, "IPV6FORWARDING", FALSE);
		nm_clear_g_free (&value);
		v = svGetValueStr (ifcfg, "IPV6_AUTOCONF", &value);
		dhcp6 = svGetValueBoolean (ifcfg, "DHCPV6C", FALSE);

		if (!g_strcmp0 (v, "shared"))
			method = NM_SETTING_IP6_CONFIG_METHOD_SHARED;
		else if (svParseBoolean (v, !ipv6forwarding))
			method = NM_SETTING_IP6_CONFIG_METHOD_AUTO;
		else if (dhcp6)
			method = NM_SETTING_IP6_CONFIG_METHOD_DHCP;
		else {
			/* IPV6_AUTOCONF=no and no IPv6 address -> method 'link-local' */
			nm_clear_g_free (&value);
			v = svGetValueStr (ifcfg, "IPV6ADDR", &value);
			if (!v) {
				nm_clear_g_free (&value);
				v = svGetValueStr (ifcfg, "IPV6ADDR_SECONDARIES", &value);
			}

			if (!v)
				method = NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL;
		}
	}
	/* TODO - handle other methods */

	/* Read IPv6 Privacy Extensions configuration */
	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "IPV6_PRIVACY", &value);
	if (v) {
		ip6_privacy = svParseBoolean (v, FALSE);
		if (!ip6_privacy)
			ip6_privacy = (g_strcmp0 (v, "rfc4941") == 0) ||
			              (g_strcmp0 (v, "rfc3041") == 0);
	}
	ip6_privacy_prefer_public_ip = svGetValueBoolean (ifcfg, "IPV6_PRIVACY_PREFER_PUBLIC_IP", FALSE);
	ip6_privacy_val = v ?
	                      (ip6_privacy ?
	                          (ip6_privacy_prefer_public_ip ? NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR : NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR) :
	                          NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED) :
	                      NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN;

	/* the route table (policy routing) is ignored if we don't handle routes. */
	route_table = svGetValueInt64 (ifcfg, "IPV6_ROUTE_TABLE", 10,
	                               0, G_MAXUINT32, 0);
	if (   route_table != 0
	    && !routes_read) {
		PARSE_WARNING ("'rule-' or 'rule6-' files are present; Policy routing (IPV6_ROUTE_TABLE) is ignored");
		route_table = 0;
	}

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, method,
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, !svGetValueBoolean (ifcfg, "IPV6_PEERDNS", TRUE),
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, !svGetValueBoolean (ifcfg, "IPV6_PEERROUTES", TRUE),
	              NM_SETTING_IP_CONFIG_NEVER_DEFAULT, never_default,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, !svGetValueBoolean (ifcfg, "IPV6_FAILURE_FATAL", FALSE),
	              NM_SETTING_IP_CONFIG_ROUTE_METRIC, svGetValueInt64 (ifcfg, "IPV6_ROUTE_METRIC", 10,
	                                                                  -1, G_MAXUINT32, -1),
	              NM_SETTING_IP_CONFIG_ROUTE_TABLE, (guint) route_table,
	              NM_SETTING_IP6_CONFIG_IP6_PRIVACY, ip6_privacy_val,
	              NULL);

	/* Don't bother to read IP, DNS and routes when IPv6 is disabled */
	if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) == 0)
		return NM_SETTING (s_ip6);

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "DHCPV6_DUID", &value);
	if (v)
		g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_DHCP_DUID, v, NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "DHCPV6_HOSTNAME", &value);
	/* Use DHCP_HOSTNAME as fallback if it is in FQDN format and ipv6.method is
	 * auto or dhcp: this is required to support old ifcfg files
	 */
	if (!v && (   !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO)
		       || !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_DHCP))) {
		nm_clear_g_free (&value);
		v = svGetValueStr (ifcfg, "DHCP_HOSTNAME", &value);
		if (v && !strchr (v, '.'))
			v = NULL;
	}
	if (v)
		g_object_set (s_ip6, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, v, NULL);

	g_object_set (s_ip6, NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME,
		      svGetValueBoolean (ifcfg, "DHCPV6_SEND_HOSTNAME", TRUE), NULL);

	/* Read static IP addresses.
	 * Read them even for AUTO and DHCP methods - in this case the addresses are
	 * added to the automatic ones. Note that this is not currently supported by
	 * the legacy 'network' service (ifup-eth).
	 */
	ipv6addr = svGetValueStr (ifcfg, "IPV6ADDR", &ipv6addr_to_free);
	ipv6addr_secondaries = svGetValueStr (ifcfg, "IPV6ADDR_SECONDARIES", &ipv6addr_secondaries_to_free);

	nm_clear_g_free (&value);
	value = g_strjoin (ipv6addr && ipv6addr_secondaries ? " " : NULL,
	                   ipv6addr ?: "",
	                   ipv6addr_secondaries ?: "",
	                   NULL);

	list = nm_utils_strsplit_set (value, " ");
	for (iter = list, i = 0; iter && *iter; iter++, i++) {
		NMIPAddress *addr = NULL;

		if (!parse_full_ip6_address (ifcfg, *iter, i, &addr, error))
			goto error;

		if (!nm_setting_ip_config_add_address (s_ip6, addr))
			PARSE_WARNING ("duplicate IP6 address");
		nm_ip_address_unref (addr);
	}

	/* Gateway */
	if (nm_setting_ip_config_get_num_addresses (s_ip6)) {
		nm_clear_g_free (&value);
		v = svGetValueStr (ifcfg, "IPV6_DEFAULTGW", &value);
		if (!v) {
			/* If no gateway in the ifcfg, try global /etc/sysconfig/network instead */
			if (network_ifcfg) {
				nm_clear_g_free (&value);
				v = svGetValueStr (network_ifcfg, "IPV6_DEFAULTGW", &value);
			}
		}
		if (v) {
			char *ptr;
			if ((ptr = strchr (v, '%')) != NULL)
				*ptr = '\0';  /* remove %interface prefix if present */
			if (!nm_utils_ipaddr_valid (AF_INET6, v)) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				             "Invalid IP6 address '%s'", v);
				goto error;
			}

			g_object_set (s_ip6, NM_SETTING_IP_CONFIG_GATEWAY, v, NULL);
		}
	}

	i_val = NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64;
	if (!svGetValueEnum (ifcfg, "IPV6_ADDR_GEN_MODE",
	                     nm_setting_ip6_config_addr_gen_mode_get_type (),
	                     &i_val, &local)) {
		PARSE_WARNING ("%s", local->message);
		g_clear_error (&local);
	}
	g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE, i_val, NULL);

	/* IPv6 tokenized interface identifier */
	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "IPV6_TOKEN", &value);
	if (v)
		g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_TOKEN, v, NULL);

	/* DNS servers
	 * Pick up just IPv6 addresses (IPv4 addresses are taken by make_ip4_setting())
	 */
	for (i = 1; i <= 10; i++) {
		char tag[256];

		numbered_tag (tag, "DNS", i);
		nm_clear_g_free (&value);
		v = svGetValueStr (ifcfg, tag, &value);
		if (!v) {
			/* all done */
			break;
		}

		if (nm_utils_ipaddr_valid (AF_INET6, v)) {
			if (!nm_setting_ip_config_add_dns (s_ip6, v))
				PARSE_WARNING ("duplicate DNS server %s", tag);
		} else if (nm_utils_ipaddr_valid (AF_INET, v)) {
			/* Ignore IPv4 addresses */
		} else {
			PARSE_WARNING ("invalid DNS server address %s", v);
			goto error;
		}
	}

	if (!routes_read) {
		/* NOP */
	} else {
		/* Read static routes from route6-<interface> file */
		route6_path = utils_get_route6_path (svFileGetName (ifcfg));
		if (!read_route_file (AF_INET6, route6_path, s_ip6, error))
			goto error;
		g_free (route6_path);
	}

	/* DNS searches */
	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "IPV6_DOMAIN", &value);
	if (v) {
		gs_free const char **searches = NULL;

		searches = nm_utils_strsplit_set (v, " ");
		if (searches) {
			for (iter = searches; *iter; iter++) {
				if (!nm_setting_ip_config_add_dns_search (s_ip6, *iter))
					PARSE_WARNING ("duplicate DNS domain '%s'", *iter);
			}
		}
	}

	/* DNS options */
	nm_clear_g_free (&value);
	parse_dns_options (s_ip6, svGetValue (ifcfg, "IPV6_RES_OPTIONS", &value));

	/* DNS priority */
	priority = svGetValueInt64 (ifcfg, "IPV6_DNS_PRIORITY", 10, G_MININT32, G_MAXINT32, 0);
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_DNS_PRIORITY,
	              priority,
	              NULL);

	return NM_SETTING (s_ip6);

error:
	g_free (route6_path);
	g_object_unref (s_ip6);
	return NULL;
}

static NMSetting *
make_tc_setting (shvarFile *ifcfg)
{
	NMSettingTCConfig *s_tc = NULL;
	char tag[256];
	int i;

	s_tc = (NMSettingTCConfig *) nm_setting_tc_config_new ();

	for (i = 1;; i++) {
		NMTCQdisc *qdisc = NULL;
		gs_free char *value_to_free = NULL;
		const char *value = NULL;
		GError *local = NULL;

		value = svGetValueStr (ifcfg, numbered_tag (tag, "QDISC", i), &value_to_free);
		if (!value)
			break;

		qdisc = nm_utils_tc_qdisc_from_str (value, &local);
		if (!qdisc) {
			PARSE_WARNING ("ignoring bad tc qdisc: '%s': %s", value, local->message);
			continue;
		}

		if (!nm_setting_tc_config_add_qdisc (s_tc, qdisc))
			PARSE_WARNING ("duplicate tc qdisc");

		nm_tc_qdisc_unref (qdisc);
	}

	for (i = 1;; i++) {
		NMTCTfilter *tfilter = NULL;
		gs_free char *value_to_free = NULL;
		const char *value = NULL;
		GError *local = NULL;

		value = svGetValueStr (ifcfg, numbered_tag (tag, "FILTER", i), &value_to_free);
		if (!value)
			break;

		tfilter = nm_utils_tc_tfilter_from_str (value, &local);
		if (!tfilter) {
			PARSE_WARNING ("ignoring bad tc filter: '%s': %s", value, local->message);
			continue;
		}

		if (!nm_setting_tc_config_add_tfilter (s_tc, tfilter))
			PARSE_WARNING ("duplicate tc filter");

		nm_tc_tfilter_unref (tfilter);
	}

	if (   nm_setting_tc_config_get_num_qdiscs (s_tc) > 0
	    || nm_setting_tc_config_get_num_tfilters (s_tc) > 0)
		return NM_SETTING (s_tc);

	g_object_unref (s_tc);
	return NULL;
}

typedef struct {
	const char *enable_key;
	const char *advertise_key;
	const char *willing_key;
	const char *flags_prop;
} DcbFlagsProperty;

enum {
	DCB_APP_FCOE_FLAGS = 0,
	DCB_APP_ISCSI_FLAGS = 1,
	DCB_APP_FIP_FLAGS = 2,
	DCB_PFC_FLAGS = 3,
	DCB_PG_FLAGS = 4,
};

static DcbFlagsProperty dcb_flags_props[] = {
	{ KEY_DCB_APP_FCOE_ENABLE,  KEY_DCB_APP_FCOE_ADVERTISE,  KEY_DCB_APP_FCOE_WILLING,  NM_SETTING_DCB_APP_FCOE_FLAGS },
	{ KEY_DCB_APP_ISCSI_ENABLE, KEY_DCB_APP_ISCSI_ADVERTISE, KEY_DCB_APP_ISCSI_WILLING, NM_SETTING_DCB_APP_ISCSI_FLAGS },
	{ KEY_DCB_APP_FIP_ENABLE,   KEY_DCB_APP_FIP_ADVERTISE,   KEY_DCB_APP_FIP_WILLING,   NM_SETTING_DCB_APP_FIP_FLAGS },
	{ KEY_DCB_PFC_ENABLE,       KEY_DCB_PFC_ADVERTISE,       KEY_DCB_PFC_WILLING,       NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS },
	{ KEY_DCB_PG_ENABLE,        KEY_DCB_PG_ADVERTISE,        KEY_DCB_PG_WILLING,        NM_SETTING_DCB_PRIORITY_GROUP_FLAGS },
	{ NULL },
};

static NMSettingDcbFlags
read_dcb_flags (shvarFile *ifcfg, DcbFlagsProperty *property)
{
	NMSettingDcbFlags flags = NM_SETTING_DCB_FLAG_NONE;

	if (svGetValueBoolean (ifcfg, property->enable_key, FALSE))
		flags |= NM_SETTING_DCB_FLAG_ENABLE;
	if (svGetValueBoolean (ifcfg, property->advertise_key, FALSE))
		flags |= NM_SETTING_DCB_FLAG_ADVERTISE;
	if (svGetValueBoolean (ifcfg, property->willing_key, FALSE))
		flags |= NM_SETTING_DCB_FLAG_WILLING;

	return flags;
}

static gboolean
read_dcb_app (shvarFile *ifcfg,
              NMSettingDcb *s_dcb,
              const char *app,
              DcbFlagsProperty *flags_prop,
              const char *priority_prop,
              GError **error)
{
	NMSettingDcbFlags flags = NM_SETTING_DCB_FLAG_NONE;
	gs_free char *value = NULL;
	const char *v;
	gboolean success = TRUE;
	int priority = -1;
	char key[255];

	flags = read_dcb_flags (ifcfg, flags_prop);

	/* Priority */
	nm_sprintf_buf (key, "DCB_APP_%s_PRIORITY", app);
	v = svGetValueStr (ifcfg, key, &value);
	if (v) {
		priority = _nm_utils_ascii_str_to_int64 (v, 0, 0, 7, -1);
		if (priority < 0) {
			success = FALSE;
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid %s value '%s' (expected 0 - 7)",
			             key, v);
		}

		if (!(flags & NM_SETTING_DCB_FLAG_ENABLE))
			PARSE_WARNING ("ignoring DCB %s priority; app not enabled", app);
	}

	if (success) {
		g_object_set (G_OBJECT (s_dcb),
		              flags_prop->flags_prop, flags,
		              priority_prop, (guint) priority,
		              NULL);
	}

	return success;
}

typedef void (*DcbSetBoolFunc) (NMSettingDcb *, guint, gboolean);

static gboolean
read_dcb_bool_array (shvarFile *ifcfg,
                     NMSettingDcb *s_dcb,
                     NMSettingDcbFlags flags,
                     const char *prop,
                     const char *desc,
                     DcbSetBoolFunc set_func,
                     GError **error)
{
	gs_free char *value = NULL;
	const char *v;
	guint i;

	v = svGetValueStr (ifcfg, prop, &value);
	if (!v)
		return TRUE;

	if (!(flags & NM_SETTING_DCB_FLAG_ENABLE)) {
		PARSE_WARNING ("ignoring %s; %s is not enabled", prop, desc);
		return TRUE;
	}

	if (strlen (v) != 8) {
		PARSE_WARNING ("%s value '%s' must be 8 characters long", prop, v);
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "boolean array must be 8 characters");
		return FALSE;
	}

	/* All characters must be either 0 or 1 */
	for (i = 0; i < 8; i++) {
		if (v[i] != '0' && v[i] != '1') {
			PARSE_WARNING ("invalid %s value '%s': not all 0s and 1s", prop, v);
			g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			                     "invalid boolean digit");
			return FALSE;
		}
		set_func (s_dcb, i, (v[i] == '1'));
	}
	return TRUE;
}

typedef void (*DcbSetUintFunc) (NMSettingDcb *, guint, guint);

static gboolean
read_dcb_uint_array (shvarFile *ifcfg,
                     NMSettingDcb *s_dcb,
                     NMSettingDcbFlags flags,
                     const char *prop,
                     const char *desc,
                     gboolean f_allowed,
                     DcbSetUintFunc set_func,
                     GError **error)
{
	gs_free char *val = NULL;
	guint i;

	val = svGetValueStr_cp (ifcfg, prop);
	if (!val)
		return TRUE;

	if (!(flags & NM_SETTING_DCB_FLAG_ENABLE)) {
		PARSE_WARNING ("ignoring %s; %s is not enabled", prop, desc);
		return TRUE;
	}

	if (strlen (val) != 8) {
		PARSE_WARNING ("%s value '%s' must be 8 characters long", prop, val);
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "uint array must be 8 characters");
		return FALSE;
	}

	/* All characters must be either 0 - 7 or (optionally) f */
	for (i = 0; i < 8; i++) {
		if (val[i] >= '0' && val[i] <= '7')
			set_func (s_dcb, i, val[i] - '0');
		else if (f_allowed && (val[i] == 'f' || val[i] == 'F'))
			set_func (s_dcb, i, 15);
		else {
			PARSE_WARNING ("invalid %s value '%s': not 0 - 7%s",
			               prop, val, f_allowed ? " or 'f'" : "");
			g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			                     "invalid uint digit");
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
read_dcb_percent_array (shvarFile *ifcfg,
                        NMSettingDcb *s_dcb,
                        NMSettingDcbFlags flags,
                        const char *prop,
                        const char *desc,
                        gboolean sum_pct,
                        DcbSetUintFunc set_func,
                        GError **error)
{
	gs_free char *val = NULL;
	gs_free const char **split = NULL;
	const char *const *iter;
	guint i, sum = 0;

	val = svGetValueStr_cp (ifcfg, prop);
	if (!val)
		return TRUE;

	if (!(flags & NM_SETTING_DCB_FLAG_ENABLE)) {
		PARSE_WARNING ("ignoring %s; %s is not enabled", prop, desc);
		return TRUE;
	}

	split = nm_utils_strsplit_set (val, ",");
	if (NM_PTRARRAY_LEN (split) != 8) {
		PARSE_WARNING ("invalid %s percentage list value '%s'", prop, val);
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "percent array must be 8 elements");
		return FALSE;
	}

	for (iter = split, i = 0; iter && *iter; iter++, i++) {
		int tmp;

		tmp = _nm_utils_ascii_str_to_int64 (*iter, 0, 0, 100, -1);
		if (tmp < 0) {
			PARSE_WARNING ("invalid %s percentage value '%s'", prop, *iter);
			g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			                     "invalid percent element");
			return FALSE;
		}
		set_func (s_dcb, i, (guint) tmp);
		sum += (guint) tmp;
	}

	if (sum_pct && (sum != 100)) {
		PARSE_WARNING ("%s percentages do not equal 100%%", prop);
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "invalid percentage sum");
		return FALSE;
	}

	return TRUE;
}

static gboolean
make_dcb_setting (shvarFile *ifcfg,
                  NMSetting **out_setting,
                  GError **error)
{
	NMSettingDcb *s_dcb = NULL;
	gboolean dcb_on;
	NMSettingDcbFlags flags = NM_SETTING_DCB_FLAG_NONE;
	char *val;

	g_return_val_if_fail (out_setting != NULL, FALSE);

	dcb_on = !!svGetValueBoolean (ifcfg, "DCB", FALSE);
	if (!dcb_on)
		return TRUE;

	s_dcb = (NMSettingDcb *) nm_setting_dcb_new ();
	g_assert (s_dcb);

	/* FCOE */
	if (!read_dcb_app (ifcfg, s_dcb, "FCOE",
	                   &dcb_flags_props[DCB_APP_FCOE_FLAGS],
	                   NM_SETTING_DCB_APP_FCOE_PRIORITY,
	                   error)) {
		g_object_unref (s_dcb);
		return FALSE;
	}
	if (nm_setting_dcb_get_app_fcoe_flags (s_dcb) & NM_SETTING_DCB_FLAG_ENABLE) {
		val = svGetValueStr_cp (ifcfg, KEY_DCB_APP_FCOE_MODE);
		if (val) {
			if (strcmp (val, NM_SETTING_DCB_FCOE_MODE_FABRIC) == 0 ||
			    strcmp (val, NM_SETTING_DCB_FCOE_MODE_VN2VN) == 0)
				g_object_set (G_OBJECT (s_dcb), NM_SETTING_DCB_APP_FCOE_MODE, val, NULL);
			else {
				PARSE_WARNING ("invalid FCoE mode '%s'", val);
				g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				                     "invalid FCoE mode");
				g_free (val);
				g_object_unref (s_dcb);
				return FALSE;
			}
			g_free (val);
		}
	}

	/* iSCSI */
	if (!read_dcb_app (ifcfg, s_dcb, "ISCSI",
	                   &dcb_flags_props[DCB_APP_ISCSI_FLAGS],
	                   NM_SETTING_DCB_APP_ISCSI_PRIORITY,
	                   error)) {
		g_object_unref (s_dcb);
		return FALSE;
	}

	/* FIP */
	if (!read_dcb_app (ifcfg, s_dcb, "FIP",
	                   &dcb_flags_props[DCB_APP_FIP_FLAGS],
	                   NM_SETTING_DCB_APP_FIP_PRIORITY,
	                   error)) {
		g_object_unref (s_dcb);
		return FALSE;
	}

	/* Priority Flow Control */
	flags = read_dcb_flags (ifcfg, &dcb_flags_props[DCB_PFC_FLAGS]);
	g_object_set (G_OBJECT (s_dcb), NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS, flags, NULL);

	if (!read_dcb_bool_array (ifcfg,
	                          s_dcb,
	                          flags,
	                          KEY_DCB_PFC_UP,
	                          "PFC",
	                          nm_setting_dcb_set_priority_flow_control,
	                          error)) {
		g_object_unref (s_dcb);
		return FALSE;
	}

	/* Priority Groups */
	flags = read_dcb_flags (ifcfg, &dcb_flags_props[DCB_PG_FLAGS]);
	g_object_set (G_OBJECT (s_dcb), NM_SETTING_DCB_PRIORITY_GROUP_FLAGS, flags, NULL);

	if (!read_dcb_uint_array (ifcfg,
	                          s_dcb,
	                          flags,
	                          KEY_DCB_PG_ID,
	                          "PGID",
	                          TRUE,
	                          nm_setting_dcb_set_priority_group_id,
	                          error)) {
		g_object_unref (s_dcb);
		return FALSE;
	}

	/* Group bandwidth */
	if (!read_dcb_percent_array (ifcfg,
	                             s_dcb,
	                             flags,
	                             KEY_DCB_PG_PCT,
	                             "PGPCT",
	                             TRUE,
	                             nm_setting_dcb_set_priority_group_bandwidth,
	                             error)) {
		g_object_unref (s_dcb);
		return FALSE;
	}

	/* Priority bandwidth */
	if (!read_dcb_percent_array (ifcfg,
	                             s_dcb,
	                             flags,
	                             KEY_DCB_PG_UPPCT,
	                             "UPPCT",
	                             FALSE,
	                             nm_setting_dcb_set_priority_bandwidth,
	                             error)) {
		g_object_unref (s_dcb);
		return FALSE;
	}

	/* Strict Bandwidth */
	if (!read_dcb_bool_array (ifcfg,
	                          s_dcb,
	                          flags,
	                          KEY_DCB_PG_STRICT,
	                          "STRICT",
	                          nm_setting_dcb_set_priority_strict_bandwidth,
	                          error)) {
		g_object_unref (s_dcb);
		return FALSE;
	}

	if (!read_dcb_uint_array (ifcfg,
	                          s_dcb,
	                          flags,
	                          KEY_DCB_PG_UP2TC,
	                          "UP2TC",
	                          FALSE,
	                          nm_setting_dcb_set_priority_traffic_class,
	                          error)) {
		g_object_unref (s_dcb);
		return FALSE;
	}

	*out_setting = NM_SETTING (s_dcb);
	return TRUE;
}

static gboolean
add_one_wep_key (shvarFile *ifcfg,
                 const char *shvar_key,
                 guint8 key_idx,
                 gboolean passphrase,
                 NMSettingWirelessSecurity *s_wsec,
                 GError **error)
{
	gs_free char *value_free = NULL;
	const char *value;
	const char *key = NULL;

	g_return_val_if_fail (ifcfg != NULL, FALSE);
	g_return_val_if_fail (shvar_key != NULL, FALSE);
	g_return_val_if_fail (key_idx <= 3, FALSE);
	g_return_val_if_fail (s_wsec != NULL, FALSE);

	value = svGetValueStr (ifcfg, shvar_key, &value_free);
	if (!value)
		return TRUE;

	/* Validate keys */
	if (passphrase) {
		if (value[0] && strlen (value) < 64)
			key = value;
	} else {
		if (NM_IN_SET (strlen (value), 10, 26)) {
			/* Hexadecimal WEP key */
			if (NM_STRCHAR_ANY (value, ch, !g_ascii_isxdigit (ch))) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				             "Invalid hexadecimal WEP key.");
				return FALSE;
			}
			key = value;
		} else if (   !strncmp (value, "s:", 2)
		           && NM_IN_SET (strlen (value), 7, 15)) {
			/* ASCII key */
			if (NM_STRCHAR_ANY (value + 2, ch, !g_ascii_isprint (ch))) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				             "Invalid ASCII WEP key.");
				return FALSE;
			}

			/* Remove 's:' prefix.
			 * Don't convert to hex string. wpa_supplicant takes 'wep_key0' option over D-Bus as byte array
			 * and converts it to hex string itself. Even though we convert hex string keys into a bin string
			 * before passing to wpa_supplicant, this prevents two unnecessary conversions. And mainly,
			 * ASCII WEP key doesn't change to HEX WEP key in UI, which could confuse users.
			 */
			key = value + 2;
		}
	}

	if (!key) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Invalid WEP key length.");
		return FALSE;
	}

	nm_setting_wireless_security_set_wep_key (s_wsec, key_idx, key);
	return TRUE;
}

static gboolean
read_wep_keys (shvarFile *ifcfg,
               NMWepKeyType key_type,
               guint8 def_idx,
               NMSettingWirelessSecurity *s_wsec,
               GError **error)
{
	if (key_type != NM_WEP_KEY_TYPE_PASSPHRASE) {
		if (!add_one_wep_key (ifcfg, "KEY1", 0, FALSE, s_wsec, error))
			return FALSE;
		if (!add_one_wep_key (ifcfg, "KEY2", 1, FALSE, s_wsec, error))
			return FALSE;
		if (!add_one_wep_key (ifcfg, "KEY3", 2, FALSE, s_wsec, error))
			return FALSE;
		if (!add_one_wep_key (ifcfg, "KEY4", 3, FALSE, s_wsec, error))
			return FALSE;
		if (!add_one_wep_key (ifcfg, "KEY", def_idx, FALSE, s_wsec, error))
			return FALSE;
	}

	if (key_type != NM_WEP_KEY_TYPE_KEY) {
		if (!add_one_wep_key (ifcfg, "KEY_PASSPHRASE1", 0, TRUE, s_wsec, error))
			return FALSE;
		if (!add_one_wep_key (ifcfg, "KEY_PASSPHRASE2", 1, TRUE, s_wsec, error))
			return FALSE;
		if (!add_one_wep_key (ifcfg, "KEY_PASSPHRASE3", 2, TRUE, s_wsec, error))
			return FALSE;
		if (!add_one_wep_key (ifcfg, "KEY_PASSPHRASE4", 3, TRUE, s_wsec, error))
			return FALSE;
	}

	return TRUE;
}

static NMSettingSecretFlags
read_secret_flags (shvarFile *ifcfg, const char *flags_key)
{
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;
	char *val;

	g_return_val_if_fail (flags_key != NULL, NM_SETTING_SECRET_FLAG_NONE);
	g_return_val_if_fail (flags_key[0] != '\0', NM_SETTING_SECRET_FLAG_NONE);
	g_return_val_if_fail (g_str_has_suffix (flags_key, "_FLAGS"), NM_SETTING_SECRET_FLAG_NONE);

	val = svGetValueStr_cp (ifcfg, flags_key);
	if (val) {
		if (strstr (val, SECRET_FLAG_AGENT))
			flags |= NM_SETTING_SECRET_FLAG_AGENT_OWNED;
		if (strstr (val, SECRET_FLAG_NOT_SAVED))
			flags |= NM_SETTING_SECRET_FLAG_NOT_SAVED;
		if (strstr (val, SECRET_FLAG_NOT_REQUIRED))
			flags |= NM_SETTING_SECRET_FLAG_NOT_REQUIRED;

		g_free (val);
	}
	return flags;
}

static NMSetting *
make_wep_setting (shvarFile *ifcfg,
                  const char *file,
                  GError **error)
{
	gs_unref_object NMSettingWirelessSecurity *s_wsec = NULL;
	char *value;
	shvarFile *keys_ifcfg = NULL;
	int default_key_idx = 0;
	gboolean has_default_key = FALSE;
	NMSettingSecretFlags key_flags;

	s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());
	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none", NULL);

	value = svGetValueStr_cp (ifcfg, "DEFAULTKEY");
	if (value) {
		default_key_idx = _nm_utils_ascii_str_to_int64 (value, 0, 1, 4, 0);
		if (default_key_idx == 0) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid default WEP key '%s'", value);
			g_free (value);
			return NULL;
		}
		has_default_key = TRUE;
		default_key_idx--;  /* convert to [0...3] */
		g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, (guint) default_key_idx, NULL);
		g_free (value);
	}

	/* Read WEP key flags */
	key_flags = read_secret_flags (ifcfg, "WEP_KEY_FLAGS");
	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS, key_flags, NULL);

	/* Read keys in the ifcfg file if they are system-owned */
	if (key_flags == NM_SETTING_SECRET_FLAG_NONE) {
		NMWepKeyType key_type;
		const char *v;
		gs_free char *to_free = NULL;

		v = svGetValueStr (ifcfg, "KEY_TYPE", &to_free);
		if (!v)
			key_type = NM_WEP_KEY_TYPE_UNKNOWN;
		else if (nm_streq (v, "key"))
			key_type = NM_WEP_KEY_TYPE_KEY;
		else if (nm_streq (v, "passphrase"))
			key_type = NM_WEP_KEY_TYPE_PASSPHRASE;
		else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid KEY_TYPE value '%s'", v);
			return FALSE;
		}

		if (!read_wep_keys (ifcfg, key_type, default_key_idx, s_wsec, error))
			return NULL;

		/* Try to get keys from the "shadow" key file */
		keys_ifcfg = utils_get_keys_ifcfg (file, FALSE);
		if (keys_ifcfg) {
			if (!read_wep_keys (keys_ifcfg, key_type, default_key_idx, s_wsec, error)) {
				svCloseFile (keys_ifcfg);
				return NULL;
			}
			svCloseFile (keys_ifcfg);
			g_assert (error == NULL || *error == NULL);
		}

		g_object_set (G_OBJECT (s_wsec),
		              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, key_type,
		              NULL);
	}

	value = svGetValueStr_cp (ifcfg, "SECURITYMODE");
	if (value) {
		char *lcase;

		lcase = g_ascii_strdown (value, -1);
		g_free (value);

		if (!strcmp (lcase, "open")) {
			g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", NULL);
		} else if (!strcmp (lcase, "restricted")) {
			g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "shared", NULL);
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid WEP authentication algorithm '%s'",
			             lcase);
			g_free (lcase);
			return NULL;
		}
		g_free (lcase);
	}

	/* If no WEP keys were given, and the keys are not agent-owned, and no
	 * default WEP key index was given, then the connection is unencrypted.
	 */
	if (   !nm_setting_wireless_security_get_wep_key (s_wsec, 0)
	    && !nm_setting_wireless_security_get_wep_key (s_wsec, 1)
	    && !nm_setting_wireless_security_get_wep_key (s_wsec, 2)
	    && !nm_setting_wireless_security_get_wep_key (s_wsec, 3)
	    && (has_default_key == FALSE)
	    && (key_flags == NM_SETTING_SECRET_FLAG_NONE)) {
		const char *auth_alg;

		auth_alg = nm_setting_wireless_security_get_auth_alg (s_wsec);
		if (auth_alg && !strcmp (auth_alg, "shared")) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "WEP Shared Key authentication is invalid for "
			             "unencrypted connections.");
			return NULL;
		}

		/* Unencrypted */
		return NULL;
	}

	return g_steal_pointer (&s_wsec);
}

static gboolean
fill_wpa_ciphers (shvarFile *ifcfg,
                  NMSettingWirelessSecurity *wsec,
                  gboolean group,
                  gboolean adhoc)
{
	gs_free char *value = NULL;
	const char *p;
	gs_free const char **list = NULL;
	const char *const *iter;
	int i = 0;

	p = svGetValueStr (ifcfg, group ? "CIPHER_GROUP" : "CIPHER_PAIRWISE", &value);
	if (!p)
		return TRUE;

	list = nm_utils_strsplit_set (p, " ");
	for (iter = list; iter && *iter; iter++, i++) {
		/* Ad-Hoc configurations cannot have pairwise ciphers, and can only
		 * have one group cipher.  Ignore any additional group ciphers and
		 * any pairwise ciphers specified.
		 */
		if (adhoc) {
			if (group && (i > 0)) {
				PARSE_WARNING ("ignoring group cipher '%s' (only one group cipher allowed "
				               "in Ad-Hoc mode)", *iter);
				continue;
			} else if (!group) {
				PARSE_WARNING ("ignoring pairwise cipher '%s' (pairwise not used "
				               "in Ad-Hoc mode)", *iter);
				continue;
			}
		}

		if (!strcmp (*iter, "CCMP")) {
			if (group)
				nm_setting_wireless_security_add_group (wsec, "ccmp");
			else
				nm_setting_wireless_security_add_pairwise (wsec, "ccmp");
		} else if (!strcmp (*iter, "TKIP")) {
			if (group)
				nm_setting_wireless_security_add_group (wsec, "tkip");
			else
				nm_setting_wireless_security_add_pairwise (wsec, "tkip");
		} else if (group && !strcmp (*iter, "WEP104"))
			nm_setting_wireless_security_add_group (wsec, "wep104");
		else if (group && !strcmp (*iter, "WEP40"))
			nm_setting_wireless_security_add_group (wsec, "wep40");
		else {
			PARSE_WARNING ("ignoring invalid %s cipher '%s'",
			               group ? "CIPHER_GROUP" : "CIPHER_PAIRWISE",
			               *iter);
		}
	}

	return TRUE;
}

#define WPA_PMK_LEN 32

static char *
parse_wpa_psk (shvarFile *ifcfg,
               const char *file,
               GBytes *ssid,
               GError **error)
{
	shvarFile *keys_ifcfg;
	gs_free char *psk = NULL;
	size_t plen;

	/* Passphrase must be between 10 and 66 characters in length because WPA
	 * hex keys are exactly 64 characters (no quoting), and WPA passphrases
	 * are between 8 and 63 characters (inclusive), plus optional quoting if
	 * the passphrase contains spaces.
	 */

	/* Try to get keys from the "shadow" key file */
	keys_ifcfg = utils_get_keys_ifcfg (file, FALSE);
	if (keys_ifcfg) {
		psk = svGetValueStr_cp (keys_ifcfg, "WPA_PSK");
		svCloseFile (keys_ifcfg);
	}

	/* Fall back to the original ifcfg */
	if (!psk)
		psk = svGetValueStr_cp (ifcfg, "WPA_PSK");

	if (!psk)
		return NULL;

	plen = strlen (psk);

	if (plen == 64) {
		/* Verify the hex PSK; 64 digits */
		if (!NM_STRCHAR_ALL (psk, ch, g_ascii_isxdigit (ch))) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid WPA_PSK (contains non-hexadecimal characters)");
			return NULL;
		}
	} else {
		if (plen < 8 || plen > 63) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid WPA_PSK (passphrases must be between "
			             "8 and 63 characters long (inclusive))");
			return NULL;
		}
	}

	return g_steal_pointer (&psk);
}

static void
read_8021x_password (shvarFile *ifcfg, shvarFile *keys_ifcfg, const char *name,
                     char **value, NMSettingSecretFlags *flags)
{
	gs_free char *flags_key = NULL;

	*value = NULL;
	flags_key = g_strdup_printf ("%s_FLAGS", name);
	*flags = read_secret_flags (ifcfg, flags_key);

	if (*flags == NM_SETTING_SECRET_FLAG_NONE) {
		*value = svGetValueStr_cp (ifcfg, name);
		if (!*value && keys_ifcfg)
			*value = svGetValueStr_cp (keys_ifcfg, name);
	}
}

static gboolean
eap_simple_reader (const char *eap_method,
                   shvarFile *ifcfg,
                   shvarFile *keys,
                   NMSetting8021x *s_8021x,
                   gboolean phase2,
                   GError **error)
{
	NMSettingSecretFlags flags;
	GBytes *bytes;
	char *value;

	value = svGetValueStr_cp (ifcfg, "IEEE_8021X_IDENTITY");
	if (!value) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Missing IEEE_8021X_IDENTITY for EAP method '%s'.",
		             eap_method);
		return FALSE;
	}
	g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, value, NULL);
	nm_clear_g_free (&value);

	read_8021x_password (ifcfg, keys, "IEEE_8021X_PASSWORD", &value, &flags);
	g_object_set (s_8021x, NM_SETTING_802_1X_PASSWORD_FLAGS, flags, NULL);
	if (value) {
		g_object_set (s_8021x, NM_SETTING_802_1X_PASSWORD, value, NULL);
		nm_clear_g_free (&value);
	}

	read_8021x_password (ifcfg, keys, "IEEE_8021X_PASSWORD_RAW", &value, &flags);
	g_object_set (s_8021x, NM_SETTING_802_1X_PASSWORD_RAW_FLAGS, flags, NULL);
	if (value) {
		bytes = nm_utils_hexstr2bin (value);
		if (!bytes) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid hex string '%s' in IEEE_8021X_PASSWORD_RAW.",
			             value);
			g_free (value);
			return FALSE;
		}
		g_object_set (s_8021x, NM_SETTING_802_1X_PASSWORD_RAW, bytes, NULL);
		g_bytes_unref (bytes);
		nm_clear_g_free (&value);
	}

	return TRUE;
}

static char *
get_full_file_path (const char *ifcfg_path, const char *file_path)
{
	const char *base = file_path;
	char *p, *ret, *dirname;

	g_return_val_if_fail (ifcfg_path != NULL, NULL);
	g_return_val_if_fail (file_path != NULL, NULL);

	if (file_path[0] == '/')
		return g_strdup (file_path);

	p = strrchr (file_path, '/');
	if (p)
		base = p + 1;

	dirname = g_path_get_dirname (ifcfg_path);
	ret = g_build_path ("/", dirname, base, NULL);
	g_free (dirname);
	return ret;
}

static char *
get_cert_value (const char *ifcfg_path, const char *value,
                NMSetting8021xCKScheme *out_scheme)
{
	if (strncmp (value, "pkcs11:", 7) == 0) {
		*out_scheme = NM_SETTING_802_1X_CK_SCHEME_PKCS11;
		return g_strdup (value);
	}

	*out_scheme = NM_SETTING_802_1X_CK_SCHEME_PATH;
	return get_full_file_path (ifcfg_path, value);
}

static gboolean
eap_tls_reader (const char *eap_method,
                shvarFile *ifcfg,
                shvarFile *keys,
                NMSetting8021x *s_8021x,
                gboolean phase2,
                GError **error)
{
	gs_free char *ca_cert = NULL;
	gs_free char *privkey = NULL;
	gs_free char *privkey_password = NULL;
	char *value;
	char *ca_cert_password = NULL;
	char *client_cert_password = NULL;
	NMSetting8021xCKFormat privkey_format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	const char *ca_cert_key = phase2 ? "IEEE_8021X_INNER_CA_CERT" : "IEEE_8021X_CA_CERT";
	const char *ca_cert_pw_key = phase2 ? "IEEE_8021X_INNER_CA_CERT_PASSWORD" : "IEEE_8021X_CA_CERT_PASSWORD";
	const char *ca_cert_pw_prop = phase2 ? NM_SETTING_802_1X_PHASE2_CA_CERT_PASSWORD : NM_SETTING_802_1X_CA_CERT_PASSWORD;
	const char *ca_cert_pw_flags_key = phase2 ? "IEEE_8021X_INNER_CA_CERT_PASSWORD_FLAGS" : "IEEE_8021X_CA_CERT_PASSWORD_FLAGS";
	const char *ca_cert_pw_flags_prop = phase2 ? NM_SETTING_802_1X_PHASE2_CA_CERT_PASSWORD_FLAGS : NM_SETTING_802_1X_CA_CERT_PASSWORD_FLAGS;
	const char *cli_cert_key = phase2 ? "IEEE_8021X_INNER_CLIENT_CERT" : "IEEE_8021X_CLIENT_CERT";
	const char *cli_cert_pw_key = phase2 ? "IEEE_8021X_INNER_CLIENT_CERT_PASSWORD" : "IEEE_8021X_CLIENT_CERT_PASSWORD";
	const char *cli_cert_pw_prop = phase2 ? NM_SETTING_802_1X_PHASE2_CLIENT_CERT_PASSWORD : NM_SETTING_802_1X_CLIENT_CERT_PASSWORD;
	const char *cli_cert_pw_flags_key = phase2 ? "IEEE_8021X_INNER_CLIENT_CERT_PASSWORD_FLAGS" : "IEEE_8021X_CLIENT_CERT_PASSWORD_FLAGS";
	const char *cli_cert_pw_flags_prop = phase2 ? NM_SETTING_802_1X_PHASE2_CLIENT_CERT_PASSWORD_FLAGS : NM_SETTING_802_1X_CLIENT_CERT_PASSWORD_FLAGS;
	const char *pk_key = phase2 ? "IEEE_8021X_INNER_PRIVATE_KEY" : "IEEE_8021X_PRIVATE_KEY";
	const char *pk_pw_key = phase2 ? "IEEE_8021X_INNER_PRIVATE_KEY_PASSWORD": "IEEE_8021X_PRIVATE_KEY_PASSWORD";
	const char *pk_pw_flags_key = phase2 ? "IEEE_8021X_INNER_PRIVATE_KEY_PASSWORD_FLAGS" : "IEEE_8021X_PRIVATE_KEY_PASSWORD_FLAGS";
	const char *pk_pw_flags_prop = phase2 ? NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS : NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD_FLAGS;
	NMSettingSecretFlags flags;
	NMSetting8021xCKScheme scheme;

	value = svGetValueStr_cp (ifcfg, "IEEE_8021X_IDENTITY");
	if (value) {
		g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, value, NULL);
		g_free (value);
	}

	ca_cert = svGetValueStr_cp (ifcfg, ca_cert_key);
	if (ca_cert) {
		gs_free char *real_cert_value = NULL;

		real_cert_value = get_cert_value (svFileGetName (ifcfg), ca_cert, &scheme);
		if (phase2) {
			if (!nm_setting_802_1x_set_phase2_ca_cert (s_8021x, real_cert_value, scheme, NULL, error))
				return FALSE;
		} else {
			if (!nm_setting_802_1x_set_ca_cert (s_8021x, real_cert_value, scheme, NULL, error))
				return FALSE;
		}

		if (scheme == NM_SETTING_802_1X_CK_SCHEME_PKCS11) {
			flags = read_secret_flags (ifcfg, ca_cert_pw_flags_key);
			g_object_set (s_8021x, ca_cert_pw_flags_prop, flags, NULL);

			if (flags == NM_SETTING_SECRET_FLAG_NONE) {
				ca_cert_password = svGetValueStr_cp (ifcfg, ca_cert_pw_key);
				g_object_set (s_8021x, ca_cert_pw_prop, ca_cert_password, NULL);
			}
		}
	} else {
		PARSE_WARNING ("missing %s for EAP method '%s'; this is insecure!",
		               ca_cert_key, eap_method);
	}

	/* Read and set private key password flags */
	flags = read_secret_flags (ifcfg, pk_pw_flags_key);
	g_object_set (s_8021x, pk_pw_flags_prop, flags, NULL);

	/* Read the private key password if it's system-owned */
	if (flags == NM_SETTING_SECRET_FLAG_NONE) {
		/* Private key password */
		privkey_password = svGetValueStr_cp (ifcfg, pk_pw_key);
		if (!privkey_password && keys) {
			/* Try the lookaside keys file */
			privkey_password = svGetValueStr_cp (keys, pk_pw_key);
		}
	}

	/* The private key itself */
	privkey = svGetValueStr_cp (ifcfg, pk_key);
	if (!privkey) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Missing %s for EAP method '%s'.",
		             pk_key,
		             eap_method);
		return FALSE;
	}

	{
		gs_free char *real_cert_value = NULL;

		real_cert_value = get_cert_value (svFileGetName (ifcfg), privkey, &scheme);
		if (phase2) {
			if (!nm_setting_802_1x_set_phase2_private_key (s_8021x,
			                                               real_cert_value,
			                                               privkey_password,
			                                               scheme,
			                                               &privkey_format,
			                                               error))
				return FALSE;
		} else {
			if (!nm_setting_802_1x_set_private_key (s_8021x,
			                                        real_cert_value,
			                                        privkey_password,
			                                        scheme,
			                                        &privkey_format,
			                                        error))
				return FALSE;
		}
	}

	/* Only set the client certificate if the private key is not PKCS#12 format,
	 * as NM (due to supplicant restrictions) requires.  If the key was PKCS#12,
	 * then nm_setting_802_1x_set_private_key() already set the client certificate
	 * to the same value as the private key.
	 */
	if (privkey_format != NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
		gs_free char *real_cert_value = NULL;
		gs_free char *client_cert = NULL;

		client_cert = svGetValueStr_cp (ifcfg, cli_cert_key);
		if (!client_cert) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Missing %s for EAP method '%s'.",
			             cli_cert_key,
			             eap_method);
			return FALSE;
		}

		real_cert_value = get_cert_value (svFileGetName (ifcfg), client_cert, &scheme);
		if (phase2) {
			if (!nm_setting_802_1x_set_phase2_client_cert (s_8021x, real_cert_value, scheme, NULL, error))
				return FALSE;
		} else {
			if (!nm_setting_802_1x_set_client_cert (s_8021x, real_cert_value, scheme, NULL, error))
				return FALSE;
		}

		if (scheme == NM_SETTING_802_1X_CK_SCHEME_PKCS11) {
			flags = read_secret_flags (ifcfg, cli_cert_pw_flags_key);
			g_object_set (s_8021x, cli_cert_pw_flags_prop, flags, NULL);

			if (flags == NM_SETTING_SECRET_FLAG_NONE) {
				client_cert_password = svGetValueStr_cp (ifcfg, cli_cert_pw_key);
				g_object_set (s_8021x, cli_cert_pw_prop, client_cert_password, NULL);
			}
		}
	}

	return TRUE;
}

static gboolean
eap_peap_reader (const char *eap_method,
                 shvarFile *ifcfg,
                 shvarFile *keys,
                 NMSetting8021x *s_8021x,
                 gboolean phase2,
                 GError **error)
{
	gs_free char *value = NULL;
	const char *v;
	gs_free const char **list = NULL;
	const char *const *iter;
	NMSetting8021xCKScheme scheme;

	v = svGetValueStr (ifcfg, "IEEE_8021X_CA_CERT", &value);
	if (v) {
		gs_free char *real_cert_value = NULL;

		real_cert_value = get_cert_value (svFileGetName (ifcfg), v, &scheme);
		if (!nm_setting_802_1x_set_ca_cert (s_8021x, real_cert_value, scheme, NULL, error))
			return FALSE;
	} else {
		PARSE_WARNING ("missing IEEE_8021X_CA_CERT for EAP method '%s'; this is insecure!",
		               eap_method);
	}

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "IEEE_8021X_PEAP_VERSION", &value);
	if (v) {
		if (!strcmp (v, "0"))
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE1_PEAPVER, "0", NULL);
		else if (!strcmp (v, "1"))
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE1_PEAPVER, "1", NULL);
		else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Unknown IEEE_8021X_PEAP_VERSION value '%s'",
			             v);
			return FALSE;
		}
	}

	if (svGetValueBoolean (ifcfg, "IEEE_8021X_PEAP_FORCE_NEW_LABEL", FALSE))
		g_object_set (s_8021x, NM_SETTING_802_1X_PHASE1_PEAPLABEL, "1", NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "IEEE_8021X_ANON_IDENTITY", &value);
	if (v)
		g_object_set (s_8021x, NM_SETTING_802_1X_ANONYMOUS_IDENTITY, v, NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "IEEE_8021X_INNER_AUTH_METHODS", &value);
	if (!v) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Missing IEEE_8021X_INNER_AUTH_METHODS.");
		return FALSE;
	}

	/* Handle options for the inner auth method */
	list = nm_utils_strsplit_set (v, " ");
	iter = list;
	if (iter) {
		if (NM_IN_STRSET (*iter, "MSCHAPV2",
		                         "MD5",
		                         "GTC")) {
			if (!eap_simple_reader (*iter, ifcfg, keys, s_8021x, TRUE, error))
				return FALSE;
		} else if (nm_streq (*iter, "TLS")) {
			if (!eap_tls_reader (*iter, ifcfg, keys, s_8021x, TRUE, error))
				return FALSE;
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Unknown IEEE_8021X_INNER_AUTH_METHOD '%s'.",
			             *iter);
			return FALSE;
		}

		{
			gs_free char *lower = NULL;

			lower = g_ascii_strdown (*iter, -1);
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTH, lower, NULL);
		}
	}

	if (!nm_setting_802_1x_get_phase2_auth (s_8021x)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "No valid IEEE_8021X_INNER_AUTH_METHODS found.");
		return FALSE;
	}

	return TRUE;
}

static gboolean
eap_ttls_reader (const char *eap_method,
                 shvarFile *ifcfg,
                 shvarFile *keys,
                 NMSetting8021x *s_8021x,
                 gboolean phase2,
                 GError **error)
{
	gs_free char *inner_auth = NULL;
	gs_free char *value = NULL;
	const char *v;
	gs_free const char **list = NULL;
	const char *const *iter;
	NMSetting8021xCKScheme scheme;

	v = svGetValueStr (ifcfg, "IEEE_8021X_CA_CERT", &value);
	if (v) {
		gs_free char *real_cert_value = NULL;

		real_cert_value = get_cert_value (svFileGetName (ifcfg), v, &scheme);
		if (!nm_setting_802_1x_set_ca_cert (s_8021x, real_cert_value, scheme, NULL, error))
			return FALSE;
	} else {
		PARSE_WARNING ("missing IEEE_8021X_CA_CERT for EAP method '%s'; this is insecure!",
		               eap_method);
	}

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "IEEE_8021X_ANON_IDENTITY", &value);
	if (v)
		g_object_set (s_8021x, NM_SETTING_802_1X_ANONYMOUS_IDENTITY, v, NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "IEEE_8021X_INNER_AUTH_METHODS", &value);
	if (!v) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Missing IEEE_8021X_INNER_AUTH_METHODS.");
		return FALSE;
	}

	inner_auth = g_ascii_strdown (v, -1);

	/* Handle options for the inner auth method */
	list = nm_utils_strsplit_set (inner_auth, " ");
	iter = list;
	if (iter) {
		if (NM_IN_STRSET (*iter, "mschapv2",
		                         "mschap",
		                         "pap",
		                         "chap")) {
			if (!eap_simple_reader (*iter, ifcfg, keys, s_8021x, TRUE, error))
				return FALSE;
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTH, *iter, NULL);
		} else if (nm_streq (*iter, "eap-tls")) {
			if (!eap_tls_reader (*iter, ifcfg, keys, s_8021x, TRUE, error))
				return FALSE;
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTHEAP, "tls", NULL);
		} else if (NM_IN_STRSET (*iter, "eap-mschapv2",
		                                "eap-md5",
		                                "eap-gtc")) {
			if (!eap_simple_reader (*iter, ifcfg, keys, s_8021x, TRUE, error))
				return FALSE;
			g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTHEAP, (*iter + NM_STRLEN ("eap-")), NULL);
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Unknown IEEE_8021X_INNER_AUTH_METHOD '%s'.",
			             *iter);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
eap_fast_reader (const char *eap_method,
                 shvarFile *ifcfg,
                 shvarFile *keys,
                 NMSetting8021x *s_8021x,
                 gboolean phase2,
                 GError **error)
{
	char *anon_ident = NULL;
	char *pac_file = NULL;
	char *real_pac_path = NULL;
	char *inner_auth = NULL;
	char *fast_provisioning = NULL;
	char *lower;
	gs_free const char **list = NULL;
	const char *const *iter;
	const char *pac_prov_str;
	gboolean allow_unauth = FALSE, allow_auth = FALSE;
	gboolean success = FALSE;

	pac_file = svGetValueStr_cp (ifcfg, "IEEE_8021X_PAC_FILE");
	if (pac_file) {
		real_pac_path = get_full_file_path (svFileGetName (ifcfg), pac_file);
		g_object_set (s_8021x, NM_SETTING_802_1X_PAC_FILE, real_pac_path, NULL);
	}

	fast_provisioning = svGetValueStr_cp (ifcfg, "IEEE_8021X_FAST_PROVISIONING");
	if (fast_provisioning) {
		gs_free const char **list1 = NULL;

		list1 = nm_utils_strsplit_set (fast_provisioning, " \t");
		for (iter = list1; iter && *iter; iter++) {
			if (strcmp (*iter, "allow-unauth") == 0)
				allow_unauth = TRUE;
			else if (strcmp (*iter, "allow-auth") == 0)
				allow_auth = TRUE;
			else {
				PARSE_WARNING ("invalid IEEE_8021X_FAST_PROVISIONING '%s' "
				               "(space-separated list of these values [allow-auth, allow-unauth] expected)",
				               *iter);
			}
		}
	}
	pac_prov_str = allow_unauth ? (allow_auth ? "3" : "1") : (allow_auth ? "2" : "0");
	g_object_set (s_8021x, NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING, pac_prov_str, NULL);

	if (!pac_file && !(allow_unauth || allow_auth)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "IEEE_8021X_PAC_FILE not provided and EAP-FAST automatic PAC provisioning disabled.");
		goto done;
	}

	anon_ident = svGetValueStr_cp (ifcfg, "IEEE_8021X_ANON_IDENTITY");
	if (anon_ident)
		g_object_set (s_8021x, NM_SETTING_802_1X_ANONYMOUS_IDENTITY, anon_ident, NULL);

	inner_auth = svGetValueStr_cp (ifcfg, "IEEE_8021X_INNER_AUTH_METHODS");
	if (!inner_auth) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Missing IEEE_8021X_INNER_AUTH_METHODS.");
		goto done;
	}

	/* Handle options for the inner auth method */
	list = nm_utils_strsplit_set (inner_auth, " ");
	iter = list;
	if (iter) {
		if (   !strcmp (*iter, "MSCHAPV2")
		    || !strcmp (*iter, "GTC")) {
			if (!eap_simple_reader (*iter, ifcfg, keys, s_8021x, TRUE, error))
				goto done;
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Unknown IEEE_8021X_INNER_AUTH_METHOD '%s'.",
			             *iter);
			goto done;
		}

		lower = g_ascii_strdown (*iter, -1);
		g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTH, lower, NULL);
		g_free (lower);
	}

	if (!nm_setting_802_1x_get_phase2_auth (s_8021x)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "No valid IEEE_8021X_INNER_AUTH_METHODS found.");
		goto done;
	}

	success = TRUE;

done:
	g_free (inner_auth);
	g_free (fast_provisioning);
	g_free (real_pac_path);
	g_free (pac_file);
	g_free (anon_ident);
	return success;
}

typedef struct {
	const char *method;
	gboolean (*reader) (const char *eap_method,
	                    shvarFile *ifcfg,
	                    shvarFile *keys,
	                    NMSetting8021x *s_8021x,
	                    gboolean phase2,
	                    GError **error);
	gboolean wifi_phase2_only;
} EAPReader;

static EAPReader eap_readers[] = {
	{ "md5", eap_simple_reader, TRUE },
	{ "pap", eap_simple_reader, TRUE },
	{ "chap", eap_simple_reader, TRUE },
	{ "mschap", eap_simple_reader, TRUE },
	{ "mschapv2", eap_simple_reader, TRUE },
	{ "leap", eap_simple_reader, FALSE },
	{ "pwd", eap_simple_reader, FALSE },
	{ "tls", eap_tls_reader, FALSE },
	{ "peap", eap_peap_reader, FALSE },
	{ "ttls", eap_ttls_reader, FALSE },
	{ "fast", eap_fast_reader, FALSE },
	{ NULL, NULL }
};

static void
read_8021x_list_value (shvarFile *ifcfg,
                       const char *ifcfg_var_name,
                       NMSetting8021x *setting,
                       const char *prop_name)
{
	gs_free char *value = NULL;
	gs_free const char **strv = NULL;
	const char *v;

	g_return_if_fail (ifcfg != NULL);
	g_return_if_fail (ifcfg_var_name != NULL);
	g_return_if_fail (prop_name != NULL);

	v = svGetValueStr (ifcfg, ifcfg_var_name, &value);
	if (!v)
		return;

	strv = nm_utils_strsplit_set (v, " \t");
	if (strv)
		g_object_set (setting, prop_name, strv, NULL);
}

static NMSetting8021x *
fill_8021x (shvarFile *ifcfg,
            const char *file,
            const char *key_mgmt,
            gboolean wifi,
            GError **error)
{
	nm_auto_shvar_file_close shvarFile *keys = NULL;
	gs_unref_object NMSetting8021x *s_8021x = NULL;
	gs_free char *value = NULL;
	const char *v;
	gs_free const char **list = NULL;
	const char *const *iter;
	gint64 timeout;
	int i_val;

	v = svGetValueStr (ifcfg, "IEEE_8021X_EAP_METHODS", &value);
	if (!v) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Missing IEEE_8021X_EAP_METHODS for key management '%s'",
		             key_mgmt);
		return NULL;
	}

	list = nm_utils_strsplit_set (v, " ");

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();

	/* Read in the lookaside keys file, if present */
	keys = utils_get_keys_ifcfg (file, FALSE);

	/* Validate and handle each EAP method */
	for (iter = list; iter && *iter; iter++) {
		EAPReader *eap = &eap_readers[0];
		gboolean found = FALSE;
		gs_free char *lower = NULL;

		lower = g_ascii_strdown (*iter, -1);
		while (eap->method) {
			if (strcmp (eap->method, lower))
				goto next;

			/* Some EAP methods don't provide keying material, thus they
			 * cannot be used with WiFi unless they are an inner method
			 * used with TTLS or PEAP or whatever.
			 */
			if (wifi && eap->wifi_phase2_only) {
				PARSE_WARNING ("ignored invalid IEEE_8021X_EAP_METHOD '%s'; not allowed for wifi.",
				               lower);
				goto next;
			}

			/* Parse EAP method specific options */
			if (!(*eap->reader)(lower, ifcfg, keys, s_8021x, FALSE, error))
				return NULL;

			nm_setting_802_1x_add_eap_method (s_8021x, lower);
			found = TRUE;
			break;

next:
			eap++;
		}

		if (!found)
			PARSE_WARNING ("ignored unknown IEEE_8021X_EAP_METHOD '%s'.", lower);
	}

	if (nm_setting_802_1x_get_num_eap_methods (s_8021x) == 0) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "No valid EAP methods found in IEEE_8021X_EAP_METHODS.");
		return NULL;
	}

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "IEEE_8021X_SUBJECT_MATCH", &value);
	g_object_set (s_8021x, NM_SETTING_802_1X_SUBJECT_MATCH, v, NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "IEEE_8021X_PHASE2_SUBJECT_MATCH", &value);
	g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_SUBJECT_MATCH, v, NULL);

	i_val = NM_SETTING_802_1X_AUTH_FLAGS_NONE;
	if (!svGetValueEnum (ifcfg, "IEEE_8021X_PHASE1_AUTH_FLAGS",
	                     nm_setting_802_1x_auth_flags_get_type (),
	                     &i_val, error))
		return NULL;
	g_object_set (s_8021x, NM_SETTING_802_1X_PHASE1_AUTH_FLAGS, (guint) i_val, NULL);

	read_8021x_list_value (ifcfg, "IEEE_8021X_ALTSUBJECT_MATCHES",
	                       s_8021x, NM_SETTING_802_1X_ALTSUBJECT_MATCHES);
	read_8021x_list_value (ifcfg, "IEEE_8021X_PHASE2_ALTSUBJECT_MATCHES",
	                       s_8021x, NM_SETTING_802_1X_PHASE2_ALTSUBJECT_MATCHES);

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "IEEE_8021X_DOMAIN_SUFFIX_MATCH", &value);
	g_object_set (s_8021x, NM_SETTING_802_1X_DOMAIN_SUFFIX_MATCH, v, NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "IEEE_8021X_PHASE2_DOMAIN_SUFFIX_MATCH", &value);
	g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_DOMAIN_SUFFIX_MATCH, v, NULL);

	timeout = svGetValueInt64 (ifcfg, "IEEE_8021X_AUTH_TIMEOUT", 10, 0, G_MAXINT32, 0);
	g_object_set (s_8021x, NM_SETTING_802_1X_AUTH_TIMEOUT, (gint) timeout, NULL);

	return g_steal_pointer (&s_8021x);
}

static NMSetting *
make_wpa_setting (shvarFile *ifcfg,
                  const char *file,
                  GBytes *ssid,
                  gboolean adhoc,
                  NMSetting8021x **s_8021x,
                  GError **error)
{
	gs_unref_object NMSettingWirelessSecurity *wsec = NULL;
	gs_free char *value = NULL;
	const char *v;
	gboolean wpa_psk = FALSE, wpa_eap = FALSE, ieee8021x = FALSE;
	int i_val;
	GError *local = NULL;

	wsec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());

	v = svGetValueStr (ifcfg, "KEY_MGMT", &value);
	wpa_psk = nm_streq0 (v, "WPA-PSK");
	wpa_eap = nm_streq0 (v, "WPA-EAP");
	ieee8021x = nm_streq0 (v, "IEEE8021X");
	if (!wpa_psk && !wpa_eap && !ieee8021x)
		return NULL; /* Not WPA or Dynamic WEP */

	/* WPS */
	i_val = NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DEFAULT;
	if (!svGetValueEnum (ifcfg, "WPS_METHOD",
	                     nm_setting_wireless_security_wps_method_get_type (),
	                     &i_val, error))
		return NULL;
	g_object_set (wsec,
	              NM_SETTING_WIRELESS_SECURITY_WPS_METHOD, (guint) i_val,
	              NULL);

	/* Pairwise and Group ciphers (only relevant for WPA/RSN) */
	if (wpa_psk || wpa_eap) {
		fill_wpa_ciphers (ifcfg, wsec, FALSE, adhoc);
		fill_wpa_ciphers (ifcfg, wsec, TRUE, adhoc);
	}

	/* WPA and/or RSN */
	if (adhoc) {
		/* Ad-Hoc mode only supports WPA proto for now */
		nm_setting_wireless_security_add_proto (wsec, "wpa");
	} else {
		gs_free char *value2 = NULL;
		const char *v2;

		v2 = svGetValueStr (ifcfg, "WPA_ALLOW_WPA", &value2);
		if (v2 && svParseBoolean (v2, TRUE))
			nm_setting_wireless_security_add_proto (wsec, "wpa");

		nm_clear_g_free (&value2);
		v2 = svGetValueStr (ifcfg, "WPA_ALLOW_WPA2", &value2);
		if (v2 && svParseBoolean (v2, TRUE))
			nm_setting_wireless_security_add_proto (wsec, "rsn");
	}

	if (wpa_psk) {
		NMSettingSecretFlags psk_flags;

		psk_flags = read_secret_flags (ifcfg, "WPA_PSK_FLAGS");
		g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_PSK_FLAGS, psk_flags, NULL);

		/* Read PSK if it's system-owned */
		if (psk_flags == NM_SETTING_SECRET_FLAG_NONE) {
			gs_free char *psk = NULL;

			psk = parse_wpa_psk (ifcfg, file, ssid, &local);
			if (psk)
				g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_PSK, psk, NULL);
			else if (local) {
				g_propagate_error (error, local);
				return NULL;
			}
		}

		if (adhoc)
			g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-none", NULL);
		else
			g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", NULL);
	} else if (wpa_eap || ieee8021x) {
		/* Adhoc mode is mutually exclusive with any 802.1x-based authentication */
		if (adhoc) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Ad-Hoc mode cannot be used with KEY_MGMT type '%s'", v);
			return NULL;
		}

		*s_8021x = fill_8021x (ifcfg, file, v, TRUE, error);
		if (!*s_8021x)
			return NULL;

		{
			gs_free char *lower = g_ascii_strdown (v, -1);

			g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, lower, NULL);
		}
	} else {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Unknown wireless KEY_MGMT type '%s'", v);
		return NULL;
	}

	i_val = NM_SETTING_WIRELESS_SECURITY_PMF_DEFAULT;
	if (!svGetValueEnum (ifcfg, "PMF",
	                     nm_setting_wireless_security_pmf_get_type (),
	                     &i_val, error))
		return NULL;
	g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_PMF, i_val, NULL);

	i_val = NM_SETTING_WIRELESS_SECURITY_FILS_DEFAULT;
	if (!svGetValueEnum (ifcfg, "FILS",
	                     nm_setting_wireless_security_fils_get_type (),
	                     &i_val, error))
		return NULL;
	g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_FILS, i_val, NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "SECURITYMODE", &value);
	if (NM_IN_STRSET (v, NULL, "open"))
		g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, v, NULL);

	return (NMSetting *) g_steal_pointer (&wsec);
}

static NMSetting *
make_leap_setting (shvarFile *ifcfg,
                   const char *file,
                   GError **error)
{
	gs_unref_object NMSettingWirelessSecurity *wsec = NULL;
	shvarFile *keys_ifcfg;
	gs_free char *value = NULL;
	NMSettingSecretFlags flags;

	wsec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());

	value = svGetValueStr_cp (ifcfg, "KEY_MGMT");
	if (!value || strcmp (value, "IEEE8021X"))
		return NULL;
	nm_clear_g_free (&value);

	value = svGetValueStr_cp (ifcfg, "SECURITYMODE");
	if (!value || strcasecmp (value, "leap"))
		return NULL; /* Not LEAP */
	nm_clear_g_free (&value);

	flags = read_secret_flags (ifcfg, "IEEE_8021X_PASSWORD_FLAGS");
	g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD_FLAGS, flags, NULL);

	/* Read LEAP password if it's system-owned */
	if (flags == NM_SETTING_SECRET_FLAG_NONE) {
		value = svGetValueStr_cp (ifcfg, "IEEE_8021X_PASSWORD");
		if (!value) {
			/* Try to get keys from the "shadow" key file */
			keys_ifcfg = utils_get_keys_ifcfg (file, FALSE);
			if (keys_ifcfg) {
				value = svGetValueStr_cp (keys_ifcfg, "IEEE_8021X_PASSWORD");
				svCloseFile (keys_ifcfg);
			}
		}
		if (value && strlen (value))
			g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD, value, NULL);
		nm_clear_g_free (&value);
	}

	value = svGetValueStr_cp (ifcfg, "IEEE_8021X_IDENTITY");
	if (!value) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Missing LEAP identity");
		return NULL;
	}
	g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, value, NULL);
	nm_clear_g_free (&value);

	g_object_set (wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x",
	              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap",
	              NULL);

	return (NMSetting *) g_steal_pointer (&wsec);
}

static NMSetting *
make_wireless_security_setting (shvarFile *ifcfg,
                                const char *file,
                                GBytes *ssid,
                                gboolean adhoc,
                                NMSetting8021x **s_8021x,
                                GError **error)
{
	NMSetting *wsec;

	g_return_val_if_fail (error && !*error, NULL);

	if (!adhoc) {
		wsec = make_leap_setting (ifcfg, file, error);
		if (wsec)
			return wsec;
		else if (*error)
			return NULL;
	}

	wsec = make_wpa_setting (ifcfg, file, ssid, adhoc, s_8021x, error);
	if (wsec)
		return wsec;
	else if (*error)
		return NULL;

	wsec = make_wep_setting (ifcfg, file, error);
	if (wsec)
		return wsec;
	else if (*error)
		return NULL;

	return NULL; /* unencrypted */
}

static const char **
transform_hwaddr_blacklist (const char *blacklist)
{
	const char **strv;
	gsize i, j;

	strv = nm_utils_strsplit_set (blacklist, " \t");
	if (!strv)
		return NULL;
	for (i = 0, j = 0; strv[j]; j++) {
		const char *s = strv[j];

		if (!nm_utils_hwaddr_valid (s, ETH_ALEN)) {
			PARSE_WARNING ("invalid MAC in HWADDR_BLACKLIST '%s'", s);
			continue;
		}
		strv[i++] = s;
	}
	strv[i] = NULL;
	return strv;
}

static NMSetting *
make_wireless_setting (shvarFile *ifcfg,
                       GError **error)
{
	NMSettingWireless *s_wireless;
	const char *cvalue;
	char *value = NULL;
	gint64 chan = 0;
	NMSettingMacRandomization mac_randomization;
	NMSettingWirelessPowersave powersave = NM_SETTING_WIRELESS_POWERSAVE_DEFAULT;

	s_wireless = NM_SETTING_WIRELESS (nm_setting_wireless_new ());

	value = svGetValueStr_cp (ifcfg, "HWADDR");
	if (value) {
		value = g_strstrip (value);
		g_object_set (s_wireless, NM_SETTING_WIRELESS_MAC_ADDRESS, value, NULL);
		g_free (value);
	}

	value = svGetValueStr_cp (ifcfg, "MACADDR");
	if (value) {
		value = g_strstrip (value);
		g_object_set (s_wireless, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, value, NULL);
		g_free (value);
	}

	value = svGetValueStr_cp (ifcfg, "GENERATE_MAC_ADDRESS_MASK");
	g_object_set (s_wireless, NM_SETTING_WIRELESS_GENERATE_MAC_ADDRESS_MASK, value, NULL);
	g_free (value);

	cvalue = svGetValueStr (ifcfg, "HWADDR_BLACKLIST", &value);
	if (cvalue) {
		gs_free const char **strv = NULL;

		strv = transform_hwaddr_blacklist (cvalue);
		g_object_set (s_wireless, NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST, strv, NULL);
		g_free (value);
	}

	value = svGetValueStr_cp (ifcfg, "ESSID");
	if (value) {
		gs_unref_bytes GBytes *bytes = NULL;
		gsize ssid_len = 0;
		gsize value_len = strlen (value);

		if (   value_len > 2
		    && (value_len % 2) == 0
		    && g_str_has_prefix (value, "0x")
		    && NM_STRCHAR_ALL (&value[2], ch, g_ascii_isxdigit (ch))) {
			/* interpret the value as hex-digits iff value starts
			 * with "0x" followed by pairs of hex digits */
			bytes = nm_utils_hexstr2bin (&value[2]);
		} else
			bytes = g_bytes_new (value, value_len);

		ssid_len = g_bytes_get_size (bytes);
		if (ssid_len > 32 || ssid_len == 0) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid SSID '%s' (size %zu not between 1 and 32 inclusive)",
			             value, ssid_len);
			g_free (value);
			goto error;
		}

		g_object_set (s_wireless, NM_SETTING_WIRELESS_SSID, bytes, NULL);
		g_free (value);
	}

	value = svGetValueStr_cp (ifcfg, "MODE");
	if (value) {
		char *lcase;
		const char *mode = NULL;

		lcase = g_ascii_strdown (value, -1);
		g_free (value);

		if (!strcmp (lcase, "ad-hoc")) {
			mode = "adhoc";
		} else if (!strcmp (lcase, "ap")) {
			mode = "ap";
		} else if (!strcmp (lcase, "managed") || !strcmp (lcase, "auto")) {
			mode = "infrastructure";
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid mode '%s' (not 'Ad-Hoc', 'Ap', 'Managed', or 'Auto')",
			             lcase);
			g_free (lcase);
			goto error;
		}
		g_free (lcase);

		g_object_set (s_wireless, NM_SETTING_WIRELESS_MODE, mode, NULL);
	}

	value = svGetValueStr_cp (ifcfg, "BSSID");
	if (value) {
		value = g_strstrip (value);
		g_object_set (s_wireless, NM_SETTING_WIRELESS_BSSID, value, NULL);
		g_free (value);
	}

	value = svGetValueStr_cp (ifcfg, "CHANNEL");
	if (value) {
		errno = 0;
		chan = _nm_utils_ascii_str_to_int64 (value, 10, 1, 196, 0);
		if (errno || (chan == 0)) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid wireless channel '%s'", value);
			g_free (value);
			goto error;
		}
		g_object_set (s_wireless, NM_SETTING_WIRELESS_CHANNEL, (guint32) chan, NULL);
		g_free (value);
	}

	value = svGetValueStr_cp (ifcfg, "BAND");
	if (value) {
		if (!strcmp (value, "a")) {
			if (chan && chan <= 14) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				             "Band '%s' invalid for channel %u", value, (guint32) chan);
				g_free (value);
				goto error;
			}
		} else if (!strcmp (value, "bg")) {
			if (chan && chan > 14) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				             "Band '%s' invalid for channel %u", value, (guint32) chan);
				g_free (value);
				goto error;
			}
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid wireless band '%s'", value);
			g_free (value);
			goto error;
		}
		g_object_set (s_wireless, NM_SETTING_WIRELESS_BAND, value, NULL);
		g_free (value);
	} else if (chan > 0) {
		if (chan > 14)
			g_object_set (s_wireless, NM_SETTING_WIRELESS_BAND, "a", NULL);
		else
			g_object_set (s_wireless, NM_SETTING_WIRELESS_BAND, "bg", NULL);
	}

	value = svGetValueStr_cp (ifcfg, "MTU");
	if (value) {
		int mtu;

		mtu = _nm_utils_ascii_str_to_int64 (value, 10, 0, 50000, -1);
		if (mtu == -1) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid wireless MTU '%s'", value);
			g_free (value);
			goto error;
		}
		g_object_set (s_wireless, NM_SETTING_WIRELESS_MTU, (guint) mtu, NULL);
		g_free (value);
	}

	g_object_set (s_wireless,
	              NM_SETTING_WIRELESS_HIDDEN,
	              svGetValueBoolean (ifcfg, "SSID_HIDDEN", FALSE),
	              NULL);

	cvalue = svGetValue (ifcfg, "POWERSAVE", &value);
	if (cvalue) {
		if (!strcmp (cvalue, "default"))
			powersave = NM_SETTING_WIRELESS_POWERSAVE_DEFAULT;
		else if (!strcmp (cvalue, "ignore"))
			powersave = NM_SETTING_WIRELESS_POWERSAVE_IGNORE;
		else if (!strcmp (cvalue, "disable") || !strcmp (cvalue, "no"))
			powersave = NM_SETTING_WIRELESS_POWERSAVE_DISABLE;
		else if (!strcmp (cvalue, "enable") || !strcmp (cvalue, "yes"))
			powersave = NM_SETTING_WIRELESS_POWERSAVE_ENABLE;
		else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid POWERSAVE value '%s'", cvalue);
			g_free (value);
			goto error;
		}
		g_free (value);
	}

	g_object_set (s_wireless,
	              NM_SETTING_WIRELESS_POWERSAVE,
	              powersave,
	              NULL);

	cvalue = svGetValue (ifcfg, "MAC_ADDRESS_RANDOMIZATION", &value);
	if (cvalue) {
		if (strcmp (cvalue, "default") == 0)
			mac_randomization = NM_SETTING_MAC_RANDOMIZATION_DEFAULT;
		else if (strcmp (cvalue, "never") == 0)
			mac_randomization = NM_SETTING_MAC_RANDOMIZATION_NEVER;
		else if (strcmp (cvalue, "always") == 0)
			mac_randomization = NM_SETTING_MAC_RANDOMIZATION_ALWAYS;
		else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid MAC_ADDRESS_RANDOMIZATION value '%s'", cvalue);
			g_free (value);
			goto error;
		}
		g_free (value);
	} else
		mac_randomization = NM_SETTING_MAC_RANDOMIZATION_DEFAULT;

	g_object_set (s_wireless,
	              NM_SETTING_WIRELESS_MAC_ADDRESS_RANDOMIZATION,
	              mac_randomization,
	              NULL);

	return NM_SETTING (s_wireless);

error:
	if (s_wireless)
		g_object_unref (s_wireless);
	return NULL;
}

static NMConnection *
wireless_connection_from_ifcfg (const char *file,
                                shvarFile *ifcfg,
                                GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *wireless_setting = NULL;
	NMSetting8021x *s_8021x = NULL;
	GBytes *ssid;
	NMSetting *security_setting = NULL;
	char *printable_ssid = NULL;
	const char *mode;
	gboolean adhoc = FALSE;
	GError *local = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (ifcfg != NULL, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	connection = nm_simple_connection_new ();

	/* Wireless */
	wireless_setting = make_wireless_setting (ifcfg, error);
	if (!wireless_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, wireless_setting);

	ssid = nm_setting_wireless_get_ssid (NM_SETTING_WIRELESS (wireless_setting));
	if (ssid) {
		printable_ssid = nm_utils_ssid_to_utf8 (g_bytes_get_data (ssid, NULL),
		                                        g_bytes_get_size (ssid));
	} else
		printable_ssid = g_strdup ("unmanaged");

	mode = nm_setting_wireless_get_mode (NM_SETTING_WIRELESS (wireless_setting));
	if (mode && !strcmp (mode, "adhoc"))
		adhoc = TRUE;

	/* Wireless security */
	security_setting = make_wireless_security_setting (ifcfg, file, ssid, adhoc, &s_8021x, &local);
	if (local) {
		g_free (printable_ssid);
		g_object_unref (connection);
		g_propagate_error (error, local);
		return NULL;
	}
	if (security_setting) {
		nm_connection_add_setting (connection, security_setting);
		if (s_8021x)
			nm_connection_add_setting (connection, NM_SETTING (s_8021x));
	}

	/* Connection */
	con_setting = make_connection_setting (file, ifcfg,
	                                       NM_SETTING_WIRELESS_SETTING_NAME,
	                                       printable_ssid, NULL);
	g_free (printable_ssid);
	if (!con_setting) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	return connection;
}

static void
parse_ethtool_option_autoneg (const char *value, gboolean *out_autoneg)
{
	if (!value) {
		PARSE_WARNING ("Auto-negotiation option missing");
		return;
	}

	if (g_str_equal (value, "off"))
		*out_autoneg = FALSE;
	else if (g_str_equal (value, "on"))
		*out_autoneg = TRUE;
	else
		PARSE_WARNING ("Auto-negotiation unknown value: %s", value);
}

static void
parse_ethtool_option_speed (const char *value, guint32 *out_speed)
{
	if (!value) {
		PARSE_WARNING ("Speed option missing");
		return;
	}

	*out_speed =  _nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXUINT32, 0);
	if (errno)
		PARSE_WARNING ("Speed value '%s' is invalid", value);
}

static void
parse_ethtool_option_duplex (const char *value, const char **out_duplex)
{
	if (!value) {
		PARSE_WARNING ("Duplex option missing");
		return;
	}

	if (g_str_equal (value, "half"))
		*out_duplex = "half";
	else if (g_str_equal (value, "full"))
		*out_duplex = "full";
	else
		PARSE_WARNING ("Duplex unknown value: %s", value);

}

static void
parse_ethtool_option_wol (const char *value, NMSettingWiredWakeOnLan *out_flags)
{
	NMSettingWiredWakeOnLan wol_flags = NM_SETTING_WIRED_WAKE_ON_LAN_NONE;

	if (!value) {
		PARSE_WARNING ("Wake-on-LAN options missing");
		return;
	}

	for (; *value; value++) {
		switch (*value) {
		case 'p':
			wol_flags |= NM_SETTING_WIRED_WAKE_ON_LAN_PHY;
			break;
		case 'u':
			wol_flags |= NM_SETTING_WIRED_WAKE_ON_LAN_UNICAST;
			break;
		case 'm':
			wol_flags |= NM_SETTING_WIRED_WAKE_ON_LAN_MULTICAST;
			break;
		case 'b':
			wol_flags |= NM_SETTING_WIRED_WAKE_ON_LAN_BROADCAST;
			break;
		case 'a':
			wol_flags |= NM_SETTING_WIRED_WAKE_ON_LAN_ARP;
			break;
		case 'g':
			wol_flags |= NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC;
			break;
		case 's':
			break;
		case 'd':
			wol_flags = NM_SETTING_WIRED_WAKE_ON_LAN_NONE;
			break;
		default:
			PARSE_WARNING ("unrecognized Wake-on-LAN option '%c'", *value);
		}
	}

	*out_flags = wol_flags;
}

static void parse_ethtool_option_sopass (const char *value, char **out_password)
{
	if (!value) {
		PARSE_WARNING ("Wake-on-LAN password missing");
		return;
	}

	g_clear_pointer (out_password, g_free);
	if (!nm_utils_hwaddr_valid (value, ETH_ALEN)) {
		PARSE_WARNING ("Wake-on-LAN password '%s' is invalid", value);
		return;
	}

	*out_password = g_strdup (value);
}

static void
parse_ethtool_option (const char *value,
                      NMSettingWiredWakeOnLan *out_flags,
                      char **out_password,
                      gboolean *out_autoneg,
                      guint32 *out_speed,
                      const char **out_duplex)
{
	gs_free const char **words = NULL;
	const char *const *iter;
	const char *opt_val, *opt;

	words = nm_utils_strsplit_set (value, "\t ");
	if (!words)
		return;

	iter = words;

	while (iter[0]) {
		opt = iter++[0];
		opt_val = iter[0];

		if (nm_streq (opt, "autoneg"))
			parse_ethtool_option_autoneg (opt_val, out_autoneg);
		else if (nm_streq (opt, "speed"))
			parse_ethtool_option_speed (opt_val, out_speed);
		else if (nm_streq (opt, "duplex"))
			parse_ethtool_option_duplex (opt_val, out_duplex);
		else if (nm_streq (opt, "wol"))
			parse_ethtool_option_wol (opt_val, out_flags);
		else if (nm_streq (opt, "sopass"))
			parse_ethtool_option_sopass (opt_val, out_password);
		else {
			/* Silently skip unknown options */
			continue;
		}

		if (iter[0])
			iter++;
	}
}

static void
parse_ethtool_options (shvarFile *ifcfg, NMSettingWired *s_wired, const char *value)
{
	NMSettingWiredWakeOnLan wol_flags = NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT;
	gs_free char *wol_password = NULL, *wol_value = NULL;
	gboolean ignore_wol_password = FALSE, autoneg = FALSE;
	guint32 speed = 0;
	const char *duplex = NULL;

	if (value) {
		gs_free const char **opts = NULL;
		const char *const *iter;

		/* WAKE_ON_LAN_IGNORE is inferred from a specified but empty ETHTOOL_OPTS */
		if (!value[0])
			wol_flags = NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE;

		opts = nm_utils_strsplit_set (value, ";");
		for (iter = opts; iter && iter[0]; iter++) {
			/* in case of repeated wol_passwords, parse_ethtool_option()
			 * will do the right thing and clear wol_password before resetting. */
			parse_ethtool_option (iter[0], &wol_flags, &wol_password, &autoneg, &speed, &duplex);
		}
	}

	/* ETHTOOL_WAKE_ON_LAN = ignore overrides WoL settings in ETHTOOL_OPTS */
	wol_value = svGetValueStr_cp (ifcfg, "ETHTOOL_WAKE_ON_LAN");
	if (wol_value) {
		if (strcmp (wol_value, "ignore") == 0)
			wol_flags = NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE;
		else
			PARSE_WARNING ("invalid ETHTOOL_WAKE_ON_LAN value '%s'", wol_value);
	}

	if (   wol_password
	    && !NM_FLAGS_HAS (wol_flags, NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC)) {
		PARSE_WARNING ("Wake-on-LAN password not expected");
		ignore_wol_password = TRUE;
	}

	g_object_set (s_wired,
	              NM_SETTING_WIRED_WAKE_ON_LAN, wol_flags,
	              NM_SETTING_WIRED_WAKE_ON_LAN_PASSWORD, ignore_wol_password ? NULL : wol_password,
	              NM_SETTING_WIRED_AUTO_NEGOTIATE, autoneg,
	              NM_SETTING_WIRED_SPEED, speed,
	              NM_SETTING_WIRED_DUPLEX, duplex,
	              NULL);
}

static NMSetting *
make_wired_setting (shvarFile *ifcfg,
                    const char *file,
                    NMSetting8021x **s_8021x,
                    GError **error)
{
	gs_unref_object NMSettingWired *s_wired = NULL;
	const char *cvalue;
	gs_free char *value = NULL;
	char *nettype;

	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());

	value = svGetValueStr_cp (ifcfg, "MTU");
	if (value) {
		int mtu;

		mtu = _nm_utils_ascii_str_to_int64 (value, 0, 0, 65535, -1);
		if (mtu >= 0)
			g_object_set (s_wired, NM_SETTING_WIRED_MTU, (guint) mtu, NULL);
		else
			PARSE_WARNING ("invalid MTU '%s'", value);
		nm_clear_g_free (&value);
	}

	value = svGetValueStr_cp (ifcfg, "HWADDR");
	if (value) {
		value = g_strstrip (value);
		g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, value, NULL);
		nm_clear_g_free (&value);
	}

	value = svGetValueStr_cp (ifcfg, "SUBCHANNELS");
	if (value) {
		const char *p = value;
		gboolean success = TRUE;

		/* basic sanity checks */
		while (*p) {
			if (!g_ascii_isxdigit (*p) && (*p != ',') && (*p != '.')) {
				PARSE_WARNING ("invalid SUBCHANNELS '%s'", value);
				success = FALSE;
				break;
			}
			p++;
		}

		if (success) {
			gs_free const char **chans = NULL;
			guint32 num_chans;

			chans = nm_utils_strsplit_set (value, ",");
			num_chans = NM_PTRARRAY_LEN (chans);
			if (num_chans < 2 || num_chans > 3) {
				PARSE_WARNING ("invalid SUBCHANNELS '%s' (%u channels, 2 or 3 expected)",
				               value, (unsigned) NM_PTRARRAY_LEN (chans));
			} else
				g_object_set (s_wired, NM_SETTING_WIRED_S390_SUBCHANNELS, chans, NULL);
		}
		nm_clear_g_free (&value);
	}

	value = svGetValueStr_cp (ifcfg, "PORTNAME");
	if (value) {
		nm_setting_wired_add_s390_option (s_wired, "portname", value);
		nm_clear_g_free (&value);
	}

	value = svGetValueStr_cp (ifcfg, "CTCPROT");
	if (value) {
		nm_setting_wired_add_s390_option (s_wired, "ctcprot", value);
		nm_clear_g_free (&value);
	}

	nettype = svGetValueStr_cp (ifcfg, "NETTYPE");
	if (nettype) {
		if (!strcmp (nettype, "qeth") || !strcmp (nettype, "lcs") || !strcmp (nettype, "ctc"))
			g_object_set (s_wired, NM_SETTING_WIRED_S390_NETTYPE, nettype, NULL);
		else
			PARSE_WARNING ("unknown s390 NETTYPE '%s'", nettype);
		g_free (nettype);
	}

	value = svGetValueStr_cp (ifcfg, "OPTIONS");
	if (value) {
		char **options, **iter;

		iter = options = g_strsplit_set (value, " ", 0);
		while (iter && *iter) {
			char *equals = strchr (*iter, '=');
			gboolean valid = FALSE;

			if (equals) {
				*equals = '\0';
				valid = nm_setting_wired_add_s390_option (s_wired, *iter, equals + 1);
			}
			if (!valid)
				PARSE_WARNING ("invalid s390 OPTION '%s'", *iter);
			iter++;
		}
		g_strfreev (options);
		nm_clear_g_free (&value);
	}

	g_object_set (s_wired,
	              NM_SETTING_WIRED_CLONED_MAC_ADDRESS,
	              svGetValueStr (ifcfg, "MACADDR", &value),
	              NULL);
	nm_clear_g_free (&value);

	g_object_set (s_wired,
	              NM_SETTING_WIRED_GENERATE_MAC_ADDRESS_MASK,
	              svGetValueStr (ifcfg, "GENERATE_MAC_ADDRESS_MASK", &value),
	              NULL);
	nm_clear_g_free (&value);

	cvalue = svGetValueStr (ifcfg, "HWADDR_BLACKLIST", &value);
	if (cvalue) {
		gs_free const char **strv = NULL;

		strv = transform_hwaddr_blacklist (cvalue);
		g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST, strv, NULL);
		nm_clear_g_free (&value);
	}

	value = svGetValueStr_cp (ifcfg, "KEY_MGMT");
	if (value) {
		if (!strcmp (value, "IEEE8021X")) {
			*s_8021x = fill_8021x (ifcfg, file, value, FALSE, error);
			if (!*s_8021x)
				return NULL;
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Unknown wired KEY_MGMT type '%s'", value);
			return NULL;
		}
		nm_clear_g_free (&value);
	}

	parse_ethtool_options (ifcfg, s_wired,
	                       svGetValue (ifcfg, "ETHTOOL_OPTS", &value));
	nm_clear_g_free (&value);

	return (NMSetting *) g_steal_pointer (&s_wired);
}

static NMConnection *
wired_connection_from_ifcfg (const char *file,
                             shvarFile *ifcfg,
                             GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *wired_setting = NULL;
	NMSetting8021x *s_8021x = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (ifcfg != NULL, NULL);

	connection = nm_simple_connection_new ();

	con_setting = make_connection_setting (file, ifcfg, NM_SETTING_WIRED_SETTING_NAME, NULL, NULL);
	if (!con_setting) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	wired_setting = make_wired_setting (ifcfg, file, &s_8021x, error);
	if (!wired_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, wired_setting);

	if (s_8021x)
		nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	return connection;
}

static gboolean
parse_infiniband_p_key (shvarFile *ifcfg,
                        int *out_p_key,
                        char **out_parent,
                        GError **error)
{
	char *device = NULL, *physdev = NULL, *pkey_id = NULL;
	char *ifname = NULL;
	int id;
	gboolean ret = FALSE;

	device = svGetValueStr_cp (ifcfg, "DEVICE");
	if (!device) {
		PARSE_WARNING ("InfiniBand connection specified PKEY but not DEVICE");
		goto done;
	}

	physdev = svGetValueStr_cp (ifcfg, "PHYSDEV");
	if (!physdev) {
		PARSE_WARNING ("InfiniBand connection specified PKEY but not PHYSDEV");
		goto done;
	}

	pkey_id = svGetValueStr_cp (ifcfg, "PKEY_ID");
	if (!pkey_id) {
		PARSE_WARNING ("InfiniBand connection specified PKEY but not PKEY_ID");
		goto done;
	}

	id = _nm_utils_ascii_str_to_int64 (pkey_id, 0, 0, 0xFFFF, -1);
	if (id == -1) {
		PARSE_WARNING ("invalid InfiniBand PKEY_ID '%s'", pkey_id);
		goto done;
	}
	id = (id | 0x8000);

	ifname = g_strdup_printf ("%s.%04x", physdev, (unsigned) id);
	if (strcmp (device, ifname) != 0) {
		PARSE_WARNING ("InfiniBand DEVICE (%s) does not match PHYSDEV+PKEY_ID (%s)",
		               device, ifname);
		goto done;
	}

	*out_p_key = id;
	*out_parent = g_strdup (physdev);
	ret = TRUE;

 done:
	g_free (device);
	g_free (physdev);
	g_free (pkey_id);
	g_free (ifname);

	if (!ret) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Failed to create InfiniBand setting.");
	}
	return ret;
}

static NMSetting *
make_infiniband_setting (shvarFile *ifcfg,
                         const char *file,
                         GError **error)
{
	NMSettingInfiniband *s_infiniband;
	char *value = NULL;

	s_infiniband = NM_SETTING_INFINIBAND (nm_setting_infiniband_new ());

	value = svGetValueStr_cp (ifcfg, "MTU");
	if (value) {
		int mtu;

		mtu = _nm_utils_ascii_str_to_int64 (value, 0, 0, 65535, -1);
		if (mtu >= 0)
			g_object_set (s_infiniband, NM_SETTING_INFINIBAND_MTU, (guint) mtu, NULL);
		else
			PARSE_WARNING ("invalid MTU '%s'", value);
		g_free (value);
	}

	value = svGetValueStr_cp (ifcfg, "HWADDR");
	if (value) {
		value = g_strstrip (value);
		g_object_set (s_infiniband, NM_SETTING_INFINIBAND_MAC_ADDRESS, value, NULL);
		g_free (value);
	}

	if (svGetValueBoolean (ifcfg, "CONNECTED_MODE", FALSE))
		g_object_set (s_infiniband, NM_SETTING_INFINIBAND_TRANSPORT_MODE, "connected", NULL);
	else
		g_object_set (s_infiniband, NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram", NULL);

	if (svGetValueBoolean (ifcfg, "PKEY", FALSE)) {
		int p_key;
		char *parent;

		if (!parse_infiniband_p_key (ifcfg, &p_key, &parent, error)) {
			g_object_unref (s_infiniband);
			return NULL;
		}

		g_object_set (s_infiniband,
		              NM_SETTING_INFINIBAND_P_KEY, p_key,
		              NM_SETTING_INFINIBAND_PARENT, parent,
		              NULL);
	}

	return (NMSetting *) s_infiniband;
}

static NMConnection *
infiniband_connection_from_ifcfg (const char *file,
                                  shvarFile *ifcfg,
                                  GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *infiniband_setting = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (ifcfg != NULL, NULL);

	connection = nm_simple_connection_new ();

	con_setting = make_connection_setting (file, ifcfg, NM_SETTING_INFINIBAND_SETTING_NAME, NULL, NULL);
	if (!con_setting) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	infiniband_setting = make_infiniband_setting (ifcfg, file, error);
	if (!infiniband_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, infiniband_setting);

	return connection;
}

static void
handle_bond_option (NMSettingBond *s_bond,
                    const char *key,
                    const char *value)
{
	char *sanitized = NULL, *j;
	const char *p = value;

	/* Remove any quotes or +/- from arp_ip_target */
	if (!g_strcmp0 (key, NM_SETTING_BOND_OPTION_ARP_IP_TARGET) && value && value[0]) {
		if (*p == '\'' || *p == '"')
			p++;
		j = sanitized = g_malloc0 (strlen (p) + 1);
		while (*p) {
			if (*p != '+' && *p != '-' && *p != '\'' && *p != '"')
				*j++ = *p;
			p++;
		}
	}

	if (!nm_setting_bond_add_option (s_bond, key, sanitized ?: value))
		PARSE_WARNING ("invalid bonding option '%s' = %s",
		               key, sanitized ?: value);
	g_free (sanitized);
}

static NMSetting *
make_bond_setting (shvarFile *ifcfg,
                   const char *file,
                   GError **error)
{
	NMSettingBond *s_bond;
	gs_free char *value = NULL;
	const char *v;

	v = svGetValueStr (ifcfg, "DEVICE", &value);
	if (!v) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "mandatory DEVICE keyword missing");
		return NULL;
	}

	s_bond = NM_SETTING_BOND (nm_setting_bond_new ());

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "BONDING_OPTS", &value);
	if (v) {
		gs_free const char **items = NULL;
		const char *const *iter;

		items = nm_utils_strsplit_set (v, " ");
		for (iter = items; iter && *iter; iter++) {
			gs_strfreev char **keys = NULL;
			const char *key, *val;

			keys = g_strsplit_set (*iter, "=", 2);
			if (keys && *keys) {
				key = *keys;
				val = *(keys + 1);
				if (val && key[0] && val[0])
					handle_bond_option (s_bond, key, val);
			}
		}
	}

	return (NMSetting *) s_bond;
}

static NMConnection *
bond_connection_from_ifcfg (const char *file,
                            shvarFile *ifcfg,
                            GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *bond_setting = NULL;
	NMSetting *wired_setting = NULL;
	NMSetting8021x *s_8021x = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (ifcfg != NULL, NULL);

	connection = nm_simple_connection_new ();

	con_setting = make_connection_setting (file, ifcfg, NM_SETTING_BOND_SETTING_NAME, NULL, _("Bond"));
	if (!con_setting) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	bond_setting = make_bond_setting (ifcfg, file, error);
	if (!bond_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, bond_setting);

	wired_setting = make_wired_setting (ifcfg, file, &s_8021x, error);
	if (!wired_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, wired_setting);

	if (s_8021x)
		nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	return connection;
}

/* Check 'error' for errors. Missing config (NULL return value) is a valid case. */
static char *
read_team_config (shvarFile *ifcfg, const char *key, GError **error)
{
	gs_free_error GError *local_error = NULL;
	gs_free char *value = NULL;
	size_t l;

	value = svGetValueStr_cp (ifcfg, key);
	if (!value)
		return NULL;

	l = strlen (value);
	if (l > 1*1024*1024) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "%s too long (size %zd)", key, l);
		return NULL;
	}

	if (!nm_utils_is_json_object (value, &local_error)) {
		PARSE_WARNING ("ignoring invalid team configuration: %s", local_error->message);
		return NULL;
	}

	return g_steal_pointer (&value);
}

static NMSetting *
make_team_setting (shvarFile *ifcfg,
                   const char *file,
                   GError **error)
{
	NMSettingTeam *s_team;
	char *value;
	GError *local_err = NULL;

	value = svGetValueStr_cp (ifcfg, "DEVICE");
	if (!value) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "mandatory DEVICE keyword missing");
		return NULL;
	}
	g_free (value);

	value = read_team_config (ifcfg, "TEAM_CONFIG", &local_err);
	if (local_err) {
		g_propagate_error (error, local_err);
		return NULL;
	}

	s_team = NM_SETTING_TEAM (nm_setting_team_new ());

	g_object_set (s_team, NM_SETTING_TEAM_CONFIG, value, NULL);
	g_free (value);

	return (NMSetting *) s_team;
}

static NMConnection *
team_connection_from_ifcfg (const char *file,
                            shvarFile *ifcfg,
                            GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *team_setting = NULL;
	NMSetting *wired_setting = NULL;
	NMSetting8021x *s_8021x = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (ifcfg != NULL, NULL);

	connection = nm_simple_connection_new ();

	con_setting = make_connection_setting (file, ifcfg, NM_SETTING_TEAM_SETTING_NAME, NULL, _("Team"));
	if (!con_setting) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	team_setting = make_team_setting (ifcfg, file, error);
	if (!team_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, team_setting);

	wired_setting = make_wired_setting (ifcfg, file, &s_8021x, error);
	if (!wired_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, wired_setting);

	if (s_8021x)
		nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	return connection;
}

typedef enum {
	BRIDGE_OPT_TYPE_MAIN,
	BRIDGE_OPT_TYPE_OPTION,
	BRIDGE_OPT_TYPE_PORT_MAIN,
	BRIDGE_OPT_TYPE_PORT_OPTION,
} BridgeOptType;

typedef void (*BridgeOptFunc) (NMSetting *setting,
                               gboolean stp,
                               const char *key,
                               const char *value,
                               BridgeOptType opt_type);

static void
handle_bridge_option (NMSetting *setting,
                      gboolean stp,
                      const char *key,
                      const char *value,
                      BridgeOptType opt_type)
{
	static const struct {
		const char *key;
		const char *property_name;
		BridgeOptType opt_type;
		gboolean only_with_stp;
		gboolean extended_bool;
	} m/*etadata*/[] = {
		{ "DELAY",              NM_SETTING_BRIDGE_FORWARD_DELAY,      BRIDGE_OPT_TYPE_MAIN,   .only_with_stp = TRUE },
		{ "priority",           NM_SETTING_BRIDGE_PRIORITY,           BRIDGE_OPT_TYPE_OPTION, .only_with_stp = TRUE },
		{ "hello_time",         NM_SETTING_BRIDGE_HELLO_TIME,         BRIDGE_OPT_TYPE_OPTION, .only_with_stp = TRUE },
		{ "max_age",            NM_SETTING_BRIDGE_MAX_AGE,            BRIDGE_OPT_TYPE_OPTION, .only_with_stp = TRUE },
		{ "ageing_time",        NM_SETTING_BRIDGE_AGEING_TIME,        BRIDGE_OPT_TYPE_OPTION },
		{ "multicast_snooping", NM_SETTING_BRIDGE_MULTICAST_SNOOPING, BRIDGE_OPT_TYPE_OPTION },
		{ "group_fwd_mask",     NM_SETTING_BRIDGE_GROUP_FORWARD_MASK, BRIDGE_OPT_TYPE_OPTION },
		{ "priority",           NM_SETTING_BRIDGE_PORT_PRIORITY,      BRIDGE_OPT_TYPE_PORT_OPTION },
		{ "path_cost",          NM_SETTING_BRIDGE_PORT_PATH_COST,     BRIDGE_OPT_TYPE_PORT_OPTION },
		{ "hairpin_mode",       NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE,  BRIDGE_OPT_TYPE_PORT_OPTION, .extended_bool = TRUE, },
	};
	const char *error_message = NULL;
	int i;
	gint64 v;

	for (i = 0; i < G_N_ELEMENTS (m); i++) {
		GParamSpec *param_spec;

		if (opt_type != m[i].opt_type)
			continue;
		if (!nm_streq (key, m[i].key))
			continue;
		if (m[i].only_with_stp && !stp) {
			PARSE_WARNING ("'%s' invalid when STP is disabled", key);
			return;
		}

		param_spec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), m[i].property_name);
		switch (param_spec->value_type) {
		case G_TYPE_BOOLEAN:
			if (m[i].extended_bool) {
				if (!strcasecmp (value, "on") || !strcasecmp (value, "yes") || !strcmp (value, "1"))
					v = TRUE;
				else if (!strcasecmp (value, "off") || !strcasecmp (value, "no"))
					v = FALSE;
				else {
					error_message = "is not a boolean";
					goto warn;
				}
			} else {
				v = _nm_utils_ascii_str_to_int64 (value, 10, 0, 1, -1);
				if (v == -1) {
					error_message = g_strerror (errno);
					goto warn;
				}
			}
			if (!nm_g_object_set_property_boolean (G_OBJECT (setting), m[i].property_name, v, NULL)) {
				error_message = "number is out of range";
				goto warn;
			}
			return;
		case G_TYPE_UINT:
			v = _nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXUINT, -1);
			if (v == -1) {
				error_message = g_strerror (errno);
				goto warn;
			}
			if (!nm_g_object_set_property_uint (G_OBJECT (setting), m[i].property_name, v, NULL)) {
				error_message = "number is out of range";
				goto warn;
			}
			return;
		default:
			nm_assert_not_reached ();
			continue;
		}

warn:
		PARSE_WARNING ("invalid %s value '%s': %s", key, value, error_message);
		return;
	}

	PARSE_WARNING ("unhandled bridge option '%s'", key);
}

static void
handle_bridging_opts (NMSetting *setting,
                      gboolean stp,
                      const char *value,
                      BridgeOptFunc func,
                      BridgeOptType opt_type)
{
	gs_free const char **items = NULL;
	const char *const *iter;

	items = nm_utils_strsplit_set (value, " ");
	for (iter = items; iter && *iter; iter++) {
		gs_strfreev char **keys = NULL;
		const char *key, *val;

		keys = g_strsplit_set (*iter, "=", 2);
		if (keys && *keys) {
			key = *keys;
			val = *(keys + 1);
			if (val && key[0] && val[0])
				func (setting, stp, key, val, opt_type);
		}
	}
}

static NMSetting *
make_bridge_setting (shvarFile *ifcfg,
                     const char *file,
                     GError **error)
{
	gs_unref_object NMSettingBridge *s_bridge = NULL;
	gs_free char *value_to_free = NULL;
	const char *value;
	gboolean stp = FALSE;
	gboolean stp_set = FALSE;

	value = svGetValueStr (ifcfg, "DEVICE", &value_to_free);
	if (!value) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "mandatory DEVICE keyword missing");
		return NULL;
	}
	nm_clear_g_free (&value_to_free);

	s_bridge = NM_SETTING_BRIDGE (nm_setting_bridge_new ());

	value = svGetValueStr (ifcfg, "BRIDGE_MACADDR", &value_to_free);
	if (value) {
		g_object_set (s_bridge, NM_SETTING_BRIDGE_MAC_ADDRESS, value, NULL);
		nm_clear_g_free (&value_to_free);
	}

	value = svGetValueStr (ifcfg, "STP", &value_to_free);
	if (value) {
		if (!strcasecmp (value, "on") || !strcasecmp (value, "yes")) {
			g_object_set (s_bridge, NM_SETTING_BRIDGE_STP, TRUE, NULL);
			stp = TRUE;
			stp_set = TRUE;
		} else if (!strcasecmp (value, "off") || !strcasecmp (value, "no")) {
			g_object_set (s_bridge, NM_SETTING_BRIDGE_STP, FALSE, NULL);
			stp_set = TRUE;
		} else
			PARSE_WARNING ("invalid STP value '%s'", value);
		nm_clear_g_free (&value_to_free);
	}

	if (!stp_set) {
		/* Missing or invalid STP property means "no" */
		g_object_set (s_bridge, NM_SETTING_BRIDGE_STP, FALSE, NULL);
	}

	value = svGetValueStr (ifcfg, "DELAY", &value_to_free);
	if (value) {
		handle_bridge_option (NM_SETTING (s_bridge), stp, "DELAY", value, BRIDGE_OPT_TYPE_MAIN);
		nm_clear_g_free (&value_to_free);
	}

	value = svGetValueStr (ifcfg, "BRIDGING_OPTS", &value_to_free);
	if (value) {
		handle_bridging_opts (NM_SETTING (s_bridge), stp, value, handle_bridge_option, BRIDGE_OPT_TYPE_OPTION);
		nm_clear_g_free (&value_to_free);
	}

	return (NMSetting *) g_steal_pointer (&s_bridge);
}

static NMConnection *
bridge_connection_from_ifcfg (const char *file,
                              shvarFile *ifcfg,
                              GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *bridge_setting = NULL;
	NMSetting *wired_setting = NULL;
	NMSetting8021x *s_8021x = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (ifcfg != NULL, NULL);

	connection = nm_simple_connection_new ();

	con_setting = make_connection_setting (file, ifcfg, NM_SETTING_BRIDGE_SETTING_NAME, NULL, _("Bridge"));
	if (!con_setting) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	bridge_setting = make_bridge_setting (ifcfg, file, error);
	if (!bridge_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, bridge_setting);

	wired_setting = make_wired_setting (ifcfg, file, &s_8021x, error);
	if (!wired_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, wired_setting);

	if (s_8021x)
		nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	return connection;
}

static NMSetting *
make_bridge_port_setting (shvarFile *ifcfg)
{
	NMSetting *s_port = NULL;
	gs_free char *value_to_free = NULL;
	const char *value;

	g_return_val_if_fail (ifcfg != NULL, FALSE);

	value = svGetValueStr (ifcfg, "BRIDGE_UUID", &value_to_free);
	if (!value)
		value = svGetValueStr (ifcfg, "BRIDGE", &value_to_free);
	if (value) {
		nm_clear_g_free (&value_to_free);

		s_port = nm_setting_bridge_port_new ();
		value = svGetValueStr (ifcfg, "BRIDGING_OPTS", &value_to_free);
		if (value) {
			handle_bridging_opts (s_port, FALSE, value, handle_bridge_option, BRIDGE_OPT_TYPE_PORT_OPTION);
			nm_clear_g_free (&value_to_free);
		}
	}

	return s_port;
}

static NMSetting *
make_team_port_setting (shvarFile *ifcfg)
{
	NMSetting *s_port = NULL;
	char *value;
	GError *error = NULL;

	value = read_team_config (ifcfg, "TEAM_PORT_CONFIG", &error);
	if (value) {
		s_port = nm_setting_team_port_new ();
		g_object_set (s_port, NM_SETTING_TEAM_PORT_CONFIG, value, NULL);
		g_free (value);
	} else if (error) {
		PARSE_WARNING ("%s", error->message);
		g_error_free (error);
	}

	return s_port;
}

static gboolean
is_bond_device (const char *name, shvarFile *parsed)
{
	g_return_val_if_fail (name != NULL, FALSE);
	g_return_val_if_fail (parsed != NULL, FALSE);

	if (svGetValueBoolean (parsed, "BONDING_MASTER", FALSE))
		return TRUE;

	return FALSE;
}

static gboolean
is_vlan_device (const char *name, shvarFile *parsed)
{
	g_return_val_if_fail (name != NULL, FALSE);
	g_return_val_if_fail (parsed != NULL, FALSE);

	if (svGetValueBoolean (parsed, "VLAN", FALSE))
		return TRUE;

	return FALSE;
}

static gboolean
is_wifi_device (const char *name, shvarFile *parsed)
{
	int ifindex;

	g_return_val_if_fail (name != NULL, FALSE);
	g_return_val_if_fail (parsed != NULL, FALSE);

	ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, name);
	if (ifindex == 0)
		return FALSE;

	return nm_platform_link_get_type (NM_PLATFORM_GET, ifindex) == NM_LINK_TYPE_WIFI;
}

static void
parse_prio_map_list (NMSettingVlan *s_vlan,
                     shvarFile *ifcfg,
                     const char *key,
                     NMVlanPriorityMap map)
{
	gs_free char *value = NULL;
	gs_free const char **list = NULL;
	const char *const *iter;
	const char *v;

	v = svGetValueStr (ifcfg, key, &value);
	if (!v)
		return;
	list = nm_utils_strsplit_set (v, ",");

	for (iter = list; iter && *iter; iter++) {
		if (!strchr (*iter, ':'))
			continue;
		if (!nm_setting_vlan_add_priority_str (s_vlan, map, *iter))
			PARSE_WARNING ("invalid %s priority map item '%s'", key, *iter);
	}
}

static NMSetting *
make_vlan_setting (shvarFile *ifcfg,
                   const char *file,
                   GError **error)
{
	gs_unref_object NMSettingVlan *s_vlan = NULL;
	gs_free char *parent = NULL;
	gs_free char *iface_name = NULL;
	gs_free char *value = NULL;
	const char *v = NULL;
	int vlan_id = -1;
	guint32 vlan_flags = 0;
	gint gvrp, reorder_hdr;

	v = svGetValueStr (ifcfg, "VLAN_ID", &value);
	if (v) {
		vlan_id = _nm_utils_ascii_str_to_int64 (v, 10, 0, 4095, -1);
		if (vlan_id == -1) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid VLAN_ID '%s'", v);
			return NULL;
		}
	}

	/* Need DEVICE if we don't have a separate VLAN_ID property */
	iface_name = svGetValueStr_cp (ifcfg, "DEVICE");
	if (!iface_name && vlan_id < 0) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "Missing DEVICE property; cannot determine VLAN ID.");
		return NULL;
	}

	s_vlan = NM_SETTING_VLAN (nm_setting_vlan_new ());

	/* Parent interface from PHYSDEV takes precedence if it exists */
	parent = svGetValueStr_cp (ifcfg, "PHYSDEV");

	if (iface_name) {
		v = strchr (iface_name, '.');
		if (v) {
			/* eth0.43; PHYSDEV is assumed from it if unknown */
			if (!parent) {
				parent = g_strndup (iface_name, v - iface_name);
				if (g_str_has_prefix (parent, "vlan")) {
					/* Like initscripts, if no PHYSDEV and we get an obviously
					 * invalid parent interface from DEVICE, fail.
					 */
					nm_clear_g_free (&parent);
				}
			}
			v++;
		} else {
			/* format like vlan43; PHYSDEV must be set */
			if (g_str_has_prefix (iface_name, "vlan"))
				v = iface_name + 4;
		}

		if (v) {
			int device_vlan_id;

			/* Grab VLAN ID from interface name; this takes precedence over the
			 * separate VLAN_ID property for backwards compat.
			 */
			device_vlan_id = _nm_utils_ascii_str_to_int64 (v, 10, 0, 4095, -1);
			if (device_vlan_id != -1)
				vlan_id = device_vlan_id;
		}
	}

	if (vlan_id < 0) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "Failed to determine VLAN ID from DEVICE or VLAN_ID.");
		return NULL;
	}
	g_object_set (s_vlan, NM_SETTING_VLAN_ID, vlan_id, NULL);

	if (parent == NULL) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "Failed to determine VLAN parent from DEVICE or PHYSDEV");
		return NULL;
	}
	g_object_set (s_vlan, NM_SETTING_VLAN_PARENT, parent, NULL);

	vlan_flags |= NM_VLAN_FLAG_REORDER_HEADERS;

	gvrp = svGetValueBoolean (ifcfg, "GVRP", -1);
	if (gvrp > 0)
		vlan_flags |= NM_VLAN_FLAG_GVRP;

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "VLAN_FLAGS", &value);
	if (v) {
		gs_free const char **strv = NULL;
		const char *const *ptr;

		strv = nm_utils_strsplit_set (v, ", ");
		for (ptr = strv; ptr && *ptr; ptr++) {
			if (nm_streq (*ptr, "GVRP") && gvrp == -1)
				vlan_flags |= NM_VLAN_FLAG_GVRP;
			if (nm_streq (*ptr, "LOOSE_BINDING"))
				vlan_flags |=  NM_VLAN_FLAG_LOOSE_BINDING;
			if (nm_streq (*ptr, "NO_REORDER_HDR"))
				vlan_flags &= ~NM_VLAN_FLAG_REORDER_HEADERS;
		}
	}

	reorder_hdr = svGetValueBoolean (ifcfg, "REORDER_HDR", -1);
	if (   reorder_hdr != -1
	    && reorder_hdr != NM_FLAGS_HAS (vlan_flags, NM_VLAN_FLAG_REORDER_HEADERS))
		PARSE_WARNING ("REORDER_HDR key is deprecated, use VLAN_FLAGS");

	if (svGetValueBoolean (ifcfg, "MVRP", FALSE))
		vlan_flags |= NM_VLAN_FLAG_MVRP;

	g_object_set (s_vlan, NM_SETTING_VLAN_FLAGS, vlan_flags, NULL);

	parse_prio_map_list (s_vlan, ifcfg, "VLAN_INGRESS_PRIORITY_MAP", NM_VLAN_INGRESS_MAP);
	parse_prio_map_list (s_vlan, ifcfg, "VLAN_EGRESS_PRIORITY_MAP", NM_VLAN_EGRESS_MAP);

	return g_steal_pointer (&s_vlan);
}

static NMConnection *
vlan_connection_from_ifcfg (const char *file,
                            shvarFile *ifcfg,
                            GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *wired_setting = NULL;
	NMSetting *vlan_setting = NULL;
	NMSetting8021x *s_8021x = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (ifcfg != NULL, NULL);

	connection = nm_simple_connection_new ();

	con_setting = make_connection_setting (file, ifcfg, NM_SETTING_VLAN_SETTING_NAME, NULL, "Vlan");
	if (!con_setting) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	vlan_setting = make_vlan_setting (ifcfg, file, error);
	if (!vlan_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, vlan_setting);

	wired_setting = make_wired_setting (ifcfg, file, &s_8021x, error);
	if (!wired_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, wired_setting);

	if (s_8021x)
		nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	return connection;
}

static NMConnection *
create_unhandled_connection (const char *filename, shvarFile *ifcfg,
                             const char *type, char **out_spec)
{
	NMConnection *connection;
	NMSetting *s_con;
	gs_free char *value = NULL;
	const char *v;

	nm_assert (out_spec && !*out_spec);

	connection = nm_simple_connection_new ();

	/* Get NAME, UUID, etc. We need to set a connection type (generic) and add
	 * an empty type-specific setting as well, to make sure it passes
	 * nm_connection_verify() later.
	 */
	s_con = make_connection_setting (filename, ifcfg, NM_SETTING_GENERIC_SETTING_NAME,
	                                 NULL, NULL);
	nm_connection_add_setting (connection, s_con);

	nm_connection_add_setting (connection, nm_setting_generic_new ());

	/* Get a spec */
	v = svGetValueStr (ifcfg, "HWADDR", &value);
	if (v) {
		gs_free char *lower = g_ascii_strdown (v, -1);

		*out_spec = g_strdup_printf ("%s:mac:%s", type, lower);
		return connection;
	}

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "SUBCHANNELS", &value);
	if (v) {
		*out_spec = g_strdup_printf ("%s:s390-subchannels:%s", type, v);
		return connection;
	}

	nm_clear_g_free (&value);
	v = svGetValueStr (ifcfg, "DEVICE", &value);
	if (v) {
		*out_spec = g_strdup_printf ("%s:interface-name:%s", type, v);
		return connection;
	}

	g_object_unref (connection);
	return NULL;
}

static void
check_dns_search_domains (shvarFile *ifcfg, NMSetting *s_ip4, NMSetting *s_ip6)
{
	if (!s_ip6)
		return;

	/* If there is no IPv4 config or it doesn't contain DNS searches,
	 * read DOMAIN and put the domains into IPv6.
	 */
	if (   !s_ip4
	    || nm_setting_ip_config_get_num_dns_searches (NM_SETTING_IP_CONFIG (s_ip4)) == 0) {
		/* DNS searches */
		gs_free char *value = NULL;
		const char *v;

		v = svGetValueStr (ifcfg, "DOMAIN", &value);
		if (v) {
			gs_free const char **searches = NULL;
			const char *const *item;

			searches = nm_utils_strsplit_set (v, " ");
			if (searches) {
				for (item = searches; *item; item++) {
					if (!nm_setting_ip_config_add_dns_search (NM_SETTING_IP_CONFIG (s_ip6), *item))
						PARSE_WARNING ("duplicate DNS domain '%s'", *item);
				}
			}
		}
	}
}

static NMConnection *
connection_from_file_full (const char *filename,
                           const char *network_file,  /* for unit tests only */
                           const char *test_type,     /* for unit tests only */
                           char **out_unhandled,
                           GError **error,
                           gboolean *out_ignore_error)
{
	nm_auto_shvar_file_close shvarFile *parsed = NULL;
	nm_auto_shvar_file_close shvarFile *network_ifcfg = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_free char *type = NULL;
	char *devtype, *bootproto;
	NMSetting *s_ip4, *s_ip6, *s_tc, *s_proxy, *s_port, *s_dcb = NULL, *s_user;
	const char *ifcfg_name = NULL;
	gboolean has_ip4_defroute = FALSE;
	gboolean has_complex_routes_v4;
	gboolean has_complex_routes_v6;

	g_return_val_if_fail (filename != NULL, NULL);
	g_return_val_if_fail (out_unhandled && !*out_unhandled, NULL);

	NM_SET_OUT (out_ignore_error, FALSE);

	/* Non-NULL only for unit tests; normally use /etc/sysconfig/network */
	if (!network_file)
		network_file = SYSCONFDIR "/sysconfig/network";

	ifcfg_name = utils_get_ifcfg_name (filename, TRUE);
	if (!ifcfg_name) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Ignoring connection '%s' because it's not an ifcfg file.", filename);
		return NULL;
	}

	parsed = svOpenFile (filename, error);
	if (!parsed)
		return NULL;

	network_ifcfg = svOpenFile (network_file, NULL);

	if (!svGetValueBoolean (parsed, "NM_CONTROLLED", TRUE)) {
		connection = create_unhandled_connection (filename, parsed, "unmanaged", out_unhandled);
		if (!connection) {
			NM_SET_OUT (out_ignore_error, TRUE);
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "NM_CONTROLLED was false but device was not uniquely identified; device will be managed");
		}
		return g_steal_pointer (&connection);
	}

	/* iBFT is handled by the iBFT settings plugin */
	bootproto = svGetValueStr_cp (parsed, "BOOTPROTO");
	if (bootproto && !g_ascii_strcasecmp (bootproto, "ibft")) {
		NM_SET_OUT (out_ignore_error, TRUE);
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Ignoring iBFT configuration");
		g_free (bootproto);
		return NULL;
	}
	g_free (bootproto);

	devtype = svGetValueStr_cp (parsed, "DEVICETYPE");
	if (devtype) {
		if (!strcasecmp (devtype, TYPE_TEAM))
			type = g_strdup (TYPE_TEAM);
		else if (!strcasecmp (devtype, TYPE_TEAM_PORT)) {
			gs_free char *device = NULL;

			type = svGetValueStr_cp (parsed, "TYPE");
			device = svGetValueStr_cp (parsed, "DEVICE");

			if (type) {
				/* nothing to do */
			} else if (device && is_vlan_device (device, parsed))
				type = g_strdup (TYPE_VLAN);
			else
				type = g_strdup (TYPE_ETHERNET);
		}
		g_free (devtype);
	}
	if (!type) {
		gs_free char *t = NULL;

		/* Team and TeamPort types are also accepted by the mere
		 * presence of TEAM_CONFIG/TEAM_MASTER. They don't require
		 * DEVICETYPE. */
		t = svGetValueStr_cp (parsed, "TEAM_CONFIG");
		if (t)
			type = g_strdup (TYPE_TEAM);
	}

	if (!type)
		type = svGetValueStr_cp (parsed, "TYPE");

	if (!type) {
		gs_free char *tmp = NULL;
		char *device;

		if ((tmp = svGetValueStr_cp (parsed, "IPV6TUNNELIPV4"))) {
			NM_SET_OUT (out_ignore_error, TRUE);
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Ignoring unsupported connection due to IPV6TUNNELIPV4");
			return NULL;
		}

		device = svGetValueStr_cp (parsed, "DEVICE");
		if (!device) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "File '%s' had neither TYPE nor DEVICE keys.", filename);
			return NULL;
		}

		if (!strcmp (device, "lo")) {
			NM_SET_OUT (out_ignore_error, TRUE);
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Ignoring loopback device config.");
			g_free (device);
			return NULL;
		}

		if (!test_type) {
			if (is_bond_device (device, parsed))
				type = g_strdup (TYPE_BOND);
			else if (is_vlan_device (device, parsed))
				type = g_strdup (TYPE_VLAN);
			else if (is_wifi_device (device, parsed))
				type = g_strdup (TYPE_WIRELESS);
			else {
				gs_free char *p_path = NULL;
				char *p_device;
				gsize i;

				/* network-functions detects DEVICETYPE based on the ifcfg-* name and the existence
				 * of a ifup script:
				 *    [ -z "$DEVICETYPE" ] && DEVICETYPE=$(echo ${DEVICE} | sed "s/[0-9]*$//")
				 * later...
				 *    OTHERSCRIPT="/etc/sysconfig/network-scripts/ifup-${DEVICETYPE}"
				 * */
#define IFUP_PATH_PREFIX "/etc/sysconfig/network-scripts/ifup-"
				i = strlen (device);
				p_path = g_malloc (NM_STRLEN (IFUP_PATH_PREFIX) + i + 1);
				p_device = &p_path[NM_STRLEN (IFUP_PATH_PREFIX)];
				memcpy (p_device, device, i + 1);

				/* strip trailing numbers */
				while (i >= 1) {
					i--;
					if (p_device[i] < '0' || p_device[i] > '9')
						break;
					p_device[i] = '\0';
				}

				if (nm_streq (p_device, "eth"))
					type = g_strdup (TYPE_ETHERNET);
				else if (nm_streq (p_device, "wireless"))
					type = g_strdup (TYPE_WIRELESS);
				else if (p_device[0]) {
					memcpy (p_path, IFUP_PATH_PREFIX, NM_STRLEN (IFUP_PATH_PREFIX));
					if (access (p_path, X_OK) == 0) {
						/* for all other types, this is not something we want to handle. */
						NM_SET_OUT (out_ignore_error, TRUE);
						g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
						             "Ignore script for unknown device type which has a matching %s script",
						             p_path);
						return NULL;
					}
				}

				if (!type)
					type = g_strdup (TYPE_ETHERNET);
			}
		} else {
			/* For the unit tests, there won't necessarily be any
			 * adapters of the connection's type in the system so the
			 * type can't be tested with ioctls.
			 */
			type = g_strdup (test_type);
		}

		g_free (device);
	} else {
		/* Check for IBM s390 CTC devices and call them Ethernet */
		if (g_strcmp0 (type, "CTC") == 0) {
			g_free (type);
			type = g_strdup (TYPE_ETHERNET);
		}
	}

	if (nm_streq0 (type, TYPE_ETHERNET)) {
		gs_free char *bond_options = NULL;

		if (svGetValueStr (parsed, "BONDING_OPTS", &bond_options)) {
			/* initscripts consider these as bond masters */
			g_free (type);
			type = g_strdup (TYPE_BOND);
		}
	}

	if (svGetValueBoolean (parsed, "BONDING_MASTER", FALSE) &&
	    strcasecmp (type, TYPE_BOND)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "BONDING_MASTER=yes key only allowed in TYPE=bond connections");
		return NULL;
	}

	/* Construct the connection */
	if (!strcasecmp (type, TYPE_ETHERNET))
		connection = wired_connection_from_ifcfg (filename, parsed, error);
	else if (!strcasecmp (type, TYPE_WIRELESS))
		connection = wireless_connection_from_ifcfg (filename, parsed, error);
	else if (!strcasecmp (type, TYPE_INFINIBAND))
		connection = infiniband_connection_from_ifcfg (filename, parsed, error);
	else if (!strcasecmp (type, TYPE_BOND))
		connection = bond_connection_from_ifcfg (filename, parsed, error);
	else if (!strcasecmp (type, TYPE_TEAM))
		connection = team_connection_from_ifcfg (filename, parsed, error);
	else if (!strcasecmp (type, TYPE_VLAN))
		connection = vlan_connection_from_ifcfg (filename, parsed, error);
	else if (!strcasecmp (type, TYPE_BRIDGE))
		connection = bridge_connection_from_ifcfg (filename, parsed, error);
	else {
		connection = create_unhandled_connection (filename, parsed, "unrecognized", out_unhandled);
		if (!connection) {
			PARSE_WARNING ("connection type was unrecognized but device was not uniquely identified; device may be managed");
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Failed to read unrecognized connection");
		}
		return g_steal_pointer (&connection);
	}

	if (!connection)
		return NULL;

	has_complex_routes_v4 = utils_has_complex_routes (filename, AF_INET);
	has_complex_routes_v6 = utils_has_complex_routes (filename, AF_INET6);

	if (has_complex_routes_v4 || has_complex_routes_v6) {
		if (has_complex_routes_v4 && !has_complex_routes_v6)
			PARSE_WARNING ("'rule-' file is present; you will need to use a dispatcher script to apply these routes");
		else if (has_complex_routes_v6 && !has_complex_routes_v4)
			PARSE_WARNING ("'rule6-' file is present; you will need to use a dispatcher script to apply these routes");
		else
			PARSE_WARNING ("'rule-' and 'rule6-' files are present; you will need to use a dispatcher script to apply these routes");
	}

	s_ip6 = make_ip6_setting (parsed,
	                          network_ifcfg,
	                          !has_complex_routes_v4 && !has_complex_routes_v6,
	                          error);
	if (!s_ip6)
		return NULL;
	else
		nm_connection_add_setting (connection, s_ip6);

	s_ip4 = make_ip4_setting (parsed,
	                          network_ifcfg,
	                          !has_complex_routes_v4 && !has_complex_routes_v6,
	                          &has_ip4_defroute,
	                          error);
	if (!s_ip4)
		return NULL;
	else {
		read_aliases (NM_SETTING_IP_CONFIG (s_ip4),
		              !has_ip4_defroute && !nm_setting_ip_config_get_gateway (NM_SETTING_IP_CONFIG (s_ip4)),
		              filename);
		nm_connection_add_setting (connection, s_ip4);
	}

	s_tc = make_tc_setting (parsed);
	if (s_tc)
		nm_connection_add_setting (connection, s_tc);

	/* For backwards compatibility, if IPv4 is disabled or the
	 * config fails for some reason, we read DOMAIN and put the
	 * values into IPv6 config instead of IPv4.
	 */
	check_dns_search_domains (parsed, s_ip4, s_ip6);

	s_proxy = make_proxy_setting (parsed);
	if (s_proxy)
		nm_connection_add_setting (connection, s_proxy);

	s_user = make_user_setting (parsed);
	if (s_user)
		nm_connection_add_setting (connection, s_user);

	/* Bridge port? */
	s_port = make_bridge_port_setting (parsed);
	if (s_port)
		nm_connection_add_setting (connection, s_port);

	/* Team port? */
	s_port = make_team_port_setting (parsed);
	if (s_port)
		nm_connection_add_setting (connection, s_port);

	if (!make_dcb_setting (parsed, &s_dcb, error))
		return NULL;
	if (s_dcb)
		nm_connection_add_setting (connection, s_dcb);

	if (!nm_connection_normalize (connection, NULL, NULL, error))
		return NULL;

	return g_steal_pointer (&connection);
}

NMConnection *
connection_from_file (const char *filename,
                      char **out_unhandled,
                      GError **error,
                      gboolean *out_ignore_error)
{
	return connection_from_file_full (filename, NULL, NULL,
	                                  out_unhandled,
	                                  error,
	                                  out_ignore_error);
}

NMConnection *
nmtst_connection_from_file (const char *filename,
                            const char *network_file,
                            const char *test_type,
                            char **out_unhandled,
                            GError **error)
{
	return connection_from_file_full (filename,
	                                  network_file,
	                                  test_type,
	                                  out_unhandled,
	                                  error,
	                                  NULL);
}

guint
devtimeout_from_file (const char *filename)
{
	shvarFile *ifcfg;
	guint devtimeout;

	g_return_val_if_fail (filename != NULL, 0);

	ifcfg = svOpenFile (filename, NULL);
	if (!ifcfg)
		return 0;

	devtimeout = svGetValueInt64 (ifcfg, "DEVTIMEOUT", 10, 0, G_MAXUINT, 0);
	svCloseFile (ifcfg);
	return devtimeout;
}
