/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
 */

/**
 * SECTION:nm-editor-bindings
 * @short_description: #GBinding-based NM connection editor helpers
 *
 * nm-editor-bindings contains helper functions to bind NMSettings objects
 * to connection editing widgets. The goal is that this should eventually be
 * shared between nmtui, nm-connection-editor, and gnome-control-center.
 */

#include "nm-default.h"

#include "nm-editor-bindings.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>

static void
value_transform_string_int (const GValue *src_value,
                            GValue       *dest_value)
{
	long val;
	char *end;

	val = strtol (g_value_get_string (src_value), &end, 10);
	if (val < G_MININT || val > G_MAXINT || *end)
		return;

	g_value_set_int (dest_value, (int) val);
}

static void
value_transform_string_uint (const GValue *src_value,
                             GValue       *dest_value)
{
	long val;
	char *end;

	val = strtol (g_value_get_string (src_value), &end, 10);
	if (val < 0 || val > G_MAXUINT || *end)
		return;

	g_value_set_uint (dest_value, (int) val);
}

void
nm_editor_bindings_init (void)
{
	/* glib registers number -> string, but not string -> number */
	g_value_register_transform_func (G_TYPE_STRING, G_TYPE_INT, value_transform_string_int);
	g_value_register_transform_func (G_TYPE_STRING, G_TYPE_UINT, value_transform_string_uint);
}

static gboolean
ip_addresses_with_prefix_to_strv (GBinding     *binding,
                                  const GValue *source_value,
                                  GValue       *target_value,
                                  gpointer      user_data)
{
	GPtrArray *addrs;
	NMIPAddress *addr;
	const char *addrstr;
	guint32 prefix;
	char **strings;
	int i;

	addrs = g_value_get_boxed (source_value);
	strings = g_new0 (char *, addrs->len + 1);

	for (i = 0; i < addrs->len; i++) {
		addr = addrs->pdata[i];
		addrstr = nm_ip_address_get_address (addr);
		prefix = nm_ip_address_get_prefix (addr);

		if (addrstr)
			strings[i] = g_strdup_printf ("%s/%d", addrstr, (int) prefix);
		else
			strings[i] = g_strdup ("");
	}

	g_value_take_boxed (target_value, strings);
	return TRUE;
}

static gboolean
ip_addresses_with_prefix_from_strv (GBinding     *binding,
                                    const GValue *source_value,
                                    GValue       *target_value,
                                    gpointer      user_data)
{
	int addr_family = GPOINTER_TO_INT (user_data);
	char **strings;
	GPtrArray *addrs;
	NMIPAddress *addr;
	char *addrstr;
	int prefix;
	int i;

	strings = g_value_get_boxed (source_value);
	/* Fetch the original property value, so as to preserve their extra attributes */
	g_object_get (g_binding_get_source (binding),
	              g_binding_get_source_property (binding), &addrs,
	              NULL);

	for (i = 0; strings[i]; i++) {
		if (i >= addrs->len) {
			if (addr_family == AF_INET)
				addr = nm_ip_address_new (AF_INET, "0.0.0.0", 32, NULL);
			else
				addr = nm_ip_address_new (AF_INET6, "::", 128, NULL);
			g_ptr_array_add (addrs, addr);
		} else
			addr = addrs->pdata[i];

		if (!nm_utils_parse_inaddr_prefix (addr_family, strings[i], &addrstr, &prefix)) {
			g_ptr_array_unref (addrs);
			return FALSE;
		}

		if (prefix == -1) {
			if (addr_family == AF_INET) {
				in_addr_t v4;

				inet_pton (addr_family, addrstr, &v4);
				if (nm_utils_ip_is_site_local (AF_INET, &v4))
					prefix = nm_utils_ip4_get_default_prefix (v4);
				else
					prefix = 32;
			} else
				prefix = 64;
		}

		nm_ip_address_set_address (addr, addrstr);
		nm_ip_address_set_prefix (addr, prefix);
		g_free (addrstr);
	}

	g_ptr_array_set_size (addrs, i);
	g_value_take_boxed (target_value, addrs);
	return TRUE;
}

/**
 * nm_editor_bind_ip_addresses_with_prefix_to_strv:
 * @addr_family: the IP address family
 * @source: the source object (eg, an #NMSettingIP4Config)
 * @source_property: the property on @source to bind (eg,
 *   %NM_SETTING_IP4_CONFIG_ADDRESSES)
 * @target: the target object (eg, an #NmtAddressList)
 * @target_property: the property on @target to bind
 *   (eg, "strings")
 * @flags: %GBindingFlags
 *
 * Binds the #GPtrArray-of-#NMIPAddress property @source_property on @source to
 * the %G_TYPE_STRV property @target_property on @target.
 *
 * Each #NMIPAddress in @source_property will be converted to a string of the
 * form "ip.ad.dr.ess/prefix" or "ip:ad:dr:ess/prefix" in @target_property (and
 * vice versa if %G_BINDING_BIDIRECTIONAL) is specified.
 */
void
nm_editor_bind_ip_addresses_with_prefix_to_strv (int            addr_family,
                                                 gpointer       source,
                                                 const char    *source_property,
                                                 gpointer       target,
                                                 const char    *target_property,
                                                 GBindingFlags  flags)
{
	g_object_bind_property_full (source, source_property,
	                             target, target_property,
	                             flags,
	                             ip_addresses_with_prefix_to_strv,
	                             ip_addresses_with_prefix_from_strv,
	                             GINT_TO_POINTER (addr_family), NULL);
}

static gboolean
ip_addresses_check_and_copy (GBinding     *binding,
                             const GValue *source_value,
                             GValue       *target_value,
                             gpointer      user_data)
{
	int addr_family = GPOINTER_TO_INT (user_data);
	char **strings;
	int i;

	strings = g_value_get_boxed (source_value);

	for (i = 0; strings[i]; i++) {
		if (!nm_utils_ipaddr_valid (addr_family, strings[i]))
			return FALSE;
	}

	g_value_set_boxed (target_value, strings);
	return TRUE;
}

/**
 * nm_editor_bind_ip_addresses_to_strv:
 * @addr_family: the IP address family
 * @source: the source object (eg, an #NMSettingIP4Config)
 * @source_property: the property on @source to bind (eg,
 *   %NM_SETTING_IP4_CONFIG_DNS)
 * @target: the target object (eg, an #NmtAddressList)
 * @target_property: the property on @target to bind
 *   (eg, "strings")
 * @flags: %GBindingFlags
 *
 * Binds the %G_TYPE_STRV property @source_property on @source to the
 * %G_TYPE_STRV property @target_property on @target, verifying that
 * each string is a valid address of type @addr_family when copying.
 */
void
nm_editor_bind_ip_addresses_to_strv (int            addr_family,
                                     gpointer       source,
                                     const char    *source_property,
                                     gpointer       target,
                                     const char    *target_property,
                                     GBindingFlags  flags)
{
	g_object_bind_property_full (source, source_property,
	                             target, target_property,
	                             flags,
	                             ip_addresses_check_and_copy,
	                             ip_addresses_check_and_copy,
	                             GINT_TO_POINTER (addr_family), NULL);
}

static gboolean
ip_gateway_to_string (GBinding     *binding,
                      const GValue *source_value,
                      GValue       *target_value,
                      gpointer      user_data)
{
	g_value_set_string (target_value, g_value_get_string (source_value));
	return TRUE;
}

static gboolean
ip_gateway_from_string (GBinding     *binding,
                        const GValue *source_value,
                        GValue       *target_value,
                        gpointer      user_data)
{
	int addr_family = GPOINTER_TO_INT (user_data);
	const char *gateway;

	gateway = g_value_get_string (source_value);
	if (gateway && !nm_utils_ipaddr_valid (addr_family, gateway))
		gateway = NULL;

	g_value_set_string (target_value, gateway);
	return TRUE;
}

static gboolean
ip_addresses_to_gateway (GBinding     *binding,
                         const GValue *source_value,
                         GValue       *target_value,
                         gpointer      user_data)
{
	GPtrArray *addrs;

	addrs = g_value_get_boxed (source_value);
	if (addrs->len == 0) {
		g_value_set_string (target_value, NULL);
		return TRUE;
	} else
		return FALSE;
}

static gboolean
ip_addresses_to_sensitivity (GBinding     *binding,
                             const GValue *source_value,
                             GValue       *target_value,
                             gpointer      user_data)
{
	GPtrArray *addrs;

	addrs = g_value_get_boxed (source_value);
	g_value_set_boolean (target_value, addrs->len != 0);
	return TRUE;
}

/**
 * nm_editor_bind_ip_gateway_to_string:
 * @addr_family: the IP address family
 * @source: the source #NMSettingIPConfig
 * @target: the target object (eg, an #NmtIPEntry)
 * @target_property: the property on @target to bind (eg, "text")
 * @target_sensitive_property: the "sensitivity" property on @target to bind
 * @flags: %GBindingFlags
 *
 * Binds the #NMSettingIPConfig:gateway property on @source to the
 * %G_TYPE_STRING property @target_property and %G_TYPE_BOOLEAN property
 * @target_sensitive_property on @target, also taking the
 * #NMSettingIPConfig:addresses property on @source into account.
 *
 * In particular, if @source has no static IP addresses, then @target_property
 * will be set to "" and @target_sensitive_property will be set to %FALSE.
 *
 * If @source has at least one static IP address, then
 * @target_sensitive_property will be set to %TRUE, @target_property will be
 * initialized from @source's #NMSettingIPConfig:gateway, and @source will be
 * updated with the value of @target_property whenever it contains a valid IP
 * address.
 */
void
nm_editor_bind_ip_gateway_to_string (int                addr_family,
                                     NMSettingIPConfig *source,
                                     gpointer           target,
                                     const char        *target_property,
                                     const char        *target_sensitive_property,
                                     GBindingFlags      flags)
{
	g_object_bind_property_full (source, "gateway",
	                             target, target_property,
	                             flags,
	                             ip_gateway_to_string,
	                             ip_gateway_from_string,
	                             GINT_TO_POINTER (addr_family), NULL);
	g_object_bind_property_full (source, "addresses",
	                             source, "gateway",
	                             (flags & G_BINDING_SYNC_CREATE),
	                             ip_addresses_to_gateway,
	                             NULL,
	                             NULL, NULL);
	g_object_bind_property_full (source, "addresses",
	                             target, target_sensitive_property,
	                             (flags & G_BINDING_SYNC_CREATE),
	                             ip_addresses_to_sensitivity,
	                             NULL,
	                             NULL, NULL);
}

static gboolean
ip_route_transform_to_dest_string (GBinding     *binding,
                                   const GValue *source_value,
                                   GValue       *target_value,
                                   gpointer      user_data)
{
	NMIPRoute *route;
	const char *addrstr;
	char *string;

	route = g_value_get_boxed (source_value);
	if (route)
		addrstr = nm_ip_route_get_dest (route);
	else
		addrstr = NULL;

	if (addrstr) {
		string = g_strdup_printf ("%s/%d", addrstr, (int) nm_ip_route_get_prefix (route));
		g_value_take_string (target_value, string);
	} else
		g_value_set_string (target_value, "");
	return TRUE;
}

static gboolean
ip_route_transform_to_next_hop_string (GBinding     *binding,
                                       const GValue *source_value,
                                       GValue       *target_value,
                                       gpointer      user_data)
{
	NMIPRoute *route;
	const char *addrstr;

	route = g_value_get_boxed (source_value);
	if (route) {
		addrstr = nm_ip_route_get_next_hop (route);
		if (!addrstr)
			addrstr = "";
	} else
		addrstr = "";

	g_value_set_string (target_value, addrstr);
	return TRUE;
}

static gboolean
ip_route_transform_to_metric_string (GBinding     *binding,
                                     const GValue *source_value,
                                     GValue       *target_value,
                                     gpointer      user_data)
{
	NMIPRoute *route;
	char *string;

	route = g_value_get_boxed (source_value);
	if (route && nm_ip_route_get_dest (route) && nm_ip_route_get_metric (route) != -1) {
		string = g_strdup_printf ("%lu", (gulong) nm_ip_route_get_metric (route));
		g_value_take_string (target_value, string);
	} else
		g_value_set_string (target_value, "");
	return TRUE;
}

static gboolean
ip_route_transform_from_dest_string (GBinding     *binding,
                                     const GValue *source_value,
                                     GValue       *target_value,
                                     gpointer      user_data)
{
	int addr_family = GPOINTER_TO_INT (user_data);
	NMIPRoute *route;
	const char *text;
	char *addrstr;
	int prefix;

	text = g_value_get_string (source_value);
	if (!nm_utils_parse_inaddr_prefix (addr_family, text, &addrstr, &prefix))
		return FALSE;

	/* Fetch the original property value */
	g_object_get (g_binding_get_source (binding),
	              g_binding_get_source_property (binding), &route,
	              NULL);

	if (prefix == -1) {
		if (addr_family == AF_INET) {
			in_addr_t v4;

			inet_pton (addr_family, addrstr, &v4);
			if (nm_utils_ip_is_site_local (AF_INET, &v4)) {
				prefix = nm_utils_ip4_get_default_prefix (v4);
				if (v4 & (~nm_utils_ip4_prefix_to_netmask (prefix)))
					prefix = 32;
			} else
				prefix = 32;
		} else
			prefix = 64;
	}

	nm_ip_route_set_dest (route, addrstr);
	nm_ip_route_set_prefix (route, prefix);
	g_free (addrstr);

	g_value_take_boxed (target_value, route);
	return TRUE;
}

static gboolean
ip_route_transform_from_next_hop_string (GBinding     *binding,
                                         const GValue *source_value,
                                         GValue       *target_value,
                                         gpointer      user_data)
{
	int addr_family = GPOINTER_TO_INT (user_data);
	NMIPRoute *route;
	const char *text;

	text = g_value_get_string (source_value);
	if (*text) {
		if (!nm_utils_ipaddr_valid (addr_family, text))
			return FALSE;
	} else
		text = NULL;

	/* Fetch the original property value */
	g_object_get (g_binding_get_source (binding),
	              g_binding_get_source_property (binding), &route,
	              NULL);

	nm_ip_route_set_next_hop (route, text);

	g_value_take_boxed (target_value, route);
	return TRUE;
}

static gboolean
ip_route_transform_from_metric_string (GBinding     *binding,
                                       const GValue *source_value,
                                       GValue       *target_value,
                                       gpointer      user_data)
{
	NMIPRoute *route;
	const char *text;
	gint64 metric;

	text = g_value_get_string (source_value);
	metric = _nm_utils_ascii_str_to_int64 (text, 10, 0, G_MAXUINT32, -1);

	/* Fetch the original property value */
	g_object_get (g_binding_get_source (binding),
	              g_binding_get_source_property (binding), &route,
	              NULL);

	nm_ip_route_set_metric (route, metric);

	g_value_take_boxed (target_value, route);
	return TRUE;
}

/**
 * nm_editor_bind_ip_route_to_strings:
 * @addr_family: the IP address family
 * @source: the source object
 * @source_property: the source property
 * @dest_target: the target object for the route's destination
 * @dest_target_property: the property on @dest_target
 * @next_hop_target: the target object for the route's next hop
 * @next_hop_target_property: the property on @next_hop_target
 * @metric_target: the target object for the route's metric
 * @metric_target_property: the property on @metric_target
 * @flags: %GBindingFlags
 *
 * Binds the #NMIPRoute-valued property @source_property on @source to the
 * three indicated string-valued target properties (and vice versa if
 * %G_BINDING_BIDIRECTIONAL is specified).
 *
 * @dest_target_property should be an "address/prefix" string, as with
 * nm_editor_bind_ip4_addresses_with_prefix_to_strv(). @next_hop_target_property
 * is a plain IP address, and @metric_target_property is a number.
 */
void
nm_editor_bind_ip_route_to_strings (int            addr_family,
                                    gpointer       source,
                                    const char    *source_property,
                                    gpointer       dest_target,
                                    const char    *dest_target_property,
                                    gpointer       next_hop_target,
                                    const char    *next_hop_target_property,
                                    gpointer       metric_target,
                                    const char    *metric_target_property,
                                    GBindingFlags  flags)
{
	g_object_bind_property_full (source, source_property,
	                             dest_target, dest_target_property,
	                             flags,
	                             ip_route_transform_to_dest_string,
	                             ip_route_transform_from_dest_string,
	                             GINT_TO_POINTER (addr_family), NULL);
	g_object_bind_property_full (source, source_property,
	                             next_hop_target, next_hop_target_property,
	                             flags,
	                             ip_route_transform_to_next_hop_string,
	                             ip_route_transform_from_next_hop_string,
	                             GINT_TO_POINTER (addr_family), NULL);
	g_object_bind_property_full (source, source_property,
	                             metric_target, metric_target_property,
	                             flags,
	                             ip_route_transform_to_metric_string,
	                             ip_route_transform_from_metric_string,
	                             GINT_TO_POINTER (addr_family), NULL);
}

/* Wireless security method binding */
typedef struct {
	NMConnection *connection;
	NMSettingWirelessSecurity *s_wsec;
	gboolean s_wsec_in_use;

	GObject *target;
	char *target_property;

	gboolean updating;
} NMEditorWirelessSecurityMethodBinding;

static const char *
get_security_type (NMEditorWirelessSecurityMethodBinding *binding)
{
	const char *key_mgmt, *auth_alg;

	if (!binding->s_wsec_in_use)
		return "none";

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (binding->s_wsec);
	auth_alg = nm_setting_wireless_security_get_auth_alg (binding->s_wsec);

	/* No IEEE 802.1x */
	if (!strcmp (key_mgmt, "none")) {
		NMWepKeyType wep_type = nm_setting_wireless_security_get_wep_key_type (binding->s_wsec);

		if (wep_type == NM_WEP_KEY_TYPE_KEY)
			return "wep-key";
		else
			return "wep-passphrase";
	}

	if (!strcmp (key_mgmt, "ieee8021x")) {
		if (auth_alg && !strcmp (auth_alg, "leap"))
			return "leap";
		return "dynamic-wep";
	}

	if (   !strcmp (key_mgmt, "wpa-none")
	    || !strcmp (key_mgmt, "wpa-psk"))
		return "wpa-personal";

	if (!strcmp (key_mgmt, "wpa-eap"))
		return "wpa-enterprise";

	return NULL;
}

static void
wireless_security_changed (GObject    *object,
                           GParamSpec *pspec,
                           gpointer    user_data)
{
	NMEditorWirelessSecurityMethodBinding *binding = user_data;

	if (binding->updating)
		return;

	binding->updating = TRUE;
	g_object_set (binding->target,
	              binding->target_property, get_security_type (binding),
	              NULL);
	binding->updating = FALSE;
}

static void
wireless_connection_changed (NMConnection *connection,
                             gpointer      user_data)
{
	NMEditorWirelessSecurityMethodBinding *binding = user_data;
	NMSettingWirelessSecurity *s_wsec;

	if (binding->updating)
		return;

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (   (s_wsec && binding->s_wsec_in_use)
	    || (!s_wsec && !binding->s_wsec_in_use))
		return;

	binding->s_wsec_in_use = !binding->s_wsec_in_use;
	wireless_security_changed (NULL, NULL, binding);
}

static void
wireless_security_target_changed (GObject    *object,
                                  GParamSpec *pspec,
                                  gpointer    user_data)
{
	NMEditorWirelessSecurityMethodBinding *binding = user_data;
	char *method;

	if (binding->updating)
		return;

	g_object_get (binding->target,
	              binding->target_property, &method,
	              NULL);

	binding->updating = TRUE;

	if (!strcmp (method, "none")) {
		if (!binding->s_wsec_in_use)
			return;
		binding->s_wsec_in_use = FALSE;
		nm_connection_remove_setting (binding->connection, NM_TYPE_SETTING_WIRELESS_SECURITY);

		binding->updating = FALSE;
		return;
	}

	if (!binding->s_wsec_in_use) {
		binding->s_wsec_in_use = TRUE;
		nm_connection_add_setting (binding->connection, NM_SETTING (binding->s_wsec));
	}

	if (!strcmp (method, "wep-key")) {
		g_object_set (binding->s_wsec,
		              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none",
		              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open",
		              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, NM_WEP_KEY_TYPE_KEY,
		              NULL);
	} else if (!strcmp (method, "wep-passphrase")) {
		g_object_set (binding->s_wsec,
		              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none",
		              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open",
		              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, NM_WEP_KEY_TYPE_PASSPHRASE,
		              NULL);
	} else if (!strcmp (method, "leap")) {
		g_object_set (binding->s_wsec,
		              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x",
		              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap",
		              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, NM_WEP_KEY_TYPE_UNKNOWN,
		              NULL);
	} else if (!strcmp (method, "dynamic-wep")) {
		g_object_set (binding->s_wsec,
		              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x",
		              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open",
		              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, NM_WEP_KEY_TYPE_UNKNOWN,
		              NULL);
	} else if (!strcmp (method, "wpa-personal")) {
		g_object_set (binding->s_wsec,
		              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
		              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, NULL,
		              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, NM_WEP_KEY_TYPE_UNKNOWN,
		              NULL);
	} else if (!strcmp (method, "wpa-enterprise")) {
		g_object_set (binding->s_wsec,
		              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap",
		              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, NULL,
		              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, NM_WEP_KEY_TYPE_UNKNOWN,
		              NULL);
	} else
		g_warn_if_reached ();

	binding->updating = FALSE;
}

static void
wireless_security_target_destroyed (gpointer  user_data,
                                    GObject  *ex_target)
{
	NMEditorWirelessSecurityMethodBinding *binding = user_data;

	g_signal_handlers_disconnect_by_func (binding->s_wsec, G_CALLBACK (wireless_security_changed), binding);
	g_object_unref (binding->s_wsec);
	g_object_unref (binding->connection);

	g_free (binding->target_property);

	g_slice_free (NMEditorWirelessSecurityMethodBinding, binding);
}

/**
 * nm_editor_bind_wireless_security_method:
 * @connection: an #NMConnection
 * @s_wsec: an #NMSettingWirelessSecurity
 * @target: the target widget
 * @target_property: the string-valued property on @target to bind
 * @flags: %GBindingFlags
 *
 * Binds the wireless security method on @connection to
 * @target_property on @target (and vice versa if
 * %G_BINDING_BIDIRECTIONAL).
 *
 * @target_property will be of the values "none", "wpa-personal",
 * "wpa-enterprise", "wep-key", "wep-passphrase", "dynamic-wep", or
 * "leap".
 *
 * If binding bidirectionally, @s_wsec will be automatically added to
 * or removed from @connection as needed when @target_property
 * changes.
 */
void
nm_editor_bind_wireless_security_method (NMConnection              *connection,
                                         NMSettingWirelessSecurity *s_wsec,
                                         gpointer                   target,
                                         const char                *target_property,
                                         GBindingFlags              flags)
{
	NMEditorWirelessSecurityMethodBinding *binding;
	char *notify;

	binding = g_slice_new0 (NMEditorWirelessSecurityMethodBinding);

	binding->target = target;
	binding->target_property = g_strdup (target_property);
	if (flags & G_BINDING_BIDIRECTIONAL) {
		notify = g_strdup_printf ("notify::%s", target_property);
		g_signal_connect (target, notify, G_CALLBACK (wireless_security_target_changed), binding);
		g_free (notify);
	}
	g_object_weak_ref (target, wireless_security_target_destroyed, binding);

	binding->connection = g_object_ref (connection);
	g_signal_connect (connection, NM_CONNECTION_CHANGED,
	                  G_CALLBACK (wireless_connection_changed), binding);
	binding->s_wsec_in_use = (nm_connection_get_setting_wireless_security (connection) != NULL);

	binding->s_wsec = g_object_ref (s_wsec);
	g_signal_connect (s_wsec, "notify::" NM_SETTING_WIRELESS_SECURITY_KEY_MGMT,
	                  G_CALLBACK (wireless_security_changed), binding);
	g_signal_connect (s_wsec, "notify::" NM_SETTING_WIRELESS_SECURITY_AUTH_ALG,
	                  G_CALLBACK (wireless_security_changed), binding);
	g_signal_connect (s_wsec, "notify::" NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE,
	                  G_CALLBACK (wireless_security_changed), binding);

	if (flags & G_BINDING_SYNC_CREATE)
		wireless_security_changed (NULL, NULL, binding);
}

/* WEP key binding */

typedef struct {
	NMSettingWirelessSecurity *s_wsec;
	GObject *entry, *key_selector;
	char *entry_property, *key_selector_property;

	gboolean updating;
} NMEditorWepKeyBinding;

static void
wep_key_setting_changed (GObject    *object,
                         GParamSpec *pspec,
                         gpointer    user_data)
{
	NMEditorWepKeyBinding *binding = user_data;
	const char *key;
	int index;

	if (binding->updating)
		return;

	index = nm_setting_wireless_security_get_wep_tx_keyidx (binding->s_wsec);
	key = nm_setting_wireless_security_get_wep_key (binding->s_wsec, index);

	binding->updating = TRUE;
	g_object_set (binding->key_selector,
	              binding->key_selector_property, index,
	              NULL);
	g_object_set (binding->entry,
	              binding->entry_property, key,
	              NULL);
	binding->updating = FALSE;
}

static void
wep_key_ui_changed (GObject    *object,
                    GParamSpec *pspec,
                    gpointer    user_data)
{
	NMEditorWepKeyBinding *binding = user_data;
	char *key;
	int index;

	if (binding->updating)
		return;

	g_object_get (binding->key_selector,
	              binding->key_selector_property, &index,
	              NULL);
	g_object_get (binding->entry,
	              binding->entry_property, &key,
	              NULL);

	binding->updating = TRUE;
	g_object_set (binding->s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, index,
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY0, index == 0 ? key : NULL,
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY1, index == 1 ? key : NULL,
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY2, index == 2 ? key : NULL,
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY3, index == 3 ? key : NULL,
	              NULL);
	binding->updating = FALSE;

	g_free (key);
}

static void
wep_key_target_destroyed (gpointer  user_data,
                          GObject  *ex_target)
{
	NMEditorWepKeyBinding *binding = user_data;

	g_signal_handlers_disconnect_by_func (binding->s_wsec, G_CALLBACK (wep_key_setting_changed), binding);

	if (ex_target != binding->entry) {
		g_signal_handlers_disconnect_by_func (binding->entry, G_CALLBACK (wep_key_ui_changed), binding);
		g_object_weak_unref (binding->entry, wep_key_target_destroyed, binding);
	} else {
		g_signal_handlers_disconnect_by_func (binding->key_selector, G_CALLBACK (wep_key_ui_changed), binding);
		g_object_weak_unref (binding->key_selector, wep_key_target_destroyed, binding);
	}

	g_object_unref (binding->s_wsec);
	g_free (binding->entry_property);
	g_free (binding->key_selector_property);

	g_slice_free (NMEditorWepKeyBinding, binding);
}

/**
 * nm_editor_bind_wireless_security_wep_key:
 * @s_wsec: an #NMSettingWirelessSecurity
 * @entry: an entry widget
 * @entry_property: the string-valued property on @entry to bind
 * @key_selector: a pop-up widget of some sort
 * @key_selector_property: the integer-valued property on
 *   @key_selector to bind
 * @flags: %GBindingFlags
 *
 * Binds the "wep-tx-keyidx" property on @s_wsec to
 * @key_selector_property on @key_selector, and the corresponding
 * "wep-keyN" property to @entry_property on @entry (and vice versa if
 * %G_BINDING_BIDIRECTIONAL).
 */
void
nm_editor_bind_wireless_security_wep_key (NMSettingWirelessSecurity *s_wsec,
                                          gpointer       entry,
                                          const char    *entry_property,
                                          gpointer       key_selector,
                                          const char    *key_selector_property,
                                          GBindingFlags  flags)
{
	NMEditorWepKeyBinding *binding;
	char *notify;

	binding = g_slice_new0 (NMEditorWepKeyBinding);
	binding->s_wsec = g_object_ref (s_wsec);
	binding->entry = entry;
	binding->entry_property = g_strdup (entry_property);
	binding->key_selector = key_selector;
	binding->key_selector_property = g_strdup (key_selector_property);

	g_signal_connect (s_wsec, "notify::" NM_SETTING_WIRELESS_SECURITY_WEP_KEY0,
	                  G_CALLBACK (wep_key_setting_changed), binding);
	g_signal_connect (s_wsec, "notify::" NM_SETTING_WIRELESS_SECURITY_WEP_KEY1,
	                  G_CALLBACK (wep_key_setting_changed), binding);
	g_signal_connect (s_wsec, "notify::" NM_SETTING_WIRELESS_SECURITY_WEP_KEY2,
	                  G_CALLBACK (wep_key_setting_changed), binding);
	g_signal_connect (s_wsec, "notify::" NM_SETTING_WIRELESS_SECURITY_WEP_KEY3,
	                  G_CALLBACK (wep_key_setting_changed), binding);

	g_signal_connect (s_wsec, "notify::" NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX,
	                  G_CALLBACK (wep_key_setting_changed), binding);

	if (flags & G_BINDING_BIDIRECTIONAL) {
		notify = g_strdup_printf ("notify::%s", entry_property);
		g_signal_connect (entry, notify, G_CALLBACK (wep_key_ui_changed), binding);
		g_free (notify);

		notify = g_strdup_printf ("notify::%s", key_selector_property);
		g_signal_connect (key_selector, notify, G_CALLBACK (wep_key_ui_changed), binding);
		g_free (notify);
	}

	g_object_weak_ref (entry, wep_key_target_destroyed, binding);
	g_object_weak_ref (key_selector, wep_key_target_destroyed, binding);

	if (flags & G_BINDING_SYNC_CREATE)
		wep_key_setting_changed (NULL, NULL, binding);
}

/* VLAN binding */

typedef struct {
	NMSettingVlan *s_vlan;
	NMSettingConnection *s_con;

	char *last_ifname_parent;
	int last_ifname_id;

	gboolean updating;
} NMEditorVlanWidgetBinding;

static gboolean
parse_interface_name (const char  *ifname,
                      char       **parent_ifname,
                      int         *id)
{
	const char *ifname_end;
	char *end;

	if (!ifname || !*ifname)
		return FALSE;

	if (g_str_has_prefix (ifname, "vlan")) {
		ifname_end = ifname + 4;
		*id = strtoul (ifname_end, &end, 10);
		if (*end || end == (char *)ifname_end || *id < 0)
			return FALSE;
		*parent_ifname = NULL;
		return TRUE;
	}

	ifname_end = strchr (ifname, '.');
	if (ifname_end) {
		*id = strtoul (ifname_end + 1, &end, 10);
		if (*end || end == (char *)ifname_end + 1 || *id < 0)
			return FALSE;
		*parent_ifname = g_strndup (ifname, ifname_end - ifname);
		return TRUE;
	}

	return FALSE;
}

static void
vlan_settings_changed (GObject    *object,
                       GParamSpec *pspec,
                       gpointer    user_data)
{
	NMEditorVlanWidgetBinding *binding = user_data;
	const char *ifname, *parent;
	char *ifname_parent;
	int ifname_id, id;

	if (binding->updating)
		return;

	ifname = nm_setting_connection_get_interface_name (binding->s_con);
	parent = nm_setting_vlan_get_parent (binding->s_vlan);
	id = nm_setting_vlan_get_id (binding->s_vlan);

	if (!parse_interface_name (ifname, &ifname_parent, &ifname_id))
		return;

	/* If the id in INTERFACE_NAME changed, and ID is either unset, or was previously
	 * in sync with INTERFACE_NAME, then update ID.
	 */
	if (   id != ifname_id
	    && (id == binding->last_ifname_id || id == 0)) {
		binding->updating = TRUE;
		g_object_set (G_OBJECT (binding->s_vlan),
		              NM_SETTING_VLAN_ID, ifname_id,
		              NULL);
		binding->updating = FALSE;
	}

	/* If the PARENT in INTERFACE_NAME changed, and PARENT is either unset, or was
	 * previously in sync with INTERFACE_NAME, then update PARENT.
	 */
	if (   g_strcmp0 (parent, ifname_parent) != 0
	    && (   g_strcmp0 (parent, binding->last_ifname_parent) == 0
	        || !parent || !*parent)) {
		binding->updating = TRUE;
		g_object_set (G_OBJECT (binding->s_vlan),
		              NM_SETTING_VLAN_PARENT, ifname_parent,
		              NULL);
		binding->updating = FALSE;
	}

	g_free (binding->last_ifname_parent);
	binding->last_ifname_parent = ifname_parent;
	binding->last_ifname_id = ifname_id;
}

static void
vlan_target_destroyed (gpointer  user_data,
                       GObject  *ex_target)
{
	NMEditorVlanWidgetBinding *binding = user_data;

	g_free (binding->last_ifname_parent);
	g_slice_free (NMEditorVlanWidgetBinding, binding);
}

/**
 * nm_editor_bind_vlan_name:
 * @s_vlan: an #NMSettingVlan
 *
 * Binds together several properties on @s_vlan, so that if the
 * %NM_SETTING_VLAN_INTERFACE_NAME matches %NM_SETTING_VLAN_PARENT
 * and %NM_SETTING_VLAN_ID in the obvious way, then changes to
 * %NM_SETTING_VLAN_INTERFACE_NAME will propagate to the other
 * two properties automatically.
 */
void
nm_editor_bind_vlan_name (NMSettingVlan *s_vlan,
                          NMSettingConnection *s_con)
{
	NMEditorVlanWidgetBinding *binding;
	const char *ifname;

	binding = g_slice_new0 (NMEditorVlanWidgetBinding);
	binding->s_vlan = s_vlan;
	binding->s_con = s_con;

	g_signal_connect (s_con, "notify::" NM_SETTING_CONNECTION_INTERFACE_NAME,
	                  G_CALLBACK (vlan_settings_changed), binding);

	g_object_weak_ref (G_OBJECT (s_vlan), vlan_target_destroyed, binding);

	ifname = nm_setting_connection_get_interface_name (s_con);
	if (!parse_interface_name (ifname, &binding->last_ifname_parent, &binding->last_ifname_id)) {
		binding->last_ifname_parent = NULL;
		binding->last_ifname_id = 0;
	}
}
