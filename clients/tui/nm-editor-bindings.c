/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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

#include "config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include <dbus/dbus-glib.h>

#include "nm-editor-bindings.h"
#include "nm-gvaluearray-compat.h"

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

	g_value_set_uint (dest_value, (gint) val);
}

void
nm_editor_bindings_init (void)
{
	/* glib registers number -> string, but not string -> number */
	g_value_register_transform_func (G_TYPE_STRING, G_TYPE_INT, value_transform_string_int);
	g_value_register_transform_func (G_TYPE_STRING, G_TYPE_UINT, value_transform_string_uint);
}

static gboolean
ip_string_parse (const char *text,
                 int         family,
                 gpointer    addr,
                 guint32    *prefix)
{
	const char *slash;
	char *addrstr, *end;
	gboolean valid;

	slash = strchr (text, '/');

	if (slash) {
		if (!prefix)
			return FALSE;
		addrstr = g_strndup (text, slash - text);
	} else
		addrstr = g_strdup (text);
	valid = (inet_pton (family, addrstr, addr) == 1);
	g_free (addrstr);

	if (!valid)
		return FALSE;

	if (slash) {
		*prefix = strtoul (slash + 1, &end, 10);
		if (   *end
		    || *prefix == 0
		    || (family == AF_INET && *prefix > 32)
		    || (family == AF_INET6 && *prefix > 128))
			valid = FALSE;
	} else if (prefix) {
		if (family == AF_INET)
			*prefix = 32;
		else
			*prefix = 128;
	}

	return valid;
}

static gboolean
ip4_addresses_with_prefix_to_strv (GBinding     *binding,
                                   const GValue *source_value,
                                   GValue       *target_value,
                                   gpointer      user_data)
{
	GPtrArray *addrs;
	GArray *addr;
	guint32 addrbytes, prefix;
	char buf[INET_ADDRSTRLEN], **strings;
	int i;

	addrs = g_value_get_boxed (source_value);
	strings = g_new0 (char *, addrs->len + 1);

	for (i = 0; i < addrs->len; i++) {
		addr = addrs->pdata[i];
		addrbytes = g_array_index (addr, guint32, 0);
		prefix = g_array_index (addr, guint32, 1);

		if (addrbytes) {
			strings[i] = g_strdup_printf ("%s/%d",
			                              inet_ntop (AF_INET, &addrbytes, buf, sizeof (buf)),
			                              (int) prefix);
		} else
			strings[i] = g_strdup ("");
	}

	g_value_take_boxed (target_value, strings);
	return TRUE;
}

static gboolean
ip4_addresses_with_prefix_from_strv (GBinding     *binding,
                                     const GValue *source_value,
                                     GValue       *target_value,
                                     gpointer      user_data)
{
	char **strings;
	GPtrArray *addrs;
	GArray *addr;
	guint32 *addrvals;
	int i;

	strings = g_value_get_boxed (source_value);
	/* Fetch the original property value, so as to preserve the gateway elements */
	g_object_get (g_binding_get_source (binding),
	              g_binding_get_source_property (binding), &addrs,
	              NULL);

	for (i = 0; strings[i]; i++) {
		if (i >= addrs->len) {
			guint32 val;

			addr = g_array_sized_new (FALSE, FALSE, sizeof (guint32), 3);
			val = 0;
			g_array_append_val (addr, val);
			val = 32;
			g_array_append_val (addr, val);
			val = 0;
			g_array_append_val (addr, val);
			g_ptr_array_add (addrs, addr);
		} else
			addr = addrs->pdata[i];
		addrvals = (guint32 *)addr->data;

		if (!ip_string_parse (strings[i], AF_INET, &addrvals[0], &addrvals[1])) {
			g_ptr_array_unref (addrs);
			return FALSE;
		}
	}

	g_ptr_array_set_size (addrs, i);
	g_value_take_boxed (target_value, addrs);
	return TRUE;
}

/**
 * nm_editor_bind_ip4_addresses_with_prefix_to_strv:
 * @source: the source object (eg, an #NMSettingIP4Config)
 * @source_property: the property on @source to bind (eg,
 *   %NM_SETTING_IP4_CONFIG_ADDRESSES)
 * @target: the target object (eg, an #NmtAddressList)
 * @target_property: the property on @target to bind
 *   (eg, "strings")
 * @flags: %GBindingFlags
 *
 * Binds the %DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT property
 * @source_property on @source to the %G_TYPE_STRV property
 * @target_property on @target.
 *
 * Each address/prefix/gateway triplet in @source_property will be
 * converted to a string of the form "ip.ad.dr.ess/prefix" in
 * @target_property (and vice versa if %G_BINDING_BIDIRECTIONAL) is
 * specified. The "gateway" fields in @source_property are ignored
 * when converting to strings, and unmodified when converting from
 * strings.
 */
void
nm_editor_bind_ip4_addresses_with_prefix_to_strv (gpointer       source,
                                                  const gchar   *source_property,
                                                  gpointer       target,
                                                  const gchar   *target_property,
                                                  GBindingFlags  flags)
{
	g_object_bind_property_full (source, source_property,
	                             target, target_property,
	                             flags,
	                             ip4_addresses_with_prefix_to_strv,
	                             ip4_addresses_with_prefix_from_strv,
	                             NULL, NULL);
}

static gboolean
ip4_addresses_to_strv (GBinding     *binding,
                       const GValue *source_value,
                       GValue       *target_value,
                       gpointer      user_data)
{
	GArray *addrs;
	guint32 addrbytes;
	char buf[INET_ADDRSTRLEN], **strings;
	int i;

	addrs = g_value_get_boxed (source_value);
	strings = g_new0 (char *, addrs->len + 1);

	for (i = 0; i < addrs->len; i++) {
		addrbytes = g_array_index (addrs, guint32, i);
		if (addrbytes)
			inet_ntop (AF_INET, &addrbytes, buf, sizeof (buf));
		else
			buf[0] = '\0';
		strings[i] = g_strdup (buf);
	}

	g_value_take_boxed (target_value, strings);
	return TRUE;
}

static gboolean
ip4_addresses_from_strv (GBinding     *binding,
                         const GValue *source_value,
                         GValue       *target_value,
                         gpointer      user_data)
{
	char **strings;
	GArray *addrs;
	guint32 addr;
	int i;

	strings = g_value_get_boxed (source_value);
	addrs = g_array_new (FALSE, FALSE, sizeof (guint32));

	for (i = 0; strings[i]; i++) {
		if (!ip_string_parse (strings[i], AF_INET, &addr, NULL)) {
			g_array_unref (addrs);
			return FALSE;
		}
		g_array_append_val (addrs, addr);
	}

	g_value_take_boxed (target_value, addrs);
	return TRUE;
}

/**
 * nm_editor_bind_ip4_addresses_to_strv:
 * @source: the source object (eg, an #NMSettingIP4Config)
 * @source_property: the property on @source to bind (eg,
 *   %NM_SETTING_IP4_CONFIG_DNS)
 * @target: the target object (eg, an #NmtAddressList)
 * @target_property: the property on @target to bind
 *   (eg, "strings")
 * @flags: %GBindingFlags
 *
 * Binds the %DBUS_TYPE_G_UINT_ARRAY property @source_property on
 * @source to the %G_TYPE_STRV property @target_property on @target.
 *
 * Each address in @source_property will be converted to a string of
 * the form "ip.ad.dr.ess" in @target_property (and vice versa if
 * %G_BINDING_BIDIRECTIONAL) is specified.
 */
void
nm_editor_bind_ip4_addresses_to_strv (gpointer       source,
                                      const gchar   *source_property,
                                      gpointer       target,
                                      const gchar   *target_property,
                                      GBindingFlags  flags)
{
	g_object_bind_property_full (source, source_property,
	                             target, target_property,
	                             flags,
	                             ip4_addresses_to_strv,
	                             ip4_addresses_from_strv,
	                             NULL, NULL);
}

static gboolean
ip4_gateway_to_string (GBinding     *binding,
                       const GValue *source_value,
                       GValue       *target_value,
                       gpointer      user_data)
{
	GPtrArray *addrs;
	GArray *addr;
	guint32 gateway = 0;
	const char *str;
	char buf[INET_ADDRSTRLEN];
	int i;

	addrs = g_value_get_boxed (source_value);
	for (i = 0; i < addrs->len; i++) {
		addr = addrs->pdata[i];
		gateway = g_array_index (addr, guint32, 2);
		if (gateway)
			break;
	}

	if (gateway)
		str = inet_ntop (AF_INET, &gateway, buf, sizeof (buf));
	else
		str = "";
	g_value_set_string (target_value, str);
	return TRUE;
}

static gboolean
ip4_gateway_from_string (GBinding     *binding,
                         const GValue *source_value,
                         GValue       *target_value,
                         gpointer      user_data)
{
	const char *text;
	GPtrArray *addrs;
	GArray *addr;
	guint32 addrbytes, *addrvals;
	int i;

	text = g_value_get_string (source_value);
	if (!ip_string_parse (text, AF_INET, &addrbytes, NULL))
		return FALSE;

	/* Fetch the original property value, so as to preserve the IP address elements */
	g_object_get (g_binding_get_source (binding),
	              g_binding_get_source_property (binding), &addrs,
	              NULL);
	if (!addrs->len) {
		g_ptr_array_unref (addrs);
		return FALSE;
	}
	addr = addrs->pdata[0];
	addrvals = (guint32 *)addr->data;
	if (addrbytes == addrvals[2]) {
		g_ptr_array_unref (addrs);
		return FALSE;
	}
	addrvals[2] = addrbytes;

	for (i = 1; i < addrs->len; i++) {
	     addr = addrs->pdata[i];
	     addrvals = (guint32 *)addr->data;
	     addrvals[2] = 0;
	}

	g_value_take_boxed (target_value, addrs);
	return TRUE;
}

/**
 * nm_editor_bind_ip4_gateway_to_string:
 * @source: the source object (eg, an #NMSettingIP4Config)
 * @source_property: the property on @source to bind (eg,
 *   %NM_SETTING_IP4_CONFIG_ADDRESSES)
 * @target: the target object (eg, an #NmtNewtEntry)
 * @target_property: the property on @target to bind
 *   (eg, "text")
 * @flags: %GBindingFlags
 *
 * Binds the %DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT property
 * @source_property on @source to the %G_TYPE_STRING property
 * @target_property on @target.
 *
 * Specifically, this binds the "gateway" field of the first address
 * in @source_property; all other addresses in @source_property are
 * ignored, and its "address" and "prefix" fields are unmodified.
 */
void
nm_editor_bind_ip4_gateway_to_string (gpointer       source,
                                      const gchar   *source_property,
                                      gpointer       target,
                                      const gchar   *target_property,
                                      GBindingFlags  flags)
{
	g_object_bind_property_full (source, source_property,
	                             target, target_property,
	                             flags,
	                             ip4_gateway_to_string,
	                             ip4_gateway_from_string,
	                             NULL, NULL);
}

static gboolean
ip4_route_transform_to_dest_string (GBinding     *binding,
                                    const GValue *source_value,
                                    GValue       *target_value,
                                    gpointer      user_data)
{
	NMIP4Route *route;
	char buf[INET_ADDRSTRLEN], *string;
	guint32 addrbytes;

	route = g_value_get_boxed (source_value);
	if (route)
		addrbytes = nm_ip4_route_get_dest (route);
	else
		addrbytes = 0;

	if (addrbytes) {
		string = g_strdup_printf ("%s/%d",
		                          inet_ntop (AF_INET, &addrbytes, buf, sizeof (buf)),
		                          (int) nm_ip4_route_get_prefix (route));
		g_value_take_string (target_value, string);
	} else
		g_value_set_string (target_value, "");
	return TRUE;
}

static gboolean
ip4_route_transform_to_next_hop_string (GBinding     *binding,
                                        const GValue *source_value,
                                        GValue       *target_value,
                                        gpointer      user_data)
{
	NMIP4Route *route;
	char buf[INET_ADDRSTRLEN];
	guint32 addrbytes;

	route = g_value_get_boxed (source_value);
	if (route)
		addrbytes = nm_ip4_route_get_next_hop (route);
	else
		addrbytes = 0;

	if (addrbytes)
		inet_ntop (AF_INET, &addrbytes, buf, sizeof (buf));
	else
		buf[0] = '\0';
	g_value_set_string (target_value, buf);
	return TRUE;
}

static gboolean
ip4_route_transform_to_metric_string (GBinding     *binding,
                                      const GValue *source_value,
                                      GValue       *target_value,
                                      gpointer      user_data)
{
	NMIP4Route *route;
	char *string;

	route = g_value_get_boxed (source_value);
	if (route && nm_ip4_route_get_dest (route)) {
		string = g_strdup_printf ("%lu", (gulong) nm_ip4_route_get_metric (route));
		g_value_take_string (target_value, string);
	} else
		g_value_set_string (target_value, "");
	return TRUE;
}

static gboolean
ip4_route_transform_from_dest_string (GBinding     *binding,
                                      const GValue *source_value,
                                      GValue       *target_value,
                                      gpointer      user_data)
{
	NMIP4Route *route;
	const char *text;
	guint32 addrbytes, prefix;

	text = g_value_get_string (source_value);
	if (!ip_string_parse (text, AF_INET, &addrbytes, &prefix))
		return FALSE;

	/* Fetch the original property value */
	g_object_get (g_binding_get_source (binding),
	              g_binding_get_source_property (binding), &route,
	              NULL);

	nm_ip4_route_set_dest (route, addrbytes);
	nm_ip4_route_set_prefix (route, prefix);

	g_value_take_boxed (target_value, route);
	return TRUE;
}

static gboolean
ip4_route_transform_from_next_hop_string (GBinding     *binding,
                                          const GValue *source_value,
                                          GValue       *target_value,
                                          gpointer      user_data)
{
	NMIP4Route *route;
	const char *text;
	guint32 addrbytes;

	text = g_value_get_string (source_value);
	if (*text) {
		if (!ip_string_parse (text, AF_INET, &addrbytes, NULL))
			return FALSE;
	} else
		addrbytes = 0;

	/* Fetch the original property value */
	g_object_get (g_binding_get_source (binding),
	              g_binding_get_source_property (binding), &route,
	              NULL);

	nm_ip4_route_set_next_hop (route, addrbytes);

	g_value_take_boxed (target_value, route);
	return TRUE;
}

static gboolean
ip4_route_transform_from_metric_string (GBinding     *binding,
                                        const GValue *source_value,
                                        GValue       *target_value,
                                        gpointer      user_data)
{
	NMIP4Route *route;
	const char *text;
	guint32 metric;

	text = g_value_get_string (source_value);
	metric = strtoul (text, NULL, 10);

	/* Fetch the original property value */
	g_object_get (g_binding_get_source (binding),
	              g_binding_get_source_property (binding), &route,
	              NULL);

	nm_ip4_route_set_metric (route, metric);

	g_value_take_boxed (target_value, route);
	return TRUE;
}

/**
 * nm_editor_bind_ip4_route_to_strings:
 * @source: the source object
 * @source_property: the source property
 * @dest_target: the target object for the route's destionation
 * @dest_target_property: the property on @dest_target
 * @next_hop_target: the target object for the route's next hop
 * @next_hop_target_property: the property on @next_hop_target
 * @metric_target: the target object for the route's metric
 * @metric_target_property: the property on @metric_target
 * @flags: %GBindingFlags
 *
 * Binds the #NMIP4Route-valued property @source_property on @source
 * to the three indicated string-valued target properties (and vice
 * versa if %G_BINDING_BIDIRECTIONAL is specified).
 *
 * @dest_target_property should be an "address/prefix" string, as with
 * nm_editor_bind_ip4_addresses_with_prefix_to_strv(). @next_hop_target
 * is a plain IP address, and @metric_target is a number.
 */
void
nm_editor_bind_ip4_route_to_strings (gpointer       source,
                                     const gchar   *source_property,
                                     gpointer       dest_target,
                                     const gchar   *dest_target_property,
                                     gpointer       next_hop_target,
                                     const gchar   *next_hop_target_property,
                                     gpointer       metric_target,
                                     const gchar   *metric_target_property,
                                     GBindingFlags  flags)
{
	g_object_bind_property_full (source, source_property,
	                             dest_target, dest_target_property,
	                             flags,
	                             ip4_route_transform_to_dest_string,
	                             ip4_route_transform_from_dest_string,
	                             NULL, NULL);
	g_object_bind_property_full (source, source_property,
	                             next_hop_target, next_hop_target_property,
	                             flags,
	                             ip4_route_transform_to_next_hop_string,
	                             ip4_route_transform_from_next_hop_string,
	                             NULL, NULL);
	g_object_bind_property_full (source, source_property,
	                             metric_target, metric_target_property,
	                             flags,
	                             ip4_route_transform_to_metric_string,
	                             ip4_route_transform_from_metric_string,
	                             NULL, NULL);
}

#define IP6_ADDRESS_SET(addr) (   addr	  \
                               && addr->len == sizeof (struct in6_addr) \
                               && memcmp (addr->data, &in6addr_any, addr->len) != 0)

static gboolean
ip6_addresses_with_prefix_to_strv (GBinding     *binding,
                                   const GValue *source_value,
                                   GValue       *target_value,
                                   gpointer      user_data)
{
	GPtrArray *addrs;
	GValueArray *addr;
	GValue *val;
	GByteArray *addrbytes;
	guint prefix;
	char **strings, buf[INET6_ADDRSTRLEN];
	int i;

	addrs = g_value_get_boxed (source_value);
	strings = g_new0 (char *, addrs->len + 1);

	for (i = 0; i < addrs->len; i++) {
		addr = addrs->pdata[i];
		val = g_value_array_get_nth (addr, 0);
		addrbytes = g_value_get_boxed (val);
		val = g_value_array_get_nth (addr, 1);
		prefix = g_value_get_uint (val);

		if (IP6_ADDRESS_SET (addrbytes)) {
			strings[i] = g_strdup_printf ("%s/%d",
			                              inet_ntop (AF_INET6, addrbytes->data, buf, sizeof (buf)),
			                              prefix);
		} else
			strings[i] = g_strdup ("");
	}

	g_value_take_boxed (target_value, strings);
	return TRUE;
}

static gboolean
ip6_addresses_with_prefix_from_strv (GBinding     *binding,
                                     const GValue *source_value,
                                     GValue       *target_value,
                                     gpointer      user_data)
{
	char **strings;
	GPtrArray *addrs;
	GValueArray *addr;
	guint32 prefix;
	GValue val = G_VALUE_INIT, *valp;
	GByteArray *ba;
	int i;

	strings = g_value_get_boxed (source_value);

	/* Fetch the original property value, so as to preserve the gateway elements */
	g_object_get (g_binding_get_source (binding),
	              g_binding_get_source_property (binding), &addrs,
	              NULL);

	for (i = 0; strings[i]; i++) {
		if (i >= addrs->len) {
			addr = g_value_array_new (3);

			g_value_init (&val, DBUS_TYPE_G_UCHAR_ARRAY);
			ba = g_byte_array_sized_new (sizeof (struct in6_addr));
			g_byte_array_append (ba, (guint8 *) &in6addr_any, sizeof (struct in6_addr));
			g_value_take_boxed (&val, ba);
			g_value_array_append (addr, &val);
			g_value_unset (&val);

			g_value_init (&val, G_TYPE_UINT);
			g_value_set_uint (&val, 128);
			g_value_array_append (addr, &val);
			g_value_unset (&val);

			g_value_init (&val, DBUS_TYPE_G_UCHAR_ARRAY);
			ba = g_byte_array_sized_new (sizeof (struct in6_addr));
			g_byte_array_append (ba, (guint8 *) &in6addr_any, sizeof (struct in6_addr));
			g_value_take_boxed (&val, ba);
			g_value_array_append (addr, &val);
			g_value_unset (&val);

			g_ptr_array_add (addrs, addr);
		} else
			addr = addrs->pdata[i];

		valp = g_value_array_get_nth (addr, 0);
		ba = g_value_get_boxed (valp);
		g_assert (ba->len == sizeof (struct in6_addr));

		if (!ip_string_parse (strings[i], AF_INET6, ba->data, &prefix)) {
			g_ptr_array_unref (addrs);
			return FALSE;
		}

		valp = g_value_array_get_nth (addr, 1);
		g_value_set_uint (valp, prefix);
	}

	g_ptr_array_set_size (addrs, i);
	g_value_set_boxed (target_value, addrs);
	return TRUE;
}

/**
 * nm_editor_bind_ip6_addresses_with_prefix_to_strv:
 * @source: the source object (eg, an #NMSettingIP6Config)
 * @source_property: the property on @source to bind (eg,
 *   %NM_SETTING_IP6_CONFIG_ADDRESSES)
 * @target: the target object (eg, an #NmtAddressList)
 * @target_property: the property on @target to bind
 *   (eg, "strings")
 * @flags: %GBindingFlags
 *
 * Binds the %DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS property
 * @source_property on @source to the %G_TYPE_STRV property
 * @target_property on @target.
 *
 * Each address/prefix/gateway triplet in @source_property will be
 * converted to a string of the form "ip::ad:dr:ess/prefix" in
 * @target_property (and vice versa if %G_BINDING_BIDIRECTIONAL) is
 * specified. The "gateway" fields in @source_property are ignored
 * when converting to strings, and unmodified when converting from
 * strings.
 */
void
nm_editor_bind_ip6_addresses_with_prefix_to_strv (gpointer       source,
                                                  const gchar   *source_property,
                                                  gpointer       target,
                                                  const gchar   *target_property,
                                                  GBindingFlags  flags)
{
	g_object_bind_property_full (source, source_property,
	                             target, target_property,
	                             flags,
	                             ip6_addresses_with_prefix_to_strv,
	                             ip6_addresses_with_prefix_from_strv,
	                             NULL, NULL);
}

static gboolean
ip6_addresses_to_strv (GBinding     *binding,
                       const GValue *source_value,
                       GValue       *target_value,
                       gpointer      user_data)
{
	GPtrArray *addrs;
	GByteArray *addrbytes;
	char buf[INET6_ADDRSTRLEN], **strings;
	int i;

	addrs = g_value_get_boxed (source_value);
	strings = g_new0 (char *, addrs->len + 1);

	for (i = 0; i < addrs->len; i++) {
		addrbytes = addrs->pdata[i];
		if (IP6_ADDRESS_SET (addrbytes))
			inet_ntop (AF_INET6, addrbytes->data, buf, sizeof (buf));
		else
			buf[0] = '\0';
		strings[i] = g_strdup (buf);
	}

	g_value_take_boxed (target_value, strings);
	return TRUE;
}

static gboolean
ip6_addresses_from_strv (GBinding     *binding,
                         const GValue *source_value,
                         GValue       *target_value,
                         gpointer      user_data)
{
	char **strings;
	GPtrArray *addrs;
	GByteArray *addr;
	struct in6_addr addrbytes;
	int i;

	strings = g_value_get_boxed (source_value);
	addrs = g_ptr_array_new ();

	for (i = 0; strings[i]; i++) {
		if (!ip_string_parse (strings[i], AF_INET6, &addrbytes, NULL)) {
			while (i--)
				g_byte_array_unref (addrs->pdata[i]);
			g_ptr_array_unref (addrs);
			return FALSE;
		}

		addr = g_byte_array_sized_new (sizeof (addrbytes));
		g_byte_array_append (addr, (guint8 *)&addrbytes, sizeof (addrbytes));
		g_ptr_array_add (addrs, addr);
	}

	g_value_take_boxed (target_value, addrs);
	return TRUE;
}

/**
 * nm_editor_bind_ip6_addresses_to_strv:
 * @source: the source object (eg, an #NMSettingIP6Config)
 * @source_property: the property on @source to bind (eg,
 *   %NM_SETTING_IP6_CONFIG_DNS)
 * @target: the target object (eg, an #NmtAddressList)
 * @target_property: the property on @target to bind
 *   (eg, "strings")
 * @flags: %GBindingFlags
 *
 * Binds the %DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UCHAR property
 * @source_property on @source to the %G_TYPE_STRV property
 * @target_property on @target.
 *
 * Each address in @source_property will be converted to a string of
 * the form "ip::ad:dr:ess" in @target_property (and vice versa if
 * %G_BINDING_BIDIRECTIONAL) is specified.
 */
void
nm_editor_bind_ip6_addresses_to_strv (gpointer       source,
                                      const gchar   *source_property,
                                      gpointer       target,
                                      const gchar   *target_property,
                                      GBindingFlags  flags)
{
	g_object_bind_property_full (source, source_property,
	                             target, target_property,
	                             flags,
	                             ip6_addresses_to_strv,
	                             ip6_addresses_from_strv,
	                             NULL, NULL);
}

static gboolean
ip6_gateway_to_string (GBinding     *binding,
                       const GValue *source_value,
                       GValue       *target_value,
                       gpointer      user_data)
{
	GPtrArray *addrs;
	GValueArray *addr;
	GValue *val;
	GByteArray *gateway;
	char buf[INET6_ADDRSTRLEN];
	const char *str;

	addrs = g_value_get_boxed (source_value);
	if (addrs->len == 0)
		return FALSE;

	addr = addrs->pdata[0];
	val = g_value_array_get_nth (addr, 2);
	gateway = g_value_get_boxed (val);

	if (IP6_ADDRESS_SET (gateway))
		str = inet_ntop (AF_INET6, gateway->data, buf, sizeof (buf));
	else
		str = "";
	g_value_set_string (target_value, str);
	return TRUE;
}

static gboolean
ip6_gateway_from_string (GBinding     *binding,
                         const GValue *source_value,
                         GValue       *target_value,
                         gpointer      user_data)
{
	GPtrArray *addrs;
	const char *text;
	GValueArray *addr;
	struct in6_addr gateway;
	GValue *val;
	GByteArray *ba;
	int i;

	text = g_value_get_string (source_value);
	if (!ip_string_parse (text, AF_INET6, &gateway, NULL))
		return FALSE;

	/* Fetch the original property value, so as to preserve the IP address elements */
	g_object_get (g_binding_get_source (binding),
	              g_binding_get_source_property (binding), &addrs,
	              NULL);
	if (!addrs->len) {
		g_ptr_array_unref (addrs);
		return FALSE;
	}

	addr = addrs->pdata[0];

	ba = g_byte_array_sized_new (sizeof (gateway));
	g_byte_array_append (ba, (guint8 *) &gateway, sizeof (gateway));

	val = g_value_array_get_nth (addr, 2);
	g_value_take_boxed (val, ba);

	for (i = 1; i < addrs->len; i++) {
		addr = addrs->pdata[i];
		val = g_value_array_get_nth (addr, 2);
		ba = g_value_get_boxed (val);

		if (ba)
			memset (ba->data, 0, ba->len);
	}

	g_value_take_boxed (target_value, addrs);
	return TRUE;
}

/**
 * nm_editor_bind_ip6_gateway_to_string:
 * @source: the source object (eg, an #NMSettingIP6Config)
 * @source_property: the property on @source to bind (eg,
 *   %NM_SETTING_IP6_CONFIG_ADDRESSES)
 * @target: the target object (eg, an #NmtNewtEntry)
 * @target_property: the property on @target to bind
 *   (eg, "text")
 * @flags: %GBindingFlags
 *
 * Binds the %DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS property
 * @source_property on @source to the %G_TYPE_STRING property
 * @target_property on @target.
 *
 * Specifically, this binds the "gateway" field of the first address
 * in @source_property; all other addresses in @source_property are
 * ignored, and its "address" and "prefix" fields are unmodified.
 */
void
nm_editor_bind_ip6_gateway_to_string (gpointer       source,
                                      const gchar   *source_property,
                                      gpointer       target,
                                      const gchar   *target_property,
                                      GBindingFlags  flags)
{
	g_object_bind_property_full (source, source_property,
	                             target, target_property,
	                             flags,
	                             ip6_gateway_to_string,
	                             ip6_gateway_from_string,
	                             NULL, NULL);
}

#define IN6_ADDR_SET(bytes) (memcmp (bytes, &in6addr_any, sizeof (struct in6_addr)) != 0)

static gboolean
ip6_route_transform_to_dest_string (GBinding     *binding,
                                    const GValue *source_value,
                                    GValue       *target_value,
                                    gpointer      user_data)
{
	NMIP6Route *route;
	char buf[INET6_ADDRSTRLEN], *string;
	const struct in6_addr *addrbytes;

	route = g_value_get_boxed (source_value);
	if (route)
		addrbytes = nm_ip6_route_get_dest (route);
	else
		addrbytes = &in6addr_any;

	if (IN6_ADDR_SET (addrbytes)) {
		string = g_strdup_printf ("%s/%d",
		                          inet_ntop (AF_INET6, addrbytes, buf, sizeof (buf)),
		                          (int) nm_ip6_route_get_prefix (route));
		g_value_take_string (target_value, string);
	} else
		g_value_set_string (target_value, "");
	return TRUE;
}

static gboolean
ip6_route_transform_to_next_hop_string (GBinding     *binding,
                                        const GValue *source_value,
                                        GValue       *target_value,
                                        gpointer      user_data)
{
	NMIP6Route *route;
	char buf[INET6_ADDRSTRLEN];
	const struct in6_addr *addrbytes;

	route = g_value_get_boxed (source_value);
	if (route)
		addrbytes = nm_ip6_route_get_next_hop (route);
	else
		addrbytes = &in6addr_any;

	if (IN6_ADDR_SET (addrbytes))
		inet_ntop (AF_INET6, addrbytes, buf, sizeof (buf));
	else
		buf[0] = '\0';
	g_value_set_string (target_value, buf);
	return TRUE;
}

static gboolean
ip6_route_transform_to_metric_string (GBinding     *binding,
                                      const GValue *source_value,
                                      GValue       *target_value,
                                      gpointer      user_data)
{
	NMIP6Route *route;
	char *string;

	route = g_value_get_boxed (source_value);
	if (route && IN6_ADDR_SET (nm_ip6_route_get_dest (route))) {
		string = g_strdup_printf ("%lu", (gulong) nm_ip6_route_get_metric (route));
		g_value_take_string (target_value, string);
	} else
		g_value_set_string (target_value, "");
	return TRUE;
}

static gboolean
ip6_route_transform_from_dest_string (GBinding     *binding,
                                      const GValue *source_value,
                                      GValue       *target_value,
                                      gpointer      user_data)
{
	NMIP6Route *route;
	const char *text;
	struct in6_addr addrbytes;
	guint32 prefix;

	text = g_value_get_string (source_value);
	if (!ip_string_parse (text, AF_INET6, &addrbytes, &prefix))
		return FALSE;

	/* Fetch the original property value */
	g_object_get (g_binding_get_source (binding),
	              g_binding_get_source_property (binding), &route,
	              NULL);

	nm_ip6_route_set_dest (route, &addrbytes);
	nm_ip6_route_set_prefix (route, prefix);

	g_value_take_boxed (target_value, route);
	return TRUE;
}

static gboolean
ip6_route_transform_from_next_hop_string (GBinding     *binding,
                                          const GValue *source_value,
                                          GValue       *target_value,
                                          gpointer      user_data)
{
	NMIP6Route *route;
	const char *text;
	struct in6_addr addrbytes;

	text = g_value_get_string (source_value);
	if (*text) {
		if (!ip_string_parse (text, AF_INET6, &addrbytes, NULL))
			return FALSE;
	} else
		addrbytes = in6addr_any;

	/* Fetch the original property value */
	g_object_get (g_binding_get_source (binding),
	              g_binding_get_source_property (binding), &route,
	              NULL);

	nm_ip6_route_set_next_hop (route, &addrbytes);

	g_value_take_boxed (target_value, route);
	return TRUE;
}

static gboolean
ip6_route_transform_from_metric_string (GBinding     *binding,
                                        const GValue *source_value,
                                        GValue       *target_value,
                                        gpointer      user_data)
{
	NMIP6Route *route;
	const char *text;
	guint32 metric;

	text = g_value_get_string (source_value);
	metric = strtoul (text, NULL, 10);

	/* Fetch the original property value */
	g_object_get (g_binding_get_source (binding),
	              g_binding_get_source_property (binding), &route,
	              NULL);

	nm_ip6_route_set_metric (route, metric);

	g_value_take_boxed (target_value, route);
	return TRUE;
}

/**
 * nm_editor_bind_ip6_route_to_strings:
 * @source: the source object
 * @source_property: the source property
 * @dest_target: the target object for the route's destionation
 * @dest_target_property: the property on @dest_target
 * @next_hop_target: the target object for the route's next hop
 * @next_hop_target_property: the property on @next_hop_target
 * @metric_target: the target object for the route's metric
 * @metric_target_property: the property on @metric_target
 * @flags: %GBindingFlags
 *
 * Binds the #NMIP6Route-valued property @source_property on @source
 * to the three indicated string-valued target properties (and vice
 * versa if %G_BINDING_BIDIRECTIONAL is specified).
 *
 * @dest_target_property should be an "address/prefix" string, as with
 * nm_editor_bind_ip6_addresses_with_prefix_to_strv(). @next_hop_target
 * is a plain IP address, and @metric_target is a number.
 */
void
nm_editor_bind_ip6_route_to_strings (gpointer       source,
                                     const gchar   *source_property,
                                     gpointer       dest_target,
                                     const gchar   *dest_target_property,
                                     gpointer       next_hop_target,
                                     const gchar   *next_hop_target_property,
                                     gpointer       metric_target,
                                     const gchar   *metric_target_property,
                                     GBindingFlags  flags)
{
	g_object_bind_property_full (source, source_property,
	                             dest_target, dest_target_property,
	                             flags,
	                             ip6_route_transform_to_dest_string,
	                             ip6_route_transform_from_dest_string,
	                             NULL, NULL);
	g_object_bind_property_full (source, source_property,
	                             next_hop_target, next_hop_target_property,
	                             flags,
	                             ip6_route_transform_to_next_hop_string,
	                             ip6_route_transform_from_next_hop_string,
	                             NULL, NULL);
	g_object_bind_property_full (source, source_property,
	                             metric_target, metric_target_property,
	                             flags,
	                             ip6_route_transform_to_metric_string,
	                             ip6_route_transform_from_metric_string,
	                             NULL, NULL);
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

	ifname = nm_setting_vlan_get_interface_name (binding->s_vlan);
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
nm_editor_bind_vlan_name (NMSettingVlan *s_vlan)
{
	NMEditorVlanWidgetBinding *binding;
	const char *ifname;

	binding = g_slice_new0 (NMEditorVlanWidgetBinding);
	binding->s_vlan = s_vlan;

	g_signal_connect (s_vlan, "notify::" NM_SETTING_VLAN_INTERFACE_NAME,
	                  G_CALLBACK (vlan_settings_changed), binding);

	g_object_weak_ref (G_OBJECT (s_vlan), vlan_target_destroyed, binding);

	ifname = nm_setting_vlan_get_interface_name (s_vlan);
	if (!parse_interface_name (ifname, &binding->last_ifname_parent, &binding->last_ifname_id)) {
		binding->last_ifname_parent = NULL;
		binding->last_ifname_id = 0;
	}
}
