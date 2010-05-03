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
 * (C) Copyright 2007 - 2010 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <string.h>

#include <dbus/dbus-glib.h>
#include "nm-setting-ip4-config.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"

GQuark
nm_setting_ip4_config_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-ip4-config-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_ip4_config_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_IP4_CONFIG_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_IP4_CONFIG_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The specified property was not allowed in combination with the current 'method' */
			ENUM_ENTRY (NM_SETTING_IP4_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD, "NotAllowedForMethod"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingIP4ConfigError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingIP4Config, nm_setting_ip4_config, NM_TYPE_SETTING)

#define NM_SETTING_IP4_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_IP4_CONFIG, NMSettingIP4ConfigPrivate))

typedef struct {
	char *method;
	GArray *dns;        /* array of guint32; elements in network byte order */
	GSList *dns_search; /* list of strings */
	GSList *addresses;  /* array of NMIP4Address */
	GSList *routes;     /* array of NMIP4Route */
	gboolean ignore_auto_routes;
	gboolean ignore_auto_dns;
	char *dhcp_client_id;
	gboolean dhcp_send_hostname;
	char *dhcp_hostname;
	gboolean never_default;
	gboolean may_fail;
} NMSettingIP4ConfigPrivate;

enum {
	PROP_0,
	PROP_METHOD,
	PROP_DNS,
	PROP_DNS_SEARCH,
	PROP_ADDRESSES,
	PROP_ROUTES,
	PROP_IGNORE_AUTO_ROUTES,
	PROP_IGNORE_AUTO_DNS,
	PROP_DHCP_CLIENT_ID,
	PROP_DHCP_SEND_HOSTNAME,
	PROP_DHCP_HOSTNAME,
	PROP_NEVER_DEFAULT,
	PROP_MAY_FAIL,

	LAST_PROP
};

NMSetting *
nm_setting_ip4_config_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_IP4_CONFIG, NULL);
}

const char *
nm_setting_ip4_config_get_method (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), NULL);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->method;
}

guint32
nm_setting_ip4_config_get_num_dns (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), 0);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dns->len;
}

guint32
nm_setting_ip4_config_get_dns (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), 0);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= priv->dns->len, 0);

	return g_array_index (priv->dns, guint32, i);
}

gboolean
nm_setting_ip4_config_add_dns (NMSettingIP4Config *setting, guint32 dns)
{
	NMSettingIP4ConfigPrivate *priv;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (i = 0; i < priv->dns->len; i++) {
		if (dns == g_array_index (priv->dns, guint32, i))
			return FALSE;
	}

	g_array_append_val (priv->dns, dns);
	return TRUE;
}

void
nm_setting_ip4_config_remove_dns (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_return_if_fail (i <= priv->dns->len);

	g_array_remove_index (priv->dns, i);
}

void
nm_setting_ip4_config_clear_dns (NMSettingIP4Config *setting)
{
	NMSettingIP4ConfigPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_array_remove_range (priv->dns, 0, priv->dns->len);
}

guint32
nm_setting_ip4_config_get_num_dns_searches (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), 0);

	return g_slist_length (NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dns_search);
}

const char *
nm_setting_ip4_config_get_dns_search (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), NULL);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->dns_search), NULL);

	return (const char *) g_slist_nth_data (priv->dns_search, i);
}

gboolean
nm_setting_ip4_config_add_dns_search (NMSettingIP4Config *setting,
                                      const char *dns_search)
{
	NMSettingIP4ConfigPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns_search != NULL, FALSE);
	g_return_val_if_fail (dns_search[0] != '\0', FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->dns_search; iter; iter = g_slist_next (iter)) {
		if (!strcmp (dns_search, (char *) iter->data))
			return FALSE;
	}

	priv->dns_search = g_slist_append (priv->dns_search, g_strdup (dns_search));
	return TRUE;
}

void
nm_setting_ip4_config_remove_dns_search (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->dns_search, i);
	g_return_if_fail (elt != NULL);

	g_free (elt->data);
	priv->dns_search = g_slist_delete_link (priv->dns_search, elt);
}

void
nm_setting_ip4_config_clear_dns_searches (NMSettingIP4Config *setting)
{
	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	nm_utils_slist_free (NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dns_search, g_free);
	NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dns_search = NULL;
}

guint32
nm_setting_ip4_config_get_num_addresses (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), 0);

	return g_slist_length (NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->addresses);
}

NMIP4Address *
nm_setting_ip4_config_get_address (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), NULL);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->addresses), NULL);

	return (NMIP4Address *) g_slist_nth_data (priv->addresses, i);
}

gboolean
nm_setting_ip4_config_add_address (NMSettingIP4Config *setting,
                                   NMIP4Address *address)
{
	NMSettingIP4ConfigPrivate *priv;
	NMIP4Address *copy;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	g_return_val_if_fail (address != NULL, FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->addresses; iter; iter = g_slist_next (iter)) {
		if (nm_ip4_address_compare ((NMIP4Address *) iter->data, address))
			return FALSE;
	}

	copy = nm_ip4_address_dup (address);
	g_return_val_if_fail (copy != NULL, FALSE);

	priv->addresses = g_slist_append (priv->addresses, copy);
	return TRUE;
}

void
nm_setting_ip4_config_remove_address (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->addresses, i);
	g_return_if_fail (elt != NULL);

	nm_ip4_address_unref ((NMIP4Address *) elt->data);
	priv->addresses = g_slist_delete_link (priv->addresses, elt);
}

void
nm_setting_ip4_config_clear_addresses (NMSettingIP4Config *setting)
{
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	nm_utils_slist_free (priv->addresses, (GDestroyNotify) nm_ip4_address_unref);
	priv->addresses = NULL;
}

guint32
nm_setting_ip4_config_get_num_routes (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), 0);

	return g_slist_length (NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->routes);
}

NMIP4Route *
nm_setting_ip4_config_get_route (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), NULL);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->routes), NULL);

	return (NMIP4Route *) g_slist_nth_data (priv->routes, i);
}

gboolean
nm_setting_ip4_config_add_route (NMSettingIP4Config *setting,
                                 NMIP4Route *route)
{
	NMSettingIP4ConfigPrivate *priv;
	NMIP4Route *copy;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	g_return_val_if_fail (route != NULL, FALSE);

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->routes; iter; iter = g_slist_next (iter)) {
		if (nm_ip4_route_compare ((NMIP4Route *) iter->data, route))
			return FALSE;
	}

	copy = nm_ip4_route_dup (route);
	g_return_val_if_fail (copy != NULL, FALSE);

	priv->routes = g_slist_append (priv->routes, copy);
	return TRUE;
}

void
nm_setting_ip4_config_remove_route (NMSettingIP4Config *setting, guint32 i)
{
	NMSettingIP4ConfigPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->routes, i);
	g_return_if_fail (elt != NULL);

	nm_ip4_route_unref ((NMIP4Route *) elt->data);
	priv->routes = g_slist_delete_link (priv->routes, elt);
}

void
nm_setting_ip4_config_clear_routes (NMSettingIP4Config *setting)
{
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	nm_utils_slist_free (priv->routes, (GDestroyNotify) nm_ip4_route_unref);
	priv->routes = NULL;
}

gboolean
nm_setting_ip4_config_get_ignore_auto_routes (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->ignore_auto_routes;
}

gboolean
nm_setting_ip4_config_get_ignore_auto_dns (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->ignore_auto_dns;
}

const char *
nm_setting_ip4_config_get_dhcp_client_id (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dhcp_client_id;
}

gboolean
nm_setting_ip4_config_get_dhcp_send_hostname (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dhcp_send_hostname;
}

const char *
nm_setting_ip4_config_get_dhcp_hostname (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->dhcp_hostname;
}

gboolean
nm_setting_ip4_config_get_never_default (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->never_default;
}

gboolean
nm_setting_ip4_config_get_may_fail (NMSettingIP4Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);

	return NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting)->may_fail;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);
	GSList *iter;
	int i;

	if (!priv->method) {
		g_set_error (error,
		             NM_SETTING_IP4_CONFIG_ERROR,
		             NM_SETTING_IP4_CONFIG_ERROR_MISSING_PROPERTY,
		             NM_SETTING_IP4_CONFIG_METHOD);
		return FALSE;
	}

	if (!strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
		if (!priv->addresses) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_MISSING_PROPERTY,
			             NM_SETTING_IP4_CONFIG_ADDRESSES);
			return FALSE;
		}
	} else if (   !strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)
	           || !strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_SHARED)
	           || !strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
		if (priv->dns && priv->dns->len) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
			             NM_SETTING_IP4_CONFIG_DNS);
			return FALSE;
		}

		if (g_slist_length (priv->dns_search)) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
			             NM_SETTING_IP4_CONFIG_DNS_SEARCH);
			return FALSE;
		}

		if (g_slist_length (priv->addresses)) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
			             NM_SETTING_IP4_CONFIG_ADDRESSES);
			return FALSE;
		}
	} else if (!strcmp (priv->method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
		/* nothing to do */
	} else {
		g_set_error (error,
		             NM_SETTING_IP4_CONFIG_ERROR,
		             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
		             NM_SETTING_IP4_CONFIG_METHOD);
		return FALSE;
	}

	if (priv->dhcp_client_id && !strlen (priv->dhcp_client_id)) {
		g_set_error (error,
		             NM_SETTING_IP4_CONFIG_ERROR,
		             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
		             NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID);
		return FALSE;
	}

	if (priv->dhcp_hostname && !strlen (priv->dhcp_hostname)) {
		g_set_error (error,
		             NM_SETTING_IP4_CONFIG_ERROR,
		             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
		             NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME);
		return FALSE;
	}

	/* Validate addresses */
	for (iter = priv->addresses, i = 0; iter; iter = g_slist_next (iter), i++) {
		NMIP4Address *addr = (NMIP4Address *) iter->data;
		guint32 prefix = nm_ip4_address_get_prefix (addr);

		if (!nm_ip4_address_get_address (addr)) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
			             NM_SETTING_IP4_CONFIG_ADDRESSES);
			return FALSE;
		}

		if (!prefix || prefix > 32) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
			             NM_SETTING_IP4_CONFIG_ADDRESSES);
			return FALSE;
		}
	}

	/* Validate routes */
	for (iter = priv->routes, i = 0; iter; iter = g_slist_next (iter), i++) {
		NMIP4Route *route = (NMIP4Route *) iter->data;
		guint32 prefix = nm_ip4_route_get_prefix (route);

		if (!nm_ip4_route_get_dest (route)) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
			             NM_SETTING_IP4_CONFIG_ROUTES);
			return FALSE;
		}

		if (!prefix || prefix > 32) {
			g_set_error (error,
			             NM_SETTING_IP4_CONFIG_ERROR,
			             NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
			             NM_SETTING_IP4_CONFIG_ROUTES);
			return FALSE;
		}
	}

	return TRUE;
}


static void
nm_setting_ip4_config_init (NMSettingIP4Config *setting)
{
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);

	g_object_set (setting, NM_SETTING_NAME, NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL);

	priv->dns = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 3);
}

static void
finalize (GObject *object)
{
	NMSettingIP4Config *self = NM_SETTING_IP4_CONFIG (object);
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (self);

	g_free (priv->method);

	g_array_free (priv->dns, TRUE);

	nm_utils_slist_free (priv->dns_search, g_free);
	nm_utils_slist_free (priv->addresses, (GDestroyNotify) nm_ip4_address_unref);
	nm_utils_slist_free (priv->routes, (GDestroyNotify) nm_ip4_route_unref);

	G_OBJECT_CLASS (nm_setting_ip4_config_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingIP4Config *setting = NM_SETTING_IP4_CONFIG (object);
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_METHOD:
		g_free (priv->method);
		priv->method = g_value_dup_string (value);
		break;
	case PROP_DNS:
		g_array_free (priv->dns, TRUE);
		priv->dns = g_value_dup_boxed (value);
		if (!priv->dns)
			priv->dns = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 3);			
		break;
	case PROP_DNS_SEARCH:
		nm_utils_slist_free (priv->dns_search, g_free);
		priv->dns_search = g_value_dup_boxed (value);
		break;
	case PROP_ADDRESSES:
		nm_utils_slist_free (priv->addresses, (GDestroyNotify) nm_ip4_address_unref);
		priv->addresses = nm_utils_ip4_addresses_from_gvalue (value);
		break;
	case PROP_ROUTES:
		nm_utils_slist_free (priv->routes, (GDestroyNotify) nm_ip4_route_unref);
		priv->routes = nm_utils_ip4_routes_from_gvalue (value);
		break;
	case PROP_IGNORE_AUTO_ROUTES:
		priv->ignore_auto_routes = g_value_get_boolean (value);
		break;
	case PROP_IGNORE_AUTO_DNS:
		priv->ignore_auto_dns = g_value_get_boolean (value);
		break;
	case PROP_DHCP_CLIENT_ID:
		g_free (priv->dhcp_client_id);
		priv->dhcp_client_id = g_value_dup_string (value);
		break;
	case PROP_DHCP_SEND_HOSTNAME:
		priv->dhcp_send_hostname = g_value_get_boolean (value);
		break;
	case PROP_DHCP_HOSTNAME:
		g_free (priv->dhcp_hostname);
		priv->dhcp_hostname = g_value_dup_string (value);
		/* FIXME: Is this a good idea? */
		if (priv->dhcp_hostname)
			priv->dhcp_send_hostname = TRUE;
		break;
	case PROP_NEVER_DEFAULT:
		priv->never_default = g_value_get_boolean (value);
		break;
	case PROP_MAY_FAIL:
		priv->may_fail = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMSettingIP4Config *setting = NM_SETTING_IP4_CONFIG (object);
	NMSettingIP4ConfigPrivate *priv = NM_SETTING_IP4_CONFIG_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_METHOD:
		g_value_set_string (value, nm_setting_ip4_config_get_method (setting));
		break;
	case PROP_DNS:
		g_value_set_boxed (value, priv->dns);
		break;
	case PROP_DNS_SEARCH:
		g_value_set_boxed (value, priv->dns_search);
		break;
	case PROP_ADDRESSES:
		nm_utils_ip4_addresses_to_gvalue (priv->addresses, value);
		break;
	case PROP_ROUTES:
		nm_utils_ip4_routes_to_gvalue (priv->routes, value);
		break;
	case PROP_IGNORE_AUTO_ROUTES:
		g_value_set_boolean (value, nm_setting_ip4_config_get_ignore_auto_routes (setting));
		break;
	case PROP_IGNORE_AUTO_DNS:
		g_value_set_boolean (value, nm_setting_ip4_config_get_ignore_auto_dns (setting));
		break;
	case PROP_DHCP_CLIENT_ID:
		g_value_set_string (value, nm_setting_ip4_config_get_dhcp_client_id (setting));
		break;
	case PROP_DHCP_SEND_HOSTNAME:
		g_value_set_boolean (value, nm_setting_ip4_config_get_dhcp_send_hostname (setting));
		break;
	case PROP_DHCP_HOSTNAME:
		g_value_set_string (value, nm_setting_ip4_config_get_dhcp_hostname (setting));
		break;
	case PROP_NEVER_DEFAULT:
		g_value_set_boolean (value, priv->never_default);
		break;
	case PROP_MAY_FAIL:
		g_value_set_boolean (value, priv->may_fail);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_ip4_config_class_init (NMSettingIP4ConfigClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingIP4ConfigPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */
	/**
	 * NMSettingIP4Config:method:
	 *
	 * IPv4 configuration method.  If 'auto' is specified then the appropriate
	 * automatic method (DHCP, PPP, etc) is used for the interface and most
	 * other properties can be left unset.  If 'link-local' is specified, then a
	 * link-local address in the 169.254/16 range will be assigned to the
	 * interface.  If 'manual' is specified, static IP addressing is used and at
	 * least one IP address must be given in the 'addresses' property.  If
	 * 'shared' is specified (indicating that this connection will provide
	 * network access to other computers) then the interface is assigned an
	 * address in the 10.42.x.1/24 range and a DHCP and forwarding DNS server
	 * are started, and the interface is NAT-ed to the current default network
	 * connection.  'disabled' means IPv4 will not be used on this connection.
	 * This property must be set.
	 **/
	g_object_class_install_property
		(object_class, PROP_METHOD,
		 g_param_spec_string (NM_SETTING_IP4_CONFIG_METHOD,
						      "Method",
						      "IPv4 configuration method.  If 'auto' is specified "
						      "then the appropriate automatic method (DHCP, PPP, "
						      "etc) is used for the interface and most other "
						      "properties can be left unset.  If 'link-local' "
						      "is specified, then a link-local address in the "
						      "169.254/16 range will be assigned to the "
						      "interface.  If 'manual' is specified, static IP "
						      "addressing is used and at least one IP address "
						      "must be given in the 'addresses' property.  If "
						      "'shared' is specified (indicating that this "
						      "connection will provide network access to other "
						      "computers) then the interface is assigned an "
						      "address in the 10.42.x.1/24 range and a DHCP and "
						      "forwarding DNS server are started, and the "
						      "interface is NAT-ed to the current default network "
						      "connection.  'disabled' means IPv4 will not be "
						      "used on this connection.  This property must be set.",
						      NULL,
						      G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP4Config:dns:
	 *
	 * List of DNS servers (network byte order).  For the 'auto' method, these
	 * DNS servers are appended to those (if any) returned by automatic
	 * configuration.  DNS servers cannot be used with the 'shared', 'link-local',
	 * or 'disabled' methods as there is no usptream network.  In all other
	 * methods, these DNS servers are used as the only DNS servers for this
	 * connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS,
		 _nm_param_spec_specialized (NM_SETTING_IP4_CONFIG_DNS,
							   "DNS",
							   "List of DNS servers (network byte order). For "
							   "the 'auto' method, these DNS servers are "
							   "appended to those (if any) returned by automatic "
							   "configuration.  DNS servers cannot be used with "
							   "the 'shared', 'link-local', or 'disabled' "
							   "methods as there is no usptream network.  In all "
							   "other methods, these DNS servers are used as the "
							   "only DNS servers for this connection.",
							   DBUS_TYPE_G_UINT_ARRAY,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP4Config:dns-search:
	 *
	 * List of DNS search domains.  For the 'auto' method, these search domains
	 * are appended to those returned by automatic configuration. Search domains
	 * cannot be used with the 'shared', 'link-local', or 'disabled' methods as
	 * there is no upstream network.  In all other methods, these search domains
	 * are used as the only search domains for this connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS_SEARCH,
		 _nm_param_spec_specialized (NM_SETTING_IP4_CONFIG_DNS_SEARCH,
							   "DNS search",
							   "List of DNS search domains.  For the 'auto' "
							   "method, these search domains are appended to "
							   "those returned by automatic configuration. "
							   "Search domains cannot be used with the 'shared', "
							   "'link-local', or 'disabled' methods as there is "
							   "no upstream network.  In all other methods, these "
							   "search domains are used as the only search domains "
							   "for this connection.",
							   DBUS_TYPE_G_LIST_OF_STRING,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP4Config:addresses:
	 *
	 * Array of IPv4 address structures.  Each IPv4 address structure is
	 * composed of 3 32-bit values; the first being the IPv4 address (network
	 * byte order), the second the prefix (1 - 32), and last the IPv4 gateway
	 * (network byte order). The gateway may be left as 0 if no gateway exists
	 * for that subnet.  For the 'auto' method, given IP addresses are appended
	 * to those returned by automatic configuration.  Addresses cannot be used
	 * with the 'shared', 'link-local', or 'disabled' methods as addressing is
	 * either automatic or disabled with these methods.
	 **/
	g_object_class_install_property
		(object_class, PROP_ADDRESSES,
		 _nm_param_spec_specialized (NM_SETTING_IP4_CONFIG_ADDRESSES,
							   "Addresses",
							   "Array of IPv4 address structures.  Each IPv4 "
							   "address structure is composed of 3 32-bit values; "
							   "the first being the IPv4 address (network byte "
							   "order), the second the prefix (1 - 32), and "
							   "last the IPv4 gateway (network byte order). The "
							   "gateway may be left as 0 if no gateway exists "
							   "for that subnet.  For the 'auto' method, given "
							   "IP addresses are appended to those returned by "
							   "automatic configuration.  Addresses cannot be "
							   "used with the 'shared', 'link-local', or "
							   "'disabled' methods as addressing is either "
							   "automatic or disabled with these methods.",
							   DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP4Config:routes:
	 *
	 * Array of IPv4 route structures.  Each IPv4 route structure is composed
	 * of 4 32-bit values; the first being the destination IPv4 network or
	 * address (network byte order), the second the destination network or
	 * address prefix (1 - 32), the third being the next-hop (network byte
	 * order) if any, and the fourth being the route metric. For the 'auto'
	 * method, given IP routes are appended to those returned by automatic
	 * configuration.  Routes cannot be used with the 'shared', 'link-local',
	 * or 'disabled' methods because there is no upstream network.
	 **/
	g_object_class_install_property
		(object_class, PROP_ROUTES,
		 _nm_param_spec_specialized (NM_SETTING_IP4_CONFIG_ROUTES,
							   "Routes",
							   "Array of IPv4 route structures.  Each IPv4 route "
							   "structure is composed of 4 32-bit values; the "
							   "first being the destination IPv4 network or "
							   "address (network byte order), the second the "
							   "destination network or address prefix (1 - 32), "
							   "the third being the next-hop (network byte order) "
							   "if any, and the fourth being the route metric. "
							   "For the 'auto' method, given IP routes are "
							   "appended to those returned by automatic "
							   "configuration.  Routes cannot be used with the "
							   "'shared', 'link-local', or 'disabled', methods "
							   "as there is no upstream network.",
							   DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP4Config:ignore-auto-routes:
	 *
	 * When the method is set to 'auto' and this property to TRUE, automatically
	 * configured routes are ignored and only routes specified in
	 * #NMSettingIP4Config:routes, if any, are used.
	 **/
	g_object_class_install_property
		(object_class, PROP_IGNORE_AUTO_ROUTES,
		 g_param_spec_boolean (NM_SETTING_IP4_CONFIG_IGNORE_AUTO_ROUTES,
						   "Ignore automatic routes",
						   "When the method is set to 'auto' and this property "
						   "to TRUE, automatically configured routes are "
						   "ignored and only routes specified in the 'routes' "
						   "property, if any, are used.",
						   FALSE,
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP4Config:ignore-auto-dns:
	 *
	 * When the method is set to 'auto' and this property to TRUE, automatically
	 * configured nameservers and search domains are ignored and only nameservers
	 * and search domains specified in #NMSettingIP4Config:dns and
	 * #NMSettingIP4Config:dns-search, if any, are used.
	 **/
	g_object_class_install_property
		(object_class, PROP_IGNORE_AUTO_DNS,
		 g_param_spec_boolean (NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS,
						   "Ignore automatic DNS",
						   "When the method is set to 'auto' and this property "
						   "to TRUE, automatically configured nameservers and "
						   "search domains are ignored and only nameservers and "
						   "search domains specified in the 'dns' and 'dns-search' "
						   "properties, if any, are used.",
						   FALSE,
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP4Config:dhcp-client-id:
	 *
	 * A string sent to the DHCP server to identify the local machine which the
	 * DHCP server may use to cusomize the DHCP lease and options.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP_CLIENT_ID,
		 g_param_spec_string (NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID,
						   "DHCP Client ID",
						   "A string sent to the DHCP server to identify the "
						   "local machine which the DHCP server may use to "
						   "cusomize the DHCP lease and options.",
						   NULL,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP4Config:dhcp-send-hostname:
	 *
	 * If TRUE, a hostname is sent to the DHCP server when acquiring a lease.
	 * Some DHCP servers use this hostname to update DNS databases, essentially
	 * providing a static hostname for the computer.  If
	 * #NMSettingIP4Config:dhcp-hostname is empty and this property is TRUE,
	 * the current persistent hostname of the computer is sent.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP_SEND_HOSTNAME,
		 g_param_spec_boolean (NM_SETTING_IP4_CONFIG_DHCP_SEND_HOSTNAME,
						   "Send DHCP hostname",
						   "If TRUE, a hostname is sent to the DHCP server when "
						   "acquiring a lease.  Some DHCP servers use this "
						   "hostname to update DNS databases, essentially "
						   "providing a static hostname for the computer.  If "
						   "the 'dhcp-hostname' property is empty and this "
						   "property is TRUE, the current persistent hostname "
						   "of the computer is sent.",
						   FALSE,
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP4Config:dhcp-hostname:
	 *
	 * If the #NMSettingIP4Config:dhcp-send-hostname property is TRUE, then the
	 * specified name will be sent to the DHCP server when acquiring a lease.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP_HOSTNAME,
		 g_param_spec_string (NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME,
						   "DHCP Hostname",
						   "If the 'dhcp-send-hostname' property is TRUE, then "
						   "the specified name will be sent to the DHCP server "
						   "when acquiring a lease.",
						   NULL,
						   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP4Config:never-default:
	 *
	 * If TRUE, this connection will never be the default IPv4 connection,
	 * meaning it will never be assigned the default route by NetworkManager.
	 **/
	g_object_class_install_property
		(object_class, PROP_NEVER_DEFAULT,
		 g_param_spec_boolean (NM_SETTING_IP4_CONFIG_NEVER_DEFAULT,
						   "Never default",
						   "If TRUE, this connection will never be the default "
						   "IPv4 connection, meaning it will never be assigned "
						   "the default route by NetworkManager.",
						   FALSE,
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP4Config:may-fail:
	 *
	 * If TRUE, allow overall network configuration to proceed even if IPv4
	 * configuration times out.  Note that at least one IP configuration
	 * must succeed or overall network configuration will still fail.  For
	 * example, in IPv6-only networks, setting this property to TRUE allows
	 * the overall network configuration to succeed if IPv4 configuration fails
	 * but IPv6 configuration completes successfully.
	 **/
	g_object_class_install_property
		(object_class, PROP_MAY_FAIL,
		 g_param_spec_boolean (NM_SETTING_IP4_CONFIG_MAY_FAIL,
						   "May Fail",
						   "If TRUE, allow overall network configuration to "
						   "proceed even if IPv4 configuration times out. "
						   "Note that at least one IP configuration must "
						   "succeed or overall network configuration will still "
						   "fail.  For example, in IPv6-only networks, setting "
						   "this property to TRUE allows the overall network "
						   "configuration to succeed if IPv4 configuration "
						   "fails but IPv6 configuration completes successfully.",
						   FALSE,
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));
}


struct NMIP4Address {
	guint32 refcount;
	guint32 address;   /* network byte order */
	guint32 prefix;
	guint32 gateway;   /* network byte order */
};

NMIP4Address *
nm_ip4_address_new (void)
{
	NMIP4Address *address;

	address = g_malloc0 (sizeof (NMIP4Address));
	address->refcount = 1;
	return address;
}

NMIP4Address *
nm_ip4_address_dup (NMIP4Address *source)
{
	NMIP4Address *address;

	g_return_val_if_fail (source != NULL, NULL);
	g_return_val_if_fail (source->refcount > 0, NULL);

	address = nm_ip4_address_new ();
	address->address = source->address;
	address->prefix = source->prefix;
	address->gateway = source->gateway;

	return address;
}

void
nm_ip4_address_ref (NMIP4Address *address)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->refcount++;
}

void
nm_ip4_address_unref (NMIP4Address *address)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->refcount--;
	if (address->refcount == 0) {
		memset (address, 0, sizeof (NMIP4Address));
		g_free (address);
	}
}

gboolean
nm_ip4_address_compare (NMIP4Address *address, NMIP4Address *other)
{
	g_return_val_if_fail (address != NULL, FALSE);
	g_return_val_if_fail (address->refcount > 0, FALSE);

	g_return_val_if_fail (other != NULL, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	if (   address->address != other->address
	    || address->prefix != other->prefix
	    || address->gateway != other->gateway)
		return FALSE;
	return TRUE;
}

guint32
nm_ip4_address_get_address (NMIP4Address *address)
{
	g_return_val_if_fail (address != NULL, 0);
	g_return_val_if_fail (address->refcount > 0, 0);

	return address->address;
}

void
nm_ip4_address_set_address (NMIP4Address *address, guint32 addr)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->address = addr;
}

guint32
nm_ip4_address_get_prefix (NMIP4Address *address)
{
	g_return_val_if_fail (address != NULL, 0);
	g_return_val_if_fail (address->refcount > 0, 0);

	return address->prefix;
}

void
nm_ip4_address_set_prefix (NMIP4Address *address, guint32 prefix)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->prefix = prefix;
}

guint32
nm_ip4_address_get_gateway (NMIP4Address *address)
{
	g_return_val_if_fail (address != NULL, 0);
	g_return_val_if_fail (address->refcount > 0, 0);

	return address->gateway;
}

void
nm_ip4_address_set_gateway (NMIP4Address *address, guint32 gateway)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->gateway = gateway;
}


struct NMIP4Route {
	guint32 refcount;

	guint32 dest;   /* network byte order */
	guint32 prefix;
	guint32 next_hop;   /* network byte order */
	guint32 metric;    /* lower metric == more preferred */
};

NMIP4Route *
nm_ip4_route_new (void)
{
	NMIP4Route *route;

	route = g_malloc0 (sizeof (NMIP4Route));
	route->refcount = 1;
	return route;
}

NMIP4Route *
nm_ip4_route_dup (NMIP4Route *source)
{
	NMIP4Route *route;

	g_return_val_if_fail (source != NULL, NULL);
	g_return_val_if_fail (source->refcount > 0, NULL);

	route = nm_ip4_route_new ();
	route->dest = source->dest;
	route->prefix = source->prefix;
	route->next_hop = source->next_hop;
	route->metric = source->metric;

	return route;
}

void
nm_ip4_route_ref (NMIP4Route *route)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->refcount++;
}

void
nm_ip4_route_unref (NMIP4Route *route)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->refcount--;
	if (route->refcount == 0) {
		memset (route, 0, sizeof (NMIP4Route));
		g_free (route);
	}
}

gboolean
nm_ip4_route_compare (NMIP4Route *route, NMIP4Route *other)
{
	g_return_val_if_fail (route != NULL, FALSE);
	g_return_val_if_fail (route->refcount > 0, FALSE);

	g_return_val_if_fail (other != NULL, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	if (   route->dest != other->dest
	    || route->prefix != other->prefix
	    || route->next_hop != other->next_hop
	    || route->metric != other->metric)
		return FALSE;
	return TRUE;
}

guint32
nm_ip4_route_get_dest (NMIP4Route *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->dest;
}

void
nm_ip4_route_set_dest (NMIP4Route *route, guint32 dest)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->dest = dest;
}

guint32
nm_ip4_route_get_prefix (NMIP4Route *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->prefix;
}

void
nm_ip4_route_set_prefix (NMIP4Route *route, guint32 prefix)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->prefix = prefix;
}

guint32
nm_ip4_route_get_next_hop (NMIP4Route *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->next_hop;
}

void
nm_ip4_route_set_next_hop (NMIP4Route *route, guint32 next_hop)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->next_hop = next_hop;
}

guint32
nm_ip4_route_get_metric (NMIP4Route *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->metric;
}

void
nm_ip4_route_set_metric (NMIP4Route *route, guint32 metric)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->metric = metric;
}

