/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * David Cantrell <dcantrel@redhat.com>
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
 */

#include <string.h>

#include <dbus/dbus-glib.h>
#include "nm-setting-ip6-config.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"

GQuark
nm_setting_ip6_config_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-ip6-config-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_ip6_config_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_IP6_CONFIG_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_IP6_CONFIG_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_IP6_CONFIG_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The specified property was not allowed in combination with the current 'method' */
			ENUM_ENTRY (NM_SETTING_IP6_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD, "NotAllowedForMethod"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingIP6ConfigError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingIP6Config, nm_setting_ip6_config, NM_TYPE_SETTING)

#define NM_SETTING_IP6_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_IP6_CONFIG, NMSettingIP6ConfigPrivate))

typedef struct {
	char *method;
	GSList *dns;        /* array of struct in6_addr */
	GSList *dns_search; /* list of strings */
	GSList *addresses;  /* array of NMIP6Address */
	GSList *routes;     /* array of NMIP6Route */
	gboolean ignore_auto_routes;
	gboolean ignore_auto_dns;
	gboolean never_default;
	gboolean may_fail;
} NMSettingIP6ConfigPrivate;


enum {
	PROP_0,
	PROP_METHOD,
	PROP_DNS,
	PROP_DNS_SEARCH,
	PROP_ADDRESSES,
	PROP_ROUTES,
	PROP_IGNORE_AUTO_ROUTES,
	PROP_IGNORE_AUTO_DNS,
	PROP_NEVER_DEFAULT,
	PROP_MAY_FAIL,

	LAST_PROP
};

NMSetting *
nm_setting_ip6_config_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_IP6_CONFIG, NULL);
}

const char *
nm_setting_ip6_config_get_method (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NULL);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->method;
}

guint32
nm_setting_ip6_config_get_num_dns (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), 0);

	return g_slist_length (NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->dns);
}

const struct in6_addr *
nm_setting_ip6_config_get_dns (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;
	

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), 0);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->dns), NULL);

	return (const struct in6_addr *) g_slist_nth_data (priv->dns, i);
}

gboolean
nm_setting_ip6_config_add_dns (NMSettingIP6Config *setting, const struct in6_addr *addr)
{
	NMSettingIP6ConfigPrivate *priv;
	struct in6_addr *copy;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->dns; iter; iter = g_slist_next (iter)) {
		if (!memcmp (addr, (struct in6_addr *) iter->data, sizeof (struct in6_addr)))
			return FALSE;
	}

	copy = g_malloc0 (sizeof (struct in6_addr));
	memcpy (copy, addr, sizeof (struct in6_addr));
	priv->dns = g_slist_append (priv->dns, copy);

	return TRUE;
}

void
nm_setting_ip6_config_remove_dns (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->dns, i);
	g_return_if_fail (elt != NULL);

	g_free (elt->data);
	priv->dns = g_slist_delete_link (priv->dns, elt);
}

void
nm_setting_ip6_config_clear_dns (NMSettingIP6Config *setting)
{
	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	nm_utils_slist_free (NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->dns, g_free);
	NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->dns = NULL;
}

guint32
nm_setting_ip6_config_get_num_dns_searches (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), 0);

	return g_slist_length (NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->dns_search);
}

const char *
nm_setting_ip6_config_get_dns_search (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NULL);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->dns_search), NULL);

	return (const char *) g_slist_nth_data (priv->dns_search, i);
}

gboolean
nm_setting_ip6_config_add_dns_search (NMSettingIP6Config *setting,
                                      const char *dns_search)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns_search != NULL, FALSE);
	g_return_val_if_fail (dns_search[0] != '\0', FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->dns_search; iter; iter = g_slist_next (iter)) {
		if (!strcmp (dns_search, (char *) iter->data))
			return FALSE;
	}

	priv->dns_search = g_slist_append (priv->dns_search, g_strdup (dns_search));
	return TRUE;
}

void
nm_setting_ip6_config_remove_dns_search (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->dns_search, i);
	g_return_if_fail (elt != NULL);

	g_free (elt->data);
	priv->dns_search = g_slist_delete_link (priv->dns_search, elt);
}

void
nm_setting_ip6_config_clear_dns_searches (NMSettingIP6Config *setting)
{
	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	nm_utils_slist_free (NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->dns_search, g_free);
	NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->dns_search = NULL;
}

guint32
nm_setting_ip6_config_get_num_addresses (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), 0);

	return g_slist_length (NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->addresses);
}

NMIP6Address *
nm_setting_ip6_config_get_address (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NULL);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->addresses), NULL);

	return (NMIP6Address *) g_slist_nth_data (priv->addresses, i);
}

gboolean
nm_setting_ip6_config_add_address (NMSettingIP6Config *setting,
                                   NMIP6Address *address)
{
	NMSettingIP6ConfigPrivate *priv;
	NMIP6Address *copy;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	g_return_val_if_fail (address != NULL, FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->addresses; iter; iter = g_slist_next (iter)) {
		if (nm_ip6_address_compare ((NMIP6Address *) iter->data, address))
			return FALSE;
	}

	copy = nm_ip6_address_dup (address);
	g_return_val_if_fail (copy != NULL, FALSE);

	priv->addresses = g_slist_append (priv->addresses, copy);
	return TRUE;
}

void
nm_setting_ip6_config_remove_address (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->addresses, i);
	g_return_if_fail (elt != NULL);

	nm_ip6_address_unref ((NMIP6Address *) elt->data);
	priv->addresses = g_slist_delete_link (priv->addresses, elt);
}

void
nm_setting_ip6_config_clear_addresses (NMSettingIP6Config *setting)
{
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);

	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	nm_utils_slist_free (priv->addresses, (GDestroyNotify) nm_ip6_address_unref);
	priv->addresses = NULL;
}

guint32
nm_setting_ip6_config_get_num_routes (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), 0);

	return g_slist_length (NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->routes);
}

NMIP6Route *
nm_setting_ip6_config_get_route (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), NULL);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (i <= g_slist_length (priv->routes), NULL);

	return (NMIP6Route *) g_slist_nth_data (priv->routes, i);
}

gboolean
nm_setting_ip6_config_add_route (NMSettingIP6Config *setting,
                                 NMIP6Route *route)
{
	NMSettingIP6ConfigPrivate *priv;
	NMIP6Route *copy;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	g_return_val_if_fail (route != NULL, FALSE);

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	for (iter = priv->routes; iter; iter = g_slist_next (iter)) {
		if (nm_ip6_route_compare ((NMIP6Route *) iter->data, route))
			return FALSE;
	}

	copy = nm_ip6_route_dup (route);
	g_return_val_if_fail (copy != NULL, FALSE);

	priv->routes = g_slist_append (priv->routes, copy);
	return TRUE;
}

void
nm_setting_ip6_config_remove_route (NMSettingIP6Config *setting, guint32 i)
{
	NMSettingIP6ConfigPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->routes, i);
	g_return_if_fail (elt != NULL);

	nm_ip6_route_unref ((NMIP6Route *) elt->data);
	priv->routes = g_slist_delete_link (priv->routes, elt);
}

void
nm_setting_ip6_config_clear_routes (NMSettingIP6Config *setting)
{
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);

	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	nm_utils_slist_free (priv->routes, (GDestroyNotify) nm_ip6_route_unref);
	priv->routes = NULL;
}

gboolean
nm_setting_ip6_config_get_ignore_auto_routes (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->ignore_auto_routes;
}

gboolean
nm_setting_ip6_config_get_ignore_auto_dns (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->ignore_auto_dns;
}

gboolean
nm_setting_ip6_config_get_never_default (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->never_default;
}

gboolean
nm_setting_ip6_config_get_may_fail (NMSettingIP6Config *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);

	return NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting)->may_fail;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (setting);

	if (!priv->method) {
		g_set_error (error,
		             NM_SETTING_IP6_CONFIG_ERROR,
		             NM_SETTING_IP6_CONFIG_ERROR_MISSING_PROPERTY,
		             NM_SETTING_IP6_CONFIG_METHOD);
		return FALSE;
	}

	if (!strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		if (!priv->addresses) {
			g_set_error (error,
			             NM_SETTING_IP6_CONFIG_ERROR,
			             NM_SETTING_IP6_CONFIG_ERROR_MISSING_PROPERTY,
			             NM_SETTING_IP6_CONFIG_ADDRESSES);
			return FALSE;
		}
	} else if (   !strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)
	           || !strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL)
	           || !strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_SHARED)) {
		if (g_slist_length (priv->dns)) {
			g_set_error (error,
			             NM_SETTING_IP6_CONFIG_ERROR,
			             NM_SETTING_IP6_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
			             NM_SETTING_IP6_CONFIG_DNS);
			return FALSE;
		}

		if (g_slist_length (priv->dns_search)) {
			g_set_error (error,
			             NM_SETTING_IP6_CONFIG_ERROR,
			             NM_SETTING_IP6_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
			             NM_SETTING_IP6_CONFIG_DNS_SEARCH);
			return FALSE;
		}

		if (g_slist_length (priv->addresses)) {
			g_set_error (error,
			             NM_SETTING_IP6_CONFIG_ERROR,
			             NM_SETTING_IP6_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD,
			             NM_SETTING_IP6_CONFIG_ADDRESSES);
			return FALSE;
		}
	} else if (   !strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_AUTO)
	           || !strcmp (priv->method, NM_SETTING_IP6_CONFIG_METHOD_DHCP)) {
		/* nothing to do */
	} else {
		g_set_error (error,
		             NM_SETTING_IP6_CONFIG_ERROR,
		             NM_SETTING_IP6_CONFIG_ERROR_INVALID_PROPERTY,
		             NM_SETTING_IP6_CONFIG_METHOD);
		return FALSE;
	}

	return TRUE;
}


static void
nm_setting_ip6_config_init (NMSettingIP6Config *setting)
{
	g_object_set (setting, NM_SETTING_NAME, NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (object);

	g_free (priv->method);

	if (priv->dns)
		g_slist_free (priv->dns);

	nm_utils_slist_free (priv->dns_search, g_free);
	nm_utils_slist_free (priv->addresses, g_free);
	nm_utils_slist_free (priv->routes, g_free);

	G_OBJECT_CLASS (nm_setting_ip6_config_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_METHOD:
		g_free (priv->method);
		priv->method = g_value_dup_string (value);
		break;
	case PROP_DNS:
		nm_utils_slist_free (priv->dns, g_free);
		priv->dns = nm_utils_ip6_dns_from_gvalue (value);
		break;
	case PROP_DNS_SEARCH:
		nm_utils_slist_free (priv->dns_search, g_free);
		priv->dns_search = g_value_dup_boxed (value);
		break;
	case PROP_ADDRESSES:
		nm_utils_slist_free (priv->addresses, g_free);
		priv->addresses = nm_utils_ip6_addresses_from_gvalue (value);
		break;
	case PROP_ROUTES:
		nm_utils_slist_free (priv->routes, g_free);
		priv->routes = nm_utils_ip6_routes_from_gvalue (value);
		break;
	case PROP_IGNORE_AUTO_ROUTES:
		priv->ignore_auto_routes = g_value_get_boolean (value);
		break;
	case PROP_IGNORE_AUTO_DNS:
		priv->ignore_auto_dns = g_value_get_boolean (value);
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
	NMSettingIP6ConfigPrivate *priv = NM_SETTING_IP6_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_METHOD:
		g_value_set_string (value, priv->method);
		break;
	case PROP_DNS:
		nm_utils_ip6_dns_to_gvalue (priv->dns, value);
		break;
	case PROP_DNS_SEARCH:
		g_value_set_boxed (value, priv->dns_search);
		break;
	case PROP_ADDRESSES:
		nm_utils_ip6_addresses_to_gvalue (priv->addresses, value);
		break;
	case PROP_ROUTES:
		nm_utils_ip6_routes_to_gvalue (priv->routes, value);
		break;
	case PROP_IGNORE_AUTO_ROUTES:
		g_value_set_boolean (value, priv->ignore_auto_routes);
		break;
	case PROP_IGNORE_AUTO_DNS:
		g_value_set_boolean (value, priv->ignore_auto_dns);
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
nm_setting_ip6_config_class_init (NMSettingIP6ConfigClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingIP6ConfigPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */
	/**
	 * NMSettingIP6Config:method:
	 *
	 * IPv6 configuration method.  If 'auto' is specified then the appropriate
	 * automatic method (DHCP, PPP, advertisement, etc) is used for the
	 * interface and most other properties can be left unset.  To force the use
	 * of DHCP only, specify 'dhcp'; this  method is only valid for ethernet-
	 * based hardware.  If 'link-local' is specified, then an IPv6 link-local
	 * address will be assigned to the interface.  If 'manual' is specified,
	 * static IP addressing is used and at least one IP address must be given
	 * in the 'addresses' property.  If 'ignored' is specified, IPv6
	 * configuration is not done. This property must be set.  NOTE: the 'shared'
	 * method are not yet supported.
	 **/
	g_object_class_install_property
		(object_class, PROP_METHOD,
		 g_param_spec_string (NM_SETTING_IP6_CONFIG_METHOD,
						      "Method",
						      "IPv6 configuration method.  If 'auto' is specified "
						      "then the appropriate automatic method (PPP, router "
						      "advertisement, etc) is used for the device and "
						      "most other properties can be left unset.  To force "
						      "the use of DHCP only, specify 'dhcp'; this method "
						      "is only valid for ethernet-based hardware.  If "
						      "'link-local' is specified, then an IPv6 link-local "
						      "address will be assigned to the interface.  If "
						      "'manual' is specified, static IP addressing is "
						      "used and at least one IP address must be given in "
						      " the 'addresses' property.  If 'ignored' is "
						      "specified, IPv6 configuration is not done. This "
						      "property must be set.  NOTE: the 'shared' method"
						      "is not yet supported.",
						      NULL,
						      G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP6Config:dns:
	 *
	 * Array of DNS servers, where each member of the array is a byte array
	 * containing the IPv6 address of the DNS server (in network byte order).
	 * For the 'auto' method, these DNS servers are appended to those (if any)
	 * returned by automatic configuration.  DNS servers cannot be used with
	 * the 'shared' or 'link-local' methods as there is no usptream network. In
	 * all other methods, these DNS servers are used as the only DNS servers for
	 * this connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS,
		 _nm_param_spec_specialized (NM_SETTING_IP6_CONFIG_DNS,
							   "DNS",
							   "Array of DNS servers, where each member of the "
							   "array is a byte array containing the IPv6 address "
							   "of the DNS server (in network byte order). For "
							   "the 'auto' method, these DNS servers are "
							   "appended to those (if any) returned by automatic "
							   "configuration.  DNS servers cannot be used with "
							   "the 'shared' or 'link-local' methods as there is "
							   "no usptream network.  In all other methods, "
							   "these DNS servers are used as the only DNS "
							   "servers for this connection.",
							   DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UCHAR,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP6Config:dns-search:
	 *
	 * List of DNS search domains.  For the 'auto' method, these search domains
	 * are appended to those returned by automatic configuration. Search domains
	 * cannot be used with the 'shared' or 'link-local' methods as there is no
	 * upstream network.  In all other methods, these search domains are used
	 * as the only search domains for this connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS_SEARCH,
		 _nm_param_spec_specialized (NM_SETTING_IP6_CONFIG_DNS_SEARCH,
							   "DNS search",
							   "List of DNS search domains.  For the 'auto' "
							   "method, these search domains are appended to "
							   "those returned by automatic configuration. "
							   "Search domains cannot be used with the 'shared' "
							   "or 'link-local' methods as there is no upstream "
							   "network.  In all other methods, these search "
							   "domains are used as the only search domains for "
							   "this connection.",
							   DBUS_TYPE_G_LIST_OF_STRING,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP6Config:addresses:
	 *
	 * Array of IPv6 address structures.  Each IPv6 address structure is
	 * composed of 3 members, the first being a byte array containing the IPv6
	 * address (network byte order), the second a 32-bit integer containing the
	 * IPv6 address prefix, and the third a byte array containing the IPv6
	 * address (network byte order) of the gateway associated with this address,
	 * if any.  If no gateway is given, the third element should be given as
	 * all zeros.  For the 'auto' method, given IP addresses are appended to
	 * those returned by automatic configuration.  Addresses cannot be used with
	 * the 'shared' or 'link-local' methods as the interface is automatically
	 * assigned an address with these methods.
	 **/
	g_object_class_install_property
		(object_class, PROP_ADDRESSES,
		 _nm_param_spec_specialized (NM_SETTING_IP6_CONFIG_ADDRESSES,
							   "Addresses",
							   "Array of IPv6 address structures.  Each IPv6 "
							   "address structure is composed of 3 members, the "
							   "first being a byte array containing the IPv6 "
							   "address (network byte order), the second a "
							   "32-bit integer containing the IPv6 address "
							   "prefix, and the third a byte array containing "
							   "the IPv6 address (network byte order) of the "
							   "gateway associated with this address, if any. "
							   "If no gateway is given, the third element should "
							   "be given as all zeros.  For the 'auto' method, "
							   "given IP addresses are appended to those returned "
							   "by automatic configuration.  Addresses cannot be "
							   "used with the 'shared' or 'link-local' methods "
							   "as the interface is automatically assigned an "
							   "address with these methods.",
							   DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP6Config:routes:
	 *
	 * Array of IPv6 route structures.  Each IPv6 route structure is composed
	 * of 4 members; the first being the destination IPv6 network or
	 * address (network byte order) as a byte array, the second the destination
	 * network or address IPv6 prefix, the third being the next-hop IPv6 address
	 * (network byte order) if any, and the fourth being the route metric. For
	 * the 'auto' method, given IP routes are appended to those returned by
	 * automatic configuration.  Routes cannot be used with the 'shared' or
	 * 'link-local' methods because there is no upstream network.
	 **/
	g_object_class_install_property
		(object_class, PROP_ROUTES,
		 _nm_param_spec_specialized (NM_SETTING_IP6_CONFIG_ROUTES,
							   "Routes",
							   "Array of IPv6 route structures.  Each IPv6 route "
							   "structure is composed of 4 members; the first "
							   "being the destination IPv6 network or address "
							   "(network byte order) as a byte array, the second "
							   "the destination network or address IPv6 prefix, "
							   "the third being the next-hop IPv6 address "
							   "(network byte order) if any, and the fourth "
							   "being the route metric. For the 'auto' method, "
							   "given IP routes are appended to those returned "
							   "by automatic configuration.  Routes cannot be "
							   "used with the 'shared' or 'link-local' methods "
							   "because there is no upstream network.",
							   DBUS_TYPE_G_ARRAY_OF_IP6_ROUTE,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP6Config:ignore-auto-routes:
	 *
	 * When the method is set to 'auto' or 'dhcp' and this property is set to
	 * TRUE, automatically configured routes are ignored and only routes
	 * specified in #NMSettingIP6Config:routes, if any, are used.
	 **/
	g_object_class_install_property
		(object_class, PROP_IGNORE_AUTO_ROUTES,
		 g_param_spec_boolean (NM_SETTING_IP6_CONFIG_IGNORE_AUTO_ROUTES,
						   "Ignore automatic routes",
						   "When the method is set to 'auto' or 'dhcp' and this "
						   "property is set to TRUE, automatically configured "
						   "routes are ignored and only routes specified in the "
						   "'routes' property, if any, are used.",
						   FALSE,
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP6Config:ignore-auto-dns:
	 *
	 * When the method is set to 'auto' or 'dhcp' and this property is set to
	 * TRUE, automatically configured nameservers and search domains are ignored
	 * and only nameservers and search domains specified in
	 * #NMSettingIP6Config:dns and #NMSettingIP6Config:dns-search, if any, are
	 * used.
	 **/
	g_object_class_install_property
		(object_class, PROP_IGNORE_AUTO_DNS,
		 g_param_spec_boolean (NM_SETTING_IP6_CONFIG_IGNORE_AUTO_DNS,
						   "Ignore DHCPv6/RDNSS DNS",
						   "When the method is set to 'auto' or 'dhcp' and this "
						   "property is set to TRUE, automatically configured "
						   "nameservers and search domains are ignored and only "
						   "nameservers and search domains specified in the 'dns' "
						   "and 'dns-search' properties, if any, are used.",
						   FALSE,
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP6Config:never-default:
	 *
	 * If TRUE, this connection will never be the default IPv6 connection,
	 * meaning it will never be assigned the default IPv6 route by NetworkManager.
	 **/
	g_object_class_install_property
		(object_class, PROP_NEVER_DEFAULT,
		 g_param_spec_boolean (NM_SETTING_IP6_CONFIG_NEVER_DEFAULT,
						   "Never default",
						   "If TRUE, this connection will never be the default "
						   "IPv6 connection, meaning it will never be assigned "
						   "the default IPv6 route by NetworkManager.",
						   FALSE,
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingIP6Config:may-fail:
	 *
	 * If TRUE, allow overall network configuration to proceed even if IPv6
	 * configuration times out.  Note that at least one IP configuration
	 * must succeed or overall network configuration will still fail.  For
	 * example, in IPv4-only networks, setting this property to TRUE allows
	 * the overall network configuration to succeed if IPv6 configuration fails
	 * but IPv4 configuration completes successfully.
	 **/
	g_object_class_install_property
		(object_class, PROP_MAY_FAIL,
		 g_param_spec_boolean (NM_SETTING_IP6_CONFIG_MAY_FAIL,
						   "May Fail",
						   "If TRUE, allow overall network configuration to "
						   "proceed even if IPv6 configuration times out. "
						   "Note that at least one IP configuration must "
						   "succeed or overall network configuration will still "
						   "fail.  For example, in IPv4-only networks, setting "
						   "this property to TRUE allows the overall network "
						   "configuration to succeed if IPv6 configuration "
						   "fails but IPv4 configuration completes successfully.",
						   FALSE,
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));
}

/********************************************************************/

struct NMIP6Address {
	guint32 refcount;
	struct in6_addr address;
	guint32 prefix;
	struct in6_addr gateway;
};

NMIP6Address *
nm_ip6_address_new (void)
{
	NMIP6Address *address;

	address = g_malloc0 (sizeof (NMIP6Address));
	address->refcount = 1;
	return address;
}

NMIP6Address *
nm_ip6_address_dup (NMIP6Address *source)
{
	NMIP6Address *address;

	g_return_val_if_fail (source != NULL, NULL);
	g_return_val_if_fail (source->refcount > 0, NULL);

	address = nm_ip6_address_new ();
	address->prefix = source->prefix;
	memcpy (&address->address, &source->address, sizeof (struct in6_addr));
	memcpy (&address->gateway, &source->gateway, sizeof (struct in6_addr));

	return address;
}

void
nm_ip6_address_ref (NMIP6Address *address)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->refcount++;
}

void
nm_ip6_address_unref (NMIP6Address *address)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->refcount--;
	if (address->refcount == 0) {
		memset (address, 0, sizeof (NMIP6Address));
		g_free (address);
	}
}

gboolean
nm_ip6_address_compare (NMIP6Address *address, NMIP6Address *other)
{
	g_return_val_if_fail (address != NULL, FALSE);
	g_return_val_if_fail (address->refcount > 0, FALSE);

	g_return_val_if_fail (other != NULL, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	if (   memcmp (&address->address, &other->address, sizeof (struct in6_addr))
	    || address->prefix != other->prefix
	    || memcmp (&address->gateway, &other->gateway, sizeof (struct in6_addr)))
		return FALSE;
	return TRUE;
}

const struct in6_addr *
nm_ip6_address_get_address (NMIP6Address *address)
{
	g_return_val_if_fail (address != NULL, 0);
	g_return_val_if_fail (address->refcount > 0, 0);

	return &address->address;
}

void
nm_ip6_address_set_address (NMIP6Address *address, const struct in6_addr *addr)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);
	g_return_if_fail (addr != NULL);

	memcpy (&address->address, addr, sizeof (struct in6_addr));
}

guint32
nm_ip6_address_get_prefix (NMIP6Address *address)
{
	g_return_val_if_fail (address != NULL, 0);
	g_return_val_if_fail (address->refcount > 0, 0);

	return address->prefix;
}

void
nm_ip6_address_set_prefix (NMIP6Address *address, guint32 prefix)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->prefix = prefix;
}

const struct in6_addr *
nm_ip6_address_get_gateway (NMIP6Address *address)
{
	g_return_val_if_fail (address != NULL, 0);
	g_return_val_if_fail (address->refcount > 0, 0);

	return &address->gateway;
}

void
nm_ip6_address_set_gateway (NMIP6Address *address, const struct in6_addr *gw)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);
	g_return_if_fail (gw != NULL);

	memcpy (&address->gateway, gw, sizeof (struct in6_addr));
}

/********************************************************************/

struct NMIP6Route {
	guint32 refcount;

	struct in6_addr dest;
	guint32 prefix;
	struct in6_addr next_hop;
	guint32 metric;    /* lower metric == more preferred */
};

NMIP6Route *
nm_ip6_route_new (void)
{
	NMIP6Route *route;

	route = g_malloc0 (sizeof (NMIP6Route));
	route->refcount = 1;
	return route;
}

NMIP6Route *
nm_ip6_route_dup (NMIP6Route *source)
{
	NMIP6Route *route;

	g_return_val_if_fail (source != NULL, NULL);
	g_return_val_if_fail (source->refcount > 0, NULL);

	route = nm_ip6_route_new ();
	route->prefix = source->prefix;
	route->metric = source->metric;
	memcpy (&route->dest, &source->dest, sizeof (struct in6_addr));
	memcpy (&route->next_hop, &source->next_hop, sizeof (struct in6_addr));

	return route;
}

void
nm_ip6_route_ref (NMIP6Route *route)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->refcount++;
}

void
nm_ip6_route_unref (NMIP6Route *route)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->refcount--;
	if (route->refcount == 0) {
		memset (route, 0, sizeof (NMIP6Route));
		g_free (route);
	}
}

gboolean
nm_ip6_route_compare (NMIP6Route *route, NMIP6Route *other)
{
	g_return_val_if_fail (route != NULL, FALSE);
	g_return_val_if_fail (route->refcount > 0, FALSE);

	g_return_val_if_fail (other != NULL, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	if (   memcmp (&route->dest, &other->dest, sizeof (struct in6_addr))
	    || route->prefix != other->prefix
	    || memcmp (&route->next_hop, &other->next_hop, sizeof (struct in6_addr))
	    || route->metric != other->metric)
		return FALSE;
	return TRUE;
}

const struct in6_addr *
nm_ip6_route_get_dest (NMIP6Route *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return &route->dest;
}

void
nm_ip6_route_set_dest (NMIP6Route *route, const struct in6_addr *dest)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);
	g_return_if_fail (dest != NULL);

	memcpy (&route->dest, dest, sizeof (struct in6_addr));
}

guint32
nm_ip6_route_get_prefix (NMIP6Route *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->prefix;
}

void
nm_ip6_route_set_prefix (NMIP6Route *route, guint32 prefix)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->prefix = prefix;
}

const struct in6_addr *
nm_ip6_route_get_next_hop (NMIP6Route *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return &route->next_hop;
}

void
nm_ip6_route_set_next_hop (NMIP6Route *route, const struct in6_addr *next_hop)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);
	g_return_if_fail (next_hop != NULL);

	memcpy (&route->next_hop, next_hop, sizeof (struct in6_addr));
}

guint32
nm_ip6_route_get_metric (NMIP6Route *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->metric;
}

void
nm_ip6_route_set_metric (NMIP6Route *route, guint32 metric)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->metric = metric;
}
