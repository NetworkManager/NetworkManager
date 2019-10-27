// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2007 - 2011 Novell, Inc.
 * Copyright (C) 2008 - 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-ip-config.h"

#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-setting-ip-config.h"
#include "nm-dbus-interface.h"
#include "nm-object-private.h"
#include "nm-utils.h"
#include "nm-core-internal.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_FAMILY,
	PROP_GATEWAY,
	PROP_ADDRESSES,
	PROP_ROUTES,
	PROP_NAMESERVERS,
	PROP_DOMAINS,
	PROP_SEARCHES,
	PROP_WINS_SERVERS,
);

typedef struct _NMIPConfigPrivate {
	char *gateway;
	GPtrArray *addresses;
	GPtrArray *routes;
	char **nameservers;
	char **domains;
	char **searches;
	char **wins;

	gboolean new_style_data;
} NMIPConfigPrivate;

G_DEFINE_ABSTRACT_TYPE (NMIPConfig, nm_ip_config, NM_TYPE_OBJECT)

#define NM_IP_CONFIG_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMIPConfig, NM_IS_IP_CONFIG, NMObject)

/*****************************************************************************/

static void
nm_ip_config_init (NMIPConfig *self)
{
	NMIPConfigPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_IP_CONFIG, NMIPConfigPrivate);

	self->_priv = priv;

	priv->addresses = g_ptr_array_new ();
	priv->routes = g_ptr_array_new ();
	priv->nameservers = g_new0 (char *, 1);
	priv->domains = g_new0 (char *, 1);
	priv->searches = g_new0 (char *, 1);
	priv->wins = g_new0 (char *, 1);
}

static gboolean
demarshal_ip_addresses (NMObject *object, GParamSpec *pspec, GVariant *value, gpointer field)
{
	NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE (object);

	if (priv->new_style_data)
		return TRUE;

	g_ptr_array_unref (priv->addresses);
	if (NM_IS_IP4_CONFIG (object))
		priv->addresses = nm_utils_ip4_addresses_from_variant (value, NULL);
	else
		priv->addresses = nm_utils_ip6_addresses_from_variant (value, NULL);
	_nm_object_queue_notify (object, NM_IP_CONFIG_ADDRESSES);

	return TRUE;
}

static gboolean
demarshal_ip_address_data (NMObject *object, GParamSpec *pspec, GVariant *value, gpointer field)
{
	NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE (object);

	priv->new_style_data = TRUE;

	g_ptr_array_unref (priv->addresses);
	if (NM_IS_IP4_CONFIG (object))
		priv->addresses = nm_utils_ip_addresses_from_variant (value, AF_INET);
	else
		priv->addresses = nm_utils_ip_addresses_from_variant (value, AF_INET6);
	_nm_object_queue_notify (object, NM_IP_CONFIG_ADDRESSES);

	return TRUE;
}

static gboolean
demarshal_ip_array (NMObject *object, GParamSpec *pspec, GVariant *value, gpointer field)
{
	char ***obj_field;

	obj_field = field;
	if (*obj_field)
		g_strfreev (*obj_field);

	if (NM_IS_IP4_CONFIG (object))
		*obj_field = nm_utils_ip4_dns_from_variant (value);
	else
		*obj_field = nm_utils_ip6_dns_from_variant (value);

	_nm_object_queue_notify (object, pspec->name);
	return TRUE;
}

static gboolean
demarshal_ip_routes (NMObject *object, GParamSpec *pspec, GVariant *value, gpointer field)
{
	NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE (object);

	if (priv->new_style_data)
		return TRUE;

	g_ptr_array_unref (priv->routes);
	if (NM_IS_IP4_CONFIG (object))
		priv->routes = nm_utils_ip4_routes_from_variant (value);
	else
		priv->routes = nm_utils_ip6_routes_from_variant (value);
	_nm_object_queue_notify (object, NM_IP_CONFIG_ROUTES);

	return TRUE;
}

static gboolean
demarshal_ip_route_data (NMObject *object, GParamSpec *pspec, GVariant *value, gpointer field)
{
	NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE (object);

	priv->new_style_data = TRUE;

	g_ptr_array_unref (priv->routes);
	if (NM_IS_IP4_CONFIG (object))
		priv->routes = nm_utils_ip_routes_from_variant (value, AF_INET);
	else
		priv->routes = nm_utils_ip_routes_from_variant (value, AF_INET6);
	_nm_object_queue_notify (object, NM_IP_CONFIG_ROUTES);

	return TRUE;
}

static void
init_dbus (NMObject *object)
{
	NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_IP_CONFIG_GATEWAY,      &priv->gateway, },
		{ NM_IP_CONFIG_ADDRESSES,    &priv->addresses, demarshal_ip_addresses },
		{ "address-data",            &priv->addresses, demarshal_ip_address_data },
		{ NM_IP_CONFIG_ROUTES,       &priv->routes, demarshal_ip_routes },
		{ "route-data",              &priv->routes, demarshal_ip_route_data },
		/* Still use deprecated "Nameservers" property instead of "NameserverData" */
		{ NM_IP_CONFIG_NAMESERVERS,  &priv->nameservers, demarshal_ip_array },
		{ NM_IP_CONFIG_DOMAINS,      &priv->domains, },
		{ NM_IP_CONFIG_SEARCHES,     &priv->searches, },
		/* Still use deprecated "WinsServers" property instead of "WinsServerData" */
		{ NM_IP_CONFIG_WINS_SERVERS, &priv->wins, demarshal_ip_array },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_ip_config_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                (NM_IS_IP4_CONFIG (object) ?
	                                 NM_DBUS_INTERFACE_IP4_CONFIG :
	                                 NM_DBUS_INTERFACE_IP6_CONFIG),
	                                property_info);
}

static void
finalize (GObject *object)
{
	NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE (object);

	g_free (priv->gateway);

	g_ptr_array_unref (priv->addresses);
	g_ptr_array_unref (priv->routes);

	g_strfreev (priv->nameservers);
	g_strfreev (priv->domains);
	g_strfreev (priv->searches);
	g_strfreev (priv->wins);

	G_OBJECT_CLASS (nm_ip_config_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMIPConfig *self = NM_IP_CONFIG (object);

	switch (prop_id) {
	case PROP_FAMILY:
		g_value_set_int (value, nm_ip_config_get_family (self));
		break;
	case PROP_GATEWAY:
		g_value_set_string (value, nm_ip_config_get_gateway (self));
		break;
	case PROP_ADDRESSES:
		g_value_take_boxed (value, _nm_utils_copy_array (nm_ip_config_get_addresses (self),
		                                                 (NMUtilsCopyFunc) nm_ip_address_dup,
		                                                 (GDestroyNotify) nm_ip_address_unref));
		break;
	case PROP_ROUTES:
		g_value_take_boxed (value, _nm_utils_copy_array (nm_ip_config_get_routes (self),
		                                                 (NMUtilsCopyFunc) nm_ip_route_dup,
		                                                 (GDestroyNotify) nm_ip_route_unref));
		break;
	case PROP_NAMESERVERS:
		g_value_set_boxed (value, (char **) nm_ip_config_get_nameservers (self));
		break;
	case PROP_DOMAINS:
		g_value_set_boxed (value, (char **) nm_ip_config_get_domains (self));
		break;
	case PROP_SEARCHES:
		g_value_set_boxed (value, (char **) nm_ip_config_get_searches (self));
		break;
	case PROP_WINS_SERVERS:
		g_value_set_boxed (value, (char **) nm_ip_config_get_wins_servers (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_ip_config_class_init (NMIPConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMIPConfigPrivate));

	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	nm_object_class->init_dbus = init_dbus;

	/**
	 * NMIPConfig:family:
	 *
	 * The IP address family of the configuration; either
	 * <literal>AF_INET</literal> or <literal>AF_INET6</literal>.
	 **/
	obj_properties[PROP_FAMILY] =
	    g_param_spec_int (NM_IP_CONFIG_FAMILY, "", "",
	                      0, 255, AF_UNSPEC,
	                      G_PARAM_READABLE |
	                      G_PARAM_STATIC_STRINGS);

	/**
	 * NMIPConfig:gateway:
	 *
	 * The IP gateway address of the configuration as string.
	 **/
	obj_properties[PROP_GATEWAY] =
	    g_param_spec_string (NM_IP_CONFIG_GATEWAY, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMIPConfig:addresses:
	 *
	 * A #GPtrArray containing the addresses (#NMIPAddress) of the configuration.
	 **/
	obj_properties[PROP_ADDRESSES] =
	    g_param_spec_boxed (NM_IP_CONFIG_ADDRESSES, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMIPConfig:routes: (type GPtrArray(NMIPRoute))
	 *
	 * A #GPtrArray containing the routes (#NMIPRoute) of the configuration.
	 **/
	obj_properties[PROP_ROUTES] =
	    g_param_spec_boxed (NM_IP_CONFIG_ROUTES, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMIPConfig:nameservers:
	 *
	 * The array containing name server IP addresses of the configuration.
	 **/
	obj_properties[PROP_NAMESERVERS] =
	    g_param_spec_boxed (NM_IP_CONFIG_NAMESERVERS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMIPConfig:domains:
	 *
	 * The array containing domain strings of the configuration.
	 **/
	obj_properties[PROP_DOMAINS] =
	    g_param_spec_boxed (NM_IP_CONFIG_DOMAINS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMIPConfig:searches:
	 *
	 * The array containing DNS search strings of the configuration.
	 **/
	obj_properties[PROP_SEARCHES] =
	    g_param_spec_boxed (NM_IP_CONFIG_SEARCHES, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMIPConfig:wins-servers:
	 *
	 * The array containing WINS server IP addresses of the configuration.
	 * (This will always be empty for IPv6 configurations.)
	 **/
	obj_properties[PROP_WINS_SERVERS] =
	    g_param_spec_boxed (NM_IP_CONFIG_WINS_SERVERS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/**
 * nm_ip_config_get_family:
 * @config: a #NMIPConfig
 *
 * Gets the IP address family
 *
 * Returns: the IP address family; either <literal>AF_INET</literal> or
 * <literal>AF_INET6</literal>
 **/
int
nm_ip_config_get_family (NMIPConfig *config)
{
	g_return_val_if_fail (NM_IS_IP_CONFIG (config), AF_UNSPEC);

	return NM_IS_IP4_CONFIG (config) ? AF_INET : AF_INET6;
}

/**
 * nm_ip_config_get_gateway:
 * @config: a #NMIPConfig
 *
 * Gets the IP gateway address.
 *
 * Returns: (transfer none): the IP address of the gateway.
 **/
const char *
nm_ip_config_get_gateway (NMIPConfig *config)
{
	g_return_val_if_fail (NM_IS_IP_CONFIG (config), NULL);

	return _nml_coerce_property_str_not_empty (NM_IP_CONFIG_GET_PRIVATE (config)->gateway);
}

/**
 * nm_ip_config_get_addresses:
 * @config: a #NMIPConfig
 *
 * Gets the IP addresses (containing the address, prefix, and gateway).
 *
 * Returns: (element-type NMIPAddress) (transfer none): the #GPtrArray
 * containing #NMIPAddress<!-- -->es.  This is the internal copy used by the
 * configuration and must not be modified. The library never modifies the
 * returned array and thus it is safe for callers to reference and keep using it.
 **/
GPtrArray *
nm_ip_config_get_addresses (NMIPConfig *config)
{
	g_return_val_if_fail (NM_IS_IP_CONFIG (config), NULL);

	return NM_IP_CONFIG_GET_PRIVATE (config)->addresses;
}

/**
 * nm_ip_config_get_nameservers:
 * @config: a #NMIPConfig
 *
 * Gets the domain name servers (DNS).
 *
 * Returns: (transfer none): the array of nameserver IP addresses
 **/
const char * const *
nm_ip_config_get_nameservers (NMIPConfig *config)
{
	g_return_val_if_fail (NM_IS_IP_CONFIG (config), NULL);

	return (const char * const *) NM_IP_CONFIG_GET_PRIVATE (config)->nameservers;
}

/**
 * nm_ip_config_get_domains:
 * @config: a #NMIPConfig
 *
 * Gets the domain names.
 *
 * Returns: (transfer none): the array of domains.
 * (This is never %NULL, though it may be 0-length).
 **/
const char * const *
nm_ip_config_get_domains (NMIPConfig *config)
{
	g_return_val_if_fail (NM_IS_IP_CONFIG (config), NULL);

	return (const char * const *) NM_IP_CONFIG_GET_PRIVATE (config)->domains;
}

/**
 * nm_ip_config_get_searches:
 * @config: a #NMIPConfig
 *
 * Gets the DNS searches.
 *
 * Returns: (transfer none): the array of DNS search strings.
 * (This is never %NULL, though it may be 0-length).
 **/
const char * const *
nm_ip_config_get_searches (NMIPConfig *config)
{
	g_return_val_if_fail (NM_IS_IP_CONFIG (config), NULL);

	return (const char * const *) NM_IP_CONFIG_GET_PRIVATE (config)->searches;
}

/**
 * nm_ip_config_get_wins_servers:
 * @config: a #NMIPConfig
 *
 * Gets the Windows Internet Name Service servers (WINS).
 *
 * Returns: (transfer none): the arry of WINS server IP address strings.
 * (This is never %NULL, though it may be 0-length.)
 **/
const char * const *
nm_ip_config_get_wins_servers (NMIPConfig *config)
{
	g_return_val_if_fail (NM_IS_IP_CONFIG (config), NULL);

	return (const char * const *) NM_IP_CONFIG_GET_PRIVATE (config)->wins;
}

/**
 * nm_ip_config_get_routes:
 * @config: a #NMIPConfig
 *
 * Gets the routes.
 *
 * Returns: (element-type NMIPRoute) (transfer none): the #GPtrArray containing
 * #NMIPRoute<!-- -->s. This is the internal copy used by the configuration, and must
 * not be modified. The library never modifies the returned array and thus it is
 * safe for callers to reference and keep using it.
 *
 **/
GPtrArray *
nm_ip_config_get_routes (NMIPConfig *config)
{
	g_return_val_if_fail (NM_IS_IP_CONFIG (config), NULL);

	return NM_IP_CONFIG_GET_PRIVATE (config)->routes;
}
