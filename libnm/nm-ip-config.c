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

NM_GOBJECT_PROPERTIES_DEFINE (NMIPConfig,
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
	GPtrArray *addresses;
	GPtrArray *routes;
	char **nameservers;
	char **domains;
	char **searches;
	char **wins_servers;
	char *gateway;

	bool addresses_new_style:1;
	bool routes_new_style:1;
	bool nameservers_new_style:1;
	bool wins_servers_new_style:1;
} NMIPConfigPrivate;

G_DEFINE_ABSTRACT_TYPE (NMIPConfig, nm_ip_config, NM_TYPE_OBJECT)

#define NM_IP_CONFIG_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMIPConfig, NM_IS_IP_CONFIG, NMObject)

/*****************************************************************************/

static NMLDBusNotifyUpdatePropFlags
_notify_update_prop_addresses (NMClient *client,
                               NMLDBusObject *dbobj,
                               const NMLDBusMetaIface *meta_iface,
                               guint dbus_property_idx,
                               GVariant *value)
{
	NMIPConfig *self = NM_IP_CONFIG (dbobj->nmobj);
	NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE (self);
	gs_unref_ptrarray GPtrArray *addresses_old = NULL;
	gs_unref_ptrarray GPtrArray *addresses_new = NULL;
	int addr_family =   meta_iface == &_nml_dbus_meta_iface_nm_ip4config
	                  ? AF_INET : AF_INET6;
	gboolean new_style;

	new_style = (((const char *) meta_iface->dbus_properties[dbus_property_idx].dbus_type)[2] == '{');

	if (priv->addresses_new_style) {
		if (!new_style)
			return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NONE;
	} else
		priv->addresses_new_style = new_style;

	if (value) {
		if (new_style)
			addresses_new = nm_utils_ip_addresses_from_variant (value, addr_family);
		else if (addr_family == AF_INET)
			addresses_new = nm_utils_ip4_addresses_from_variant (value, NULL);
		else
			addresses_new = nm_utils_ip6_addresses_from_variant (value, NULL);
		nm_assert (addresses_new);
	}
	if (!addresses_new)
		addresses_new = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_address_unref);

	addresses_old = priv->addresses;
	priv->addresses = g_steal_pointer (&addresses_new);
	return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NOTIFY;
}

static NMLDBusNotifyUpdatePropFlags
_notify_update_prop_routes (NMClient *client,
                            NMLDBusObject *dbobj,
                            const NMLDBusMetaIface *meta_iface,
                            guint dbus_property_idx,
                            GVariant *value)
{
	NMIPConfig *self = NM_IP_CONFIG (dbobj->nmobj);
	NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE (self);
	gs_unref_ptrarray GPtrArray *routes_old = NULL;
	gs_unref_ptrarray GPtrArray *routes_new = NULL;
	int addr_family =   meta_iface == &_nml_dbus_meta_iface_nm_ip4config
	                  ? AF_INET : AF_INET6;
	gboolean new_style;

	new_style = (((const char *) meta_iface->dbus_properties[dbus_property_idx].dbus_type)[2] == '{');

	if (priv->routes_new_style) {
		if (!new_style)
			return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NONE;
	} else
		priv->routes_new_style = new_style;

	if (value) {
		if (new_style)
			routes_new = nm_utils_ip_routes_from_variant (value, addr_family);
		else if (addr_family == AF_INET)
			routes_new = nm_utils_ip4_routes_from_variant (value);
		else
			routes_new = nm_utils_ip6_routes_from_variant (value);
		nm_assert (routes_new);
	}
	if (!routes_new)
		routes_new = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_route_unref);

	routes_old = priv->routes;
	priv->routes = g_steal_pointer (&routes_new);
	return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NOTIFY;
}

static NMLDBusNotifyUpdatePropFlags
_notify_update_prop_nameservers (NMClient *client,
                                 NMLDBusObject *dbobj,
                                 const NMLDBusMetaIface *meta_iface,
                                 guint dbus_property_idx,
                                 GVariant *value)
{
	NMIPConfig *self = NM_IP_CONFIG (dbobj->nmobj);
	NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE (self);
	gs_strfreev char **nameservers_new = NULL;
	gboolean new_style = TRUE;
	int addr_family =   meta_iface == &_nml_dbus_meta_iface_nm_ip4config
	                  ? AF_INET : AF_INET6;

	if (addr_family == AF_INET) {
		new_style = (((const char *) meta_iface->dbus_properties[dbus_property_idx].dbus_type)[1] == 'a');

		if (priv->nameservers_new_style) {
			if (!new_style)
				return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NONE;
		} else
			priv->nameservers_new_style = new_style;
	}

	if (value) {
		if (addr_family == AF_INET6)
			nameservers_new = nm_utils_ip6_dns_from_variant (value);
		else if (!new_style)
			nameservers_new = nm_utils_ip4_dns_from_variant (value);
		else {
			GVariantIter iter;
			GVariantIter *iter_v;
			gs_unref_ptrarray GPtrArray *arr = NULL;

			g_variant_iter_init (&iter, value);
			while (g_variant_iter_next (&iter, "a{sv}", &iter_v)) {
				const char *key;
				GVariant *val;

				while (g_variant_iter_next (iter_v, "{&sv}", &key, &val)) {
					if (nm_streq (key, "address")) {
						gs_free char *val_str = NULL;

						if (!g_variant_is_of_type (val, G_VARIANT_TYPE_STRING))
							goto next;
						if (!nm_utils_parse_inaddr (AF_INET, g_variant_get_string (val, NULL), &val_str))
							goto next;
						if (!arr)
							arr = g_ptr_array_new ();
						g_ptr_array_add (arr, g_steal_pointer (&val_str));
						goto next;
					}
next:
					g_variant_unref (val);
				}
				g_variant_iter_free (iter_v);
			}
			if (   arr
			    && arr->len > 0)
				nameservers_new = nm_utils_strv_dup (arr->pdata, arr->len, FALSE);
			else
				nameservers_new = g_new0 (char *, 1);
		}
		nm_assert (nameservers_new);
	}

	g_strfreev (priv->nameservers);
	priv->nameservers = g_steal_pointer (&nameservers_new);
	return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NOTIFY;
}

static NMLDBusNotifyUpdatePropFlags
_notify_update_prop_wins_servers (NMClient *client,
                                  NMLDBusObject *dbobj,
                                  const NMLDBusMetaIface *meta_iface,
                                  guint dbus_property_idx,
                                  GVariant *value)
{
	NMIPConfig *self = NM_IP_CONFIG (dbobj->nmobj);
	NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE (self);
	gs_strfreev char **wins_servers_new = NULL;
	gboolean new_style;

	new_style = (((const char *) meta_iface->dbus_properties[dbus_property_idx].dbus_type)[1] == 's');

	if (priv->wins_servers_new_style) {
		if (!new_style)
			return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NONE;
	} else
		priv->wins_servers_new_style = new_style;

	if (value) {
		if (new_style)
			wins_servers_new = g_variant_dup_strv (value, NULL);
		else
			wins_servers_new = nm_utils_ip4_dns_from_variant (value);
		nm_assert (wins_servers_new);
	}

	g_strfreev (priv->wins_servers);
	priv->wins_servers = g_steal_pointer (&wins_servers_new);
	return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NOTIFY;
}

/*****************************************************************************/

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

/*****************************************************************************/

static void
nm_ip_config_init (NMIPConfig *self)
{
	NMIPConfigPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_IP_CONFIG, NMIPConfigPrivate);

	self->_priv = priv;

	priv->addresses = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_address_unref);
	priv->routes = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_route_unref);
}

static void
finalize (GObject *object)
{
	NMIPConfigPrivate *priv = NM_IP_CONFIG_GET_PRIVATE (object);

	g_free (priv->gateway);

	g_ptr_array_unref (priv->routes);
	g_ptr_array_unref (priv->addresses);

	g_strfreev (priv->nameservers);
	g_strfreev (priv->domains);
	g_strfreev (priv->searches);
	g_strfreev (priv->wins_servers);

	G_OBJECT_CLASS (nm_ip_config_parent_class)->finalize (object);
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_ip4config = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_IP4_CONFIG,
	nm_ip4_config_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_FCN    ("AddressData",    PROP_ADDRESSES,    "aa{sv}",          _notify_update_prop_addresses                                         ),
		NML_DBUS_META_PROPERTY_INIT_FCN    ("Addresses",      PROP_ADDRESSES,    "aau",             _notify_update_prop_addresses,    .obj_property_no_reverse_idx = TRUE ),
		NML_DBUS_META_PROPERTY_INIT_TODO   ("DnsOptions",    "as"                                                                                                         ),
		NML_DBUS_META_PROPERTY_INIT_TODO   ("DnsPriority",   "i"                                                                                                          ),
		NML_DBUS_META_PROPERTY_INIT_AS     ("Domains",        PROP_DOMAINS,      NMIPConfigPrivate, domains                                                               ),
		NML_DBUS_META_PROPERTY_INIT_S      ("Gateway",        PROP_GATEWAY,      NMIPConfigPrivate, gateway                                                               ),
		NML_DBUS_META_PROPERTY_INIT_FCN    ("NameserverData", PROP_NAMESERVERS,  "aa{sv}",          _notify_update_prop_nameservers                                       ),
		NML_DBUS_META_PROPERTY_INIT_FCN    ("Nameservers",    PROP_NAMESERVERS,  "au",              _notify_update_prop_nameservers,  .obj_property_no_reverse_idx = TRUE ),
		NML_DBUS_META_PROPERTY_INIT_FCN    ("RouteData",      PROP_ROUTES,       "aa{sv}",          _notify_update_prop_routes                                            ),
		NML_DBUS_META_PROPERTY_INIT_FCN    ("Routes",         PROP_ROUTES,       "aau",             _notify_update_prop_routes,       .obj_property_no_reverse_idx = TRUE ),
		NML_DBUS_META_PROPERTY_INIT_AS     ("Searches",       PROP_SEARCHES,     NMIPConfigPrivate, searches                                                              ),
		NML_DBUS_META_PROPERTY_INIT_FCN    ("WinsServerData", PROP_WINS_SERVERS, "as",              _notify_update_prop_wins_servers                                      ),
		NML_DBUS_META_PROPERTY_INIT_FCN    ("WinsServers",    PROP_WINS_SERVERS, "au",              _notify_update_prop_wins_servers, .obj_property_no_reverse_idx = TRUE ),
	),
	.base_struct_offset = G_STRUCT_OFFSET (NMIPConfig, _priv),
);

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_ip6config = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_IP6_CONFIG,
	nm_ip6_config_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_FCN         ("AddressData", PROP_ADDRESSES,   "aa{sv}",          _notify_update_prop_addresses                                       ),
		NML_DBUS_META_PROPERTY_INIT_FCN         ("Addresses",   PROP_ADDRESSES,   "a(ayuay)",        _notify_update_prop_addresses,  .obj_property_no_reverse_idx = TRUE ),
		NML_DBUS_META_PROPERTY_INIT_TODO        ("DnsOptions",  "as"                                                                                                     ),
		NML_DBUS_META_PROPERTY_INIT_TODO        ("DnsPriority", "i"                                                                                                      ),
		NML_DBUS_META_PROPERTY_INIT_AS          ("Domains",     PROP_DOMAINS,     NMIPConfigPrivate, domains                                                             ),
		NML_DBUS_META_PROPERTY_INIT_S           ("Gateway",     PROP_GATEWAY,     NMIPConfigPrivate, gateway                                                             ),
		NML_DBUS_META_PROPERTY_INIT_FCN         ("Nameservers", PROP_NAMESERVERS, "aay",             _notify_update_prop_nameservers                                     ),
		NML_DBUS_META_PROPERTY_INIT_FCN         ("RouteData",   PROP_ROUTES,      "aa{sv}",          _notify_update_prop_routes                                          ),
		NML_DBUS_META_PROPERTY_INIT_FCN         ("Routes",      PROP_ROUTES,      "a(ayuayu)",       _notify_update_prop_routes,     .obj_property_no_reverse_idx = TRUE ),
		NML_DBUS_META_PROPERTY_INIT_AS          ("Searches",    PROP_SEARCHES,    NMIPConfigPrivate, searches                                                            ),
	),
	.base_struct_offset = G_STRUCT_OFFSET (NMIPConfig, _priv),
);

static void
nm_ip_config_class_init (NMIPConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMIPConfigPrivate));

	object_class->get_property = get_property;
	object_class->finalize     = finalize;

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

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_ip4config,
	                                                         &_nml_dbus_meta_iface_nm_ip6config);
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
const char *const*
nm_ip_config_get_nameservers (NMIPConfig *config)
{
	g_return_val_if_fail (NM_IS_IP_CONFIG (config), NULL);

	return _nml_coerce_property_strv_not_null (NM_IP_CONFIG_GET_PRIVATE (config)->nameservers);
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
const char *const*
nm_ip_config_get_domains (NMIPConfig *config)
{
	g_return_val_if_fail (NM_IS_IP_CONFIG (config), NULL);

	return _nml_coerce_property_strv_not_null (NM_IP_CONFIG_GET_PRIVATE (config)->domains);
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
const char *const*
nm_ip_config_get_searches (NMIPConfig *config)
{
	g_return_val_if_fail (NM_IS_IP_CONFIG (config), NULL);

	return _nml_coerce_property_strv_not_null (NM_IP_CONFIG_GET_PRIVATE (config)->searches);
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
const char *const*
nm_ip_config_get_wins_servers (NMIPConfig *config)
{
	g_return_val_if_fail (NM_IS_IP_CONFIG (config), NULL);

	return _nml_coerce_property_strv_not_null (NM_IP_CONFIG_GET_PRIVATE (config)->wins_servers);
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
