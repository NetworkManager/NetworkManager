/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */


#include <glib.h>
#include <stdio.h>
#include <string.h>
#include "nm-ip4-config.h"
#include "nm-dbus-manager.h"
#include "NetworkManager.h"
#include "NetworkManagerUtils.h"

#include <netlink/route/addr.h>
#include <netlink/utils.h>
#include <netinet/in.h>

#include "nm-ip4-config-glue.h"
#include "nm-dbus-glib-types.h"


G_DEFINE_TYPE (NMIP4Config, nm_ip4_config, G_TYPE_OBJECT)

#define NM_IP4_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IP4_CONFIG, NMIP4ConfigPrivate))

typedef struct {
	guint32	ip4_address;
	guint32	ip4_ptp_address;
	guint32	ip4_gateway;
	guint32	ip4_netmask;
	guint32	ip4_broadcast;

	guint32	mtu;	/* Maximum Transmission Unit of the interface */
	guint32	mss;	/* Maximum Segment Size of the route */

	GArray *nameservers;
	GPtrArray *domains;
	GPtrArray *searches;

	gchar *	hostname;
	gchar *	nis_domain;
	GArray *nis_servers;
	GArray *static_routes;
} NMIP4ConfigPrivate;


enum {
	PROP_0,
	PROP_ADDRESS,
	PROP_GATEWAY,
	PROP_NETMASK,
	PROP_BROADCAST,
	PROP_HOSTNAME,
	PROP_NAMESERVERS,
	PROP_DOMAINS,
	PROP_NIS_DOMAIN,
	PROP_NIS_SERVERS,
	PROP_STATIC_ROUTES,

	LAST_PROP
};


NMIP4Config *
nm_ip4_config_new (void)
{
	GObject *object;
	DBusGConnection *connection;
	char *path;
	static guint32 counter = 0;

	object = g_object_new (NM_TYPE_IP4_CONFIG, NULL);

	connection = nm_dbus_manager_get_connection (nm_dbus_manager_get ());
	path = g_strdup_printf (NM_DBUS_PATH "/IP4Config/%d", counter++);

	dbus_g_connection_register_g_object (connection, path, object);
	g_free (path);

	return (NMIP4Config *) object;
}

NMIP4Config *nm_ip4_config_copy (NMIP4Config *src_config)
{
	NMIP4Config *dst_config;
	NMIP4ConfigPrivate *priv;
	int i;
	int len;

	g_return_val_if_fail (NM_IS_IP4_CONFIG (src_config), NULL);

	dst_config = nm_ip4_config_new ();
	priv = NM_IP4_CONFIG_GET_PRIVATE (dst_config);

	nm_ip4_config_set_address     (dst_config, nm_ip4_config_get_address (src_config));
	nm_ip4_config_set_ptp_address (dst_config, nm_ip4_config_get_ptp_address (src_config));
	nm_ip4_config_set_gateway     (dst_config, nm_ip4_config_get_gateway (src_config));
	nm_ip4_config_set_netmask     (dst_config, nm_ip4_config_get_netmask (src_config));
	nm_ip4_config_set_broadcast   (dst_config, nm_ip4_config_get_broadcast (src_config));
	nm_ip4_config_set_hostname    (dst_config, nm_ip4_config_get_hostname (src_config));
	nm_ip4_config_set_nis_domain  (dst_config, nm_ip4_config_get_nis_domain (src_config));

	len = nm_ip4_config_get_num_nameservers (src_config);
	for (i = 0; i < len; i++)
		nm_ip4_config_add_nameserver (dst_config, nm_ip4_config_get_nameserver (src_config, i));

	len = nm_ip4_config_get_num_domains (src_config);
	for (i = 0; i < len; i++)
		nm_ip4_config_add_domain (dst_config, nm_ip4_config_get_domain (src_config, i));

	len = nm_ip4_config_get_num_nis_servers (src_config);
	for (i = 0; i < len; i++)
		nm_ip4_config_add_nis_server (dst_config, nm_ip4_config_get_nis_server (src_config, i));

	len = nm_ip4_config_get_num_static_routes (src_config);
	for (i = 0; i < len; i++) {
		guint32 addr = nm_ip4_config_get_static_route (src_config, i * 2);
		guint32 route = nm_ip4_config_get_static_route (src_config, (i * 2) + 1);

		nm_ip4_config_add_static_route (dst_config, addr, route);
	}		

	return dst_config;
}

guint32 nm_ip4_config_get_address (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return NM_IP4_CONFIG_GET_PRIVATE (config)->ip4_address;
}

void nm_ip4_config_set_address (NMIP4Config *config, guint32 addr)
{
	g_return_if_fail (NM_IS_IP4_CONFIG (config));

	NM_IP4_CONFIG_GET_PRIVATE (config)->ip4_address = addr;
}

guint32 nm_ip4_config_get_ptp_address (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return NM_IP4_CONFIG_GET_PRIVATE (config)->ip4_ptp_address;
}

void nm_ip4_config_set_ptp_address (NMIP4Config *config, guint32 ptp_addr)
{
	g_return_if_fail (NM_IS_IP4_CONFIG (config));

	NM_IP4_CONFIG_GET_PRIVATE (config)->ip4_ptp_address = ptp_addr;
}

guint32 nm_ip4_config_get_gateway (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return NM_IP4_CONFIG_GET_PRIVATE (config)->ip4_gateway;
}

void nm_ip4_config_set_gateway (NMIP4Config *config, guint32 gateway)
{
	g_return_if_fail (NM_IS_IP4_CONFIG (config));

	NM_IP4_CONFIG_GET_PRIVATE (config)->ip4_gateway = gateway;
}

guint32 nm_ip4_config_get_netmask (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return NM_IP4_CONFIG_GET_PRIVATE (config)->ip4_netmask;
}

void nm_ip4_config_set_netmask (NMIP4Config *config, guint32 netmask)
{
	g_return_if_fail (NM_IS_IP4_CONFIG (config));

	NM_IP4_CONFIG_GET_PRIVATE (config)->ip4_netmask = netmask;
}

guint32 nm_ip4_config_get_broadcast (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return NM_IP4_CONFIG_GET_PRIVATE (config)->ip4_broadcast;
}

void nm_ip4_config_set_broadcast (NMIP4Config *config, guint32 broadcast)
{
	g_return_if_fail (NM_IS_IP4_CONFIG (config));

	NM_IP4_CONFIG_GET_PRIVATE (config)->ip4_broadcast = broadcast;
}

void nm_ip4_config_add_nameserver (NMIP4Config *config, guint32 nameserver)
{
	g_return_if_fail (NM_IS_IP4_CONFIG (config));

	if (nameserver != 0)
		g_array_append_val (NM_IP4_CONFIG_GET_PRIVATE (config)->nameservers, nameserver);
}

guint32 nm_ip4_config_get_nameserver (NMIP4Config *config, guint i)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return g_array_index (NM_IP4_CONFIG_GET_PRIVATE (config)->nameservers, guint32, i);
}

guint32 nm_ip4_config_get_num_nameservers (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return NM_IP4_CONFIG_GET_PRIVATE (config)->nameservers->len;
}

void nm_ip4_config_add_nis_server (NMIP4Config *config, guint32 nis_server)
{
	g_return_if_fail (NM_IS_IP4_CONFIG (config));

	g_array_append_val (NM_IP4_CONFIG_GET_PRIVATE (config)->nis_servers, nis_server);
}

guint32 nm_ip4_config_get_nis_server (NMIP4Config *config, guint i)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return g_array_index (NM_IP4_CONFIG_GET_PRIVATE (config)->nis_servers, guint32, i);
}

guint32 nm_ip4_config_get_num_nis_servers (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return NM_IP4_CONFIG_GET_PRIVATE (config)->nis_servers->len;
}

void nm_ip4_config_set_hostname (NMIP4Config *config, const char *hostname)
{
	g_return_if_fail (NM_IS_IP4_CONFIG (config));
	g_return_if_fail (hostname != NULL);

	if (!strlen (hostname))
		return;

	NM_IP4_CONFIG_GET_PRIVATE (config)->hostname = g_strdup (hostname);
}

const char *nm_ip4_config_get_hostname (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	return NM_IP4_CONFIG_GET_PRIVATE (config)->hostname;
}

void nm_ip4_config_set_nis_domain (NMIP4Config *config, const char *domain) 
{
	g_return_if_fail (NM_IS_IP4_CONFIG (config));
	g_return_if_fail (domain != NULL);
	
	if (!strlen (domain))
		return;
	
	NM_IP4_CONFIG_GET_PRIVATE (config)->nis_domain = g_strdup (domain);
}

const char *nm_ip4_config_get_nis_domain (NMIP4Config *config)
{
	g_return_val_if_fail( NM_IS_IP4_CONFIG (config), NULL);
	return NM_IP4_CONFIG_GET_PRIVATE (config)->nis_domain;
}

void nm_ip4_config_add_static_route (NMIP4Config *config, guint32 host, guint32 gateway)
{
	g_return_if_fail (NM_IS_IP4_CONFIG (config));

	g_array_append_val (NM_IP4_CONFIG_GET_PRIVATE (config)->static_routes, host);
	g_array_append_val (NM_IP4_CONFIG_GET_PRIVATE (config)->static_routes, gateway);
}

guint32 nm_ip4_config_get_static_route (NMIP4Config *config, guint i)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return g_array_index (NM_IP4_CONFIG_GET_PRIVATE (config)->static_routes, guint32, i);
}

guint32 nm_ip4_config_get_num_static_routes (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return (NM_IP4_CONFIG_GET_PRIVATE (config)->static_routes->len) / 2;
}


void nm_ip4_config_add_domain (NMIP4Config *config, const char *domain)
{
	g_return_if_fail (NM_IS_IP4_CONFIG (config));
	g_return_if_fail (domain != NULL);
	g_return_if_fail (strlen (domain) > 0);

	if (!strlen (domain))
		return;

	g_ptr_array_add (NM_IP4_CONFIG_GET_PRIVATE (config)->domains, g_strdup (domain));
}

const char *nm_ip4_config_get_domain (NMIP4Config *config, guint i)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	return (const char *) g_ptr_array_index (NM_IP4_CONFIG_GET_PRIVATE (config)->domains, i);
}

guint32 nm_ip4_config_get_num_domains (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return NM_IP4_CONFIG_GET_PRIVATE (config)->domains->len;
}

void nm_ip4_config_add_search (NMIP4Config *config, const char *search)
{
	g_return_if_fail (config != NULL);
	g_return_if_fail (search != NULL);
	g_return_if_fail (strlen (search) > 0);

	g_ptr_array_add (NM_IP4_CONFIG_GET_PRIVATE (config)->searches, g_strdup (search));
}

const char *nm_ip4_config_get_search (NMIP4Config *config, guint i)
{
	g_return_val_if_fail (config != NULL, NULL);

	return (const char *) g_ptr_array_index (NM_IP4_CONFIG_GET_PRIVATE (config)->searches, i);
}

guint32 nm_ip4_config_get_num_searches (NMIP4Config *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return NM_IP4_CONFIG_GET_PRIVATE (config)->searches->len;
}

guint32 nm_ip4_config_get_mtu (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return NM_IP4_CONFIG_GET_PRIVATE (config)->mtu;
}

void nm_ip4_config_set_mtu (NMIP4Config *config, guint32 mtu)
{
	g_return_if_fail (NM_IS_IP4_CONFIG (config));

	NM_IP4_CONFIG_GET_PRIVATE (config)->mtu = mtu;
}

guint32 nm_ip4_config_get_mss (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return NM_IP4_CONFIG_GET_PRIVATE (config)->mss;
}

void nm_ip4_config_set_mss (NMIP4Config *config, guint32 mss)
{
	g_return_if_fail (NM_IS_IP4_CONFIG (config));

	NM_IP4_CONFIG_GET_PRIVATE (config)->mss = mss;
}

/* libnl convenience/conversion functions */

static int ip4_addr_to_rtnl_local (guint32 ip4_address, struct rtnl_addr *addr)
{
	struct nl_addr * local = NULL;
	int err = 0;

	g_return_val_if_fail (addr != NULL, -1);

	local = nm_utils_ip4_addr_to_nl_addr (ip4_address);
	err = rtnl_addr_set_local (addr, local);
	nl_addr_put (local);

	return err;
}

static int ip4_addr_to_rtnl_peer (guint32 ip4_address, struct rtnl_addr *addr)
{
	struct nl_addr * peer = NULL;
	int err = 0;

	g_return_val_if_fail (addr != NULL, -1);

	peer = nm_utils_ip4_addr_to_nl_addr (ip4_address);
	err = rtnl_addr_set_peer (addr, peer);
	nl_addr_put (peer);

	return err;
}

static void ip4_addr_to_rtnl_prefixlen (guint32 ip4_netmask, struct rtnl_addr *addr)
{
	g_return_if_fail (addr != NULL);

	rtnl_addr_set_prefixlen (addr, nm_utils_ip4_netmask_to_prefix (ip4_netmask));
}

static int ip4_addr_to_rtnl_broadcast (guint32 ip4_broadcast, struct rtnl_addr *addr)
{
	struct nl_addr	* local = NULL;
	int err = 0;

	g_return_val_if_fail (addr != NULL, -1);

	local = nm_utils_ip4_addr_to_nl_addr (ip4_broadcast);
	err = rtnl_addr_set_broadcast (addr, local);
	nl_addr_put (local);

	return err;
}


struct rtnl_addr * nm_ip4_config_to_rtnl_addr (NMIP4Config *config, guint32 flags)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	struct rtnl_addr *	addr = NULL;
	gboolean			success = TRUE;

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	if (!(addr = rtnl_addr_alloc()))
		return NULL;

	if (flags & NM_RTNL_ADDR_ADDR)
		success = (ip4_addr_to_rtnl_local (priv->ip4_address, addr) >= 0);

	if (flags & NM_RTNL_ADDR_PTP_ADDR)
		success = (ip4_addr_to_rtnl_peer (priv->ip4_ptp_address, addr) >= 0);

	if (flags & NM_RTNL_ADDR_NETMASK)
		ip4_addr_to_rtnl_prefixlen (priv->ip4_netmask, addr);

	if (flags & NM_RTNL_ADDR_BROADCAST) {
		guint32 bcast = priv->ip4_broadcast;

		/* Calculate the broadcast address if needed */
		if (!bcast) {
			guint32 hostmask, network;

			network = ntohl (priv->ip4_address) & ntohl (priv->ip4_netmask);
			hostmask = ~ntohl (priv->ip4_netmask);
			bcast = htonl (network | hostmask);
		}

		success = (ip4_addr_to_rtnl_broadcast (bcast, addr) >= 0);
	}

	if (!success)
	{
		rtnl_addr_put (addr);
		addr = NULL;
	}

	return addr;
}

static void
nm_ip4_config_init (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	priv->nameservers = g_array_new (FALSE, TRUE, sizeof (guint32));
	priv->nis_servers = g_array_new (FALSE, TRUE, sizeof (guint32));
	priv->static_routes = g_array_new (FALSE, TRUE, sizeof (guint32));
	priv->domains = g_ptr_array_new ();
	priv->searches = g_ptr_array_new ();
}

static void
finalize (GObject *object)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (object);

	g_free (priv->hostname);
	g_free (priv->nis_domain);
	g_array_free (priv->nameservers, TRUE);
	g_ptr_array_free (priv->domains, TRUE);
	g_ptr_array_free (priv->searches, TRUE);
	g_array_free (priv->nis_servers, TRUE);
	g_array_free (priv->static_routes, TRUE);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_ADDRESS:
		g_value_set_uint (value, priv->ip4_address);
		break;
	case PROP_GATEWAY:
		g_value_set_uint (value, priv->ip4_gateway);
		break;
	case PROP_NETMASK:
		g_value_set_uint (value, priv->ip4_netmask);
		break;
	case PROP_BROADCAST:
		g_value_set_uint (value, priv->ip4_broadcast);
		break;
	case PROP_HOSTNAME:
		g_value_set_string (value, priv->hostname);
		break;
	case PROP_NAMESERVERS:
		g_value_set_boxed (value, priv->nameservers);
		break;
	case PROP_DOMAINS:
		g_value_set_boxed (value, priv->domains);
		break;
	case PROP_NIS_DOMAIN:
		g_value_set_string (value, priv->nis_domain);
		break;
	case PROP_NIS_SERVERS:
		g_value_set_boxed (value, priv->nis_servers);
		break;
	case PROP_STATIC_ROUTES:
		g_value_set_boxed (value, priv->static_routes);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_ip4_config_class_init (NMIP4ConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMIP4ConfigPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_ADDRESS,
		 g_param_spec_uint (NM_IP4_CONFIG_ADDRESS,
							"Address",
							"IP4 address",
							0, G_MAXUINT32, 0,
							G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_GATEWAY,
		 g_param_spec_uint (NM_IP4_CONFIG_GATEWAY,
							"Gateway",
							"Gateway address",
							0, G_MAXUINT32, 0,
							G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_NETMASK,
		 g_param_spec_uint (NM_IP4_CONFIG_NETMASK,
							"Netmask",
							"Netmask address",
							0, G_MAXUINT32, 0,
							G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_BROADCAST,
		 g_param_spec_uint (NM_IP4_CONFIG_BROADCAST,
							"Broadcast",
							"Broadcast address",
							0, G_MAXUINT32, 0,
							G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_HOSTNAME,
		 g_param_spec_string (NM_IP4_CONFIG_HOSTNAME,
							  "Hostname",
							  "Hostname",
							  NULL,
							  G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_NAMESERVERS,
		 g_param_spec_boxed (NM_IP4_CONFIG_NAMESERVERS,
							 "Nameservers",
							 "DNS list",
							 DBUS_TYPE_G_UINT_ARRAY,
							 G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_DOMAINS,
		 g_param_spec_boxed (NM_IP4_CONFIG_DOMAINS,
							 "Domains",
							 "Domains",
							 DBUS_TYPE_G_ARRAY_OF_STRING,
							 G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_NIS_DOMAIN,
		 g_param_spec_string (NM_IP4_CONFIG_NIS_DOMAIN,
							  "NIS domain",
							  "NIS domain name",
							  NULL,
							  G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_NIS_SERVERS,
		 g_param_spec_boxed (NM_IP4_CONFIG_NIS_SERVERS,
							 "NIS servers",
							 "NIS servers",
							 DBUS_TYPE_G_UINT_ARRAY,
							 G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_STATIC_ROUTES,
		 g_param_spec_boxed (NM_IP4_CONFIG_STATIC_ROUTES,
							 "Static routes",
							 "Sattic routes",
							 DBUS_TYPE_G_UINT_ARRAY,
							 G_PARAM_READABLE));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (config_class),
									 &dbus_glib_nm_ip4_config_object_info);
}
