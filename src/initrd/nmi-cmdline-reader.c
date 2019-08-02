/* NetworkManager initrd configuration generator
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
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-core-internal.h"
#include "nm-initrd-generator.h"

/*****************************************************************************/

#define _NMLOG(level, domain, ...) \
    nm_log ((level), (domain), NULL, NULL, \
            "cmdline-reader: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) \
            _NM_UTILS_MACRO_REST (__VA_ARGS__))

/*****************************************************************************/

static gboolean
_connection_matches_type (gpointer key, gpointer value, gpointer user_data)
{
	NMConnection *connection = value;
	const char *type_name = user_data;
	NMSettingConnection *s_con;

	s_con = nm_connection_get_setting_connection (connection);
	if (type_name == NULL)
		return nm_setting_connection_get_master (s_con) == NULL;
	else
		return strcmp (nm_setting_connection_get_connection_type (s_con), type_name) == 0;
}

static NMConnection *
get_conn (GHashTable *connections, const char *ifname, const char *type_name)
{
	NMConnection *connection;
	NMSetting *setting;
	const char *basename;
	NMConnectionMultiConnect multi_connect;

	if (ifname) {
		basename = ifname;
		multi_connect = NM_CONNECTION_MULTI_CONNECT_SINGLE;
	} else {
		/* This is essentially for the "ip=dhcp" scenario. */
		basename = "default_connection";
		multi_connect = NM_CONNECTION_MULTI_CONNECT_MULTIPLE;
	}

	connection = g_hash_table_lookup (connections, (gpointer) basename);
	if (!connection && !ifname) {
		/*
		 * If ifname was not given, we'll match the connection by type.
		 * If the type was not given either, then we're happy with any connection but slaves.
		 * This is so that things like "bond=bond0:eth1,eth2 nameserver=1.3.3.7 end up
		 * slapping the nameserver to the most reasonable connection (bond0).
		 */
		connection = g_hash_table_find (connections,
		                                _connection_matches_type,
		                                (gpointer) type_name);
	}

	if (connection) {
		setting = (NMSetting *)nm_connection_get_setting_connection (connection);
	} else {
		connection = nm_simple_connection_new ();
		g_hash_table_insert (connections, g_strdup (basename), connection);

		/* Start off assuming dynamic IP configurations. */

		setting = nm_setting_ip4_config_new ();
		nm_connection_add_setting (connection, setting);
		g_object_set (setting,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
		              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
		              NULL);

		setting = nm_setting_ip6_config_new ();
		nm_connection_add_setting (connection, setting);
		g_object_set (setting,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
		              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
		              NULL);

		setting = nm_setting_connection_new ();
		nm_connection_add_setting (connection, setting);
		g_object_set (setting,
		              NM_SETTING_CONNECTION_ID, ifname ?: "Wired Connection",
		              NM_SETTING_CONNECTION_UUID, nm_utils_uuid_generate_a (),
		              NM_SETTING_CONNECTION_INTERFACE_NAME, ifname,
		              NM_SETTING_CONNECTION_MULTI_CONNECT, multi_connect,
		              NULL);

		if (!type_name)
			type_name = NM_SETTING_WIRED_SETTING_NAME;
	}

	if (type_name) {
		g_object_set (setting, NM_SETTING_CONNECTION_TYPE, type_name, NULL);
		if (!nm_connection_get_setting_by_name (connection, type_name)) {
			setting = g_object_new (nm_setting_lookup_type (type_name), NULL);
			nm_connection_add_setting (connection, setting);
		}
	}

	return connection;
}

static char *
get_word (char **argument, const char separator)
{
	char *word;
	int nest = 0;

	if (*argument == NULL)
		return NULL;

	if (**argument == '[') {
		nest++;
		(*argument)++;
	}

	word = *argument;

	while (**argument != '\0') {
		if (nest && **argument == ']') {
			**argument = '\0';
			(*argument)++;
			nest--;
			continue;
		}

		if (nest == 0 && **argument == separator) {
			**argument = '\0';
			(*argument)++;
			break;
		}
		(*argument)++;
	}

	return *word ? word : NULL;
}

static void
_base_setting_set (NMConnection *connection, const char *property, const char *value)
{
	NMSetting *setting;
	const char *type_name = nm_connection_get_connection_type (connection);
	GObjectClass *object_class = g_type_class_ref (nm_setting_lookup_type (type_name));
	GParamSpec *spec = g_object_class_find_property (object_class, property);

	if (!spec) {
		_LOGW (LOGD_CORE, "'%s' does not support setting %s", type_name, property);
		return;
	}

	setting = nm_connection_get_setting_by_name (connection, type_name);

	if (G_IS_PARAM_SPEC_UINT (spec)) {
		guint v;

		v =  _nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXUINT, 0);
		if (   errno
		    || !nm_g_object_set_property_uint (G_OBJECT (setting), property, v, NULL)) {
			_LOGW (LOGD_CORE,
			       "Could not set property '%s.%s' to '%s'",
			       type_name, property, value);
		}
	} else if (G_IS_PARAM_SPEC_STRING (spec))
		g_object_set (setting, property, value, NULL);
	else
		_LOGW (LOGD_CORE, "Don't know how to set '%s' of %s", property, type_name);

	g_type_class_unref (object_class);
}

static void
parse_ip (GHashTable *connections, const char *sysfs_dir, char *argument)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4 = NULL, *s_ip6 = NULL;
	gs_unref_hashtable GHashTable *ibft = NULL;
	const char *tmp;
	const char *kind = NULL;
	const char *client_ip = NULL;
	const char *peer = NULL;
	const char *gateway_ip = NULL;
	const char *netmask = NULL;
	const char *client_hostname = NULL;
	const char *ifname = NULL;
	const char *mtu = NULL;
	const char *macaddr = NULL;
	int client_ip_family = AF_UNSPEC;
	int client_ip_prefix = -1;
	const char *dns[2] = { 0, };
	int dns_addr_family[2] = { 0, };
	int i;
	GError *error = NULL;

	if (!*argument)
		return;

	tmp = get_word (&argument, ':');
	if (!*argument) {
		/* ip={dhcp|on|any|dhcp6|auto6|ibft} */
		kind = tmp;
	} else {
		client_ip_family = guess_ip_address_family (tmp);
		if (client_ip_family != AF_UNSPEC) {
			/* <client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>: */
			client_ip = tmp;
			peer = get_word (&argument, ':');
			gateway_ip = get_word (&argument, ':');
			netmask = get_word (&argument, ':');
			client_hostname = get_word (&argument, ':');
			ifname = get_word (&argument, ':');
		} else {
			ifname = tmp;
		}

		/* <ifname>:{none|off|dhcp|on|any|dhcp6|auto6|ibft} */

		kind = get_word (&argument, ':');

		tmp = get_word (&argument, ':');
		dns_addr_family[0] = guess_ip_address_family (tmp);
		if (dns_addr_family[0] != AF_UNSPEC) {
			dns[0] = tmp;
			dns[1] = get_word (&argument, ':');
			dns_addr_family[1] = guess_ip_address_family (dns[1]);
			if (*argument)
				_LOGW (LOGD_CORE, "Ignoring extra: '%s'.", argument);
		} else {
			mtu = tmp;
			macaddr = argument;
		}
	}

	if (ifname == NULL && g_strcmp0 (kind, "ibft") == 0) {
		GHashTableIter iter;
		const char *mac;
		GHashTable *nic;
		const char *index;

		/* This is the ip=ibft case. Just take all we got from iBFT
		 * and don't process anything else, since there's no ifname
		 * specified to apply it to. */
		if (!ibft)
			ibft = nmi_ibft_read (sysfs_dir);

		g_hash_table_iter_init (&iter, ibft);
		while (g_hash_table_iter_next (&iter, (gpointer)&mac, (gpointer)&nic)) {
			connection = nm_simple_connection_new ();

			index = g_hash_table_lookup (nic, "index");
			if (!index) {
				_LOGW (LOGD_CORE, "Ignoring an iBFT entry without an index");
				continue;
			}

			if (!nmi_ibft_update_connection_from_nic (connection, nic, &error)) {
				_LOGW (LOGD_CORE, "Unable to merge iBFT configuration: %s", error->message);
				g_error_free (error);
			}

			g_hash_table_insert (connections,
			                     g_strdup_printf ("ibft%s", index),
			                     connection);
		}

		return;
	}

	/* Parsing done, construct the NMConnection. */
	connection = get_conn (connections, ifname, NULL);
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);

	if (netmask && *netmask) {
		NMIPAddr addr;

		if (nm_utils_parse_inaddr_bin (AF_INET, netmask, NULL, &addr))
			client_ip_prefix = nm_utils_ip4_netmask_to_prefix (addr.addr4);
		else
			client_ip_prefix = _nm_utils_ascii_str_to_int64 (netmask, 10, 0, 32, -1);

		if (client_ip_prefix == -1)
			_LOGW (LOGD_CORE, "Invalid IP mask: %s", netmask);
	}

	/* Static IP configuration might be present. */
	if (client_ip && *client_ip) {
		NMIPAddress *address = NULL;
		NMIPAddr addr;

		if (nm_utils_parse_inaddr_prefix_bin (client_ip_family, client_ip, NULL, &addr,
		                                      client_ip_prefix == -1 ? &client_ip_prefix : NULL)) {
			if (client_ip_prefix == -1) {
				switch (client_ip_family) {
				case AF_INET:
					client_ip_prefix = _nm_utils_ip4_get_default_prefix (addr.addr4);
					break;
				case AF_INET6:
					client_ip_prefix = 64;
					break;
				}
			}

			address = nm_ip_address_new_binary (client_ip_family, &addr.addr_ptr, client_ip_prefix, &error);
			if (!address) {
				_LOGW (LOGD_CORE, "Invalid address '%s': %s", client_ip, error->message);
				g_clear_error (&error);
			}
		} else {
			_LOGW (LOGD_CORE, "Unrecognized address: %s", client_ip);
		}

		if (address) {
			switch (client_ip_family) {
			case AF_INET:
				g_object_set (s_ip4,
				              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
				              NM_SETTING_IP_CONFIG_MAY_FAIL, FALSE,
				              NULL);
				nm_setting_ip_config_add_address (s_ip4, address);
				break;
			case AF_INET6:
				g_object_set (s_ip6,
				              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
				              NM_SETTING_IP_CONFIG_MAY_FAIL, FALSE,
				              NULL);
				nm_setting_ip_config_add_address (s_ip6, address);
				break;
			default:
				_LOGW (LOGD_CORE, "Unknown address family: %s", client_ip);
				break;
			}
			nm_ip_address_unref (address);
		}
	}

	/* Dynamic IP configuration configured explicitly. */
	if (g_strcmp0 (kind, "none") == 0 || (g_strcmp0 (kind, "off") == 0)) {
		if (nm_setting_ip_config_get_num_addresses (s_ip6) == 0) {
			g_object_set (s_ip6,
			              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_DISABLED,
			              NULL);
		}
		if (nm_setting_ip_config_get_num_addresses (s_ip4) == 0) {
			g_object_set (s_ip4,
			              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
			              NULL);
		}
	} else if (g_strcmp0 (kind, "dhcp") == 0) {
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
		              NM_SETTING_IP_CONFIG_MAY_FAIL, FALSE,
		              NULL);
		if (nm_setting_ip_config_get_num_addresses (s_ip6) == 0) {
			g_object_set (s_ip6,
			              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_DISABLED,
			              NULL);
		}
	} else if (g_strcmp0 (kind, "dhcp6") == 0) {
		g_object_set (s_ip6,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_DHCP,
		              NM_SETTING_IP_CONFIG_MAY_FAIL, FALSE,
		              NULL);
		if (nm_setting_ip_config_get_num_addresses (s_ip4) == 0) {
			g_object_set (s_ip4,
			              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
			              NULL);
		}
	} else if (g_strcmp0 (kind, "auto6") == 0) {
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_MAY_FAIL, FALSE,
		              NULL);
		if (nm_setting_ip_config_get_num_addresses (s_ip4) == 0) {
			g_object_set (s_ip4,
			              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
			              NULL);
		}
	} else if (g_strcmp0 (kind, "ibft") == 0) {
		gs_free char *address_path = g_build_filename (sysfs_dir, "class", "net", ifname, "address", NULL);
		gs_free char *mac, *mac_up = NULL;
		GHashTable *nic = NULL;

		if (!g_file_get_contents (address_path, &mac, NULL, &error)) {
			_LOGW (LOGD_CORE, "Can't get a MAC address for %s: %s", ifname, error->message);
			g_clear_error (&error);
		}

		if (mac) {
			g_strchomp (mac);
			mac_up = g_ascii_strup (mac, -1);
			if (!ibft)
				ibft = nmi_ibft_read (sysfs_dir);
			nic = g_hash_table_lookup (ibft, mac_up);
			if (!nic)
				_LOGW (LOGD_CORE, "No iBFT NIC for %s (%s)", ifname, mac_up);
		}

		if (nic) {
			if (!nmi_ibft_update_connection_from_nic (connection, nic, &error)) {
				_LOGW (LOGD_CORE, "Unable to merge iBFT configuration: %s", error->message);
				g_clear_error (&error);
			}
		}
	}

	if (peer && *peer)
		_LOGW (LOGD_CORE, "Ignoring peer: %s (not implemented)\n", peer);

	if (gateway_ip && *gateway_ip) {
		int addr_family = guess_ip_address_family (gateway_ip);

		if (nm_utils_ipaddr_valid (addr_family, gateway_ip)) {
			switch (addr_family) {
			case AF_INET:
				g_object_set (s_ip4, NM_SETTING_IP_CONFIG_GATEWAY, gateway_ip, NULL);
				break;
			case AF_INET6:
				g_object_set (s_ip6, NM_SETTING_IP_CONFIG_GATEWAY, gateway_ip, NULL);
				break;
			default:
				_LOGW (LOGD_CORE, "Unknown address family: %s", gateway_ip);
				break;
			}
		} else {
			_LOGW (LOGD_CORE, "Invalid gateway: %s", gateway_ip);
		}
	}

	if (client_hostname && *client_hostname) {
		g_object_set (s_ip4, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, client_hostname, NULL);
		g_object_set (s_ip6, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, client_hostname, NULL);
	}

	for (i = 0; i < 2; i++) {
		if (dns_addr_family[i] == AF_UNSPEC)
			break;
		if (nm_utils_ipaddr_valid (dns_addr_family[i], dns[i])) {
			switch (dns_addr_family[i]) {
			case AF_INET:
				nm_setting_ip_config_add_dns (s_ip4, dns[i]);
				break;
			case AF_INET6:
				nm_setting_ip_config_add_dns (s_ip6, dns[i]);
				break;
			default:
				_LOGW (LOGD_CORE, "Unknown address family: %s", dns[i]);
				break;
			}
		} else {
			_LOGW (LOGD_CORE, "Invalid name server: %s", dns[i]);
		}
	}

	if (mtu && *mtu)
		_base_setting_set (connection, "mtu", mtu);

	if (macaddr && *macaddr)
		_base_setting_set (connection, "cloned-mac-address", macaddr);
}

static void
parse_master (GHashTable *connections, char *argument, const char *type_name)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingBond *s_bond;
	gs_free char *master_to_free = NULL;
	const char *master;
	char *slaves;
	const char *slave;
	char *opts;
	char *opt;
	const char *opt_name;
	const char *mtu = NULL;

	master = get_word (&argument, ':');
	if (!master)
		master = master_to_free = g_strdup_printf ("%s0", type_name);
	slaves = get_word (&argument, ':');

	connection = get_conn (connections, master, type_name);
	s_con = nm_connection_get_setting_connection (connection);
	master = nm_setting_connection_get_uuid (s_con);

	if (strcmp (type_name, NM_SETTING_BOND_SETTING_NAME) == 0) {
		s_bond = (NMSettingBond *)nm_connection_get_setting_by_name (connection, type_name);

		opts = get_word (&argument, ':');
		while (opts && *opts) {
			opt = get_word (&opts, ',');
			opt_name = get_word (&opt, '=');
			nm_setting_bond_add_option (s_bond, opt_name, opt);
		}

		mtu = get_word (&argument, ':');
	}

	do {
		slave = get_word (&slaves, ',');
		if (slave == NULL)
			slave = "eth0";

		connection = get_conn (connections, slave, NULL);
		s_con = nm_connection_get_setting_connection (connection);
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_SLAVE_TYPE, type_name,
		              NM_SETTING_CONNECTION_MASTER, master,
		              NULL);
		if (mtu)
			_base_setting_set (connection, "mtu", mtu);
	} while (slaves && *slaves != '\0');

	if (argument && *argument)
		_LOGW (LOGD_CORE, "Ignoring extra: '%s'.", argument);
}

static void
parse_rd_route (GHashTable *connections, char *argument)
{
	NMConnection *connection;
	const char *net;
	const char *gateway;
	const char *interface;
	int family = AF_UNSPEC;
	NMIPAddr net_addr = { };
	NMIPAddr gateway_addr = { };
	int net_prefix = -1;
	NMIPRoute *route;
	NMSettingIPConfig *s_ip;
	GError *error = NULL;

	net = get_word (&argument, ':');
	gateway = get_word (&argument, ':');
	interface = get_word (&argument, ':');

	connection = get_conn (connections, interface, NULL);

	if (net && *net) {
		if (!nm_utils_parse_inaddr_prefix_bin (family, net, &family, &net_addr, &net_prefix)) {
			_LOGW (LOGD_CORE, "Unrecognized address: %s", net);
			return;
		}
	}

	if (gateway && *gateway) {
		if (!nm_utils_parse_inaddr_bin (family, gateway, &family, &gateway_addr)) {
			_LOGW (LOGD_CORE, "Unrecognized address: %s", gateway);
			return;
		}
	}

	switch (family) {
	case AF_INET:
		s_ip = nm_connection_get_setting_ip4_config (connection);
		if (net_prefix == -1)
			net_prefix = 32;
		break;
	case AF_INET6:
		s_ip = nm_connection_get_setting_ip6_config (connection);
		if (net_prefix == -1)
			net_prefix = 128;
		break;
	default:
		_LOGW (LOGD_CORE, "Unknown address family: %s", net);
		return;
	}

	route = nm_ip_route_new_binary (family, &net_addr.addr_ptr, net_prefix, &gateway_addr.addr_ptr, -1, &error);
	if (!route) {
		g_warning ("Invalid route '%s via %s': %s\n", net, gateway, error->message);
		g_clear_error (&error);
		return;
	}

	nm_setting_ip_config_add_route (s_ip, route);
	nm_ip_route_unref (route);
}

static void
parse_vlan (GHashTable *connections, char *argument)
{
	NMConnection *connection;
	NMSettingVlan *s_vlan;
	const char *vlan;
	const char *phy;
	const char *vlanid;

	vlan = get_word (&argument, ':');
	phy = get_word (&argument, ':');

	for (vlanid = vlan + strlen (vlan); vlanid > vlan; vlanid--) {
		if (!g_ascii_isdigit (*(vlanid - 1)))
			break;
	}

	connection = get_conn (connections, vlan, NM_SETTING_VLAN_SETTING_NAME);

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_object_set (s_vlan,
	              NM_SETTING_VLAN_PARENT, phy,
	              NM_SETTING_VLAN_ID, g_ascii_strtoull (vlanid, NULL, 10),
	              NULL);

	if (argument && *argument)
		_LOGW (LOGD_CORE, "Ignoring extra: '%s'.", argument);
}

static void
parse_bootdev (GHashTable *connections, char *argument)
{
	NMConnection *connection;
	NMSettingConnection *s_con;

	connection = get_conn (connections, NULL, NULL);

	s_con = nm_connection_get_setting_connection (connection);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, argument,
	              NULL);
}

static void
parse_nameserver (GHashTable *connections, char *argument)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip = NULL;
	char *dns;

	connection = get_conn (connections, NULL, NULL);

	dns = get_word (&argument, '\0');

	switch (guess_ip_address_family (dns)) {
	case AF_INET:
		s_ip = nm_connection_get_setting_ip4_config (connection);
		break;
	case AF_INET6:
		s_ip = nm_connection_get_setting_ip6_config (connection);
		break;
	default:
		_LOGW (LOGD_CORE, "Unknown address family: %s", dns);
		break;
	}

	nm_setting_ip_config_add_dns (s_ip, dns);

	if (argument && *argument)
		_LOGW (LOGD_CORE, "Ignoring extra: '%s'.", argument);
}

static void
parse_rd_peerdns (GHashTable *connections, char *argument)
{
	gboolean auto_dns = !_nm_utils_ascii_str_to_bool (argument, TRUE);
	NMConnection *connection;
	NMSettingIPConfig *s_ip = NULL;

	connection = get_conn (connections, NULL, NULL);

	s_ip = nm_connection_get_setting_ip4_config (connection);
	g_object_set (s_ip,
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, auto_dns,
	              NULL);

	s_ip = nm_connection_get_setting_ip6_config (connection);
	g_object_set (s_ip,
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, auto_dns,
	              NULL);
}

static void
_normalize_conn (gpointer key, gpointer value, gpointer user_data)
{
	NMConnection *connection = value;

	nm_connection_normalize (connection, NULL, NULL, NULL);
}

GHashTable *
nmi_cmdline_reader_parse (const char *sysfs_dir, char **argv)
{
	GHashTable *connections;
	const char *tag;
	char *argument;
	gboolean ignore_bootif = FALSE;
	gboolean neednet = FALSE;
	char *bootif = NULL;
	int i;

	connections = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_object_unref);

	for (i = 0; argv[i]; i++) {
		argument = argv[i];
		tag = get_word (&argument, '=');
		if (strcmp (tag, "ip") == 0)
			parse_ip (connections, sysfs_dir, argument);
		else if (strcmp (tag, "rd.route") == 0)
			parse_rd_route (connections, argument);
		else if (strcmp (tag, "bridge") == 0)
			parse_master (connections, argument, NM_SETTING_BRIDGE_SETTING_NAME);
		else if (strcmp (tag, "bond") == 0)
			parse_master (connections, argument, NM_SETTING_BOND_SETTING_NAME);
		else if (strcmp (tag, "team") == 0)
			parse_master (connections, argument, NM_SETTING_TEAM_SETTING_NAME);
		else if (strcmp (tag, "vlan") == 0)
			parse_vlan (connections, argument);
		else if (strcmp (tag, "bootdev") == 0)
			parse_bootdev (connections, argument);
		else if (strcmp (tag, "nameserver") == 0)
			parse_nameserver (connections, argument);
		else if (strcmp (tag, "rd.peerdns") == 0)
			parse_rd_peerdns (connections, argument);
		else if (strcmp (tag, "rd.bootif") == 0)
			ignore_bootif = !_nm_utils_ascii_str_to_bool (argument, TRUE);
		else if (strcmp (tag, "rd.neednet") == 0)
			neednet = _nm_utils_ascii_str_to_bool (argument, TRUE);
		else if (strcasecmp (tag, "BOOTIF") == 0)
			bootif = argument;
	}

	if (ignore_bootif)
		bootif = NULL;
	if (bootif) {
		NMConnection *connection;
		NMSettingWired *s_wired;

		if (   !nm_utils_hwaddr_valid (bootif, ETH_ALEN)
		    && g_str_has_prefix (bootif, "01-")
		    && nm_utils_hwaddr_valid (&bootif[3], ETH_ALEN)) {
			/*
			 * BOOTIF MAC address can be prefixed with a hardware type identifier.
			 * "01" stays for "wired", no other are known.
			 */
			bootif += 3;
		}

		connection = get_conn (connections, NULL, NM_SETTING_WIRED_SETTING_NAME);

		s_wired = nm_connection_get_setting_wired (connection);
		g_object_set (s_wired,
		              NM_SETTING_WIRED_MAC_ADDRESS, bootif,
		              NULL);
	}
	if (neednet && g_hash_table_size (connections) == 0) {
		/* Make sure there's some connection. */
		get_conn (connections, NULL, NM_SETTING_WIRED_SETTING_NAME);
	}

	g_hash_table_foreach (connections, _normalize_conn, NULL);

	return connections;
}
