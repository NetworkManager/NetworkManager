// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-core-internal.h"
#include "nm-initrd-generator.h"
#include "systemd/nm-sd-utils-shared.h"

/*****************************************************************************/

#define _NMLOG(level, domain, ...) \
    nm_log ((level), (domain), NULL, NULL, \
            "cmdline-reader: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) \
            _NM_UTILS_MACRO_REST (__VA_ARGS__))

/*****************************************************************************/

typedef struct {
	GHashTable *hash;
	GPtrArray *array;
	NMConnection *bootdev_connection;   /* connection for bootdev=$ifname */
	NMConnection *default_connection;   /* connection not bound to any ifname */
	char *hostname;

	/* Parameters to be set for all connections */
	gboolean ignore_auto_dns;
	int dhcp_timeout;
} Reader;

static Reader *
reader_new (void)
{
	Reader *reader;

	reader = g_slice_new (Reader);
	*reader = (Reader) {
		.hash  = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_object_unref),
		.array = g_ptr_array_new (),
	};

	return reader;
}

static GHashTable *
reader_destroy (Reader *reader, gboolean free_hash)
{
	gs_unref_hashtable GHashTable *hash = NULL;

	g_ptr_array_unref (reader->array);
	hash = g_steal_pointer (&reader->hash);
	nm_clear_g_free (&reader->hostname);
	nm_g_slice_free (reader);
	if (!free_hash)
		return g_steal_pointer (&hash);
	return NULL;
}

static NMConnection *
reader_add_connection (Reader *reader, const char *name, NMConnection *connection_take)
{
	char *name_dup;

	name_dup = g_strdup (name);
	if (g_hash_table_insert (reader->hash, name_dup, connection_take))
		g_ptr_array_add (reader->array, name_dup);

	return connection_take;
}

/* Returns a new connection owned by the reader */
static NMConnection *
reader_create_connection (Reader *reader,
                          const char *basename,
                          const char *id,
                          const char *ifname,
                          const char *type_name,
                          NMConnectionMultiConnect multi_connect)
{
	NMConnection *connection;
	NMSetting *setting;

	connection = reader_add_connection (reader,
	                                    basename,
	                                    nm_simple_connection_new ());

	/* Start off assuming dynamic IP configurations. */

	setting = nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, setting);
	g_object_set (setting,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, reader->ignore_auto_dns,
	              NM_SETTING_IP_CONFIG_DHCP_TIMEOUT, reader->dhcp_timeout,
	              NULL);

	setting = nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, setting);
	g_object_set (setting,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE, (int) NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, reader->ignore_auto_dns,
	              NM_SETTING_IP_CONFIG_DHCP_TIMEOUT, reader->dhcp_timeout,
	              NULL);

	setting = nm_setting_connection_new ();
	nm_connection_add_setting (connection, setting);
	g_object_set (setting,
	              NM_SETTING_CONNECTION_ID, id,
	              NM_SETTING_CONNECTION_UUID, nm_utils_uuid_generate_a (),
	              NM_SETTING_CONNECTION_INTERFACE_NAME, ifname,
	              NM_SETTING_CONNECTION_TYPE, type_name,
	              NM_SETTING_CONNECTION_MULTI_CONNECT, multi_connect,
	              NULL);

	return connection;
}

static NMConnection *
reader_get_default_connection (Reader *reader)
{
	NMConnection *con;

	if (!reader->default_connection) {
		con = reader_create_connection (reader,
		                                "default_connection",
		                                "Wired Connection",
		                                NULL,
		                                NM_SETTING_WIRED_SETTING_NAME,
		                                NM_CONNECTION_MULTI_CONNECT_MULTIPLE);
		reader->default_connection = con;
	}
	return reader->default_connection;
}

static NMConnection *
reader_get_connection (Reader *reader,
                       const char *ifname,
                       const char *type_name,
                       gboolean create_if_missing)
{
	NMConnection *connection = NULL;
	NMSetting *setting;

	if (!ifname) {
		NMConnection *candidate;
		NMSettingConnection *s_con;
		guint i;

		/*
		 * If ifname was not given, we'll match the connection by type.
		 * If the type was not given either, then we're happy with any connection but slaves.
		 * This is so that things like "bond=bond0:eth1,eth2 nameserver=1.3.3.7 end up
		 * slapping the nameserver to the most reasonable connection (bond0).
		 */
		for (i = 0; i < reader->array->len; i++) {
			candidate = g_hash_table_lookup (reader->hash, reader->array->pdata[i]);
			s_con = nm_connection_get_setting_connection (candidate);

			if (   type_name == NULL
			    && nm_setting_connection_get_master (s_con) == NULL) {
				connection = candidate;
				break;
			}

			if (   type_name != NULL
			    && nm_streq (nm_setting_connection_get_connection_type (s_con), type_name)) {
				connection = candidate;
				break;
			}
		}
	} else
		connection = g_hash_table_lookup (reader->hash, (gpointer) ifname);

	if (!connection) {
		if (!create_if_missing)
			return NULL;

		if (!type_name)
			type_name = NM_SETTING_WIRED_SETTING_NAME;

		connection = reader_create_connection (reader, ifname,
		                                       ifname ?: "Wired Connection",
		                                       ifname, type_name,
		                                       NM_CONNECTION_MULTI_CONNECT_SINGLE);
	}
	setting = (NMSetting *) nm_connection_get_setting_connection (connection);

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
reader_read_all_connections_from_fw (Reader *reader, const char *sysfs_dir)
{
	gs_unref_hashtable GHashTable *ibft = NULL;
	NMConnection *dt_connection;
	const char *mac;
	GHashTable *nic;
	const char *index;
	GError *error = NULL;
	guint i, length;
	gs_free const char **keys = NULL;

	ibft = nmi_ibft_read (sysfs_dir);
	keys = nm_utils_strdict_get_keys (ibft, TRUE, &length);

	for (i = 0; i < length; i++) {
		gs_unref_object NMConnection *connection = NULL;
		gs_free char *name = NULL;

		mac = keys[i];
		nic = g_hash_table_lookup (ibft, mac);
		connection = nm_simple_connection_new ();
		index = g_hash_table_lookup (nic, "index");
		if (!index) {
			_LOGW (LOGD_CORE, "Ignoring an iBFT entry without an index");
			continue;
		}

		if (!nmi_ibft_update_connection_from_nic (connection, nic, &error)) {
			_LOGW (LOGD_CORE, "Unable to merge iBFT configuration: %s", error->message);
			g_error_free (error);
			continue;
		}

		name = g_strdup_printf ("ibft%s", index);
		reader_add_connection (reader, name, g_steal_pointer (&connection));
	}

	dt_connection = nmi_dt_reader_parse (sysfs_dir);
	if (dt_connection)
		reader_add_connection (reader, "ofw", dt_connection);
}

static void
reader_parse_ip (Reader *reader, const char *sysfs_dir, char *argument)
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

		if (client_hostname && !nm_sd_hostname_is_valid (client_hostname, FALSE))
			client_hostname = NULL;

		if (client_hostname) {
			g_free (reader->hostname);
			reader->hostname = g_strdup (client_hostname);
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

	if (   ifname == NULL
	    && NM_IN_STRSET (kind, "fw", "ibft")) {
		reader_read_all_connections_from_fw (reader, sysfs_dir);
		return;
	}

	/* Parsing done, construct the NMConnection. */
	if (ifname)
		connection = reader_get_connection (reader, ifname, NULL, TRUE);
	else
		connection = reader_get_default_connection (reader);

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
	if (NM_IN_STRSET (kind, "none", "off")) {
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
	} else if (nm_streq0 (kind, "dhcp")) {
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
		              NM_SETTING_IP_CONFIG_MAY_FAIL, FALSE,
		              NULL);
		if (nm_setting_ip_config_get_num_addresses (s_ip6) == 0) {
			g_object_set (s_ip6,
			              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
			              NULL);
		}
	} else if (nm_streq0 (kind, "dhcp6")) {
		g_object_set (s_ip6,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_DHCP,
		              NM_SETTING_IP_CONFIG_MAY_FAIL, FALSE,
		              NULL);
		if (nm_setting_ip_config_get_num_addresses (s_ip4) == 0) {
			g_object_set (s_ip4,
			              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
			              NULL);
		}
	} else if (nm_streq0 (kind, "auto6")) {
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_MAY_FAIL, FALSE,
		              NULL);
		if (nm_setting_ip_config_get_num_addresses (s_ip4) == 0) {
			g_object_set (s_ip4,
			              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
			              NULL);
		}
	} else if (nm_streq0 (kind, "ibft")) {
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

		if (nm_utils_ipaddr_is_valid (addr_family, gateway_ip)) {
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
		if (nm_utils_ipaddr_is_valid (dns_addr_family[i], dns[i])) {
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
reader_parse_master (Reader *reader,
                     char *argument,
                     const char *type_name,
                     const char *default_name)
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
		master = master_to_free = g_strdup_printf ("%s0", default_name ?: type_name);
	slaves = get_word (&argument, ':');

	connection = reader_get_connection (reader, master, type_name, TRUE);
	s_con = nm_connection_get_setting_connection (connection);
	master = nm_setting_connection_get_uuid (s_con);

	if (nm_streq (type_name, NM_SETTING_BOND_SETTING_NAME)) {
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

		connection = reader_get_connection (reader, slave, NULL, TRUE);
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
reader_add_routes (Reader *reader, GPtrArray *array)
{
	guint i;

	for (i = 0; i < array->len; i++) {
		NMConnection *connection = NULL;
		const char *net;
		const char *gateway;
		const char *interface;
		int family = AF_UNSPEC;
		NMIPAddr net_addr = { };
		NMIPAddr gateway_addr = { };
		int net_prefix = -1;
		NMIPRoute *route;
		NMSettingIPConfig *s_ip;
		char *argument;
		gs_free_error GError *error = NULL;

		argument = array->pdata[i];
		net = get_word (&argument, ':');
		gateway = get_word (&argument, ':');
		interface = get_word (&argument, ':');

		if (interface)
			connection = reader_get_connection (reader, interface, NULL, TRUE);
		if (!connection)
			connection = reader->bootdev_connection;
		if (!connection)
			connection = reader_get_connection (reader, interface, NULL, FALSE);
		if (!connection)
			connection = reader_get_default_connection (reader);

		if (net && *net) {
			if (!nm_utils_parse_inaddr_prefix_bin (family, net, &family, &net_addr, &net_prefix)) {
				_LOGW (LOGD_CORE, "Unrecognized address: %s", net);
				continue;
			}
		}

		if (gateway && *gateway) {
			if (!nm_utils_parse_inaddr_bin (family, gateway, &family, &gateway_addr)) {
				_LOGW (LOGD_CORE, "Unrecognized address: %s", gateway);
				continue;
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
			continue;
		}

		route = nm_ip_route_new_binary (family, &net_addr.addr_ptr, net_prefix, &gateway_addr.addr_ptr, -1, &error);
		if (!route) {
			g_warning ("Invalid route '%s via %s': %s\n", net, gateway, error->message);
			continue;
		}

		nm_setting_ip_config_add_route (s_ip, route);
		nm_ip_route_unref (route);
	}
}

static void
reader_parse_vlan (Reader *reader, char *argument)
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

	connection = reader_get_connection (reader, vlan, NM_SETTING_VLAN_SETTING_NAME, TRUE);

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_object_set (s_vlan,
	              NM_SETTING_VLAN_PARENT, phy,
	              NM_SETTING_VLAN_ID, (guint) _nm_utils_ascii_str_to_int64 (vlanid, 10, 0, G_MAXUINT, G_MAXUINT),
	              NULL);

	if (argument && *argument)
		_LOGW (LOGD_CORE, "Ignoring extra: '%s'.", argument);
}

static void
reader_parse_rd_znet (Reader *reader, char *argument, gboolean net_ifnames)
{
	const char *nettype;
	const char *subchannels[4] = { 0, 0, 0, 0 };
	const char *tmp;
	gs_free char *ifname = NULL;
	const char *prefix;
	NMConnection *connection;
	NMSettingWired *s_wired;
	static int count_ctc = 0;
	static int count_eth = 0;
	int index;

	nettype = get_word (&argument, ',');
	subchannels[0] = get_word (&argument, ',');
	subchannels[1] = get_word (&argument, ',');

	if (nm_streq0 (nettype, "ctc")) {
		if (net_ifnames == TRUE) {
			prefix = "sl";
		} else {
			prefix = "ctc";
			index = count_ctc++;
		}
	} else {
		subchannels[2] = get_word (&argument, ',');
		if (net_ifnames == TRUE) {
			prefix = "en";
		} else {
			prefix = "eth";
			index = count_eth++;
		}
	}

	if (net_ifnames == TRUE) {
		const char *bus_id;
		size_t bus_id_len;
		size_t bus_id_start;

		/* The following logic is taken from names_ccw() in systemd/src/udev/udev-builtin-net_id.c */
		bus_id = subchannels[0];
		bus_id_len = strlen (bus_id);
		bus_id_start = strspn (bus_id, ".0");
		bus_id += bus_id_start < bus_id_len ? bus_id_start : bus_id_len - 1;

		ifname = g_strdup_printf ("%sc%s", prefix, bus_id);
	} else {
		ifname = g_strdup_printf ("%s%d", prefix, index);
	}

	connection = reader_get_connection (reader, ifname, NM_SETTING_WIRED_SETTING_NAME, FALSE);
	if (!connection)
		return;
	s_wired = nm_connection_get_setting_wired (connection);
	g_object_set (s_wired,
	              NM_SETTING_WIRED_S390_NETTYPE, nettype,
	              NM_SETTING_WIRED_S390_SUBCHANNELS, &subchannels,
	              NULL);

	while ((tmp = get_word (&argument, ',')) != NULL) {
		char *val;

		val = strchr (tmp, '=');
		if (val) {
			gs_free char *key = NULL;

			key = g_strndup (tmp, val - tmp);
			val[0] = '\0';
			val++;
			nm_setting_wired_add_s390_option (s_wired, key, val);
		}
	}
}

static void
_normalize_conn (gpointer key, gpointer value, gpointer user_data)
{
	NMConnection *connection = value;

	nm_connection_normalize (connection, NULL, NULL, NULL);
}

static void
reader_add_nameservers (Reader *reader, GPtrArray *nameservers)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip;
	GHashTableIter iter;
	int addr_family;
	const char *ns;
	guint i;

	for (i = 0; i < nameservers->len; i++) {
		ns = nameservers->pdata[i];
		addr_family = guess_ip_address_family (ns);
		if (addr_family == AF_UNSPEC) {
			_LOGW (LOGD_CORE, "Unknown address family: %s", ns);
			continue;
		}

		g_hash_table_iter_init (&iter, reader->hash);
		while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &connection)) {
			switch (addr_family) {
			case AF_INET:
				s_ip = nm_connection_get_setting_ip4_config (connection);
				if (!NM_IN_STRSET (nm_setting_ip_config_get_method (s_ip),
				                   NM_SETTING_IP4_CONFIG_METHOD_AUTO,
				                   NM_SETTING_IP4_CONFIG_METHOD_MANUAL))
					continue;
				break;
			case AF_INET6:
				s_ip = nm_connection_get_setting_ip6_config (connection);
				if (!NM_IN_STRSET (nm_setting_ip_config_get_method (s_ip),
				                   NM_SETTING_IP6_CONFIG_METHOD_AUTO,
				                   NM_SETTING_IP6_CONFIG_METHOD_DHCP,
				                   NM_SETTING_IP6_CONFIG_METHOD_MANUAL))
					continue;
				break;
			default:
				nm_assert_not_reached ();
				continue;
			}

			nm_setting_ip_config_add_dns (s_ip, ns);
		}
	}
}

GHashTable *
nmi_cmdline_reader_parse (const char *sysfs_dir, const char *const*argv, char **hostname)
{
	Reader *reader;
	const char *tag;
	gboolean ignore_bootif = FALSE;
	gboolean neednet = FALSE;
	gs_free char *bootif_val = NULL;
	gs_free char *bootdev = NULL;
	gboolean net_ifnames = TRUE;
	gs_unref_ptrarray GPtrArray *nameservers = NULL;
	gs_unref_ptrarray GPtrArray *routes = NULL;
	gs_unref_ptrarray GPtrArray *znets = NULL;
	int i;

	reader = reader_new ();

	for (i = 0; argv[i]; i++) {
		gs_free char *argument_clone = NULL;
		char *argument;

		argument_clone = g_strdup (argv[i]);
		argument = argument_clone;

		tag = get_word (&argument, '=');

		if (nm_streq (tag, "net.ifnames"))
			net_ifnames = !nm_streq (argument, "0");
		else if (nm_streq (tag, "rd.peerdns"))
			reader->ignore_auto_dns = !_nm_utils_ascii_str_to_bool (argument, TRUE);
		else if (nm_streq (tag, "rd.net.timeout.dhcp")) {
			reader->dhcp_timeout = _nm_utils_ascii_str_to_int64 (argument,
			                                                     10, 0, G_MAXINT32, 0);
		}
	}

	for (i = 0; argv[i]; i++) {
		gs_free char *argument_clone = NULL;
		char *argument;
		char *word;

		argument_clone = g_strdup (argv[i]);
		argument = argument_clone;

		tag = get_word (&argument, '=');
		if (nm_streq (tag, "ip"))
			reader_parse_ip (reader, sysfs_dir, argument);
		else if (nm_streq (tag, "rd.route")) {
			if (!routes)
				routes = g_ptr_array_new_with_free_func (g_free);
			g_ptr_array_add (routes, g_strdup (argument));
		} else if (nm_streq (tag, "bridge"))
			reader_parse_master (reader, argument, NM_SETTING_BRIDGE_SETTING_NAME, "br");
		else if (nm_streq (tag, "bond"))
			reader_parse_master (reader, argument, NM_SETTING_BOND_SETTING_NAME, NULL);
		else if (nm_streq (tag, "team"))
			reader_parse_master (reader, argument, NM_SETTING_TEAM_SETTING_NAME, NULL);
		else if (nm_streq (tag, "vlan"))
			reader_parse_vlan (reader, argument);
		else if (nm_streq (tag, "bootdev")) {
			g_free (bootdev);
			bootdev = g_strdup (argument);
		} else if (nm_streq (tag, "nameserver")) {
			word = get_word (&argument, '\0');
			if (word) {
				if (!nameservers)
					nameservers = g_ptr_array_new_with_free_func (g_free);
				g_ptr_array_add (nameservers, g_strdup (word));
			}
			if (argument && *argument)
				_LOGW (LOGD_CORE, "Ignoring extra: '%s'.", argument);
		} else if (nm_streq (tag, "rd.iscsi.ibft") && _nm_utils_ascii_str_to_bool (argument, TRUE))
			reader_read_all_connections_from_fw (reader, sysfs_dir);
		else if (nm_streq (tag, "rd.bootif"))
			ignore_bootif = !_nm_utils_ascii_str_to_bool (argument, TRUE);
		else if (nm_streq (tag, "rd.neednet"))
			neednet = _nm_utils_ascii_str_to_bool (argument, TRUE);
		else if (nm_streq (tag, "rd.znet")) {
			if (!znets)
				znets = g_ptr_array_new_with_free_func (g_free);
			g_ptr_array_add (znets, g_strdup (argument));
		} else if (g_ascii_strcasecmp (tag, "BOOTIF") == 0) {
			nm_clear_g_free (&bootif_val);
			bootif_val = g_strdup (argument);
		}
	}

	if (ignore_bootif)
		nm_clear_g_free (&bootif_val);
	if (bootif_val) {
		NMConnection *connection;
		NMSettingWired *s_wired;
		const char *bootif = bootif_val;

		if (   !nm_utils_hwaddr_valid (bootif, ETH_ALEN)
		    && g_str_has_prefix (bootif, "01-")
		    && nm_utils_hwaddr_valid (&bootif[3], ETH_ALEN)) {
			/*
			 * BOOTIF MAC address can be prefixed with a hardware type identifier.
			 * "01" stays for "wired", no other are known.
			 */
			bootif += 3;
		}

		connection = reader_get_connection (reader, NULL, NM_SETTING_WIRED_SETTING_NAME, FALSE);
		if (!connection)
			connection = reader_get_default_connection (reader);

		s_wired = nm_connection_get_setting_wired (connection);

		if (   nm_connection_get_interface_name (connection)
		    || (   nm_setting_wired_get_mac_address (s_wired)
		        && !nm_utils_hwaddr_matches (nm_setting_wired_get_mac_address (s_wired), -1,
		                                     bootif, -1))) {
			connection = reader_create_connection (reader,
			                                       "bootif_connection",
			                                       "BOOTIF Connection",
			                                       NULL,
			                                       NM_SETTING_WIRED_SETTING_NAME,
			                                       NM_CONNECTION_MULTI_CONNECT_SINGLE);
			s_wired = (NMSettingWired *) nm_setting_wired_new ();
			nm_connection_add_setting (connection, (NMSetting *) s_wired);
		}

		g_object_set (s_wired,
		              NM_SETTING_WIRED_MAC_ADDRESS, bootif,
		              NULL);
	}

	if (bootdev) {
		NMConnection *connection;

		connection = reader_get_connection (reader, bootdev, NULL, TRUE);
		reader->bootdev_connection = connection;
	}

	if (neednet && g_hash_table_size (reader->hash) == 0) {
		/* Make sure there's some connection. */
		reader_get_default_connection (reader);
	}

	if (routes)
		reader_add_routes (reader, routes);

	if (nameservers)
		reader_add_nameservers (reader, nameservers);

	if (znets) {
		for (i = 0; i < znets->len; i++)
			reader_parse_rd_znet (reader, znets->pdata[i], net_ifnames);
	}

	g_hash_table_foreach (reader->hash, _normalize_conn, NULL);

	NM_SET_OUT (hostname, g_steal_pointer (&reader->hostname));

	return reader_destroy (reader, FALSE);
}
