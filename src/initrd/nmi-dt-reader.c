// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-initrd-generator.h"

#include <arpa/inet.h>

#include "nm-core-internal.h"

/*****************************************************************************/

#define _NMLOG(level, domain, ...) \
    nm_log ((level), (domain), NULL, NULL, \
            "dt-reader: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) \
            _NM_UTILS_MACRO_REST (__VA_ARGS__))

/*****************************************************************************/

static gboolean
dt_get_property (const char *base,
                 const char *dev,
                 const char *prop,
                 char **contents,
                 size_t *length)
{
	gs_free char *filename = g_build_filename (base, dev, prop, NULL);
	gs_free_error GError *error = NULL;

	if (!g_file_test (filename, G_FILE_TEST_EXISTS))
		return FALSE;

	if (!contents)
		return TRUE;

	if (!g_file_get_contents (filename, contents, length, &error)) {
		_LOGW (LOGD_CORE, "%s: Can not read the %s property: %s",
		       dev, prop, error->message);
		return FALSE;
	}

	return TRUE;
}

static NMIPAddress *
dt_get_ipaddr_property (const char *base,
                        const char *dev,
                        const char *prop,
                        int *family)
{
	gs_free char *buf = NULL;
	size_t len;
	int f;

	if (!dt_get_property (base, dev, prop, &buf, &len))
		return NULL;

	f = nm_utils_addr_family_from_size (len);
	if (   f == AF_UNSPEC
	    || (   *family != AF_UNSPEC
	        && *family != f)) {
		_LOGW (LOGD_CORE, "%s: Address %s has unrecognized length (%zd)",
		       dev, prop, len);
		return NULL;
	}

	*family = f;
	return nm_ip_address_new_binary (f, buf, 0, NULL);
}

static char *
dt_get_hwaddr_property (const char *base,
                        const char *dev,
                        const char *prop)
{
	gs_free guint8 *buf = NULL;
	size_t len;

	if (!dt_get_property (base, dev, prop, (char **) &buf, &len))
		return NULL;

	if (len != ETH_ALEN) {
		_LOGW (LOGD_CORE, "%s: MAC address %s has unrecognized length (%zd)",
		       dev, prop, len);
		return NULL;
	}

	return g_strdup_printf ("%02x:%02x:%02x:%02x:%02x:%02x",
	                        buf[0], buf[1], buf[2],
	                        buf[3], buf[4], buf[4]);
}

static NMIPAddress *
str_addr (const char *str, int *family)
{
	NMIPAddr addr_bin;

	if (!nm_utils_parse_inaddr_bin_full (*family,
	                                     TRUE,
	                                     str,
	                                     family,
	                                     &addr_bin)) {
		_LOGW (LOGD_CORE, "Malformed IP address: '%s'", str);
		return NULL;
	}
	return nm_ip_address_new_binary (*family, &addr_bin, 0, NULL);
}

NMConnection *
nmi_dt_reader_parse (const char *sysfs_dir)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_free char *base = NULL;
	gs_free char *bootpath = NULL;
	gs_strfreev char **tokens = NULL;
	char *path = NULL;
	gboolean bootp = FALSE;
	const char *s_ipaddr = NULL;
	const char *s_netmask = NULL;
	const char *s_gateway = NULL;
	nm_auto_unref_ip_address NMIPAddress *ipaddr = NULL;
	nm_auto_unref_ip_address NMIPAddress *gateway = NULL;
	const char *duplex = NULL;
	gs_free char *hwaddr = NULL;
	gs_free char *local_hwaddr = NULL;
	gs_free char *hostname = NULL;
	guint32 speed = 0;
	int prefix = -1;
	NMSettingIPConfig *s_ip = NULL;
	NMSetting *s_ip4 = NULL;
	NMSetting *s_ip6 = NULL;
	NMSetting *s_wired = NULL;
	int family = AF_UNSPEC;
	int i = 0;
	char *c;
	gs_free_error GError *error = NULL;

	base = g_build_filename (sysfs_dir, "firmware", "devicetree",
	                         "base", NULL);

	if (!dt_get_property (base, "chosen", "bootpath", &bootpath, NULL))
		return NULL;

	c = strchr (bootpath, ':');
	if (c) {
		*c = '\0';
		path = c + 1;
	} else {
		path = "";
	}

	dt_get_property (base, "chosen", "client-name", &hostname, NULL);

	local_hwaddr = dt_get_hwaddr_property (base, bootpath, "local-mac-address");
	hwaddr = dt_get_hwaddr_property (base, bootpath, "mac-address");
	if (g_strcmp0 (local_hwaddr, hwaddr) == 0)
		nm_clear_g_free (&local_hwaddr);

	tokens = g_strsplit (path, ",", 0);

	/*
	 * Ethernet device settings. Defined by "Open Firmware,
	 * Recommended Practice: Device Support Extensions, Version 1.0 [1]
	 * [1] https://www.devicetree.org/open-firmware/practice/devicex/dse1_0a.ps
	 */

	for (i = 0; tokens[i]; i++) {
		/* Skip these. They have magical meaning for OpenFirmware. */
		if (   strcmp (tokens[i], "nfs") == 0
		    || strcmp (tokens[i], "last") == 0)
			continue;
		if (strcmp (tokens[i], "promiscuous") == 0) {
			/* Ignore. */
			continue;
		}

		if (g_str_has_prefix (tokens[i], "speed=")) {
			speed = _nm_utils_ascii_str_to_int64 (tokens[i] + 6,
			                                      10, 0, G_MAXUINT32, 0);
			continue;
		}

		if (g_str_has_prefix (tokens[i], "duplex=auto")) {
			continue;
		} else if (   g_str_has_prefix (tokens[i], "duplex=half")
		           || g_str_has_prefix (tokens[i], "duplex=full")) {
			duplex = tokens[i] + 7;
			continue;
		}

		break;
	}

	/*
	 * Network boot configuration. Defined by "Open Firmware,
	 * Recommended Practice: TFTP Booting Extension, Version 1.0 [1]
	 * [1] https://www.devicetree.org/open-firmware/practice/obp-tftp/tftp1_0.pdf
	 */

	for (; tokens[i]; i++) {
		if (   strcmp (tokens[i], "bootp") == 0
		    || strcmp (tokens[i], "dhcp") == 0
		    || strcmp (tokens[i], "rarp") == 0) {
			bootp = TRUE;
			continue;
		}
		break;
	}

	/* s-iaddr, or perhaps a raw absolute filename */
	if (tokens[i] && tokens[i][0] != '/')
		i++;

	/* filename */
	if (tokens[i])
		i++;

	/* c-iaddr */
	if (tokens[i]) {
		s_ipaddr = tokens[i];
		i++;
	}

	/* g-iaddr */
	if (tokens[i]) {
		s_gateway = tokens[i];
		i++;
	}

	if (tokens[i] && (   strchr (tokens[i], '.')
	                  || strchr (tokens[i], ':'))) {
		/* yaboot claims the mask can be specified here,
		 * though it doesn't support it. */
		s_netmask = tokens[i];
		i++;
	}

	/* bootp-retries */
	if (tokens[i])
		i++;

	/* tftp-retries */
	if (tokens[i])
		i++;

	if (tokens[i]) {
		/* yaboot accepts a mask here */
		s_netmask = tokens[i];
		i++;
	}

	connection = nm_simple_connection_new ();

	nm_connection_add_setting (connection,
	                           g_object_new (NM_TYPE_SETTING_CONNECTION,
	                                         NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	                                         NM_SETTING_CONNECTION_ID, "OpenFirmware Connection",
	                                         NULL));

	s_ip4 = nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, s_ip4);

	s_ip6 = nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, s_ip6);

	g_object_set (s_ip6,
	              NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE, (int) NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
	              NULL);

	if (!bootp && dt_get_property (base, "chosen", "bootp-response", NULL, NULL))
		bootp = TRUE;

	if (!bootp) {
		nm_auto_unref_ip_address NMIPAddress *netmask = NULL;

		netmask = dt_get_ipaddr_property (base, "chosen", "netmask-ip", &family);
		gateway = dt_get_ipaddr_property (base, "chosen", "gateway-ip", &family);
		if (gateway)
			s_gateway = nm_ip_address_get_address (gateway);
		ipaddr = dt_get_ipaddr_property (base, "chosen", "client-ip", &family);

		if (family == AF_UNSPEC) {
			nm_assert (netmask == NULL);
			nm_assert (gateway == NULL);
			nm_assert (ipaddr == NULL);

			netmask = str_addr (s_netmask, &family);
			ipaddr = str_addr (s_ipaddr, &family);

			prefix = _nm_utils_ascii_str_to_int64 (s_netmask, 10, 0, 128, -1);
		}

		if (prefix == -1 && family == AF_INET && netmask) {
			guint32 netmask_v4;

			nm_ip_address_get_address_binary (netmask, &netmask_v4);
			prefix = nm_utils_ip4_netmask_to_prefix (netmask_v4);
		}

		if (prefix == -1)
			_LOGW (LOGD_CORE, "Unable to determine the network prefix");
		else
			nm_ip_address_set_prefix (ipaddr, prefix);
	}

	if (!ipaddr) {
		family = AF_UNSPEC;
		bootp = TRUE;
	}

	if (bootp) {
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
		              NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, hostname,
		              NULL);
		g_object_set (s_ip6,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
		              NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, hostname,
		              NULL);
	} else {
		switch (family) {
		case AF_INET:
			s_ip = (NMSettingIPConfig *) s_ip4;
			g_object_set (s_ip4,
			              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
			              NULL);
			g_object_set (s_ip6,
			              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_DISABLED,
			              NULL);
			break;
		case AF_INET6:
			s_ip = (NMSettingIPConfig *) s_ip6;
			g_object_set (s_ip4,
			              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
			              NULL);
			g_object_set (s_ip6,
			              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
			              NULL);
			break;
		default:
			g_return_val_if_reached (NULL);
		}

		nm_setting_ip_config_add_address (s_ip, ipaddr);
		g_object_set (s_ip, NM_SETTING_IP_CONFIG_GATEWAY, s_gateway, NULL);
	}

	if (duplex || speed || hwaddr || local_hwaddr) {
		s_wired = nm_setting_wired_new ();
		nm_connection_add_setting (connection, s_wired);

		g_object_set (s_wired,
		              NM_SETTING_WIRED_SPEED, speed,
		              NM_SETTING_WIRED_DUPLEX, duplex,
		              NM_SETTING_WIRED_MAC_ADDRESS, hwaddr,
		              NM_SETTING_WIRED_CLONED_MAC_ADDRESS, local_hwaddr,
		              NULL);
	}

	if (!nm_connection_normalize (connection, NULL, NULL, &error)) {
		_LOGW (LOGD_CORE, "Generated an invalid connection: %s",
		       error->message);
		nm_clear_pointer (&connection, g_object_unref);
	}

	return g_steal_pointer (&connection);
}
