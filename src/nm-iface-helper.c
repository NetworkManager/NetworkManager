/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "config.h"

#include <glib-unix.h>
#include <getopt.h>
#include <locale.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <signal.h>

/* Cannot include <net/if.h> due to conflict with <linux/if.h>.
 * Forward declare if_nametoindex. */
extern unsigned int if_nametoindex (const char *__ifname);

#include "nm-default.h"
#include "NetworkManagerUtils.h"
#include "nm-linux-platform.h"
#include "nm-dhcp-manager.h"
#include "main-utils.h"
#include "nm-rdisc.h"
#include "nm-lndp-rdisc.h"
#include "nm-utils.h"

#if !defined(NM_DIST_VERSION)
# define NM_DIST_VERSION VERSION
#endif

#define NMIH_PID_FILE_FMT NMRUNDIR "/nm-iface-helper-%d.pid"

static GMainLoop *main_loop = NULL;
static int ifindex = -1;

static struct {
	gboolean slaac;
	gboolean show_version;
	gboolean become_daemon;
	gboolean debug;
	gboolean g_fatal_warnings;
	gboolean slaac_required;
	gboolean dhcp4_required;
	int tempaddr;
	char *ifname;
	char *uuid;
	char *dhcp4_address;
	char *dhcp4_clientid;
	char *dhcp4_hostname;
	char *iid_str;
	char *logging_backend;
	char *opt_log_level;
	char *opt_log_domains;
	guint32 priority_v4;
	guint32 priority_v6;
} global_opt = {
	.tempaddr = NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN,
	.priority_v4 = NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP4,
	.priority_v6 = NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6,
};

static void
dhcp4_state_changed (NMDhcpClient *client,
                     NMDhcpState state,
                     NMIP4Config *ip4_config,
                     GHashTable *options,
                     gpointer user_data)
{
	static NMIP4Config *last_config = NULL;
	NMIP4Config *existing;

	g_return_if_fail (!ip4_config || NM_IS_IP4_CONFIG (ip4_config));

	nm_log_dbg (LOGD_DHCP4, "(%s): new DHCPv4 client state %d", global_opt.ifname, state);

	switch (state) {
	case NM_DHCP_STATE_BOUND:
		g_assert (ip4_config);
		existing = nm_ip4_config_capture (ifindex, FALSE);
		if (last_config)
			nm_ip4_config_subtract (existing, last_config);

		nm_ip4_config_merge (existing, ip4_config);
		if (!nm_ip4_config_commit (existing, ifindex, TRUE, global_opt.priority_v4))
			nm_log_warn (LOGD_DHCP4, "(%s): failed to apply DHCPv4 config", global_opt.ifname);

		if (last_config)
			g_object_unref (last_config);
		last_config = nm_ip4_config_new (nm_dhcp_client_get_ifindex (client));
		nm_ip4_config_replace (last_config, ip4_config, NULL);
		break;
	case NM_DHCP_STATE_TIMEOUT:
	case NM_DHCP_STATE_DONE:
	case NM_DHCP_STATE_FAIL:
		if (global_opt.dhcp4_required) {
			nm_log_warn (LOGD_DHCP4, "(%s): DHCPv4 timed out or failed, quitting...", global_opt.ifname);
			g_main_loop_quit (main_loop);
		} else
			nm_log_warn (LOGD_DHCP4, "(%s): DHCPv4 timed out or failed", global_opt.ifname);
		break;
	default:
		break;
	}
}

static void
rdisc_config_changed (NMRDisc *rdisc, NMRDiscConfigMap changed, gpointer user_data)
{
	static NMIP6Config *last_config = NULL;
	NMIP6Config *existing;
	NMIP6Config *ip6_config;
	static int system_support = -1;
	guint ifa_flags = 0x00;
	int i;

	if (system_support == -1) {
		/*
		 * Check, if both libnl and the kernel are recent enough,
		 * to help user space handling RA. If it's not supported,
		 * we have no ipv6-privacy and must add autoconf addresses
		 * as /128. The reason for the /128 is to prevent the kernel
		 * from adding a prefix route for this address.
		 **/
		system_support = nm_platform_check_support_libnl_extended_ifa_flags () &&
		                 nm_platform_check_support_kernel_extended_ifa_flags (NM_PLATFORM_GET);
	}

	if (system_support)
		ifa_flags = IFA_F_NOPREFIXROUTE;
	if (global_opt.tempaddr == NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR
	    || global_opt.tempaddr == NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR)
	{
		/* without system_support, this flag will be ignored. Still set it, doesn't seem to do any harm. */
		ifa_flags |= IFA_F_MANAGETEMPADDR;
	}

	ip6_config = nm_ip6_config_new (ifindex);

	if (changed & NM_RDISC_CONFIG_GATEWAYS) {
		/* Use the first gateway as ordered in router discovery cache. */
		if (rdisc->gateways->len) {
			NMRDiscGateway *gateway = &g_array_index (rdisc->gateways, NMRDiscGateway, 0);

			nm_ip6_config_set_gateway (ip6_config, &gateway->address);
		} else
			nm_ip6_config_set_gateway (ip6_config, NULL);
	}

	if (changed & NM_RDISC_CONFIG_ADDRESSES) {
		/* Rebuild address list from router discovery cache. */
		nm_ip6_config_reset_addresses (ip6_config);

		/* rdisc->addresses contains at most max_addresses entries.
		 * This is different from what the kernel does, which
		 * also counts static and temporary addresses when checking
		 * max_addresses.
		 **/
		for (i = 0; i < rdisc->addresses->len; i++) {
			NMRDiscAddress *discovered_address = &g_array_index (rdisc->addresses, NMRDiscAddress, i);
			NMPlatformIP6Address address;

			memset (&address, 0, sizeof (address));
			address.address = discovered_address->address;
			address.plen = system_support ? 64 : 128;
			address.timestamp = discovered_address->timestamp;
			address.lifetime = discovered_address->lifetime;
			address.preferred = discovered_address->preferred;
			if (address.preferred > address.lifetime)
				address.preferred = address.lifetime;
			address.source = NM_IP_CONFIG_SOURCE_RDISC;
			address.flags = ifa_flags;

			nm_ip6_config_add_address (ip6_config, &address);
		}
	}

	if (changed & NM_RDISC_CONFIG_ROUTES) {
		/* Rebuild route list from router discovery cache. */
		nm_ip6_config_reset_routes (ip6_config);

		for (i = 0; i < rdisc->routes->len; i++) {
			NMRDiscRoute *discovered_route = &g_array_index (rdisc->routes, NMRDiscRoute, i);
			NMPlatformIP6Route route;

			/* Only accept non-default routes.  The router has no idea what the
			 * local configuration or user preferences are, so sending routes
			 * with a prefix length of 0 is quite rude and thus ignored.
			 */
			if (discovered_route->plen > 0) {
				memset (&route, 0, sizeof (route));
				route.network = discovered_route->network;
				route.plen = discovered_route->plen;
				route.gateway = discovered_route->gateway;
				route.source = NM_IP_CONFIG_SOURCE_RDISC;
				route.metric = global_opt.priority_v6;

				nm_ip6_config_add_route (ip6_config, &route);
			}
		}
	}

	if (changed & NM_RDISC_CONFIG_DHCP_LEVEL) {
		/* Unsupported until systemd DHCPv6 is ready */
	}

	if (changed & NM_RDISC_CONFIG_HOP_LIMIT)
		nm_platform_sysctl_set_ip6_hop_limit_safe (NM_PLATFORM_GET, global_opt.ifname, rdisc->hop_limit);

	if (changed & NM_RDISC_CONFIG_MTU) {
		char val[16];

		g_snprintf (val, sizeof (val), "%d", rdisc->mtu);
		nm_platform_sysctl_set (NM_PLATFORM_GET, nm_utils_ip6_property_path (global_opt.ifname, "mtu"), val);
	}

	existing = nm_ip6_config_capture (ifindex, FALSE, global_opt.tempaddr);
	if (last_config)
		nm_ip6_config_subtract (existing, last_config);

	nm_ip6_config_merge (existing, ip6_config);
	if (!nm_ip6_config_commit (existing, ifindex, TRUE))
		nm_log_warn (LOGD_IP6, "(%s): failed to apply IPv6 config", global_opt.ifname);

	if (last_config)
		g_object_unref (last_config);
	last_config = nm_ip6_config_new (ifindex);
	nm_ip6_config_replace (last_config, ip6_config, NULL);
}

static void
rdisc_ra_timeout (NMRDisc *rdisc, gpointer user_data)
{
	if (global_opt.slaac_required) {
		nm_log_warn (LOGD_IP6, "(%s): IPv6 timed out or failed, quitting...", global_opt.ifname);
		g_main_loop_quit (main_loop);
	} else
		nm_log_warn (LOGD_IP6, "(%s): IPv6 timed out or failed", global_opt.ifname);
}

static gboolean
quit_handler (gpointer user_data)
{
	g_main_loop_quit (main_loop);
	return G_SOURCE_REMOVE;
}

static void
setup_signals (void)
{
	signal (SIGPIPE, SIG_IGN);
	g_unix_signal_add (SIGINT, quit_handler, NULL);
	g_unix_signal_add (SIGTERM, quit_handler, NULL);
}

static void
do_early_setup (int *argc, char **argv[])
{
	gint64 priority64_v4 = -1;
	gint64 priority64_v6 = -1;
	GOptionEntry options[] = {
		/* Interface/IP config */
		{ "ifname", 'i', 0, G_OPTION_ARG_STRING, &global_opt.ifname, N_("The interface to manage"), N_("eth0") },
		{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &global_opt.uuid, N_("Connection UUID"), N_("661e8cd0-b618-46b8-9dc9-31a52baaa16b") },
		{ "slaac", 's', 0, G_OPTION_ARG_NONE, &global_opt.slaac, N_("Whether to manage IPv6 SLAAC"), NULL },
		{ "slaac-required", '6', 0, G_OPTION_ARG_NONE, &global_opt.slaac_required, N_("Whether SLAAC must be successful"), NULL },
		{ "slaac-tempaddr", 't', 0, G_OPTION_ARG_INT, &global_opt.tempaddr, N_("Use an IPv6 temporary privacy address"), NULL },
		{ "dhcp4", 'd', 0, G_OPTION_ARG_STRING, &global_opt.dhcp4_address, N_("Current DHCPv4 address"), NULL },
		{ "dhcp4-required", '4', 0, G_OPTION_ARG_NONE, &global_opt.dhcp4_required, N_("Whether DHCPv4 must be successful"), NULL },
		{ "dhcp4-clientid", 'c', 0, G_OPTION_ARG_STRING, &global_opt.dhcp4_clientid, N_("Hex-encoded DHCPv4 client ID"), NULL },
		{ "dhcp4-hostname", 'h', 0, G_OPTION_ARG_STRING, &global_opt.dhcp4_hostname, N_("Hostname to send to DHCP server"), N_("barbar") },
		{ "priority4", '\0', 0, G_OPTION_ARG_INT64, &priority64_v4, N_("Route priority for IPv4"), N_("0") },
		{ "priority6", '\0', 0, G_OPTION_ARG_INT64, &priority64_v6, N_("Route priority for IPv6"), N_("1024") },
		{ "iid", 'e', 0, G_OPTION_ARG_STRING, &global_opt.iid_str, N_("Hex-encoded Interface Identifier"), "" },
		{ "logging-backend", '\0', 0, G_OPTION_ARG_STRING, &global_opt.logging_backend, N_("The logging backend configuration value. See logging.backend in NetworkManager.conf"), NULL },

		/* Logging/debugging */
		{ "version", 'V', 0, G_OPTION_ARG_NONE, &global_opt.show_version, N_("Print NetworkManager version and exit"), NULL },
		{ "no-daemon", 'n', G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, &global_opt.become_daemon, N_("Don't become a daemon"), NULL },
		{ "debug", 'b', 0, G_OPTION_ARG_NONE, &global_opt.debug, N_("Don't become a daemon, and log to stderr"), NULL },
		{ "log-level", 0, 0, G_OPTION_ARG_STRING, &global_opt.opt_log_level, N_("Log level: one of [%s]"), "INFO" },
		{ "log-domains", 0, 0, G_OPTION_ARG_STRING, &global_opt.opt_log_domains,
		  N_("Log domains separated by ',': any combination of [%s]"),
		  "PLATFORM,RFKILL,WIFI" },
		{ "g-fatal-warnings", 0, 0, G_OPTION_ARG_NONE, &global_opt.g_fatal_warnings, N_("Make all warnings fatal"), NULL },
		{NULL}
	};

	if (!nm_main_utils_early_setup ("nm-iface-helper",
	                                argc,
	                                argv,
	                                options,
	                                NULL,
	                                NULL,
	                                _("nm-iface-helper is a small, standalone process that manages a single network interface.")))
		exit (1);

	if (priority64_v4 >= 0 && priority64_v4 <= G_MAXUINT32)
		global_opt.priority_v4 = (guint32) priority64_v4;
	if (priority64_v6 >= 0 && priority64_v6 <= G_MAXUINT32)
		global_opt.priority_v6 = (guint32) priority64_v6;
}

int
main (int argc, char *argv[])
{
	char *bad_domains = NULL;
	GError *error = NULL;
	gboolean wrote_pidfile = FALSE;
	gs_free char *pidfile = NULL;
	gs_unref_object NMDhcpClient *dhcp4_client = NULL;
	gs_unref_object NMRDisc *rdisc = NULL;
	GByteArray *hwaddr = NULL;
	size_t hwaddr_len = 0;
	gconstpointer tmp;
	gs_free NMUtilsIPv6IfaceId *iid = NULL;

	nm_g_type_init ();

	setpgid (getpid (), getpid ());

	do_early_setup (&argc, &argv);

	if (global_opt.g_fatal_warnings) {
		GLogLevelFlags fatal_mask;

		fatal_mask = g_log_set_always_fatal (G_LOG_FATAL_MASK);
		fatal_mask |= G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL;
		g_log_set_always_fatal (fatal_mask);
	}

	if (global_opt.show_version) {
		fprintf (stdout, NM_DIST_VERSION "\n");
		exit (0);
	}

	nm_main_utils_ensure_root ();

	if (!global_opt.ifname || !global_opt.uuid) {
		fprintf (stderr, _("An interface name and UUID are required\n"));
		exit (1);
	}

	ifindex = if_nametoindex (global_opt.ifname);
	if (ifindex <= 0) {
		fprintf (stderr, _("Failed to find interface index for %s (%s)\n"), global_opt.ifname, strerror (errno));
		exit (1);
	}
	pidfile = g_strdup_printf (NMIH_PID_FILE_FMT, ifindex);
	nm_main_utils_ensure_not_running_pidfile (pidfile);

	nm_main_utils_ensure_rundir ();

	if (!nm_logging_setup (global_opt.opt_log_level,
	                       global_opt.opt_log_domains,
	                       &bad_domains,
	                       &error)) {
		fprintf (stderr,
		         _("%s.  Please use --help to see a list of valid options.\n"),
		         error->message);
		exit (1);
	} else if (bad_domains) {
		fprintf (stderr,
		         _("Ignoring unrecognized log domain(s) '%s' passed on command line.\n"),
		         bad_domains);
		g_clear_pointer (&bad_domains, g_free);
	}

	if (global_opt.become_daemon && !global_opt.debug) {
		if (daemon (0, 0) < 0) {
			int saved_errno;

			saved_errno = errno;
			fprintf (stderr, _("Could not daemonize: %s [error %u]\n"),
			         g_strerror (saved_errno),
			         saved_errno);
			exit (1);
		}
		if (nm_main_utils_write_pidfile (pidfile))
			wrote_pidfile = TRUE;
	}

	/* Set up unix signal handling - before creating threads, but after daemonizing! */
	main_loop = g_main_loop_new (NULL, FALSE);
	setup_signals ();

	nm_logging_syslog_openlog (global_opt.logging_backend
	                           ? global_opt.logging_backend
	                           : (global_opt.debug ? "debug" : NULL));

	nm_log_info (LOGD_CORE, "nm-iface-helper (version " NM_DIST_VERSION ") is starting...");

	/* Set up platform interaction layer */
	nm_linux_platform_setup ();

	tmp = nm_platform_link_get_address (NM_PLATFORM_GET, ifindex, &hwaddr_len);
	if (tmp) {
		hwaddr = g_byte_array_sized_new (hwaddr_len);
		g_byte_array_append (hwaddr, tmp, hwaddr_len);
	}

	if (global_opt.iid_str) {
		GBytes *bytes;
		gsize ignored = 0;

		bytes = nm_utils_hexstr2bin (global_opt.iid_str);
		if (!bytes || g_bytes_get_size (bytes) != sizeof (*iid)) {
			fprintf (stderr, _("(%s): Invalid IID %s\n"), global_opt.ifname, global_opt.iid_str);
			exit (1);
		}
		iid = g_bytes_unref_to_data (bytes, &ignored);
	}

	if (global_opt.dhcp4_address) {
		nm_platform_sysctl_set (NM_PLATFORM_GET, nm_utils_ip4_property_path (global_opt.ifname, "promote_secondaries"), "1");

		dhcp4_client = nm_dhcp_manager_start_ip4 (nm_dhcp_manager_get (),
		                                          global_opt.ifname,
		                                          ifindex,
		                                          hwaddr,
		                                          global_opt.uuid,
		                                          global_opt.priority_v4,
		                                          !!global_opt.dhcp4_hostname,
		                                          global_opt.dhcp4_hostname,
		                                          global_opt.dhcp4_clientid,
		                                          45,
		                                          NULL,
		                                          global_opt.dhcp4_address);
		g_assert (dhcp4_client);
		g_signal_connect (dhcp4_client,
		                  NM_DHCP_CLIENT_SIGNAL_STATE_CHANGED,
		                  G_CALLBACK (dhcp4_state_changed),
		                  NULL);
	}

	if (global_opt.slaac) {
		nm_platform_link_set_user_ipv6ll_enabled (NM_PLATFORM_GET, ifindex, TRUE);

		rdisc = nm_lndp_rdisc_new (ifindex, global_opt.ifname);
		g_assert (rdisc);

		if (iid)
			nm_rdisc_set_iid (rdisc, *iid);

		nm_platform_sysctl_set (NM_PLATFORM_GET, nm_utils_ip6_property_path (global_opt.ifname, "accept_ra"), "1");
		nm_platform_sysctl_set (NM_PLATFORM_GET, nm_utils_ip6_property_path (global_opt.ifname, "accept_ra_defrtr"), "0");
		nm_platform_sysctl_set (NM_PLATFORM_GET, nm_utils_ip6_property_path (global_opt.ifname, "accept_ra_pinfo"), "0");
		nm_platform_sysctl_set (NM_PLATFORM_GET, nm_utils_ip6_property_path (global_opt.ifname, "accept_ra_rtr_pref"), "0");

		g_signal_connect (rdisc,
		                  NM_RDISC_CONFIG_CHANGED,
		                  G_CALLBACK (rdisc_config_changed),
		                  NULL);
		g_signal_connect (rdisc,
		                  NM_RDISC_RA_TIMEOUT,
		                  G_CALLBACK (rdisc_ra_timeout),
		                  NULL);
		nm_rdisc_start (rdisc);
	}

	g_main_loop_run (main_loop);

	g_clear_pointer (&hwaddr, g_byte_array_unref);

	if (pidfile && wrote_pidfile)
		unlink (pidfile);

	nm_log_info (LOGD_CORE, "exiting");
	exit (0);
}

/*******************************************************/
/* Stub functions */

void
nm_main_config_reload (int signal)
{
	nm_log_info (LOGD_CORE, "reloading configuration not supported");
}

gconstpointer nm_config_get (void);
const char *nm_config_get_dhcp_client (gpointer unused);
gboolean nm_config_get_configure_and_quit (gpointer unused);
gconstpointer nm_bus_manager_get (void);
void nm_bus_manager_register_object (gpointer unused, const char *path, gpointer object);
void nm_bus_manager_unregister_object (gpointer unused, gpointer object);

gconstpointer
nm_config_get (void)
{
	return GUINT_TO_POINTER (1);
}

const char *
nm_config_get_dhcp_client (gpointer unused)
{
	return "internal";
}

gboolean
nm_config_get_configure_and_quit (gpointer unused)
{
	return TRUE;
}

gconstpointer
nm_bus_manager_get (void)
{
	return GUINT_TO_POINTER (1);
}

void
nm_bus_manager_register_object (gpointer unused, const char *path, gpointer object)
{
}

void
nm_bus_manager_unregister_object (gpointer unused, gpointer object)
{
}

