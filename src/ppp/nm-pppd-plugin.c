// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include <config.h>
#define ___CONFIG_H__

#include <pppd/pppd.h>
#include <pppd/fsm.h>
#include <pppd/ipcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <dlfcn.h>

#define INET6
#include <pppd/eui64.h>
#include <pppd/ipv6cp.h>

#include "nm-default.h"

#include "nm-dbus-interface.h"

#include "nm-pppd-plugin.h"
#include "nm-ppp-status.h"

int plugin_init (void);

char pppd_version[] = VERSION;

static struct {
	GDBusConnection *dbus_connection;
	char *ipparam;
} gl;

static void
nm_phasechange (int arg)
{
	NMPPPStatus ppp_status = NM_PPP_STATUS_UNKNOWN;
	char *ppp_phase;

	g_return_if_fail (G_IS_DBUS_CONNECTION (gl.dbus_connection));

	switch (arg) {
	case PHASE_DEAD:
		ppp_status = NM_PPP_STATUS_DEAD;
		ppp_phase = "dead";
		break;
	case PHASE_INITIALIZE:
		ppp_status = NM_PPP_STATUS_INITIALIZE;
		ppp_phase = "initialize";
		break;
	case PHASE_SERIALCONN:
		ppp_status = NM_PPP_STATUS_SERIALCONN;
		ppp_phase = "serial connection";
		break;
	case PHASE_DORMANT:
		ppp_status = NM_PPP_STATUS_DORMANT;
		ppp_phase = "dormant";
		break;
	case PHASE_ESTABLISH:
		ppp_status = NM_PPP_STATUS_ESTABLISH;
		ppp_phase = "establish";
		break;
	case PHASE_AUTHENTICATE:
		ppp_status = NM_PPP_STATUS_AUTHENTICATE;
		ppp_phase = "authenticate";
		break;
	case PHASE_CALLBACK:
		ppp_status = NM_PPP_STATUS_CALLBACK;
		ppp_phase = "callback";
		break;
	case PHASE_NETWORK:
		ppp_status = NM_PPP_STATUS_NETWORK;
		ppp_phase = "network";
		break;
	case PHASE_RUNNING:
		ppp_status = NM_PPP_STATUS_RUNNING;
		ppp_phase = "running";
		break;
	case PHASE_TERMINATE:
		ppp_status = NM_PPP_STATUS_TERMINATE;
		ppp_phase = "terminate";
		break;
	case PHASE_DISCONNECT:
		ppp_status = NM_PPP_STATUS_DISCONNECT;
		ppp_phase = "disconnect";
		break;
	case PHASE_HOLDOFF:
		ppp_status = NM_PPP_STATUS_HOLDOFF;
		ppp_phase = "holdoff";
		break;
	case PHASE_MASTER:
		ppp_status = NM_PPP_STATUS_MASTER;
		ppp_phase = "master";
		break;

	default:
		ppp_phase = "unknown";
		break;
	}

	g_message ("nm-ppp-plugin: status %d / phase '%s'",
	           ppp_status,
	           ppp_phase);

	if (ppp_status != NM_PPP_STATUS_UNKNOWN) {
		g_dbus_connection_call (gl.dbus_connection,
		                        NM_DBUS_SERVICE,
		                        gl.ipparam,
		                        NM_DBUS_INTERFACE_PPP,
		                        "SetState",
		                        g_variant_new ("(u)", ppp_status),
		                        G_VARIANT_TYPE ("()"),
		                        G_DBUS_CALL_FLAGS_NONE,
		                        -1,
		                        NULL,
		                        NULL,
		                        NULL);
	}

	if (ppp_status == NM_PPP_STATUS_RUNNING) {
		gs_unref_variant GVariant *ret = NULL;
		char new_name[IF_NAMESIZE];
		int ifindex;

		ifindex = if_nametoindex (ifname);

		/* Make a sync call to ensure that when the call
		 * terminates the interface already has its final
		 * name. */
		ret = g_dbus_connection_call_sync (gl.dbus_connection,
		                                   NM_DBUS_SERVICE,
		                                   gl.ipparam,
		                                   NM_DBUS_INTERFACE_PPP,
		                                   "SetIfindex",
		                                   g_variant_new ("(i)", ifindex),
		                                   G_VARIANT_TYPE ("()"),
		                                   G_DBUS_CALL_FLAGS_NONE,
		                                   25000,
		                                   NULL,
		                                   NULL);

		/* Update the name in pppd if NM changed it */
		if (   if_indextoname (ifindex, new_name)
		    && !nm_streq0 (ifname, new_name)) {
			g_message ("nm-ppp-plugin: interface name changed from '%s' to '%s'", ifname, new_name);
			g_strlcpy (ifname, new_name, IF_NAMESIZE);
		}
	}
}

static void
nm_phasechange_hook (void *data, int arg)
{
	/* We send the nofication in exitnotify instead */
	if (arg == PHASE_DEAD)
		return;

	nm_phasechange (arg);
}

static void
nm_ip_up (void *data, int arg)
{
	ipcp_options opts = ipcp_gotoptions[0];
	ipcp_options peer_opts = ipcp_hisoptions[0];
	GVariantBuilder builder;
	guint32 pppd_made_up_address = htonl (0x0a404040 + ifunit);

	g_return_if_fail (G_IS_DBUS_CONNECTION (gl.dbus_connection));

	g_message ("nm-ppp-plugin: ip-up event");

	if (!opts.ouraddr) {
		g_warning ("nm-ppp-plugin: didn't receive an internal IP from pppd!");
		nm_phasechange (PHASE_DEAD);
		return;
	}

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

	/* Keep sending the interface name to be backwards compatible
	 * with older versions of NM during a package upgrade, where
	 * NM is not restarted and the pppd plugin was not loaded. */
	g_variant_builder_add (&builder, "{sv}",
	                       NM_PPP_IP4_CONFIG_INTERFACE,
	                       g_variant_new_string (ifname));

	g_variant_builder_add (&builder, "{sv}",
	                       NM_PPP_IP4_CONFIG_ADDRESS,
	                       g_variant_new_uint32 (opts.ouraddr));

	/* Prefer the peer options remote address first, _unless_ pppd made the
	 * address up, at which point prefer the local options remote address,
	 * and if that's not right, use the made-up address as a last resort.
	 */
	if (peer_opts.hisaddr && (peer_opts.hisaddr != pppd_made_up_address)) {
		g_variant_builder_add (&builder, "{sv}",
		                       NM_PPP_IP4_CONFIG_GATEWAY,
		                       g_variant_new_uint32 (peer_opts.hisaddr));
	} else if (opts.hisaddr) {
		g_variant_builder_add (&builder, "{sv}",
		                       NM_PPP_IP4_CONFIG_GATEWAY,
		                       g_variant_new_uint32 (opts.hisaddr));
	} else if (peer_opts.hisaddr == pppd_made_up_address) {
		/* As a last resort, use the made-up address */
		g_variant_builder_add (&builder, "{sv}",
		                       NM_PPP_IP4_CONFIG_GATEWAY,
		                       g_variant_new_uint32 (peer_opts.ouraddr));
	}

	g_variant_builder_add (&builder, "{sv}",
	                       NM_PPP_IP4_CONFIG_PREFIX,
	                       g_variant_new_uint32 (32));

	if (opts.dnsaddr[0] || opts.dnsaddr[1]) {
		guint32 dns[2];
		int len = 0;

		if (opts.dnsaddr[0])
			dns[len++] = opts.dnsaddr[0];
		if (opts.dnsaddr[1])
			dns[len++] = opts.dnsaddr[1];

		g_variant_builder_add (&builder, "{sv}",
		                       NM_PPP_IP4_CONFIG_DNS,
		                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
		                                                  dns, len, sizeof (guint32)));
	}

	if (opts.winsaddr[0] || opts.winsaddr[1]) {
		guint32 wins[2];
		int len = 0;

		if (opts.winsaddr[0])
			wins[len++] = opts.winsaddr[0];
		if (opts.winsaddr[1])
			wins[len++] = opts.winsaddr[1];

		g_variant_builder_add (&builder, "{sv}",
		                       NM_PPP_IP4_CONFIG_WINS,
		                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
		                                                  wins, len, sizeof (guint32)));
	}

	g_message ("nm-ppp-plugin: sending IPv4 config to NetworkManager...");

	g_dbus_connection_call (gl.dbus_connection,
	                        NM_DBUS_SERVICE,
	                        gl.ipparam,
	                        NM_DBUS_INTERFACE_PPP,
	                        "SetIp4Config",
	                        g_variant_new ("(a{sv})", &builder),
	                        G_VARIANT_TYPE ("()"),
	                        G_DBUS_CALL_FLAGS_NONE,
	                        -1,
	                        NULL,
	                        NULL,
	                        NULL);
}

static GVariant *
eui64_to_variant (eui64_t eui)
{
	guint64 iid;

	G_STATIC_ASSERT (sizeof (iid) == sizeof (eui));

	memcpy (&iid, &eui, sizeof (eui));
	return g_variant_new_uint64 (iid);
}

static void
nm_ip6_up (void *data, int arg)
{
	ipv6cp_options *ho = &ipv6cp_hisoptions[0];
	ipv6cp_options *go = &ipv6cp_gotoptions[0];
	GVariantBuilder builder;

	g_return_if_fail (G_IS_DBUS_CONNECTION (gl.dbus_connection));

	g_message ("nm-ppp-plugin: ip6-up event");

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
	/* Keep sending the interface name to be backwards compatible
	 * with older versions of NM during a package upgrade, where
	 * NM is not restarted and the pppd plugin was not loaded. */
	g_variant_builder_add (&builder, "{sv}",
	                       NM_PPP_IP6_CONFIG_INTERFACE,
	                       g_variant_new_string (ifname));
	g_variant_builder_add (&builder, "{sv}",
	                       NM_PPP_IP6_CONFIG_OUR_IID,
	                       eui64_to_variant (go->ourid));
	g_variant_builder_add (&builder, "{sv}",
	                       NM_PPP_IP6_CONFIG_PEER_IID,
	                       eui64_to_variant (ho->hisid));

	/* DNS is done via DHCPv6 or router advertisements */

	g_message ("nm-ppp-plugin: sending IPv6 config to NetworkManager...");

	g_dbus_connection_call (gl.dbus_connection,
	                        NM_DBUS_SERVICE,
	                        gl.ipparam,
	                        NM_DBUS_INTERFACE_PPP,
	                        "SetIp6Config",
	                        g_variant_new ("(a{sv})", &builder),
	                        G_VARIANT_TYPE ("()"),
	                        G_DBUS_CALL_FLAGS_NONE,
	                        -1,
	                        NULL,
	                        NULL,
	                        NULL);
}

static int
get_chap_check (void)
{
	return 1;
}

static int
get_pap_check (void)
{
	return 1;
}

static int
get_credentials (char *username, char *password)
{
	gs_unref_variant GVariant *ret = NULL;
	gs_free_error GError *error = NULL;
	const char *my_username;
	const char *my_password;

	if (!password) {
		/* pppd is checking pap support; return 1 for supported */
		g_return_val_if_fail (username, -1);
		return 1;
	}

	g_return_val_if_fail (username, -1);
	g_return_val_if_fail (G_IS_DBUS_CONNECTION (gl.dbus_connection), -1);

	g_message ("nm-ppp-plugin: passwd-hook, requesting credentials...");

	ret = g_dbus_connection_call_sync (gl.dbus_connection,
	                                   NM_DBUS_SERVICE,
	                                   gl.ipparam,
	                                   NM_DBUS_INTERFACE_PPP,
	                                   "NeedSecrets",
	                                   NULL,
	                                   G_VARIANT_TYPE ("(ss)"),
	                                   G_DBUS_CALL_FLAGS_NONE,
	                                   -1,
	                                   NULL,
	                                   &error);
	if (!ret) {
		g_warning ("nm-ppp-plugin: could not get secrets: %s",
		           error->message);
		return -1;
	}

	g_message ("nm-ppp-plugin: got credentials from NetworkManager");

	g_variant_get (ret, "(&s&s)", &my_username, &my_password);

	g_strlcpy (username, my_username, MAXNAMELEN);
	g_strlcpy (password, my_password, MAXSECRETLEN);

	return 1;
}

static void
nm_exit_notify (void *data, int arg)
{
	g_return_if_fail (G_IS_DBUS_CONNECTION (gl.dbus_connection));

	/* We wait until this point to notify dead phase to make sure that
	 * the serial port has recovered already its original settings.
	 */
	nm_phasechange (PHASE_DEAD);

	g_message ("nm-ppp-plugin: cleaning up");

	g_clear_object (&gl.dbus_connection);
	nm_clear_g_free (&gl.ipparam);
}

static void
add_ip6_notifier (void)
{
	static struct notifier **notifier = NULL;
	static gsize load_once = 0;

	if (g_once_init_enter (&load_once)) {
		void *handle = dlopen(NULL, RTLD_NOW | RTLD_GLOBAL);

		if (handle) {
			notifier = dlsym (handle, "ipv6_up_notifier");
			dlclose (handle);
		}
		g_once_init_leave (&load_once, 1);
	}
	if (notifier)
		add_notifier (notifier, nm_ip6_up, NULL);
	else
		g_message ("nm-ppp-plugin: no IPV6CP notifier support; IPv6 not available");
}

int
plugin_init (void)
{
	gs_free_error GError *err = NULL;

	g_message ("nm-ppp-plugin: initializing");

	nm_assert (!gl.dbus_connection);
	nm_assert (!gl.ipparam);

	gl.dbus_connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &err);
	if (!gl.dbus_connection) {
		g_warning ("nm-pppd-plugin: couldn't connect to system bus: %s",
		           err->message);
		return -1;
	}

	gl.ipparam = g_strdup (ipparam);

	chap_passwd_hook = get_credentials;
	chap_check_hook = get_chap_check;
	pap_passwd_hook = get_credentials;
	pap_check_hook = get_pap_check;

	add_notifier (&phasechange, nm_phasechange_hook, NULL);
	add_notifier (&ip_up_notifier, nm_ip_up, NULL);
	add_notifier (&exitnotify, nm_exit_notify, NULL);
	add_ip6_notifier ();

	return 0;
}
