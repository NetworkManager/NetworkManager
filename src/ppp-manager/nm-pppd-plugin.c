/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <pppd/pppd.h>
#include <pppd/fsm.h>
#include <pppd/ipcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glib.h>
#include <dbus/dbus.h>

#include "nm-pppd-plugin.h"
#include "nm-ppp-status.h"
#include "dbus-dict-helpers.h"

char pppd_version[] = VERSION;

static void
nm_phasechange (void *data, int arg)
{
	NMPPPStatus status = NM_PPP_STATUS_UNKNOWN;
	char *phase;

	switch (arg) {
	case PHASE_DEAD:
		status = NM_PPP_STATUS_DEAD;
		phase = "dead";
		break;
	case PHASE_INITIALIZE:
		status = NM_PPP_STATUS_INITIALIZE;
		phase = "initialize";
		break;
	case PHASE_SERIALCONN:
		status = NM_PPP_STATUS_SERIALCONN;
		phase = "serial connection";
		break;
	case PHASE_DORMANT:
		status = NM_PPP_STATUS_DORMANT;
		phase = "dormant";
		break;
	case PHASE_ESTABLISH:
		status = NM_PPP_STATUS_ESTABLISH;
		phase = "establish";
		break;
	case PHASE_AUTHENTICATE:
		status = NM_PPP_STATUS_AUTHENTICATE;
		phase = "authenticate";
		break;
	case PHASE_CALLBACK:
		status = NM_PPP_STATUS_CALLBACK;
		phase = "callback";
		break;
	case PHASE_NETWORK:
		status = NM_PPP_STATUS_NETWORK;
		phase = "network";
		break;
	case PHASE_RUNNING:
		status = NM_PPP_STATUS_RUNNING;
		phase = "running";
		break;
	case PHASE_TERMINATE:
		status = NM_PPP_STATUS_TERMINATE;
		phase = "terminate";
		break;
	case PHASE_DISCONNECT:
		status = NM_PPP_STATUS_DISCONNECT;
		phase = "disconnect";
		break;
	case PHASE_HOLDOFF:
		status = NM_PPP_STATUS_HOLDOFF;
		phase = "holdoff";
		break;
	case PHASE_MASTER:
		status = NM_PPP_STATUS_MASTER;
		phase = "master";
		break;

	default:
		phase = "unknown";
		break;
	}

	g_message ("pppd reported new phase: %s", phase);

	if (status != NM_PPP_STATUS_UNKNOWN) {
		DBusConnection *connection = (DBusConnection *) data;
		DBusMessage *message;

		message = dbus_message_new_signal (NM_DBUS_PATH_PPP,
									NM_DBUS_INTERFACE_PPP,
									"Status");
		if (!message) {
			g_warning ("Couldn't allocate the dbus message");
			return;
		}

		if (!dbus_message_append_args (message, 
								 DBUS_TYPE_UINT32, &status,
								 DBUS_TYPE_INVALID)) {
			g_warning ("could not append message args");
			goto out;
		}

		if (!dbus_connection_send (connection, message, NULL)) {
			g_warning ("could not send dbus message");
			goto out;
		}

	out:
		dbus_message_unref (message);
	}
}

static const gchar *
ip4_address_as_string (guint32 ip)
{
	struct in_addr tmp_addr;
	gchar *ip_string;

	tmp_addr.s_addr = ip;
	ip_string = inet_ntoa (tmp_addr);

	return ip_string;
}

static void
nm_ip_up (void *data, int arg)
{
	DBusConnection *connection = (DBusConnection *) data;
	DBusMessage *signal;
	DBusMessageIter iter;
	DBusMessageIter iter_dict;
	guint32 ip4_address;
	guint32 ip4_gateway;
	guint32 ip4_dns_1;
	guint32 ip4_dns_2;
	guint32 ip4_wins_1;
	guint32 ip4_wins_2;
	guint32 ip4_netmask = 0xFFFFFFFF; /* Default mask of 255.255.255.255 */

	ip4_address = ipcp_gotoptions[ifunit].ouraddr;
	if (!ip4_address) {
		g_warning ("Didn't receive an internal IP from pppd");
		return;
	}

	ip4_gateway = ipcp_gotoptions[ifunit].hisaddr;

	ip4_dns_1 = ipcp_gotoptions[ifunit].dnsaddr[0];
	ip4_dns_2 = ipcp_gotoptions[ifunit].dnsaddr[1];
	ip4_wins_1 = ipcp_gotoptions[ifunit].winsaddr[0];
	ip4_wins_2 = ipcp_gotoptions[ifunit].winsaddr[1];

	g_message ("Got ip configuration");
	g_message ("address: %s", ip4_address_as_string (ip4_address));
	g_message ("gateway: %s", ip4_address_as_string (ip4_gateway));
	g_message ("netmask: %s", ip4_address_as_string (ip4_netmask));
	g_message ("DNS1: %s",    ip4_address_as_string (ip4_dns_1));
	g_message ("DNS2: %s",    ip4_address_as_string (ip4_dns_2));
	g_message ("WINS1: %s",   ip4_address_as_string (ip4_wins_1));
	g_message ("WINS2: %s",   ip4_address_as_string (ip4_wins_2));

	signal = dbus_message_new_signal (NM_DBUS_PATH_PPP,
							    NM_DBUS_INTERFACE_PPP,
							    "IP4Config");
	if (!signal)
		goto out;

	dbus_message_iter_init_append (signal, &iter);
	if (!nmu_dbus_dict_open_write (&iter, &iter_dict)) {
		g_warning ("dict open write failed!");
		goto out;
	}

	if (!nmu_dbus_dict_append_string (&iter_dict, "interface", ifname)) {
		g_warning ("couldn't append interface to dict");
		goto out;
	}

	if (!nmu_dbus_dict_append_uint32 (&iter_dict, "addres", ip4_address)) {
		g_warning ("couldn't append address to dict");
		goto out;
	}

	if (!nmu_dbus_dict_append_uint32 (&iter_dict, "netmask", ip4_netmask)) {
		g_warning ("couldn't append netmask to dict");
		goto out;
	}

	if (!nmu_dbus_dict_append_uint32 (&iter_dict, "gateway", ip4_gateway)) {
		g_warning ("couldn't append gateway to dict");
		goto out;
	}

	if (ip4_dns_1 || ip4_dns_2) {
		guint32 ip4_dns[2];
		guint32 ip4_dns_len = 0;

		if (ip4_dns_1)
			ip4_dns[ip4_dns_len++] = ip4_dns_1;
		if (ip4_dns_2)
			ip4_dns[ip4_dns_len++] = ip4_dns_2;

		if (!nmu_dbus_dict_append_uint32_array (&iter_dict,
		                                        "dns_server",
		                                        ip4_dns,
		                                        ip4_dns_len)) {
			g_warning ("couldn't append dns_servers to dict");
			goto out;
		}
	}

	if (ip4_wins_1 || ip4_wins_2) {
		guint32 ip4_wins[2];
		guint32 ip4_wins_len = 0;

		if (ip4_wins_1)
			ip4_wins[ip4_wins_len++] = ip4_wins_1;
		if (ip4_wins_2)
			ip4_wins[ip4_wins_len++] = ip4_wins_2;

		if (!nmu_dbus_dict_append_uint32_array (&iter_dict,
		                                        "wins_server",
		                                        ip4_wins,
		                                        ip4_wins_len)) {
			g_warning ("couldn't append wins_servers to dict");
			goto out;
		}
	}

	if (!nmu_dbus_dict_close_write (&iter, &iter_dict)) {
		g_warning ("dict close write failed!");
		goto out;
	}

	if (!dbus_connection_send (connection, signal, NULL)) {
		g_warning ("could not send dbus message");
		goto out;
	}

 out:
	if (signal)
		dbus_message_unref (signal);
}

static void
nm_exit_notify (void *data, int arg)
{
	DBusConnection *connection = (DBusConnection *) data;

	g_message ("exiting");

	if (connection)
		dbus_connection_unref (connection);
}

static DBusConnection *
nm_dbus_prepare_connection (void)
{
	DBusConnection *connection;
	DBusError err;

	dbus_error_init (&err);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!connection || dbus_error_is_set (&err)) {
		g_warning ("Could not get the system bus. Make sure the message bus daemon is running.");
		goto out;
	}

	dbus_connection_set_exit_on_disconnect (connection, FALSE);

	dbus_error_init (&err);
	dbus_bus_request_name (connection, NM_DBUS_SERVICE_PPP, 0, &err);
	if (dbus_error_is_set (&err)) {
		g_warning ("Could not acquire the dbus service. dbus_bus_request_name() says: '%s'.", err.message);
		goto out;
	}

 out:
	if (dbus_error_is_set (&err)) {
		dbus_error_free (&err);
		connection = NULL;
	}

	return connection;
}


int
plugin_init (void)
{
	DBusConnection *connection;

	connection = nm_dbus_prepare_connection ();
	if (connection) {
		add_notifier (&phasechange, nm_phasechange, connection);
		add_notifier (&ip_up_notifier, nm_ip_up, connection);
		add_notifier (&exitnotify, nm_exit_notify, connection);
	}

	return connection ? 0 : -1;
}
