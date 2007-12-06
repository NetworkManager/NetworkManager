/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <pppd/pppd.h>
#include <pppd/fsm.h>
#include <pppd/ipcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glib/gtypes.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>

#include "nm-pppd-plugin.h"
#include "nm-ppp-status.h"
#include "nm-pppd-plugin-glue.h"

GType nm_pppd_plugin_get_type (void);
int plugin_init (void);

char pppd_version[] = VERSION;

#define NM_TYPE_PPPD_PLUGIN            (nm_pppd_plugin_get_type ())
#define NM_PPPD_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_PPPD_PLUGIN, NMPppdPlugin))
#define NM_PPPD_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_PPPD_PLUGIN, NMPppdPluginClass))
#define NM_IS_PPPD_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_PPPD_PLUGIN))
#define NM_IS_PPPD_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_PPPD_PLUGIN))
#define NM_PPPD_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_PPPD_PLUGIN, NMPppdPluginClass))

typedef struct {
	GObject parent;
} NMPppdPlugin;

typedef struct {
	GObjectClass parent;

	void (*state_changed)  (NMPppdPlugin *plugin,
					    NMPPPStatus status);
	void (*ip4_config)     (NMPppdPlugin *plugin,
					    GHashTable  *ip4_config);
} NMPppdPluginClass;

G_DEFINE_TYPE (NMPppdPlugin, nm_pppd_plugin, G_TYPE_OBJECT)

#define NM_PPPD_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_PPPD_PLUGIN, NMPppdPluginPrivate))

typedef struct {
	DBusGConnection *bus;
} NMPppdPluginPrivate;

enum {
	STATE_CHANGED,
	IP4_CONFIG,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void
nm_pppd_plugin_init (NMPppdPlugin *plugin)
{
}

static void
finalize (GObject *object)
{
	dbus_g_connection_unref (NM_PPPD_PLUGIN_GET_PRIVATE (object)->bus);

	G_OBJECT_CLASS (nm_pppd_plugin_parent_class)->finalize (object);
}

static void
nm_pppd_plugin_class_init (NMPppdPluginClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);

	g_type_class_add_private (object_class, sizeof (NMPppdPluginPrivate));
	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (plugin_class),
							   &dbus_glib_nm_pppd_plugin_object_info);

	object_class->finalize = finalize;

	/* signals */
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMPppdPluginClass, state_changed),
				    NULL, NULL,
				    g_cclosure_marshal_VOID__UINT,
				    G_TYPE_NONE, 1,
				    G_TYPE_UINT);

	signals[IP4_CONFIG] =
		g_signal_new ("ip4-config",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMPppdPluginClass, ip4_config),
				    NULL, NULL,
				    g_cclosure_marshal_VOID__BOXED,
				    G_TYPE_NONE, 1,
				    dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE));
}

static NMPppdPlugin *
nm_pppd_plugin_new (DBusGConnection *bus)
{
	GObject *obj;

	obj = g_object_new (NM_TYPE_PPPD_PLUGIN, NULL);
	if (!obj)
		return NULL;

	NM_PPPD_PLUGIN_GET_PRIVATE (obj)->bus = dbus_g_connection_ref (bus);
	dbus_g_connection_register_g_object (bus, NM_DBUS_PATH_PPP, obj);

	return (NMPppdPlugin *) obj;
}

static void
nm_pppd_plugin_state_changed (NMPppdPlugin *plugin, NMPPPStatus ppp_status)
{
	g_signal_emit (plugin, signals[STATE_CHANGED], 0, ppp_status);
}

static void
nm_pppd_plugin_ip4_config (NMPppdPlugin *plugin, GHashTable *ip4_config)
{
	g_signal_emit (plugin, signals[IP4_CONFIG], 0, ip4_config);
}

/*****************************************************************************/

static void
nm_phasechange (void *data, int arg)
{
	NMPppdPlugin *plugin = NM_PPPD_PLUGIN (data);
	NMPPPStatus ppp_status = NM_PPP_STATUS_UNKNOWN;
	char *ppp_phase;

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

	if (ppp_status != NM_PPP_STATUS_UNKNOWN)
		nm_pppd_plugin_state_changed (plugin, ppp_status);
}

static GValue *
str_to_gvalue (const char *str)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, str);

	return val;
}

static GValue *
uint_to_gvalue (guint32 i)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_UINT);
	g_value_set_uint (val, i);

	return val;
}

static void
value_destroy (gpointer data)
{
	GValue *val = (GValue *) data;

	g_value_unset (val);
	g_slice_free (GValue, val);
}

static void
nm_ip_up (void *data, int arg)
{
	NMPppdPlugin *plugin = NM_PPPD_PLUGIN (data);
	ipcp_options opts = ipcp_gotoptions[ifunit];
	GHashTable *hash;
	GArray *array;
	GValue *val;

	if (!opts.ouraddr) {
		g_warning ("Didn't receive an internal IP from pppd");
		return;
	}

	hash = g_hash_table_new_full (g_str_hash, g_str_equal,
							NULL, value_destroy);

	g_hash_table_insert (hash, NM_PPP_IP4_CONFIG_INTERFACE, 
					 str_to_gvalue (ifname));
	g_hash_table_insert (hash, NM_PPP_IP4_CONFIG_ADDRESS, 
					 uint_to_gvalue (opts.ouraddr));
	g_hash_table_insert (hash, NM_PPP_IP4_CONFIG_GATEWAY, 
					 uint_to_gvalue (opts.hisaddr));
	g_hash_table_insert (hash, NM_PPP_IP4_CONFIG_NETMASK, 
					 uint_to_gvalue (0xFFFFFFFF));

	if (opts.dnsaddr[0] || opts.dnsaddr[1]) {
		array = g_array_new (FALSE, FALSE, sizeof (guint32));

		if (opts.dnsaddr[0])
			g_array_append_val (array, opts.dnsaddr[0]);
		if (opts.dnsaddr[1])
			g_array_append_val (array, opts.dnsaddr[1]);

		val = g_slice_new0 (GValue);
		g_value_init (val, DBUS_TYPE_G_UINT_ARRAY);
		g_value_set_boxed (val, array);

		g_hash_table_insert (hash, NM_PPP_IP4_CONFIG_DNS, val);
	}

	if (opts.winsaddr[0] || opts.winsaddr[1]) {
		array = g_array_new (FALSE, FALSE, sizeof (guint32));

		if (opts.winsaddr[0])
			g_array_append_val (array, opts.winsaddr[0]);
		if (opts.winsaddr[1])
			g_array_append_val (array, opts.winsaddr[1]);

		val = g_slice_new0 (GValue);
		g_value_init (val, DBUS_TYPE_G_UINT_ARRAY);
		g_value_set_boxed (val, array);

		g_hash_table_insert (hash, NM_PPP_IP4_CONFIG_WINS, val);
	}

	nm_pppd_plugin_ip4_config (plugin, hash);
	g_hash_table_destroy (hash);
}

static void
nm_exit_notify (void *data, int arg)
{
	NMPppdPlugin *plugin = NM_PPPD_PLUGIN (data);

	g_object_unref (plugin);
}

int
plugin_init (void)
{
	DBusGConnection *bus;
	DBusGProxy *bus_proxy;
	NMPppdPlugin *plugin;
	guint request_name_result;
	GError *err = NULL;

	g_type_init ();

	bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!bus) {
		g_warning ("Couldn't connect to system bus: %s", err->message);
		g_error_free (err);
		return -1;
	}

	bus_proxy = dbus_g_proxy_new_for_name (bus,
								    "org.freedesktop.DBus",
								    "/org/freedesktop/DBus",
								    "org.freedesktop.DBus");

	if (!dbus_g_proxy_call (bus_proxy, "RequestName", &err,
					    G_TYPE_STRING, NM_DBUS_SERVICE_PPP,
					    G_TYPE_UINT, 0,
					    G_TYPE_INVALID,
					    G_TYPE_UINT, &request_name_result,
					    G_TYPE_INVALID)) {
		g_warning ("Failed to acquire '" NM_DBUS_SERVICE_PPP "'");
		g_error_free (err);
		dbus_g_connection_unref (bus);
		g_object_unref (bus_proxy);

		return -1;
	}

	g_object_unref (bus_proxy);

	plugin = nm_pppd_plugin_new (bus);
	dbus_g_connection_unref (bus);

	add_notifier (&phasechange, nm_phasechange, plugin);
	add_notifier (&ip_up_notifier, nm_ip_up, plugin);
	add_notifier (&exitnotify, nm_exit_notify, plugin);

	return 0;
}
