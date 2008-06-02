/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

/* nm-dhcp-manager.c - Handle the DHCP daemon for NetworkManager
 *
 * Copyright (C) 2005 Dan Williams
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */


#include <glib.h>
#include <dbus/dbus.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "nm-dhcp-manager.h"
#include "nm-marshal.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-dbus-manager.h"
#include "nm-dbus-glib-types.h"

#define NM_DHCP_CLIENT_DBUS_SERVICE "org.freedesktop.nm_dhcp_client"
#define NM_DHCP_CLIENT_DBUS_IFACE   "org.freedesktop.nm_dhcp_client"

#define NM_DHCP_MANAGER_RUN_DIR		LOCALSTATEDIR "/run"

#define NM_DHCP_MANAGER_PID_FILENAME	"dhclient"
#define NM_DHCP_MANAGER_PID_FILE_EXT	"pid"

#define NM_DHCP_MANAGER_LEASE_FILENAME	"dhclient"
#define NM_DHCP_MANAGER_LEASE_FILE_EXT	"lease"

#define ACTION_SCRIPT_PATH	LIBEXECDIR "/nm-dhcp-client.action"

#define NM_DHCP_TIMEOUT   	45 /* DHCP timeout, in seconds */

static const char *dhclient_binary_paths[] =
{
	"/sbin/dhclient",
	"/usr/sbin/dhclient",
	"/usr/local/sbin/dhclient",
	NULL
};

typedef struct {
        char *			iface;
        guchar 			state;
        GPid 			dhclient_pid;
        guint			timeout_id;
        guint			watch_id;
        NMDHCPManager *	manager;
        GHashTable *	options;
} NMDHCPDevice;

typedef struct {
	NMDBusManager * dbus_mgr;
	GHashTable *	devices;
	DBusGProxy *	proxy;
} NMDHCPManagerPrivate;


#define NM_DHCP_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP_MANAGER, NMDHCPManagerPrivate))

G_DEFINE_TYPE (NMDHCPManager, nm_dhcp_manager, G_TYPE_OBJECT)

enum {
	STATE_CHANGED,
	TIMEOUT,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static NMDHCPManager *nm_dhcp_manager_new (void);

static void nm_dhcp_manager_cancel_transaction_real (NMDHCPDevice *device, gboolean blocking);

static void stop_dhclient (const char * iface, const pid_t pid, gboolean blocking);

static char *
get_pidfile_for_iface (const char * iface)
{
	return g_strdup_printf ("%s/%s-%s.%s",
	                        NM_DHCP_MANAGER_RUN_DIR,
	                        NM_DHCP_MANAGER_PID_FILENAME,
	                        iface,
	                        NM_DHCP_MANAGER_PID_FILE_EXT);
}


static char *
get_leasefile_for_iface (const char * iface)
{
	return g_strdup_printf ("%s/%s-%s.%s",
	                        NM_DHCP_MANAGER_RUN_DIR,
	                        NM_DHCP_MANAGER_LEASE_FILENAME,
	                        iface,
	                        NM_DHCP_MANAGER_LEASE_FILE_EXT);
}

NMDHCPManager *
nm_dhcp_manager_get (void)
{
	static NMDHCPManager *singleton = NULL;

	if (!singleton)
		singleton = nm_dhcp_manager_new ();
	g_object_ref (singleton);

	return singleton;
}

static void
nm_dhcp_manager_init (NMDHCPManager *manager)
{
}

static void
finalize (GObject *object)
{
	G_OBJECT_CLASS (nm_dhcp_manager_parent_class)->finalize (object);
}

static void
nm_dhcp_manager_class_init (NMDHCPManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMDHCPManagerPrivate));

	/* virtual methods */
	object_class->finalize = finalize;

	/* signals */
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDHCPManagerClass, state_changed),
					  NULL, NULL,
					  nm_marshal_VOID__STRING_UCHAR,
					  G_TYPE_NONE, 2,
					  G_TYPE_STRING,
					  G_TYPE_UCHAR);

	signals[TIMEOUT] =
		g_signal_new ("timeout",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDHCPManagerClass, timeout),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__STRING,
					  G_TYPE_NONE, 1,
					  G_TYPE_STRING);
}

static gboolean state_is_bound (guint8 state)
{
	if ((state == DHC_BOUND)
	    || (state == DHC_RENEW)
	    || (state == DHC_REBOOT)
	    || (state == DHC_REBIND))
		return TRUE;

	return FALSE;
}


static void
nm_dhcp_device_timeout_cleanup (NMDHCPDevice * device)
{
	if (device->timeout_id) {
		g_source_remove (device->timeout_id);
		device->timeout_id = 0;
	}
}

static void
nm_dhcp_device_watch_cleanup (NMDHCPDevice * device)
{
	if (device->watch_id) {
		g_source_remove (device->watch_id);
		device->watch_id = 0;
	}
}

static void
nm_dhcp_device_destroy (NMDHCPDevice *device)
{
	nm_dhcp_device_timeout_cleanup (device);
	nm_dhcp_device_watch_cleanup (device);
	g_hash_table_remove_all (device->options);
	g_free (device->iface);
	g_slice_free (NMDHCPDevice, device);
}


static inline const char *
state_to_string (guint32 state)
{
	switch (state)
	{
		case DHC_PREINIT:
			return "preinit";
		case DHC_BOUND:
			return "bound";
		case DHC_RENEW:
			return "renew";
		case DHC_REBOOT:
			return "reboot";
		case DHC_REBIND:
			return "rebind";
		case DHC_STOP:
			return "stop";
		case DHC_MEDIUM:
			return "medium";
		case DHC_TIMEOUT:
			return "timeout";
		case DHC_FAIL:
			return "fail";
		case DHC_EXPIRE:
			return "expire";
		case DHC_RELEASE:
			return "release";
		case DHC_START:
			return "successfully started";
		case DHC_ABEND:
			return "abnormal exit";
		case DHC_END:
			return "normal exit";
		default:
			break;
	}
	return NULL;
}

static inline guint32
string_to_state (const char *state)
{
	if (strcmp("PREINIT", state) == 0)
		return DHC_PREINIT;
	else if (strcmp("BOUND", state) == 0)
		return DHC_BOUND;
	else if (strcmp("RENEW", state) == 0)
		return DHC_RENEW;
	else if (strcmp("REBOOT", state) == 0)
		return DHC_REBOOT;
	else if (strcmp("REBIND", state) == 0)
		return DHC_REBIND;
	else if (strcmp("STOP", state) == 0)
		return DHC_STOP;
	else if (strcmp("MEDIUM", state) == 0)
		return DHC_MEDIUM;
	else if (strcmp("TIMEOUT", state) == 0)
		return DHC_TIMEOUT;
	else if (strcmp("FAIL", state) == 0)
		return DHC_FAIL;
	else if (strcmp("EXPIRE", state) == 0)
		return DHC_EXPIRE;
	else if (strcmp("RELEASE", state) == 0)
		return DHC_RELEASE;
	else if (strcmp("START", state) == 0)
		return DHC_START;
	else if (strcmp("ABEND", state) == 0)
		return DHC_ABEND;
	else if (strcmp("END", state) == 0)
		return DHC_END;
	else
		return 255;
}

static char *
get_option (GHashTable * hash,
            gpointer key)
{
	GValue * value;

	value = g_hash_table_lookup (hash, key);
	if (value == NULL)
		return NULL;

	if (G_VALUE_TYPE (value) != DBUS_TYPE_G_UCHAR_ARRAY) {
		nm_warning ("Unexpected key %s value type was not "
		            "DBUS_TYPE_G_UCHAR_ARRAY",
		            (char *) key);
		return NULL;
	}

	return nm_utils_garray_to_string ((GArray *) g_value_get_boxed (value));
}

static void
copy_option (gpointer key,
             gpointer value,
             gpointer user_data)
{
	NMDHCPDevice * device = (NMDHCPDevice *) user_data;
	char * dup_key = NULL;
	char * dup_value = NULL;

	dup_key = g_strdup (key);
	if (!dup_key)
		goto error;

	if (G_VALUE_TYPE (value) != DBUS_TYPE_G_UCHAR_ARRAY) {
		nm_warning ("Unexpected key %s value type was not "
		            "DBUS_TYPE_G_UCHAR_ARRAY",
		            (char *) key);
		goto error;
	}

	dup_value = nm_utils_garray_to_string ((GArray *) g_value_get_boxed (value));
	if (!dup_value)
		goto error;

	g_hash_table_insert (device->options, dup_key, dup_value);
	return;

error:
	g_free (dup_key);
	g_free (dup_value);
}

static void
handle_options (NMDHCPManager * manager,
                NMDHCPDevice * device,
                GHashTable * options,
                const char * reason)
{
	guint32 old_state = device->state;
	guint32 new_state = string_to_state (reason);

	/* Clear old and save new DHCP options */
	g_hash_table_remove_all (device->options);
	g_hash_table_foreach (options, copy_option, device);

	if (old_state == new_state)
		return;

	/* Handle changed device state */
	if (state_is_bound (new_state)) {
		/* Cancel the timeout if the DHCP client is now bound */
		nm_dhcp_device_timeout_cleanup (device);
	}

	device->state = new_state;
	nm_info ("DHCP: device %s state changed %s -> %s",
	         device->iface,
	         state_to_string (old_state),
	         state_to_string (device->state));

	g_signal_emit (G_OBJECT (device->manager),
	               signals[STATE_CHANGED],
	               0,
	               device->iface,
	               device->state);
}

static void
nm_dhcp_manager_handle_event (DBusGProxy *proxy,
                              GHashTable *options,
                              gpointer user_data)
{
	NMDHCPManager * manager;
	NMDHCPManagerPrivate * priv;
	NMDHCPDevice * device;
	char * iface = NULL;
	char * pid_str = NULL;
	char * reason = NULL;
	unsigned long temp;
	pid_t pid;

	manager = NM_DHCP_MANAGER (user_data);
	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	iface = get_option (options, "interface");
	if (iface == NULL) {
		nm_warning ("DHCP event didn't have associated interface.");
		goto out;
	}

	device = (NMDHCPDevice *) g_hash_table_lookup (priv->devices, iface);
	if (device == NULL) {
		nm_warning ("Unhandled DHCP event for interface %s", iface);
		goto out;
	}

	pid_str = get_option (options, "pid");
	if (pid_str == NULL) {
		nm_warning ("DHCP event didn't have associated dhclient PID.");
		goto out;
	}

	temp = strtoul(pid_str, NULL, 10);
	if ((temp == ULONG_MAX) && (errno == ERANGE)) {
		nm_warning ("Couldn't convert PID");
		goto out;
	}

	pid = (pid_t) temp;
	if (pid != device->dhclient_pid) {
		nm_warning ("Received DHCP event from unexpected PID %u (expected %u)",
		            pid,
		            device->dhclient_pid);
		goto out;
	}

	reason = get_option (options, "reason");
	if (reason == NULL) {
		nm_warning ("DHCP event didn't have a reason");
		goto out;
	}

	handle_options (manager, device, options, reason);

out:
	g_free (iface);
	g_free (pid_str);
	g_free (reason);
}

static NMDHCPManager *
nm_dhcp_manager_new (void)
{
	NMDHCPManager *manager;
	NMDHCPManagerPrivate *priv;
	DBusGConnection * g_connection;

	manager = g_object_new (NM_TYPE_DHCP_MANAGER, NULL);
	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	priv->devices = g_hash_table_new_full (g_str_hash, g_str_equal,
										   NULL,
										   (GDestroyNotify) nm_dhcp_device_destroy);
	if (!priv->devices) {
		nm_warning ("Error: not enough memory to initialize DHCP manager "
		            "tables");
		g_object_unref (manager);
		manager = NULL;
		goto out;
	}

	priv->dbus_mgr = nm_dbus_manager_get ();
	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	priv->proxy = dbus_g_proxy_new_for_name (g_connection,
	                                         NM_DHCP_CLIENT_DBUS_SERVICE,
	                                         "/",
	                                         NM_DHCP_CLIENT_DBUS_IFACE);
	if (!priv->proxy) {
		nm_warning ("Error: could not init DHCP manager proxy");
		g_object_unref (manager);
	}

	dbus_g_proxy_add_signal (priv->proxy,
	                         "Event",
	                         DBUS_TYPE_G_MAP_OF_VARIANT,
	                         G_TYPE_INVALID);

	dbus_g_proxy_connect_signal (priv->proxy, "Event",
								 G_CALLBACK (nm_dhcp_manager_handle_event),
								 manager,
								 NULL);

out:
	return manager;
}


/*
 * nm_dhcp_manager_handle_timeout
 *
 * Called after timeout of a DHCP transaction to notify device of the failure.
 *
 */
static gboolean
nm_dhcp_manager_handle_timeout (gpointer user_data)
{
	NMDHCPDevice *device = (NMDHCPDevice *) user_data;

	nm_info ("Device '%s' DHCP transaction took too long (>%ds), stopping it.",
			 device->iface, NM_DHCP_TIMEOUT);

	nm_dhcp_manager_cancel_transaction (device->manager, device->iface);

	g_signal_emit (G_OBJECT (device->manager), signals[TIMEOUT], 0, device->iface);

	return FALSE;
}

static NMDHCPDevice *
nm_dhcp_device_new (NMDHCPManager *manager, const char *iface)
{
	NMDHCPDevice *device;
	GHashTable * hash = NM_DHCP_MANAGER_GET_PRIVATE (manager)->devices;

	device = g_slice_new0 (NMDHCPDevice);
	if (!device) {
		nm_warning ("%s: Out of memory creating DHCP transaction object.", iface);
		return NULL;
	}

	device->iface = g_strdup (iface);
	if (!device) {
		nm_warning ("%s: Out of memory creating DHCP transaction object "
		            "property 'iface'.",
		            iface);
		goto error;
	}
	
	device->manager = manager;

	nm_dhcp_manager_cancel_transaction_real (device, FALSE);

	/* Do this after the transaction cancel since that clears options out */
	device->options = g_hash_table_new_full (g_str_hash,
	                                         g_str_equal,
	                                         g_free,
	                                         g_free);
	if (!device->options) {
		nm_warning ("%s: Out of memory creating DHCP transaction object "
		            "property 'options'.",
		            iface);
		goto error;
	}

	g_hash_table_insert (hash, device->iface, device);
	return device;

error:
	g_hash_table_destroy (device->options);
	g_free (device->iface);
	g_slice_free (NMDHCPDevice, device);
	return NULL;
}


/*
 * dhclient_watch_cb
 *
 * Watch our child dhclient process and get notified of events from it.
 *
 */
static void dhclient_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMDHCPDevice *device = (NMDHCPDevice *)user_data;

	if (!WIFEXITED (status)) {
		device->state = DHC_ABEND;
		nm_warning ("dhclient died abnormally");
	}
	device->dhclient_pid = 0;

	nm_dhcp_device_watch_cleanup (device);
	nm_dhcp_device_timeout_cleanup (device);

	g_signal_emit (G_OBJECT (device->manager), signals[STATE_CHANGED], 0, device->iface, device->state);
}

/*
 * nm_vpn_service_child_setup
 *
 * Give child a different process group to ensure signal separation.
 *
 */
static void
dhclient_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process at this point */
	pid_t pid = getpid ();
	setpgid (pid, pid);
}

static gboolean
dhclient_run (NMDHCPDevice *device)
{
	const char **	dhclient_binary = NULL;
	GPtrArray *		dhclient_argv = NULL;
	GPid			pid;
	GError *		error = NULL;
	char *			pidfile = NULL;
	char *			leasefile = NULL;
	char *			conffile = NULL;
	gboolean		success = FALSE;
	char *			pid_contents = NULL;

	/* Find dhclient */
	dhclient_binary = dhclient_binary_paths;
	while (*dhclient_binary != NULL) {
		if (g_file_test (*dhclient_binary, G_FILE_TEST_EXISTS))
			break;
		dhclient_binary++;
	}

	if (!*dhclient_binary) {
		nm_warning ("Could not find dhclient binary.");
		goto out;
	}

	pidfile = get_pidfile_for_iface (device->iface);
	if (!pidfile) {
		nm_warning ("%s: not enough memory for dhclient options.", device->iface);
		goto out;
	}

	leasefile = get_leasefile_for_iface (device->iface);
	if (!leasefile) {
		nm_warning ("%s: not enough memory for dhclient options.", device->iface);
		goto out;
	}

	conffile = g_strdup_printf (SYSCONFDIR "/dhclient-%s.conf", device->iface);
	if (!conffile) {
		nm_warning ("%s: not enough memory for dhclient options.", device->iface);
		goto out;
	}

	/* Kill any existing dhclient bound to this interface */
	if (g_file_get_contents (pidfile, &pid_contents, NULL, NULL)) {
		unsigned long int tmp = strtoul (pid_contents, NULL, 10);

		if (!((tmp == ULONG_MAX) && (errno == ERANGE)))
			stop_dhclient (device->iface, (pid_t) tmp, TRUE);
		remove (pidfile);
	}

	dhclient_argv = g_ptr_array_new ();
	g_ptr_array_add (dhclient_argv, (gpointer) (*dhclient_binary));

	g_ptr_array_add (dhclient_argv, (gpointer) "-d");

	g_ptr_array_add (dhclient_argv, (gpointer) "-sf");	/* Set script file */
	g_ptr_array_add (dhclient_argv, (gpointer) ACTION_SCRIPT_PATH );

	g_ptr_array_add (dhclient_argv, (gpointer) "-pf");	/* Set pid file */
	g_ptr_array_add (dhclient_argv, (gpointer) pidfile);

	g_ptr_array_add (dhclient_argv, (gpointer) "-lf");	/* Set lease file */
	g_ptr_array_add (dhclient_argv, (gpointer) leasefile);

	g_ptr_array_add (dhclient_argv, (gpointer) "-cf");	/* Set interface config file */
	g_ptr_array_add (dhclient_argv, (gpointer) conffile);

	g_ptr_array_add (dhclient_argv, (gpointer) device->iface);
	g_ptr_array_add (dhclient_argv, NULL);

	if (!g_spawn_async (NULL, (char **) dhclient_argv->pdata, NULL, 0,
	                    &dhclient_child_setup, NULL, &pid, &error)) {
		nm_warning ("dhclient failed to start.  error: '%s'", error->message);
		g_error_free (error);
		goto out;
	}

	nm_info ("dhclient started with pid %d", pid);

	device->dhclient_pid = pid;
	device->watch_id = g_child_watch_add (pid,
	                                      (GChildWatchFunc) dhclient_watch_cb,
	                                      device);
	success = TRUE;

out:
	g_free (pid_contents);
	g_free (conffile);
	g_free (leasefile);
	g_free (pidfile);
	g_ptr_array_free (dhclient_argv, TRUE);
	return success;
}

gboolean
nm_dhcp_manager_begin_transaction (NMDHCPManager *manager,
								   const char *iface,
								   guint32 timeout)
{
	NMDHCPManagerPrivate *priv;
	NMDHCPDevice *device;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (manager), FALSE);
	g_return_val_if_fail (iface != NULL, FALSE);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	device = (NMDHCPDevice *) g_hash_table_lookup (priv->devices, iface);
	if (!device)
		device = nm_dhcp_device_new (manager, iface);

	if (state_is_bound (device->state) || (device->state == DHC_START)) {
		/* Cancel any DHCP transaction already in progress */
		nm_dhcp_manager_cancel_transaction_real (device, TRUE);
	}

	nm_info ("Activation (%s) Beginning DHCP transaction.", iface);

	if (timeout == 0)
		timeout = NM_DHCP_TIMEOUT;

	/* Set up a timeout on the transaction to kill it after the timeout */
	device->timeout_id = g_timeout_add (timeout * 1000,
	                                    nm_dhcp_manager_handle_timeout,
	                                    device);

	dhclient_run (device);

	return TRUE;
}

static void
stop_dhclient (const char * iface,
               pid_t pid,
               gboolean blocking)
{
	int i = 20; /* 4 seconds */

	/* Tell it to quit */
	kill (pid, SIGTERM);

	while (blocking && i-- > 0) {
		gint child_status;
		int ret;
		ret = waitpid (pid, &child_status, WNOHANG);
		if (ret > 0) {
			break;
		} else if (ret == -1) {
			/* Child already exited */
			if (errno == ECHILD)
				break;
			/* Otherwise, force kill the process */
			i = 0;
			break;
		}
		g_usleep (G_USEC_PER_SEC / 5);
	}

	if (i <= 0) {
		nm_warning ("%s: dhclient pid %d didn't exit, will kill it.", iface, pid);
		kill (pid, SIGKILL);
	}
}

static void
nm_dhcp_manager_cancel_transaction_real (NMDHCPDevice *device, gboolean blocking)
{
	char * pidfile;
	char * leasefile;

	if (!device->dhclient_pid)
		return;

	stop_dhclient (device->iface, device->dhclient_pid, blocking);

	nm_info ("%s: canceled DHCP transaction, dhclient pid %d",
	         device->iface,
	         device->dhclient_pid);

	device->dhclient_pid = 0;
	device->state = DHC_END;

	/* Clean up the pidfile if it got left around */
	pidfile = get_pidfile_for_iface (device->iface);
	if (pidfile) {
		remove (pidfile);
		g_free (pidfile);
	}

	/* Clean up the leasefile if it got left around */
	leasefile = get_leasefile_for_iface (device->iface);
	if (leasefile) {
		remove (leasefile);
		g_free (leasefile);
	}

	nm_dhcp_device_watch_cleanup (device);
	nm_dhcp_device_timeout_cleanup (device);
	g_hash_table_remove_all (device->options);
}


/*
 * nm_dhcp_manager_cancel_transaction
 *
 * Stop any in-progress DHCP transaction on a particular device.
 *
 */
void
nm_dhcp_manager_cancel_transaction (NMDHCPManager *manager,
                                    const char *iface)
{
	NMDHCPDevice *device;
	NMDHCPManagerPrivate *priv;

	g_return_if_fail (NM_IS_DHCP_MANAGER (manager));
	g_return_if_fail (iface != NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	device = (NMDHCPDevice *) g_hash_table_lookup (priv->devices, iface);

	if (!device || !device->dhclient_pid)
		return;

	nm_dhcp_manager_cancel_transaction_real (device, TRUE);
}


/*
 * nm_dhcp_manager_get_ip4_config
 *
 * Get IP4 configuration values from the DHCP daemon
 *
 */
NMIP4Config *
nm_dhcp_manager_get_ip4_config (NMDHCPManager *manager,
                                const char *iface)
{
	NMDHCPManagerPrivate *priv;
	NMDHCPDevice *device;
	NMIP4Config *ip4_config = NULL;
	struct in_addr tmp_addr;
	NMSettingIP4Address *addr = NULL;
	char *str = NULL;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (manager), NULL);
	g_return_val_if_fail (iface != NULL, NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	device = (NMDHCPDevice *) g_hash_table_lookup (priv->devices, iface);
	if (!device) {
		nm_warning ("Device '%s' transaction not started.", iface);
		return NULL;
	}

	if (!state_is_bound (device->state)) {
		nm_warning ("%s: dhclient didn't bind to a lease.", device->iface);
		return NULL;
	}

	ip4_config = nm_ip4_config_new ();
	if (!ip4_config) {
		nm_warning ("%s: couldn't allocate memory for an IP4Config!", device->iface);
		return NULL;
	}

	addr = g_malloc0 (sizeof (NMSettingIP4Address));
	if (!addr) {
		nm_warning ("%s: couldn't allocate memory for an IP4 Address!", device->iface);
		goto error;
	}

	str = g_hash_table_lookup (device->options, "new_ip_address");
	if (str && inet_aton (str, &tmp_addr)) {
		addr->address = tmp_addr.s_addr;
		nm_info ("  address %s", str);
	} else
		goto error;

	str = g_hash_table_lookup (device->options, "new_subnet_mask");
	if (str && inet_aton (str, &tmp_addr)) {
		addr->netmask = tmp_addr.s_addr;
		nm_info ("  netmask %s", str);
	}

	str = g_hash_table_lookup (device->options, "new_routers");
	if (str && inet_aton (str, &tmp_addr)) {
		addr->gateway = tmp_addr.s_addr;
		nm_info("  gateway %s", str);
	}

	nm_ip4_config_take_address (ip4_config, addr);
	addr = NULL;

	str = g_hash_table_lookup (device->options, "new_host_name");
	if (str) {
		nm_ip4_config_set_hostname (ip4_config, str);
		nm_info ("  hostname '%s'", str);
	}

	str = g_hash_table_lookup (device->options, "new_domain_name_servers");
	if (str) {
		char **searches = g_strsplit (str, " ", 0);
		char **s;

		for (s = searches; *s; s++) {
			if (inet_aton (*s, &tmp_addr)) {
				nm_ip4_config_add_nameserver (ip4_config, tmp_addr.s_addr);
				nm_info ("  nameserver '%s'", *s);
			} else
				nm_warning ("Ignoring invalid nameserver '%s'", *s);
		}
		g_strfreev (searches);
	}

	str = g_hash_table_lookup (device->options, "new_domain_name");
	if (str) {
		char **domains = g_strsplit (str, " ", 0);
		char **s;

		for (s = domains; *s; s++) {
			nm_info ("  domain name '%s'", *s);
			nm_ip4_config_add_domain (ip4_config, *s);
		}
		g_strfreev (domains);
	}

	str = g_hash_table_lookup (device->options, "new_domain_search");
	if (str) {
		char **searches = g_strsplit (str, " ", 0);
		char **s;

		for (s = searches; *s; s++) {
			nm_info ("  domain search '%s'", *s);
			nm_ip4_config_add_search (ip4_config, *s);
		}
		g_strfreev (searches);
	}

	str = g_hash_table_lookup (device->options, "new_nis_domain");
	if (str) {
		nm_ip4_config_set_nis_domain (ip4_config, str);
		nm_info ("  nis domain '%s'", str);
	}

	str = g_hash_table_lookup (device->options, "new_nis_servers");
	if (str) {
		char **searches = g_strsplit (str, " ", 0);
		char **s;

		for (s = searches; *s; s++) {
			if (inet_aton (*s, &tmp_addr)) {
				nm_ip4_config_add_nis_server (ip4_config, tmp_addr.s_addr);
				nm_info ("  nis server '%s'", *s);
			} else
				nm_warning ("Ignoring invalid nis server '%s'", *s);
		}
		g_strfreev (searches);
	}

	str = g_hash_table_lookup (device->options, "new_static_routes");
	if (str) {
		char **searches = g_strsplit (str, " ", 0);

		if ((g_strv_length (searches) % 2) == 0) {
			char **s;

			for (s = searches; *s; s += 2) {
				struct in_addr rt_addr;
				struct in_addr rt_route;

				if (inet_aton (*s, &rt_addr) == 0) {
					nm_warning ("DHCP provided invalid static route address: '%s'", *s);
					continue;
				}
				if (inet_aton (*(s + 1), &rt_route) == 0) {
					nm_warning ("DHCP provided invalid static route gateway: '%s'", *(s + 1));
					continue;
				}

				// FIXME: ensure the IP addresse and route are sane

				addr = g_malloc0 (sizeof (NMSettingIP4Address));
				addr->address = (guint32) rt_addr.s_addr;
				addr->netmask = 0xFFFFFFFF; /* 255.255.255.255 */
				addr->gateway = (guint32) rt_route.s_addr;

				nm_ip4_config_take_static_route (ip4_config, addr);
				addr = NULL;
				nm_info ("  static route %s gw %s", *s, *(s + 1));
			}
		} else {
			nm_info ("  static routes provided, but invalid");
		}
		g_strfreev (searches);
	}

	str = g_hash_table_lookup (device->options, "new_interface_mtu");
	if (str) {
		int int_mtu = atoi (str);

		if (int_mtu)
			nm_ip4_config_set_mtu (ip4_config, int_mtu);
	}

	return ip4_config;

error:
	if (addr)
		g_free (addr);

	g_object_unref (ip4_config);

	return NULL;
}
