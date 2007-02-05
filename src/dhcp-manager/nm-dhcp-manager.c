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
#include <string.h>

#include "nm-dhcp-manager.h"
#include "nm-dhcp-marshal.h"
#include "nm-dbus-manager.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"


#define DHCP_SERVICE_NAME "com.redhat.dhcp"
#define DHCP_OBJECT_PATH  "/com/redhat/dhcp"
#define NM_DHCP_TIMEOUT   45 /* DHCP timeout, in seconds */

typedef struct {
	char *iface;
	DBusGProxy *listener_proxy;
	guchar state;
	guint timeout_id;

	NMDHCPManager *manager;
} NMDHCPDevice;

typedef struct {
	gboolean running;
	NMDBusManager *dbus_mgr;
	GHashTable *devices;
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

static void nm_dhcp_manager_cancel_transaction_real (NMDHCPManager *manager,
													 NMDHCPDevice *device,
													 gboolean blocking);

static void nm_dhcp_manager_name_owner_changed (NMDBusManager *dbus_mgr,
                                                DBusConnection *connection,
                                                const char *name,
                                                const char *old,
                                                const char *new,
                                                gpointer user_data);

static void nm_dhcp_manager_dbus_connection_changed (NMDBusManager *dbus_mgr,
                                                     DBusConnection *connection,
                                                     gpointer user_data);

NMDHCPManager *
nm_dhcp_manager_get (void)
{
	static NMDHCPManager *singleton = NULL;

	if (!singleton)
		singleton = nm_dhcp_manager_new ();
	else
		g_object_ref (singleton);

	return singleton;
}

static void
nm_dhcp_manager_init (NMDHCPManager *msg)
{
}

static void
finalize (GObject *object)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (object);

	g_object_unref (priv->dbus_mgr);

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
					  nm_dhcp_marshal_VOID__STRING_UCHAR,
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
	if ((state == DHCDBD_BOUND)
	    || (state == DHCDBD_RENEW)
	    || (state == DHCDBD_REBOOT)
	    || (state == DHCDBD_REBIND)
		|| (state == DHCDBD_START))
		return TRUE;

	return FALSE;
}


static gboolean state_is_down (guint8 state)
{
	if (   (state == DHCDBD_NBI)
	    || (state == DHCDBD_RELEASE)
	    || (state == DHCDBD_ABEND)
	    || (state == DHCDBD_END))
		return TRUE;

	return FALSE;
}


static void
nm_dhcp_device_destroy (NMDHCPDevice *device)
{
	g_free (device->iface);
	g_slice_free (NMDHCPDevice, device);
}


static NMDHCPManager *
nm_dhcp_manager_new (void)
{
	NMDHCPManager *manager;
	NMDHCPManagerPrivate *priv;

	manager = g_object_new (NM_TYPE_DHCP_MANAGER, NULL);
	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);
	priv->dbus_mgr = nm_dbus_manager_get ();
	priv->running = nm_dbus_manager_name_has_owner (priv->dbus_mgr,
													DHCP_SERVICE_NAME);

	priv->devices = g_hash_table_new_full (g_str_hash, g_str_equal,
										   NULL,
										   (GDestroyNotify) nm_dhcp_device_destroy);

	g_signal_connect (G_OBJECT (priv->dbus_mgr),
	                  "name-owner-changed",
	                  G_CALLBACK (nm_dhcp_manager_name_owner_changed),
	                  manager);
	g_signal_connect (G_OBJECT (priv->dbus_mgr),
	                  "dbus-connection-changed",
	                  G_CALLBACK (nm_dhcp_manager_dbus_connection_changed),
	                  manager);

	return manager;
}


NMDHCPState
nm_dhcp_manager_get_state_for_device (NMDHCPManager *manager,
									  const char *iface)
{
	NMDHCPDevice *device;
	char *path;
	NMDHCPState state = 0;
	NMDHCPManagerPrivate *priv;
	DBusGConnection *connection;
	DBusGProxy *proxy;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (manager), 0);
	g_return_val_if_fail (iface != NULL, 0);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	if (!priv->running) {
		nm_warning ("dhcdbd not running!");
		return 0;
	}

	/* First, see if we've already got it's device from signal. */
	device = (NMDHCPDevice *) g_hash_table_lookup (priv->devices, iface);
	if (device)
		return device->state;

	/* Nope, do it the hard (and slow) way. */
	connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	if (!connection) {
		nm_warning ("could not get dbus connection.");
		return 0;
	}

	path = g_strdup_printf (DHCP_OBJECT_PATH"/%s", iface);
	proxy = dbus_g_proxy_new_for_name (connection,
									   DHCP_SERVICE_NAME,
									   path,
									   DHCP_SERVICE_NAME ".dbus.get");
	g_free (path);

	if (!dbus_g_proxy_call (proxy, "reason", &err,
							G_TYPE_INVALID,
							G_TYPE_UINT, &state,
							G_TYPE_INVALID)) {
		/* Sssh... it's OK to get an error here, we don't necessarily know if the device
		   is added or not. */
		g_error_free (err);
	}

	g_object_unref (proxy);

	return state;
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

	g_signal_emit (G_OBJECT (device->manager), signals[TIMEOUT], 0, device->iface);

	nm_dhcp_manager_cancel_transaction (device->manager, device->iface, FALSE);

	return FALSE;
}


static inline const char * state_to_string (guchar state)
{
	switch (state)
	{
		case DHCDBD_PREINIT:
			return "starting";
		case DHCDBD_BOUND:
			return "bound";
		case DHCDBD_RENEW:
			return "renew";
		case DHCDBD_REBOOT:
			return "reboot";
		case DHCDBD_REBIND:
			return "rebind";
		case DHCDBD_TIMEOUT:
			return "timeout";
		case DHCDBD_FAIL:
			return "fail";
		case DHCDBD_START:
			return "successfully started";
		case DHCDBD_ABEND:
			return "abnormal exit";
		case DHCDBD_END:
			return "normal exit";
		default:
			break;
	}
	return NULL;
}

static void
proxy_state_changed (DBusGProxy *proxy, guchar state, gpointer user_data)
{
	NMDHCPDevice *device = (NMDHCPDevice *) user_data;
	const char *desc;

	if (device->state == state)
		return;

	device->state = state;

	desc = state_to_string (state);
	nm_info ("DHCP daemon state is now %d (%s) for interface %s",
			 state, desc ? desc : "unknown", device->iface);

	
	if (device->timeout_id) {
		g_source_remove (device->timeout_id);
		device->timeout_id = 0;
	}

	g_signal_emit (G_OBJECT (device->manager), signals[STATE_CHANGED], 0, device->iface, state);
}

static NMDHCPDevice *
nm_dhcp_device_new (NMDHCPManager *manager, const char *iface)
{
	NMDHCPDevice *device;
	GHashTable *hash = NM_DHCP_MANAGER_GET_PRIVATE (manager)->devices;

	DBusGConnection *connection = nm_dbus_manager_get_connection (NM_DHCP_MANAGER_GET_PRIVATE (manager)->dbus_mgr);

	device = g_slice_new0 (NMDHCPDevice);
	device->iface = g_strdup (iface);
	device->manager = manager;

	device->listener_proxy = dbus_g_proxy_new_for_name (connection,
														DHCP_SERVICE_NAME,
														DHCP_OBJECT_PATH,
														DHCP_SERVICE_NAME ".state");

	dbus_g_proxy_add_signal (device->listener_proxy, iface, G_TYPE_UCHAR, G_TYPE_INVALID);

	dbus_g_proxy_connect_signal (device->listener_proxy,
								 iface,
								 G_CALLBACK (proxy_state_changed),
								 device,
								 NULL);

	device->state = nm_dhcp_manager_get_state_for_device (manager, iface);

	g_hash_table_insert (hash, device->iface, device);

	return device;
}

gboolean
nm_dhcp_manager_begin_transaction (NMDHCPManager *manager,
								   const char *iface)
{
	NMDHCPManagerPrivate *priv;
	DBusGConnection *connection;
	DBusGProxy *proxy = NULL;
	NMDHCPDevice *device;
	char *path;
	guint tmp;
	const guint32 opt1 = 31;  /* turns off ALL actions and dhclient-script just writes options to dhcdbd */
	const guint32 opt2 = 2;   /* dhclient is run in ONE SHOT mode and releases existing leases when brought down */
	GError *err = NULL;
	gboolean success = FALSE;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (manager), FALSE);
	g_return_val_if_fail (iface != NULL, FALSE);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	if (!priv->running) {
		nm_warning ("dhcdbd not running!");
		return FALSE;
	}

	connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	if (!connection) {
		nm_warning ("could not get dbus connection.");
		return FALSE;
	}

	device = (NMDHCPDevice *) g_hash_table_lookup (priv->devices, iface);
	if (!device)
		device = nm_dhcp_device_new (manager, iface);

	if (state_is_bound (device->state)) {
		/* Cancel any DHCP transaction already in progress */
		nm_dhcp_manager_cancel_transaction_real (manager, device, TRUE);
	}

	path = g_strdup_printf (DHCP_OBJECT_PATH"/%s", iface);
	proxy = dbus_g_proxy_new_for_name (connection,
									   DHCP_SERVICE_NAME,
									   path,
									   DHCP_SERVICE_NAME);
	g_free (path);

	nm_info ("Activation (%s) Beginning DHCP transaction.", iface);

	if (!dbus_g_proxy_call (proxy, "up", &err,
							G_TYPE_UINT, opt1,
							G_TYPE_UINT, opt2,
							G_TYPE_INVALID,
							G_TYPE_UINT, &tmp,
							G_TYPE_INVALID)) {
		nm_warning ("Couldn't send DHCP 'up' message because: '%s'", err->message);
		g_error_free (err);
		goto out;
	}

	/* Set up a timeout on the transaction to kill it after NM_DHCP_TIMEOUT seconds */
	device->timeout_id = g_timeout_add (NM_DHCP_TIMEOUT * 1000,
										nm_dhcp_manager_handle_timeout,
										device);
	success = TRUE;

out:
	if (proxy)
		g_object_unref (proxy);

	return success;
}

static void
nm_dhcp_manager_cancel_transaction_real (NMDHCPManager *manager,
										 NMDHCPDevice *device,
										 gboolean blocking)
{
	DBusGConnection *connection;
	DBusGProxy *proxy = NULL;
	char *path;
	guint *tmp;
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);
	GError *err = NULL;

	if (!state_is_bound (device->state))
		return;

	connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	if (!connection) {
		nm_warning ("could not get dbus connection.");
		return;
	}

	path = g_strdup_printf (DHCP_OBJECT_PATH"/%s", device->iface);
	proxy = dbus_g_proxy_new_for_name (connection,
									   DHCP_SERVICE_NAME,
									   path,
									   DHCP_SERVICE_NAME);
	g_free (path);

	if (!dbus_g_proxy_call (proxy, "down", &err,
							G_TYPE_INVALID,
							G_TYPE_UINT, &tmp,
							G_TYPE_INVALID)) {
		nm_warning ("Couldn't send DHCP 'down' message because: '%s'", err->message);
		g_error_free (err);
		goto out;
	}

	/* Yes, the state has to reach DHCDBD_END. */
	while (blocking && device->state != DHCDBD_END) {
		while (g_main_context_pending (NULL))
			g_main_context_iteration (NULL, TRUE);

		g_usleep (G_USEC_PER_SEC / 5);
	}

	if (device->timeout_id) {
		g_source_remove (device->timeout_id);
		device->timeout_id = 0;
	}

 out:
	if (proxy)
		g_object_unref (proxy);
}


/*
 * nm_dhcp_manager_cancel_transaction
 *
 * Stop any in-progress DHCP transaction on a particular device.
 *
 */
void
nm_dhcp_manager_cancel_transaction (NMDHCPManager *manager,
                                    const char *iface,
									gboolean blocking)
{
	NMDHCPDevice *device;
	NMDHCPManagerPrivate *priv;

	g_return_if_fail (NM_IS_DHCP_MANAGER (manager));
	g_return_if_fail (iface != NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	if (!priv->running)
		return;

	device = (NMDHCPDevice *) g_hash_table_lookup (priv->devices, iface);

	if (!device || state_is_down (device->state))
		return;

	nm_dhcp_manager_cancel_transaction_real (manager, device, blocking);
}


static gboolean
get_ip4_uint32s (DBusConnection *dbus_connection,
                 const char *path,
                 const char *item,
                 guint32 **ip4_uint32,
                 guint32 *num_items,
                 gboolean ignore_error)
{
	DBusMessage *	message = NULL;
	DBusMessage *	reply = NULL;
	gboolean	success = FALSE;
	DBusError	error;
	GArray *	buffer;
	DBusMessageIter	iter;

	g_return_val_if_fail (dbus_connection != NULL, FALSE);
	g_return_val_if_fail (path != NULL, FALSE);
	g_return_val_if_fail (ip4_uint32 != NULL, FALSE);
	g_return_val_if_fail (num_items != NULL, FALSE);

	*ip4_uint32 = NULL;
	*num_items = 0;
	message = dbus_message_new_method_call (DHCP_SERVICE_NAME,
	                                        path,
	                                        DHCP_SERVICE_NAME".dbus.get",
	                                        item);
	if (!message) {
		nm_warning ("could not allocate dbus message.");
		goto out;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (dbus_connection,
	                                                   message,
	                                                   -1,
	                                                   &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error)) {
		if (!ignore_error) {
			nm_warning ("error calling '%s', DHCP daemon returned "
			            "error '%s', message '%s'.",
			            item,
			            error.name,
			            error.message);
		}
		dbus_error_free (&error);
		goto out;
	}

	if (!reply) {
		nm_warning ("error calling '%s', DHCP daemon did not respond.",
		            item);
		goto out;
	}

	dbus_message_iter_init (reply, &iter);

	buffer = g_array_new (TRUE, TRUE, sizeof (guint32));
	while (dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_UINT32) {
		guint32 uint32_value;
	
		dbus_message_iter_get_basic (&iter, &uint32_value);
		g_array_append_val (buffer, uint32_value);
		dbus_message_iter_next (&iter);
		success = TRUE;
	}

	if (success) {
		*ip4_uint32 = (guint32 *)(buffer->data);
		*num_items = buffer->len;
	}
	g_array_free (buffer, FALSE);
	dbus_message_unref (reply);

out:
	return success;
}


static gboolean
get_ip4_string (DBusConnection *dbus_connection,
                const char *path,
                const char *item,
                char **string,
                gboolean ignore_error)
{
	DBusMessage *	message = NULL;
	DBusMessage *	reply = NULL;
	gboolean	success = FALSE;
	DBusError	error;
	DBusMessageIter	iter;

	g_return_val_if_fail (dbus_connection != NULL, FALSE);
	g_return_val_if_fail (path != NULL, FALSE);
	g_return_val_if_fail (string != NULL, FALSE);

	*string = NULL;
	message = dbus_message_new_method_call (DHCP_SERVICE_NAME,
	                                        path,
	                                        DHCP_SERVICE_NAME".dbus.get",
	                                        item);
	if (!message) {
		nm_warning ("could not allocate dbus message.");
		goto out;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (dbus_connection,
	                                                   message,
	                                                   -1,
	                                                   &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error)) {
		if (!ignore_error) {
			nm_warning ("error calling '%s', DHCP daemon returned "
			            "error '%s', message '%s'.",
			            item,
			            error.name,
			            error.message);
		}
		dbus_error_free (&error);
		*string = NULL;
		goto out;
	}

	if (!reply) {
		nm_warning ("error calling '%s', DHCP daemon did not respond.",
		            item);
		goto out;
	}

	dbus_message_iter_init (reply, &iter);
	if (dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_STRING) {
		char *dbus_string;

		dbus_error_init (&error);
		if (dbus_message_get_args (reply,
		                           &error,
		                           DBUS_TYPE_STRING, &dbus_string,
		                           DBUS_TYPE_INVALID)) {
			*string = g_strdup (dbus_string);
			success = TRUE;
		}
	} else if (dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_ARRAY) {
		char *byte_array = NULL;
		int   len = 0;

		dbus_error_init (&error);
		if (dbus_message_get_args (reply,
		                           &error,
		                           DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &byte_array, &len,
		                           DBUS_TYPE_INVALID)) {
			byte_array[len] = '\0';
			*string = g_strdup (byte_array);
			success = TRUE;
		}
	}

out:
	return success;
}


static gboolean
nm_completion_dhcp_bound_test (int tries,
                               nm_completion_args args)
{
	NMDHCPDevice *device = (NMDHCPDevice *) args[0];

	if (state_is_bound (device->state))
		return TRUE;

	return FALSE;
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
	NMIP4Config *		ip4_config = NULL;
	int			i;
	guint32			count = 0;
	guint32 *		ip4_address = NULL;
	guint32 *		ip4_netmask = NULL;
	guint32 *		ip4_broadcast = NULL;
	guint32 *		ip4_nameservers = NULL;
	guint32 *		ip4_gateway = NULL;
	guint32			num_ip4_nameservers = 0;
	guint32			num_ip4_nis_servers = 0;
	char *			hostname = NULL;
	char *			domain_names = NULL;
	char *			nis_domain = NULL;
	guint32 *		ip4_nis_servers = NULL;
	struct in_addr		temp_addr;
	nm_completion_args	args;
	DBusConnection *	connection;
	char *			path = NULL;

	g_return_val_if_fail (NM_IS_DHCP_MANAGER (manager), NULL);
	g_return_val_if_fail (iface != NULL, NULL);

	priv = NM_DHCP_MANAGER_GET_PRIVATE (manager);

	if (!priv->running)
		return NULL;

	device = (NMDHCPDevice *) g_hash_table_lookup (priv->devices, iface);
	if (!device) {
		nm_warning ("Device '%s' transaction not started.", iface);
		return NULL;
	}

	args[0] = device;
	nm_wait_for_completion (30, G_USEC_PER_SEC / 10,
							nm_completion_dhcp_bound_test, NULL, args);

	if (!state_is_bound (device->state)) {
		nm_warning ("Tried to get IP4 Config for a device when dhcdbd "
		            "wasn't in a BOUND state!");
		return NULL;
	}

	connection = nm_dbus_manager_get_dbus_connection (priv->dbus_mgr);
	if (!connection) {
		nm_warning ("could not get dbus connection.");
		return NULL;
	}

	path = g_strdup_printf (DHCP_OBJECT_PATH"/%s", iface);

	if (!get_ip4_uint32s (connection, path, "ip_address", &ip4_address, &count, FALSE) || !count)
		goto out;

	if (!get_ip4_uint32s (connection, path, "subnet_mask", &ip4_netmask, &count, FALSE) || !count)
		goto out;

	if (!get_ip4_uint32s (connection, path, "broadcast_address", &ip4_broadcast, &count, FALSE) || !count)
		goto out;

	if (!get_ip4_uint32s (connection, path, "routers", &ip4_gateway, &count, TRUE) || !count) {
		/* If DHCP doesn't have a 'routers', just use the DHCP server's address as our gateway for now */
		if (!get_ip4_uint32s (connection, path, "dhcp_server_identifier", &ip4_gateway, &count, FALSE) || !count)
			goto out;
	}

	get_ip4_string (connection, path, "host_name", &hostname, TRUE);
	get_ip4_uint32s (connection, path, "domain_name_servers", &ip4_nameservers, &num_ip4_nameservers, FALSE);
	get_ip4_string (connection, path, "domain_name", &domain_names, TRUE);
	get_ip4_string (connection, path, "nis_domain", &nis_domain, TRUE);
	get_ip4_uint32s (connection, path, "nis_servers", &ip4_nis_servers, &num_ip4_nis_servers, TRUE);

	nm_info ("Retrieved the following IP4 configuration from the DHCP daemon:");

	ip4_config = nm_ip4_config_new ();
	nm_ip4_config_set_address (ip4_config, ip4_address[0]);
	temp_addr.s_addr = ip4_address[0];
	nm_info ("  address %s", inet_ntoa (temp_addr));

	nm_ip4_config_set_netmask (ip4_config, ip4_netmask[0]);
	temp_addr.s_addr = ip4_netmask[0];
	nm_info ("  netmask %s", inet_ntoa (temp_addr));

	nm_ip4_config_set_broadcast (ip4_config, ip4_broadcast[0]);
	temp_addr.s_addr = ip4_broadcast[0];
	nm_info ("  broadcast %s", inet_ntoa (temp_addr));

	nm_ip4_config_set_gateway (ip4_config, ip4_gateway[0]);
	temp_addr.s_addr = ip4_gateway[0];
	nm_info ("  gateway %s", inet_ntoa (temp_addr));

	for (i = 0; i < num_ip4_nameservers; i++) {
		nm_ip4_config_add_nameserver (ip4_config, ip4_nameservers[i]);
		temp_addr.s_addr = ip4_nameservers[i];
		nm_info ("  nameserver %s", inet_ntoa (temp_addr));
	}

	if (hostname) {
		nm_ip4_config_set_hostname (ip4_config, hostname);
		nm_info ("  hostname '%s'", hostname);
	}

	if (domain_names) {
		char **searches = g_strsplit (domain_names, " ", 0);
		char **s;

		for (s = searches; *s; s++) {
			nm_info ("  domain name '%s'", *s);
			nm_ip4_config_add_domain (ip4_config, *s);
		}
		g_strfreev (searches);
	}

	if (nis_domain) {
		nm_ip4_config_set_nis_domain (ip4_config, nis_domain);
		nm_info ("  nis domain '%s'", nis_domain);
	}

	for (i = 0; i < num_ip4_nis_servers; i++) {
		nm_ip4_config_add_nis_server (ip4_config, ip4_nis_servers[i]);
		temp_addr.s_addr = ip4_nis_servers[i];
		nm_info ("  nis server %s", inet_ntoa (temp_addr));
	}

	/*
	 * FIXME:
	 * Grab the MTU from the backend. If DHCP servers can send recommended
	 * MTU's, should set that here.
	 */

out:
	g_free (path);

	return ip4_config;
}


/*
 * nm_dhcp_manager_process_name_owner_changed
 *
 * Respond to "service created"/"service deleted" signals from dbus for the active DHCP daemon.
 *
 */
static void
nm_dhcp_manager_name_owner_changed (NMDBusManager *dbus_mgr,
                                    DBusConnection *connection,
                                    const char *name,
                                    const char *old,
                                    const char *new,
                                    gpointer user_data)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (user_data);
	gboolean		old_owner_good = (old && strlen (old));
	gboolean		new_owner_good = (new && strlen (new));

	/* Can't handle the signal if its not from the DHCP service */
	if (strcmp (DHCP_SERVICE_NAME, name) != 0)
		return;

	if (!old_owner_good && new_owner_good) {
		priv->running = TRUE;
	} else if (old_owner_good && !new_owner_good) {
		priv->running = FALSE;
		g_hash_table_remove_all (priv->devices);
	}
}


static void
nm_dhcp_manager_dbus_connection_changed (NMDBusManager *dbus_mgr,
                                         DBusConnection *connection,
                                         gpointer user_data)
{
	NMDHCPManagerPrivate *priv = NM_DHCP_MANAGER_GET_PRIVATE (user_data);

	if (connection) {
		if (nm_dbus_manager_name_has_owner (dbus_mgr, DHCP_SERVICE_NAME))
			priv->running = TRUE;
	} else {
		priv->running = FALSE;
		g_hash_table_remove_all (priv->devices);
	}
}
