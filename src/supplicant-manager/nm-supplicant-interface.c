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
 * (C) Copyright 2006 Red Hat, Inc.
 */

#include <string.h>
#include <glib.h>

#include "nm-supplicant-interface.h"
#include "nm-supplicant-manager.h"
#include "nm-device.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-utils.h"
#include "nm-supplicant-marshal.h"
#include "nm-supplicant-config.h"
#include "nm-dbus-manager.h"
#include "dbus-dict-helpers.h"
#include "NetworkManagerMain.h"

#define WPAS_DBUS_IFACE_INTERFACE   WPAS_DBUS_INTERFACE ".Interface"
#define WPAS_DBUS_IFACE_BSSID       WPAS_DBUS_INTERFACE ".BSSID"


#define NM_SUPPLICANT_INTERFACE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                                 NM_TYPE_SUPPLICANT_INTERFACE, \
                                                 NMSupplicantInterfacePrivate))

static void nm_supplicant_interface_set_property (GObject *      object,
                                                  guint          prop_id,
                                                  const GValue * value,
                                                  GParamSpec *   pspec);

static void nm_supplicant_interface_get_property (GObject *      object,
                                                  guint          prop_id,
                                                  GValue *       value,
                                                  GParamSpec *   pspec);

static void nm_supplicant_interface_start (NMSupplicantInterface * self);

static void nm_supplicant_interface_add_to_supplicant (NMSupplicantInterface * self,
                                                       gboolean get_only);

static void nm_supplicant_interface_smgr_state_changed (NMSupplicantManager * smgr,
                                                        guint32 new_state,
                                                        guint32 old_state,
                                                        gpointer user_data);

static void nm_supplicant_interface_set_state (NMSupplicantInterface * self,
                                               guint32 new_state);


/* Signals */
enum {
	STATE,             /* change in the interface's state */
	REMOVED,           /* interface was removed by the supplicant */
	SCANNED_AP,        /* interface saw a new access point from a scan */
	SCAN_RESULT,       /* result of a wireless scan request */
	CONNECTION_STATE,  /* link state of the device's connection */
	CONNECTION_ERROR,  /* an error occurred during a connection request */
	LAST_SIGNAL
};
static guint nm_supplicant_interface_signals[LAST_SIGNAL] = { 0 };


/* Properties */
enum {
	PROP_0 = 0,
	PROP_SUPPLICANT_MANAGER,
	PROP_DEVICE,
	PROP_STATE,
	PROP_CONNECTION_STATE,
	LAST_PROP
};


struct _NMSupplicantInterfacePrivate
{
	NMSupplicantManager * smgr;
	gulong                smgr_state_sig_handler;
	NMDBusManager *       dbus_mgr;
	NMDevice *            dev;

	guint32               state;
	GSList *              assoc_pcalls;
	GSList *              other_pcalls;

	guint32               con_state;

	char *                wpas_iface_op;
	char *                wpas_net_op;
	guint32               wpas_sig_handler_id;
	GSource *             scan_results_timeout;
	guint32               last_scan;

	NMSupplicantConfig *  cfg;

	gboolean              dispose_has_run;
};

static GSList *
pcall_list_add_pcall (GSList * pcall_list,
                      DBusPendingCall * pcall)
{
	GSList * elt;

	g_return_val_if_fail (pcall != NULL, pcall_list);

	for (elt = pcall_list; elt; elt = g_slist_next (elt)) {
		if (pcall == elt->data)
			return pcall_list;
	}

	return g_slist_append (pcall_list, pcall);
}

static GSList *
pcall_list_remove_pcall (GSList * pcall_list,
                         DBusPendingCall * pcall)
{
	GSList * elt;

	g_return_val_if_fail (pcall != NULL, pcall_list);

	for (elt = pcall_list; elt; elt = g_slist_next (elt)) {
		DBusPendingCall * item = (DBusPendingCall *) elt->data;

		if (item == pcall) {
			if (!dbus_pending_call_get_completed (pcall))
				dbus_pending_call_cancel (pcall);
			dbus_pending_call_unref (pcall);
			pcall_list = g_slist_remove_link (pcall_list, elt);
			g_slist_free_1 (elt);
			goto out;
		}
	}

out:
	return pcall_list;
}

static GSList *
pcall_list_clear (GSList * pcall_list)
{
	GSList * elt;

	for (elt = pcall_list; elt; elt = g_slist_next (elt)) {
		DBusPendingCall * pcall = (DBusPendingCall *) elt->data;

		if (!dbus_pending_call_get_completed (pcall))
			dbus_pending_call_cancel (pcall);
		dbus_pending_call_unref (pcall);
	}
	g_slist_free (pcall_list);
	return NULL;
}


NMSupplicantInterface *
nm_supplicant_interface_new (NMSupplicantManager * smgr, NMDevice * dev)
{
	NMSupplicantInterface * iface;

	g_return_val_if_fail (smgr != NULL, NULL);
	g_return_val_if_fail (dev != NULL, NULL);

	iface = g_object_new (NM_TYPE_SUPPLICANT_INTERFACE,
	                      "supplicant-manager", smgr,
	                      "device", dev,
	                      NULL);
	if (iface) {
		nm_supplicant_interface_start (iface);
	}

	return iface;
}

static void
nm_supplicant_interface_init (NMSupplicantInterface * self)
{
	self->priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	self->priv->state = NM_SUPPLICANT_INTERFACE_STATE_INIT;
	self->priv->con_state = NM_SUPPLICANT_INTERFACE_CON_STATE_DISCONNECTED;
	self->priv->smgr = NULL;
	self->priv->dev = NULL;
	self->priv->wpas_iface_op = NULL;
	self->priv->assoc_pcalls = NULL;
	self->priv->other_pcalls = NULL;
	self->priv->dispose_has_run = FALSE;

	self->priv->dbus_mgr = nm_dbus_manager_get (NULL);
}


static void
nm_supplicant_interface_set_property (GObject *      object,
                                      guint          prop_id,
                                      const GValue * value,
                                      GParamSpec *   pspec)
{
	NMSupplicantInterface * self = NM_SUPPLICANT_INTERFACE (object);
	gulong id;

	switch (prop_id) {
		case PROP_SUPPLICANT_MANAGER:
			self->priv->smgr = NM_SUPPLICANT_MANAGER (g_value_get_object (value));
			g_object_ref (G_OBJECT (self->priv->smgr));
			
			id = g_signal_connect (G_OBJECT (self->priv->smgr),
			                       "state",
			                       G_CALLBACK (nm_supplicant_interface_smgr_state_changed),
			                       self);
			self->priv->smgr_state_sig_handler = id;
			break;
		case PROP_DEVICE:
			self->priv->dev = NM_DEVICE (g_value_get_object (value));
			g_object_ref (G_OBJECT (self->priv->dev));
			break;
		case PROP_STATE:
			/* warn on setting read-only property */
			break;
		case PROP_CONNECTION_STATE:
			/* warn on setting read-only property */
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
nm_supplicant_interface_get_property (GObject *     object,
                                      guint         prop_id,
                                      GValue *      value,
                                      GParamSpec *  pspec)
{
	NMSupplicantInterface * self = NM_SUPPLICANT_INTERFACE (object);

	switch (prop_id) {
		case PROP_SUPPLICANT_MANAGER:
			g_value_set_object (value, G_OBJECT (self->priv->smgr));
			break;
		case PROP_DEVICE:
			g_value_set_object (value, G_OBJECT (self->priv->dev));
			break;
		case PROP_STATE:
			g_value_set_uint (value, self->priv->state);
			break;
		case PROP_CONNECTION_STATE:
			g_value_set_uint (value, self->priv->con_state);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
nm_supplicant_interface_dispose (GObject *object)
{
	NMSupplicantInterface *      self = NM_SUPPLICANT_INTERFACE (object);
	NMSupplicantInterfaceClass * klass;
	GObjectClass *               parent_class;  

	if (self->priv->dispose_has_run) {
		/* If dispose did already run, return. */
		return;
	}

	/* Make sure dispose does not run twice. */
	self->priv->dispose_has_run = TRUE;

	/* 
	 * In dispose, you are supposed to free all types referenced from this
	 * object which might themselves hold a reference to self. Generally,
	 * the most simple solution is to unref all members on which you own a 
	 * reference.
	 */
	if (self->priv->scan_results_timeout) {
		g_source_destroy (self->priv->scan_results_timeout);
		self->priv->scan_results_timeout = NULL;
	}

	if (self->priv->smgr) {
		g_signal_handler_disconnect (G_OBJECT (self->priv->smgr),
		                             self->priv->smgr_state_sig_handler);
		g_object_unref (self->priv->smgr);
		self->priv->smgr = NULL;
	}

	if (self->priv->dev) {
		g_object_unref (self->priv->dev);
		self->priv->dev = NULL;
	}

	/* Cancel pending calls before unrefing the dbus manager */
	self->priv->other_pcalls = pcall_list_clear (self->priv->other_pcalls);
	self->priv->assoc_pcalls = pcall_list_clear (self->priv->assoc_pcalls);

	if (self->priv->dbus_mgr) {
		if (self->priv->wpas_sig_handler_id) {
			nm_dbus_manager_remove_signal_handler (self->priv->dbus_mgr,
			                                       self->priv->wpas_sig_handler_id);
			self->priv->wpas_sig_handler_id = 0;
		}

		g_object_unref (self->priv->dbus_mgr);
		self->priv->dbus_mgr = NULL;
	}

	if (self->priv->cfg) {
		g_object_unref (self->priv->cfg);
		self->priv->cfg = NULL;
	}

	/* Chain up to the parent class */
	klass = NM_SUPPLICANT_INTERFACE_CLASS (g_type_class_peek (NM_TYPE_SUPPLICANT_INTERFACE));
	parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
	parent_class->dispose (object);
}

static void
nm_supplicant_interface_finalize (GObject *object)
{
	NMSupplicantInterface *      self = NM_SUPPLICANT_INTERFACE (object);
	NMSupplicantInterfaceClass * klass;
	GObjectClass *               parent_class;

	if (self->priv->wpas_iface_op) {
		g_free (self->priv->wpas_iface_op);
		self->priv->wpas_iface_op = NULL;
	}

	if (self->priv->wpas_net_op) {
		g_free (self->priv->wpas_net_op);
		self->priv->wpas_net_op = NULL;
	}

	/* Chain up to the parent class */
	klass = NM_SUPPLICANT_INTERFACE_CLASS (g_type_class_peek (NM_TYPE_SUPPLICANT_INTERFACE));
	parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
	parent_class->finalize (object);
}


static void
nm_supplicant_interface_class_init (NMSupplicantInterfaceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = nm_supplicant_interface_dispose;
	object_class->finalize = nm_supplicant_interface_finalize;
	object_class->set_property = nm_supplicant_interface_set_property;
	object_class->get_property = nm_supplicant_interface_get_property;

	g_type_class_add_private (object_class, sizeof (NMSupplicantInterfacePrivate));

	/* Properties */
	g_object_class_install_property (object_class,
	                                 PROP_SUPPLICANT_MANAGER,
	                                 g_param_spec_object ("supplicant-manager",
	                                                      "Supplicant Manager",
	                                                      "Supplicant manager to which this interface belongs",
	                                                      NM_TYPE_SUPPLICANT_MANAGER,
	                                                      G_PARAM_READABLE | G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));
  
	g_object_class_install_property (object_class,
	                                 PROP_DEVICE,
	                                 g_param_spec_object ("device",
	                                                      "Device",
	                                                      "Device which this interface represents to the supplicant",
	                                                      NM_TYPE_DEVICE,
	                                                      G_PARAM_READABLE | G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (object_class,
	                                 PROP_DEVICE,
	                                 g_param_spec_uint ("state",
	                                                    "State",
	                                                    "State of the supplicant interface; INIT, READY, or DOWN",
	                                                    NM_SUPPLICANT_INTERFACE_STATE_INIT,
	                                                    NM_SUPPLICANT_INTERFACE_STATE_LAST - 1,
	                                                    NM_SUPPLICANT_INTERFACE_STATE_INIT,
	                                                    G_PARAM_READABLE));

	/* Signals */
	nm_supplicant_interface_signals[STATE] =
		g_signal_new ("state",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, state),
		              NULL, NULL,
		              nm_supplicant_marshal_VOID__UINT_UINT,
		              G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);
	klass->state = NULL;

	nm_supplicant_interface_signals[REMOVED] =
		g_signal_new ("removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, removed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);
	klass->removed = NULL;

	nm_supplicant_interface_signals[SCANNED_AP] =
		g_signal_new ("scanned-ap",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, scanned_ap),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__POINTER,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);
	klass->scanned_ap = NULL;

	nm_supplicant_interface_signals[SCAN_RESULT] =
		g_signal_new ("scan-result",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, scan_result),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__UINT,
		              G_TYPE_NONE, 1, G_TYPE_UINT);
	klass->scan_result = NULL;

	nm_supplicant_interface_signals[CONNECTION_STATE] =
		g_signal_new ("connection-state",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, connection_state),
		              NULL, NULL,
		              nm_supplicant_marshal_VOID__UINT_UINT,
		              G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);
	klass->connection_state = NULL;

	nm_supplicant_interface_signals[CONNECTION_ERROR] =
		g_signal_new ("connection-error",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, connection_error),
		              NULL, NULL,
		              nm_supplicant_marshal_VOID__CHAR_CHAR,
		              G_TYPE_NONE, 2, G_TYPE_CHAR, G_TYPE_CHAR);
	klass->connection_error = NULL;
}

GType
nm_supplicant_interface_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMSupplicantInterfaceClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_supplicant_interface_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMSupplicantInterface),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_supplicant_interface_init,
			NULL		/* value_table */
		};

		type = g_type_register_static (G_TYPE_OBJECT,
								 "NMSupplicantInterface",
								 &info, 0);
	}
	return type;
}

static void
emit_error_helper (NMSupplicantInterface * self,
                   const char * name,
                   const char * message)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (name != NULL);
	g_return_if_fail (message != NULL);

	g_signal_emit (G_OBJECT (self),
	               nm_supplicant_interface_signals[CONNECTION_ERROR],
	               0,
	               name,
	               message);
}


static void
set_wpas_iface_op_from_message (NMSupplicantInterface * self,
                                DBusMessage * message)
{
	DBusError error;
	char * path = NULL;

	dbus_error_init (&error);

	/* Interface was found; cache its object path */
	if (!dbus_message_get_args (message,
	                            &error,
	                            DBUS_TYPE_OBJECT_PATH, &path,
	                            DBUS_TYPE_INVALID)) {
		nm_warning ("Error getting interface path from supplicant: %s - %s",
		            error.name,
		            error.message);
	} else {
		if (self->priv->wpas_iface_op)
			g_free (self->priv->wpas_iface_op);
		self->priv->wpas_iface_op = g_strdup (path);
	}

	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
}

static void
bssid_properties_cb (DBusPendingCall * pcall,
                     NMSupplicantInterface * self)
{
	DBusError     error;
	DBusMessage * reply = NULL;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (self != NULL);

	dbus_error_init (&error);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR) {
		if (!dbus_set_error_from_message (&error, reply)) {
			nm_warning ("Couldn't set error from DBus message.");
			goto out;
		}
		nm_warning ("Couldn't retrieve BSSID properties: %s - %s",
		            error.name,
		            error.message);
		goto out;
	}

	g_signal_emit (G_OBJECT (self),
	               nm_supplicant_interface_signals[SCANNED_AP],
	               0,
	               reply);

out:
	if (reply)
		dbus_message_unref (reply);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	self->priv->other_pcalls = pcall_list_remove_pcall (self->priv->other_pcalls, pcall);
}

static void
request_bssid_properties (NMSupplicantInterface * self,
                          const char * op)
{
	DBusMessage * message = NULL;
	DBusConnection * connection = NULL;
	DBusPendingCall * pcall = NULL;

	g_return_if_fail (self != NULL);
	g_return_if_fail (op != NULL);

	connection = nm_dbus_manager_get_dbus_connection (self->priv->dbus_mgr);
	if (!connection) {
		nm_warning ("could not get dbus connection.");
		goto out;
	}

	message = dbus_message_new_method_call (WPAS_DBUS_SERVICE,
	                                        op,
	                                        WPAS_DBUS_IFACE_BSSID,
	                                        "properties");
	if (!message) {
		nm_warning ("could not allocate dbus message.");
		goto out;
	}

	pcall = nm_dbus_send_with_callback (connection,
	                                    message,
	                                    (DBusPendingCallNotifyFunction) bssid_properties_cb,
	                                    self,
	                                    NULL,
	                                    __func__);
	if (!pcall) {
		nm_warning ("could not send dbus message.");
		goto out;
	}
	self->priv->other_pcalls = pcall_list_add_pcall (self->priv->other_pcalls, pcall);

out:
	if (message)
		dbus_message_unref (message);
}

static void
scan_results_cb (DBusPendingCall * pcall,
                 NMSupplicantInterface * self)
{
	DBusError     error;
	DBusMessage * reply = NULL;
	char **       bssids;
	int           num_bssids;
	char **       item;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (self != NULL);

	dbus_error_init (&error);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (!dbus_message_get_args (reply,
	                            &error,
	                            DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &bssids, &num_bssids,
	                            DBUS_TYPE_INVALID)) {
		nm_warning ("could not get scan results: %s - %s.",
		            error.name,
		            error.message);
		goto out;
	}

	/* Notify listeners of the result of the scan */
	g_signal_emit (G_OBJECT (self),
	               nm_supplicant_interface_signals[SCAN_RESULT],
	               0,
	               NM_SUPPLICANT_INTERFACE_SCAN_RESULT_SUCCESS);

	/* Fire off a "properties" call for each returned BSSID */
	for (item = bssids; *item; item++) {
		request_bssid_properties (self, *item);
	}
	dbus_free_string_array (bssids);

out:
	if (reply)
		dbus_message_unref (reply);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	self->priv->other_pcalls = pcall_list_remove_pcall (self->priv->other_pcalls, pcall);
}

static gboolean
request_scan_results (gpointer user_data)
{
	NMSupplicantInterface * self = (NMSupplicantInterface *) user_data;
	DBusMessage *           message = NULL;
	DBusPendingCall *       pcall;
	DBusConnection *        connection;
	GTimeVal                cur_time;

	if (!self || !self->priv->wpas_iface_op) {
		nm_warning ("Invalid user_data or bad supplicant interface object path.");
		goto out;
	}

	connection = nm_dbus_manager_get_dbus_connection (self->priv->dbus_mgr);
	if (!connection) {
		nm_warning ("could not get dbus connection.");
		goto out;
	}

	message = dbus_message_new_method_call (WPAS_DBUS_SERVICE,
	                                        self->priv->wpas_iface_op,
	                                        WPAS_DBUS_IFACE_INTERFACE,
	                                        "scanResults");
	if (!message) {
		nm_warning ("could not allocate dbus message.");
		goto out;
	}

	pcall = nm_dbus_send_with_callback (connection,
	                                    message,
	                                    (DBusPendingCallNotifyFunction) scan_results_cb,
	                                    self,
	                                    NULL,
	                                    __func__);
	if (!pcall) {
		nm_warning ("could not send dbus message.");
		goto out;
	}
	self->priv->other_pcalls = pcall_list_add_pcall (self->priv->other_pcalls, pcall);

	g_get_current_time (&cur_time);
	self->priv->last_scan = cur_time.tv_sec;

out:
	if (message)
		dbus_message_unref (message);

	if (self->priv->scan_results_timeout) {
		g_source_unref (self->priv->scan_results_timeout);
		self->priv->scan_results_timeout = NULL;
	}

	return FALSE;
}

static void
wpas_iface_query_scan_results (NMSupplicantInterface * self)
{
	guint id;
	GSource * source;
	NMData * app_data;

	g_return_if_fail (self != NULL);
	g_return_if_fail (self->priv->dev);

	/* Only query scan results if a query is not queued */
	if (self->priv->scan_results_timeout)
		return;

	app_data = nm_device_get_app_data (self->priv->dev);
	if (!app_data)
		return;

	/* Only fetch scan results every 4s max, but initially do it right away */
	if (self->priv->last_scan == 0) {
		source = g_idle_source_new ();
	} else {
		source = g_timeout_source_new (4000);
	}
	g_source_set_callback (source, request_scan_results, self, NULL);
	id = g_source_attach (source, app_data->main_context);
	self->priv->scan_results_timeout = source;
}

static guint32
wpas_state_string_to_enum (const char * str_state)
{
	guint32 enum_state = NM_SUPPLICANT_INTERFACE_CON_STATE_DISCONNECTED;

	if (!strcmp (str_state, "DISCONNECTED")) {
		enum_state = NM_SUPPLICANT_INTERFACE_CON_STATE_DISCONNECTED;
	} else if (!strcmp (str_state, "INACTIVE")) {
		enum_state = NM_SUPPLICANT_INTERFACE_CON_STATE_INACTIVE;
	} else if (!strcmp (str_state, "SCANNING")) {
		enum_state = NM_SUPPLICANT_INTERFACE_CON_STATE_SCANNING;
	} else if (!strcmp (str_state, "ASSOCIATING")) {
		enum_state = NM_SUPPLICANT_INTERFACE_CON_STATE_ASSOCIATING;
	} else if (!strcmp (str_state, "ASSOCIATED")) {
		enum_state = NM_SUPPLICANT_INTERFACE_CON_STATE_ASSOCIATED;
	} else if (!strcmp (str_state, "4WAY_HANDSHAKE")) {
		enum_state = NM_SUPPLICANT_INTERFACE_CON_STATE_4WAY_HANDSHAKE;
	} else if (!strcmp (str_state, "GROUP_HANDSHAKE")) {
		enum_state = NM_SUPPLICANT_INTERFACE_CON_STATE_GROUP_HANDSHAKE;
	} else if (!strcmp (str_state, "COMPLETED")) {
		enum_state = NM_SUPPLICANT_INTERFACE_CON_STATE_COMPLETED;
	}

	return enum_state;
}

static void
wpas_iface_handle_state_change (NMSupplicantInterface * self,
                                DBusMessage * message)
{
	DBusError error;
	char *    str_old_state;
	char *    str_new_state;
	guint32   old_state, enum_new_state;

	dbus_error_init (&error);
	if (!dbus_message_get_args (message,
	                            &error,
	                            DBUS_TYPE_STRING, &str_new_state,
	                            DBUS_TYPE_STRING, &str_old_state,
	                            DBUS_TYPE_INVALID)) {
		nm_warning ("could not get message arguments: %s - %s",
		            error.name,
		            error.message);
		goto out;
	}

	enum_new_state = wpas_state_string_to_enum (str_new_state);
	old_state = self->priv->con_state;
	self->priv->con_state = enum_new_state;
	if (self->priv->con_state != old_state) {
		g_signal_emit (G_OBJECT (self),
		               nm_supplicant_interface_signals[CONNECTION_STATE],
		               0,
		               self->priv->con_state,
		               old_state);
	}

out:
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
}

static gboolean
wpas_iface_signal_handler (DBusConnection * connection,
                           DBusMessage * message,
                           gpointer user_data)
{
	NMSupplicantInterface * self = (NMSupplicantInterface *) user_data;
	const char *            op = dbus_message_get_path (message);
	gboolean                handled = FALSE;

	g_return_val_if_fail (self != NULL, FALSE);

	if (!op || !self->priv->wpas_iface_op)
		return FALSE;

	/* Only handle signals for our interface */
	if (strcmp (op, self->priv->wpas_iface_op) != 0)
		return FALSE;

	if (dbus_message_is_signal (message,
	                            WPAS_DBUS_IFACE_INTERFACE,
	                            "ScanResultsAvailable")) {
		wpas_iface_query_scan_results (self);
		handled = TRUE;
	} else if (dbus_message_is_signal (message,
	                                   WPAS_DBUS_IFACE_INTERFACE,
	                                   "StateChange")) {
		wpas_iface_handle_state_change (self, message);
		handled = TRUE;
	}

	return handled;
}

static void
iface_state_cb (DBusPendingCall * pcall,
                NMSupplicantInterface * self)
{
	DBusError     error;
	DBusMessage * reply = NULL;
	char *        state_str = NULL;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (self != NULL);

	dbus_error_init (&error);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR) {
		if (!dbus_set_error_from_message (&error, reply)) {
			nm_warning ("couldn't get error information.");
		} else {
			nm_warning ("could not get interface state: %s - %s.",
			            error.name,
			            error.message);
		}
		goto out;
	}

	if (!dbus_message_get_args (reply,
	                            &error,
	                            DBUS_TYPE_STRING, &state_str,
	                            DBUS_TYPE_INVALID)) {
		nm_warning ("could not get interface state: %s - %s.",
		            error.name,
		            error.message);
		goto out;
	}

	self->priv->con_state = wpas_state_string_to_enum (state_str);
	nm_supplicant_interface_set_state (self, NM_SUPPLICANT_INTERFACE_STATE_READY);

out:
	if (reply)
		dbus_message_unref (reply);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	self->priv->other_pcalls = pcall_list_remove_pcall (self->priv->other_pcalls, pcall);
}

static void
wpas_iface_get_state (NMSupplicantInterface *self)
{
	DBusMessage *           message = NULL;
	DBusPendingCall *       pcall;
	DBusConnection *        connection;

	if (!self || !self->priv->wpas_iface_op) {
		nm_warning ("Invalid user_data or bad supplicant interface object path.");
		goto out;
	}

	connection = nm_dbus_manager_get_dbus_connection (self->priv->dbus_mgr);
	if (!connection) {
		nm_warning ("could not get dbus connection.");
		goto out;
	}

	message = dbus_message_new_method_call (WPAS_DBUS_SERVICE,
	                                        self->priv->wpas_iface_op,
	                                        WPAS_DBUS_IFACE_INTERFACE,
	                                        "state");
	if (!message) {
		nm_warning ("could not allocate dbus message.");
		goto out;
	}

	pcall = nm_dbus_send_with_callback (connection,
	                                    message,
	                                    (DBusPendingCallNotifyFunction) iface_state_cb,
	                                    self,
	                                    NULL,
	                                    __func__);
	if (!pcall) {
		nm_warning ("could not send dbus message.");
		goto out;
	}
	self->priv->other_pcalls = pcall_list_add_pcall (self->priv->other_pcalls, pcall);

out:
	if (message)
		dbus_message_unref (message);
}

#define WPAS_ERROR_INVALID_IFACE \
	WPAS_DBUS_INTERFACE ".InvalidInterface"
#define WPAS_ERROR_EXISTS_ERROR \
	WPAS_DBUS_INTERFACE ".ExistsError"

static void
nm_supplicant_interface_add_cb (DBusPendingCall * pcall,
                                NMSupplicantInterface * self)
{
	DBusError error;
	DBusMessage * reply = NULL;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (self != NULL);

	dbus_error_init (&error);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_is_error (reply, WPAS_ERROR_INVALID_IFACE)) {
		/* Interface not added, try to add it */
		nm_supplicant_interface_add_to_supplicant (self, FALSE);
	} else if (dbus_message_is_error (reply, WPAS_ERROR_EXISTS_ERROR)) {
		/* Interface already added, just try to get the interface */
		nm_supplicant_interface_add_to_supplicant (self, TRUE);
	} else if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR) {
		if (!dbus_set_error_from_message (&error, reply))
			goto out;

		nm_warning ("Unexpected supplicant error getting interface: %s - %s",
		            error.name,
		            error.message);
	} else {
		guint32 id;

		/* Success; cache the object path */
		set_wpas_iface_op_from_message (self, reply);

		/* Attach to the scan results signal */
		id = nm_dbus_manager_register_signal_handler (self->priv->dbus_mgr,
		                                              WPAS_DBUS_IFACE_INTERFACE,
		                                              WPAS_DBUS_SERVICE,
		                                              wpas_iface_signal_handler,
		                                              self);
		self->priv->wpas_sig_handler_id = id;

		/* Interface added to the supplicant; get its initial state. */
		wpas_iface_get_state (self);
	}

out:
	if (reply)
		dbus_message_unref (reply);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	self->priv->other_pcalls = pcall_list_remove_pcall (self->priv->other_pcalls, pcall);
}


static void
nm_supplicant_interface_add_to_supplicant (NMSupplicantInterface * self,
                                           gboolean get_only)
{
	DBusConnection *  dbus_connection;
	DBusMessage *     message = NULL;
	DBusMessageIter   iter;
	const char *      dev_iface;
	DBusPendingCall * pcall;

	g_return_if_fail (self != NULL);

	dbus_connection = nm_dbus_manager_get_dbus_connection (self->priv->dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get the dbus connection.");
		goto out;
	}

	/* Request the interface object from the supplicant */
	message = dbus_message_new_method_call (WPAS_DBUS_SERVICE,
	                                        WPAS_DBUS_PATH,
	                                        WPAS_DBUS_INTERFACE,
	                                        get_only ? "getInterface" : "addInterface");
	if (!message) {
		nm_warning ("Not enough memory to allocate dbus message.");
		goto out;
	}

	dbus_message_iter_init_append (message, &iter);
	dev_iface = nm_device_get_iface (self->priv->dev);
	if (!dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &dev_iface)) {
		nm_warning ("Couldn't add device interface to message.");
		goto out;
	}

	/* Add the supplicant driver name if we're adding */
	if (!get_only) {
		DBusMessageIter iter_dict;
		char * driver = "wext";

		if (!nmu_dbus_dict_open_write (&iter, &iter_dict)) {
			nm_warning ("dict open write failed!");
			goto out;
		}

		if (nm_device_is_802_3_ethernet (self->priv->dev))
			driver = "wired";
		if (!nmu_dbus_dict_append_string (&iter_dict, "driver", driver)) {
			nm_warning ("couldn't append driver to dict");
			goto out;
		}

		if (!nmu_dbus_dict_close_write (&iter, &iter_dict)) {
			nm_warning ("dict close write failed!");
			goto out;
		}
	}

	pcall = nm_dbus_send_with_callback (dbus_connection,
	                                    message,
	                                    (DBusPendingCallNotifyFunction) nm_supplicant_interface_add_cb,
	                                    self,
	                                    NULL,
	                                    __func__);
	if (!pcall) {
		nm_warning ("could not send dbus message.");
		goto out;
	}
	self->priv->other_pcalls = pcall_list_add_pcall (self->priv->other_pcalls, pcall);

out:
	if (message)
		dbus_message_unref (message);
}

static void
nm_supplicant_interface_start (NMSupplicantInterface * self)
{
	guint32          state;

	g_return_if_fail (self != NULL);

	/* Can only start the interface from INIT state */
	g_return_if_fail (self->priv->state == NM_SUPPLICANT_INTERFACE_STATE_INIT);

	state = nm_supplicant_manager_get_state (self->priv->smgr);
	if (state == NM_SUPPLICANT_MANAGER_STATE_IDLE) {
		nm_supplicant_interface_set_state (self, NM_SUPPLICANT_INTERFACE_STATE_STARTING);
		nm_supplicant_interface_add_to_supplicant (self, FALSE);
	} else if (state == NM_SUPPLICANT_MANAGER_STATE_DOWN) {
		/* Don't do anything; wait for signal from supplicant manager
		 * that its state has changed.
		 */
	} else {
			nm_warning ("Unknown supplicant manager state!");
	}
}

static void
nm_supplicant_interface_handle_supplicant_manager_idle_state (NMSupplicantInterface * self)
{
	g_return_if_fail (self != NULL);

	switch (self->priv->state) {
		case NM_SUPPLICANT_INTERFACE_STATE_INIT:
			/* Move to STARTING state when supplicant is ready */
			nm_supplicant_interface_start (self);
			break;
		case NM_SUPPLICANT_INTERFACE_STATE_STARTING:
			/* Don't do anything here, though we should never hit this */
			break;
		case NM_SUPPLICANT_INTERFACE_STATE_READY:
			/* Don't do anything here, though we should never hit this */
			break;
		case NM_SUPPLICANT_INTERFACE_STATE_DOWN:
			/* Don't do anything here; interface can't get out of DOWN state */
			break;
		default:
			nm_warning ("Unknown supplicant interface state!");
			break;
	}
}


static void
nm_supplicant_interface_set_state (NMSupplicantInterface * self,
                                   guint32 new_state)
{
	guint32 old_state;

	g_return_if_fail (self != NULL);
	g_return_if_fail (new_state < NM_SUPPLICANT_INTERFACE_STATE_LAST);

	if (new_state == self->priv->state)
		return;

	old_state = self->priv->state;
	if (new_state == NM_SUPPLICANT_INTERFACE_STATE_DOWN) {
		/* If the interface is transitioning to DOWN and there's are
		 * in-progress pending calls, cancel them.
		 */
		self->priv->other_pcalls = pcall_list_clear (self->priv->other_pcalls);
		self->priv->assoc_pcalls = pcall_list_clear (self->priv->assoc_pcalls);
	}

	self->priv->state = new_state;
	g_signal_emit (G_OBJECT (self),
	               nm_supplicant_interface_signals[STATE],
	               0,
	               self->priv->state,
	               old_state);
}

static void
nm_supplicant_interface_smgr_state_changed (NMSupplicantManager * smgr,
                                            guint32 new_state,
                                            guint32 old_state,
                                            gpointer user_data)
{
	NMSupplicantInterface * self = NM_SUPPLICANT_INTERFACE (user_data);

	switch (new_state) {
		case NM_SUPPLICANT_MANAGER_STATE_DOWN:
			/* The supplicant went away, likely the connection to it is also
			 * gone.  Therefore, this interface must move to the DOWN state
			 * and be disposed of.
			 */
			nm_supplicant_interface_set_state (self, NM_SUPPLICANT_INTERFACE_STATE_DOWN);
			break;
		case NM_SUPPLICANT_MANAGER_STATE_IDLE:
			/* Handle the supplicant now being available. */
			nm_supplicant_interface_handle_supplicant_manager_idle_state (self);
			break;
		default:
			nm_warning ("Unknown supplicant manager state!");
			break;
	}
}


static void
remove_network_cb (DBusPendingCall * pcall,
                   NMSupplicantInterface * self)
{
	DBusError error;
	DBusMessage * reply = NULL;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (self != NULL);

	dbus_error_init (&error);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR) {
		dbus_set_error_from_message (&error, reply);
		nm_warning ("Couldn't remove network from supplicant interface: %s - %s",
		            error.name,
		            error.message);
	}

out:
	if (reply)
		dbus_message_unref (reply);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	self->priv->other_pcalls = pcall_list_remove_pcall (self->priv->other_pcalls, pcall);
}

static void
disconnect_cb (DBusPendingCall * pcall,
               NMSupplicantInterface * self)
{
	DBusError error;
	DBusMessage * reply = NULL;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (self != NULL);

	dbus_error_init (&error);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR) {
		dbus_set_error_from_message (&error, reply);
		nm_warning ("Couldn't disconnect supplicant interface: %s - %s",
		            error.name,
		            error.message);
	}

out:
	if (reply)
		dbus_message_unref (reply);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	self->priv->other_pcalls = pcall_list_remove_pcall (self->priv->other_pcalls, pcall);
}

void
nm_supplicant_interface_disconnect (NMSupplicantInterface * self)
{
	DBusMessage *     message = NULL;
	DBusPendingCall * pcall = NULL;
	DBusConnection *  dbus_connection;

	g_return_if_fail (self != NULL);

	/* Clear and cancel all pending calls related to a prior
	 * connection attempt.
	 */
	self->priv->assoc_pcalls = pcall_list_clear (self->priv->assoc_pcalls);

	/* Don't do anything if there is no connection to the supplicant yet. */
	if (!self->priv->wpas_iface_op)
		return;

	dbus_connection = nm_dbus_manager_get_dbus_connection (self->priv->dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get the dbus connection.");
		goto out;
	}

	/* Don't try to disconnect if the supplicant interface is already
	 * disconnected.
	 */
	if (self->priv->con_state != NM_SUPPLICANT_INTERFACE_CON_STATE_DISCONNECTED
	    && self->priv->con_state != NM_SUPPLICANT_INTERFACE_CON_STATE_INACTIVE) {
		if (self->priv->wpas_net_op) {
			g_free (self->priv->wpas_net_op);
			self->priv->wpas_net_op = NULL;
		}
		return;
	}

	/* Remove any network that was added by NetworkManager */
	if (self->priv->wpas_net_op) {
		message = dbus_message_new_method_call (WPAS_DBUS_SERVICE,
		                                        self->priv->wpas_iface_op,
		                                        WPAS_DBUS_IFACE_INTERFACE,
		                                        "removeNetwork");
		if (!message) {
			nm_warning ("Couldn't create dbus message.");
			goto out;
		}

		if (!dbus_message_append_args (message,
		                               DBUS_TYPE_OBJECT_PATH, &self->priv->wpas_net_op,
		                               DBUS_TYPE_INVALID)) {
			nm_warning ("Couldn't compose removeNetwork dbus message.");
			goto out;
		}

		pcall = nm_dbus_send_with_callback (dbus_connection,
		                                    message,
		                                    (DBusPendingCallNotifyFunction) remove_network_cb,
		                                    self,
		                                    NULL,
		                                    __func__);
		dbus_message_unref (message);
		g_free (self->priv->wpas_net_op);
		self->priv->wpas_net_op = NULL;
	}

	/* Send a general disconnect command */
	message = dbus_message_new_method_call (WPAS_DBUS_SERVICE,
	                                        self->priv->wpas_iface_op,
	                                        WPAS_DBUS_IFACE_INTERFACE,
	                                        "disconnect");
	if (!message) {
		nm_warning ("Couldn't create dbus message.");
		goto out;
	}

	pcall = nm_dbus_send_with_callback (dbus_connection,
	                                    message,
	                                    (DBusPendingCallNotifyFunction) disconnect_cb,
	                                    self,
	                                    NULL,
	                                    __func__);

out:
	if (message)
		dbus_message_unref (message);
}

#define WPAS_DBUS_IFACE_NETWORK	WPAS_DBUS_INTERFACE ".Network"

static void
select_network_cb (DBusPendingCall * pcall,
                   NMSupplicantInterface * self)
{
	DBusError        error;
	DBusMessage *    reply = NULL;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (self != NULL);

	dbus_error_init (&error);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!dbus_pending_call_get_completed (pcall)) {
		emit_error_helper (self, "SelectNetworkError", "pending call not yet completed");
		goto out;
	}

	if (!(reply = dbus_pending_call_steal_reply (pcall))) {
		emit_error_helper (self, "SelectNetworkError", "could not steal reply");
		goto out;
	}

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR) {
		dbus_set_error_from_message (&error, reply);
		nm_warning ("Couldn't select network config: %s - %s",
		            error.name,
		            error.message);
		emit_error_helper (self, error.name, error.message);
		goto out;
	}

out:
	if (reply)
		dbus_message_unref (reply);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	self->priv->assoc_pcalls = pcall_list_remove_pcall (self->priv->assoc_pcalls, pcall);
}

static void
set_network_cb (DBusPendingCall * pcall,
                NMSupplicantInterface * self)
{
	DBusError        error;
	DBusMessage *    reply = NULL;
	DBusConnection * dbus_connection;
	DBusMessage *    message = NULL;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (self != NULL);

	dbus_connection = nm_dbus_manager_get_dbus_connection (self->priv->dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get the dbus connection.");
		emit_error_helper (self, "SetNetworkError", "could not get the dbus connection.");
		goto out;
	}

	dbus_error_init (&error);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!dbus_pending_call_get_completed (pcall)) {
		emit_error_helper (self, "SetNetworkError", "pending call not yet completed");
		goto out;
	}

	if (!(reply = dbus_pending_call_steal_reply (pcall))) {
		emit_error_helper (self, "SetNetworkError", "could not steal reply");
		goto out;
	}

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR) {
		dbus_set_error_from_message (&error, reply);
		nm_warning ("Couldn't set network config: %s - %s",
		            error.name,
		            error.message);
		emit_error_helper (self, error.name, error.message);
		goto out;
	}

	message = dbus_message_new_method_call (WPAS_DBUS_SERVICE,
	                                        self->priv->wpas_iface_op,
	                                        WPAS_DBUS_IFACE_INTERFACE,
	                                        "selectNetwork");
	if (!message) {
		nm_warning ("Couldn't create dbus message.");
		emit_error_helper (self, "SetNetworkError", "could not create dbus message.");
		goto out;
	}

	if (!dbus_message_append_args (message,
	                               DBUS_TYPE_OBJECT_PATH, &self->priv->wpas_net_op,
	                               DBUS_TYPE_INVALID)) {
		emit_error_helper (self, "SetNetworkError", "could not add arguments to message.");
		goto out;
	}

	nm_dbus_send_with_callback (dbus_connection,
	                            message,
	                            (DBusPendingCallNotifyFunction) select_network_cb,
	                            self,
	                            NULL,
	                            __func__);

out:
	if (reply)
		dbus_message_unref (reply);
	if (message)
		dbus_message_unref (message);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	self->priv->assoc_pcalls = pcall_list_remove_pcall (self->priv->assoc_pcalls, pcall);
}

static void
add_network_cb (DBusPendingCall * pcall,
                NMSupplicantInterface * self)
{
	DBusError error;
	DBusMessage * reply = NULL;
	DBusMessage * message = NULL;
	DBusConnection * dbus_connection = NULL;
	char * net_op = NULL;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (self != NULL);

	dbus_connection = nm_dbus_manager_get_dbus_connection (self->priv->dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get the dbus connection.");
		emit_error_helper (self, "AddNetworkError", "could not get the dbus connection.");
		goto out;
	}

	dbus_error_init (&error);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!dbus_pending_call_get_completed (pcall)) {
		emit_error_helper (self, "AddNetworkError", "pending call not yet completed.");
		goto out;
	}

	if (!(reply = dbus_pending_call_steal_reply (pcall))) {
		emit_error_helper (self, "AddNetworkError", "could not steal reply");
		goto out;
	}

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR) {
		dbus_set_error_from_message (&error, reply);
		nm_warning ("Couldn't add a network to the supplicant interface: %s - %s",
		            error.name,
		            error.message);
		emit_error_helper (self, error.name, error.message);
		goto out;
	}

	if (!dbus_message_get_args (reply,
	                            &error,
	                            DBUS_TYPE_OBJECT_PATH, &net_op,
	                            DBUS_TYPE_INVALID)) {
		nm_warning ("couldn't get network object path from the supplicant: %s - %s",
		            error.name,
		            error.message);
		emit_error_helper (self, error.name, error.message);
		goto out;
	}
	self->priv->wpas_net_op = g_strdup (net_op);

	message = dbus_message_new_method_call (WPAS_DBUS_SERVICE,
	                                        self->priv->wpas_net_op,
	                                        WPAS_DBUS_IFACE_NETWORK,
	                                        "set");
	if (!message) {
		nm_warning ("Couldn't create dbus message.");
		emit_error_helper (self, "AddNetworkError", "could not create dbus message.");
		goto out;
	}

	if (!nm_supplicant_config_add_to_dbus_message (self->priv->cfg, message)) {
		emit_error_helper (self, "AddNetworkError", "could not add config to dbus message.");
		goto out;
	}

	nm_dbus_send_with_callback (dbus_connection,
	                            message,
	                            (DBusPendingCallNotifyFunction) set_network_cb,
	                            self,
	                            NULL,
	                            __func__);
	dbus_message_unref (message);
	
out:
	if (reply)
		dbus_message_unref (reply);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	self->priv->assoc_pcalls = pcall_list_remove_pcall (self->priv->assoc_pcalls, pcall);
}

static void
set_ap_scan_cb (DBusPendingCall * pcall,
                NMSupplicantInterface * self)
{
	DBusError error;
	DBusMessage * reply = NULL;
	DBusMessage * message = NULL;
	DBusConnection * dbus_connection = NULL;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (self != NULL);

	dbus_connection = nm_dbus_manager_get_dbus_connection (self->priv->dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get the dbus connection.");
		emit_error_helper (self, "SetAPScanError", "could not get the dbus connection.");
		goto out;
	}

	dbus_error_init (&error);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!dbus_pending_call_get_completed (pcall)) {
		emit_error_helper (self, "SetAPScanError", "pending call not yet completed.");
		goto out;
	}

	if (!(reply = dbus_pending_call_steal_reply (pcall))) {
		emit_error_helper (self, "SetAPScanError", "could not steal reply");
		goto out;
	}

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR) {
		dbus_set_error_from_message (&error, reply);
		nm_warning ("Couldn't send AP scan mode to the supplicant interface: %s - %s",
		            error.name,
		            error.message);
		emit_error_helper (self, error.name, error.message);
		goto out;
	}

	message = dbus_message_new_method_call (WPAS_DBUS_SERVICE,
	                                        self->priv->wpas_iface_op,
	                                        WPAS_DBUS_IFACE_INTERFACE,
	                                        "addNetwork");
	if (!message) {
		nm_warning ("Couldn't create dbus message.");
		emit_error_helper (self, "SetAPScanError", "couldn't create addNetwork message");
		goto out;
	}

	pcall = nm_dbus_send_with_callback (dbus_connection,
	                                    message,
	                                    (DBusPendingCallNotifyFunction) add_network_cb,
	                                    self,
	                                    NULL,
	                                    __func__);
	
out:
	if (reply)
		dbus_message_unref (reply);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	self->priv->assoc_pcalls = pcall_list_remove_pcall (self->priv->assoc_pcalls, pcall);
}

#include <stdio.h>
gboolean
nm_supplicant_interface_set_config (NMSupplicantInterface * self,
                                    NMSupplicantConfig * cfg)
{
	DBusConnection *  dbus_connection;
	DBusMessage *     message = NULL;
	DBusPendingCall * pcall = NULL;
	gboolean          success = FALSE;
	guint32           ap_scan;

	g_return_val_if_fail (self != NULL, FALSE);

	dbus_connection = nm_dbus_manager_get_dbus_connection (self->priv->dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get the dbus connection.");
		goto out;
	}

	nm_supplicant_interface_disconnect (self);

	if (self->priv->cfg)
		g_object_unref (self->priv->cfg);
	self->priv->cfg = cfg;

	if (cfg == NULL) {
		success = TRUE;
		goto out;
	}

	g_object_ref (self->priv->cfg);

	message = dbus_message_new_method_call (WPAS_DBUS_SERVICE,
	                                        self->priv->wpas_iface_op,
	                                        WPAS_DBUS_IFACE_INTERFACE,
	                                        "setAPScan");
	if (!message) {
		nm_warning ("Couldn't create dbus message.");
		goto out;
	}

	ap_scan = nm_supplicant_config_get_ap_scan (self->priv->cfg);
	if (!dbus_message_append_args (message,
	                               DBUS_TYPE_UINT32, &ap_scan,
	                               DBUS_TYPE_INVALID))
	{
		nm_warning ("couldn't set ap scan message arguments.");
		goto out;
	}

	pcall = nm_dbus_send_with_callback (dbus_connection,
	                                    message,
	                                    (DBusPendingCallNotifyFunction) set_ap_scan_cb,
	                                    self,
	                                    NULL,
	                                    __func__);
	success = TRUE;

out:
	if (message)
		dbus_message_unref (message);
	return success;
}

NMDevice *
nm_supplicant_interface_get_device (NMSupplicantInterface * self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return self->priv->dev;
}

static void
scan_request_cb (DBusPendingCall * pcall,
                 NMSupplicantInterface * self)
{
	DBusError     error;
	DBusMessage * reply = NULL;
	guint32       success = FALSE;
	guint32       scan_result = NM_SUPPLICANT_INTERFACE_SCAN_RESULT_ERROR;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (self != NULL);

	dbus_error_init (&error);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (!dbus_message_get_args (reply,
	                            &error,
	                            DBUS_TYPE_UINT32, &success,
	                            DBUS_TYPE_INVALID)) {
		nm_warning ("could not get scan request result: %s - %s.",
		            error.name,
		            error.message);
		goto out;
	}

	/* Notify listeners of the result of the scan */
	if (success == 1)
		scan_result = NM_SUPPLICANT_INTERFACE_SCAN_RESULT_SUCCESS;
	g_signal_emit (G_OBJECT (self),
	               nm_supplicant_interface_signals[SCAN_RESULT],
	               0,
	               scan_result);	

out:
	if (reply)
		dbus_message_unref (reply);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	self->priv->other_pcalls = pcall_list_remove_pcall (self->priv->other_pcalls, pcall);
}

gboolean
nm_supplicant_interface_request_scan (NMSupplicantInterface * self)
{
	DBusConnection *  dbus_connection;
	DBusMessage *     message = NULL;
	gboolean          success = FALSE;
	DBusPendingCall * pcall;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (self->priv->state == NM_SUPPLICANT_INTERFACE_STATE_READY, FALSE);

	dbus_connection = nm_dbus_manager_get_dbus_connection (self->priv->dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get the dbus connection.");
		goto out;
	}

	message = dbus_message_new_method_call (WPAS_DBUS_SERVICE,
	                                        self->priv->wpas_iface_op,
	                                        WPAS_DBUS_IFACE_INTERFACE,
	                                        "scan");
	if (!message) {
		nm_warning ("Not enough memory to allocate dbus message.");
		goto out;
	}

	pcall = nm_dbus_send_with_callback (dbus_connection,
	                                    message,
	                                    (DBusPendingCallNotifyFunction) scan_request_cb,
	                                    self,
	                                    NULL,
	                                    __func__);
	if (!pcall) {
		nm_warning ("could not send dbus message.");
		goto out;
	}
	self->priv->other_pcalls = pcall_list_add_pcall (self->priv->other_pcalls, pcall);
	success = TRUE;

out:
	if (message)
		dbus_message_unref (message);
	return success;
}

guint32
nm_supplicant_interface_get_state (NMSupplicantInterface * self)
{
	g_return_val_if_fail (self != NULL, NM_SUPPLICANT_INTERFACE_STATE_DOWN);

	return self->priv->state;
}

guint32
nm_supplicant_interface_get_connection_state (NMSupplicantInterface * self)
{
	g_return_val_if_fail (self != NULL, NM_SUPPLICANT_INTERFACE_CON_STATE_DISCONNECTED);

	return self->priv->con_state;
}

