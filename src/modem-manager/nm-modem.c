/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include <string.h>
#include "nm-modem.h"
#include "nm-device-private.h"
#include "nm-device-interface.h"
#include "nm-dbus-manager.h"
#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-setting-cdma.h"
#include "nm-marshal.h"
#include "nm-properties-changed-signal.h"
#include "nm-modem-types.h"
#include "nm-utils.h"
#include "nm-serial-device-glue.h"

G_DEFINE_TYPE (NMModem, nm_modem, NM_TYPE_DEVICE)

#define NM_MODEM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM, NMModemPrivate))

enum {
	PROP_0,
	PROP_PATH,

	LAST_PROP
};

typedef struct {
	NMDBusManager *dbus_mgr;
	char *path;
	DBusGProxy *proxy;
	NMPPPManager *ppp_manager;
	NMIP4Config	 *pending_ip4_config;

	guint state_to_disconnected_id;

	/* PPP stats */
	guint32 in_bytes;
	guint32 out_bytes;
} NMModemPrivate;

enum {
	PPP_STATS,
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

NMPPPManager *
nm_modem_get_ppp_manager (NMModem *self)
{
	g_return_val_if_fail (NM_IS_MODEM (self), NULL);

	return NM_MODEM_GET_PRIVATE (self)->ppp_manager;
}

DBusGProxy *
nm_modem_get_proxy (NMModem *self,
					const char *interface)
{

	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);
	const char *current_iface;

	g_return_val_if_fail (NM_IS_MODEM (self), NULL);

	/* Default to the default interface. */
	if (interface == NULL)
		interface = MM_DBUS_INTERFACE_MODEM;

	current_iface = dbus_g_proxy_get_interface (priv->proxy);
	if (!current_iface || strcmp (current_iface, interface))
		dbus_g_proxy_set_interface (priv->proxy, interface);

	return priv->proxy;
}

void
nm_modem_connect (NMModem *self,
				  const char *number)
{
	g_return_if_fail (NM_IS_MODEM (self));

	NM_MODEM_GET_CLASS (self)->connect (self, number);
}

const char *
nm_modem_get_ppp_name (NMModem *self,
					   NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_MODEM (self), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	if (NM_MODEM_GET_CLASS (self)->get_ppp_name)
		return NM_MODEM_GET_CLASS (self)->get_ppp_name (self, connection);

	return NULL;
}

static void
ppp_state_changed (NMPPPManager *ppp_manager, NMPPPStatus status, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	switch (status) {
	case NM_PPP_STATUS_NETWORK:
		nm_device_state_changed (device, NM_DEVICE_STATE_IP_CONFIG, NM_DEVICE_STATE_REASON_NONE);
		break;
	case NM_PPP_STATUS_DISCONNECT:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_DISCONNECT);
		break;
	case NM_PPP_STATUS_DEAD:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_FAILED);
		break;
	case NM_PPP_STATUS_AUTHENTICATE:
		nm_device_state_changed (device, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);
		break;
	default:
		break;
	}
}

static void
ppp_ip4_config (NMPPPManager *ppp_manager,
				const char *iface,
				NMIP4Config *config,
				gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	nm_device_set_ip_iface (device, iface);
	NM_MODEM_GET_PRIVATE (device)->pending_ip4_config = g_object_ref (config);
	nm_device_activate_schedule_stage4_ip_config_get (device);
}

static void
ppp_stats (NMPPPManager *ppp_manager,
		   guint32 in_bytes,
		   guint32 out_bytes,
		   gpointer user_data)
{
	NMModem *self = NM_MODEM (user_data);
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);

	if (priv->in_bytes != in_bytes || priv->out_bytes != out_bytes) {
		priv->in_bytes = in_bytes;
		priv->out_bytes = out_bytes;

		g_signal_emit (self, signals[PPP_STATS], 0, in_bytes, out_bytes);
	}
}

static NMActStageReturn
real_act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (device);
	NMActRequest *req;
	const char *ppp_name = NULL;
	GError *err = NULL;
	NMActStageReturn ret;

	req = nm_device_get_act_request (device);
	g_assert (req);

	ppp_name = nm_modem_get_ppp_name (NM_MODEM (device),
									  nm_act_request_get_connection (req));

	priv->ppp_manager = nm_ppp_manager_new (nm_device_get_iface (device));
	if (nm_ppp_manager_start (priv->ppp_manager, req, ppp_name, &err)) {
		g_signal_connect (priv->ppp_manager, "state-changed",
						  G_CALLBACK (ppp_state_changed),
						  device);
		g_signal_connect (priv->ppp_manager, "ip4-config",
						  G_CALLBACK (ppp_ip4_config),
						  device);
		g_signal_connect (priv->ppp_manager, "stats",
						  G_CALLBACK (ppp_stats),
						  device);

		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else {
		nm_warning ("%s", err->message);
		g_error_free (err);

		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;

		*reason = NM_DEVICE_STATE_REASON_PPP_START_FAILED;
		ret = NM_ACT_STAGE_RETURN_FAILURE;
	}

	return ret;
}

static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *device,
								NMIP4Config **config,
								NMDeviceStateReason *reason)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (device);

	*config = priv->pending_ip4_config;
	priv->pending_ip4_config = NULL;

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
real_deactivate_quickly (NMDevice *device)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (device);

	nm_device_set_ip_iface (device, NULL);

	if (priv->pending_ip4_config) {
		g_object_unref (priv->pending_ip4_config);
		priv->pending_ip4_config = NULL;
	}

	priv->in_bytes = priv->out_bytes = 0;

	if (priv->ppp_manager) {
		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;
	}

	dbus_g_proxy_call_no_reply (nm_modem_get_proxy (NM_MODEM (device), NULL),
								"Enable", G_TYPE_BOOLEAN, FALSE, G_TYPE_INVALID);
}

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_NM_SUPPORTED;
}


static void
connect_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	GError *error = NULL;

	if (dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID))
		nm_device_activate_schedule_stage2_device_config (device);
	else {
		nm_warning ("Connect failed: %s", error->message);
		g_error_free (error);
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED);
	}
}

static void
real_connect (NMModem *modem, const char *number)
{
	dbus_g_proxy_begin_call_with_timeout (nm_modem_get_proxy (modem, MM_DBUS_INTERFACE_MODEM),
										  "Connect", connect_done,
										  modem, NULL, 60000,
										  G_TYPE_STRING, number ? number : "",
										  G_TYPE_INVALID);
}

static gboolean
unavailable_to_disconnected (gpointer user_data)
{
	nm_device_state_changed (NM_DEVICE (user_data),
							 NM_DEVICE_STATE_DISCONNECTED,
							 NM_DEVICE_STATE_REASON_NONE);
	return FALSE;
}

static void
device_state_changed (NMDeviceInterface *device,
					  NMDeviceState new_state,
					  NMDeviceState old_state,
					  NMDeviceStateReason reason,
					  gpointer user_data)
{
	NMModem *self = NM_MODEM (user_data);
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);

	/* Remove any previous delayed transition to disconnected */
	if (priv->state_to_disconnected_id) {
		g_source_remove (priv->state_to_disconnected_id);
		priv->state_to_disconnected_id = 0;
	}

	/* If transitioning to UNAVAILBLE and we have a carrier, transition to
	 * DISCONNECTED because the device is ready to use.	 Otherwise the carrier-on
	 * handler will handle the transition to DISCONNECTED when the carrier is detected.
	 */
	if (new_state == NM_DEVICE_STATE_UNAVAILABLE)
		priv->state_to_disconnected_id = g_idle_add (unavailable_to_disconnected, user_data);

	/* Make sure we don't leave the serial device open */
	switch (new_state) {
	case NM_DEVICE_STATE_NEED_AUTH:
		if (priv->ppp_manager)
			break;
		/* else fall through */
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_FAILED:
	case NM_DEVICE_STATE_DISCONNECTED:
		dbus_g_proxy_call_no_reply (nm_modem_get_proxy (self, NULL),
									"Disconnect", G_TYPE_INVALID);
		break;
	default:
		break;
	}
}

/*****************************************************************************/

static void
nm_modem_init (NMModem *self)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);

	priv->dbus_mgr = nm_dbus_manager_get ();
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMModemPrivate *priv;

	object = G_OBJECT_CLASS (nm_modem_parent_class)->constructor (type,
																  n_construct_params,
																  construct_params);
	if (!object)
		return NULL;

	priv = NM_MODEM_GET_PRIVATE (object);

	if (!priv->path) {
		g_warning ("DBus path not provided");
		goto err;
	}

	priv->proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (priv->dbus_mgr),
											 MM_DBUS_SERVICE, priv->path, MM_DBUS_INTERFACE_MODEM);

	g_signal_connect (object, "state-changed", G_CALLBACK (device_state_changed), object);

	return object;

 err:
	g_object_unref (object);
	return NULL;
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PATH:
		g_value_set_string (value, priv->path);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}

}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PATH:
		/* Construct only */
		priv->path = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (object);

	if (priv->state_to_disconnected_id) {
		g_source_remove (priv->state_to_disconnected_id);
		priv->state_to_disconnected_id = 0;
	}

	if (priv->proxy)
		g_object_unref (priv->proxy);

	g_object_unref (priv->dbus_mgr);

	G_OBJECT_CLASS (nm_modem_parent_class)->finalize (object);
}

static void
nm_modem_class_init (NMModemClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMModemPrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	device_class->get_generic_capabilities = real_get_generic_capabilities;
	device_class->act_stage2_config = real_act_stage2_config;
	device_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	device_class->deactivate_quickly = real_deactivate_quickly;

	klass->connect = real_connect;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_PATH,
		 g_param_spec_string (NM_MODEM_PATH,
							  "DBus path",
							  "DBus path",
							  NULL,
							  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* Signals */
	signals[PPP_STATS] =
		g_signal_new ("ppp-stats",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMModemClass, ppp_stats),
					  NULL, NULL,
					  _nm_marshal_VOID__UINT_UINT,
					  G_TYPE_NONE, 2,
					  G_TYPE_UINT, G_TYPE_UINT);

	signals[PROPERTIES_CHANGED] = 
		nm_properties_changed_signal_new (object_class,
										  G_STRUCT_OFFSET (NMModemClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_serial_device_object_info);
}
