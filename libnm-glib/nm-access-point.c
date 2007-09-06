#include "nm-access-point.h"
#include "NetworkManager.h"

#include "nm-access-point-bindings.h"

G_DEFINE_TYPE (NMAccessPoint, nm_access_point, NM_TYPE_OBJECT)

#define NM_ACCESS_POINT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_ACCESS_POINT, NMAccessPointPrivate))

typedef struct {
	DBusGProxy *ap_proxy;
	gint8 strength;
} NMAccessPointPrivate;

enum {
	STRENGTH_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void strength_changed_proxy (NMAccessPoint *ap, guchar strength);

static void
nm_access_point_init (NMAccessPoint *ap)
{
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	NMObject *object;
	NMAccessPointPrivate *priv;

	object = (NMObject *) G_OBJECT_CLASS (nm_access_point_parent_class)->constructor (type,
																					  n_construct_params,
																					  construct_params);
	if (!object)
		return NULL;

	priv = NM_ACCESS_POINT_GET_PRIVATE (object);

	priv->ap_proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (object),
												NM_DBUS_SERVICE,
												nm_object_get_path (object),
												NM_DBUS_INTERFACE_DEVICE);

	dbus_g_proxy_add_signal (priv->ap_proxy, "StrengthChanged", G_TYPE_UCHAR, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->ap_proxy,
								 "StrengthChanged",
								 G_CALLBACK (strength_changed_proxy),
								 NULL,
								 NULL);
	return G_OBJECT (object);
}


static void
nm_access_point_class_init (NMAccessPointClass *ap_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ap_class);

	g_type_class_add_private (ap_class, sizeof (NMAccessPointPrivate));

	/* virtual methods */
	object_class->constructor = constructor;

	/* signals */
	signals[STRENGTH_CHANGED] =
		g_signal_new ("strength-changed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMAccessPointClass, strength_changed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__UCHAR,
					  G_TYPE_NONE, 1,
					  G_TYPE_UCHAR);

}

NMAccessPoint *
nm_access_point_new (DBusGConnection *connection, const char *path)
{
	return (NMAccessPoint *) g_object_new (NM_TYPE_ACCESS_POINT,
										   NM_OBJECT_CONNECTION, connection,
										   NM_OBJECT_PATH, path,
										   NULL);
}

static void
strength_changed_proxy (NMAccessPoint *ap, guchar strength)
{
	NMAccessPointPrivate *priv = NM_ACCESS_POINT_GET_PRIVATE (ap);

	if (priv->strength != strength) {
		priv->strength = strength;
		g_signal_emit (ap, signals[STRENGTH_CHANGED], 0, strength);
	}
}

guint32
nm_access_point_get_flags (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NM_802_11_AP_FLAGS_NONE);

	return nm_object_get_uint_property (NM_OBJECT (ap), NM_DBUS_INTERFACE_ACCESS_POINT, "Flags");
}

guint32
nm_access_point_get_wpa_flags (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NM_802_11_AP_SEC_NONE);

	return nm_object_get_uint_property (NM_OBJECT (ap), NM_DBUS_INTERFACE_ACCESS_POINT, "WpaFlags");
}

guint32
nm_access_point_get_rsn_flags (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NM_802_11_AP_SEC_NONE);

	return nm_object_get_uint_property (NM_OBJECT (ap), NM_DBUS_INTERFACE_ACCESS_POINT, "RsnFlags");
}

GByteArray *
nm_access_point_get_ssid (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NULL);

	return nm_object_get_byte_array_property (NM_OBJECT (ap), NM_DBUS_INTERFACE_ACCESS_POINT, "Ssid");
}

gdouble
nm_access_point_get_frequency (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	return nm_object_get_double_property (NM_OBJECT (ap), NM_DBUS_INTERFACE_ACCESS_POINT, "Frequency");
}

char *
nm_access_point_get_hw_address (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NULL);

	return nm_object_get_string_property (NM_OBJECT (ap), NM_DBUS_INTERFACE_ACCESS_POINT, "HwAddress");
}

int
nm_access_point_get_mode (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	return nm_object_get_int_property (NM_OBJECT (ap), NM_DBUS_INTERFACE_ACCESS_POINT, "Mode");
}

guint32
nm_access_point_get_rate (NMAccessPoint *ap)
{
	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	return nm_object_get_uint_property (NM_OBJECT (ap), NM_DBUS_INTERFACE_ACCESS_POINT, "Rate");
}

gint8
nm_access_point_get_strength (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);

	if (priv->strength == 0)
		priv->strength = nm_object_get_byte_property (NM_OBJECT (ap), NM_DBUS_INTERFACE_ACCESS_POINT, "Strength");

	return priv->strength;
}
