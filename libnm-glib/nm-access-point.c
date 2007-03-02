#include "nm-access-point.h"
#include "NetworkManager.h"
#include "nm-utils.h"

#include "nm-access-point-bindings.h"

G_DEFINE_TYPE (NMAccessPoint, nm_access_point, DBUS_TYPE_G_PROXY)

#define NM_ACCESS_POINT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_ACCESS_POINT, NMAccessPointPrivate))

typedef struct {
	int strength;
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

static void
nm_access_point_class_init (NMAccessPointClass *ap_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ap_class);

	g_type_class_add_private (ap_class, sizeof (NMAccessPointPrivate));

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
	NMAccessPoint *ap;

	ap = (NMAccessPoint *) g_object_new (NM_TYPE_ACCESS_POINT,
										 "name", NM_DBUS_SERVICE,
										 "path", path, 
										 "interface", NM_DBUS_INTERFACE_ACCESS_POINT,
										 "connection", connection,
										 NULL);

	dbus_g_proxy_add_signal (DBUS_G_PROXY (ap), "StrengthChanged", G_TYPE_UCHAR, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (DBUS_G_PROXY (ap),
								 "StrengthChanged",
								 G_CALLBACK (strength_changed_proxy),
								 NULL,
								 NULL);

	return ap;
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
nm_access_point_get_capabilities (NMAccessPoint *ap)
{
	GValue value = {0,};
	guint32 caps = 0;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	if (nm_dbus_get_property (DBUS_G_PROXY (ap),
							  NM_DBUS_INTERFACE_ACCESS_POINT,
							  "Capabilities",
							  &value))
		caps = g_value_get_uint (&value);

	return caps;
}

gboolean
nm_access_point_is_encrypted (NMAccessPoint *ap)
{
	GValue value = {0,};
	int encrypted = FALSE;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), FALSE);

	if (nm_dbus_get_property (DBUS_G_PROXY (ap),
							  NM_DBUS_INTERFACE_ACCESS_POINT,
							  "Encrypted",
							  &value))
		encrypted = g_value_get_boolean (&value);

	return encrypted;
}

char *
nm_access_point_get_essid (NMAccessPoint *ap)
{
	GValue value = {0,};
	char *essid = NULL;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NULL);

	if (nm_dbus_get_property (DBUS_G_PROXY (ap),
							  NM_DBUS_INTERFACE_ACCESS_POINT,
							  "Essid",
							  &value))
		essid = g_strdup (g_value_get_string (&value));

	return essid;
}

gdouble
nm_access_point_get_frequency (NMAccessPoint *ap)
{
	GValue value = {0,};
	double freq = 0.0;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), freq);

	if (nm_dbus_get_property (DBUS_G_PROXY (ap),
							  NM_DBUS_INTERFACE_ACCESS_POINT,
							  "Frequency",
							  &value))
		freq = g_value_get_double (&value);

	return freq;

}

char *
nm_access_point_get_hw_address (NMAccessPoint *ap)
{
	GValue value = {0,};
	char *address = NULL;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NULL);

	if (nm_dbus_get_property (DBUS_G_PROXY (ap),
							  NM_DBUS_INTERFACE_ACCESS_POINT,
							  "HwAddress",
							  &value))
		address = g_strdup (g_value_get_string (&value));

	return address;
}

int
nm_access_point_get_mode (NMAccessPoint *ap)
{
	GValue value = {0,};
	int mode = 0;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	if (nm_dbus_get_property (DBUS_G_PROXY (ap),
							  NM_DBUS_INTERFACE_ACCESS_POINT,
							  "Mode",
							  &value))
		mode = g_value_get_int (&value);

	return mode;
}

guint32
nm_access_point_get_rate (NMAccessPoint *ap)
{
	GValue value = {0,};
	guint32 rate = 0;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	if (nm_dbus_get_property (DBUS_G_PROXY (ap),
							  NM_DBUS_INTERFACE_ACCESS_POINT,
							  "Rate",
							  &value))
		rate = g_value_get_uint (&value);

	return rate;
}

int
nm_access_point_get_strength (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);

	if (priv->strength == 0) {
		GValue value = {0,};
	
		if (nm_dbus_get_property (DBUS_G_PROXY (ap),
								  NM_DBUS_INTERFACE_ACCESS_POINT,
								  "Strength",
								  &value))
			priv->strength = g_value_get_int (&value);
	}

	return priv->strength;
}
