#include "nm-access-point.h"
#include "NetworkManager.h"
#include "nm-utils.h"

#include "nm-access-point-bindings.h"

G_DEFINE_TYPE (NMAccessPoint, nm_access_point, DBUS_TYPE_G_PROXY)

static void
nm_access_point_init (NMAccessPoint *ap)
{
}

static void
nm_access_point_class_init (NMAccessPointClass *ap_class)
{
}

NMAccessPoint *
nm_access_point_new (DBusGConnection *connection, const char *path)
{
	return (NMAccessPoint *) g_object_new (NM_TYPE_ACCESS_POINT,
										   "name", NM_DBUS_SERVICE,
										   "path", path, 
										   "interface", NM_DBUS_INTERFACE_ACCESS_POINT,
										   "connection", connection,
										   NULL);
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
	GValue value = {0,};
	int strength = 0;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	if (nm_dbus_get_property (DBUS_G_PROXY (ap),
							  NM_DBUS_INTERFACE_ACCESS_POINT,
							  "Strength",
							  &value))
		strength = g_value_get_int (&value);

	return strength;
}
