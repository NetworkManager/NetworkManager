#include "nm-ip4-config.h"
#include "nm-device-private.h"
#include "nm-utils.h"


G_DEFINE_TYPE (NMIP4Config, nm_ip4_config, DBUS_TYPE_G_PROXY)

static void
nm_ip4_config_init (NMIP4Config *config)
{
}

static void
nm_ip4_config_class_init (NMIP4ConfigClass *config_class)
{
}

#define INTERFACE NM_DBUS_INTERFACE ".IP4Config"

NMIP4Config *
nm_ip4_config_new (DBusGConnection *connection, const char *object_path)
{
	return (NMIP4Config *) g_object_new (NM_TYPE_IP4_CONFIG,
										 "name", NM_DBUS_SERVICE,
										 "path", object_path, 
										 "interface", INTERFACE,
										 "connection", connection,
										 NULL);
}

guint32
nm_ip4_config_get_address (NMIP4Config *config)
{
	guint32 address = 0;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	if (nm_dbus_get_property (DBUS_G_PROXY (config),
							  INTERFACE,
							  "Address",
							  &value))
		address = g_value_get_uint (&value);

	return address;
}

guint32
nm_ip4_config_get_gateway (NMIP4Config *config)
{
	guint32 gateway = 0;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	if (nm_dbus_get_property (DBUS_G_PROXY (config),
							  INTERFACE,
							  "Gateway",
							  &value))
		gateway = g_value_get_uint (&value);

	return gateway;
}

guint32
nm_ip4_config_get_netmask (NMIP4Config *config)
{
	guint32 netmask = 0;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	if (nm_dbus_get_property (DBUS_G_PROXY (config),
							  INTERFACE,
							  "Netmask",
							  &value))
		netmask = g_value_get_uint (&value);

	return netmask;
}

guint32
nm_ip4_config_get_broadcast (NMIP4Config *config)
{
	guint32 broadcast = 0;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	if (nm_dbus_get_property (DBUS_G_PROXY (config),
							  INTERFACE,
							  "Broadcast",
							  &value))
		broadcast = g_value_get_uint (&value);

	return broadcast;
}

char *
nm_ip4_config_get_hostname (NMIP4Config *config)
{
	char *address = NULL;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	if (nm_dbus_get_property (DBUS_G_PROXY (config),
							  INTERFACE,
							  "Hostname",
							  &value))
		address = g_strdup (g_value_get_string (&value));

	return address;
}

GArray *
nm_ip4_config_get_nameservers (NMIP4Config *config)
{
	GArray *array = NULL;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	if (nm_dbus_get_property (DBUS_G_PROXY (config),
							  INTERFACE,
							  "Nameservers",
							  &value))
		array = (GArray *) g_value_get_boxed (&value);

	return array;
}


char **
nm_ip4_config_get_domains (NMIP4Config *config)
{
	char **array = NULL;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	if (nm_dbus_get_property (DBUS_G_PROXY (config),
							  INTERFACE,
							  "Domains",
							  &value))
		array = (char **) g_value_get_boxed (&value);

	return array;
}

char *
nm_ip4_config_get_nis_domain (NMIP4Config *config)
{
	char *address = NULL;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	if (nm_dbus_get_property (DBUS_G_PROXY (config),
							  INTERFACE,
							  "NisDomain",
							  &value))
		address = g_strdup (g_value_get_string (&value));

	return address;
}

GArray *
nm_ip4_config_get_nis_servers (NMIP4Config *config)
{
	GArray *array = NULL;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	if (nm_dbus_get_property (DBUS_G_PROXY (config),
							  INTERFACE,
							  "NisServers",
							  &value))
		array = (GArray *) g_value_get_boxed (&value);

	return array;
}
