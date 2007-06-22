#include "nm-ip4-config.h"
#include "NetworkManager.h"

#define INTERFACE NM_DBUS_INTERFACE ".IP4Config"

G_DEFINE_TYPE (NMIP4Config, nm_ip4_config, NM_TYPE_OBJECT)

static void
nm_ip4_config_init (NMIP4Config *config)
{
}

static void
nm_ip4_config_class_init (NMIP4ConfigClass *config_class)
{
}

NMIP4Config *
nm_ip4_config_new (DBusGConnection *connection, const char *object_path)
{
	return (NMIP4Config *) g_object_new (NM_TYPE_IP4_CONFIG,
										 NM_OBJECT_CONNECTION, connection,
										 NM_OBJECT_PATH, object_path,
										 NULL);
}

guint32
nm_ip4_config_get_address (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return nm_object_get_uint_property (NM_OBJECT (config), INTERFACE, "Address");
}

guint32
nm_ip4_config_get_gateway (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return nm_object_get_uint_property (NM_OBJECT (config), INTERFACE, "Gateway");
}

guint32
nm_ip4_config_get_netmask (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return nm_object_get_uint_property (NM_OBJECT (config), INTERFACE, "Netmask");
}

guint32
nm_ip4_config_get_broadcast (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	return nm_object_get_uint_property (NM_OBJECT (config), INTERFACE, "Broadcast");
}

char *
nm_ip4_config_get_hostname (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	return nm_object_get_string_property (NM_OBJECT (config), INTERFACE, "Hostname");
}

GArray *
nm_ip4_config_get_nameservers (NMIP4Config *config)
{
	GArray *array = NULL;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	if (nm_object_get_property (NM_OBJECT (config),
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

	if (nm_object_get_property (NM_OBJECT (config),
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

	if (nm_object_get_property (NM_OBJECT (config),
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

	if (nm_object_get_property (NM_OBJECT (config),
								INTERFACE,
								"NisServers",
								&value))
		array = (GArray *) g_value_get_boxed (&value);

	return array;
}
