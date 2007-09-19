#include <iwlib.h>

#include "nm-access-point.h"
#include "NetworkManager.h"

#include "nm-access-point-bindings.h"

G_DEFINE_TYPE (NMAccessPoint, nm_access_point, NM_TYPE_OBJECT)

#define NM_ACCESS_POINT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_ACCESS_POINT, NMAccessPointPrivate))

typedef struct {
	gboolean disposed;
	DBusGProxy *ap_proxy;
	guint32 flags;
	guint32 wpa_flags;
	guint32 rsn_flags;
	GByteArray *ssid;
	guint32 frequency;
	char *hw_address;
	int mode;
	guint32 rate;
	gint8 strength;
} NMAccessPointPrivate;

enum {
	PROP_0,
	PROP_FLAGS,
	PROP_WPA_FLAGS,
	PROP_RSN_FLAGS,
	PROP_SSID,
	PROP_FREQUENCY,
	PROP_HW_ADDRESS,
	PROP_MODE,
	PROP_RATE,
	PROP_STRENGTH,

	LAST_PROP
};

#define DBUS_PROP_FLAGS "Flags"
#define DBUS_PROP_WPA_FLAGS "WpaFlags"
#define DBUS_PROP_RSN_FLAGS "RsnFlags"
#define DBUS_PROP_SSID "Ssid"
#define DBUS_PROP_FREQUENCY "Frequency"
#define DBUS_PROP_HW_ADDRESS "HwAddress"
#define DBUS_PROP_MODE "Mode"
#define DBUS_PROP_RATE "Rate"
#define DBUS_PROP_STRENGTH "Strength"

static void properties_changed_proxy (DBusGProxy *proxy,
                                      GHashTable *properties,
                                      gpointer user_data);

static void
nm_access_point_init (NMAccessPoint *ap)
{
}

static void
dispose (GObject *object)
{
	NMAccessPointPrivate *priv = NM_ACCESS_POINT_GET_PRIVATE (object);

	if (priv->disposed)
		return;
	priv->disposed = TRUE;

	g_object_unref (priv->ap_proxy);

	G_OBJECT_CLASS (nm_access_point_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMAccessPointPrivate *priv = NM_ACCESS_POINT_GET_PRIVATE (object);

	if (priv->ssid)
		g_byte_array_free (priv->ssid, TRUE);

	if (priv->hw_address)
		g_free (priv->hw_address);

	G_OBJECT_CLASS (nm_access_point_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMAccessPointPrivate *priv = NM_ACCESS_POINT_GET_PRIVATE (object);
	GArray * ssid;
	int len;
	int i;

	switch (prop_id) {
	case PROP_FLAGS:
		g_value_set_uint (value, priv->flags);
		break;
	case PROP_WPA_FLAGS:
		g_value_set_uint (value, priv->wpa_flags);
		break;
	case PROP_RSN_FLAGS:
		g_value_set_uint (value, priv->rsn_flags);
		break;
	case PROP_SSID:
		len = priv->ssid ? priv->ssid->len : 0;
		ssid = g_array_sized_new (FALSE, TRUE, sizeof (unsigned char), len);
		for (i = 0; i < len; i++)
			g_array_append_val (ssid, priv->ssid->data[i]);
		g_value_set_boxed (value, ssid);
		g_array_free (ssid, TRUE);
		break;
	case PROP_FREQUENCY:
		g_value_set_uint (value, priv->frequency);
		break;
	case PROP_HW_ADDRESS:
		g_value_set_string (value, priv->hw_address);
		break;
	case PROP_MODE:
		g_value_set_int (value, priv->mode);
		break;
	case PROP_RATE:
		g_value_set_uint (value, priv->rate);
		break;
	case PROP_STRENGTH:
		g_value_set_char (value, priv->strength);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
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
												NM_DBUS_INTERFACE_ACCESS_POINT);

	dbus_g_proxy_add_signal (priv->ap_proxy, "PropertiesChanged",
	                         dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->ap_proxy,
								 "PropertiesChanged",
								 G_CALLBACK (properties_changed_proxy),
								 NM_ACCESS_POINT (object),
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
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_FLAGS,
		 g_param_spec_uint (NM_ACCESS_POINT_FLAGS,
		                    "Flags",
		                    "Flags",
		                    NM_802_11_AP_FLAGS_NONE,
		                    NM_802_11_AP_FLAGS_PRIVACY,
		                    NM_802_11_AP_FLAGS_NONE,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_WPA_FLAGS,
		 g_param_spec_uint (NM_ACCESS_POINT_WPA_FLAGS,
		                    "WPA Flags",
		                    "WPA Flags",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_RSN_FLAGS,
		 g_param_spec_uint (NM_ACCESS_POINT_RSN_FLAGS,
		                    "RSN Flags",
		                    "RSN Flags",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_SSID,
	     g_param_spec_boxed (NM_ACCESS_POINT_SSID,
	                         "SSID",
	                         "SSID",
	                         DBUS_TYPE_G_UCHAR_ARRAY,
	                         G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_FREQUENCY,
		 g_param_spec_uint (NM_ACCESS_POINT_FREQUENCY,
							"Frequency",
							"Frequency",
							0, 10000, 0,
							G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_ACCESS_POINT_HW_ADDRESS,
							  "MAC Address",
							  "Hardware MAC address",
							  NULL,
							  G_PARAM_READABLE));
	
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_int (NM_ACCESS_POINT_MODE,
						   "Mode",
						   "Mode",
						   IW_MODE_ADHOC, IW_MODE_INFRA, IW_MODE_INFRA,
						   G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_RATE,
		 g_param_spec_uint (NM_ACCESS_POINT_RATE,
							"Rate",
							"Rate",
							0, G_MAXUINT16, 0,
							G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_STRENGTH,
		 g_param_spec_char (NM_ACCESS_POINT_STRENGTH,
							"Strength",
							"Strength",
							G_MININT8, G_MAXINT8, 0,
							G_PARAM_READABLE));
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
handle_property_changed (gpointer key, gpointer data, gpointer user_data)
{
	NMAccessPoint *ap = NM_ACCESS_POINT (user_data);
	NMAccessPointPrivate *priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	char *g_propname = NULL;
	GValue *value = (GValue *) data;
	gboolean success = TRUE;

	if (!strcmp (key, DBUS_PROP_FLAGS)) {
		g_propname = NM_ACCESS_POINT_FLAGS;
		if (G_VALUE_HOLDS_UINT (value))
			priv->flags = g_value_get_uint (value);
	} else if (!strcmp (key, DBUS_PROP_WPA_FLAGS)) {
		g_propname = NM_ACCESS_POINT_WPA_FLAGS;
		if (G_VALUE_HOLDS_UINT (value))
			priv->wpa_flags = g_value_get_uint (value);
	} else if (!strcmp (key, DBUS_PROP_RSN_FLAGS)) {
		g_propname = NM_ACCESS_POINT_RSN_FLAGS;
		if (G_VALUE_HOLDS_UINT (value))
			priv->rsn_flags = g_value_get_uint (value);
	} else if (!strcmp (key, DBUS_PROP_SSID)) {
		GArray * tmp = g_value_get_boxed (value);

		g_propname = NM_ACCESS_POINT_SSID;

		if (priv->ssid) {
			g_byte_array_free (priv->ssid, TRUE);
			priv->ssid = NULL;
		}

		if (tmp && tmp->len) {
			int i;
			unsigned char byte;

			priv->ssid = g_byte_array_sized_new (tmp->len);
			for (i = 0; i < tmp->len; i++) {
				byte = g_array_index (tmp, unsigned char, i);
				g_byte_array_append (priv->ssid, &byte, 1);
			}
		}
	} else if (!strcmp (key, DBUS_PROP_FREQUENCY)) {
		g_propname = NM_ACCESS_POINT_FREQUENCY;
		if (G_VALUE_HOLDS_UINT (value))
			priv->frequency = g_value_get_uint (value);
	} else if (!strcmp (key, DBUS_PROP_HW_ADDRESS)) {
		g_propname = NM_ACCESS_POINT_HW_ADDRESS;

		if (priv->hw_address) {
			g_free (priv->hw_address);
			priv->hw_address = NULL;
		}

		if (G_VALUE_HOLDS_STRING (value))
			priv->hw_address = g_strdup (g_value_get_string (value));
	} else if (!strcmp (key, DBUS_PROP_MODE)) {
		g_propname = NM_ACCESS_POINT_MODE;
		if (G_VALUE_HOLDS_UINT (value))
			priv->mode = g_value_get_uint (value);
	} else if (!strcmp (key, DBUS_PROP_RATE)) {
		g_propname = NM_ACCESS_POINT_RATE;
		if (G_VALUE_HOLDS_UINT (value))
			priv->rate = g_value_get_uint (value);
	} else if (!strcmp (key, DBUS_PROP_STRENGTH)) {
		g_propname = NM_ACCESS_POINT_STRENGTH;
		if (G_VALUE_HOLDS_CHAR (value))
			priv->strength = g_value_get_char (value);
	} else {
		success = FALSE;
	}

	if (success) {
		g_object_notify (G_OBJECT (ap), g_propname);
	}
}

static void
properties_changed_proxy (DBusGProxy *proxy,
                          GHashTable *properties,
                          gpointer user_data)
{
	NMAccessPoint *ap = NM_ACCESS_POINT (user_data);
	NMAccessPointPrivate *priv = NM_ACCESS_POINT_GET_PRIVATE (ap);

	g_hash_table_foreach (properties, handle_property_changed, ap);
}

guint32
nm_access_point_get_flags (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NM_802_11_AP_FLAGS_NONE);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->flags) {
		priv->flags = nm_object_get_uint_property (NM_OBJECT (ap),
		                                           NM_DBUS_INTERFACE_ACCESS_POINT,
		                                           DBUS_PROP_FLAGS);
	}

	return priv->flags;
}

guint32
nm_access_point_get_wpa_flags (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NM_802_11_AP_SEC_NONE);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->wpa_flags) {
		priv->wpa_flags = nm_object_get_uint_property (NM_OBJECT (ap),
		                                               NM_DBUS_INTERFACE_ACCESS_POINT,
		                                               DBUS_PROP_WPA_FLAGS);
	}

	return priv->wpa_flags;
}

guint32
nm_access_point_get_rsn_flags (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NM_802_11_AP_SEC_NONE);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->rsn_flags) {
		priv->rsn_flags = nm_object_get_uint_property (NM_OBJECT (ap),
		                                               NM_DBUS_INTERFACE_ACCESS_POINT,
		                                               DBUS_PROP_RSN_FLAGS);
	}

	return priv->rsn_flags;
}

const GByteArray *
nm_access_point_get_ssid (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NULL);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->ssid) {
		priv->ssid = nm_object_get_byte_array_property (NM_OBJECT (ap),
		                                                NM_DBUS_INTERFACE_ACCESS_POINT,
		                                                DBUS_PROP_SSID);
	}

	return priv->ssid;
}

guint32
nm_access_point_get_frequency (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->frequency) {
		priv->frequency = nm_object_get_uint_property (NM_OBJECT (ap),
		                                               NM_DBUS_INTERFACE_ACCESS_POINT,
		                                               DBUS_PROP_FREQUENCY);
	}

	return priv->frequency;
}

char *
nm_access_point_get_hw_address (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NULL);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->hw_address) {
		priv->hw_address = nm_object_get_string_property (NM_OBJECT (ap),
		                                                  NM_DBUS_INTERFACE_ACCESS_POINT,
		                                                  DBUS_PROP_HW_ADDRESS);
	}

	return priv->hw_address;
}

int
nm_access_point_get_mode (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->mode) {
		priv->mode = nm_object_get_int_property (NM_OBJECT (ap),
		                                         NM_DBUS_INTERFACE_ACCESS_POINT,
		                                         DBUS_PROP_MODE);
	}

	return priv->mode;
}

guint32
nm_access_point_get_rate (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->rate) {
		priv->rate = nm_object_get_uint_property (NM_OBJECT (ap),
		                                          NM_DBUS_INTERFACE_ACCESS_POINT,
		                                          DBUS_PROP_RATE);
	}

	return priv->rate;
}

gint8
nm_access_point_get_strength (NMAccessPoint *ap)
{
	NMAccessPointPrivate *priv;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), 0);

	priv = NM_ACCESS_POINT_GET_PRIVATE (ap);
	if (!priv->strength) {
		priv->strength = nm_object_get_byte_property (NM_OBJECT (ap),
		                                              NM_DBUS_INTERFACE_ACCESS_POINT,
		                                              DBUS_PROP_STRENGTH);
	}

	return priv->strength;
}
