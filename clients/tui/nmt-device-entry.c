/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmt-device-entry
 * @short_description: #NmtNewtEntry for identifying a device
 *
 * #NmtDeviceEntry provides a widget for identifying a device, either
 * by interface name or by hardware address. The user can enter either
 * value, and the entry's #NmtDeviceEntry:interface-name or
 * #NmtDeviceEntry:mac-address property will be set accordingly. If
 * the entry recognizes the interface name or mac address typed in as
 * matching a known #NMDevice, then it will also display the other
 * property in parentheses.
 *
 * FIXME: #NmtDeviceEntry is currently an #NmtEditorGrid object, so that
 * we can possibly eventually add a button to its "extra" field, that
 * would pop up a form for selecting a device. But if we're not going
 * to implement that then we should make it just an #NmtNewtEntry.
 */

#include "nm-default.h"

#include <string.h>
#include <sys/socket.h>
#include <linux/if_arp.h>

#include "NetworkManager.h"

#include "nmtui.h"
#include "nmt-device-entry.h"

G_DEFINE_TYPE (NmtDeviceEntry, nmt_device_entry, NMT_TYPE_EDITOR_GRID)

#define NMT_DEVICE_ENTRY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_DEVICE_ENTRY, NmtDeviceEntryPrivate))

typedef struct {
	GType hardware_type;
	NmtDeviceEntryDeviceFilter device_filter;
	gpointer device_filter_data;
	int arptype;

	char *interface_name;
	char *mac_address;

	char *label;
	NmtNewtEntry *entry;
	NmtNewtWidget *button;

	gboolean updating;
} NmtDeviceEntryPrivate;

enum {
	PROP_0,
	PROP_LABEL,
	PROP_WIDTH,
	PROP_HARDWARE_TYPE,
	PROP_INTERFACE_NAME,
	PROP_MAC_ADDRESS,

	LAST_PROP
};

/**
 * nmt_device_entry_new:
 * @label: the label for the entry
 * @width: the width of the entry
 * @hardware_type: the type of #NMDevice to be selected, or
 *   %G_TYPE_NONE if this is for a virtual device type.
 *
 * Creates a new #NmtDeviceEntry, for identifying a device of type
 * @hardware_type. If @hardware_type is %G_TYPE_NONE (and you do not
 * set a #NmtDeviceEntryDeviceFilter), then this will only allow
 * specifying an interface name, not a hardware address.
 *
 * Returns: a new #NmtDeviceEntry.
 */
NmtNewtWidget *
nmt_device_entry_new (const char *label,
                      int         width,
                      GType       hardware_type)
{
	return g_object_new (NMT_TYPE_DEVICE_ENTRY,
	                     "label", label,
	                     "width", width,
	                     "hardware-type", hardware_type,
	                     NULL);
}

static gboolean
device_entry_parse (NmtDeviceEntry  *deventry,
                    const char      *text,
                    char           **interface_name,
                    char           **mac_address)
{
	NmtDeviceEntryPrivate *priv = NMT_DEVICE_ENTRY_GET_PRIVATE (deventry);
	guint8 buf[NM_UTILS_HWADDR_LEN_MAX];
	char **words;
	int len;

	*interface_name = *mac_address = NULL;
	if (!*text)
		return TRUE;

	if (priv->hardware_type == G_TYPE_NONE && !priv->device_filter) {
		if (nm_utils_iface_valid_name (text)) {
			*interface_name = g_strdup (text);
			return TRUE;
		} else
			return FALSE;
	}

	words = g_strsplit (text, " ", -1);
	if (g_strv_length (words) > 2) {
		g_strfreev (words);
		return FALSE;
	}

	if (words[1]) {
		len = strlen (words[1]);
		if (len < 3 || words[1][0] != '(' || words[1][len - 1] != ')')
			goto fail;

		memmove (words[1], words[1] + 1, len - 2);
		words[1][len - 2] = '\0';
	}

	len = nm_utils_hwaddr_len (priv->arptype);
	if (   nm_utils_hwaddr_aton (words[0], buf, len)
	    && (!words[1] || nm_utils_iface_valid_name (words[1]))) {
		*mac_address = words[0];
		*interface_name = NULL;
		g_free (words);
		return TRUE;
	} else if (   nm_utils_iface_valid_name (words[0])
	           && (!words[1] || nm_utils_hwaddr_aton (words[1], buf, len))) {
		*interface_name = words[0];
		*mac_address = NULL;
		g_free (words);
		return TRUE;
	}

 fail:
	g_strfreev (words);
	return FALSE;
}

static gboolean
device_entry_validate (NmtNewtEntry *entry,
                       const char   *text,
                       gpointer      user_data)
{
	NmtDeviceEntry *deventry = user_data;
	char *ifname, *mac;

	if (!device_entry_parse (deventry, text, &ifname, &mac))
		return FALSE;

	g_free (ifname);
	g_free (mac);
	return TRUE;
}

static NMDevice *
find_device_by_interface_name (NmtDeviceEntry *deventry,
                               const char     *interface_name)
{
	NmtDeviceEntryPrivate *priv = NMT_DEVICE_ENTRY_GET_PRIVATE (deventry);
	const GPtrArray *devices;
	NMDevice *device = NULL;
	int i;

	devices = nm_client_get_devices (nm_client);
	for (i = 0; i < devices->len && !device; i++) {
		NMDevice *candidate = devices->pdata[i];

		if (   priv->hardware_type != G_TYPE_NONE
		    && !G_TYPE_CHECK_INSTANCE_TYPE (candidate, priv->hardware_type))
			continue;

		if (   priv->device_filter
		    && !priv->device_filter (deventry, candidate, priv->device_filter_data))
			continue;

		if (!g_strcmp0 (interface_name, nm_device_get_iface (candidate)))
			device = candidate;
	}

	return device;
}

static NMDevice *
find_device_by_mac_address (NmtDeviceEntry *deventry,
                            const char     *mac_address)
{
	NmtDeviceEntryPrivate *priv = NMT_DEVICE_ENTRY_GET_PRIVATE (deventry);
	const GPtrArray *devices;
	NMDevice *device = NULL;
	int i;

	devices = nm_client_get_devices (nm_client);
	for (i = 0; i < devices->len && !device; i++) {
		NMDevice *candidate = devices->pdata[i];
		char *hwaddr;

		if (   priv->hardware_type != G_TYPE_NONE
		    && !G_TYPE_CHECK_INSTANCE_TYPE (candidate, priv->hardware_type))
			continue;

		if (   priv->device_filter
		    && !priv->device_filter (deventry, candidate, priv->device_filter_data))
			continue;

		g_object_get (G_OBJECT (candidate), "hw-address", &hwaddr, NULL);
		if (hwaddr && !g_ascii_strcasecmp (mac_address, hwaddr))
			device = candidate;
		g_free (hwaddr);
	}

	return device;
}

static void
update_entry (NmtDeviceEntry *deventry)
{
	NmtDeviceEntryPrivate *priv = NMT_DEVICE_ENTRY_GET_PRIVATE (deventry);
	const char *ifname;
	char *mac, *text;
	NMDevice *ifname_device, *mac_device;

	if (priv->interface_name) {
		ifname = priv->interface_name;
		ifname_device = find_device_by_interface_name (deventry, priv->interface_name);
	} else {
		ifname = NULL;
		ifname_device = NULL;
	}

	if (priv->mac_address) {
		mac = g_strdup (priv->mac_address);
		mac_device = find_device_by_mac_address (deventry, priv->mac_address);
	} else {
		mac = NULL;
		mac_device = NULL;
	}

	if (!ifname && mac_device)
		ifname = nm_device_get_iface (mac_device);
	if (!mac && ifname_device && (priv->hardware_type != G_TYPE_NONE))
		g_object_get (G_OBJECT (ifname_device), "hw-address", &mac, NULL);

	if (ifname_device && mac_device && ifname_device != mac_device) {
		/* Mismatch! */
		text = g_strdup_printf ("%s != %s", priv->interface_name, mac);
	} else if (ifname && mac) {
		if (ifname_device)
			text = g_strdup_printf ("%s (%s)", ifname, mac);
		else
			text = g_strdup_printf ("%s (%s)", mac, ifname);
	} else if (ifname)
		text = g_strdup (ifname);
	else if (mac)
		text = g_strdup (mac);
	else
		text = g_strdup ("");

	priv->updating = TRUE;
	g_object_set (G_OBJECT (priv->entry), "text", text, NULL);
	priv->updating = FALSE;
	g_free (text);

	g_free (mac);
}

static gboolean
nmt_device_entry_set_interface_name (NmtDeviceEntry *deventry,
                                     const char     *interface_name)
{
	NmtDeviceEntryPrivate *priv = NMT_DEVICE_ENTRY_GET_PRIVATE (deventry);

	if (g_strcmp0 (interface_name, priv->interface_name) != 0) {
		g_free (priv->interface_name);
		priv->interface_name = g_strdup (interface_name);

		g_object_notify (G_OBJECT (deventry), "interface-name");
		return TRUE;
	} else
		return FALSE;
}

static gboolean
nmt_device_entry_set_mac_address (NmtDeviceEntry *deventry,
                                  const char     *mac_address)
{
	NmtDeviceEntryPrivate *priv = NMT_DEVICE_ENTRY_GET_PRIVATE (deventry);
	gboolean changed;

	if (mac_address && !priv->mac_address) {
		priv->mac_address = g_strdup (mac_address);
		changed = TRUE;
	} else if (!mac_address && priv->mac_address) {
		g_clear_pointer (&priv->mac_address, g_free);
		changed = TRUE;
	} else if (   mac_address && priv->mac_address
	           && !nm_utils_hwaddr_matches (mac_address, -1, priv->mac_address, -1)) {
		g_free (priv->mac_address);
		priv->mac_address = g_strdup (mac_address);
		changed = TRUE;
	} else
		changed = FALSE;

	if (changed)
		g_object_notify (G_OBJECT (deventry), "mac-address");
	return changed;
}

static void
entry_text_changed (GObject    *object,
                    GParamSpec *pspec,
                    gpointer    deventry)
{
	NmtDeviceEntryPrivate *priv = NMT_DEVICE_ENTRY_GET_PRIVATE (deventry);
	const char *text;
	char *ifname, *mac;

	if (priv->updating)
		return;

	text = nmt_newt_entry_get_text (priv->entry);
	if (!device_entry_parse (deventry, text, &ifname, &mac))
		return;

	nmt_device_entry_set_interface_name (deventry, ifname);
	g_free (ifname);

	nmt_device_entry_set_mac_address (deventry, mac);
	g_free (mac);
}

static void
nmt_device_entry_init (NmtDeviceEntry *deventry)
{
	NmtDeviceEntryPrivate *priv = NMT_DEVICE_ENTRY_GET_PRIVATE (deventry);
	NmtNewtWidget *entry;

	priv->hardware_type = G_TYPE_NONE;

	entry = nmt_newt_entry_new (-1, 0);
	priv->entry = NMT_NEWT_ENTRY (entry);
	nmt_newt_entry_set_validator (priv->entry, device_entry_validate, deventry);
	g_signal_connect (priv->entry, "notify::text",
	                  G_CALLBACK (entry_text_changed), deventry);

#if 0
	priv->button = nmt_newt_button_new (_("Select..."));
	g_signal_connect (priv->button, "clicked",
	                  G_CALLBACK (do_select_dialog), deventry);
#endif
}

static void
nmt_device_entry_constructed (GObject *object)
{
	NmtDeviceEntryPrivate *priv = NMT_DEVICE_ENTRY_GET_PRIVATE (object);

	nmt_editor_grid_append (NMT_EDITOR_GRID (object), priv->label, NMT_NEWT_WIDGET (priv->entry), NULL);

	G_OBJECT_CLASS (nmt_device_entry_parent_class)->constructed (object);
}

static void
nmt_device_entry_finalize (GObject *object)
{
	NmtDeviceEntryPrivate *priv = NMT_DEVICE_ENTRY_GET_PRIVATE (object);

	g_free (priv->interface_name);
	g_free (priv->mac_address);

	G_OBJECT_CLASS (nmt_device_entry_parent_class)->finalize (object);
}

/**
 * NmtDeviceEntryDeviceFilter:
 * @deventry: the #NmtDeviceEntry
 * @device: an #NMDevice
 * @user_data: user data
 *
 * Filter function for determining which devices can be specified
 * on an entry.
 *
 * Returns: %TRUE if @device is acceptable for @deventry
 */

/**
 * nmt_device_entry_set_device_filter:
 * @deventry: the #NmtDeviceEntry
 * @filter: the filter
 * @user_data: data for @filter
 *
 * Sets a device filter on @deventry. Only devices that pass @filter
 * will be recognized by @deventry.
 *
 * If the entry's #NmtDeviceEntry:hardware-type is not %G_TYPE_NONE,
 * then only devices that both match the hardware type and are
 * accepted by the filter will be allowed.
 */
void
nmt_device_entry_set_device_filter (NmtDeviceEntry             *deventry,
                                    NmtDeviceEntryDeviceFilter  filter,
                                    gpointer                    user_data)
{
	NmtDeviceEntryPrivate *priv = NMT_DEVICE_ENTRY_GET_PRIVATE (deventry);

	priv->device_filter = filter;
	priv->device_filter_data = user_data;
}

static void
nmt_device_entry_set_property (GObject      *object,
                               guint         prop_id,
                               const GValue *value,
                               GParamSpec   *pspec)
{
	NmtDeviceEntry *deventry = NMT_DEVICE_ENTRY (object);
	NmtDeviceEntryPrivate *priv = NMT_DEVICE_ENTRY_GET_PRIVATE (deventry);
	const char *interface_name;
	const char *mac_address;

	switch (prop_id) {
	case PROP_LABEL:
		priv->label = g_value_dup_string (value);
		break;
	case PROP_WIDTH:
		nmt_newt_entry_set_width (priv->entry, g_value_get_int (value));
		break;
	case PROP_HARDWARE_TYPE:
		priv->hardware_type = g_value_get_gtype (value);
		priv->arptype = (priv->hardware_type == NM_TYPE_DEVICE_INFINIBAND) ? ARPHRD_INFINIBAND : ARPHRD_ETHER;
		break;
	case PROP_INTERFACE_NAME:
		interface_name = g_value_get_string (value);
		if (nmt_device_entry_set_interface_name (deventry, interface_name))
			update_entry (deventry);
		break;
	case PROP_MAC_ADDRESS:
		mac_address = g_value_get_string (value);
		if (nmt_device_entry_set_mac_address (deventry, mac_address))
			update_entry (deventry);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_device_entry_get_property (GObject    *object,
                               guint       prop_id,
                               GValue     *value,
                               GParamSpec *pspec)
{
	NmtDeviceEntryPrivate *priv = NMT_DEVICE_ENTRY_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_LABEL:
		g_value_set_string (value, priv->label);
		break;
	case PROP_WIDTH:
		g_value_set_int (value, nmt_newt_entry_get_width (priv->entry));
		break;
	case PROP_HARDWARE_TYPE:
		g_value_set_gtype (value, priv->hardware_type);
		break;
	case PROP_INTERFACE_NAME:
		g_value_set_string (value, priv->interface_name);
		break;
	case PROP_MAC_ADDRESS:
		g_value_set_string (value, priv->mac_address);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_device_entry_class_init (NmtDeviceEntryClass *deventry_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (deventry_class);

	g_type_class_add_private (deventry_class, sizeof (NmtDeviceEntryPrivate));

	/* virtual methods */
	object_class->constructed  = nmt_device_entry_constructed;
	object_class->set_property = nmt_device_entry_set_property;
	object_class->get_property = nmt_device_entry_get_property;
	object_class->finalize     = nmt_device_entry_finalize;

	/**
	 * NmtDeviceEntry:label:
	 *
	 * The entry's label
	 */
	g_object_class_install_property
		(object_class, PROP_LABEL,
		 g_param_spec_string ("label", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtDeviceEntry:width:
	 *
	 * The entry's width in characters
	 */
	g_object_class_install_property
		(object_class, PROP_WIDTH,
		 g_param_spec_int ("width", "", "",
		                   -1, 80, -1,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));
	/**
	 * NmtDeviceEntry:hardware-type:
	 *
	 * The type of #NMDevice to limit the entry to, or %G_TYPE_NONE
	 * if the entry is for a virtual device and should not accept
	 * hardware addresses.
	 */
	g_object_class_install_property
		(object_class, PROP_HARDWARE_TYPE,
		 g_param_spec_gtype ("hardware-type", "", "",
		                     G_TYPE_NONE,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));
	/**
	 * NmtDeviceEntry:interface-name:
	 *
	 * The interface name of the device identified by the entry.
	 */
	g_object_class_install_property
		(object_class, PROP_INTERFACE_NAME,
		 g_param_spec_string ("interface-name", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtDeviceEntry:mac-address:
	 *
	 * The hardware address of the device identified by the entry.
	 */
	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS,
		 g_param_spec_string ("mac-address", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
}
