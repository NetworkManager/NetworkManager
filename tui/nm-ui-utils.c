/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager Applet -- allow user control over networking
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2007 - 2012 Red Hat, Inc.
 */

/**
 * SECTION:nm-ui-utils
 * @short_description: Applet/Connection editor utilities
 *
 * This is stolen directly from libnm-gtk and should probably
 * eventually migrate into libnm-glib. FIXME.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <glib/gi18n.h>
#include <gudev/gudev.h>

#include <nm-device.h>

#include "nm-ui-utils.h"

static char *ignored_words[] = {
	"Semiconductor",
	"Components",
	"Corporation",
	"Communications",
	"Company",
	"Corp.",
	"Corp",
	"Co.",
	"Inc.",
	"Inc",
	"Incorporated",
	"Ltd.",
	"Limited.",
	"Intel?",
	"chipset",
	"adapter",
	"[hex]",
	"NDIS",
	"Module",
	NULL
};

static char *ignored_phrases[] = {
	"Multiprotocol MAC/baseband processor",
	"Wireless LAN Controller",
	"Wireless LAN Adapter",
	"Wireless Adapter",
	"Network Connection",
	"Wireless Cardbus Adapter",
	"Wireless CardBus Adapter",
	"54 Mbps Wireless PC Card",
	"Wireless PC Card",
	"Wireless PC",
	"PC Card with XJACK(r) Antenna",
	"Wireless cardbus",
	"Wireless LAN PC Card",
	"Technology Group Ltd.",
	"Communication S.p.A.",
	"Business Mobile Networks BV",
	"Mobile Broadband Minicard Composite Device",
	"Mobile Communications AB",
	"(PC-Suite Mode)",
	NULL
};

static char *
fixup_desc_string (const char *desc)
{
	char *p, *temp;
	char **words, **item;
	GString *str;

	p = temp = g_strdup (desc);
	while (*p) {
		if (*p == '_' || *p == ',')
			*p = ' ';
		p++;
	}

	/* Attempt to shorten ID by ignoring certain phrases */
	for (item = ignored_phrases; *item; item++) {
		guint32 ignored_len = strlen (*item);

		p = strstr (temp, *item);
		if (p)
			memmove (p, p + ignored_len, strlen (p + ignored_len) + 1); /* +1 for the \0 */
	}

	/* Attmept to shorten ID by ignoring certain individual words */
	words = g_strsplit (temp, " ", 0);
	str = g_string_new_len (NULL, strlen (temp));
	g_free (temp);

	for (item = words; *item; item++) {
		int i = 0;
		gboolean ignore = FALSE;

		if (g_ascii_isspace (**item) || (**item == '\0'))
			continue;

		while (ignored_words[i] && !ignore) {
			if (!strcmp (*item, ignored_words[i]))
				ignore = TRUE;
			i++;
		}

		if (!ignore) {
			if (str->len)
				g_string_append_c (str, ' ');
			g_string_append (str, *item);
		}
	}
	g_strfreev (words);

	temp = str->str;
	g_string_free (str, FALSE);

	return temp;
}

#define VENDOR_TAG "nma_utils_get_device_vendor"
#define PRODUCT_TAG "nma_utils_get_device_product"
#define DESCRIPTION_TAG "nma_utils_get_device_description"

static void
get_description (NMDevice *device)
{
	char *description = NULL;
	const char *dev_product;
	const char *dev_vendor;
	char *product, *pdown;
	char *vendor, *vdown;
	GString *str;

	dev_product = nm_device_get_product (device);
	dev_vendor = nm_device_get_vendor (device);
	if (!dev_product || !dev_vendor) {
		g_object_set_data (G_OBJECT (device),
		                   DESCRIPTION_TAG,
		                   (char *) nm_device_get_iface (device));
		return;
	}

	product = fixup_desc_string (dev_product);
	vendor = fixup_desc_string (dev_vendor);

	str = g_string_new_len (NULL, strlen (vendor) + strlen (product) + 1);

	/* Another quick hack; if all of the fixed up vendor string
	 * is found in product, ignore the vendor.
	 */
	pdown = g_ascii_strdown (product, -1);
	vdown = g_ascii_strdown (vendor, -1);
	if (!strstr (pdown, vdown)) {
		g_string_append (str, vendor);
		g_string_append_c (str, ' ');
	}
	g_free (pdown);
	g_free (vdown);

	g_string_append (str, product);

	description = g_string_free (str, FALSE);

	g_object_set_data_full (G_OBJECT (device),
	                        VENDOR_TAG, vendor,
	                        (GDestroyNotify) g_free);
	g_object_set_data_full (G_OBJECT (device),
	                        PRODUCT_TAG, product,
	                        (GDestroyNotify) g_free);
	g_object_set_data_full (G_OBJECT (device),
	                        DESCRIPTION_TAG, description,
	                        (GDestroyNotify) g_free);
}

/**
 * nma_utils_get_device_vendor:
 * @device: an #NMDevice
 *
 * Gets a cleaned-up version of #NMDevice:vendor for @device. This
 * removes strings like "Inc." that would just take up unnecessary
 * space in the UI.
 *
 * Returns: a cleaned-up vendor string, or %NULL if the vendor is
 *   not known
 */
const char *
nma_utils_get_device_vendor (NMDevice *device)
{
	const char *vendor;

	g_return_val_if_fail (device != NULL, NULL);

	vendor = g_object_get_data (G_OBJECT (device), VENDOR_TAG);
	if (!vendor) {
		get_description (device);
		vendor = g_object_get_data (G_OBJECT (device), VENDOR_TAG);
	}

	return vendor;
}

/**
 * nma_utils_get_device_product:
 * @device: an #NMDevice
 *
 * Gets a cleaned-up version of #NMDevice:product for @device. This
 * removes strings like "Wireless LAN Adapter" that would just take up
 * unnecessary space in the UI.
 *
 * Returns: a cleaned-up product string, or %NULL if the product name
 *   is not known
 */
const char *
nma_utils_get_device_product (NMDevice *device)
{
	const char *product;

	g_return_val_if_fail (device != NULL, NULL);

	product = g_object_get_data (G_OBJECT (device), PRODUCT_TAG);
	if (!product) {
		get_description (device);
		product = g_object_get_data (G_OBJECT (device), PRODUCT_TAG);
	}

	return product;
}

/**
 * nma_utils_get_device_description:
 * @device: an #NMDevice
 *
 * Gets a description of @device, incorporating the results of
 * nma_utils_get_device_vendor() and
 * nma_utils_get_device_product().
 *
 * Returns: a description of @device. If either the vendor or the
 *   product name is unknown, this returns the interface name.
 */
const char *
nma_utils_get_device_description (NMDevice *device)
{
	const char *description;

	g_return_val_if_fail (device != NULL, NULL);

	description = g_object_get_data (G_OBJECT (device), DESCRIPTION_TAG);
	if (!description) {
		get_description (device);
		description = g_object_get_data (G_OBJECT (device), DESCRIPTION_TAG);
	}

	return description;
}

static gboolean
find_duplicates (char     **names,
                 gboolean  *duplicates,
                 int        num_devices)
{
	int i, j;
	gboolean found_any = FALSE;

	memset (duplicates, 0, num_devices * sizeof (gboolean));
	for (i = 0; i < num_devices; i++) {
		if (duplicates[i])
			continue;
		for (j = i + 1; j < num_devices; j++) {
			if (duplicates[j])
				continue;
			if (!strcmp (names[i], names[j]))
				duplicates[i] = duplicates[j] = found_any = TRUE;
		}
	}

	return found_any;
}

/**
 * nma_utils_get_device_generic_type_name:
 * @device: an #NMDevice
 *
 * Gets a "generic" name for the type of @device.
 *
 * Returns: @device's generic type name
 */
const char *
nma_utils_get_device_generic_type_name (NMDevice *device)
{
	switch (nm_device_get_device_type (device)) {
	case NM_DEVICE_TYPE_ETHERNET:
	case NM_DEVICE_TYPE_INFINIBAND:
		return _("Wired");
	default:
		return nma_utils_get_device_type_name (device);
	}
}

/**
 * nma_utils_get_device_type_name:
 * @device: an #NMDevice
 *
 * Gets a specific name for the type of @device.
 *
 * Returns: @device's generic type name
 */
const char *
nma_utils_get_device_type_name (NMDevice *device)
{
	switch (nm_device_get_device_type (device)) {
	case NM_DEVICE_TYPE_ETHERNET:
		return _("Ethernet");
	case NM_DEVICE_TYPE_WIFI:
		return _("Wi-Fi");
	case NM_DEVICE_TYPE_BT:
		return _("Bluetooth");
	case NM_DEVICE_TYPE_OLPC_MESH:
		return _("OLPC Mesh");
	case NM_DEVICE_TYPE_WIMAX:
		return _("WiMAX");
	case NM_DEVICE_TYPE_MODEM:
		return _("Mobile Broadband");
	case NM_DEVICE_TYPE_INFINIBAND:
		return _("InfiniBand");
	case NM_DEVICE_TYPE_BOND:
		return _("Bond");
	case NM_DEVICE_TYPE_TEAM:
		return _("Team");
	case NM_DEVICE_TYPE_BRIDGE:
		return _("Bridge");
	case NM_DEVICE_TYPE_VLAN:
		return _("VLAN");
	case NM_DEVICE_TYPE_ADSL:
		return _("ADSL");
	default:
		return _("Unknown");
	}
}

static char *
get_device_type_name_with_iface (NMDevice *device)
{
	const char *type_name = nma_utils_get_device_type_name (device);

	switch (nm_device_get_device_type (device)) {
	case NM_DEVICE_TYPE_BOND:
	case NM_DEVICE_TYPE_TEAM:
	case NM_DEVICE_TYPE_BRIDGE:
	case NM_DEVICE_TYPE_VLAN:
		return g_strdup_printf ("%s (%s)", type_name, nm_device_get_iface (device));
	default:
		return g_strdup (type_name);
	}
}

static char *
get_device_generic_type_name_with_iface (NMDevice *device)
{
	switch (nm_device_get_device_type (device)) {
	case NM_DEVICE_TYPE_ETHERNET:
	case NM_DEVICE_TYPE_INFINIBAND:
		return g_strdup (_("Wired"));
	default:
		return get_device_type_name_with_iface (device);
	}
}

#define BUS_TAG "nm-ui-utils.c:get_bus_name"

static const char *
get_bus_name (GUdevClient *uclient, NMDevice *device)
{
	GUdevDevice *udevice;
	const char *ifname, *bus;
	char *display_bus;

	bus = g_object_get_data (G_OBJECT (device), BUS_TAG);
	if (bus) {
		if (*bus)
			return bus;
		else
			return NULL;
	}

	ifname = nm_device_get_iface (device);
	if (!ifname)
		return NULL;

	udevice = g_udev_client_query_by_subsystem_and_name (uclient, "net", ifname);
	if (!udevice)
		udevice = g_udev_client_query_by_subsystem_and_name (uclient, "tty", ifname);
	if (!udevice)
		return NULL;

	bus = g_udev_device_get_property (udevice, "ID_BUS");
	if (!g_strcmp0 (bus, "pci"))
		display_bus = g_strdup (_("PCI"));
	else if (!g_strcmp0 (bus, "usb"))
		display_bus = g_strdup (_("USB"));
	else {
		/* Use "" instead of NULL so we can tell later that we've
		 * already tried.
		 */
		display_bus = g_strdup ("");
	}

	g_object_set_data_full (G_OBJECT (device),
	                        BUS_TAG, display_bus,
	                        (GDestroyNotify) g_free);
	if (*display_bus)
		return display_bus;
	else
		return NULL;
}

/**
 * nma_utils_disambiguate_device_names:
 * @devices: (array length=num_devices): a set of #NMDevice
 * @num_devices: length of @devices
 *
 * Generates a list of short-ish unique presentation names for the
 * devices in @devices.
 *
 * Returns: (transfer full) (array zero-terminated=1): the device names
 */
char **
nma_utils_disambiguate_device_names (NMDevice **devices,
                                     int        num_devices)
{
	static const char *subsys[3] = { "net", "tty", NULL };
	GUdevClient *uclient;
	char **names;
	gboolean *duplicates;
	int i;

	names = g_new (char *, num_devices + 1);
	duplicates = g_new (gboolean, num_devices);

	/* Generic device name */
	for (i = 0; i < num_devices; i++)
		names[i] = get_device_generic_type_name_with_iface (devices[i]);
	if (!find_duplicates (names, duplicates, num_devices))
		goto done;

	/* Try specific names (eg, "Ethernet" and "InfiniBand" rather
	 * than "Wired")
	 */
	for (i = 0; i < num_devices; i++) {
		if (duplicates[i]) {
			g_free (names[i]);
			names[i] = get_device_type_name_with_iface (devices[i]);
		}
	}
	if (!find_duplicates (names, duplicates, num_devices))
		goto done;

	/* Try prefixing bus name (eg, "PCI Ethernet" vs "USB Ethernet") */
	uclient = g_udev_client_new (subsys);
	for (i = 0; i < num_devices; i++) {
		if (duplicates[i]) {
			const char *bus = get_bus_name (uclient, devices[i]);
			char *name;

			if (!bus)
				continue;

			g_free (names[i]);
			name = get_device_type_name_with_iface (devices[i]);
			/* Translators: the first %s is a bus name (eg, "USB") or
			 * product name, the second is a device type (eg,
			 * "Ethernet"). You can change this to something like
			 * "%2$s (%1$s)" if there's no grammatical way to combine
			 * the strings otherwise.
			 */
			names[i] = g_strdup_printf (C_("long device name", "%s %s"),
			                            bus, name);
			g_free (name);
		}
	}
	g_object_unref (uclient);
	if (!find_duplicates (names, duplicates, num_devices))
		goto done;

	/* Try prefixing vendor name */
	for (i = 0; i < num_devices; i++) {
		if (duplicates[i]) {
			const char *vendor = nma_utils_get_device_vendor (devices[i]);
			char *name;

			if (!vendor)
				continue;

			g_free (names[i]);
			name = get_device_type_name_with_iface (devices[i]);
			names[i] = g_strdup_printf (C_("long device name", "%s %s"),
			                            vendor,
			                            nma_utils_get_device_type_name (devices[i]));
			g_free (name);
		}
	}
	if (!find_duplicates (names, duplicates, num_devices))
		goto done;

	/* We have multiple identical network cards, so we have to differentiate
	 * them by interface name.
	 */
	for (i = 0; i < num_devices; i++) {
		if (duplicates[i]) {
			const char *interface = nm_device_get_iface (devices[i]);

			if (!interface)
				continue;

			g_free (names[i]);
			names[i] = g_strdup_printf ("%s (%s)",
			                            nma_utils_get_device_type_name (devices[i]),
			                            interface);
		}
	}

 done:
	g_free (duplicates);
	names[num_devices] = NULL;
	return names;
}

/**
 * nma_utils_get_connection_device_name:
 * @connection: an #NMConnection for a virtual device type
 *
 * Returns the name that nma_utils_disambiguate_device_names() would
 * return for the virtual device that would be created for @connection.
 * Eg, "VLAN (eth1.1)".
 *
 * Returns: (transfer full): the name of @connection's device
 */
char *
nma_utils_get_connection_device_name (NMConnection *connection)
{
	const char *iface, *type, *display_type;
	NMSettingConnection *s_con;

	iface = nm_connection_get_virtual_iface_name (connection);
	g_return_val_if_fail (iface != NULL, NULL);

	s_con = nm_connection_get_setting_connection (connection);
	g_return_val_if_fail (s_con != NULL, NULL);
	type = nm_setting_connection_get_connection_type (s_con);

	if (!strcmp (type, NM_SETTING_BOND_SETTING_NAME))
		display_type = _("Bond");
	else if (!strcmp (type, NM_SETTING_TEAM_SETTING_NAME))
		display_type = _("Team");
	else if (!strcmp (type, NM_SETTING_BRIDGE_SETTING_NAME))
		display_type = _("Bridge");
	else if (!strcmp (type, NM_SETTING_VLAN_SETTING_NAME))
		display_type = _("VLAN");
	else {
		g_warning ("Unrecognized virtual device type '%s'", type);
		display_type = type;
	}

	return g_strdup_printf ("%s (%s)", display_type, iface);
}
