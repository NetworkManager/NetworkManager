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
 * SECTION:nmt-connect-connection-list
 * @short_description: Connection list for "nmtui connect"
 *
 * #NmtConnectConnectionList is the list of devices, connections, and
 * access points displayed by "nmtui connect".
 */

#include "config.h"

#include <stdlib.h>

#include <NetworkManager.h>

#include "nmtui.h"
#include "nmt-connect-connection-list.h"

G_DEFINE_TYPE (NmtConnectConnectionList, nmt_connect_connection_list, NMT_TYPE_NEWT_LISTBOX)

#define NMT_CONNECT_CONNECTION_LIST_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_CONNECT_CONNECTION_LIST, NmtConnectConnectionListPrivate))

typedef struct {
	char *name;
	NMDevice *device;

	int sort_order;

	GSList *conns;
} NmtConnectDevice;

typedef struct {
	const char *name;
	char *ssid;

	NMConnection *conn;
	NMAccessPoint *ap;
	NMDevice *device;
	NMActiveConnection *active;
} NmtConnectConnection;

typedef struct {
	GSList *nmt_devices;
} NmtConnectConnectionListPrivate;

/**
 * nmt_connect_connection_list_new:
 *
 * Creates a new #NmtConnectConnectionList
 *
 * Returns: a new #NmtConnectConnectionList
 */
NmtNewtWidget *
nmt_connect_connection_list_new (void)
{
	return g_object_new (NMT_TYPE_CONNECT_CONNECTION_LIST,
	                     "flags", NMT_NEWT_LISTBOX_SCROLL | NMT_NEWT_LISTBOX_BORDER,
	                     "skip-null-keys", TRUE,
	                     NULL);
}

static void
nmt_connect_connection_list_init (NmtConnectConnectionList *list)
{
}

static void
nmt_connect_connection_free (NmtConnectConnection *nmtconn)
{
	g_clear_object (&nmtconn->conn);
	g_clear_object (&nmtconn->ap);
	g_clear_object (&nmtconn->active);
	g_free (nmtconn->ssid);
}

static void
nmt_connect_device_free (NmtConnectDevice *nmtdev)
{
	g_clear_pointer (&nmtdev->name, g_free);
	g_clear_object (&nmtdev->device);

	g_slist_free_full (nmtdev->conns, (GDestroyNotify) nmt_connect_connection_free);
}

static const char *device_sort_order[] = {
	"NMDeviceEthernet",
	"NMDeviceInfiniband",
	"NMDeviceWifi",
	NM_SETTING_VLAN_SETTING_NAME,
	NM_SETTING_BOND_SETTING_NAME,
	NM_SETTING_TEAM_SETTING_NAME,
	NM_SETTING_BRIDGE_SETTING_NAME,
	"NMDeviceModem",
	"NMDeviceBt"
};
static const int device_sort_order_len = G_N_ELEMENTS (device_sort_order);

static int
get_sort_order_for_device (NMDevice *device)
{
	const char *type;
	int i;

	type = G_OBJECT_TYPE_NAME (device);
	for (i = 0; i < device_sort_order_len; i++) {
		if (!strcmp (type, device_sort_order[i]))
			return i;
	}

	return -1;
}

static int
get_sort_order_for_connection (NMConnection *conn)
{
	NMSettingConnection *s_con;
	const char *type;
	int i;

	s_con = nm_connection_get_setting_connection (conn);
	type = nm_setting_connection_get_connection_type (s_con);

	for (i = 0; i < device_sort_order_len; i++) {
		if (!strcmp (type, device_sort_order[i]))
			return i;
	}

	return -1;
}

static int
sort_connections (gconstpointer  a,
                  gconstpointer  b)
{
	NmtConnectConnection *nmta = (NmtConnectConnection *)a;
	NmtConnectConnection *nmtb = (NmtConnectConnection *)b;

	/* If nmta and nmtb both have NMConnections, sort them by timestamp */
	if (nmta->conn && nmtb->conn) {
		NMSettingConnection *s_con_a, *s_con_b;
		guint64 time_a, time_b;

		s_con_a = nm_connection_get_setting_connection (nmta->conn);
		s_con_b = nm_connection_get_setting_connection (nmtb->conn);

		time_a = nm_setting_connection_get_timestamp (s_con_a);
		time_b = nm_setting_connection_get_timestamp (s_con_b);

		return (int) (time_b - time_a);
	}

	/* If one is an NMConnection and the other is an NMAccessPoint, the
	 * connection comes first.
	 */
	if (nmta->conn)
		return -1;
	else if (nmtb->conn)
		return 1;

	g_return_val_if_fail (nmta->ap && nmtb->ap, 0);

	/* If both are access points, then sort by strength */
	return nm_access_point_get_strength (nmtb->ap) - nm_access_point_get_strength (nmta->ap);
}

static void
add_connections_for_device (NmtConnectDevice *nmtdev,
                            const GPtrArray  *connections)
{
	int i;

	for (i = 0; i < connections->len; i++) {
		NMConnection *conn = connections->pdata[i];
		NMSettingConnection *s_con;

		s_con = nm_connection_get_setting_connection (conn);
		if (nm_setting_connection_get_master (s_con))
			continue;

		if (nm_device_connection_valid (nmtdev->device, conn)) {
			NmtConnectConnection *nmtconn = g_slice_new0 (NmtConnectConnection);

			nmtconn->name = nm_connection_get_id (conn);
			nmtconn->device = nmtdev->device;
			nmtconn->conn = g_object_ref (conn);
			nmtdev->conns = g_slist_prepend (nmtdev->conns, nmtconn);
		}
	}
}

/* stolen from nm-applet */
static char *
hash_ap (NMAccessPoint *ap)
{
	unsigned char input[66];
	GBytes *ssid;
	NM80211Mode mode;
	guint32 flags;
	guint32 wpa_flags;
	guint32 rsn_flags;

	memset (&input[0], 0, sizeof (input));

	ssid = nm_access_point_get_ssid (ap);
	if (ssid)
		memcpy (input, g_bytes_get_data (ssid, NULL), g_bytes_get_size (ssid));

	mode = nm_access_point_get_mode (ap);
	if (mode == NM_802_11_MODE_INFRA)
		input[32] |= (1 << 0);
	else if (mode == NM_802_11_MODE_ADHOC)
		input[32] |= (1 << 1);
	else
		input[32] |= (1 << 2);

	/* Separate out no encryption, WEP-only, and WPA-capable */
	flags = nm_access_point_get_flags (ap);
	wpa_flags = nm_access_point_get_wpa_flags (ap);
	rsn_flags = nm_access_point_get_rsn_flags (ap);
	if (  !(flags & NM_802_11_AP_FLAGS_PRIVACY)
	      && (wpa_flags == NM_802_11_AP_SEC_NONE)
	      && (rsn_flags == NM_802_11_AP_SEC_NONE))
		input[32] |= (1 << 3);
	else if (   (flags & NM_802_11_AP_FLAGS_PRIVACY)
	            && (wpa_flags == NM_802_11_AP_SEC_NONE)
	            && (rsn_flags == NM_802_11_AP_SEC_NONE))
		input[32] |= (1 << 4);
	else if (   !(flags & NM_802_11_AP_FLAGS_PRIVACY)
	            &&  (wpa_flags != NM_802_11_AP_SEC_NONE)
	            &&  (rsn_flags != NM_802_11_AP_SEC_NONE))
		input[32] |= (1 << 5);
	else
		input[32] |= (1 << 6);

	/* duplicate it */
	memcpy (&input[33], &input[0], 32);
	return g_compute_checksum_for_data (G_CHECKSUM_MD5, input, sizeof (input));
}

static void
add_connections_for_aps (NmtConnectDevice *nmtdev,
                         const GPtrArray  *connections)
{
	NmtConnectConnection *nmtconn;
	NMConnection *conn;
	NMAccessPoint *ap;
	const GPtrArray *aps;
	GHashTable *seen_ssids;
	GBytes *ssid;
	char *ap_hash;
	int i, c;

	aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (nmtdev->device));
	if (!aps->len)
		return;

	seen_ssids = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	for (i = 0; i < aps->len; i++) {
		ap = aps->pdata[i];

		if (!nm_access_point_get_ssid (ap))
			continue;

		ap_hash = hash_ap (ap);
		if (g_hash_table_contains (seen_ssids, ap_hash)) {
			g_free (ap_hash);
			continue;
		}
		g_hash_table_add (seen_ssids, ap_hash);

		nmtconn = g_slice_new0 (NmtConnectConnection);
		nmtconn->device = nmtdev->device;
		nmtconn->ap = g_object_ref (ap);
		ssid = nm_access_point_get_ssid (ap);
		if (ssid)
			nmtconn->ssid = nm_utils_ssid_to_utf8 (g_bytes_get_data (ssid, NULL),
			                                       g_bytes_get_size (ssid));

		for (c = 0; c < connections->len; c++) {
			conn = connections->pdata[c];
			if (   nm_device_connection_valid (nmtdev->device, conn)
			    && nm_access_point_connection_valid (ap, conn)) {
				nmtconn->name = nm_connection_get_id (conn);
				nmtconn->conn = g_object_ref (conn);
				break;
			}
		}

		if (!nmtconn->name)
			nmtconn->name = nmtconn->ssid ? nmtconn->ssid : "<unknown>";

		nmtdev->conns = g_slist_prepend (nmtdev->conns, nmtconn);
	}

	g_hash_table_unref (seen_ssids);
}

static GSList *
append_nmt_devices_for_devices (GSList           *nmt_devices,
                                const GPtrArray  *devices,
                                char            **names,
                                const GPtrArray  *connections)
{
	NmtConnectDevice *nmtdev;
	NMDevice *device;
	int i, sort_order;

	for (i = 0; i < devices->len; i++) {
		device = devices->pdata[i];

		sort_order = get_sort_order_for_device (device);
		if (sort_order == -1)
			continue;

		nmtdev = g_slice_new0 (NmtConnectDevice);
		nmtdev->name = g_strdup (names[i]);
		nmtdev->device = g_object_ref (device);
		nmtdev->sort_order = sort_order;

		if (NM_IS_DEVICE_WIFI (device))
			add_connections_for_aps (nmtdev, connections);
		else
			add_connections_for_device (nmtdev, connections);
		nmtdev->conns = g_slist_sort (nmtdev->conns, sort_connections);

		nmt_devices = g_slist_prepend (nmt_devices, nmtdev);
	}

	return nmt_devices;
}

static GSList *
append_nmt_devices_for_virtual_devices (GSList          *nmt_devices,
                                        const GPtrArray *connections)
{
	NmtConnectDevice *nmtdev = NULL;
	int i;
	GHashTable *devices_by_name;
	char *name;
	NMConnection *conn;
	NmtConnectConnection *nmtconn;
	int sort_order;

	devices_by_name = g_hash_table_new (g_str_hash, g_str_equal);

	for (i = 0; i < connections->len; i++) {
		conn = connections->pdata[i];
		sort_order = get_sort_order_for_connection (conn);
		if (sort_order == -1)
			continue;

		name = nm_connection_get_virtual_device_description (conn);
		if (name)
			nmtdev = g_hash_table_lookup (devices_by_name, name);
		if (nmtdev)
			g_free (name);
		else {
			nmtdev = g_slice_new0 (NmtConnectDevice);
			nmtdev->name = name ? name : g_strdup ("Unknown");
			nmtdev->sort_order = sort_order;

			g_hash_table_insert (devices_by_name, nmtdev->name, nmtdev);
			nmt_devices = g_slist_prepend (nmt_devices, nmtdev);
		}

		nmtconn = g_slice_new0 (NmtConnectConnection);
		nmtconn->name = nm_connection_get_id (conn);
		nmtconn->conn = g_object_ref (conn);

		nmtdev->conns = g_slist_insert_sorted (nmtdev->conns, nmtconn, sort_connections);
	}

	g_hash_table_destroy (devices_by_name);
	return nmt_devices;
}

static GSList *
append_nmt_devices_for_vpns (GSList          *nmt_devices,
                             const GPtrArray *connections)
{
	NmtConnectDevice *nmtdev;
	int i;
	NMConnection *conn;
	NmtConnectConnection *nmtconn;

	nmtdev = g_slice_new0 (NmtConnectDevice);
	nmtdev->name = g_strdup (_("VPN"));
	nmtdev->sort_order = 100;

	for (i = 0; i < connections->len; i++) {
		conn = connections->pdata[i];
		if (!nm_connection_is_type (conn, NM_SETTING_VPN_SETTING_NAME))
			continue;

		nmtconn = g_slice_new0 (NmtConnectConnection);
		nmtconn->name = nm_connection_get_id (conn);
		nmtconn->conn = g_object_ref (conn);

		nmtdev->conns = g_slist_insert_sorted (nmtdev->conns, nmtconn, sort_connections);
	}

	if (nmtdev->conns)
		nmt_devices = g_slist_prepend (nmt_devices, nmtdev);
	else
		nmt_connect_device_free (nmtdev);

	return nmt_devices;
}

static int
sort_nmt_devices (gconstpointer  a,
                  gconstpointer  b)
{
	NmtConnectDevice *nmta = (NmtConnectDevice *)a;
	NmtConnectDevice *nmtb = (NmtConnectDevice *)b;

	if (nmta->sort_order != nmtb->sort_order)
		return nmta->sort_order - nmtb->sort_order;

	return strcmp (nmta->name, nmtb->name);
}

static NMActiveConnection *
connection_find_ac (NMConnection    *conn,
                    const GPtrArray *acs)
{
	NMActiveConnection *ac;
	NMRemoteConnection *ac_conn;
	int i;

	for (i = 0; i < acs->len; i++) {
		ac = acs->pdata[i];
		ac_conn = nm_active_connection_get_connection (ac);

		if (conn == NM_CONNECTION (ac_conn))
			return ac;
	}

	return NULL;
}

static void
nmt_connect_connection_list_rebuild (NmtConnectConnectionList *list)
{
	NmtConnectConnectionListPrivate *priv = NMT_CONNECT_CONNECTION_LIST_GET_PRIVATE (list);
	NmtNewtListbox *listbox = NMT_NEWT_LISTBOX (list);
	const GPtrArray *devices, *acs, *connections;
	int max_width;
	char **names, *row, active_col;
	const char *strength_col;
	GSList *nmt_devices, *diter, *citer;
	NmtConnectDevice *nmtdev;
	NmtConnectConnection *nmtconn;

	g_slist_free_full (priv->nmt_devices, (GDestroyNotify) nmt_connect_device_free);
	priv->nmt_devices = NULL;
	nmt_newt_listbox_clear (listbox);

	devices = nm_client_get_devices (nm_client);
	acs = nm_client_get_active_connections (nm_client);
	connections = nm_client_get_connections (nm_client);

	nmt_devices = NULL;

	names = nm_device_disambiguate_names ((NMDevice **) devices->pdata, devices->len);
	nmt_devices = append_nmt_devices_for_devices (nmt_devices, devices, names, connections);
	g_strfreev (names);

	nmt_devices = append_nmt_devices_for_virtual_devices (nmt_devices, connections);
	nmt_devices = append_nmt_devices_for_vpns (nmt_devices, connections);

	nmt_devices = g_slist_sort (nmt_devices, sort_nmt_devices);

	max_width = 0;
	for (diter = nmt_devices; diter; diter = diter->next) {
		nmtdev = diter->data;
		for (citer = nmtdev->conns; citer; citer = citer->next) {
			nmtconn = citer->data;

			max_width = MAX (max_width, nmt_newt_text_width (nmtconn->name));
		}
	}

	for (diter = nmt_devices; diter; diter = diter->next) {
		nmtdev = diter->data;

		if (nmtdev->conns) {
			if (diter != nmt_devices)
				nmt_newt_listbox_append (listbox, "", NULL);
			nmt_newt_listbox_append (listbox, nmtdev->name, NULL);
		}

		for (citer = nmtdev->conns; citer; citer = citer->next) {
			nmtconn = citer->data;

			if (nmtconn->conn)
				nmtconn->active = connection_find_ac (nmtconn->conn, acs);
			if (nmtconn->active) {
				g_object_ref (nmtconn->active);
				active_col = '*';
			} else
				active_col = ' ';

			if (nmtconn->ap) {
				guint8 strength = nm_access_point_get_strength (nmtconn->ap);

				strength_col = nm_utils_wifi_strength_bars (strength);
			} else
				strength_col = NULL;

			row = g_strdup_printf ("%c %s%-*s%s%s",
			                       active_col,
			                       nmtconn->name,
			                       (int)(max_width - nmt_newt_text_width (nmtconn->name)), "",
			                       strength_col ? " " : "",
			                       strength_col ? strength_col : "");

			nmt_newt_listbox_append (listbox, row, nmtconn);
			g_free (row);
		}
	}

	priv->nmt_devices = nmt_devices;

	g_object_notify (G_OBJECT (listbox), "active");
	g_object_notify (G_OBJECT (listbox), "active-key");
}

static void
rebuild_on_property_changed (GObject    *object,
                             GParamSpec *spec,
                             gpointer    list)
{
	nmt_connect_connection_list_rebuild (list);
}

static void
nmt_connect_connection_list_constructed (GObject *object)
{
	NmtConnectConnectionList *list = NMT_CONNECT_CONNECTION_LIST (object);

	g_signal_connect (nm_client, "notify::" NM_CLIENT_ACTIVE_CONNECTIONS,
	                  G_CALLBACK (rebuild_on_property_changed), list);
	g_signal_connect (nm_client, "notify::" NM_CLIENT_CONNECTIONS,
	                  G_CALLBACK (rebuild_on_property_changed), list);
	g_signal_connect (nm_client, "notify::" NM_CLIENT_DEVICES,
	                  G_CALLBACK (rebuild_on_property_changed), list);

	nmt_connect_connection_list_rebuild (list);

	G_OBJECT_CLASS (nmt_connect_connection_list_parent_class)->constructed (object);
}

static void
nmt_connect_connection_list_finalize (GObject *object)
{
	NmtConnectConnectionListPrivate *priv = NMT_CONNECT_CONNECTION_LIST_GET_PRIVATE (object);

	g_slist_free_full (priv->nmt_devices, (GDestroyNotify) nmt_connect_device_free);

	g_signal_handlers_disconnect_by_func (nm_client, G_CALLBACK (rebuild_on_property_changed), object);

	G_OBJECT_CLASS (nmt_connect_connection_list_parent_class)->finalize (object);
}

static void
nmt_connect_connection_list_class_init (NmtConnectConnectionListClass *list_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (list_class);

	g_type_class_add_private (list_class, sizeof (NmtConnectConnectionListPrivate));

	/* virtual methods */
	object_class->constructed  = nmt_connect_connection_list_constructed;
	object_class->finalize     = nmt_connect_connection_list_finalize;
}

/**
 * nmt_connect_connection_list_get_connection:
 * @list: an #NmtConnectConnectionList
 * @identifier: a connection ID or UUID, or device name
 * @connection: (out) (transfer none): the #NMConnection to be activated
 * @device: (out) (transfer none): the #NMDevice to activate @connection on
 * @specific_object: (out) (transfer none): the "specific object" to connect to
 * @active: (out) (transfer none): the #NMActiveConnection corresponding
 *   to the selection, if any.
 *
 * Gets information about the indicated connection.
 *
 * Returns: %TRUE if there was a match, %FALSE if not.
 */
gboolean
nmt_connect_connection_list_get_connection (NmtConnectConnectionList  *list,
                                            const char                *identifier,
                                            NMConnection             **connection,
                                            NMDevice                 **device,
                                            NMObject                 **specific_object,
                                            NMActiveConnection       **active)
{
	NmtConnectConnectionListPrivate *priv = NMT_CONNECT_CONNECTION_LIST_GET_PRIVATE (list);
	GSList *diter, *citer;
	NmtConnectDevice *nmtdev;
	NmtConnectConnection *nmtconn = NULL;
	NMConnection *conn = NULL;

	g_return_val_if_fail (identifier, FALSE);

	if (nm_utils_is_uuid (identifier))
		conn = NM_CONNECTION (nm_client_get_connection_by_uuid (nm_client, identifier));
	if (!conn)
		conn = NM_CONNECTION (nm_client_get_connection_by_id (nm_client, identifier));

	for (diter = priv->nmt_devices; diter; diter = diter->next) {
		nmtdev = diter->data;
		if (!nmtdev->conns)
			continue;

		for (citer = nmtdev->conns; citer; citer = citer->next) {
			nmtconn = citer->data;
			if (conn) {
				if (conn == nmtconn->conn)
					goto found;
			} else if (nmtconn->ssid && !strcmp (identifier, nmtconn->ssid))
				goto found;
		}

		if (!conn && nmtdev->device && !strcmp (identifier, nm_device_get_ip_iface (nmtdev->device))) {
			nmtconn = nmtdev->conns->data;
			goto found;
		}
	}

	return FALSE;

 found:
	if (connection)
		*connection = nmtconn->conn;
	if (device)
		*device = nmtconn->device;
	if (specific_object)
		*specific_object = NM_OBJECT (nmtconn->ap);
	if (active)
		*active = nmtconn->active;

	return TRUE;
}

/**
 * nmt_connect_connection_list_get_selection:
 * @list: an #NmtConnectConnectionList
 * @connection: (out) (transfer none): the #NMConnection to be activated
 * @device: (out) (transfer none): the #NMDevice to activate @connection on
 * @specific_object: (out) (transfer none): the "specific object" to connect to
 * @active: (out) (transfer none): the #NMActiveConnection corresponding
 *   to the selection, if any.
 *
 * Gets information about the selected row.
 *
 * Returns: %TRUE if there is a selection, %FALSE if not.
 */
gboolean
nmt_connect_connection_list_get_selection (NmtConnectConnectionList  *list,
                                           NMConnection             **connection,
                                           NMDevice                 **device,
                                           NMObject                 **specific_object,
                                           NMActiveConnection       **active)
{
	NmtConnectConnection *nmtconn;

	nmtconn = nmt_newt_listbox_get_active_key (NMT_NEWT_LISTBOX (list));
	if (!nmtconn)
		return FALSE;

	if (connection)
		*connection = nmtconn->conn;
	if (device)
		*device = nmtconn->device;
	if (specific_object)
		*specific_object = NM_OBJECT (nmtconn->ap);
	if (active)
		*active = nmtconn->active;

	return TRUE;
}
