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
 * SECTION:nmt-page-vlan
 * @short_description: The editor page for VLAN connections
 */

#include "nm-default.h"

#include "nm-editor-bindings.h"

#include "nmt-page-vlan.h"
#include "nmt-device-entry.h"
#include "nmt-mac-entry.h"
#include "nmt-mtu-entry.h"

G_DEFINE_TYPE (NmtPageVlan, nmt_page_vlan, NMT_TYPE_EDITOR_PAGE_DEVICE)

NmtEditorPage *
nmt_page_vlan_new (NMConnection   *conn,
                   NmtDeviceEntry *deventry)
{
	return g_object_new (NMT_TYPE_PAGE_VLAN,
	                     "connection", conn,
	                     "device-entry", deventry,
	                     NULL);
}

static void
nmt_page_vlan_init (NmtPageVlan *vlan)
{
}

static gboolean
vlan_device_filter (NmtDeviceEntry *deventry,
                    NMDevice       *device,
                    gpointer        user_data)
{
	// FIXME
	return NM_IS_DEVICE_ETHERNET (device);
}

static void
nmt_page_vlan_constructed (GObject *object)
{
	NmtPageVlan *vlan = NMT_PAGE_VLAN (object);
	NmtEditorSection *section;
	NmtEditorGrid *grid;
	NMSettingWired *s_wired;
	NMSettingVlan *s_vlan;
	NmtNewtWidget *widget, *parent, *id_entry;
	NMConnection *conn;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (vlan));
	s_vlan = nm_connection_get_setting_vlan (conn);
	if (!s_vlan) {
		nm_connection_add_setting (conn, nm_setting_vlan_new ());
		s_vlan = nm_connection_get_setting_vlan (conn);
	}
	s_wired = nm_connection_get_setting_wired (conn);
	if (!s_wired) {
		nm_connection_add_setting (conn, nm_setting_wired_new ());
		s_wired = nm_connection_get_setting_wired (conn);
	}

	section = nmt_editor_section_new (_("VLAN"), NULL, TRUE);
	grid = nmt_editor_section_get_body (section);

	nm_editor_bind_vlan_name (s_vlan, nm_connection_get_setting_connection (conn));

	widget = parent = nmt_device_entry_new (_("Parent"), 40, G_TYPE_NONE);
	nmt_device_entry_set_device_filter (NMT_DEVICE_ENTRY (widget),
	                                    vlan_device_filter, vlan);
	g_object_bind_property (s_vlan, NM_SETTING_VLAN_PARENT,
	                        widget, "interface-name",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	g_object_bind_property (s_wired, NM_SETTING_WIRED_MAC_ADDRESS,
	                        widget, "mac-address",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	widget = id_entry = nmt_newt_entry_numeric_new (8, 0, 4094);
	g_object_bind_property (s_vlan, NM_SETTING_VLAN_ID,
	                        widget, "text",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("VLAN id"), widget, NULL);

	nmt_editor_grid_append (grid, NULL, nmt_newt_separator_new (), NULL);

	widget = nmt_mac_entry_new (40, ETH_ALEN, NMT_MAC_ENTRY_TYPE_CLONED);
	g_object_bind_property (s_wired, NM_SETTING_WIRED_CLONED_MAC_ADDRESS,
	                        widget, "mac-address",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Cloned MAC address"), widget, NULL);

	widget = nmt_mtu_entry_new ();
	g_object_bind_property (s_wired, NM_SETTING_WIRED_MTU,
	                        widget, "mtu",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("MTU"), widget, NULL);

	nmt_editor_page_add_section (NMT_EDITOR_PAGE (vlan), section);

	G_OBJECT_CLASS (nmt_page_vlan_parent_class)->constructed (object);
}

static void
nmt_page_vlan_class_init (NmtPageVlanClass *vlan_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (vlan_class);

	/* virtual methods */
	object_class->constructed = nmt_page_vlan_constructed;
}
