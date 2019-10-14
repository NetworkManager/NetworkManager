// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmt-page-ethernet
 * @short_description: The editor page for Ethernet connections
 */

#include "nm-default.h"

#include "nmt-page-ethernet.h"
#include "nmt-mac-entry.h"
#include "nmt-mtu-entry.h"

G_DEFINE_TYPE (NmtPageEthernet, nmt_page_ethernet, NMT_TYPE_EDITOR_PAGE_DEVICE)

NmtEditorPage *
nmt_page_ethernet_new (NMConnection   *conn,
                       NmtDeviceEntry *deventry)
{
	return g_object_new (NMT_TYPE_PAGE_ETHERNET,
	                     "connection", conn,
	                     "device-entry", deventry,
	                     NULL);
}

static void
nmt_page_ethernet_init (NmtPageEthernet *ethernet)
{
}

static void
nmt_page_ethernet_constructed (GObject *object)
{
	NmtPageEthernet *ethernet = NMT_PAGE_ETHERNET (object);
	NmtDeviceEntry *deventry;
	NmtEditorSection *section;
	NmtEditorGrid *grid;
	NMSettingWired *s_wired;
	NmtNewtWidget *widget;
	NMConnection *conn;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (ethernet));
	s_wired = nm_connection_get_setting_wired (conn);
	if (!s_wired) {
		nm_connection_add_setting (conn, nm_setting_wired_new ());
		s_wired = nm_connection_get_setting_wired (conn);
	}

	deventry = nmt_editor_page_device_get_device_entry (NMT_EDITOR_PAGE_DEVICE (object));
	g_object_bind_property (s_wired, NM_SETTING_WIRED_MAC_ADDRESS,
	                        deventry, "mac-address",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);

	section = nmt_editor_section_new (_("ETHERNET"), NULL, FALSE);
	grid = nmt_editor_section_get_body (section);

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

	nmt_editor_page_add_section (NMT_EDITOR_PAGE (ethernet), section);

	G_OBJECT_CLASS (nmt_page_ethernet_parent_class)->constructed (object);
}

static void
nmt_page_ethernet_class_init (NmtPageEthernetClass *ethernet_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ethernet_class);

	object_class->constructed = nmt_page_ethernet_constructed;
}
