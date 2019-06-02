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
 * SECTION:nmt-page-infiniband
 * @short_description: The editor page for InfiniBand connections
 */

#include "nm-default.h"

#include "nmt-page-infiniband.h"
#include "nmt-mtu-entry.h"

G_DEFINE_TYPE (NmtPageInfiniband, nmt_page_infiniband, NMT_TYPE_EDITOR_PAGE_DEVICE)

NmtEditorPage *
nmt_page_infiniband_new (NMConnection   *conn,
                         NmtDeviceEntry *deventry)
{
	return g_object_new (NMT_TYPE_PAGE_INFINIBAND,
	                     "connection", conn,
	                     "device-entry", deventry,
	                     NULL);
}

static void
nmt_page_infiniband_init (NmtPageInfiniband *infiniband)
{
}

static NmtNewtPopupEntry transport_mode[] = {
	{ N_("Datagram"),  "datagram" },
	{ N_("Connected"), "connected" },
	{ NULL, NULL }
};

static void
nmt_page_infiniband_constructed (GObject *object)
{
	NmtPageInfiniband *infiniband = NMT_PAGE_INFINIBAND (object);
	NmtDeviceEntry *deventry;
	NmtEditorSection *section;
	NmtEditorGrid *grid;
	NMSettingInfiniband *s_ib;
	NmtNewtWidget *widget;
	NMConnection *conn;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (infiniband));
	s_ib = nm_connection_get_setting_infiniband (conn);
	if (!s_ib) {
		nm_connection_add_setting (conn, nm_setting_infiniband_new ());
		s_ib = nm_connection_get_setting_infiniband (conn);
	}
	/* initialize 'transport-mode' if it is NULL */
	if (!nm_setting_infiniband_get_transport_mode (s_ib)) {
		g_object_set (G_OBJECT (s_ib),
		              NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram",
		              NULL);
	}

	deventry = nmt_editor_page_device_get_device_entry (NMT_EDITOR_PAGE_DEVICE (object));
	g_object_bind_property (s_ib, NM_SETTING_INFINIBAND_MAC_ADDRESS,
	                        deventry, "mac-address",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);

	section = nmt_editor_section_new (_("INFINIBAND"), NULL, TRUE);
	grid = nmt_editor_section_get_body (section);

	widget = nmt_newt_popup_new (transport_mode);
	g_object_bind_property (s_ib, NM_SETTING_INFINIBAND_TRANSPORT_MODE,
	                        widget, "active-id",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Transport mode"), widget, NULL);

	widget = nmt_mtu_entry_new ();
	g_object_bind_property (s_ib, NM_SETTING_INFINIBAND_MTU,
	                        widget, "mtu",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("MTU"), widget, NULL);

	nmt_editor_page_add_section (NMT_EDITOR_PAGE (infiniband), section);

	G_OBJECT_CLASS (nmt_page_infiniband_parent_class)->constructed (object);
}

static void
nmt_page_infiniband_class_init (NmtPageInfinibandClass *infiniband_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (infiniband_class);

	object_class->constructed = nmt_page_infiniband_constructed;
}
