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
 * Copyright 2016 Red Hat, Inc.
 */
/**
 * SECTION:nmt-page-ip_tunnel
 * @short_description: The editor page for IP tunnel connections
 */

#include "nm-default.h"

#include "nmt-page-ip-tunnel.h"

#include "nmt-device-entry.h"
#include "nmt-mtu-entry.h"

G_DEFINE_TYPE (NmtPageIPTunnel, nmt_page_ip_tunnel, NMT_TYPE_EDITOR_PAGE_DEVICE)

#define NMT_PAGE_IP_TUNNEL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_PAGE_IP_TUNNEL, NmtPageIPTunnelPrivate))

typedef struct {
	NmtNewtEntry *input_key;
	NmtNewtEntry *output_key;
} NmtPageIPTunnelPrivate;

NmtEditorPage *
nmt_page_ip_tunnel_new (NMConnection   *conn,
                        NmtDeviceEntry *deventry)
{
	return g_object_new (NMT_TYPE_PAGE_IP_TUNNEL,
	                     "connection", conn,
	                     "device-entry", deventry,
	                     NULL);
}

static void
nmt_page_ip_tunnel_init (NmtPageIPTunnel *ip_tunnel)
{
}

static void
mode_changed (GObject    *object,
              GParamSpec *pspec,
              gpointer    user_data)
{
	NMSettingIPTunnel *s_ip_tunnel = NM_SETTING_IP_TUNNEL (object);
	NmtPageIPTunnel *ip_tunnel = NMT_PAGE_IP_TUNNEL (user_data);
	NmtPageIPTunnelPrivate *priv = NMT_PAGE_IP_TUNNEL_GET_PRIVATE (ip_tunnel);
	NMIPTunnelMode mode;
	gboolean enable_keys;

	mode = nm_setting_ip_tunnel_get_mode (s_ip_tunnel);
	enable_keys = NM_IN_SET (mode, NM_IP_TUNNEL_MODE_GRE, NM_IP_TUNNEL_MODE_IP6GRE);
	nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->input_key), enable_keys);
	nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->output_key), enable_keys);

	if (!enable_keys) {
		nmt_newt_entry_set_text (priv->input_key, "");
		nmt_newt_entry_set_text (priv->output_key, "");
	}
}

static NmtNewtPopupEntry tunnel_mode[] = {
	/* The order must match the NM_IP_TUNNEL_MODE_* enum */
	{ N_("IPIP"),   "IPIP" },
	{ N_("GRE"),    "GRE" },
	{ N_("SIT"),    "SIT" },
	{ N_("ISATAP"), "ISATAP" },
	{ N_("VTI"),    "VTI" },
	{ N_("IP6IP6"), "IP6IP6" },
	{ N_("IPIP6"),  "IPIP6" },
	{ N_("IP6GRE"), "IP6GRE" },
	{ N_("VTI6"),   "VTI6" },
	{ NULL, NULL }
};

static gboolean
add_offset (GBinding     *binding,
            const GValue *from_value,
            GValue       *to_value,
            gpointer      user_data)
{
	guint v;
	int offset = GPOINTER_TO_INT (user_data);

	g_return_val_if_fail (G_VALUE_HOLDS (from_value, G_TYPE_UINT), FALSE);
	g_return_val_if_fail (G_VALUE_HOLDS (to_value, G_TYPE_UINT), FALSE);

	v = g_value_get_uint (from_value);
	v += offset;

	g_value_set_uint (to_value, v);

	return TRUE;
}

static void
nmt_page_ip_tunnel_constructed (GObject *object)
{
	NmtPageIPTunnel *ip_tunnel = NMT_PAGE_IP_TUNNEL (object);
	NmtPageIPTunnelPrivate *priv = NMT_PAGE_IP_TUNNEL_GET_PRIVATE (ip_tunnel);
	NmtEditorSection *section;
	NmtEditorGrid *grid;
	NMSettingIPTunnel *s_ip_tunnel;
	NmtNewtWidget *widget, *parent;
	NMConnection *conn;
	GClosure *s2w, *w2s;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (ip_tunnel));
	s_ip_tunnel = nm_connection_get_setting_ip_tunnel (conn);
	if (!s_ip_tunnel) {
		nm_connection_add_setting (conn, nm_setting_ip_tunnel_new ());
		s_ip_tunnel = nm_connection_get_setting_ip_tunnel (conn);
	}

	/* Initialize the mode for new connections */
	if (nm_setting_ip_tunnel_get_mode (s_ip_tunnel) == NM_IP_TUNNEL_MODE_UNKNOWN) {
		g_object_set (s_ip_tunnel,
		              NM_SETTING_IP_TUNNEL_MODE, (guint) NM_IP_TUNNEL_MODE_IPIP,
		              NULL);
	}

	section = nmt_editor_section_new (_("IP tunnel"), NULL, TRUE);
	grid = nmt_editor_section_get_body (section);

	/* To convert between widget index (0-based) and setting index (1-based) */
	s2w = g_cclosure_new (G_CALLBACK (add_offset), GINT_TO_POINTER (-1), NULL);
	w2s = g_cclosure_new (G_CALLBACK (add_offset), GINT_TO_POINTER (1), NULL);

	widget = nmt_newt_popup_new (tunnel_mode);
	g_object_bind_property_with_closures (s_ip_tunnel, NM_SETTING_IP_TUNNEL_MODE,
	                        widget, "active",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE,
	                        s2w, w2s);
	nmt_editor_grid_append (grid, _("Mode"), widget, NULL);

	widget = parent = nmt_device_entry_new (_("Parent"), 40, G_TYPE_NONE);
	g_object_bind_property (s_ip_tunnel, NM_SETTING_IP_TUNNEL_PARENT,
	                        widget, "interface-name",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, NULL, widget, NULL);

	widget = nmt_newt_entry_new (40, 0);
	nmt_editor_grid_append (grid, _("Local IP"), widget, NULL);
	g_object_bind_property (s_ip_tunnel, NM_SETTING_IP_TUNNEL_LOCAL,
	                        widget, "text",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

	widget = nmt_newt_entry_new (40, 0);
	nmt_editor_grid_append (grid, _("Remote IP"), widget, NULL);
	g_object_bind_property (s_ip_tunnel, NM_SETTING_IP_TUNNEL_REMOTE,
	                        widget, "text",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

	widget = nmt_newt_entry_new (40, 0);
	nmt_editor_grid_append (grid, _("Input key"), widget, NULL);
	g_object_bind_property (s_ip_tunnel, NM_SETTING_IP_TUNNEL_INPUT_KEY,
	                        widget, "text",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
	priv->input_key = NMT_NEWT_ENTRY (widget);

	widget = nmt_newt_entry_new (40, 0);
	nmt_editor_grid_append (grid, _("Output key"), widget, NULL);
	g_object_bind_property (s_ip_tunnel, NM_SETTING_IP_TUNNEL_OUTPUT_KEY,
	                        widget, "text",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
	priv->output_key = NMT_NEWT_ENTRY (widget);

	widget = nmt_mtu_entry_new ();
	g_object_bind_property (s_ip_tunnel, NM_SETTING_IP_TUNNEL_MTU,
	                        widget, "mtu",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("MTU"), widget, NULL);

	g_signal_connect (s_ip_tunnel, "notify::" NM_SETTING_IP_TUNNEL_MODE,
	                  G_CALLBACK (mode_changed), ip_tunnel);
	mode_changed (G_OBJECT (s_ip_tunnel), NULL, ip_tunnel);

	nmt_editor_page_add_section (NMT_EDITOR_PAGE (ip_tunnel), section);

	G_OBJECT_CLASS (nmt_page_ip_tunnel_parent_class)->constructed (object);
}

static void
nmt_page_ip_tunnel_class_init (NmtPageIPTunnelClass *ip_tunnel_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ip_tunnel_class);

	g_type_class_add_private (ip_tunnel_class, sizeof (NmtPageIPTunnelPrivate));

	/* virtual methods */
	object_class->constructed = nmt_page_ip_tunnel_constructed;
}
