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
 * SECTION:nmt-page-bond
 * @short_description: The editor page for Bond connections
 *
 * Note that this is fairly different from most of the other editor
 * pages, because #NMSettingBond doesn't have properties, so we
 * can't just use #GBinding.
 */

#include "nm-default.h"

#include "nmt-page-bond.h"

#include "nmt-mac-entry.h"
#include "nmt-address-list.h"
#include "nmt-slave-list.h"

G_DEFINE_TYPE (NmtPageBond, nmt_page_bond, NMT_TYPE_EDITOR_PAGE_DEVICE)

#define NMT_PAGE_BOND_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_PAGE_BOND, NmtPageBondPrivate))

typedef enum {
	NMT_PAGE_BOND_MONITORING_UNKNOWN = -1,
	NMT_PAGE_BOND_MONITORING_MII = 0,
	NMT_PAGE_BOND_MONITORING_ARP = 1,
} NmtPageBondMonitoringMode;

typedef struct {
	NmtSlaveList *slaves;

	NmtNewtPopup *mode;
	NmtNewtEntry *primary;
	NmtNewtPopup *monitoring;
	NmtNewtEntry *miimon;
	NmtNewtEntry *updelay;
	NmtNewtEntry *downdelay;
	NmtNewtEntry *arp_interval;
	NmtAddressList *arp_ip_target;

	NmtPageBondMonitoringMode monitoring_mode;

	NMSettingBond *s_bond;
	GType slave_type;
	gboolean updating;
} NmtPageBondPrivate;

NmtEditorPage *
nmt_page_bond_new (NMConnection   *conn,
                   NmtDeviceEntry *deventry)
{
	return g_object_new (NMT_TYPE_PAGE_BOND,
	                     "connection", conn,
	                     "device-entry", deventry,
	                     NULL);
}

static void
nmt_page_bond_init (NmtPageBond *bond)
{
	NmtPageBondPrivate *priv = NMT_PAGE_BOND_GET_PRIVATE (bond);

	priv->monitoring_mode = NMT_PAGE_BOND_MONITORING_UNKNOWN;
	priv->slave_type = G_TYPE_NONE;
}

static NmtNewtPopupEntry bond_mode[] = {
	{ N_("Round-robin"),                            "balance-rr" },
	{ N_("Active Backup"),                          "active-backup" },
	{ N_("XOR"),                                    "balance-xor" },
	{ N_("Broadcast"),                              "broadcast" },
	{ N_("802.3ad"),                                "802.3ad" },
	{ N_("Adaptive Transmit Load Balancing (tlb)"), "balance-tlb" },
	{ N_("Adaptive Load Balancing (alb)"),          "balance-alb" },
	{ NULL, NULL }
};

/* NB: the ordering/numbering here corresponds to NmtPageBondMonitoringMode */
static NmtNewtPopupEntry bond_monitoring[] = {
	{ N_("MII (recommended)"), "mii" },
	{ N_("ARP"),               "arp" },
	{ NULL, NULL }
};

static void
bond_options_changed (GObject    *object,
                      GParamSpec *pspec,
                      gpointer    user_data)
{
	NMSettingBond *s_bond = NM_SETTING_BOND (object);
	NmtPageBond *bond = NMT_PAGE_BOND (user_data);
	NmtPageBondPrivate *priv = NMT_PAGE_BOND_GET_PRIVATE (bond);
	const char *val;
	char **ips;

	if (priv->updating)
		return;

	priv->updating = TRUE;

	val = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_MODE);
	nmt_newt_popup_set_active_id (priv->mode, val);

	if (!strcmp (val, "active-backup")) {
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->primary), TRUE);
		val = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_PRIMARY);
		nmt_newt_entry_set_text (priv->primary, val);
	} else
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->primary), FALSE);

	if (priv->monitoring_mode == NMT_PAGE_BOND_MONITORING_UNKNOWN) {
		val = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL);
		if (val && strcmp (val, "0") != 0)
			priv->monitoring_mode = NMT_PAGE_BOND_MONITORING_ARP;
		else
			priv->monitoring_mode = NMT_PAGE_BOND_MONITORING_MII;
	}
	nmt_newt_popup_set_active (priv->monitoring, priv->monitoring_mode);

	if (priv->monitoring_mode == NMT_PAGE_BOND_MONITORING_MII) {
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->miimon), TRUE);
		val = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_MIIMON);
		nmt_newt_entry_set_text (priv->miimon, val);

		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->updelay), TRUE);
		val = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_UPDELAY);
		nmt_newt_entry_set_text (priv->updelay, val);

		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->downdelay), TRUE);
		val = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY);
		nmt_newt_entry_set_text (priv->downdelay, val);

		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->arp_interval), FALSE);
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->arp_ip_target), FALSE);
	} else {
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->arp_interval), TRUE);
		val = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL);
		nmt_newt_entry_set_text (priv->arp_interval, val);

		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->arp_ip_target), TRUE);
		val = nm_setting_bond_get_option_by_name (s_bond, NM_SETTING_BOND_OPTION_ARP_IP_TARGET);
		ips = g_strsplit (val, ",", -1);
		g_object_set (G_OBJECT (priv->arp_ip_target),
		              "strings", ips,
		              NULL);
		g_strfreev (ips);

		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->miimon), FALSE);
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->updelay), FALSE);
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->downdelay), FALSE);
	}

	priv->updating = FALSE;
}

static void
slaves_changed (GObject    *object,
                GParamSpec *pspec,
                gpointer    user_data)
{
	NmtPageBond *bond = NMT_PAGE_BOND (user_data);
	NmtPageBondPrivate *priv = NMT_PAGE_BOND_GET_PRIVATE (bond);
	GPtrArray *slaves;

	g_object_get (object, "connections", &slaves, NULL);
	if (slaves->len == 0) {
		if (priv->slave_type == G_TYPE_NONE)
			return;
		priv->slave_type = G_TYPE_NONE;
	} else {
		NMConnection *slave = slaves->pdata[0];

		if (priv->slave_type != G_TYPE_NONE)
			return;

		if (nm_connection_is_type (slave, NM_SETTING_INFINIBAND_SETTING_NAME))
			priv->slave_type = NM_TYPE_SETTING_INFINIBAND;
		else
			priv->slave_type = NM_TYPE_SETTING_WIRED;
	}

	if (priv->slave_type == NM_TYPE_SETTING_INFINIBAND) {
		nmt_newt_popup_set_active_id (priv->mode, "active-backup");
		nmt_newt_component_set_sensitive (NMT_NEWT_COMPONENT (priv->mode), FALSE);
	} else
		nmt_newt_component_set_sensitive (NMT_NEWT_COMPONENT (priv->mode), TRUE);
}

#define WIDGET_CHANGED_FUNC(widget, func, option)							\
static void																	\
widget ## _widget_changed (GObject    *object,								\
                           GParamSpec *pspec,								\
                           gpointer    user_data)							\
{																			\
	NmtPageBond *bond = NMT_PAGE_BOND (user_data);							\
	NmtPageBondPrivate *priv = NMT_PAGE_BOND_GET_PRIVATE (bond);			\
																			\
	if (priv->updating)														\
		return;																\
																			\
	priv->updating = TRUE;													\
	nm_setting_bond_add_option (priv->s_bond, option, func (priv->widget));	\
	priv->updating = FALSE;													\
}

WIDGET_CHANGED_FUNC (primary, nmt_newt_entry_get_text, NM_SETTING_BOND_OPTION_PRIMARY)
WIDGET_CHANGED_FUNC (miimon, nmt_newt_entry_get_text, NM_SETTING_BOND_OPTION_MIIMON)
WIDGET_CHANGED_FUNC (updelay, nmt_newt_entry_get_text, NM_SETTING_BOND_OPTION_UPDELAY)
WIDGET_CHANGED_FUNC (downdelay, nmt_newt_entry_get_text, NM_SETTING_BOND_OPTION_DOWNDELAY)
WIDGET_CHANGED_FUNC (arp_interval, nmt_newt_entry_get_text, NM_SETTING_BOND_OPTION_ARP_INTERVAL)

static void
mode_widget_changed (GObject    *object,
                     GParamSpec *pspec,
                     gpointer    user_data)
{
	NmtPageBond *bond = NMT_PAGE_BOND (user_data);
	NmtPageBondPrivate *priv = NMT_PAGE_BOND_GET_PRIVATE (bond);
	const char *mode;

	if (priv->updating)
		return;

	mode = nmt_newt_popup_get_active_id (priv->mode);
	priv->updating = TRUE;
	nm_setting_bond_add_option (priv->s_bond, NM_SETTING_BOND_OPTION_MODE, mode);
	priv->updating = FALSE;

	if (!strcmp (mode, "balance-tlb") || !strcmp (mode, "balance-alb")) {
		nmt_newt_popup_set_active (priv->monitoring, NMT_PAGE_BOND_MONITORING_MII);
		nmt_newt_component_set_sensitive (NMT_NEWT_COMPONENT (priv->monitoring), FALSE);
	} else
		nmt_newt_component_set_sensitive (NMT_NEWT_COMPONENT (priv->monitoring), TRUE);

	if (!strcmp (mode, "active-backup")) {
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->primary), TRUE);
		nm_setting_bond_add_option (priv->s_bond, NM_SETTING_BOND_OPTION_PRIMARY,
		                            nmt_newt_entry_get_text (priv->primary));
	} else {
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->primary), FALSE);
		nm_setting_bond_remove_option (priv->s_bond, NM_SETTING_BOND_OPTION_PRIMARY);
	}
}

static void
monitoring_widget_changed (GObject    *object,
                           GParamSpec *pspec,
                           gpointer    user_data)
{
	NmtPageBond *bond = NMT_PAGE_BOND (user_data);
	NmtPageBondPrivate *priv = NMT_PAGE_BOND_GET_PRIVATE (bond);

	if (priv->updating)
		return;

	priv->monitoring_mode = nmt_newt_popup_get_active (priv->monitoring);
	if (priv->monitoring_mode == NMT_PAGE_BOND_MONITORING_MII) {
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->miimon), TRUE);
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->updelay), TRUE);
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->downdelay), TRUE);

		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->arp_interval), FALSE);
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->arp_ip_target), FALSE);
	} else {
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->arp_interval), TRUE);
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->arp_ip_target), TRUE);

		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->miimon), FALSE);
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->updelay), FALSE);
		nmt_newt_widget_set_visible (NMT_NEWT_WIDGET (priv->downdelay), FALSE);
	}
}

static void
arp_ip_target_widget_changed (GObject    *object,
                              GParamSpec *pspec,
                              gpointer    user_data)
{
	NmtPageBond *bond = NMT_PAGE_BOND (user_data);
	NmtPageBondPrivate *priv = NMT_PAGE_BOND_GET_PRIVATE (bond);
	char **ips, *target;

	if (priv->updating)
		return;

	g_object_get (G_OBJECT (priv->arp_ip_target),
	              "strings", &ips,
	              NULL);
	target = g_strjoinv (",", ips);

	priv->updating = TRUE;
	nm_setting_bond_add_option (priv->s_bond, NM_SETTING_BOND_OPTION_ARP_IP_TARGET, target);
	priv->updating = FALSE;

	g_free (target);
	g_strfreev (ips);
}

static gboolean
bond_connection_type_filter (GType    connection_type,
                             gpointer user_data)
{
	NmtPageBond *bond = user_data;
	NmtPageBondPrivate *priv = NMT_PAGE_BOND_GET_PRIVATE (bond);

	if (   priv->slave_type != NM_TYPE_SETTING_WIRED
	    && connection_type == NM_TYPE_SETTING_INFINIBAND)
		return TRUE;
	if (   priv->slave_type != NM_TYPE_SETTING_INFINIBAND
	    && connection_type == NM_TYPE_SETTING_WIRED)
		return TRUE;

	return FALSE;
}

static void
nmt_page_bond_constructed (GObject *object)
{
	NmtPageBond *bond = NMT_PAGE_BOND (object);
	NmtPageBondPrivate *priv = NMT_PAGE_BOND_GET_PRIVATE (bond);
	NmtEditorSection *section;
	NmtEditorGrid *grid;
	NMSettingWired *s_wired;
	NMSettingBond *s_bond;
	NmtNewtWidget *widget, *label;
	NMConnection *conn;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (bond));
	s_bond = nm_connection_get_setting_bond (conn);
	if (!s_bond) {
		nm_connection_add_setting (conn, nm_setting_bond_new ());
		s_bond = nm_connection_get_setting_bond (conn);
	}
	priv->s_bond = s_bond;

	s_wired = nm_connection_get_setting_wired (conn);
	if (!s_wired) {
		nm_connection_add_setting (conn, nm_setting_wired_new ());
		s_wired = nm_connection_get_setting_wired (conn);
	}

	section = nmt_editor_section_new (_("BOND"), NULL, TRUE);
	grid = nmt_editor_section_get_body (section);

	widget = nmt_newt_separator_new ();
	nmt_editor_grid_append (grid, _("Slaves"), widget, NULL);
	nmt_editor_grid_set_row_flags (grid, widget, NMT_EDITOR_GRID_ROW_LABEL_ALIGN_LEFT);

	widget = nmt_slave_list_new (conn, bond_connection_type_filter, bond);
	g_signal_connect (widget, "notify::connections",
	                  G_CALLBACK (slaves_changed), bond);
	nmt_editor_grid_append (grid, NULL, widget, NULL);
	priv->slaves = NMT_SLAVE_LIST (widget);

	widget = nmt_newt_popup_new (bond_mode);
	g_signal_connect (widget, "notify::active-id",
	                  G_CALLBACK (mode_widget_changed), bond);
	nmt_editor_grid_append (grid, _("Mode"), widget, NULL);
	priv->mode = NMT_NEWT_POPUP (widget);

	widget = nmt_newt_entry_new (40, 0);
	g_signal_connect (widget, "notify::text",
	                  G_CALLBACK (primary_widget_changed), bond);
	nmt_editor_grid_append (grid, _("Primary"), widget, NULL);
	priv->primary = NMT_NEWT_ENTRY (widget);

	widget = nmt_newt_popup_new (bond_monitoring);
	g_signal_connect (widget, "notify::active",
	                  G_CALLBACK (monitoring_widget_changed), bond);
	nmt_editor_grid_append (grid, _("Link monitoring"), widget, NULL);
	priv->monitoring = NMT_NEWT_POPUP (widget);

	widget = nmt_newt_entry_numeric_new (10, 0, G_MAXINT);
	g_signal_connect (widget, "notify::text",
	                  G_CALLBACK (miimon_widget_changed), bond);
	label = nmt_newt_label_new (C_("milliseconds", "ms"));
	nmt_editor_grid_append (grid, _("Monitoring frequency"), widget, label);
	priv->miimon = NMT_NEWT_ENTRY (widget);

	widget = nmt_newt_entry_numeric_new (10, 0, G_MAXINT);
	g_signal_connect (widget, "notify::text",
	                  G_CALLBACK (updelay_widget_changed), bond);
	label = nmt_newt_label_new (C_("milliseconds", "ms"));
	nmt_editor_grid_append (grid, _("Link up delay"), widget, label);
	priv->updelay = NMT_NEWT_ENTRY (widget);

	widget = nmt_newt_entry_numeric_new (10, 0, G_MAXINT);
	g_signal_connect (widget, "notify::text",
	                  G_CALLBACK (downdelay_widget_changed), bond);
	label = nmt_newt_label_new (C_("milliseconds", "ms"));
	nmt_editor_grid_append (grid, _("Link down delay"), widget, label);
	priv->downdelay = NMT_NEWT_ENTRY (widget);

	widget = nmt_newt_entry_numeric_new (10, 0, G_MAXINT);
	g_signal_connect (widget, "notify::text",
	                  G_CALLBACK (arp_interval_widget_changed), bond);
	label = nmt_newt_label_new (C_("milliseconds", "ms"));
	nmt_editor_grid_append (grid, _("Monitoring frequency"), widget, label);
	priv->arp_interval = NMT_NEWT_ENTRY (widget);

	widget = nmt_address_list_new (NMT_ADDRESS_LIST_IP4);
	g_signal_connect (widget, "notify::strings",
	                  G_CALLBACK (arp_ip_target_widget_changed), bond);
	nmt_editor_grid_append (grid, _("ARP targets"), widget, NULL);
	priv->arp_ip_target = NMT_ADDRESS_LIST (widget);

	widget = nmt_mac_entry_new (40, ETH_ALEN, NMT_MAC_ENTRY_TYPE_CLONED);
	g_object_bind_property (s_wired, NM_SETTING_WIRED_CLONED_MAC_ADDRESS,
	                        widget, "mac-address",
	                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	nmt_editor_grid_append (grid, _("Cloned MAC address"), widget, NULL);

	g_signal_connect (s_bond, "notify::" NM_SETTING_BOND_OPTIONS,
	                  G_CALLBACK (bond_options_changed), bond);
	bond_options_changed (G_OBJECT (s_bond), NULL, bond);
	slaves_changed (G_OBJECT (priv->slaves), NULL, bond);

	nmt_editor_page_add_section (NMT_EDITOR_PAGE (bond), section);

	G_OBJECT_CLASS (nmt_page_bond_parent_class)->constructed (object);
}

static void
nmt_page_bond_saved (NmtEditorPage *editor_page)
{
	NmtPageBondPrivate *priv = NMT_PAGE_BOND_GET_PRIVATE (editor_page);

	nmt_edit_connection_list_recommit (NMT_EDIT_CONNECTION_LIST (priv->slaves));
}

static void
nmt_page_bond_class_init (NmtPageBondClass *bond_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (bond_class);
	NmtEditorPageClass *editor_page_class = NMT_EDITOR_PAGE_CLASS (bond_class);

	g_type_class_add_private (bond_class, sizeof (NmtPageBondPrivate));

	object_class->constructed = nmt_page_bond_constructed;
	editor_page_class->saved = nmt_page_bond_saved;
}
