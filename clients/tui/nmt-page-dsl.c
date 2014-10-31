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
 * Copyright 2014 Red Hat, Inc.
 */

/**
 * SECTION:nmt-page-dsl
 * @short_description: The editor page for DSL connections
 */

#include "config.h"

#include <glib.h>
#include <glib/gi18n-lib.h>

#include "nmt-page-dsl.h"
#include "nmt-password-fields.h"

G_DEFINE_TYPE (NmtPageDsl, nmt_page_dsl, NMT_TYPE_EDITOR_PAGE)

NmtNewtWidget *
nmt_page_dsl_new (NMConnection *conn) 
{
	return g_object_new (NMT_TYPE_PAGE_DSL,
	                     "connection", conn,
	                     "title", _("DSL"),
	                     NULL);
}

static void
nmt_page_dsl_init (NmtPageDsl *dsl)
{
}

static void
nmt_page_dsl_constructed (GObject *object)
{
	NmtPageDsl *dsl = NMT_PAGE_DSL (object);
	NmtEditorGrid *grid;
	NMSettingPppoe *s_pppoe;
	NmtNewtWidget *widget;
	NMConnection *conn;

	conn = nmt_editor_page_get_connection (NMT_EDITOR_PAGE (dsl));
	s_pppoe = nm_connection_get_setting_pppoe (conn);
	if (!s_pppoe) {
		nm_connection_add_setting (conn, nm_setting_pppoe_new ());
		s_pppoe = nm_connection_get_setting_pppoe (conn);
	}

	grid = NMT_EDITOR_GRID (dsl);

	widget = nmt_newt_entry_new (40, 0);
	nmt_editor_grid_append (grid, _("Username"), widget, NULL);
	g_object_bind_property (s_pppoe, NM_SETTING_PPPOE_USERNAME,
	                        widget, "text",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

	widget = nmt_password_fields_new (40, NMT_PASSWORD_FIELDS_SHOW_PASSWORD);
	g_object_bind_property (s_pppoe, NM_SETTING_PPPOE_PASSWORD,
	                        widget, "password",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);
	nmt_editor_grid_append (grid, _("Password"), widget, NULL);

	widget = nmt_newt_entry_new (40, 0);
	nmt_editor_grid_append (grid, _("Service"), widget, NULL);
	g_object_bind_property (s_pppoe, NM_SETTING_PPPOE_SERVICE,
	                        widget, "text",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

	G_OBJECT_CLASS (nmt_page_dsl_parent_class)->constructed (object);
}

static void
nmt_page_dsl_class_init (NmtPageDslClass *dsl_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (dsl_class);

	object_class->constructed = nmt_page_dsl_constructed;
}
