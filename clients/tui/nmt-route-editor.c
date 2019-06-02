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
 * SECTION:nmt-route-editor
 * @short_description: Route editing dialog
 *
 * #NmtRouteEditor implements a form for editing IPv4 or IPv6 routes.
 * This was implemented as a separate dialog because it seemed too
 * wide to fit into the main window.
 */

#include "nm-default.h"

#include "nmt-route-editor.h"
#include "nmt-route-table.h"

G_DEFINE_TYPE (NmtRouteEditor, nmt_route_editor, NMT_TYPE_NEWT_FORM)

#define NMT_ROUTE_EDITOR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_ROUTE_EDITOR, NmtRouteEditorPrivate))

typedef struct {
	NMSetting *orig_setting;
	NMSetting *edit_setting;

} NmtRouteEditorPrivate;

enum {
	PROP_0,
	PROP_SETTING,

	LAST_PROP
};

/**
 * nmt_route_editor_new:
 * @setting: the #NMSettingIP4Config or #NMSettingIP6Config to edit
 *
 * Creates a new #NmtRouteEditor to edit the routes in @setting
 *
 * Returns: a new #NmtRouteEditor
 */
NmtNewtForm *
nmt_route_editor_new (NMSetting *setting)
{
	return g_object_new (NMT_TYPE_ROUTE_EDITOR,
	                     "setting", setting,
	                     NULL);
}

static void
nmt_route_editor_init (NmtRouteEditor *entry)
{
}

static void
save_routes_and_exit (NmtNewtButton *button,
                      gpointer       user_data)
{
	NmtRouteEditor *editor = user_data;
	NmtRouteEditorPrivate *priv = NMT_ROUTE_EDITOR_GET_PRIVATE (editor);
	GPtrArray *routes;

	g_object_get (priv->edit_setting,
	              NM_SETTING_IP_CONFIG_ROUTES, &routes,
	              NULL);
	g_object_set (priv->orig_setting,
	              NM_SETTING_IP_CONFIG_ROUTES, routes,
	              NULL);
	g_ptr_array_unref (routes);

	nmt_newt_form_quit (NMT_NEWT_FORM (editor));
}

static void
nmt_route_editor_constructed (GObject *object)
{
	NmtRouteEditor *editor = NMT_ROUTE_EDITOR (object);
	NmtRouteEditorPrivate *priv = NMT_ROUTE_EDITOR_GET_PRIVATE (editor);
	NmtNewtWidget *vbox, *routes, *buttons, *ok, *cancel;

	if (G_OBJECT_CLASS (nmt_route_editor_parent_class)->constructed)
		G_OBJECT_CLASS (nmt_route_editor_parent_class)->constructed (object);

	if (NM_IS_SETTING_IP4_CONFIG (priv->edit_setting))
		routes = nmt_route_table_new (AF_INET);
	else
		routes = nmt_route_table_new (AF_INET6);
	g_object_bind_property (priv->edit_setting, NM_SETTING_IP_CONFIG_ROUTES,
	                        routes, "routes",
	                        G_BINDING_SYNC_CREATE | G_BINDING_BIDIRECTIONAL);

	vbox = nmt_newt_grid_new ();
	nmt_newt_grid_add (NMT_NEWT_GRID (vbox), routes, 0, 0);

	buttons = nmt_newt_grid_new ();
	nmt_newt_grid_add (NMT_NEWT_GRID (vbox), buttons, 0, 1);
	nmt_newt_widget_set_padding (buttons, 0, 1, 0, 0);

	cancel = g_object_ref_sink (nmt_newt_button_new (_("Cancel")));
	nmt_newt_widget_set_exit_on_activate (cancel, TRUE);
	nmt_newt_grid_add (NMT_NEWT_GRID (buttons), cancel, 0, 0);
	nmt_newt_grid_set_flags (NMT_NEWT_GRID (buttons), cancel,
	                         NMT_NEWT_GRID_EXPAND_X | NMT_NEWT_GRID_ANCHOR_RIGHT |
	                         NMT_NEWT_GRID_FILL_Y);

	ok = g_object_ref_sink (nmt_newt_button_new (_("OK")));
	g_signal_connect (ok, "clicked", G_CALLBACK (save_routes_and_exit), editor);
	nmt_newt_grid_add (NMT_NEWT_GRID (buttons), ok, 1, 0);
	nmt_newt_widget_set_padding (ok, 1, 0, 0, 0);
	g_object_bind_property (routes, "valid",
	                        ok, "sensitive",
	                        G_BINDING_SYNC_CREATE);

	nmt_newt_form_set_content (NMT_NEWT_FORM (editor), vbox);
}

static void
nmt_route_editor_finalize (GObject *object)
{
	NmtRouteEditorPrivate *priv = NMT_ROUTE_EDITOR_GET_PRIVATE (object);

	g_clear_object (&priv->orig_setting);
	g_clear_object (&priv->edit_setting);

	G_OBJECT_CLASS (nmt_route_editor_parent_class)->finalize (object);
}

static void
nmt_route_editor_set_property (GObject      *object,
                               guint         prop_id,
                               const GValue *value,
                               GParamSpec   *pspec)
{
	NmtRouteEditorPrivate *priv = NMT_ROUTE_EDITOR_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SETTING:
		priv->orig_setting = g_value_dup_object (value);
		priv->edit_setting = nm_setting_duplicate (priv->orig_setting);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_route_editor_get_property (GObject    *object,
                               guint       prop_id,
                               GValue     *value,
                               GParamSpec *pspec)
{
	NmtRouteEditorPrivate *priv = NMT_ROUTE_EDITOR_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SETTING:
		g_value_set_object (value, priv->edit_setting);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_route_editor_class_init (NmtRouteEditorClass *entry_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (entry_class);

	g_type_class_add_private (entry_class, sizeof (NmtRouteEditorPrivate));

	/* virtual methods */
	object_class->constructed  = nmt_route_editor_constructed;
	object_class->set_property = nmt_route_editor_set_property;
	object_class->get_property = nmt_route_editor_get_property;
	object_class->finalize     = nmt_route_editor_finalize;

	/**
	 * NmtRouteEditor:setting:
	 *
	 * The #NMSettingIP4Config or #NMSettingIP6Config whose routes are
	 * being edited.
	 */
	g_object_class_install_property
		(object_class, PROP_SETTING,
		 g_param_spec_object ("setting", "", "",
		                      NM_TYPE_SETTING,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));
}
