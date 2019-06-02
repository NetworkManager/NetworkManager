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
 * SECTION:nmt-editor-section:
 * @short_description: A section of the #NmtEditor
 *
 * #NmtEditorSection is the abstract base class for #NmtEditor sections.
 */

#include "nm-default.h"

#include "nmt-editor-section.h"
#include "nmt-newt-toggle-button.h"

G_DEFINE_TYPE (NmtEditorSection, nmt_editor_section, NMT_TYPE_NEWT_SECTION)

#define NMT_EDITOR_SECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_EDITOR_SECTION, NmtEditorSectionPrivate))

typedef struct {
	NmtEditorGrid *header, *body;
	char *title;
	NmtNewtWidget *header_widget;
	NmtNewtWidget *toggle;

	gboolean show_by_default;
} NmtEditorSectionPrivate;

enum {
	PROP_0,

	PROP_TITLE,
	PROP_SHOW_BY_DEFAULT,
	PROP_HEADER_WIDGET,

	LAST_PROP
};

/**
 * nmt_editor_section_new:
 * @title: the section title
 * @header_widget: (allow-none): the widget to show next to the title
 * @show_by_default: whether the section should be open by default
 *
 * Creates a new #NmtEditorSection.
 *
 * Returns: a new #NmtEditorSection
 */
NmtEditorSection *
nmt_editor_section_new (const char *title,
                        NmtNewtWidget *header_widget,
                        gboolean show_by_default)
{
	return g_object_new (NMT_TYPE_EDITOR_SECTION,
	                     "title", title,
	                     "header-widget", header_widget,
	                     "show-by-default", show_by_default,
	                     NULL);
}

static void
rebuild_header (NmtEditorSection *section)
{
	NmtEditorSectionPrivate *priv = NMT_EDITOR_SECTION_GET_PRIVATE (section);

	/* Removing any widget in an NmtEditorGrid removes its whole row, so we can
	 * remove the existing title/widget/toggle by asking to remove toggle.
	 */
	nmt_newt_container_remove (NMT_NEWT_CONTAINER (priv->header), priv->toggle);

	nmt_editor_grid_append (priv->header,
	                        priv->title,
	                        priv->header_widget,
	                        priv->toggle);
	nmt_editor_grid_set_row_flags (priv->header,
	                               priv->toggle,
	                               NMT_EDITOR_GRID_ROW_LABEL_ALIGN_LEFT |
	                               NMT_EDITOR_GRID_ROW_EXTRA_ALIGN_RIGHT);
}

static void
nmt_editor_section_init (NmtEditorSection *section)
{
	NmtEditorSectionPrivate *priv = NMT_EDITOR_SECTION_GET_PRIVATE (section);

	priv->header = NMT_EDITOR_GRID (nmt_editor_grid_new ());
	priv->body = NMT_EDITOR_GRID (nmt_editor_grid_new ());
	priv->toggle = nmt_newt_toggle_button_new (_("Hide"), _("Show"));
	g_object_ref_sink (priv->toggle);

	nmt_newt_section_set_header (NMT_NEWT_SECTION (section), NMT_NEWT_WIDGET (priv->header));
	nmt_newt_section_set_body (NMT_NEWT_SECTION (section), NMT_NEWT_WIDGET (priv->body));

	g_object_bind_property (priv->toggle, "active",
	                        section, "open",
	                        G_BINDING_SYNC_CREATE);
}

static void
nmt_editor_section_finalize (GObject *object)
{
	NmtEditorSectionPrivate *priv = NMT_EDITOR_SECTION_GET_PRIVATE (object);

	g_free (priv->title);
	g_clear_object (&priv->header_widget);
	g_clear_object (&priv->toggle);

	G_OBJECT_CLASS (nmt_editor_section_parent_class)->finalize (object);
}

/**
 * nmt_editor_section_get_header_widget:
 * @section: the #NmtEditorSection
 *
 * Gets the section's header widget.
 *
 * Returns: the section's header widget.
 */
NmtNewtWidget *
nmt_editor_section_get_header_widget (NmtEditorSection *section)
{
	NmtEditorSectionPrivate *priv = NMT_EDITOR_SECTION_GET_PRIVATE (section);

	return priv->header_widget;
}

/**
 * nmt_editor_section_get_body:
 * @section: the #NmtEditorSection
 *
 * Gets the section's body grid, so that you can add things to it.
 *
 * Returns: the #NmtEditorGrid used for the section body
 */
NmtEditorGrid *
nmt_editor_section_get_body (NmtEditorSection *section)
{
	NmtEditorSectionPrivate *priv = NMT_EDITOR_SECTION_GET_PRIVATE (section);

	return priv->body;
}

/**
 * nmt_editor_section_get_title:
 * @section: the #NmtEditorSection
 *
 * Gets the section's title.
 *
 * Returns: the section's title
 */
const char *
nmt_editor_section_get_title (NmtEditorSection *section)
{
	NmtEditorSectionPrivate *priv = NMT_EDITOR_SECTION_GET_PRIVATE (section);

	return priv->title;
}

static void
nmt_editor_section_set_property (GObject      *object,
                                 guint         prop_id,
                                 const GValue *value,
                                 GParamSpec   *pspec)
{
	NmtEditorSection *section = NMT_EDITOR_SECTION (object);
	NmtEditorSectionPrivate *priv = NMT_EDITOR_SECTION_GET_PRIVATE (section);

	switch (prop_id) {
	case PROP_TITLE:
		priv->title = g_value_dup_string (value);
		rebuild_header (section);
		break;
	case PROP_SHOW_BY_DEFAULT:
		priv->show_by_default = g_value_get_boolean (value);
		nmt_newt_toggle_button_set_active (NMT_NEWT_TOGGLE_BUTTON (priv->toggle),
		                                   priv->show_by_default);
		break;
	case PROP_HEADER_WIDGET:
		priv->header_widget = g_value_get_object (value);
		if (priv->header_widget)
			g_object_ref_sink (priv->header_widget);
		rebuild_header (section);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_editor_section_get_property (GObject    *object,
                                 guint       prop_id,
                                 GValue     *value,
                                 GParamSpec *pspec)
{
	NmtEditorSectionPrivate *priv = NMT_EDITOR_SECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_TITLE:
		g_value_set_string (value, priv->title);
		break;
	case PROP_SHOW_BY_DEFAULT:
		g_value_set_boolean (value, priv->show_by_default);
		break;
	case PROP_HEADER_WIDGET:
		g_value_set_object (value, priv->header_widget);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_editor_section_class_init (NmtEditorSectionClass *section_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (section_class);

	g_type_class_add_private (section_class, sizeof (NmtEditorSectionPrivate));

	/* virtual methods */
	object_class->set_property = nmt_editor_section_set_property;
	object_class->get_property = nmt_editor_section_get_property;
	object_class->finalize     = nmt_editor_section_finalize;

	/* properties */

	/**
	 * NmtEditorSection:title:
	 *
	 * The section's title.
	 */
	g_object_class_install_property
		(object_class, PROP_TITLE,
		 g_param_spec_string ("title", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NmtEditorSection:show-by-default:
	 *
	 * Whether the section should be expanded by default.
	 */
	g_object_class_install_property
		(object_class, PROP_SHOW_BY_DEFAULT,
		 g_param_spec_boolean ("show-by-default", "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NmtEditorSection:header-widget:
	 *
	 * The widget (if any) that appears between the section title and its toggle
	 * button.
	 */
	g_object_class_install_property
		(object_class, PROP_HEADER_WIDGET,
		 g_param_spec_object ("header-widget", "", "",
		                      NMT_TYPE_NEWT_WIDGET,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
}
