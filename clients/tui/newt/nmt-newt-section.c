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
 * SECTION:nmt-newt-section
 * @short_description: A collapsible section
 *
 * #NmtNewtSection is a container with two children; the header and
 * the body. The header is always visible, but the body is only
 * visible when the container is #NmtNewtSection:open.
 *
 * Note that there is no default way to open and close an
 * #NmtNewtSection. You need to implement this yourself. (Eg, by
 * binding the #NmtToggleButton:active property of an #NmtToggleButton
 * in the section's header to the section's #NmtNewtSection:open
 * property.)
 *
 * In addition to the header and body, the #NmtNewtSection also
 * optionally draws a border along the left side, indicating the
 * extent of the section.
 */

#include "nm-default.h"

#include <string.h>

#include "nmt-newt-section.h"
#include "nmt-newt-grid.h"
#include "nmt-newt-label.h"
#include "nmt-newt-utils.h"

G_DEFINE_TYPE (NmtNewtSection, nmt_newt_section, NMT_TYPE_NEWT_CONTAINER)

#define NMT_NEWT_SECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_SECTION, NmtNewtSectionPrivate))

typedef struct {
	NmtNewtWidget *header;
	int hheight_req, hwidth_req;

	NmtNewtWidget *body;
	int bheight_req, bwidth_req;

	gboolean show_border;
	NmtNewtWidget *border_grid;
	NmtNewtWidget *border_open_label;
	NmtNewtWidget *border_closed_label;
	NmtNewtWidget *border_end_label;
	GPtrArray *border_line_labels;

	gboolean open;
} NmtNewtSectionPrivate;

static char *closed_glyph, *open_glyph, *line_glyph, *end_glyph;

enum {
	PROP_0,

	PROP_SHOW_BORDER,
	PROP_OPEN,

	LAST_PROP
};

/**
 * nmt_newt_section_new:
 * @show_border: whether to show the border on the side of the section
 *
 * Creates a new #NmtNewtSection
 *
 * Returns: a new #NmtNewtSection
 */
NmtNewtWidget *
nmt_newt_section_new (gboolean show_border)
{
	return g_object_new (NMT_TYPE_NEWT_SECTION,
	                     "show-border", show_border,
	                     NULL);
}

static void
nmt_newt_section_init (NmtNewtSection *section)
{
	NmtNewtSectionPrivate *priv = NMT_NEWT_SECTION_GET_PRIVATE (section);
	NmtNewtContainerClass *parent_class = NMT_NEWT_CONTAINER_CLASS (nmt_newt_section_parent_class);

	priv->show_border = TRUE;

	priv->border_grid = nmt_newt_grid_new ();
	parent_class->add (NMT_NEWT_CONTAINER (section), priv->border_grid);

	priv->border_open_label = nmt_newt_label_new (open_glyph);
	nmt_newt_widget_set_visible (priv->border_open_label, FALSE);
	nmt_newt_grid_add (NMT_NEWT_GRID (priv->border_grid), priv->border_open_label, 0, 0);

	priv->border_closed_label = nmt_newt_label_new (closed_glyph);
	nmt_newt_grid_add (NMT_NEWT_GRID (priv->border_grid), priv->border_closed_label, 0, 0);

	priv->border_end_label = nmt_newt_label_new (end_glyph);
	nmt_newt_widget_set_visible (priv->border_open_label, FALSE);
	nmt_newt_grid_add (NMT_NEWT_GRID (priv->border_grid), priv->border_end_label, 0, 1);

	priv->border_line_labels = g_ptr_array_new ();
}

static void
nmt_newt_section_finalize (GObject *object)
{
	NmtNewtSectionPrivate *priv = NMT_NEWT_SECTION_GET_PRIVATE (object);

	g_ptr_array_unref (priv->border_line_labels);

	G_OBJECT_CLASS (nmt_newt_section_parent_class)->finalize (object);
}

/**
 * nmt_newt_section_set_header:
 * @section: an #NmtNewtSection
 * @header: the header widget
 *
 * Sets @section's header widget.
 */
void
nmt_newt_section_set_header (NmtNewtSection *section,
                             NmtNewtWidget  *header)
{
	NmtNewtSectionPrivate *priv = NMT_NEWT_SECTION_GET_PRIVATE (section);
	NmtNewtContainerClass *parent_class = NMT_NEWT_CONTAINER_CLASS (nmt_newt_section_parent_class);
	NmtNewtContainer *container = NMT_NEWT_CONTAINER (section);

	if (priv->header)
		parent_class->remove (container, priv->header);
	priv->header = header;
	parent_class->add (container, header);
}

/**
 * nmt_newt_section_get_header:
 * @section: an #NmtNewtSection
 *
 * Gets @section's header widget.
 *
 * Returns: @section's header widget.
 */
NmtNewtWidget *
nmt_newt_section_get_header (NmtNewtSection *section)
{
	NmtNewtSectionPrivate *priv = NMT_NEWT_SECTION_GET_PRIVATE (section);

	return priv->header;
}

/**
 * nmt_newt_section_set_body:
 * @section: an #NmtNewtSection
 * @body: the body widget
 *
 * Sets @section's body widget.
 */
void
nmt_newt_section_set_body (NmtNewtSection *section,
                           NmtNewtWidget  *body)
{
	NmtNewtSectionPrivate *priv = NMT_NEWT_SECTION_GET_PRIVATE (section);
	NmtNewtContainerClass *parent_class = NMT_NEWT_CONTAINER_CLASS (nmt_newt_section_parent_class);
	NmtNewtContainer *container = NMT_NEWT_CONTAINER (section);

	if (priv->body)
		parent_class->remove (container, priv->body);
	priv->body = body;
	parent_class->add (container, body);
}

/**
 * nmt_newt_section_get_body:
 * @section: an #NmtNewtSection
 *
 * Gets @section's body widget.
 *
 * Returns: @section's body widget.
 */
NmtNewtWidget *
nmt_newt_section_get_body (NmtNewtSection *section)
{
	NmtNewtSectionPrivate *priv = NMT_NEWT_SECTION_GET_PRIVATE (section);

	return priv->body;
}

static void
nmt_newt_section_remove (NmtNewtContainer *container,
                         NmtNewtWidget    *widget)
{
	NmtNewtSection *section = NMT_NEWT_SECTION (container);
	NmtNewtSectionPrivate *priv = NMT_NEWT_SECTION_GET_PRIVATE (section);
	NmtNewtContainerClass *parent_class = NMT_NEWT_CONTAINER_CLASS (nmt_newt_section_parent_class);

	if (widget == priv->header)
		priv->header = NULL;
	else if (widget == priv->body)
		priv->body = NULL;
	else if (widget == priv->border_grid)
		priv->border_grid = NULL;

	parent_class->remove (container, widget);
}

static newtComponent *
nmt_newt_section_get_components (NmtNewtWidget *widget)
{
	NmtNewtSectionPrivate *priv = NMT_NEWT_SECTION_GET_PRIVATE (widget);
	newtComponent *child_cos;
	GPtrArray *cos;
	int i;

	g_return_val_if_fail (priv->header != NULL && priv->body != NULL, NULL);

	cos = g_ptr_array_new ();

	if (priv->show_border) {
		child_cos = nmt_newt_widget_get_components (priv->border_grid);
		for (i = 0; child_cos[i]; i++)
			g_ptr_array_add (cos, child_cos[i]);
		g_free (child_cos);
	}

	child_cos = nmt_newt_widget_get_components (priv->header);
	for (i = 0; child_cos[i]; i++)
		g_ptr_array_add (cos, child_cos[i]);
	g_free (child_cos);

	if (priv->open) {
		child_cos = nmt_newt_widget_get_components (priv->body);
		for (i = 0; child_cos[i]; i++)
			g_ptr_array_add (cos, child_cos[i]);
		g_free (child_cos);
	}

	g_ptr_array_add (cos, NULL);
	return (newtComponent *) g_ptr_array_free (cos, FALSE);
}

static void
nmt_newt_section_size_request (NmtNewtWidget *widget,
                               int           *width,
                               int           *height)
{
	NmtNewtSectionPrivate *priv = NMT_NEWT_SECTION_GET_PRIVATE (widget);
	int w_ignore, h_ignore;

	g_return_if_fail (priv->header != NULL && priv->body != NULL);

	if (priv->show_border)
		nmt_newt_widget_size_request (priv->border_grid, &w_ignore, &h_ignore);
	nmt_newt_widget_size_request (priv->header, &priv->hwidth_req, &priv->hheight_req);
	nmt_newt_widget_size_request (priv->body, &priv->bwidth_req, &priv->bheight_req);

	*width = MAX (priv->hwidth_req, priv->bwidth_req) + 2;
	if (priv->open)
		*height = priv->hheight_req + priv->bheight_req + (priv->show_border ? 1 : 0);
	else
		*height = priv->hheight_req;
}

static void
adjust_border_for_allocation (NmtNewtSectionPrivate *priv,
                              int                    height)
{
	int i;

	/* We have to use a series of one-line labels rather than a multi-line
	 * textbox, because newt will hide any component that's partially offscreen,
	 * but we want the on-screen portion of the border to show even if part of
	 * it is offscreen.
	 */

	if (height == 1) {
		nmt_newt_widget_set_visible (priv->border_closed_label, TRUE);
		nmt_newt_widget_set_visible (priv->border_open_label, FALSE);
		for (i = 0; i < priv->border_line_labels->len; i++)
			nmt_newt_widget_set_visible (priv->border_line_labels->pdata[i], FALSE);
		nmt_newt_widget_set_visible (priv->border_end_label, FALSE);
	} else {
		nmt_newt_widget_set_visible (priv->border_closed_label, FALSE);
		nmt_newt_widget_set_visible (priv->border_open_label, TRUE);
		for (i = 0; i < height - 2; i++) {
			if (i >= priv->border_line_labels->len) {
				NmtNewtWidget *label;

				label = nmt_newt_label_new (line_glyph);
				g_ptr_array_add (priv->border_line_labels, label);
				nmt_newt_grid_add (NMT_NEWT_GRID (priv->border_grid), label, 0, i + 1);
			} else 
				nmt_newt_widget_set_visible (priv->border_line_labels->pdata[i], TRUE);
		}
		nmt_newt_widget_set_visible (priv->border_end_label, TRUE);
		nmt_newt_grid_move (NMT_NEWT_GRID (priv->border_grid), priv->border_end_label, 0, height - 1);
	}
}

static void
nmt_newt_section_size_allocate (NmtNewtWidget *widget,
                                int            x,
                                int            y,
                                int            width,
                                int            height)
{
	NmtNewtSectionPrivate *priv = NMT_NEWT_SECTION_GET_PRIVATE (widget);

	if (priv->show_border) {
		int w_ignore, h_ignore;

		adjust_border_for_allocation (priv, height);
		nmt_newt_widget_size_request (priv->border_grid, &w_ignore, &h_ignore);
		nmt_newt_widget_size_allocate (priv->border_grid, x, y, 1, height);
		nmt_newt_widget_size_allocate (priv->header, x + 2, y, width, priv->hheight_req);
	} else
		nmt_newt_widget_size_allocate (priv->header, x, y, width, priv->hheight_req);

	if (priv->open) {
		nmt_newt_widget_size_allocate (priv->body, x + 2, y + priv->hheight_req,
		                               width, height - priv->hheight_req);
	}
}

static void
nmt_newt_section_set_property (GObject      *object,
                               guint         prop_id,
                               const GValue *value,
                               GParamSpec   *pspec)
{
	NmtNewtSectionPrivate *priv = NMT_NEWT_SECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SHOW_BORDER:
		priv->show_border = g_value_get_boolean (value);
		nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (object));
		break;
	case PROP_OPEN:
		priv->open = g_value_get_boolean (value);
		nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (object));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_section_get_property (GObject    *object,
                               guint       prop_id,
                               GValue     *value,
                               GParamSpec *pspec)
{
	NmtNewtSectionPrivate *priv = NMT_NEWT_SECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SHOW_BORDER:
		g_value_set_boolean (value, priv->show_border);
		break;
	case PROP_OPEN:
		g_value_set_boolean (value, priv->open);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_section_class_init (NmtNewtSectionClass *section_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (section_class);
	NmtNewtWidgetClass *widget_class = NMT_NEWT_WIDGET_CLASS (section_class);
	NmtNewtContainerClass *container_class = NMT_NEWT_CONTAINER_CLASS (section_class);

	g_type_class_add_private (section_class, sizeof (NmtNewtSectionPrivate));

	/* virtual methods */
	object_class->set_property = nmt_newt_section_set_property;
	object_class->get_property = nmt_newt_section_get_property;
	object_class->finalize     = nmt_newt_section_finalize;

	widget_class->get_components = nmt_newt_section_get_components;
	widget_class->size_request   = nmt_newt_section_size_request;
	widget_class->size_allocate  = nmt_newt_section_size_allocate;

	container_class->remove = nmt_newt_section_remove;

	/* properties */

	/**
	 * NmtNewtSection:show-border:
	 *
	 * %TRUE if the section should show a border along the left side.
	 */
	g_object_class_install_property
		(object_class, PROP_SHOW_BORDER,
		 g_param_spec_boolean ("show-border", "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NmtNewtSection:open:
	 *
	 * %TRUE if the section is open (ie, its body is visible), %FALSE
	 * if not.
	 */
	g_object_class_install_property
		(object_class, PROP_OPEN,
		 g_param_spec_boolean ("open", "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/* globals */
	closed_glyph = nmt_newt_locale_from_utf8 ("\342\225\220"); /* ═ */
	open_glyph   = nmt_newt_locale_from_utf8 ("\342\225\244"); /* ╤ */
	line_glyph   = nmt_newt_locale_from_utf8 ("\342\224\202"); /* │ */
	end_glyph    = nmt_newt_locale_from_utf8 ("\342\224\224"); /* └ */
	if (!*closed_glyph || !*open_glyph || !*line_glyph || !*end_glyph) {
		g_free (closed_glyph);
		g_free (open_glyph);
		g_free (line_glyph);
		g_free (end_glyph);

		closed_glyph = g_strdup ("-");
		open_glyph   = g_strdup ("+");
		line_glyph   = g_strdup ("|");
		end_glyph    = g_strdup ("\\");
	}
}
