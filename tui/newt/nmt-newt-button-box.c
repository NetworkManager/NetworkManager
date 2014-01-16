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
 * SECTION:nmt-newt-button-box
 * @short_description: A container for #NmtNewtButtons
 *
 * #NmtNewtButtonBox is a container for creating and holding
 * #NmtNewtButtons.
 *
 * A button box can be either horizontally or vertically laid out, and
 * has two sections within it: the "start" (left or top) and "end"
 * (right or bottom). Buttons are added from left to right or top to bottom
 * within each of the two sections.
 */

#include "config.h"

#include <string.h>

#include "nmt-newt-button-box.h"
#include "nmt-newt-button.h"

G_DEFINE_TYPE (NmtNewtButtonBox, nmt_newt_button_box, NMT_TYPE_NEWT_CONTAINER)

#define NMT_NEWT_BUTTON_BOX_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_BUTTON_BOX, NmtNewtButtonBoxPrivate))

typedef struct {
	NmtNewtButtonBoxOrientation orientation;
	GPtrArray *start_buttons, *end_buttons;
} NmtNewtButtonBoxPrivate;

enum {
	PROP_0,

	PROP_ORIENTATION,

	LAST_PROP
};

/**
 * NmtNewtButtonBoxOrientation:
 * @NMT_NEWT_BUTTON_BOX_HORIZONTAL: horizontal
 * @NMT_NEWT_BUTTON_BOX_VERTICAL: vertical
 *
 * The orientation of an #NmtNewtButtonBox
 */

/**
 * nmt_newt_button_box_new:
 * @orientation: the orientation
 *
 * Creates a new #NmtNewtButtonBox
 *
 * Returns: a new #NmtNewtButtonBox
 */
NmtNewtWidget *
nmt_newt_button_box_new (NmtNewtButtonBoxOrientation orientation)
{
	return g_object_new (NMT_TYPE_NEWT_BUTTON_BOX,
	                     "orientation", orientation,
	                     NULL);
}

static void
nmt_newt_button_box_init (NmtNewtButtonBox *bbox)
{
	NmtNewtButtonBoxPrivate *priv = NMT_NEWT_BUTTON_BOX_GET_PRIVATE (bbox);

	priv->start_buttons = g_ptr_array_new ();
	priv->end_buttons = g_ptr_array_new ();
}

/**
 * nmt_newt_button_box_add_start:
 * @bbox: an #NmtNewtButtonBox
 * @label: the label for the newt button
 *
 * Creates a new #NmtNewtButton with the given @label, adds it
 * to the "start" section of @bbox, and returns the newly-created
 * button.
 *
 * Returns: the newly-created button, already added to @bbox
 */
NmtNewtWidget *
nmt_newt_button_box_add_start (NmtNewtButtonBox *bbox,
                               const char       *label)
{
	NmtNewtWidget *button;

	button = nmt_newt_button_new (label);
	nmt_newt_button_box_add_widget_start (bbox, button);
	return button;
}

/**
 * nmt_newt_button_box_add_widget_start:
 * @bbox: an #NmtNewtButtonBox
 * @widget: the #NmtNewtWidget to add
 *
 * Adds the given widget to the "start" section of @bbox.
 */
void
nmt_newt_button_box_add_widget_start (NmtNewtButtonBox *bbox,
                                      NmtNewtWidget    *widget)
{
	NmtNewtButtonBoxPrivate *priv = NMT_NEWT_BUTTON_BOX_GET_PRIVATE (bbox);

	NMT_NEWT_CONTAINER_CLASS (nmt_newt_button_box_parent_class)->
		add (NMT_NEWT_CONTAINER (bbox), widget);
	g_ptr_array_add (priv->start_buttons, widget);
}

/**
 * nmt_newt_button_box_add_end:
 * @bbox: an #NmtNewtButtonBox
 * @label: the label for the newt button
 *
 * Creates a new #NmtNewtButton with the given @label, adds it
 * to the "end" section of @bbox, and returns the newly-created
 * button.
 *
 * Returns: the newly-created button, already added to @bbox
 */
NmtNewtWidget *
nmt_newt_button_box_add_end (NmtNewtButtonBox *bbox,
                             const char       *label)
{
	NmtNewtWidget *button;

	button = nmt_newt_button_new (label);
	nmt_newt_button_box_add_widget_end (bbox, button);
	return button;
}

/**
 * nmt_newt_button_box_add_widget_end:
 * @bbox: an #NmtNewtButtonBox
 * @widget: the #NmtNewtWidget to add
 *
 * Adds the given widget to the "end" section of @bbox.
 */
void
nmt_newt_button_box_add_widget_end (NmtNewtButtonBox *bbox,
                                    NmtNewtWidget    *widget)
{
	NmtNewtButtonBoxPrivate *priv = NMT_NEWT_BUTTON_BOX_GET_PRIVATE (bbox);

	NMT_NEWT_CONTAINER_CLASS (nmt_newt_button_box_parent_class)->
		add (NMT_NEWT_CONTAINER (bbox), widget);
	g_ptr_array_add (priv->end_buttons, widget);
}

static void
nmt_newt_button_box_remove (NmtNewtContainer *container,
                            NmtNewtWidget    *child)
{
	NmtNewtButtonBoxPrivate *priv = NMT_NEWT_BUTTON_BOX_GET_PRIVATE (container);
	int i;

	NMT_NEWT_CONTAINER_CLASS (nmt_newt_button_box_parent_class)->
		remove (container, child);

	for (i = 0; i < priv->start_buttons->len; i++) {
		if (priv->start_buttons->pdata[i] == (gpointer) child) {
			g_ptr_array_remove_index (priv->start_buttons, i);
			return;
		}
	}
	for (i = 0; i < priv->end_buttons->len; i++) {
		if (priv->end_buttons->pdata[i] == (gpointer) child) {
			g_ptr_array_remove_index (priv->end_buttons, i);
			return;
		}
	}
}

static void
add_buttons (GPtrArray *buttons, GPtrArray *cos)
{
	NmtNewtWidget *child;
	newtComponent *child_cos;
	int i, c;

	for (i = 0; i < buttons->len; i++) {
		child = buttons->pdata[i];

		if (!nmt_newt_widget_get_visible (child))
			continue;

		child_cos = nmt_newt_widget_get_components (child);
		for (c = 0; child_cos[c]; c++)
			g_ptr_array_add (cos, child_cos[c]);
		g_free (child_cos);
	}
}

static newtComponent *
nmt_newt_button_box_get_components (NmtNewtWidget *widget)
{
	NmtNewtButtonBoxPrivate *priv = NMT_NEWT_BUTTON_BOX_GET_PRIVATE (widget);
	GPtrArray *cos;

	cos = g_ptr_array_new ();
	add_buttons (priv->start_buttons, cos);
	add_buttons (priv->end_buttons, cos);
	g_ptr_array_add (cos, NULL);

	return (newtComponent *) g_ptr_array_free (cos, FALSE);
}

static void
size_request_buttons (NmtNewtButtonBox *bbox,
                      GPtrArray        *buttons,
                      int              *width,
                      int              *height)
{
	NmtNewtButtonBoxPrivate *priv = NMT_NEWT_BUTTON_BOX_GET_PRIVATE (bbox);
	int child_width, child_height;
	int i;

	for (i = 0; i < buttons->len; i++) {
		NmtNewtWidget *child = buttons->pdata[i];

		nmt_newt_widget_size_request (child, &child_width, &child_height);
		if (priv->orientation == NMT_NEWT_BUTTON_BOX_HORIZONTAL) {
			*width += child_width;
			if (i > 0)
				*width += 1;
			*height = MAX (*height, child_height);
		} else {
			*height += child_height;
			if (i > 0)
				*height += 1;
			*width = MAX (*width, child_width);
		}
	}
}

static void
nmt_newt_button_box_size_request (NmtNewtWidget *widget,
                                  int           *width,
                                  int           *height)
{
	NmtNewtButtonBox *bbox = NMT_NEWT_BUTTON_BOX (widget);
	NmtNewtButtonBoxPrivate *priv = NMT_NEWT_BUTTON_BOX_GET_PRIVATE (widget);

	*width = *height = 0;
	size_request_buttons (bbox, priv->start_buttons, width, height);
	size_request_buttons (bbox, priv->end_buttons, width, height);

	if (priv->start_buttons && priv->end_buttons) {
		if (priv->orientation == NMT_NEWT_BUTTON_BOX_HORIZONTAL)
			*width += 1;
		else
			*height += 1;
	}
}

static void
nmt_newt_button_box_size_allocate (NmtNewtWidget *widget,
                                   int            x,
                                   int            y,
                                   int            width,
                                   int            height)
{
	NmtNewtButtonBoxPrivate *priv = NMT_NEWT_BUTTON_BOX_GET_PRIVATE (widget);
	NmtNewtWidget *child;
	int child_x, child_y, child_width, child_height;
	int i;

	child_x = x;
	child_y = y;
	for (i = 0; i < priv->start_buttons->len; i++) {
		child = priv->start_buttons->pdata[i];
		nmt_newt_widget_size_request (child, &child_width, &child_height);

		if (priv->orientation == NMT_NEWT_BUTTON_BOX_HORIZONTAL) {
			nmt_newt_widget_size_allocate (child, child_x, child_y, child_width, child_height);
			child_x += child_width + 1;
		} else {
			nmt_newt_widget_size_allocate (child, child_x, child_y, child_width, child_height);
			child_y += child_height + 1;
		}
	}

	if (priv->orientation == NMT_NEWT_BUTTON_BOX_HORIZONTAL)
		child_x = x + width;
	else
		child_y = y + height;

	for (i = priv->end_buttons->len - 1; i >= 0; i--) {
		child = priv->end_buttons->pdata[i];
		nmt_newt_widget_size_request (child, &child_width, &child_height);

		if (priv->orientation == NMT_NEWT_BUTTON_BOX_HORIZONTAL) {
			nmt_newt_widget_size_allocate (child,
			                               child_x - child_width, child_y,
			                               child_width, child_height);
			child_x -= child_width + 1;
		} else {
			nmt_newt_widget_size_allocate (child,
			                               child_x, child_y - child_height,
			                               child_width, child_height);
			child_y -= child_height + 1;
		}
	}
}

static void
nmt_newt_button_box_set_property (GObject      *object,
                                  guint         prop_id,
                                  const GValue *value,
                                  GParamSpec   *pspec)
{
	NmtNewtButtonBoxPrivate *priv = NMT_NEWT_BUTTON_BOX_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_ORIENTATION:
		priv->orientation = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_button_box_get_property (GObject    *object,
                                  guint       prop_id,
                                  GValue     *value,
                                  GParamSpec *pspec)
{
	NmtNewtButtonBoxPrivate *priv = NMT_NEWT_BUTTON_BOX_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_ORIENTATION:
		g_value_set_int (value, priv->orientation);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_button_box_class_init (NmtNewtButtonBoxClass *bbox_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (bbox_class);
	NmtNewtWidgetClass *widget_class = NMT_NEWT_WIDGET_CLASS (bbox_class);
	NmtNewtContainerClass *container_class = NMT_NEWT_CONTAINER_CLASS (bbox_class);

	g_type_class_add_private (bbox_class, sizeof (NmtNewtButtonBoxPrivate));

	object_class->get_property = nmt_newt_button_box_get_property;
	object_class->set_property = nmt_newt_button_box_set_property;

	widget_class->get_components = nmt_newt_button_box_get_components;
	widget_class->size_request   = nmt_newt_button_box_size_request;
	widget_class->size_allocate  = nmt_newt_button_box_size_allocate;

	container_class->remove = nmt_newt_button_box_remove;

	g_object_class_install_property (object_class, PROP_ORIENTATION,
	                                 g_param_spec_int ("orientation", "", "",
	                                                   0, G_MAXINT, 0,
	                                                   G_PARAM_READWRITE |
	                                                   G_PARAM_CONSTRUCT_ONLY |
	                                                   G_PARAM_STATIC_STRINGS));
}
