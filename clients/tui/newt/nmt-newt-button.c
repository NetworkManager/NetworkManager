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
 * SECTION:nmt-newt-button
 * @short_description: Push buttons
 *
 * #NmtNewtButton implements a button widget.
 */

#include "nm-default.h"

#include "nmt-newt-button.h"
#include "nmt-newt-utils.h"

G_DEFINE_TYPE (NmtNewtButton, nmt_newt_button, NMT_TYPE_NEWT_COMPONENT)

#define NMT_NEWT_BUTTON_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_BUTTON, NmtNewtButtonPrivate))

typedef struct {
	char *label;
} NmtNewtButtonPrivate;

enum {
	PROP_0,
	PROP_LABEL,

	LAST_PROP
};

enum {
	CLICKED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/**
 * nmt_newt_button_new:
 * @label: the (initial) button label
 *
 * Creates a new button.
 *
 * Returns: a new #NmtNewtButton
 */
NmtNewtWidget *
nmt_newt_button_new (const char *label)
{
	return g_object_new (NMT_TYPE_NEWT_BUTTON,
	                     "label", label,
	                     NULL);
}

/**
 * nmt_newt_button_set_label:
 * @button: an #NmtNewtButton
 * @label: the new label
 *
 * Updates @button's label.
 */
void
nmt_newt_button_set_label (NmtNewtButton *button,
                           const char    *label)
{
	NmtNewtButtonPrivate *priv = NMT_NEWT_BUTTON_GET_PRIVATE (button);

	if (!g_strcmp0 (priv->label, label))
		return;

	g_free (priv->label);
	priv->label = g_strdup (label);
	nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (button));
}

/**
 * nmt_newt_button_get_label:
 * @button: an #NmtNewtButton
 *
 * Gets @button's label.
 *
 * Returns: @button's label.
 */
const char *
nmt_newt_button_get_label (NmtNewtButton *button)
{
	NmtNewtButtonPrivate *priv = NMT_NEWT_BUTTON_GET_PRIVATE (button);

	return priv->label;
}

static void
nmt_newt_button_init (NmtNewtButton *button)
{
}

static void
nmt_newt_button_finalize (GObject *object)
{
	NmtNewtButtonPrivate *priv = NMT_NEWT_BUTTON_GET_PRIVATE (object);

	g_free (priv->label);

	G_OBJECT_CLASS (nmt_newt_button_parent_class)->finalize (object);
}

static newtComponent
nmt_newt_button_build_component (NmtNewtComponent *component,
                                 gboolean          sensitive)
{
	NmtNewtButtonPrivate *priv = NMT_NEWT_BUTTON_GET_PRIVATE (component);
	newtComponent co;
	char *label = NULL, *label_lc;

	if (sensitive) {
		label_lc = nmt_newt_locale_from_utf8 (priv->label);
		co = newtCompactButton (-1, -1, label_lc);
		g_free (label_lc);
	} else {
		label = g_strdup_printf (" <%s>", priv->label);
		label_lc = nmt_newt_locale_from_utf8 (label);
		co = newtLabel (-1, -1, label_lc);
		g_free (label_lc);
		newtLabelSetColors (co, NMT_NEWT_COLORSET_DISABLED_BUTTON);
	}

	return co;
}

static void
nmt_newt_button_size_request (NmtNewtWidget *widget,
                              int           *width,
                              int           *height)
{
	NMT_NEWT_WIDGET_CLASS (nmt_newt_button_parent_class)->size_request (widget, width, height);

	/* remove the automatically-added left padding */
	(*width)--;
}

static void
nmt_newt_button_size_allocate (NmtNewtWidget *widget,
                               int            x,
                               int            y,
                               int            width,
                               int            height)
{
	/* account for the automatically-added left padding */
	x--;
	width++;

	NMT_NEWT_WIDGET_CLASS (nmt_newt_button_parent_class)->size_allocate (widget, x, y, width, height);
}

static void
nmt_newt_button_activated (NmtNewtWidget *widget)
{
	g_signal_emit (widget, signals[CLICKED], 0);

	NMT_NEWT_WIDGET_CLASS (nmt_newt_button_parent_class)->activated (widget);
}

static void
nmt_newt_button_set_property (GObject      *object,
                              guint         prop_id,
                              const GValue *value,
                              GParamSpec   *pspec)
{
	switch (prop_id) {
	case PROP_LABEL:
		nmt_newt_button_set_label (NMT_NEWT_BUTTON (object),
		                           g_value_get_string (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_button_get_property (GObject    *object,
                             guint       prop_id,
                             GValue     *value,
                             GParamSpec *pspec)
{
	NmtNewtButtonPrivate *priv = NMT_NEWT_BUTTON_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_LABEL:
		g_value_set_string (value, priv->label);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_button_class_init (NmtNewtButtonClass *button_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (button_class);
	NmtNewtComponentClass *component_class = NMT_NEWT_COMPONENT_CLASS (button_class);
	NmtNewtWidgetClass *widget_class = NMT_NEWT_WIDGET_CLASS (button_class);

	g_type_class_add_private (button_class, sizeof (NmtNewtButtonPrivate));

	/* virtual methods */
	object_class->set_property = nmt_newt_button_set_property;
	object_class->get_property = nmt_newt_button_get_property;
	object_class->finalize     = nmt_newt_button_finalize;

	widget_class->size_request  = nmt_newt_button_size_request;
	widget_class->size_allocate = nmt_newt_button_size_allocate;
	widget_class->activated     = nmt_newt_button_activated;

	component_class->build_component = nmt_newt_button_build_component;

	/* signals */

	/**
	 * NmtNewtButton::clicked:
	 * @button: the #NmtNewtButton
	 *
	 * Emitted when the button is clicked.
	 */
	signals[CLICKED] =
		g_signal_new ("clicked",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	/* properties */

	/**
	 * NmtNewtButton:label:
	 *
	 * The button's label
	 */
	g_object_class_install_property
		(object_class, PROP_LABEL,
		 g_param_spec_string ("label", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
}
