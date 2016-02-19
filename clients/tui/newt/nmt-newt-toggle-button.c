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
 * SECTION:nmt-newt-toggle-button
 * @short_description: Toggle buttons
 *
 * #NmtNewtToggleButton implements a two-state toggle button.
 */

#include "nm-default.h"

#include "nmt-newt-toggle-button.h"

G_DEFINE_TYPE (NmtNewtToggleButton, nmt_newt_toggle_button, NMT_TYPE_NEWT_BUTTON)

#define NMT_NEWT_TOGGLE_BUTTON_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_TOGGLE_BUTTON, NmtNewtToggleButtonPrivate))

typedef struct {
	char *on_label, *off_label;
	gboolean active;
} NmtNewtToggleButtonPrivate;

enum {
	PROP_0,
	PROP_ON_LABEL,
	PROP_OFF_LABEL,
	PROP_ACTIVE,

	LAST_PROP
};

/**
 * nmt_newt_toggle_button_new:
 * @on_label: the button's label when it is in the "on" state
 * @off_label: the button's label when it is in the "off" state
 *
 * Creates a new #NmtNewtToggleButton
 *
 * Returns: a new #NmtNewtToggleButton
 */
NmtNewtWidget *
nmt_newt_toggle_button_new (const char *on_label,
                            const char *off_label)
{
	return g_object_new (NMT_TYPE_NEWT_TOGGLE_BUTTON,
	                     "on-label", on_label,
	                     "off-label", off_label,
	                     NULL);
}

/**
 * nmt_newt_toggle_button_get_active:
 * @button: an #NmtNewtToggleButton
 *
 * Gets whether @button is currently "on" or "off"
 *
 * Returns: whether @button is currently "on" (%TRUE) or "off" (%FALSE)
 */
gboolean
nmt_newt_toggle_button_get_active (NmtNewtToggleButton *button)
{
	NmtNewtToggleButtonPrivate *priv = NMT_NEWT_TOGGLE_BUTTON_GET_PRIVATE (button);

	return priv->active;
}

/**
 * nmt_newt_toggle_button_set_active:
 * @button: an #NmtNewtToggleButton
 * @active: whether @button should be "on" or "off"
 *
 * Sets whether @button is currently "on" or "off"
 */
void
nmt_newt_toggle_button_set_active (NmtNewtToggleButton *button,
                                   gboolean             active)
{
	NmtNewtToggleButtonPrivate *priv = NMT_NEWT_TOGGLE_BUTTON_GET_PRIVATE (button);

	if (priv->active == active)
		return;

	priv->active = active;
	g_object_set (G_OBJECT (button),
	              "label", active ? priv->on_label : priv->off_label,
	              NULL);
	g_object_notify (G_OBJECT (button), "active");
}

static void
nmt_newt_toggle_button_init (NmtNewtToggleButton *button)
{
}

static void
nmt_newt_toggle_button_finalize (GObject *object)
{
	NmtNewtToggleButtonPrivate *priv = NMT_NEWT_TOGGLE_BUTTON_GET_PRIVATE (object);

	g_free (priv->on_label);
	g_free (priv->off_label);

	G_OBJECT_CLASS (nmt_newt_toggle_button_parent_class)->finalize (object);
}

static void
nmt_newt_toggle_button_activated (NmtNewtWidget *widget)
{
	NmtNewtToggleButton *button = NMT_NEWT_TOGGLE_BUTTON (widget);

	nmt_newt_toggle_button_set_active (button, !nmt_newt_toggle_button_get_active (button));

	NMT_NEWT_WIDGET_CLASS (nmt_newt_toggle_button_parent_class)->activated (widget);
}

static void
nmt_newt_toggle_button_set_property (GObject      *object,
                                     guint         prop_id,
                                     const GValue *value,
                                     GParamSpec   *pspec)
{
	NmtNewtToggleButtonPrivate *priv = NMT_NEWT_TOGGLE_BUTTON_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_ON_LABEL:
		g_free (priv->on_label);
		priv->on_label = g_value_dup_string (value);
		if (priv->active)
			g_object_set (object, "label", priv->on_label, NULL);
		break;
	case PROP_OFF_LABEL:
		g_free (priv->off_label);
		priv->off_label = g_value_dup_string (value);
		if (!priv->active)
			g_object_set (object, "label", priv->off_label, NULL);
		break;
	case PROP_ACTIVE:
		priv->active = g_value_get_boolean (value);
		g_object_set (object,
		              "label", priv->active ? priv->on_label : priv->off_label,
		              NULL);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_toggle_button_get_property (GObject    *object,
                                     guint       prop_id,
                                     GValue     *value,
                                     GParamSpec *pspec)
{
	NmtNewtToggleButtonPrivate *priv = NMT_NEWT_TOGGLE_BUTTON_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_ON_LABEL:
		g_value_set_string (value, priv->on_label);
		break;
	case PROP_OFF_LABEL:
		g_value_set_string (value, priv->off_label);
		break;
	case PROP_ACTIVE:
		g_value_set_boolean (value, priv->active);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_toggle_button_class_init (NmtNewtToggleButtonClass *button_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (button_class);
	NmtNewtWidgetClass *widget_class = NMT_NEWT_WIDGET_CLASS (button_class);

	g_type_class_add_private (button_class, sizeof (NmtNewtToggleButtonPrivate));

	/* virtual methods */
	object_class->set_property = nmt_newt_toggle_button_set_property;
	object_class->get_property = nmt_newt_toggle_button_get_property;
	object_class->finalize     = nmt_newt_toggle_button_finalize;

	widget_class->activated = nmt_newt_toggle_button_activated;

	/**
	 * NmtNewtToggleButton:on-label:
	 *
	 * The label the button displays when it is "on".
	 */
	g_object_class_install_property
		(object_class, PROP_ON_LABEL,
		 g_param_spec_string ("on-label", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtToggleButton:off-label:
	 *
	 * The label the button displays when it is "off".
	 */
	g_object_class_install_property
		(object_class, PROP_OFF_LABEL,
		 g_param_spec_string ("off-label", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtToggleButton:active:
	 *
	 * Whether the button is currently "on" (%TRUE) or "off" (%FALSE)
	 */
	g_object_class_install_property
		(object_class, PROP_ACTIVE,
		 g_param_spec_boolean ("active", "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));
}
