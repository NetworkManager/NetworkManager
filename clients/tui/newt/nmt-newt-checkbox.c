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
 * SECTION:nmt-newt-checkbox
 * @short_description: Checkboxes
 *
 * #NmtNewtCheckbox implements a checkbox widget.
 */

#include "nm-default.h"

#include "nmt-newt-checkbox.h"
#include "nmt-newt-utils.h"

G_DEFINE_TYPE (NmtNewtCheckbox, nmt_newt_checkbox, NMT_TYPE_NEWT_COMPONENT)

#define NMT_NEWT_CHECKBOX_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_CHECKBOX, NmtNewtCheckboxPrivate))

typedef struct {
	char *label_lc;
	gboolean active;
} NmtNewtCheckboxPrivate;

enum {
	PROP_0,
	PROP_LABEL,
	PROP_ACTIVE,

	LAST_PROP
};

#define CHECKBOX_INACTIVE ' '
#define CHECKBOX_ACTIVE   'X'
#define CHECKBOX_STATES   " X"

/**
 * nmt_newt_checkbox_new:
 * @label: the (initial) checkbox label
 *
 * Creates a new checkbox.
 *
 * Returns: a new #NmtNewtCheckbox
 */
NmtNewtWidget *
nmt_newt_checkbox_new (const char *label)
{
	return g_object_new (NMT_TYPE_NEWT_CHECKBOX,
	                     "label", label,
	                     NULL);
}

/**
 * nmt_newt_checkbox_set_active:
 * @checkbox: an #NmtNewtCheckbox
 * @active: whether @checkbox should be checked
 *
 * Updates @checkbox's checked state
 */
void
nmt_newt_checkbox_set_active (NmtNewtCheckbox *checkbox,
                              gboolean         active)
{
	NmtNewtCheckboxPrivate *priv = NMT_NEWT_CHECKBOX_GET_PRIVATE (checkbox);
	newtComponent co;

	active = !!active;
	if (active == priv->active)
		return;

	priv->active = active;

	co = nmt_newt_component_get_component (NMT_NEWT_COMPONENT (checkbox));
	if (co)
		newtCheckboxSetValue (co, priv->active ? CHECKBOX_ACTIVE : CHECKBOX_INACTIVE);

	g_object_notify (G_OBJECT (checkbox), "active");
}

/**
 * nmt_newt_checkbox_get_active:
 * @checkbox: an #NmtNewtCheckbox
 *
 * Gets @checkbox's checked state
 *
 * Returns: @checkbox's checked state
 */
gboolean
nmt_newt_checkbox_get_active (NmtNewtCheckbox *checkbox)
{
	NmtNewtCheckboxPrivate *priv = NMT_NEWT_CHECKBOX_GET_PRIVATE (checkbox);

	return priv->active;
}

static void
nmt_newt_checkbox_init (NmtNewtCheckbox *checkbox)
{
}

static void
nmt_newt_checkbox_finalize (GObject *object)
{
	NmtNewtCheckboxPrivate *priv = NMT_NEWT_CHECKBOX_GET_PRIVATE (object);

	g_free (priv->label_lc);

	G_OBJECT_CLASS (nmt_newt_checkbox_parent_class)->finalize (object);
}

static void
checkbox_toggled_callback (newtComponent  co,
                           void          *checkbox)
{
	NmtNewtCheckboxPrivate *priv = NMT_NEWT_CHECKBOX_GET_PRIVATE (checkbox);
	gboolean active;

	active = (newtCheckboxGetValue (co) == CHECKBOX_ACTIVE);
	if (active != priv->active) {
		priv->active = active;
		g_object_notify (checkbox, "active");
	}
}

static newtComponent
nmt_newt_checkbox_build_component (NmtNewtComponent *component,
                                   gboolean          sensitive)
{
	NmtNewtCheckboxPrivate *priv = NMT_NEWT_CHECKBOX_GET_PRIVATE (component);
	newtComponent co;

	co = newtCheckbox (-1, -1, priv->label_lc,
	                   priv->active ? CHECKBOX_ACTIVE : CHECKBOX_INACTIVE,
	                   CHECKBOX_STATES, NULL);
	if (!sensitive)
		newtCheckboxSetFlags (co, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
	newtComponentAddCallback (co, checkbox_toggled_callback, component);
	return co;
}

static void
nmt_newt_checkbox_set_property (GObject      *object,
                                guint         prop_id,
                                const GValue *value,
                                GParamSpec   *pspec)
{
	NmtNewtCheckbox *checkbox = NMT_NEWT_CHECKBOX (object);
	NmtNewtCheckboxPrivate *priv = NMT_NEWT_CHECKBOX_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_LABEL:
		g_free (priv->label_lc);
		priv->label_lc = nmt_newt_locale_from_utf8 (g_value_get_string (value));
		break;
	case PROP_ACTIVE:
		nmt_newt_checkbox_set_active (checkbox, g_value_get_boolean (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_checkbox_get_property (GObject    *object,
                                guint       prop_id,
                                GValue     *value,
                                GParamSpec *pspec)
{
	NmtNewtCheckboxPrivate *priv = NMT_NEWT_CHECKBOX_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_LABEL:
		g_value_take_string (value, nmt_newt_locale_to_utf8 (priv->label_lc));
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
nmt_newt_checkbox_class_init (NmtNewtCheckboxClass *checkbox_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (checkbox_class);
	NmtNewtComponentClass *component_class = NMT_NEWT_COMPONENT_CLASS (checkbox_class);

	g_type_class_add_private (checkbox_class, sizeof (NmtNewtCheckboxPrivate));

	/* virtual methods */
	object_class->set_property = nmt_newt_checkbox_set_property;
	object_class->get_property = nmt_newt_checkbox_get_property;
	object_class->finalize     = nmt_newt_checkbox_finalize;

	component_class->build_component = nmt_newt_checkbox_build_component;

	/**
	 * NmtNewtCheckbox:label:
	 *
	 * The checkbox's label
	 */
	g_object_class_install_property
		(object_class, PROP_LABEL,
		 g_param_spec_string ("label", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtCheckbox:active:
	 *
	 * The checkbox's checked state
	 */
	g_object_class_install_property
		(object_class, PROP_ACTIVE,
		 g_param_spec_boolean ("active", "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));
}
