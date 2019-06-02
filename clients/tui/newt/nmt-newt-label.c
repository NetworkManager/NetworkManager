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
 * SECTION:nmt-newt-label
 * @short_description: Labels
 *
 * #NmtNewtLabel implements a single-line label.
 *
 * See also #NmtNewtTextbox, for multiline.
 */

#include "nm-default.h"

#include "nmt-newt-label.h"

#include "nmt-newt-utils.h"

G_DEFINE_TYPE (NmtNewtLabel, nmt_newt_label, NMT_TYPE_NEWT_COMPONENT)

#define NMT_NEWT_LABEL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_LABEL, NmtNewtLabelPrivate))

typedef struct {
	char *text;
	NmtNewtLabelStyle style;
	gboolean highlight;
} NmtNewtLabelPrivate;

enum {
	PROP_0,
	PROP_TEXT,
	PROP_STYLE,
	PROP_HIGHLIGHT,

	LAST_PROP
};

/**
 * nmt_newt_label_new:
 * @text: the initial label text
 *
 * Creates a new #NmtNewtLabel
 *
 * Returns: a new #NmtNewtLabel
 */
NmtNewtWidget *
nmt_newt_label_new (const char *text)
{
	return g_object_new (NMT_TYPE_NEWT_LABEL,
	                     "text", text,
	                     NULL);
}

/**
 * nmt_newt_label_set_text:
 * @label: an #NmtNewtLabel
 * @text: the new text
 *
 * Updates @label's text.
 */
void
nmt_newt_label_set_text (NmtNewtLabel *label,
                         const char   *text)
{
	NmtNewtLabelPrivate *priv = NMT_NEWT_LABEL_GET_PRIVATE (label);

	if (!g_strcmp0 (priv->text, text))
		return;

	g_free (priv->text);
	priv->text = g_strdup (text);

	g_object_notify (G_OBJECT (label), "text");
	nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (label));
}

/**
 * nmt_newt_label_get_text:
 * @label: an #NmtNewtLabel
 *
 * Gets @label's text
 *
 * Returns: @label's text
 */
const char *
nmt_newt_label_get_text (NmtNewtLabel *label)
{
	NmtNewtLabelPrivate *priv = NMT_NEWT_LABEL_GET_PRIVATE (label);

	return priv->text;
}

/**
 * NmtNewtLabelStyle:
 * @NMT_NEWT_LABEL_NORMAL: a normal label
 * @NMT_NEWT_LABEL_PLAIN: a "plain-looking" label
 *
 * The label style. Normal labels are blue. Plain labels are black,
 * making them look more like they are text in their own right rather
 * than just being a label for something else.
 */

/**
 * nmt_newt_label_set_style:
 * @label: an #NmtNewtLabel
 * @style: the #NmtNewtLabelStyle
 *
 * Sets the style of @label
 */
void
nmt_newt_label_set_style (NmtNewtLabel      *label,
                          NmtNewtLabelStyle  style)
{
	NmtNewtLabelPrivate *priv = NMT_NEWT_LABEL_GET_PRIVATE (label);

	if (priv->style == style)
		return;

	priv->style = style;
	g_object_notify (G_OBJECT (label), "style");
	nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (label));
}

/**
 * nmt_newt_label_get_style:
 * @label: an #NmtNewtLabel
 *
 * Gets the style of @label
 *
 * Returns: the style of @label
 */
NmtNewtLabelStyle
nmt_newt_label_get_style (NmtNewtLabel *label)
{
	NmtNewtLabelPrivate *priv = NMT_NEWT_LABEL_GET_PRIVATE (label);

	return priv->style;
}

/**
 * nmt_newt_label_set_highlight:
 * @label: an #NmtNewtLabel
 * @highlight: %TRUE if @label should be highlighted
 *
 * Sets whether @label is highlighted. Highlighted labels are red;
 * this is generally used to highlight invalid widgets.
 */
void
nmt_newt_label_set_highlight (NmtNewtLabel *label,
                              gboolean      highlight)
{
	NmtNewtLabelPrivate *priv = NMT_NEWT_LABEL_GET_PRIVATE (label);

	highlight = !!highlight;
	if (priv->highlight == highlight)
		return;

	priv->highlight = highlight;
	g_object_notify (G_OBJECT (label), "highlight");
	nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (label));
}

/**
 * nmt_newt_label_get_highlight:
 * @label: an #NmtNewtLabel
 *
 * Gets whether @label is highlighted.
 *
 * Returns: whether @label is highlighted.
 */
gboolean
nmt_newt_label_get_highlight (NmtNewtLabel *label)
{
	NmtNewtLabelPrivate *priv = NMT_NEWT_LABEL_GET_PRIVATE (label);

	return priv->highlight;
}

static void
nmt_newt_label_init (NmtNewtLabel *label)
{
}

static void
nmt_newt_label_finalize (GObject *object)
{
	NmtNewtLabelPrivate *priv = NMT_NEWT_LABEL_GET_PRIVATE (object);

	g_free (priv->text);

	G_OBJECT_CLASS (nmt_newt_label_parent_class)->finalize (object);
}

static newtComponent
nmt_newt_label_build_component (NmtNewtComponent *component,
                                gboolean          sensitive)
{
	NmtNewtLabelPrivate *priv = NMT_NEWT_LABEL_GET_PRIVATE (component);
	newtComponent co;
	char *text_lc;

	text_lc = nmt_newt_locale_from_utf8 (priv->text);
	co = newtLabel (-1, -1, text_lc);
	g_free (text_lc);

	if (priv->highlight)
		newtLabelSetColors (co, NMT_NEWT_COLORSET_BAD_LABEL);
	else if (priv->style == NMT_NEWT_LABEL_PLAIN)
		newtLabelSetColors (co, NMT_NEWT_COLORSET_PLAIN_LABEL);

	return co;
}

static void
nmt_newt_label_set_property (GObject      *object,
                             guint         prop_id,
                             const GValue *value,
                             GParamSpec   *pspec)
{
	NmtNewtLabel *label = NMT_NEWT_LABEL (object);

	switch (prop_id) {
	case PROP_TEXT:
		nmt_newt_label_set_text (label, g_value_get_string (value));
		break;
	case PROP_STYLE:
		nmt_newt_label_set_style (label, g_value_get_int (value));
		break;
	case PROP_HIGHLIGHT:
		nmt_newt_label_set_highlight (label, g_value_get_boolean (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_label_get_property (GObject    *object,
                             guint       prop_id,
                             GValue     *value,
                             GParamSpec *pspec)
{
	NmtNewtLabelPrivate *priv = NMT_NEWT_LABEL_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_TEXT:
		g_value_set_string (value, priv->text);
		break;
	case PROP_STYLE:
		g_value_set_int (value, priv->style);
		break;
	case PROP_HIGHLIGHT:
		g_value_set_boolean (value, priv->highlight);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_label_class_init (NmtNewtLabelClass *label_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (label_class);
	NmtNewtComponentClass *component_class = NMT_NEWT_COMPONENT_CLASS (label_class);

	g_type_class_add_private (label_class, sizeof (NmtNewtLabelPrivate));

	/* virtual methods */
	object_class->set_property = nmt_newt_label_set_property;
	object_class->get_property = nmt_newt_label_get_property;
	object_class->finalize     = nmt_newt_label_finalize;

	component_class->build_component = nmt_newt_label_build_component;

	/**
	 * NmtNewtLabel:text:
	 *
	 * The label's text
	 */
	g_object_class_install_property
		(object_class, PROP_TEXT,
		 g_param_spec_string ("text", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtLabel:style:
	 *
	 * The label's #NmtNewtLabelStyle
	 */
	g_object_class_install_property
		(object_class, PROP_STYLE,
		 g_param_spec_int ("style", "", "",
		                   0, G_MAXINT, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtLabel:highlight:
	 *
	 * Whether the label is highlighted.
	 */
	g_object_class_install_property
		(object_class, PROP_HIGHLIGHT,
		 g_param_spec_boolean ("highlight", "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));
}
