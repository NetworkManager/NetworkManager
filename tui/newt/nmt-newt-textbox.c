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
 * SECTION:nmt-newt-textbox
 * @short_description: Multi-line text box
 *
 * #NmtNewtTextbox implements a multi-line text, optionally with
 * word-wrapping.
 */

#include "config.h"

#include <string.h>

#include "nmt-newt-textbox.h"
#include "nmt-newt-utils.h"

G_DEFINE_TYPE (NmtNewtTextbox, nmt_newt_textbox, NMT_TYPE_NEWT_COMPONENT)

#define NMT_NEWT_TEXTBOX_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_TEXTBOX, NmtNewtTextboxPrivate))

typedef struct {
	int wrap_width;
	NmtNewtTextboxFlags flags;

	char *text;
	int width, height;
} NmtNewtTextboxPrivate;

enum {
	PROP_0,
	PROP_TEXT,
	PROP_FLAGS,
	PROP_WRAP_WIDTH,

	LAST_PROP
};

/**
 * NmtNewtTextboxFlags:
 * @NMT_NEWT_TEXTBOX_SCROLLABLE: the textbox should be scollable.
 * @NMT_NEWT_TEXTBOX_SET_BACKGROUND: the textbox should have a
 *   white background
 *
 * Flags for an #NmtNewtTextbox
 */

/**
 * nmt_newt_textbox_new:
 * @flags: the textbox's flags
 * @wrap_width: width in characters at which to word-wrap, or
 *   0 to not wrap.
 *
 * Creates a new #NmtNewtTextbox.
 *
 * Returns: a new #NmtNewtTextbox
 */
NmtNewtWidget *
nmt_newt_textbox_new (NmtNewtTextboxFlags flags,
                      int                 wrap_width)
{
	return g_object_new (NMT_TYPE_NEWT_TEXTBOX,
	                     "flags", flags,
	                     "wrap-width", wrap_width,
	                     NULL);
}

/**
 * nmt_newt_textbox_get_text:
 * @textbox: an #NmtNewtTextbox
 *
 * Gets @textbox's text
 *
 * Returns: @textbox's text
 */
void
nmt_newt_textbox_set_text (NmtNewtTextbox *textbox,
                           const char     *text)
{
	NmtNewtTextboxPrivate *priv = NMT_NEWT_TEXTBOX_GET_PRIVATE (textbox);
	char **lines;
	int i, width;

	if (!text)
		text = "";
	if (!strcmp (priv->text, text))
		return;

	g_free (priv->text);
	priv->text = g_strdup (text);

	priv->width = priv->height = 0;
	lines = g_strsplit (priv->text, "\n", -1);
	for (i = 0; lines[i]; i++) {
		width = nmt_newt_text_width (lines[i]);
		if (width > priv->width)
			priv->width = width;
	}
	g_free (lines);
	priv->height = MIN (i, 1);

	g_object_notify (G_OBJECT (textbox), "text");
	nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (textbox));
}

/**
 * nmt_newt_textbox_get_text:
 * @textbox: an #NmtNewtTextbox
 *
 * Gets @textbox's text
 *
 * Returns: @textbox's text
 */
const char *
nmt_newt_textbox_get_text (NmtNewtTextbox *textbox)
{
	NmtNewtTextboxPrivate *priv = NMT_NEWT_TEXTBOX_GET_PRIVATE (textbox);

	return priv->text;
}

static void
nmt_newt_textbox_init (NmtNewtTextbox *textbox)
{
	NmtNewtTextboxPrivate *priv = NMT_NEWT_TEXTBOX_GET_PRIVATE (textbox);

	priv->text = g_strdup ("");
}

static void
nmt_newt_textbox_finalize (GObject *object)
{
	NmtNewtTextboxPrivate *priv = NMT_NEWT_TEXTBOX_GET_PRIVATE (object);

	g_free (priv->text);

	G_OBJECT_CLASS (nmt_newt_textbox_parent_class)->finalize (object);
}

static guint
convert_flags (NmtNewtTextboxFlags flags)
{
	guint newt_flags = 0;

	if (flags & NMT_NEWT_TEXTBOX_SCROLLABLE)
		newt_flags |= NEWT_FLAG_SCROLL;

	return newt_flags;
}

static newtComponent
nmt_newt_textbox_build_component (NmtNewtComponent *component,
                                gboolean          sensitive)
{
	NmtNewtTextboxPrivate *priv = NMT_NEWT_TEXTBOX_GET_PRIVATE (component);
	newtComponent co;
	const char *text;
	char *text_lc;

	text = priv->text;
	if (!*text)
		text = "\n";

	text_lc = nmt_newt_locale_from_utf8 (text);
	if (priv->wrap_width > 0) {
		co = newtTextboxReflowed (-1, -1, text_lc, priv->wrap_width, 0, 0, 0);
	} else {
		co = newtTextbox (-1, -1, priv->width, priv->height, convert_flags (priv->flags));
		newtTextboxSetText (co, text_lc);
	}
	g_free (text_lc);

	if (priv->flags & NMT_NEWT_TEXTBOX_SET_BACKGROUND)
		newtTextboxSetColors (co, NMT_NEWT_COLORSET_TEXTBOX_WITH_BACKGROUND, NEWT_COLORSET_ACTTEXTBOX);

	return co;
}

static void
nmt_newt_textbox_set_property (GObject      *object,
                               guint         prop_id,
                               const GValue *value,
                               GParamSpec   *pspec)
{
	NmtNewtTextbox *textbox = NMT_NEWT_TEXTBOX (object);
	NmtNewtTextboxPrivate *priv = NMT_NEWT_TEXTBOX_GET_PRIVATE (textbox);

	switch (prop_id) {
	case PROP_TEXT:
		nmt_newt_textbox_set_text (textbox, g_value_get_string (value));
		break;
	case PROP_FLAGS:
		priv->flags = g_value_get_uint (value);
		break;
	case PROP_WRAP_WIDTH:
		priv->wrap_width = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_textbox_get_property (GObject    *object,
                               guint       prop_id,
                               GValue     *value,
                               GParamSpec *pspec)
{
	NmtNewtTextboxPrivate *priv = NMT_NEWT_TEXTBOX_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_TEXT:
		g_value_set_string (value, priv->text);
		break;
	case PROP_FLAGS:
		g_value_set_uint (value, priv->flags);
		break;
	case PROP_WRAP_WIDTH:
		g_value_set_int (value, priv->wrap_width);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_textbox_class_init (NmtNewtTextboxClass *textbox_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (textbox_class);
	NmtNewtComponentClass *component_class = NMT_NEWT_COMPONENT_CLASS (textbox_class);

	g_type_class_add_private (textbox_class, sizeof (NmtNewtTextboxPrivate));

	/* virtual methods */
	object_class->set_property = nmt_newt_textbox_set_property;
	object_class->get_property = nmt_newt_textbox_get_property;
	object_class->finalize     = nmt_newt_textbox_finalize;

	component_class->build_component = nmt_newt_textbox_build_component;

	/**
	 * NmtNewtTextbox:text:
	 *
	 * The textbox's text
	 */
	g_object_class_install_property (object_class, PROP_TEXT,
	                                 g_param_spec_string ("text", "", "",
	                                                      "",
	                                                      G_PARAM_READWRITE |
	                                                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtTextbox:flags:
	 *
	 * The textbox's flags
	 */
	g_object_class_install_property (object_class, PROP_FLAGS,
	                                 g_param_spec_uint ("flags", "", "",
	                                                    0, G_MAXUINT, 0,
	                                                    G_PARAM_READWRITE |
	                                                    G_PARAM_CONSTRUCT_ONLY |
	                                                    G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtTextbox:wrap-width:
	 *
	 * The width in characters at which the textbox's text
	 * will wrap, or 0 if it does not wrap.
	 */
	g_object_class_install_property (object_class, PROP_WRAP_WIDTH,
	                                 g_param_spec_int ("wrap-width", "", "",
	                                                   0, G_MAXINT, 0,
	                                                   G_PARAM_READWRITE |
	                                                   G_PARAM_CONSTRUCT_ONLY |
	                                                   G_PARAM_STATIC_STRINGS));
}
