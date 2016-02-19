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
 * SECTION:nmt-newt-entry-numeric
 * @short_description: Numeric text entry
 *
 * #NmtNewtEntryNumeric implements a numeric-only #NmtNewtEntry.
 *
 * #NmtNewtEntryNumeric provides its own #NmtNewtEntryFilter and
 * #NmtNewtEntryValidator functions, so you should not set your own.
 */

#include "nm-default.h"

#include <stdlib.h>

#include "nmt-newt-entry-numeric.h"

G_DEFINE_TYPE (NmtNewtEntryNumeric, nmt_newt_entry_numeric, NMT_TYPE_NEWT_ENTRY)

#define NMT_NEWT_ENTRY_NUMERIC_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_ENTRY_NUMERIC, NmtNewtEntryNumericPrivate))

typedef struct {
	int min, max;
} NmtNewtEntryNumericPrivate;

enum {
	PROP_0,
	PROP_MINIMUM,
	PROP_MAXIMUM,

	LAST_PROP
};

/**
 * nmt_newt_entry_numeric_new:
 * @width: the entry's width in characters
 * @min: the minimum valid value
 * @max: the maximum valid value
 *
 * Creates a new #NmtNewtEntryNumeric, accepting values in the
 * indicated range.
 *
 * Returns: a new #NmtNewtEntryNumeric
 */
NmtNewtWidget *
nmt_newt_entry_numeric_new (int width,
                            int min,
                            int max)
{
	return g_object_new (NMT_TYPE_NEWT_ENTRY_NUMERIC,
	                     "width", width,
	                     "minimum", min,
	                     "maximum", max,
	                     NULL);
}

static gboolean
newt_entry_numeric_filter (NmtNewtEntry *entry,
                           const char   *text,
                           int           ch,
                           int           position,
                           gpointer      user_data)
{
	NmtNewtEntryNumericPrivate *priv = NMT_NEWT_ENTRY_NUMERIC_GET_PRIVATE (entry);

	if (g_ascii_isdigit (ch))
		return TRUE;

	if (ch == '-' && position == 0 && priv->min < 0)
		return TRUE;

	return FALSE;
}

static gboolean
newt_entry_numeric_validate (NmtNewtEntry *entry,
                             const char   *text,
                             gpointer      user_data)
{
	NmtNewtEntryNumericPrivate *priv = NMT_NEWT_ENTRY_NUMERIC_GET_PRIVATE (entry);
	int val;
	char *end;

	if (!*text)
		return FALSE;

	val = strtoul (text, &end, 10);
	if (*end)
		return FALSE;
	if (val < priv->min || val > priv->max)
		return FALSE;

	return TRUE;
}

static void
nmt_newt_entry_numeric_init (NmtNewtEntryNumeric *entry)
{
	nmt_newt_entry_set_filter (NMT_NEWT_ENTRY (entry), newt_entry_numeric_filter, NULL);
	nmt_newt_entry_set_validator (NMT_NEWT_ENTRY (entry), newt_entry_numeric_validate, NULL);
}

static void
nmt_newt_entry_numeric_constructed (GObject *object)
{
	NmtNewtEntryNumericPrivate *priv = NMT_NEWT_ENTRY_NUMERIC_GET_PRIVATE (object);

	if (!*nmt_newt_entry_get_text (NMT_NEWT_ENTRY (object))) {
		char buf[32];

		g_snprintf (buf, sizeof (buf), "%d", priv->min);
		nmt_newt_entry_set_text (NMT_NEWT_ENTRY (object), buf);
	}

	G_OBJECT_CLASS (nmt_newt_entry_numeric_parent_class)->constructed (object);
}

static void
nmt_newt_entry_numeric_set_property (GObject      *object,
                                     guint         prop_id,
                                     const GValue *value,
                                     GParamSpec   *pspec)
{
	NmtNewtEntryNumericPrivate *priv = NMT_NEWT_ENTRY_NUMERIC_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MINIMUM:
		priv->min = g_value_get_int (value);
		break;
	case PROP_MAXIMUM:
		priv->max = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_entry_numeric_get_property (GObject    *object,
                                     guint       prop_id,
                                     GValue     *value,
                                     GParamSpec *pspec)
{
	NmtNewtEntryNumericPrivate *priv = NMT_NEWT_ENTRY_NUMERIC_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MINIMUM:
		g_value_set_int (value, priv->min);
		break;
	case PROP_MAXIMUM:
		g_value_set_int (value, priv->max);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_newt_entry_numeric_class_init (NmtNewtEntryNumericClass *entry_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (entry_class);

	g_type_class_add_private (entry_class, sizeof (NmtNewtEntryNumericPrivate));

	/* virtual methods */
	object_class->constructed = nmt_newt_entry_numeric_constructed;
	object_class->set_property = nmt_newt_entry_numeric_set_property;
	object_class->get_property = nmt_newt_entry_numeric_get_property;

	/**
	 * NmtNewtEntryNumeric:minimum:
	 *
	 * The minimum #NmtNewtWidget:valid value for the entry. If this
	 * is non-negative, then the entry will not allow negative numbers
	 * to be entered.
	 */
	g_object_class_install_property
		(object_class, PROP_MINIMUM,
		 g_param_spec_int ("minimum", "", "",
		                   G_MININT, G_MAXINT, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_CONSTRUCT_ONLY |
		                   G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtEntryNumeric:maximum:
	 *
	 * The maximum #NmtNewtWidget:valid value for the entry.
	 */
	g_object_class_install_property
		(object_class, PROP_MAXIMUM,
		 g_param_spec_int ("maximum", "", "",
		                   G_MININT, G_MAXINT, G_MAXINT,
		                   G_PARAM_READWRITE |
		                   G_PARAM_CONSTRUCT_ONLY |
		                   G_PARAM_STATIC_STRINGS));
}
