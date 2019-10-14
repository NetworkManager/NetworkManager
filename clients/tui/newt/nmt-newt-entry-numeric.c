// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
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
	gint64 min, max;
	bool optional;
} NmtNewtEntryNumericPrivate;

enum {
	PROP_0,
	PROP_MINIMUM,
	PROP_MAXIMUM,
	PROP_OPTIONAL,

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
                            gint64 min,
                            gint64 max)
{
	return nmt_newt_entry_numeric_new_full (width,
	                                        min,
	                                        max,
	                                        FALSE);
}

/**
 * nmt_newt_entry_numeric_new_full:
 * @width: the entry's width in characters
 * @min: the minimum valid value
 * @max: the maximum valid value
 * @optional: whether an empty entry is valid
 *
 * Creates a new #NmtNewtEntryNumeric, accepting values in the
 * indicated range.
 *
 * Returns: a new #NmtNewtEntryNumeric
 */
NmtNewtWidget *
nmt_newt_entry_numeric_new_full (int width,
                                 gint64 min,
                                 gint64 max,
                                 gboolean optional)
{
	return g_object_new (NMT_TYPE_NEWT_ENTRY_NUMERIC,
	                     "width", width,
	                     "minimum", min,
	                     "maximum", max,
	                     "optional", optional,
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
	gint64 val;

	if (!*text)
		return priv->optional ? TRUE : FALSE;

	val = _nm_utils_ascii_str_to_int64 (text, 10, priv->min, priv->max, G_MAXINT64);
	return val != G_MAXINT64 || errno == 0;
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

		g_snprintf (buf, sizeof (buf), "%lld", (long long) priv->min);
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
		priv->min = g_value_get_int64 (value);
		break;
	case PROP_MAXIMUM:
		priv->max = g_value_get_int64 (value);
		break;
	case PROP_OPTIONAL:
		priv->optional = g_value_get_boolean (value);
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
		g_value_set_int64 (value, priv->min);
		break;
	case PROP_MAXIMUM:
		g_value_set_int64 (value, priv->max);
		break;
	case PROP_OPTIONAL:
		g_value_set_boolean (value, priv->optional);
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
		 g_param_spec_int64 ("minimum", "", "",
		                     G_MININT64, G_MAXINT64, 0,
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
		 g_param_spec_int64 ("maximum", "", "",
		                     G_MININT64, G_MAXINT64, G_MAXINT64,
		                     G_PARAM_READWRITE |
		                     G_PARAM_CONSTRUCT_ONLY |
		                     G_PARAM_STATIC_STRINGS));
	/**
	 * NmtNewtEntryNumeric:optional:
	 *
	 * If %TRUE, allow empty string to indicate some default value.
	 * It means the property is optional and can be left at the default
	 */
	g_object_class_install_property
		(object_class, PROP_OPTIONAL,
		 g_param_spec_boolean ("optional", "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));
}
