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
 * SECTION:nmt-mtu-entry
 * @short_description: #NmtNewtEntry for MTU entry
 *
 * #NmtMtuEntry is an #NmtNewtEntry for entering MTU values. It will
 * only allow typing numeric characters, and will set its
 * #NmtNewtWidget:valid property depending on whether it currently
 * contains a valid MTU.
 *
 * The entry also has an attached #NmtNewtLabel. When the entry value
 * is "0", the label will read "(default)". Otherwise it reads "bytes",
 * indicating the units used by the entry.
 */

#include "config.h"

#include <stdlib.h>

#include "nmt-mtu-entry.h"

G_DEFINE_TYPE (NmtMtuEntry, nmt_mtu_entry, NMT_TYPE_NEWT_GRID)

#define NMT_MTU_ENTRY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_MTU_ENTRY, NmtMtuEntryPrivate))

typedef struct {
	int mtu;

	NmtNewtEntry *entry;
	NmtNewtLabel *label;

} NmtMtuEntryPrivate;

enum {
	PROP_0,
	PROP_MTU,

	LAST_PROP
};

/**
 * nmt_mtu_entry_new:
 *
 * Creates a new #NmtMtuEntry
 *
 * Returns: a new #NmtMtuEntry
 */
NmtNewtWidget *
nmt_mtu_entry_new (void)
{
	return g_object_new (NMT_TYPE_MTU_ENTRY, NULL);
}

static gboolean
mtu_validator (NmtNewtEntry *entry,
               const char   *text,
               gpointer      user_data)
{
	NmtMtuEntryPrivate *priv = NMT_MTU_ENTRY_GET_PRIVATE (user_data);

	if (*text && !atoi (text)) {
		nmt_newt_entry_set_text (entry, "");
		text = "";
	}

	if (!*text)
		nmt_newt_label_set_text (priv->label, _("(default)"));
	else
		nmt_newt_label_set_text (priv->label, _("bytes"));

	return TRUE;
}

static gboolean
mtu_transform_to_text (GBinding     *binding,
                       const GValue *source_value,
                       GValue       *target_value,
                       gpointer      user_data)
{
	int mtu = g_value_get_int (source_value);

	if (mtu)
		g_value_transform (source_value, target_value);
	else
		g_value_set_string (target_value, "");
	return TRUE;
}

static void
nmt_mtu_entry_init (NmtMtuEntry *entry)
{

	NmtMtuEntryPrivate *priv = NMT_MTU_ENTRY_GET_PRIVATE (entry);
	NmtNewtGrid *grid = NMT_NEWT_GRID (entry);
	NmtNewtWidget *real_entry, *label;

	real_entry = nmt_newt_entry_numeric_new (10, 0, 65535);
	priv->entry = NMT_NEWT_ENTRY (real_entry);

	label = nmt_newt_label_new (_("bytes"));
	priv->label = NMT_NEWT_LABEL (label);

	nmt_newt_grid_add (grid, real_entry, 0, 0);
	nmt_newt_grid_add (grid, label, 1, 0);
	nmt_newt_widget_set_padding (label, 1, 0, 0, 0);

	nmt_newt_entry_set_validator (priv->entry, mtu_validator, entry);
	g_object_bind_property_full (entry, "mtu", real_entry, "text",
	                             G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE,
	                             mtu_transform_to_text,
	                             NULL,
	                             NULL, NULL);
}

static void
nmt_mtu_entry_set_property (GObject      *object,
                            guint         prop_id,
                            const GValue *value,
                            GParamSpec   *pspec)
{
	NmtMtuEntryPrivate *priv = NMT_MTU_ENTRY_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MTU:
		priv->mtu = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_mtu_entry_get_property (GObject    *object,
                            guint       prop_id,
                            GValue     *value,
                            GParamSpec *pspec)
{
	NmtMtuEntryPrivate *priv = NMT_MTU_ENTRY_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MTU:
		g_value_set_int (value, priv->mtu);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_mtu_entry_class_init (NmtMtuEntryClass *entry_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (entry_class);

	g_type_class_add_private (entry_class, sizeof (NmtMtuEntryPrivate));

	/* virtual methods */
	object_class->set_property = nmt_mtu_entry_set_property;
	object_class->get_property = nmt_mtu_entry_get_property;

	/**
	 * NmtMtuEntry:mtu:
	 *
	 * The contents of the entry, as a number.
	 */
	g_object_class_install_property
		(object_class, PROP_MTU,
		 g_param_spec_int ("mtu", "", "",
		                   0, G_MAXINT, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));
}
