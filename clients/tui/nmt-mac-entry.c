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
 * SECTION:nmt-mac-entry
 * @short_description: #NmtNewtEntry for hardware address entry
 *
 * #NmtMacEntry is an #NmtNewtEntry for entering hardware addresses.
 * It will only allow typing characters that are valid in a hardware
 * address, and will set its #NmtNewtWidget:valid property depending
 * on whether it currently contains a valid hardware address.
 */

#include "nm-default.h"

#include "nmt-mac-entry.h"

#include "nm-common-macros.h"

G_DEFINE_TYPE (NmtMacEntry, nmt_mac_entry, NMT_TYPE_NEWT_ENTRY)

#define NMT_MAC_ENTRY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_MAC_ENTRY, NmtMacEntryPrivate))

typedef struct {
	int mac_length;
	int mac_str_length;
	NmtMacEntryType entry_type;

} NmtMacEntryPrivate;

enum {
	PROP_0,
	PROP_MAC_LENGTH,
	PROP_MAC_ADDRESS,
	PROP_ENTRY_TYPE,

	LAST_PROP
};

/**
 * nmt_mac_entry_new:
 * @width: the width in characters of the entry
 * @mac_length: the length in bytes of the hardware address
 *   (either %ETH_ALEN or %INFINIBAND_ALEN)
 * @entry_type: the type of the entry.
 *
 * Creates a new #NmtMacEntry.
 *
 * Returns: a new #NmtMacEntry.
 */
NmtNewtWidget *
nmt_mac_entry_new (int width,
                   int mac_length,
                   NmtMacEntryType entry_type)
{
	return g_object_new (NMT_TYPE_MAC_ENTRY,
	                     "width", width,
	                     "mac-length", mac_length,
	                     "entry-type", (int) entry_type,
	                     NULL);
}

static gboolean
mac_filter (NmtNewtEntry *entry,
            const char   *text,
            int           ch,
            int           position,
            gpointer      user_data)
{
	NmtMacEntryPrivate *priv = NMT_MAC_ENTRY_GET_PRIVATE (entry);

	if (priv->entry_type != NMT_MAC_ENTRY_TYPE_MAC)
		return TRUE;

	if (position >= priv->mac_str_length)
		return FALSE;

	return g_ascii_isxdigit (ch) || ch == ':';
}

static gboolean
mac_validator (NmtNewtEntry *entry,
               const char   *text,
               gpointer      user_data)
{
	NmtMacEntryPrivate *priv = NMT_MAC_ENTRY_GET_PRIVATE (entry);
	const char *p;

	if (!*text)
		return TRUE;

	if (priv->entry_type == NMT_MAC_ENTRY_TYPE_CLONED) {
		if (NM_CLONED_MAC_IS_SPECIAL (text))
			return TRUE;
	}

	p = text;
	while (   g_ascii_isxdigit (p[0])
	       && g_ascii_isxdigit (p[1])
	       && p[2] == ':')
		p += 3;

	if (   !g_ascii_isxdigit (p[0])
	    || !g_ascii_isxdigit (p[1]))
		return FALSE;
	p += 2;

	if (!*p)
		return (p - text == priv->mac_str_length);

	if (   g_ascii_isxdigit (p[0])
	    && !p[1]
	    && p - text < priv->mac_str_length) {
		char *fixed = g_strdup_printf ("%.*s:%c", (int)(p - text), text, *p);

		nmt_newt_entry_set_text (entry, fixed);
		g_free (fixed);

		/* FIXME: NmtNewtEntry doesn't correctly deal with us calling set_text()
		 * from inside the validator.
		 */
		nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (entry));
	}

	return FALSE;
}

static void
nmt_mac_entry_init (NmtMacEntry *entry)
{
	nmt_newt_entry_set_filter (NMT_NEWT_ENTRY (entry), mac_filter, NULL);
	nmt_newt_entry_set_validator (NMT_NEWT_ENTRY (entry), mac_validator, NULL);
}

static void
nmt_mac_entry_notify (GObject    *object,
                      GParamSpec *pspec)
{
	if (G_OBJECT_CLASS (nmt_mac_entry_parent_class)->notify)
		G_OBJECT_CLASS (nmt_mac_entry_parent_class)->notify (object, pspec);

	if (pspec->owner_type == NMT_TYPE_NEWT_ENTRY && !strcmp (pspec->name, "text"))
		g_object_notify (object, "mac-address");
}

static void
nmt_mac_entry_set_property (GObject      *object,
                            guint         prop_id,
                            const GValue *value,
                            GParamSpec   *pspec)
{
	NmtMacEntryPrivate *priv = NMT_MAC_ENTRY_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MAC_LENGTH:
		priv->mac_length = g_value_get_int (value);
		priv->mac_str_length = priv->mac_length * 3 - 1;
		break;
	case PROP_MAC_ADDRESS:
		nmt_newt_entry_set_text (NMT_NEWT_ENTRY (object), g_value_get_string (value));
		break;
	case PROP_ENTRY_TYPE:
		/* construct-only */
		priv->entry_type = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_mac_entry_get_property (GObject    *object,
                            guint       prop_id,
                            GValue     *value,
                            GParamSpec *pspec)
{
	NmtMacEntryPrivate *priv = NMT_MAC_ENTRY_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MAC_LENGTH:
		g_value_set_int (value, priv->mac_length);
		break;
	case PROP_MAC_ADDRESS:
		g_value_set_string (value,
		                    nm_str_not_empty (nmt_newt_entry_get_text (NMT_NEWT_ENTRY (object))));
		break;
	case PROP_ENTRY_TYPE:
		g_value_set_int (value, priv->entry_type);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_mac_entry_class_init (NmtMacEntryClass *entry_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (entry_class);

	g_type_class_add_private (entry_class, sizeof (NmtMacEntryPrivate));

	/* virtual methods */
	object_class->notify = nmt_mac_entry_notify;
	object_class->set_property = nmt_mac_entry_set_property;
	object_class->get_property = nmt_mac_entry_get_property;

	/**
	 * NmtMacEntry:mac-length:
	 *
	 * The length in bytes of the hardware address type the entry
	 * accepts: either %ETH_ALEN or %INFINIBAND_ALEN.
	 */
	g_object_class_install_property
		(object_class, PROP_MAC_LENGTH,
		 g_param_spec_int ("mac-length", "", "",
		                   0, INFINIBAND_ALEN, ETH_ALEN,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));
	/**
	 * NmtMacEntry:mac-address:
	 *
	 * The MAC address, as a string (as with the various #NMSetting
	 * "mac-address" properties).
	 */
	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS,
		 g_param_spec_string ("mac-address", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtMacEntry:entry-type:
	 *
	 * The type of the #NmtMacEntry. Can be either used for plain
	 * MAC addresses or for the extended format for cloned MAC addresses.
	 */
	g_object_class_install_property
		(object_class, PROP_ENTRY_TYPE,
		 g_param_spec_int ("entry-type", "", "",
		                   NMT_MAC_ENTRY_TYPE_MAC, NMT_MAC_ENTRY_TYPE_CLONED, NMT_MAC_ENTRY_TYPE_MAC,
		                   G_PARAM_READWRITE |
		                   G_PARAM_CONSTRUCT_ONLY |
		                   G_PARAM_STATIC_STRINGS));
}
