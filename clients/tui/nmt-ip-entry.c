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
 * SECTION:nmt-ip-entry
 * @short_description: #NmtNewtEntry for IP address entry
 *
 * #NmtIPEntry is an #NmtNewtEntry for entering IP addresses, or IP
 * address/prefix combination. It will only allow typing characters
 * that are valid in an IP address, and will set its
 * #NmtNewtWidget:valid property depending on whether it currently
 * contains a valid IP address.
 */

#include "nm-default.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>

#include "nmt-ip-entry.h"

G_DEFINE_TYPE (NmtIPEntry, nmt_ip_entry, NMT_TYPE_NEWT_ENTRY)

#define NMT_IP_ENTRY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_IP_ENTRY, NmtIPEntryPrivate))

typedef struct {
	int family;
	gboolean prefix;
	gboolean optional;

} NmtIPEntryPrivate;

enum {
	PROP_0,
	PROP_FAMILY,
	PROP_PREFIX,
	PROP_OPTIONAL,

	LAST_PROP
};

/**
 * nmt_ip_entry_new:
 * @width: the width of the entry
 * @family: the IP address family. Eg, %AF_INET
 * @prefix: whether to require a trailing "/prefix"
 * @optional: whether the address is optional
 *
 * Creates a new #NmtIPEntry, to accept IP addresses in the indicated
 * @family, or (if @prefix is %TRUE), to accept IP address/prefix combos.
 *
 * If @optional is %TRUE then the address is considered optional, and
 * so will still be #NmtNewtWidget:valid even when it is empty. If
 * @optional is %FALSE, the entry will be invalid when it is empty.
 */
NmtNewtWidget *
nmt_ip_entry_new (int      width,
                  int      family,
                  gboolean prefix,
                  gboolean optional)
{
	return g_object_new (NMT_TYPE_IP_ENTRY,
	                     "width", width,
	                     "family", family,
	                     "prefix", prefix,
	                     "optional", optional,
	                     NULL);
}

static gboolean
ip_entry_filter (NmtNewtEntry *entry,
                 const char   *text,
                 int           ch,
                 int           position,
                 gpointer      user_data)
{
	NmtIPEntryPrivate *priv = NMT_IP_ENTRY_GET_PRIVATE (entry);
	const char *slash;
	gboolean inaddr;

	if (g_ascii_isdigit (ch))
		return TRUE;

	slash = strchr (text, '/');
	if (ch == '/')
		return priv->prefix && slash == NULL;

	inaddr = !slash || (position <= (slash - text));

	if (priv->family == AF_INET) {
		if (ch == '.')
			return inaddr;
		else
			return FALSE;
	} else if (priv->family == AF_INET6) {
		if (g_ascii_isxdigit (ch) || ch == ':')
			return inaddr;
		else
			return FALSE;
	} else
		g_return_val_if_reached (FALSE);
}

static gboolean
ip_entry_validate (NmtNewtEntry *entry,
                   const char   *text,
                   gpointer      user_data)
{
	NmtIPEntryPrivate *priv = NMT_IP_ENTRY_GET_PRIVATE (entry);
	guchar buf[16];
	guint32 prefix;
	const char *slash;
	char *addrstr, *end;
	gboolean valid;

	if (!*text)
		return priv->optional;

	slash = strchr (text, '/');

	if (slash) {
		if (!priv->prefix)
			return FALSE;
		addrstr = g_strndup (text, slash - text);
	} else
		addrstr = g_strdup (text);
	valid = (inet_pton (priv->family, addrstr, buf) == 1);
	g_free (addrstr);

	if (!valid)
		return FALSE;

	if (slash) {
		prefix = strtoul (slash + 1, &end, 10);
		if (   *end
		    || prefix == 0
		    || (priv->family == AF_INET && prefix > 32)
		    || (priv->family == AF_INET6 && prefix > 128))
			valid = FALSE;
	}

	return valid;
}

static void
nmt_ip_entry_init (NmtIPEntry *entry)
{
	nmt_newt_entry_set_filter (NMT_NEWT_ENTRY (entry), ip_entry_filter, NULL);
	nmt_newt_entry_set_validator (NMT_NEWT_ENTRY (entry), ip_entry_validate, NULL);
}

static void
nmt_ip_entry_set_property (GObject      *object,
                           guint         prop_id,
                           const GValue *value,
                           GParamSpec   *pspec)
{
	NmtIPEntryPrivate *priv = NMT_IP_ENTRY_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_FAMILY:
		priv->family = g_value_get_int (value);
		break;
	case PROP_PREFIX:
		priv->prefix = g_value_get_boolean (value);
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
nmt_ip_entry_get_property (GObject    *object,
                           guint       prop_id,
                           GValue     *value,
                           GParamSpec *pspec)
{
	NmtIPEntryPrivate *priv = NMT_IP_ENTRY_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_FAMILY:
		g_value_set_int (value, priv->family);
		break;
	case PROP_PREFIX:
		g_value_set_boolean (value, priv->prefix);
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
nmt_ip_entry_class_init (NmtIPEntryClass *entry_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (entry_class);

	g_type_class_add_private (entry_class, sizeof (NmtIPEntryPrivate));

	/* virtual methods */
	object_class->set_property = nmt_ip_entry_set_property;
	object_class->get_property = nmt_ip_entry_get_property;

	/**
	 * NmtIPEntry:family:
	 *
	 * The address family. Eg, %AF_INET
	 */
	g_object_class_install_property
		(object_class, PROP_FAMILY,
		 g_param_spec_int ("family", "", "",
		                   0, G_MAXINT, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_CONSTRUCT_ONLY |
		                   G_PARAM_STATIC_STRINGS));
	/**
	 * NmtIPEntry:prefix:
	 *
	 * If %TRUE, the entry accepts address/prefix combinations. If
	 * %FALSE it accepts just addresses.
	 */
	g_object_class_install_property
		(object_class, PROP_PREFIX,
		 g_param_spec_boolean ("prefix", "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));
	/**
	 * NmtIPEntry:optional:
	 *
	 * If %TRUE, the entry will be #NmtNewtWidget:valid when it is
	 * empty. If %FALSE, it will only be valid when it contains a
	 * valid address or address/prefix.
	 */
	g_object_class_install_property
		(object_class, PROP_OPTIONAL,
		 g_param_spec_boolean ("optional", "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));
}
