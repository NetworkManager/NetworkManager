/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2009 - 2010 Red Hat, Inc.
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <glib.h>
#include <dbus/dbus-glib.h>
#include "config.h"

#include <nm-setting-8021x.h>
#include <nm-setting-bluetooth.h>
#include <nm-setting-cdma.h>
#include <nm-setting-connection.h>
#include <nm-setting-gsm.h>
#include <nm-setting.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-olpc-mesh.h>
#include <nm-setting-ppp.h>
#include <nm-setting-pppoe.h>
#include <nm-setting-serial.h>
#include <nm-setting-vpn.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>

#include <nm-utils.h>

typedef NMSetting* (*SettingNewFunc) (void);

static SettingNewFunc funcs[] = {
	nm_setting_802_1x_new,
	nm_setting_bluetooth_new,
	nm_setting_cdma_new,
	nm_setting_connection_new,
	nm_setting_gsm_new,
	nm_setting_ip4_config_new,
	nm_setting_ip6_config_new,
	nm_setting_olpc_mesh_new,
	nm_setting_ppp_new,
	nm_setting_pppoe_new,
	nm_setting_serial_new,
	nm_setting_vpn_new,
	nm_setting_wired_new,
	nm_setting_wireless_new,
	nm_setting_wireless_security_new,
	NULL
};

typedef struct {
	const char *gvalue_name;
	const char *new_name;
} TypeNameElement;

static TypeNameElement name_map[] = {
	{ "gchararray", "string" },
	{ "GSList_gchararray_", "array of string" },
	{ "GArray_guchar_", "byte array" },
	{ "gboolean", "boolean" },
	{ "guint64", "uint64" },
	{ "gint", "int32" },
	{ "guint", "uint32" },
	{ "GArray_guint_", "array of uint32" },
	{ "GPtrArray_GArray_guint__", "array of array of uint32" },
	{ "GPtrArray_GArray_guchar__", "array of byte array" },
	{ "GHashTable_gchararray+gchararray_", "dict of (string::string)" },
	{ "GPtrArray_GValueArray_GArray_guchar_+guint+GArray_guchar___", "array of (byte array, uint32, byte array)" },
	{ "GPtrArray_GValueArray_GArray_guchar_+guint+GArray_guchar_+guint__", "array of (byte array, uint32, byte array, uint32)" },
	{ NULL, NULL }
};

static void
write_one_setting (FILE *f, SettingNewFunc func)
{
	int w;
	NMSetting *s;
	GParamSpec **props, **iter;
	guint num;

	s = func ();

	/* write out section header */
	w = fprintf (f, "<p><h2>Setting name: '%s'</h2></p>\n", nm_setting_get_name (s));

	w = fprintf (f, "<table cellspacing=10 border=0 cellpadding=2>\n");
	w = fprintf (f, "<th align=left>Key Name</th>\n");
	w = fprintf (f, "<th align=left>Value Type</th>\n");
	w = fprintf (f, "<th align=left>Default Value</th>\n");
	w = fprintf (f, "<th align=left>Value Description</th>\n");
	props = g_object_class_list_properties (G_OBJECT_GET_CLASS (G_OBJECT (s)), &num);
	for (iter = props; iter && *iter; iter++) {
		const char *key_name, *value_type, *value_desc;
		char *default_value;
		TypeNameElement *name_iter;
		GValue value = { 0, };

		value_type = g_type_name (G_PARAM_SPEC_VALUE_TYPE (*iter));
		for (name_iter = &name_map[0]; name_iter && name_iter->gvalue_name; name_iter++) {
			if (!strcmp (value_type, name_iter->gvalue_name)) {
				value_type = name_iter->new_name;
				break;
			}
		}

		key_name = g_param_spec_get_name (*iter);
		value_desc = g_param_spec_get_blurb (*iter);

		g_value_init (&value, G_PARAM_SPEC_VALUE_TYPE (*iter));
		g_param_value_set_default (*iter, &value);
		default_value = g_strdup_value_contents (&value);
		if (default_value && !strcmp (default_value, "NULL")) {
			g_free (default_value);
			default_value = NULL;
		}

		if (!strcmp (key_name, NM_SETTING_NAME)) {
			g_free (default_value);
			default_value = NULL;
			g_object_get (G_OBJECT (s), NM_SETTING_NAME, &default_value, NULL);
		}

		w = fprintf (f, "<tr align=left valign=top>\n");
		w = fprintf (f, "<td><strong>%s</strong></td>\n", key_name);
		w = fprintf (f, "<td>%s</td>\n", value_type);
		w = fprintf (f, "<td>%s</td>\n", default_value ? default_value : "");
		w = fprintf (f, "<td>%s</td>\n", value_desc);
		w = fprintf (f, "</tr>\n");

		g_free (default_value);
	}

	w = fprintf (f, "</table><br/>\n");
	g_object_unref (s);
}

int
main (int argc, char *argv[])
{
	GError *error = NULL;
	FILE *f;
	int w;
	SettingNewFunc *fptr;

	if (argc != 2) {
		fprintf (stderr, "Usage: %s <output file>\n", argv[0]);
		_exit (1);
	}

	g_type_init ();

	if (!nm_utils_init (&error)) {
		fprintf (stderr, "ERR: failed to initialize libnm-util: %s", error->message);
		_exit (2);
	}

	f = fopen (argv[1], "w");
	if (!f) {
		fprintf (stderr, "ERR: could not create %s: %d\n", argv[1], errno);
		_exit (3);
	}

	w = fprintf (f, "<html>\n<head>\n");
	w = fprintf (f, "<title>NetworkManager " PACKAGE_VERSION " Settings Specification</title>");
	w = fprintf (f, "</head>\n<body>\n");

	for (fptr = funcs; fptr && *fptr; fptr++)
		write_one_setting (f, *fptr);

	w = fprintf (f, "</body>\n</html>\n");

	fclose (f);
	_exit (0);
}

