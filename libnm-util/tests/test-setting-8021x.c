/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2008 - 2009 Red Hat, Inc.
 *
 */

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <string.h>

#include "nm-test-helpers.h"
#include <nm-utils.h>

#include "nm-setting-connection.h"
#include "nm-setting-8021x.h"

static void
compare_decrypted (const char *test,
                   const char *decrypted_path,
                   const GByteArray *key)
{
	char *contents = NULL;
	gsize len = 0;
	GError *error = NULL;
	gboolean success;

	success = g_file_get_contents (decrypted_path, &contents, &len, &error);
	ASSERT (success == TRUE,
	        test, "failed to read decrypted key file: %s", error->message);

	ASSERT (len > 0, test, "decrypted key file invalid (size 0)");

	ASSERT (len == key->len,
	        test, "decrypted key file (%d) and decrypted key data (%d) lengths don't match",
	        len, key->len);

	ASSERT (memcmp (contents, key->data, len) == 0,
	        test, "decrypted key file and decrypted key data don't match");

	g_free (contents);
}

static void
test_private_key_import (const char *path,
                         const char *password,
                         const char *decrypted_path,
                         NMSetting8021xCKScheme scheme)
{
	NMSetting8021x *s_8021x;
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	GError *error = NULL;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	ASSERT (s_8021x != NULL, "private-key-import", "setting was NULL");

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             path,
	                                             password,
	                                             scheme,
	                                             &format,
	                                             &error);
	ASSERT (success == TRUE,
	        "private-key-import", "error reading private key: %s", error->message);

	if (   scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB
	    && format != NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
		const GByteArray *key;

		ASSERT (decrypted_path != NULL, "private-key-import", "missing decrypted key file");

		key = nm_setting_802_1x_get_private_key_blob (s_8021x);
		ASSERT (key != NULL, "private-key-import", "missing private key blob");
		compare_decrypted ("private-key-import", decrypted_path, key);
	}

	g_object_unref (s_8021x);
}

static void
test_phase2_private_key_import (const char *path,
                                const char *password,
                                const char *decrypted_path,
                                NMSetting8021xCKScheme scheme)
{
	NMSetting8021x *s_8021x;
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	GError *error = NULL;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	ASSERT (s_8021x != NULL, "phase2-private-key-import", "setting was NULL");

	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    path,
	                                                    password,
	                                                    scheme,
	                                                    &format,
	                                                    &error);
	ASSERT (success == TRUE,
	        "phase2-private-key-import", "error reading private key: %s", error->message);

	if (   scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB
	    && format != NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
		const GByteArray *key;

		ASSERT (decrypted_path != NULL, "phase2-private-key-import", "missing decrypted key file");

		key = nm_setting_802_1x_get_phase2_private_key_blob (s_8021x);
		ASSERT (key != NULL, "phase2-private-key-import", "missing private key blob");
		compare_decrypted ("phase2-private-key-import", decrypted_path, key);
	}

	g_object_unref (s_8021x);
}

int main (int argc, char **argv)
{
	GError *error = NULL;
	DBusGConnection *bus;
	char *base;
	const char *decrypted = NULL;

	if (argc < 3)
		FAIL ("init", "need at least two arguments: <path> <password> [decrypted private key]");

	if (argc == 4)
		decrypted = argv[3];

	g_type_init ();
	bus = dbus_g_bus_get (DBUS_BUS_SESSION, NULL);

	if (!nm_utils_init (&error))
		FAIL ("nm-utils-init", "failed to initialize libnm-util: %s", error->message);

	/* The tests */
	test_private_key_import (argv[1], argv[2], NULL, NM_SETTING_802_1X_CK_SCHEME_PATH);
	test_phase2_private_key_import (argv[1], argv[2], NULL, NM_SETTING_802_1X_CK_SCHEME_PATH);

	test_private_key_import (argv[1], argv[2], decrypted, NM_SETTING_802_1X_CK_SCHEME_BLOB);
	test_phase2_private_key_import (argv[1], argv[2], decrypted, NM_SETTING_802_1X_CK_SCHEME_BLOB);

	base = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", base);
	g_free (base);
	return 0;
}

