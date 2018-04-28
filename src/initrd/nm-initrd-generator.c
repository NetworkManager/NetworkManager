/* NetworkManager initrd configuration generator
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
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nm-core-utils.h"
#include "nm-core-internal.h"
#include "nm-keyfile-internal.h"

#include "nm-initrd-generator.h"

/*****************************************************************************/

#define _NMLOG(level, domain, ...) \
    nm_log ((level), (domain), NULL, NULL, \
            "initrd-generator: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) \
            _NM_UTILS_MACRO_REST (__VA_ARGS__))

/*****************************************************************************/

static void
output_conn (gpointer key, gpointer value, gpointer user_data)
{
	const char *basename = key;
	NMConnection *connection = value;
	char *connections_dir = user_data;
	GKeyFile *file;
	gs_free char *data = NULL;
	GError *error = NULL;
	gsize len;

	if (!nm_connection_normalize (connection, NULL, NULL, &error)) {
		g_print ("%s\n", error->message);
		g_error_free (error);
		return;
	}

	file = nm_keyfile_write (connection, NULL, NULL, &error);
	if (file == NULL) {
		g_print ("%s\n", error->message);
		g_error_free (error);
		return;
	}

	data = g_key_file_to_data (file, &len, &error);
	if (!data) {
		g_print ("%s\n", error->message);
		g_error_free (error);
	} else if (connections_dir) {
		char *filename = g_build_filename (connections_dir, basename, NULL);

		if (!nm_utils_file_set_contents (filename, data, len, 0600, &error)) {
			g_print ("%s\n", error->message);
			g_error_free (error);
		}
		g_free (filename);
	} else {
		g_print ("\n*** Connection '%s' ***\n\n%s\n", basename, data);
	}

	g_key_file_free (file);
}

#define DEFAULT_CONNECTIONS_DIR  NMRUNDIR "/system-connections"
#define DEFAULT_SYSFS_DIR        "/sys"

int
main (int argc, char *argv[])
{
	GHashTable *connections;
	gs_free char *connections_dir = NULL;
	gs_free char *sysfs_dir = NULL;
	gboolean dump_to_stdout = FALSE;
	gs_strfreev char **remaining = NULL;
	GOptionEntry option_entries[] = {
		{ "connections-dir", 'c', 0, G_OPTION_ARG_FILENAME, &connections_dir, "Output connection directory", DEFAULT_CONNECTIONS_DIR },
		{ "sysfs-dir", 'd', 0, G_OPTION_ARG_FILENAME, &sysfs_dir, "The sysfs mount point", DEFAULT_SYSFS_DIR },
		{ "stdout", 's', 0, G_OPTION_ARG_NONE, &dump_to_stdout, "Dump connections to standard output", NULL },
		{ G_OPTION_REMAINING, '\0', 0, G_OPTION_ARG_STRING_ARRAY, &remaining, NULL, NULL },
		{ NULL }
	};
	GOptionContext *option_context;
	GError *error = NULL;

	option_context = g_option_context_new ("-- [ip=...] [rd.route=...] [bridge=...] [bond=...] [team=...] [vlan=...] "
	                                       "[bootdev=...] [nameserver=...] [rd.peerdns=...] [rd.bootif=...] [BOOTIF=...] ... ");

	g_option_context_set_summary (option_context, "Generate early NetworkManager configuration.");
	g_option_context_set_description (option_context,
		"This tool scans the command line for options relevant to network\n"
		"configuration and creates configuration files for an early instance\n"
		"of NetworkManager run from the initial ramdisk during early boot.");
	g_option_context_add_main_entries (option_context, option_entries, GETTEXT_PACKAGE);

	if (!g_option_context_parse (option_context, &argc, &argv, &error)) {
		_LOGW (LOGD_CORE, "%s\n", error->message);
		return 1;
	}

	if (!remaining) {
		/* No arguments, no networking. Don't bother. */
		return 0;
	}

	if (!connections_dir)
		connections_dir = g_strdup (DEFAULT_CONNECTIONS_DIR);
	if (!sysfs_dir)
		sysfs_dir = g_strdup (DEFAULT_SYSFS_DIR);
	if (dump_to_stdout)
		g_clear_pointer (&connections_dir, g_free);

	if (connections_dir && g_mkdir_with_parents (connections_dir, 0755) != 0) {
		_LOGW (LOGD_CORE, "%s: %s\n", connections_dir, strerror (errno));
		return 1;
	}

	connections = nmi_cmdline_reader_parse (sysfs_dir, remaining);
	g_hash_table_foreach (connections, output_conn, connections_dir);
	g_hash_table_destroy (connections);

	return 0;
}
