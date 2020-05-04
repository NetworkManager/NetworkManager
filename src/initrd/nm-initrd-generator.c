// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nm-core-utils.h"
#include "nm-core-internal.h"
#include "nm-keyfile/nm-keyfile-internal.h"
#include "nm-initrd-generator.h"
#include "nm-glib-aux/nm-io-utils.h"

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
	gs_unref_keyfile GKeyFile *file = NULL;
	gs_free char *data = NULL;
	gs_free_error GError *error = NULL;
	gsize len;

	if (!nm_connection_normalize (connection, NULL, NULL, &error))
		goto err_out;

	file = nm_keyfile_write (connection, NULL, NULL, &error);
	if (file == NULL)
		goto err_out;

	data = g_key_file_to_data (file, &len, &error);
	if (!data)
		goto err_out;

	if (connections_dir) {
		gs_free char *filename = NULL;
		gs_free char *full_filename = NULL;

		filename = nm_keyfile_utils_create_filename (basename, TRUE);
		full_filename = g_build_filename (connections_dir, filename, NULL);

		if (!nm_utils_file_set_contents (full_filename,
		                                 data,
		                                 len,
		                                 0600,
		                                 NULL,
		                                 &error))
			goto err_out;
	} else
		g_print ("\n*** Connection '%s' ***\n\n%s", basename, data);

	return;
err_out:
	g_print ("%s\n", error->message);
}

#define DEFAULT_SYSFS_DIR        "/sys"
#define DEFAULT_INITRD_DATA_DIR  NMRUNDIR "/initrd"

int
main (int argc, char *argv[])
{
	GHashTable *connections;
	gs_free char *connections_dir = NULL;
	gs_free char *initrd_dir = NULL;
	gs_free char *sysfs_dir = NULL;
	gboolean dump_to_stdout = FALSE;
	gs_strfreev char **remaining = NULL;
	GOptionEntry option_entries[] = {
		{ "connections-dir",  'c',  0, G_OPTION_ARG_FILENAME,     &connections_dir, "Output connection directory",         NM_KEYFILE_PATH_NAME_RUN },
		{ "initrd-data-dir",  'i',  0, G_OPTION_ARG_FILENAME,     &initrd_dir,      "Output initrd data directory",        DEFAULT_INITRD_DATA_DIR },
		{ "sysfs-dir",        'd',  0, G_OPTION_ARG_FILENAME,     &sysfs_dir,       "The sysfs mount point",               DEFAULT_SYSFS_DIR },
		{ "stdout",           's',  0, G_OPTION_ARG_NONE,         &dump_to_stdout,  "Dump connections to standard output", NULL },
		{ G_OPTION_REMAINING, '\0', 0, G_OPTION_ARG_STRING_ARRAY, &remaining,       NULL,                                  NULL },
		{ NULL }
	};
	GOptionContext *option_context;
	gs_free_error GError *error = NULL;
	int errsv;

	option_context = g_option_context_new ("-- [ip=...] [rd.route=...] [bridge=...] [bond=...] [team=...] [vlan=...] "
	                                       "[bootdev=...] [nameserver=...] [rd.peerdns=...] [rd.bootif=...] [BOOTIF=...] [rd.znet=...] ... ");

	g_option_context_set_summary (option_context, "Generate early NetworkManager configuration.");
	g_option_context_set_description (option_context,
		"This tool scans the command line for options relevant to network\n"
		"configuration and creates configuration files for an early instance\n"
		"of NetworkManager run from the initial ramdisk during early boot.");
	g_option_context_add_main_entries (option_context, option_entries, GETTEXT_PACKAGE);

	if (!g_option_context_parse (option_context, &argc, &argv, &error)) {
		_LOGW (LOGD_CORE, "%s", error->message);
		return 1;
	}

	if (!remaining) {
		/* No arguments, no networking. Don't bother. */
		return 0;
	}

	if (!connections_dir)
		connections_dir = g_strdup (NM_KEYFILE_PATH_NAME_RUN);
	if (!sysfs_dir)
		sysfs_dir = g_strdup (DEFAULT_SYSFS_DIR);
	if (!initrd_dir)
		initrd_dir = g_strdup (DEFAULT_INITRD_DATA_DIR);
	if (dump_to_stdout)
		nm_clear_g_free (&connections_dir);

	if (connections_dir && g_mkdir_with_parents (connections_dir, 0755) != 0) {
		errsv = errno;
		_LOGW (LOGD_CORE, "%s: %s", connections_dir, nm_strerror_native (errsv));
		return 1;
	}

	connections = nmi_cmdline_reader_parse (sysfs_dir, (const char *const*) remaining);
	g_hash_table_foreach (connections, output_conn, connections_dir);
	g_hash_table_destroy (connections);

	if (g_mkdir_with_parents (initrd_dir, 0755) != 0) {
		errsv = errno;
		_LOGW (LOGD_CORE, "%s: %s", initrd_dir, nm_strerror_native (errsv));
		return 1;
	}
	return 0;
}
