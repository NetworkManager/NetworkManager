/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef _KEYFILE_PLUGIN_WRITER_H
#define _KEYFILE_PLUGIN_WRITER_H

#include <glib.h>
#include <nm-connection.h>

gboolean write_connection (NMConnection *connection, char **out_path, GError **error);

char *writer_id_to_filename (const char *id);

#endif /* _KEYFILE_PLUGIN_WRITER_H */
