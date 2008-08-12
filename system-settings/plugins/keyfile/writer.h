/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef _KEYFILE_PLUGIN_WRITER_H
#define _KEYFILE_PLUGIN_WRITER_H

#include <glib.h>
#include <nm-connection.h>

gboolean write_connection (NMConnection *connection, GError **error);

#endif /* _KEYFILE_PLUGIN_WRITER_H */
