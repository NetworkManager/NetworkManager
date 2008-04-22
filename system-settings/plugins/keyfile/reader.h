/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef _KEYFILE_PLUGIN_READER_H
#define _KEYFILE_PLUGIN_READER_H

#include <glib.h>
#include <nm-connection.h>

NMConnection *connection_from_file (const char *filename);

#endif /* _KEYFILE_PLUGIN_READER_H */
