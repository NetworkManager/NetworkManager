// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef __NMS_IFCFG_RH_READER_H__
#define __NMS_IFCFG_RH_READER_H__

#include "nm-connection.h"

NMConnection *connection_from_file (const char *filename,
                                    char **out_unhandled,
                                    GError **error,
                                    gboolean *out_ignore_error);

NMConnection *nmtst_connection_from_file (const char *filename,
                                          const char *network_file,
                                          const char *test_type,
                                          char **out_unhandled,
                                          GError **error);

#endif  /* __NMS_IFCFG_RH_READER_H__ */
