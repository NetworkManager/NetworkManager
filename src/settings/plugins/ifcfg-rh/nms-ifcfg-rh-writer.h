// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager system settings service - keyfile plugin
 *
 * Copyright (C) 2009 Red Hat, Inc.
 */

#ifndef __NMS_IFCFG_RH_WRITER_H__
#define __NMS_IFCFG_RH_WRITER_H__

#include "nm-connection.h"


typedef gboolean (*NMSIfcfgRHWriterAllowFilenameCb) (const char *check_filename,
                                                     gpointer allow_filename_user_data);

gboolean nms_ifcfg_rh_writer_can_write_connection (NMConnection *connection,
                                                   GError **error);

gboolean nms_ifcfg_rh_writer_write_connection (NMConnection *connection,
                                               const char *ifcfg_dir,
                                               const char *filename,
                                               NMSIfcfgRHWriterAllowFilenameCb allow_filename_cb,
                                               gpointer allow_filename_user_data,
                                               char **out_filename,
                                               NMConnection **out_reread,
                                               gboolean *out_reread_same,
                                               GError **error);

#endif /* __NMS_IFCFG_RH_WRITER_H__ */
