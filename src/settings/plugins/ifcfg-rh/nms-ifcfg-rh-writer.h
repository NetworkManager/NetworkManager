/* NetworkManager system settings service - keyfile plugin
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
