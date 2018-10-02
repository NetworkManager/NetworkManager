/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 */

#ifndef __NMS_KEYFILE_CONNECTION_H__
#define __NMS_KEYFILE_CONNECTION_H__

#include "settings/nm-settings-connection.h"

#define NMS_TYPE_KEYFILE_CONNECTION            (nms_keyfile_connection_get_type ())
#define NMS_KEYFILE_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMS_TYPE_KEYFILE_CONNECTION, NMSKeyfileConnection))
#define NMS_KEYFILE_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMS_TYPE_KEYFILE_CONNECTION, NMSKeyfileConnectionClass))
#define NMS_IS_KEYFILE_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMS_TYPE_KEYFILE_CONNECTION))
#define NMS_IS_KEYFILE_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMS_TYPE_KEYFILE_CONNECTION))
#define NMS_KEYFILE_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMS_TYPE_KEYFILE_CONNECTION, NMSKeyfileConnectionClass))

typedef struct _NMSKeyfileConnection NMSKeyfileConnection;
typedef struct _NMSKeyfileConnectionClass NMSKeyfileConnectionClass;

GType nms_keyfile_connection_get_type (void);

NMSKeyfileConnection *nms_keyfile_connection_new (NMConnection *source,
                                                  const char *full_path,
                                                  const char *profile_dir,
                                                  GError **error);

#endif /* __NMS_KEYFILE_CONNECTION_H__ */
