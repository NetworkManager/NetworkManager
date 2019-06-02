/* NetworkManager system settings service
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
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef __NMS_IBFT_CONNECTION_H__
#define __NMS_IBFT_CONNECTION_H__

#include "settings/nm-settings-connection.h"

#define NMS_TYPE_IBFT_CONNECTION            (nms_ibft_connection_get_type ())
#define NMS_IBFT_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMS_TYPE_IBFT_CONNECTION, NMSIbftConnection))
#define NMS_IBFT_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMS_TYPE_IBFT_CONNECTION, NMSIbftConnectionClass))
#define NMS_IS_IBFT_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMS_TYPE_IBFT_CONNECTION))
#define NMS_IS_IBFT_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMS_TYPE_IBFT_CONNECTION))
#define NMS_IBFT_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMS_TYPE_IBFT_CONNECTION, NMSIbftConnectionClass))

typedef struct _NMSIbftConnection NMSIbftConnection;
typedef struct _NMSIbftConnectionClass NMSIbftConnectionClass;

GType nms_ibft_connection_get_type (void);

NMSIbftConnection *nms_ibft_connection_new (const GPtrArray *block,
                                           GError **error);

#endif /* __NMS_IBFT_CONNECTION_H__ */
