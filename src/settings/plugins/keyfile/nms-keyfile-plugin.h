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
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 */

#ifndef __NMS_KEYFILE_PLUGIN_H__
#define __NMS_KEYFILE_PLUGIN_H__

#define NMS_TYPE_KEYFILE_PLUGIN            (nms_keyfile_plugin_get_type ())
#define NMS_KEYFILE_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMS_TYPE_KEYFILE_PLUGIN, NMSKeyfilePlugin))
#define NMS_KEYFILE_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMS_TYPE_KEYFILE_PLUGIN, NMSKeyfilePluginClass))
#define NMS_IS_KEYFILE_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMS_TYPE_KEYFILE_PLUGIN))
#define NMS_IS_KEYFILE_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMS_TYPE_KEYFILE_PLUGIN))
#define NMS_KEYFILE_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMS_TYPE_KEYFILE_PLUGIN, NMSKeyfilePluginClass))

typedef struct _NMSKeyfilePlugin NMSKeyfilePlugin;
typedef struct _NMSKeyfilePluginClass NMSKeyfilePluginClass;

GType nms_keyfile_plugin_get_type (void);

NMSKeyfilePlugin *nms_keyfile_plugin_new (void);

#endif /* __NMS_KEYFILE_PLUGIN_H__ */
