// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager system settings service (ifupdown)
 *
 * Alexander Sack <asac@ubuntu.com>
 *
 * (C) Copyright 2008 Canonical Ltd.
 */

#ifndef __NMS_IFUPDOWN_PLUGIN_H__
#define __NMS_IFUPDOWN_PLUGIN_H__

#define PLUGIN_NAME "ifupdown"

#define NMS_TYPE_IFUPDOWN_PLUGIN            (nms_ifupdown_plugin_get_type ())
#define NMS_IFUPDOWN_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMS_TYPE_IFUPDOWN_PLUGIN, NMSIfupdownPlugin))
#define NMS_IFUPDOWN_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMS_TYPE_IFUPDOWN_PLUGIN, NMSIfupdownPluginClass))
#define NMS_IS_IFUPDOWN_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMS_TYPE_IFUPDOWN_PLUGIN))
#define NMS_IS_IFUPDOWN_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMS_TYPE_IFUPDOWN_PLUGIN))
#define NMS_IFUPDOWN_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMS_TYPE_IFUPDOWN_PLUGIN, NMSIfupdownPluginClass))

typedef struct _NMSIfupdownPlugin NMSIfupdownPlugin;
typedef struct _NMSIfupdownPluginClass NMSIfupdownPluginClass;

GType nms_ifupdown_plugin_get_type (void);

#endif /* __NMS_IFUPDOWN_PLUGIN_H__ */
