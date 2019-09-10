// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager system settings service
 *
 * Dan Williams <dcbw@redhat.com>
 * Søren Sandmann <sandmann@daimi.au.dk>
 *
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#ifndef __NMS_IFCFG_RH_PLUGIN_H__
#define __NMS_IFCFG_RH_PLUGIN_H__

#define NMS_TYPE_IFCFG_RH_PLUGIN            (nms_ifcfg_rh_plugin_get_type ())
#define NMS_IFCFG_RH_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMS_TYPE_IFCFG_RH_PLUGIN, NMSIfcfgRHPlugin))
#define NMS_IFCFG_RH_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMS_TYPE_IFCFG_RH_PLUGIN, NMSIfcfgRHPluginClass))
#define NMS_IS_IFCFG_RH_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMS_TYPE_IFCFG_RH_PLUGIN))
#define NMS_IS_IFCFG_RH_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMS_TYPE_IFCFG_RH_PLUGIN))
#define NMS_IFCFG_RH_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMS_TYPE_IFCFG_RH_PLUGIN, NMSIfcfgRHPluginClass))

typedef struct _NMSIfcfgRHPlugin NMSIfcfgRHPlugin;
typedef struct _NMSIfcfgRHPluginClass NMSIfcfgRHPluginClass;

GType nms_ifcfg_rh_plugin_get_type (void);

#endif /* __NMS_IFCFG_RH_PLUGIN_H__ */
