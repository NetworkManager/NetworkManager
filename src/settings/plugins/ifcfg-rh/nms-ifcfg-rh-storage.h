/* NetworkManager
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
 * Copyright (C) 2019 Red Hat, Inc.
 */

#ifndef __NMS_IFCFG_RH_STORAGE_H__
#define __NMS_IFCFG_RH_STORAGE_H__

#include "c-list/src/c-list.h"
#include "settings/nm-settings-storage.h"

/*****************************************************************************/

#define NMS_TYPE_IFCFG_RH_STORAGE            (nms_ifcfg_rh_storage_get_type ())
#define NMS_IFCFG_RH_STORAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMS_TYPE_IFCFG_RH_STORAGE, NMSIfcfgRHStorage))
#define NMS_IFCFG_RH_STORAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMS_TYPE_IFCFG_RH_STORAGE, NMSIfcfgRHStorageClass))
#define NMS_IS_IFCFG_RH_STORAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMS_TYPE_IFCFG_RH_STORAGE))
#define NMS_IS_IFCFG_RH_STORAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMS_TYPE_IFCFG_RH_STORAGE))
#define NMS_IFCFG_RH_STORAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMS_TYPE_IFCFG_RH_STORAGE, NMSIfcfgRHStorageClass))

typedef struct {
	NMSettingsStorage parent;

	NMConnection *connection;

	char *unmanaged_spec;
	char *unrecognized_spec;

	/* The timestamp (stat's mtime) of the file. Newer files have
	 * higher priority. */
	struct timespec stat_mtime;

	bool dirty:1;

} NMSIfcfgRHStorage;

typedef struct _NMSIfcfgRHStorageClass NMSIfcfgRHStorageClass;

GType nms_ifcfg_rh_storage_get_type (void);

struct _NMSIfcfgRHPlugin;

NMSIfcfgRHStorage *nms_ifcfg_rh_storage_new_connection (struct _NMSIfcfgRHPlugin *plugin,
                                                        const char *filename,
                                                        NMConnection *connection_take,
                                                        const struct timespec *mtime);

NMSIfcfgRHStorage *nms_ifcfg_rh_storage_new_unhandled (struct _NMSIfcfgRHPlugin *plugin,
                                                       const char *filename,
                                                       const char *unmanaged_spec,
                                                       const char *unrecognized_spec);

void nms_ifcfg_rh_storage_destroy (NMSIfcfgRHStorage *self);

/*****************************************************************************/

gboolean nms_ifcfg_rh_storage_equal_type (const NMSIfcfgRHStorage *self_a,
                                          const NMSIfcfgRHStorage *self_b);

void nms_ifcfg_rh_storage_copy_content (NMSIfcfgRHStorage *dst,
                                        const NMSIfcfgRHStorage *src);

NMConnection *nms_ifcfg_rh_storage_steal_connection (NMSIfcfgRHStorage *self);

/*****************************************************************************/

static inline const char *
nms_ifcfg_rh_storage_get_uuid_opt (const NMSIfcfgRHStorage *self)
{
	return nm_settings_storage_get_uuid_opt ((const NMSettingsStorage *) self);
}

static inline const char *
nms_ifcfg_rh_storage_get_filename (const NMSIfcfgRHStorage *self)
{
	return nm_settings_storage_get_filename ((const NMSettingsStorage *) self);
}

#endif /* __NMS_IFCFG_RH_STORAGE_H__ */
