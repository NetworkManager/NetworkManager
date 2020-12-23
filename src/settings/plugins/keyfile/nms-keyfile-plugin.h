/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 */

#ifndef __NMS_KEYFILE_PLUGIN_H__
#define __NMS_KEYFILE_PLUGIN_H__

#include "settings/nm-settings-plugin.h"
#include "settings/nm-settings-storage.h"

#include "nms-keyfile-utils.h"

#define NMS_TYPE_KEYFILE_PLUGIN (nms_keyfile_plugin_get_type())
#define NMS_KEYFILE_PLUGIN(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NMS_TYPE_KEYFILE_PLUGIN, NMSKeyfilePlugin))
#define NMS_KEYFILE_PLUGIN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMS_TYPE_KEYFILE_PLUGIN, NMSKeyfilePluginClass))
#define NMS_IS_KEYFILE_PLUGIN(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMS_TYPE_KEYFILE_PLUGIN))
#define NMS_IS_KEYFILE_PLUGIN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NMS_TYPE_KEYFILE_PLUGIN))
#define NMS_KEYFILE_PLUGIN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMS_TYPE_KEYFILE_PLUGIN, NMSKeyfilePluginClass))

typedef struct _NMSKeyfilePlugin      NMSKeyfilePlugin;
typedef struct _NMSKeyfilePluginClass NMSKeyfilePluginClass;

GType nms_keyfile_plugin_get_type(void);

NMSKeyfilePlugin *nms_keyfile_plugin_new(void);

gboolean nms_keyfile_plugin_add_connection(NMSKeyfilePlugin *  self,
                                           NMConnection *      connection,
                                           gboolean            in_memory,
                                           gboolean            is_nm_generated,
                                           gboolean            is_volatile,
                                           gboolean            is_external,
                                           const char *        shadowed_storage,
                                           gboolean            shadowed_owned,
                                           NMSettingsStorage **out_storage,
                                           NMConnection **     out_connection,
                                           GError **           error);

gboolean nms_keyfile_plugin_update_connection(NMSKeyfilePlugin *  self,
                                              NMSettingsStorage * storage,
                                              NMConnection *      connection,
                                              gboolean            is_nm_generated,
                                              gboolean            is_volatile,
                                              gboolean            is_external,
                                              const char *        shadowed_storage,
                                              gboolean            shadowed_owned,
                                              gboolean            force_rename,
                                              NMSettingsStorage **out_storage,
                                              NMConnection **     out_connection,
                                              GError **           error);

gboolean nms_keyfile_plugin_set_nmmeta_tombstone(NMSKeyfilePlugin *  self,
                                                 gboolean            simulate,
                                                 const char *        uuid,
                                                 gboolean            in_memory,
                                                 gboolean            set,
                                                 const char *        shadowed_storage,
                                                 NMSettingsStorage **out_storage,
                                                 gboolean *          out_hard_failure);

#endif /* __NMS_KEYFILE_PLUGIN_H__ */
