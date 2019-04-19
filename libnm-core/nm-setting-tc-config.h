/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2017 Red Hat, Inc.
 */

#ifndef NM_SETTING_TC_CONFIG_H
#define NM_SETTING_TC_CONFIG_H

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

typedef struct NMTCQdisc NMTCQdisc;

NM_AVAILABLE_IN_1_12
GType       nm_tc_qdisc_get_type             (void);

NM_AVAILABLE_IN_1_12
NMTCQdisc  *nm_tc_qdisc_new                  (const char *kind,
                                              guint32 parent,
                                              GError **error);

NM_AVAILABLE_IN_1_12
void        nm_tc_qdisc_ref                  (NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_12
void        nm_tc_qdisc_unref                (NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_12
gboolean    nm_tc_qdisc_equal                (NMTCQdisc *qdisc,
                                              NMTCQdisc *other);

NM_AVAILABLE_IN_1_12
NMTCQdisc  *nm_tc_qdisc_dup                  (NMTCQdisc  *qdisc);

NM_AVAILABLE_IN_1_12
const char *nm_tc_qdisc_get_kind             (NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_12
guint32     nm_tc_qdisc_get_handle           (NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_12
void        nm_tc_qdisc_set_handle           (NMTCQdisc *qdisc,
                                              guint32 handle);
NM_AVAILABLE_IN_1_12
guint32     nm_tc_qdisc_get_parent           (NMTCQdisc *qdisc);

NM_AVAILABLE_IN_1_18
const char **nm_tc_qdisc_get_attribute_names (NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_18
GVariant   *nm_tc_qdisc_get_attribute        (NMTCQdisc *qdisc,
                                              const char *name);
NM_AVAILABLE_IN_1_18
void        nm_tc_qdisc_set_attribute        (NMTCQdisc *qdisc,
                                              const char *name,
                                              GVariant *value);

typedef struct NMTCAction NMTCAction;

NM_AVAILABLE_IN_1_12
GType       nm_tc_action_get_type            (void);

NM_AVAILABLE_IN_1_12
NMTCAction  *nm_tc_action_new                (const char *kind,
                                              GError **error);

NM_AVAILABLE_IN_1_12
void        nm_tc_action_ref                 (NMTCAction *action);
NM_AVAILABLE_IN_1_12
void        nm_tc_action_unref               (NMTCAction *action);
NM_AVAILABLE_IN_1_12
gboolean    nm_tc_action_equal               (NMTCAction *action,
                                              NMTCAction *other);

NM_AVAILABLE_IN_1_12
NMTCAction  *nm_tc_action_dup                (NMTCAction  *action);

NM_AVAILABLE_IN_1_12
const char *nm_tc_action_get_kind            (NMTCAction *action);

NM_AVAILABLE_IN_1_12
char      **nm_tc_action_get_attribute_names (NMTCAction *action);
NM_AVAILABLE_IN_1_12
GVariant   *nm_tc_action_get_attribute       (NMTCAction *action,
                                              const char *name);
NM_AVAILABLE_IN_1_12
void        nm_tc_action_set_attribute       (NMTCAction *action,
                                              const char *name,
                                              GVariant *value);

typedef struct NMTCTfilter NMTCTfilter;

NM_AVAILABLE_IN_1_12
GType       nm_tc_tfilter_get_type           (void);

NM_AVAILABLE_IN_1_12
NMTCTfilter  *nm_tc_tfilter_new              (const char *kind,
                                              guint32 parent,
                                              GError **error);

NM_AVAILABLE_IN_1_12
void        nm_tc_tfilter_ref                (NMTCTfilter *tfilter);
NM_AVAILABLE_IN_1_12
void        nm_tc_tfilter_unref              (NMTCTfilter *tfilter);
NM_AVAILABLE_IN_1_12
gboolean    nm_tc_tfilter_equal              (NMTCTfilter *tfilter,
                                              NMTCTfilter *other);

NM_AVAILABLE_IN_1_12
NMTCTfilter  *nm_tc_tfilter_dup              (NMTCTfilter  *tfilter);

NM_AVAILABLE_IN_1_12
const char *nm_tc_tfilter_get_kind           (NMTCTfilter *tfilter);
NM_AVAILABLE_IN_1_12
guint32     nm_tc_tfilter_get_handle         (NMTCTfilter *tfilter);
NM_AVAILABLE_IN_1_12
void        nm_tc_tfilter_set_handle         (NMTCTfilter *tfilter,
                                              guint32 handle);
NM_AVAILABLE_IN_1_12
guint32     nm_tc_tfilter_get_parent         (NMTCTfilter *tfilter);
NM_AVAILABLE_IN_1_12
NMTCAction *nm_tc_tfilter_get_action         (NMTCTfilter *tfilter);
NM_AVAILABLE_IN_1_12
void        nm_tc_tfilter_set_action         (NMTCTfilter *tfilter, NMTCAction *action);

#define NM_TYPE_SETTING_TC_CONFIG            (nm_setting_tc_config_get_type ())
#define NM_SETTING_TC_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_TC_CONFIG, NMSettingTCConfig))
#define NM_SETTING_TC_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_TC_CONFIG, NMSettingTCConfigClass))
#define NM_IS_SETTING_TC_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_TC_CONFIG))
#define NM_IS_SETTING_TC_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_TC_CONFIG))
#define NM_SETTING_TC_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_TC_CONFIG, NMSettingTCConfigClass))

#define NM_SETTING_TC_CONFIG_SETTING_NAME    "tc"

#define NM_SETTING_TC_CONFIG_QDISCS          "qdiscs"
#define NM_SETTING_TC_CONFIG_TFILTERS        "tfilters"

typedef struct _NMSettingTCConfigClass NMSettingTCConfigClass;

GType nm_setting_tc_config_get_type (void);

NM_AVAILABLE_IN_1_12
NMSetting *nm_setting_tc_config_new (void);

NM_AVAILABLE_IN_1_12
guint      nm_setting_tc_config_get_num_qdiscs          (NMSettingTCConfig *setting);
NM_AVAILABLE_IN_1_12
NMTCQdisc *nm_setting_tc_config_get_qdisc               (NMSettingTCConfig *setting,
                                                         guint idx);
NM_AVAILABLE_IN_1_12
gboolean   nm_setting_tc_config_add_qdisc               (NMSettingTCConfig *setting,
                                                         NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_12
void       nm_setting_tc_config_remove_qdisc            (NMSettingTCConfig *setting,
                                                         guint idx);
NM_AVAILABLE_IN_1_12
gboolean   nm_setting_tc_config_remove_qdisc_by_value   (NMSettingTCConfig *setting,
                                                         NMTCQdisc *qdisc);
NM_AVAILABLE_IN_1_12
void       nm_setting_tc_config_clear_qdiscs            (NMSettingTCConfig *setting);

NM_AVAILABLE_IN_1_12
guint      nm_setting_tc_config_get_num_tfilters        (NMSettingTCConfig *setting);
NM_AVAILABLE_IN_1_12
NMTCTfilter *nm_setting_tc_config_get_tfilter           (NMSettingTCConfig *setting,
                                                         guint idx);
NM_AVAILABLE_IN_1_12
gboolean   nm_setting_tc_config_add_tfilter             (NMSettingTCConfig *setting,
                                                         NMTCTfilter *tfilter);
NM_AVAILABLE_IN_1_12
void       nm_setting_tc_config_remove_tfilter          (NMSettingTCConfig *setting,
                                                         guint idx);
NM_AVAILABLE_IN_1_12
gboolean   nm_setting_tc_config_remove_tfilter_by_value (NMSettingTCConfig *setting,
                                                         NMTCTfilter *tfilter);
NM_AVAILABLE_IN_1_12
void       nm_setting_tc_config_clear_tfilters          (NMSettingTCConfig *setting);

G_END_DECLS

#endif /* NM_SETTING_TC_CONFIG_H */
