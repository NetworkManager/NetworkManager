/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2026 Red Hat, Inc.
 */

#ifndef __NM_SETTING_GENEVE_H__
#define __NM_SETTING_GENEVE_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_GENEVE (nm_setting_geneve_get_type())
#define NM_SETTING_GENEVE(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_GENEVE, NMSettingGeneve))
#define NM_SETTING_GENEVE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_GENEVE, NMSettingGeneveClass))
#define NM_IS_SETTING_GENEVE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_GENEVE))
#define NM_IS_SETTING_GENEVE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_GENEVE))
#define NM_SETTING_GENEVE_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_GENEVE, NMSettingGeneveClass))

#define NM_SETTING_GENEVE_SETTING_NAME "geneve"

#define NM_SETTING_GENEVE_ID               "id"
#define NM_SETTING_GENEVE_REMOTE           "remote"
#define NM_SETTING_GENEVE_DESTINATION_PORT "destination-port"
#define NM_SETTING_GENEVE_TOS              "tos"
#define NM_SETTING_GENEVE_TTL              "ttl"
#define NM_SETTING_GENEVE_DF               "df"

/**
 * NMSettingGeneveDf:
 * @NM_SETTING_GENEVE_DF_UNSET: Don't set the DF flag, packets may be fragmented.
 * @NM_SETTING_GENEVE_DF_SET: Always set the DF flag, packets will not be fragmented.
 * @NM_SETTING_GENEVE_DF_INHERIT: Inherit the DF flag from the inner IP header.
 *
 * #NMSettingGeneveDf values indicate how the Don't Fragment (DF) flag should be handled
 * in the outer IP header of GENEVE tunnel packets.
 *
 * Since: 1.56, 1.54.4
 */
typedef enum {
    NM_SETTING_GENEVE_DF_UNSET   = 0,
    NM_SETTING_GENEVE_DF_SET     = 1,
    NM_SETTING_GENEVE_DF_INHERIT = 2,
} NMSettingGeneveDf;

typedef struct _NMSettingGeneveClass NMSettingGeneveClass;

NM_AVAILABLE_IN_1_54_4
GType nm_setting_geneve_get_type(void);
NM_AVAILABLE_IN_1_54_4
NMSetting *nm_setting_geneve_new(void);
NM_AVAILABLE_IN_1_54_4
guint nm_setting_geneve_get_id(NMSettingGeneve *setting);
NM_AVAILABLE_IN_1_54_4
const char *nm_setting_geneve_get_remote(NMSettingGeneve *setting);
NM_AVAILABLE_IN_1_54_4
guint nm_setting_geneve_get_destination_port(NMSettingGeneve *setting);
NM_AVAILABLE_IN_1_54_4
guint nm_setting_geneve_get_tos(NMSettingGeneve *setting);
NM_AVAILABLE_IN_1_54_4
guint nm_setting_geneve_get_ttl(NMSettingGeneve *setting);
NM_AVAILABLE_IN_1_54_4
NMSettingGeneveDf nm_setting_geneve_get_df(NMSettingGeneve *setting);

G_END_DECLS

#endif /* __NM_SETTING_GENEVE_H__ */
