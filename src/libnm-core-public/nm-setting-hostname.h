/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2020 Red Hat, Inc.
 */

#ifndef NM_SETTING_HOSTNAME_H
#define NM_SETTING_HOSTNAME_H

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_HOSTNAME (nm_setting_hostname_get_type())
#define NM_SETTING_HOSTNAME(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_HOSTNAME, NMSettingHostname))
#define NM_SETTING_HOSTNAME_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_HOSTNAME, NMSettingHostnameClass))
#define NM_IS_SETTING_HOSTNAME(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_HOSTNAME))
#define NM_IS_SETTING_HOSTNAME_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_HOSTNAME))
#define NM_SETTING_HOSTNAME_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_HOSTNAME, NMSettingHostnameClass))

#define NM_SETTING_HOSTNAME_SETTING_NAME "hostname"

#define NM_SETTING_HOSTNAME_PRIORITY          "priority"
#define NM_SETTING_HOSTNAME_FROM_DHCP         "from-dhcp"
#define NM_SETTING_HOSTNAME_FROM_DNS_LOOKUP   "from-dns-lookup"
#define NM_SETTING_HOSTNAME_ONLY_FROM_DEFAULT "only-from-default"

typedef struct _NMSettingHostnameClass NMSettingHostnameClass;

NM_AVAILABLE_IN_1_30
GType nm_setting_hostname_get_type(void);
NM_AVAILABLE_IN_1_30
NMSetting *nm_setting_hostname_new(void);

NM_AVAILABLE_IN_1_30
int nm_setting_hostname_get_priority(NMSettingHostname *setting);
NM_AVAILABLE_IN_1_30
NMTernary nm_setting_hostname_get_from_dhcp(NMSettingHostname *setting);
NM_AVAILABLE_IN_1_30
NMTernary nm_setting_hostname_get_from_dns_lookup(NMSettingHostname *setting);
NM_AVAILABLE_IN_1_30
NMTernary nm_setting_hostname_get_only_from_default(NMSettingHostname *setting);

G_END_DECLS

#endif /* NM_SETTING_HOSTNAME_H */
