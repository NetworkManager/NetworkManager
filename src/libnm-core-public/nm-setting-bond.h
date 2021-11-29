/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2011 - 2013 Red Hat, Inc.
 */

#ifndef __NM_SETTING_BOND_H__
#define __NM_SETTING_BOND_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_BOND (nm_setting_bond_get_type())
#define NM_SETTING_BOND(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_BOND, NMSettingBond))
#define NM_SETTING_BOND_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_BOND, NMSettingBondClass))
#define NM_IS_SETTING_BOND(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_BOND))
#define NM_IS_SETTING_BOND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_BOND))
#define NM_SETTING_BOND_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_BOND, NMSettingBondClass))

#define NM_SETTING_BOND_SETTING_NAME "bond"

#define NM_SETTING_BOND_OPTIONS "options"

/* Valid options for the 'options' property */
#define NM_SETTING_BOND_OPTION_MODE              "mode"
#define NM_SETTING_BOND_OPTION_MIIMON            "miimon"
#define NM_SETTING_BOND_OPTION_DOWNDELAY         "downdelay"
#define NM_SETTING_BOND_OPTION_UPDELAY           "updelay"
#define NM_SETTING_BOND_OPTION_ARP_INTERVAL      "arp_interval"
#define NM_SETTING_BOND_OPTION_ARP_IP_TARGET     "arp_ip_target"
#define NM_SETTING_BOND_OPTION_ARP_VALIDATE      "arp_validate"
#define NM_SETTING_BOND_OPTION_PRIMARY           "primary"
#define NM_SETTING_BOND_OPTION_PRIMARY_RESELECT  "primary_reselect"
#define NM_SETTING_BOND_OPTION_FAIL_OVER_MAC     "fail_over_mac"
#define NM_SETTING_BOND_OPTION_USE_CARRIER       "use_carrier"
#define NM_SETTING_BOND_OPTION_AD_SELECT         "ad_select"
#define NM_SETTING_BOND_OPTION_XMIT_HASH_POLICY  "xmit_hash_policy"
#define NM_SETTING_BOND_OPTION_RESEND_IGMP       "resend_igmp"
#define NM_SETTING_BOND_OPTION_LACP_RATE         "lacp_rate"
#define NM_SETTING_BOND_OPTION_ACTIVE_SLAVE      "active_slave"
#define NM_SETTING_BOND_OPTION_AD_ACTOR_SYS_PRIO "ad_actor_sys_prio"
#define NM_SETTING_BOND_OPTION_AD_ACTOR_SYSTEM   "ad_actor_system"
#define NM_SETTING_BOND_OPTION_AD_USER_PORT_KEY  "ad_user_port_key"
#define NM_SETTING_BOND_OPTION_ALL_SLAVES_ACTIVE "all_slaves_active"
#define NM_SETTING_BOND_OPTION_ARP_ALL_TARGETS   "arp_all_targets"
#define NM_SETTING_BOND_OPTION_MIN_LINKS         "min_links"
#define NM_SETTING_BOND_OPTION_NUM_GRAT_ARP      "num_grat_arp"
#define NM_SETTING_BOND_OPTION_NUM_UNSOL_NA      "num_unsol_na"
#define NM_SETTING_BOND_OPTION_PACKETS_PER_SLAVE "packets_per_slave"
#define NM_SETTING_BOND_OPTION_TLB_DYNAMIC_LB    "tlb_dynamic_lb"
#define NM_SETTING_BOND_OPTION_LP_INTERVAL       "lp_interval"
#define NM_SETTING_BOND_OPTION_PEER_NOTIF_DELAY  "peer_notif_delay"

typedef struct _NMSettingBondClass NMSettingBondClass;

GType nm_setting_bond_get_type(void);

NMSetting  *nm_setting_bond_new(void);
guint32     nm_setting_bond_get_num_options(NMSettingBond *setting);
gboolean    nm_setting_bond_get_option(NMSettingBond *setting,
                                       guint32        idx,
                                       const char   **out_name,
                                       const char   **out_value);
const char *nm_setting_bond_get_option_by_name(NMSettingBond *setting, const char *name);
gboolean    nm_setting_bond_add_option(NMSettingBond *setting, const char *name, const char *value);
gboolean    nm_setting_bond_remove_option(NMSettingBond *setting, const char *name);

gboolean nm_setting_bond_validate_option(const char *name, const char *value);

const char **nm_setting_bond_get_valid_options(NMSettingBond *setting);

const char *nm_setting_bond_get_option_default(NMSettingBond *setting, const char *name);

NM_AVAILABLE_IN_1_24
const char *nm_setting_bond_get_option_normalized(NMSettingBond *setting, const char *name);

G_END_DECLS

#endif /* __NM_SETTING_BOND_H__ */
