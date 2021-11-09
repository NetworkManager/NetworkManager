/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2013 Jiri Pirko <jiri@resnulli.us>
 */

#ifndef __NM_SETTING_TEAM_H__
#define __NM_SETTING_TEAM_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

/**
 * NMTeamLinkWatcherArpPingFlags:
 * @NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE: no one among the arp_ping link watcher
 *    boolean options ('validate_active', 'validate_inactive', 'send_always') is
 *    enabled (set to true).
 * @NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE: the arp_ping link watcher
 *    option 'validate_active' is enabled (set to true).
 * @NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE: the arp_ping link watcher
 *    option 'validate_inactive' is enabled (set to true).
 * @NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS: the arp_ping link watcher option
 *    'send_always' is enabled (set to true).
 */
typedef enum {                                                           /*< flags >*/
               NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE              = 0, /*< skip >*/
               NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE   = 0x2,
               NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE = 0x4,
               NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS       = 0x8,
} NMTeamLinkWatcherArpPingFlags;

#define NM_TEAM_LINK_WATCHER_ETHTOOL   "ethtool"
#define NM_TEAM_LINK_WATCHER_ARP_PING  "arp_ping"
#define NM_TEAM_LINK_WATCHER_NSNA_PING "nsna_ping"

typedef struct NMTeamLinkWatcher NMTeamLinkWatcher;

GType nm_team_link_watcher_get_type(void);

NM_AVAILABLE_IN_1_12
NMTeamLinkWatcher *nm_team_link_watcher_new_ethtool(int delay_up, int delay_down, GError **error);
NM_AVAILABLE_IN_1_12
NMTeamLinkWatcher *nm_team_link_watcher_new_nsna_ping(int         init_wait,
                                                      int         interval,
                                                      int         missed_max,
                                                      const char *target_host,
                                                      GError    **error);
NM_AVAILABLE_IN_1_12
NMTeamLinkWatcher *nm_team_link_watcher_new_arp_ping(int                           init_wait,
                                                     int                           interval,
                                                     int                           missed_max,
                                                     const char                   *target_host,
                                                     const char                   *source_host,
                                                     NMTeamLinkWatcherArpPingFlags flags,
                                                     GError                      **error);
NM_AVAILABLE_IN_1_16
NMTeamLinkWatcher *nm_team_link_watcher_new_arp_ping2(int                           init_wait,
                                                      int                           interval,
                                                      int                           missed_max,
                                                      int                           vlanid,
                                                      const char                   *target_host,
                                                      const char                   *source_host,
                                                      NMTeamLinkWatcherArpPingFlags flags,
                                                      GError                      **error);
NM_AVAILABLE_IN_1_12
void nm_team_link_watcher_ref(NMTeamLinkWatcher *watcher);
NM_AVAILABLE_IN_1_12
void nm_team_link_watcher_unref(NMTeamLinkWatcher *watcher);
NM_AVAILABLE_IN_1_12
gboolean nm_team_link_watcher_equal(const NMTeamLinkWatcher *watcher,
                                    const NMTeamLinkWatcher *other);
NM_AVAILABLE_IN_1_12
NMTeamLinkWatcher *nm_team_link_watcher_dup(const NMTeamLinkWatcher *watcher);
NM_AVAILABLE_IN_1_12
const char *nm_team_link_watcher_get_name(const NMTeamLinkWatcher *watcher);
NM_AVAILABLE_IN_1_12
int nm_team_link_watcher_get_delay_up(const NMTeamLinkWatcher *watcher);
NM_AVAILABLE_IN_1_12
int nm_team_link_watcher_get_delay_down(const NMTeamLinkWatcher *watcher);
NM_AVAILABLE_IN_1_12
int nm_team_link_watcher_get_init_wait(const NMTeamLinkWatcher *watcher);
NM_AVAILABLE_IN_1_12
int nm_team_link_watcher_get_interval(const NMTeamLinkWatcher *watcher);
NM_AVAILABLE_IN_1_12
int nm_team_link_watcher_get_missed_max(const NMTeamLinkWatcher *watcher);
NM_AVAILABLE_IN_1_12
const char *nm_team_link_watcher_get_target_host(const NMTeamLinkWatcher *watcher);
NM_AVAILABLE_IN_1_12
const char *nm_team_link_watcher_get_source_host(const NMTeamLinkWatcher *watcher);
NM_AVAILABLE_IN_1_12
NMTeamLinkWatcherArpPingFlags nm_team_link_watcher_get_flags(const NMTeamLinkWatcher *watcher);
NM_AVAILABLE_IN_1_16
int nm_team_link_watcher_get_vlanid(const NMTeamLinkWatcher *watcher);

#define NM_TYPE_SETTING_TEAM (nm_setting_team_get_type())
#define NM_SETTING_TEAM(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_TEAM, NMSettingTeam))
#define NM_SETTING_TEAM_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_TEAM, NMSettingTeamClass))
#define NM_IS_SETTING_TEAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_TEAM))
#define NM_IS_SETTING_TEAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_TEAM))
#define NM_SETTING_TEAM_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_TEAM, NMSettingTeamClass))

#define NM_SETTING_TEAM_SETTING_NAME "team"

#define NM_SETTING_TEAM_CONFIG                      "config"
#define NM_SETTING_TEAM_NOTIFY_PEERS_COUNT          "notify-peers-count"
#define NM_SETTING_TEAM_NOTIFY_PEERS_INTERVAL       "notify-peers-interval"
#define NM_SETTING_TEAM_MCAST_REJOIN_COUNT          "mcast-rejoin-count"
#define NM_SETTING_TEAM_MCAST_REJOIN_INTERVAL       "mcast-rejoin-interval"
#define NM_SETTING_TEAM_RUNNER                      "runner"
#define NM_SETTING_TEAM_RUNNER_HWADDR_POLICY        "runner-hwaddr-policy"
#define NM_SETTING_TEAM_RUNNER_TX_HASH              "runner-tx-hash"
#define NM_SETTING_TEAM_RUNNER_TX_BALANCER          "runner-tx-balancer"
#define NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL "runner-tx-balancer-interval"
#define NM_SETTING_TEAM_RUNNER_ACTIVE               "runner-active"
#define NM_SETTING_TEAM_RUNNER_FAST_RATE            "runner-fast-rate"
#define NM_SETTING_TEAM_RUNNER_SYS_PRIO             "runner-sys-prio"
#define NM_SETTING_TEAM_RUNNER_MIN_PORTS            "runner-min-ports"
#define NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY    "runner-agg-select-policy"
#define NM_SETTING_TEAM_LINK_WATCHERS               "link-watchers"

#define NM_SETTING_TEAM_RUNNER_BROADCAST    "broadcast"
#define NM_SETTING_TEAM_RUNNER_ROUNDROBIN   "roundrobin"
#define NM_SETTING_TEAM_RUNNER_RANDOM       "random"
#define NM_SETTING_TEAM_RUNNER_ACTIVEBACKUP "activebackup"
#define NM_SETTING_TEAM_RUNNER_LOADBALANCE  "loadbalance"
#define NM_SETTING_TEAM_RUNNER_LACP         "lacp"

#define NM_SETTING_TEAM_RUNNER_HWADDR_POLICY_SAME_ALL    "same_all"
#define NM_SETTING_TEAM_RUNNER_HWADDR_POLICY_BY_ACTIVE   "by_active"
#define NM_SETTING_TEAM_RUNNER_HWADDR_POLICY_ONLY_ACTIVE "only_active"

#define NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY_LACP_PRIO        "lacp_prio"
#define NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY_LACP_PRIO_STABLE "lacp_prio_stable"
#define NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY_BANDWIDTH        "bandwidth"
#define NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY_COUNT            "count"
#define NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY_PORT_CONFIG      "port_config"

#define NM_SETTING_TEAM_NOTIFY_PEERS_COUNT_ACTIVEBACKUP_DEFAULT 1
#define NM_SETTING_TEAM_NOTIFY_MCAST_COUNT_ACTIVEBACKUP_DEFAULT 1
#define NM_SETTING_TEAM_RUNNER_DEFAULT                          NM_SETTING_TEAM_RUNNER_ROUNDROBIN
#define NM_SETTING_TEAM_RUNNER_HWADDR_POLICY_DEFAULT            NM_SETTING_TEAM_RUNNER_HWADDR_POLICY_SAME_ALL
#define NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL_DEFAULT     50
#define NM_SETTING_TEAM_RUNNER_SYS_PRIO_DEFAULT                 65535
#define NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY_DEFAULT \
    NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY_LACP_PRIO

typedef struct _NMSettingTeamClass NMSettingTeamClass;

GType nm_setting_team_get_type(void);

NMSetting *nm_setting_team_new(void);

const char *nm_setting_team_get_config(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
int nm_setting_team_get_notify_peers_count(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
int nm_setting_team_get_notify_peers_interval(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
int nm_setting_team_get_mcast_rejoin_count(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
int nm_setting_team_get_mcast_rejoin_interval(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
const char *nm_setting_team_get_runner(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
const char *nm_setting_team_get_runner_hwaddr_policy(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
const char *nm_setting_team_get_runner_tx_balancer(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
int nm_setting_team_get_runner_tx_balancer_interval(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
gboolean nm_setting_team_get_runner_active(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
gboolean nm_setting_team_get_runner_fast_rate(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
int nm_setting_team_get_runner_sys_prio(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
int nm_setting_team_get_runner_min_ports(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
const char *nm_setting_team_get_runner_agg_select_policy(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
gboolean nm_setting_team_remove_runner_tx_hash_by_value(NMSettingTeam *setting, const char *txhash);
NM_AVAILABLE_IN_1_12
guint nm_setting_team_get_num_runner_tx_hash(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
const char *nm_setting_team_get_runner_tx_hash(NMSettingTeam *setting, guint idx);
NM_AVAILABLE_IN_1_12
void nm_setting_team_remove_runner_tx_hash(NMSettingTeam *setting, guint idx);
NM_AVAILABLE_IN_1_12
gboolean nm_setting_team_add_runner_tx_hash(NMSettingTeam *setting, const char *txhash);
NM_AVAILABLE_IN_1_12
guint nm_setting_team_get_num_link_watchers(NMSettingTeam *setting);
NM_AVAILABLE_IN_1_12
NMTeamLinkWatcher *nm_setting_team_get_link_watcher(NMSettingTeam *setting, guint idx);
NM_AVAILABLE_IN_1_12
gboolean nm_setting_team_add_link_watcher(NMSettingTeam *setting, NMTeamLinkWatcher *link_watcher);
NM_AVAILABLE_IN_1_12
void nm_setting_team_remove_link_watcher(NMSettingTeam *setting, guint idx);
NM_AVAILABLE_IN_1_12
gboolean nm_setting_team_remove_link_watcher_by_value(NMSettingTeam     *setting,
                                                      NMTeamLinkWatcher *link_watcher);
NM_AVAILABLE_IN_1_12
void nm_setting_team_clear_link_watchers(NMSettingTeam *setting);
G_END_DECLS

#endif /* __NM_SETTING_TEAM_H__ */
