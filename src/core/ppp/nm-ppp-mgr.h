/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef __NM_PPP_MGR_H__
#define __NM_PPP_MGR_H__

#include "nm-l3cfg.h"

typedef struct _NMPppMgr NMPppMgr;

typedef enum _nm_packed {
    /* NMPppMgr is starting. It will call nm_ppp_manager_start() on an idle
     * handler. */
    NM_PPP_MGR_STATE_STARTING,

    /* NMPppMgr called nm_ppp_manager_start() and is now waiting to get
     * an ifindex. At this time, we theoretically might already get IP configuration
     * but that is cached and meaningless until we have the ifindex. */
    NM_PPP_MGR_STATE_WAITING_FOR_IFINDEX,

    /* NMPppMgr received an ifindex from NMPPPManager. But no IP configuration
     * is yet received. */
    NM_PPP_MGR_STATE_HAVE_IFINDEX,

    /* NMPppMgr received an ifindex and IP configuration from NMPPPManager.
     * Whether we have IPv4 and/or IPv6 is unspecified.
     *
     * If we have only either IPv4 or IPv6, then it's also unclear unknown
     * whether the other address family will still arrive or not. */
    NM_PPP_MGR_STATE_HAVE_IP_CONFIG,

    /* Meta enum value which is the first failed state. All states larger than
     * this are final (dead) states. */
    _NM_PPP_MGR_STATE_FAILED_START,

    /* NMPPPManager failed to start. This is a final (dead) state. */
    NM_PPP_MGR_STATE_FAILED_TO_START = _NM_PPP_MGR_STATE_FAILED_START,

    /* NMPppMgr started, but it failed to get the ifindex (possibly after timeout).
     * This is a final (dead) state. */
    NM_PPP_MGR_STATE_FAILED_TO_IFINDEX,

    /* An unspecified failed state. This is a final (dead) state. */
    NM_PPP_MGR_STATE_FAILED,
} NMPppMgrState;

const char *nm_ppp_mgr_state_to_string(NMPppMgrState state);

typedef enum {
    NM_PPP_MGR_CALLBACK_TYPE_STATE_CHANGED,
    NM_PPP_MGR_CALLBACK_TYPE_STATS_CHANGED,
} NMPppMgrCallbackType;

const char *nm_ppp_mgr_callback_type_to_string(NMPppMgrCallbackType callback_type);

typedef struct {
    guint32 in_bytes;
    guint32 out_bytes;
} NMPppMgrStatsData;

typedef struct {
    const NML3ConfigData     *l3cd;
    const NMUtilsIPv6IfaceId *ipv6_iid;
    NMOptionBool              ip_enabled;
    bool                      ip_received;
} NMPppMgrIPData;

typedef struct {
    NMPppMgrCallbackType callback_type;
    union {
        struct {
            const char *reason_msg;
            union {
                struct {
                    const NMPppMgrIPData *ip_data_6;
                    const NMPppMgrIPData *ip_data_4;
                };
                const NMPppMgrIPData *ip_data_x[2];
            };
            const NMPppMgrStatsData *stats_data;
            int                      ifindex;
            NMDeviceStateReason      reason;
            NMPppMgrState            old_state;
            NMPppMgrState            state;
            union {
                struct {
                    bool ip_changed_6;
                    bool ip_changed_4;
                };
                bool ip_changed_x[2];
            };
        } data;
    };
} NMPppMgrCallbackData;

typedef void (*NMPppMgrCallback)(NMPppMgr                   *self,
                                 const NMPppMgrCallbackData *callback_data,
                                 gpointer                    user_data);

typedef struct {
    NMNetns    *netns;
    const char *parent_iface;

    NMPppMgrCallback callback;
    gpointer         user_data;

    NMActRequest *act_req;
    const char   *ppp_username;
    guint32       timeout_secs;
    guint         baud_override;
} NMPppMgrConfig;

gboolean _nm_assert_is_ppp_mgr(const NMPppMgr *self);

#define NM_IS_PPP_MGR(self)                      \
    ({                                           \
        const NMPppMgr *_self = (self);          \
                                                 \
        nm_assert(_nm_assert_is_ppp_mgr(_self)); \
        !!_self;                                 \
    })

NMPppMgr *nm_ppp_mgr_start(const NMPppMgrConfig *config, GError **error);

NMPppMgrState            nm_ppp_mgr_get_state(const NMPppMgr *self);
int                      nm_ppp_mgr_get_ifindex(const NMPppMgr *self);
const NMPppMgrIPData    *nm_ppp_mgr_get_ip_data(const NMPppMgr *self, int addr_family);
const NMPppMgrStatsData *nm_ppp_mgr_get_stats(const NMPppMgr *self);

void nm_ppp_mgr_destroy(NMPppMgr *self);

#endif /* __NM_PPP_MGR_H__ */
