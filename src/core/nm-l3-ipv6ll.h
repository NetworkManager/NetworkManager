/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_L3_IPV6LL_H__
#define __NM_L3_IPV6LL_H__

#include "nm-l3cfg.h"
#include "nm-core-utils.h"

/*****************************************************************************/

typedef struct _NML3IPv6LL NML3IPv6LL;

typedef enum _nm_packed {

    /* NONE is not actually used by NML3IPv6LL. This is a bogus placeholder
     * state for external users. */
    NM_L3_IPV6LL_STATE_NONE,

    NM_L3_IPV6LL_STATE_STARTING,
    NM_L3_IPV6LL_STATE_DAD_IN_PROGRESS,
    NM_L3_IPV6LL_STATE_READY,
    NM_L3_IPV6LL_STATE_DAD_FAILED,
} NML3IPv6LLState;

const char *nm_l3_ipv6ll_state_to_string(NML3IPv6LLState state);

typedef void (*NML3IPv6LLNotifyFcn)(NML3IPv6LL *           ipv6ll,
                                    NML3IPv6LLState        state,
                                    const struct in6_addr *lladdr,
                                    gpointer               user_data);

static inline gboolean
NM_IS_L3_IPV6LL(const NML3IPv6LL *self)
{
    nm_assert(!self || (NM_IS_L3CFG(*((NML3Cfg **) self))));
    return !!self;
}

NML3IPv6LL *_nm_l3_ipv6ll_new(NML3Cfg *                 l3cfg,
                              gboolean                  assume,
                              NMUtilsStableType         stable_type,
                              const char *              ifname,
                              const char *              network_id,
                              const NMUtilsIPv6IfaceId *token_iid,
                              NML3IPv6LLNotifyFcn       notify_fcn,
                              gpointer                  user_data);

static inline NML3IPv6LL *
nm_l3_ipv6ll_new_stable_privacy(NML3Cfg *           l3cfg,
                                gboolean            assume,
                                NMUtilsStableType   stable_type,
                                const char *        ifname,
                                const char *        network_id,
                                NML3IPv6LLNotifyFcn notify_fcn,
                                gpointer            user_data)
{
    nm_assert(stable_type != NM_UTILS_STABLE_TYPE_NONE);
    return _nm_l3_ipv6ll_new(l3cfg,
                             assume,
                             stable_type,
                             ifname,
                             network_id,
                             NULL,
                             notify_fcn,
                             user_data);
}

static inline NML3IPv6LL *
nm_l3_ipv6ll_new_token(NML3Cfg *                 l3cfg,
                       gboolean                  assume,
                       const NMUtilsIPv6IfaceId *token_iid,
                       NML3IPv6LLNotifyFcn       notify_fcn,
                       gpointer                  user_data)
{
    return _nm_l3_ipv6ll_new(l3cfg,
                             assume,
                             NM_UTILS_STABLE_TYPE_NONE,
                             NULL,
                             NULL,
                             token_iid,
                             notify_fcn,
                             user_data);
}

void nm_l3_ipv6ll_destroy(NML3IPv6LL *self);

NM_AUTO_DEFINE_FCN0(NML3IPv6LL *, _nm_auto_destroy_l3ipv6ll, nm_l3_ipv6ll_destroy);
#define nm_auto_destroy_l3ipv6ll nm_auto(_nm_auto_destroy_l3ipv6ll)

/*****************************************************************************/

NML3Cfg *nm_l3_ipv6ll_get_l3cfg(NML3IPv6LL *self);

int nm_l3_ipv6ll_get_ifindex(NML3IPv6LL *self);

NMPlatform *nm_l3_ipv6ll_get_platform(NML3IPv6LL *self);

/*****************************************************************************/

NML3IPv6LLState nm_l3_ipv6ll_get_state(NML3IPv6LL *self, const struct in6_addr **out_lladdr);

const NML3ConfigData *nm_l3_ipv6ll_get_l3cd(NML3IPv6LL *self);

/*****************************************************************************/

#endif /* __NM_L3_IPV6LL_H__ */
