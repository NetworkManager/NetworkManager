/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_L3_IPV4LL_H__
#define __NM_L3_IPV4LL_H__

#include "nm-l3cfg.h"

/*****************************************************************************/

typedef enum _nm_packed {
    NM_L3_IPV4LL_STATE_UNKNOWN,
    NM_L3_IPV4LL_STATE_DISABLED,
    NM_L3_IPV4LL_STATE_WAIT_FOR_LINK,
    NM_L3_IPV4LL_STATE_EXTERNAL,
    NM_L3_IPV4LL_STATE_PROBING,
    NM_L3_IPV4LL_STATE_READY,
    NM_L3_IPV4LL_STATE_DEFENDING,
} NML3IPv4LLState;

const char *nm_l3_ipv4ll_state_to_string(NML3IPv4LLState val, char *buf, gsize len);

static inline gboolean
nm_l3_ipv4ll_state_is_good(NML3IPv4LLState state)
{
    switch (state) {
    case NM_L3_IPV4LL_STATE_UNKNOWN:
    case NM_L3_IPV4LL_STATE_DISABLED:
    case NM_L3_IPV4LL_STATE_WAIT_FOR_LINK:
    case NM_L3_IPV4LL_STATE_PROBING:
        return FALSE;
    case NM_L3_IPV4LL_STATE_EXTERNAL:
    case NM_L3_IPV4LL_STATE_READY:
    case NM_L3_IPV4LL_STATE_DEFENDING:
        return TRUE;
    }
    return nm_assert_unreachable_val(FALSE);
}

/*****************************************************************************/

typedef struct _NML3IPv4LL NML3IPv4LL;

static inline gboolean
NM_IS_L3_IPV4LL(const NML3IPv4LL *self)
{
    nm_assert(!self
              || (NM_IS_L3CFG(*((NML3Cfg **) self))
                  && (*((int *) (((char *) self) + sizeof(gpointer)))) > 0));
    return !!self;
}

NML3IPv4LL *nm_l3_ipv4ll_new(NML3Cfg *self);

NML3IPv4LL *nm_l3_ipv4ll_ref(NML3IPv4LL *self);
void        nm_l3_ipv4ll_unref(NML3IPv4LL *self);

NM_AUTO_DEFINE_FCN0(NML3IPv4LL *, _nm_auto_unref_l3ipv4ll, nm_l3_ipv4ll_unref);
#define nm_auto_unref_l3ipv4ll nm_auto(_nm_auto_unref_l3ipv4ll)

/*****************************************************************************/

NML3Cfg *nm_l3_ipv4ll_get_l3cfg(NML3IPv4LL *self);

int nm_l3_ipv4ll_get_ifindex(NML3IPv4LL *self);

NMPlatform *nm_l3_ipv4ll_get_platform(NML3IPv4LL *self);

/*****************************************************************************/

/* By default, NML3IPv4LL is disabled. You also need to register (enable) it.
 * The intent of this API is that multiple users can enable/register their own
 * settings, and NML3IPv4LL will mediate the different requests.
 *
 * Also, by setting timeout_msec to zero, NML3IPv4LL is disabled again (zero
 * wins over all timeouts). This is useful if you do DHCP and IPv4LL on the
 * same interface. You possibly want to disable IPv4LL if you have a valid
 * DHCP lease. By registering a timeout_msec to zero, you can disable IPv4LL.
 *
 * Also, a registration keeps the NML3IPv4LL instance alive (it also takes
 * a reference).  */

typedef struct _NML3IPv4LLRegistration NML3IPv4LLRegistration;

NML3IPv4LLRegistration *nm_l3_ipv4ll_register_new(NML3IPv4LL *self, guint timeout_msec);

NML3IPv4LLRegistration *nm_l3_ipv4ll_register_update(NML3IPv4LLRegistration *reg,
                                                     guint                   timeout_msec);

NML3IPv4LLRegistration *nm_l3_ipv4ll_register_remove(NML3IPv4LLRegistration *reg);

NM_AUTO_DEFINE_FCN0(NML3IPv4LLRegistration *,
                    _nm_auto_remove_l3ipv4ll_registration,
                    nm_l3_ipv4ll_register_remove);
#define nm_auto_remove_l3ipv4ll_registration nm_auto(_nm_auto_remove_l3ipv4ll_registration)

static inline NML3IPv4LL *
nm_l3_ipv4ll_register_get_instance(NML3IPv4LLRegistration *reg)
{
    NML3IPv4LL *ipv4ll;

    if (!reg)
        return NULL;
    ipv4ll = *((NML3IPv4LL **) reg);
    nm_assert(NM_IS_L3_IPV4LL(ipv4ll));
    return ipv4ll;
}

/*****************************************************************************/

NML3IPv4LLState nm_l3_ipv4ll_get_state(NML3IPv4LL *self);

gboolean nm_l3_ipv4ll_is_timed_out(NML3IPv4LL *self);

in_addr_t nm_l3_ipv4ll_get_addr(NML3IPv4LL *self);

const NML3ConfigData *nm_l3_ipv4ll_get_l3cd(NML3IPv4LL *self);

#endif /* __NM_L3_IPV4LL_H__ */
