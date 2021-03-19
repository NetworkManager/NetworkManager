/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_NET_AUX_H__
#define __NM_NET_AUX_H__

const char *nm_net_aux_rtnl_rtntype_n2a(guint8 v);
int         nm_net_aux_rtnl_rtntype_a2n(const char *name);

#define nm_net_aux_rtnl_rtntype_n2a_maybe_buf(v, buf)                      \
    ({                                                                     \
        const guint8 _v = (v);                                             \
                                                                           \
        /* Warning: this will only touch/initialize @buf if necessary.
         * That means, don't assume that @buf was initialized after calling
         * this macro. */     \
        nm_net_aux_rtnl_rtntype_n2a(v) ?: nm_sprintf_buf((buf), "%u", _v); \
    })

/*****************************************************************************/

#endif /* __NM_NET_AUX_H__ */
