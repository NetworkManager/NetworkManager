/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-prog.h"

#include "libnm-log-core/nm-logging.h"
#include "libnm-platform/nm-netlink.h"
#include "libnm-platform/nmp-netns.h"
#include "libnm-platform/nm-platform-utils.h"
#include "libnm-platform/nmp-object.h"

#include "libnm-glib-aux/nm-test-utils.h"

/*****************************************************************************/

G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectIP4Address));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectIP4Route));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectIP6Address));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectIP6Route));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLink));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkBond));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkBridge));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkGre));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkInfiniband));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkIp6Tnl));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkIpIp));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkMacsec));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkMacvlan));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkSit));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkTun));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkVlan));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkVrf));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkVti));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkVti6));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkVxlan));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectLnkWireGuard));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectQdisc));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectRoutingRule));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPObjectTfilter));

G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformIP4Address));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformIP4Route));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformIP6Address));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformIP6Route));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformIPAddress));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformIPAddress));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformIPRoute));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformIPXAddress));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformIPXRoute));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLink));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkBond));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkBridge));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkGre));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkInfiniband));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkIp6Tnl));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkIpIp));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkMacsec));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkMacvlan));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkSit));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkTun));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkVlan));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkVrf));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkVti));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkVti6));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkVxlan));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformLnkWireGuard));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformObjWithIfindex));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformQdisc));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformRoutingRule));
G_STATIC_ASSERT(_nm_alignof(NMPlatformObject) == _nm_alignof(NMPlatformTfilter));

/*****************************************************************************/

static void
test_use_symbols(void)
{
    static void (*const SYMBOLS[])(void) = {
        (void (*)(void)) nl_nlmsghdr_to_str,
        (void (*)(void)) nlmsg_hdr,
        (void (*)(void)) nlmsg_reserve,
        (void (*)(void)) nla_reserve,
        (void (*)(void)) nlmsg_alloc_convert,
        (void (*)(void)) nlmsg_alloc_new,
        (void (*)(void)) nlmsg_alloc,
        (void (*)(void)) nlmsg_free,
        (void (*)(void)) nlmsg_append,
        (void (*)(void)) nlmsg_parse,
        (void (*)(void)) nlmsg_put,
        (void (*)(void)) nla_strlcpy,
        (void (*)(void)) nla_memcpy,
        (void (*)(void)) nla_put,
        (void (*)(void)) nla_find,
        (void (*)(void)) nla_nest_cancel,
        (void (*)(void)) nla_nest_start,
        (void (*)(void)) nla_nest_end,
        (void (*)(void)) nla_parse,
        (void (*)(void)) nlmsg_get_proto,
        (void (*)(void)) nlmsg_set_proto,
        (void (*)(void)) nlmsg_set_src,
        (void (*)(void)) nlmsg_get_creds,
        (void (*)(void)) nlmsg_set_creds,
        (void (*)(void)) genlmsg_put,
        (void (*)(void)) genlmsg_data,
        (void (*)(void)) genlmsg_user_hdr,
        (void (*)(void)) genlmsg_hdr,
        (void (*)(void)) genlmsg_user_data,
        (void (*)(void)) genlmsg_attrdata,
        (void (*)(void)) genlmsg_len,
        (void (*)(void)) genlmsg_attrlen,
        (void (*)(void)) genlmsg_valid_hdr,
        (void (*)(void)) genlmsg_parse,
        (void (*)(void)) genl_ctrl_resolve,
        (void (*)(void)) nl_socket_new,
        (void (*)(void)) nl_socket_free,
        (void (*)(void)) nl_socket_get_fd,
        (void (*)(void)) nl_socket_get_local_port,
        (void (*)(void)) nl_socket_get_msg_buf_size,
        (void (*)(void)) nl_socket_set_passcred,
        (void (*)(void)) nl_socket_set_msg_buf_size,
        (void (*)(void)) nlmsg_get_dst,
        (void (*)(void)) nl_socket_set_nonblocking,
        (void (*)(void)) nl_socket_set_buffer_size,
        (void (*)(void)) nl_socket_add_memberships,
        (void (*)(void)) nl_wait_for_ack,
        (void (*)(void)) nl_recvmsgs,
        (void (*)(void)) nl_sendmsg,
        (void (*)(void)) nl_send_iovec,
        (void (*)(void)) nl_complete_msg,
        (void (*)(void)) nl_send,
        (void (*)(void)) nl_send_auto,
        (void (*)(void)) nl_recv,

        (void (*)(void)) nmp_netns_bind_to_path,
        (void (*)(void)) nmp_netns_bind_to_path_destroy,
        (void (*)(void)) nmp_netns_get_current,
        (void (*)(void)) nmp_netns_get_fd_mnt,
        (void (*)(void)) nmp_netns_get_fd_net,
        (void (*)(void)) nmp_netns_get_initial,
        (void (*)(void)) nmp_netns_is_initial,
        (void (*)(void)) nmp_netns_new,
        (void (*)(void)) nmp_netns_pop,
        (void (*)(void)) nmp_netns_push,
        (void (*)(void)) nmp_netns_push_type,

        NULL,
    };

    /* The only (not very exciting) purpose of this test is to see that
     * we can use various symbols and don't get a linker error. */
    assert(G_N_ELEMENTS(SYMBOLS) == NM_PTRARRAY_LEN(SYMBOLS) + 1);
}

/*****************************************************************************/

static void
test_nmp_link_mode_all_advertised_modes_bits(void)
{
    guint32 flags[(SCHAR_MAX + 1) / 32];
    guint   max_bit;
    int     i;

    memset(flags, 0, sizeof(flags));

    max_bit = 0;
    for (i = 0; i < (int) G_N_ELEMENTS(_nmp_link_mode_all_advertised_modes_bits); i++) {
        if (i > 0) {
            g_assert_cmpint(_nmp_link_mode_all_advertised_modes_bits[i - 1],
                            <,
                            _nmp_link_mode_all_advertised_modes_bits[i]);
        }
        g_assert_cmpint(_nmp_link_mode_all_advertised_modes_bits[i], <, SCHAR_MAX);
        g_assert_cmpint(_nmp_link_mode_all_advertised_modes_bits[i] / 32, <, G_N_ELEMENTS(flags));
        flags[_nmp_link_mode_all_advertised_modes_bits[i] / 32] |=
            (1u << (_nmp_link_mode_all_advertised_modes_bits[i] % 32u));
        max_bit = NM_MAX(max_bit, _nmp_link_mode_all_advertised_modes_bits[i]);
    }

    g_assert_cmpint((max_bit + 31u) / 32u, ==, G_N_ELEMENTS(_nmp_link_mode_all_advertised_modes));

    for (i = 0; i < (int) G_N_ELEMENTS(_nmp_link_mode_all_advertised_modes); i++) {
        if (flags[i] != _nmp_link_mode_all_advertised_modes[i]) {
            NM_PRAGMA_WARNING_DISABLE_DANGLING_POINTER
            g_error("_nmp_link_mode_all_advertised_modes[%d] should be 0x%0x but is 0x%0x "
                    "(according to the bits in _nmp_link_mode_all_advertised_modes_bits)",
                    i,
                    flags[i],
                    _nmp_link_mode_all_advertised_modes[i]);
            NM_PRAGMA_WARNING_REENABLE
        }
    }
}

/*****************************************************************************/

static void
test_nmpclass_consistency(void)
{
    NMPObjectType obj_type;
    NMPObjectType obj_type2;

    G_STATIC_ASSERT(G_N_ELEMENTS(_nmp_classes) == NMP_OBJECT_TYPE_MAX);

    for (obj_type = 1; obj_type <= NMP_OBJECT_TYPE_MAX; obj_type++) {
        const NMPClass *klass = nmp_class_from_type(obj_type);
        gboolean        is_lnk;

        g_assert(klass);
        g_assert(klass == &_nmp_classes[obj_type - 1]);

        g_assert_cmpint(klass->obj_type, ==, obj_type);
        g_assert(klass->obj_type_name);

        g_assert((!!klass->cmd_obj_cmp) == (!!klass->cmd_obj_hash_update));
        g_assert((!!klass->cmd_plobj_cmp) == (!!klass->cmd_plobj_hash_update));
        g_assert((!!klass->cmd_plobj_id_cmp) == (!!klass->cmd_plobj_id_hash_update));

        g_assert((!!klass->cmd_obj_cmp) != (!!klass->cmd_plobj_cmp));
        g_assert((!!klass->cmd_obj_hash_update) != (!!klass->cmd_plobj_hash_update));

        g_assert((!klass->cmd_obj_cmp) || (!klass->cmd_plobj_id_cmp));
        g_assert((!klass->cmd_obj_hash_update) || (!klass->cmd_plobj_id_hash_update));

        g_assert_cmpint(klass->sizeof_public, >, 0);
        g_assert_cmpint(klass->sizeof_data, >=, klass->sizeof_public);

        g_assert((!!klass->cmd_obj_to_string) != (!!klass->cmd_plobj_to_string));
        g_assert(!klass->cmd_plobj_to_string_id || klass->cmd_plobj_to_string);

        is_lnk = (obj_type >= NMP_OBJECT_TYPE_LNK_BRIDGE && obj_type <= NMP_OBJECT_TYPE_LNK_BOND);
        if (klass->lnk_link_type == NM_LINK_TYPE_NONE) {
            G_STATIC_ASSERT(NM_LINK_TYPE_NONE == 0);
            g_assert(!is_lnk);
        } else
            g_assert(is_lnk);

        for (obj_type2 = 1; obj_type2 < obj_type; obj_type2++) {
            const NMPClass *klass2 = nmp_class_from_type(obj_type2);

            g_assert_cmpstr(klass->obj_type_name, !=, klass2->obj_type_name);
        }
    }
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    g_test_add_func("/nm-platform/test_use_symbols", test_use_symbols);
    g_test_add_func("/nm-platform/test_nmp_link_mode_all_advertised_modes_bits",
                    test_nmp_link_mode_all_advertised_modes_bits);
    g_test_add_func("/nm-platform/test_nmpclass_consistency", test_nmpclass_consistency);

    return g_test_run();
}
