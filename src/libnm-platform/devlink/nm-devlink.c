/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2024 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-devlink.h"

#include <linux/if.h>
#include <linux/devlink.h>

#include "libnm-log-core/nm-logging.h"
#include "libnm-platform/nm-netlink.h"
#include "libnm-platform/nm-platform.h"
#include "libnm-platform/nm-platform-utils.h"

#define _NMLOG_PREFIX_NAME "devlink"
#define _NMLOG_DOMAIN      LOGD_PLATFORM | LOGD_DEVICE
#define _NMLOG(level, ...)                                                                        \
    G_STMT_START                                                                                  \
    {                                                                                             \
        char        _ifname_buf[IFNAMSIZ];                                                        \
        const char *_ifname = self ? nmp_utils_if_indextoname(self->ifindex, _ifname_buf) : NULL; \
                                                                                                  \
        nm_log((level),                                                                           \
               _NMLOG_DOMAIN,                                                                     \
               _ifname ?: NULL,                                                                   \
               NULL,                                                                              \
               "%s%s%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),                                   \
               _NMLOG_PREFIX_NAME,                                                                \
               NM_PRINT_FMT_QUOTED(_ifname, " (", _ifname, ")", "")                               \
                   _NM_UTILS_MACRO_REST(__VA_ARGS__));                                            \
    }                                                                                             \
    G_STMT_END

#define CB_RESULT_PENDING 0
#define CB_RESULT_OK      1

struct _NMDevlink {
    NMPlatform     *plat;
    struct nl_sock *genl_sock_sync;
    guint16         genl_family_id;
    int             ifindex;
};

/**
 * nm_devlink_new:
 * @platform: the #NMPlatform that will use this #NMDevlink instance
 * @genl_sock_sync: the netlink socket (will be used synchronously)
 * @ifindex: the kernel's netdev ifindex corresponding to the devlink device
 *
 * Create a new #NMDevlink instance to make devlink queries regarding a specific
 * device.
 *
 * Returns: (transfer full): the allocated new #NMDevlink
 */
NMDevlink *
nm_devlink_new(NMPlatform *platform, struct nl_sock *genl_sock_sync, int ifindex)
{
    NMDevlink *self = g_new(NMDevlink, 1);

    self->plat           = platform;
    self->genl_sock_sync = genl_sock_sync;
    self->genl_family_id = nm_platform_genl_get_family_id(platform, NMP_GENL_FAMILY_TYPE_DEVLINK);
    self->ifindex        = ifindex;
    return self;
}

/**
 * nm_devlink_get_dev_identifier:
 * @self: the #NMDevlink
 * @out_bus: (out): the "bus_name" part of the devlink device identifier
 * @out_addr: (out): the "bus_addr" part of the devlink device identifier
 * @error: (optional): the error location
 *
 * Get the devlink device identifier of the device for which the #NMDevlink was
 * created (with the @ifindex argument of nm_devlink_get_new()). A devlink device
 * is identified as "bus_name/bus_addr" (i.e. "pci/0000:65:00.0"). This function
 * provides both parts separately.
 *
 * Note that here we only get the potential devlink device identifier. The real devlink
 * device might not even exist if the hw doesn't implement devlink or the netdev
 * doesn't have a 1-1 corresponding devlink device (i.e. because it's a VF or
 * because the hw uses a "one eswitch for many ports" model).
 *
 * Also note that currently only PCI devices are supported, an error will be
 * returned for other kind of devices.
 *
 * Returns: FALSE in case of error, TRUE otherwise
 */
gboolean
nm_devlink_get_dev_identifier(NMDevlink *self, char **out_bus, char **out_addr, GError **error)
{
    const char               *bus;
    char                      sbuf[IFNAMSIZ];
    NMPUtilsEthtoolDriverInfo ethtool_driver_info;

    nm_assert(out_bus != NULL && out_addr != NULL);
    nm_assert(!error || !*error);

    if (!nm_platform_link_get_udev_property(self->plat, self->ifindex, "ID_BUS", &bus)) {
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    "Can't get udev info for device '%s'",
                    nmp_utils_if_indextoname(self->ifindex, sbuf));
        return FALSE;
    }

    if (!nm_streq0(bus, "pci")) {
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    "Devlink is only supported for PCI but device '%s' has bus name '%s'",
                    nmp_utils_if_indextoname(self->ifindex, sbuf),
                    bus);
        return FALSE;
    }

    if (!nmp_utils_ethtool_get_driver_info(self->ifindex, &ethtool_driver_info)) {
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    "Can't get ethtool driver info for device '%s'",
                    nmp_utils_if_indextoname(self->ifindex, sbuf));
        return FALSE;
    }

    *out_bus  = g_strdup("pci");
    *out_addr = g_strdup(ethtool_driver_info._private_bus_info);
    return TRUE;
}

static struct nl_msg *
devlink_alloc_msg(NMDevlink *self, uint8_t cmd, uint16_t flags)
{
    nm_auto_nlmsg struct nl_msg *msg = nlmsg_alloc(0);
    if (!msg)
        return NULL;

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, self->genl_family_id, 0, flags, cmd, 0);
    return g_steal_pointer(&msg);
}

static int
ack_cb_handler(const struct nl_msg *msg, void *data)
{
    int *result = data;
    *result     = CB_RESULT_OK;
    return NL_STOP;
}

static int
finish_cb_handler(const struct nl_msg *msg, void *data)
{
    int *result = data;
    *result     = CB_RESULT_OK;
    return NL_SKIP;
}

static int
err_cb_handler(const struct sockaddr_nl *nla, const struct nlmsgerr *err, void *data)
{
    void      **args       = data;
    NMDevlink  *self       = args[0];
    int        *result     = args[1];
    char      **err_msg    = args[2];
    const char *extack_msg = NULL;

    *result = err->error;
    nlmsg_parse_error(nlmsg_undata(err), &extack_msg);

    _LOGT("error response (%d - %s)", err->error, extack_msg ?: nm_strerror(err->error));

    if (err_msg)
        *err_msg = g_strdup(extack_msg ?: nm_strerror(err->error));

    return NL_SKIP;
}

static int
devlink_send_and_recv(NMDevlink     *self,
                      struct nl_msg *msg,
                      int (*valid_handler)(const struct nl_msg *, void *),
                      void  *valid_data,
                      char **err_msg)
{
    int                nle;
    int                cb_result = CB_RESULT_PENDING;
    void              *err_arg[] = {self, &cb_result, err_msg};
    const struct nl_cb cb        = {
               .err_cb     = err_cb_handler,
               .err_arg    = err_arg,
               .finish_cb  = finish_cb_handler,
               .finish_arg = &cb_result,
               .ack_cb     = ack_cb_handler,
               .ack_arg    = &cb_result,
               .valid_cb   = valid_handler,
               .valid_arg  = valid_data,
    };

    g_return_val_if_fail(msg != NULL, -ENOMEM);

    if (err_msg)
        *err_msg = NULL;

    nle = nl_send_auto(self->genl_sock_sync, msg);
    if (nle < 0)
        goto out;

    while (cb_result == CB_RESULT_PENDING) {
        nle = nl_recvmsgs(self->genl_sock_sync, &cb);
        if (nle < 0 && nle != -EAGAIN) {
            _LOGW("nl_recvmsgs() error (%d - %s)", nle, nm_strerror(nle));
            break;
        }
    }

out:
    if (nle < 0 && err_msg && *err_msg == NULL)
        *err_msg = strdup(nm_strerror(nle));

    if (nle >= 0 && cb_result < 0)
        nle = cb_result;
    return nle;
}

static int
devlink_parse_eswitch_mode(const struct nl_msg *msg, void *data)
{
    static const struct nla_policy eswitch_policy[] = {
        [DEVLINK_ATTR_ESWITCH_MODE]        = {.type = NLA_U16},
        [DEVLINK_ATTR_ESWITCH_INLINE_MODE] = {.type = NLA_U8},
        [DEVLINK_ATTR_ESWITCH_ENCAP_MODE]  = {.type = NLA_U8},
    };
    NMDevlinkEswitchParams *params = data;
    struct genlmsghdr      *gnlh   = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr          *tb[G_N_ELEMENTS(eswitch_policy)];

    if (nla_parse_arr(tb, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), eswitch_policy) < 0)
        return NL_SKIP;

    if (!tb[DEVLINK_ATTR_ESWITCH_MODE] || !tb[DEVLINK_ATTR_ESWITCH_INLINE_MODE]
        || !tb[DEVLINK_ATTR_ESWITCH_ENCAP_MODE])
        return NL_SKIP;

    params->mode       = (_NMSriovEswitchMode) nla_get_u16(tb[DEVLINK_ATTR_ESWITCH_MODE]);
    params->encap_mode = (_NMSriovEswitchEncapMode) nla_get_u8(tb[DEVLINK_ATTR_ESWITCH_ENCAP_MODE]);
    params->inline_mode =
        (_NMSriovEswitchInlineMode) nla_get_u8(tb[DEVLINK_ATTR_ESWITCH_INLINE_MODE]);
    return NL_OK;
}

/*
 * nm_devlink_get_eswitch_params:
 * @self: the #NMDevlink
 * @out_params: the eswitch parameters read via Devlink
 * @error: the error location
 *
 * Get the eswitch configuration of the device related to the #NMDevlink instance. Note
 * that this might be unsupported by the device (see nm_devlink_get_dev()).
 *
 * Returns: FALSE in case of error, TRUE otherwise
 */
gboolean
nm_devlink_get_eswitch_params(NMDevlink *self, NMDevlinkEswitchParams *out_params, GError **error)
{
    nm_auto_nlmsg struct nl_msg *msg     = NULL;
    gs_free char                *bus     = NULL;
    gs_free char                *addr    = NULL;
    gs_free char                *err_msg = NULL;
    int                          rc;

    nm_assert(out_params);

    if (!nm_devlink_get_dev_identifier(self, &bus, &addr, error))
        return FALSE;

    msg = devlink_alloc_msg(self, DEVLINK_CMD_ESWITCH_GET, 0);
    NLA_PUT_STRING(msg, DEVLINK_ATTR_BUS_NAME, bus);
    NLA_PUT_STRING(msg, DEVLINK_ATTR_DEV_NAME, addr);

    rc = devlink_send_and_recv(self, msg, devlink_parse_eswitch_mode, out_params, &err_msg);
    if (rc < 0) {
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    "devlink: eswitch get failed (%d - %s)",
                    rc,
                    err_msg);
        return FALSE;
    }

    _LOGD("eswitch get success");

    return TRUE;

nla_put_failure:
    g_return_val_if_reached(FALSE);
}

/*
 * nm_devlink_set_eswitch_params:
 * @self: the #NMDevlink
 * @params: the eswitch parameters to set
 * @error: the error location
 *
 * Set the eswitch configuration of the device related to the #NMDevlink instance. Note
 * that this might be unsupported by the device (see nm_devlink_get_dev()).
 *
 * If any of the eswitch parameters is set to "preserve" it won't be modified.
 *
 * Returns: FALSE in case of error, TRUE otherwise
 */
gboolean
nm_devlink_set_eswitch_params(NMDevlink *self, NMDevlinkEswitchParams params, GError **error)
{
    nm_auto_nlmsg struct nl_msg *msg     = NULL;
    gs_free char                *bus     = NULL;
    gs_free char                *addr    = NULL;
    gs_free char                *err_msg = NULL;
    int                          rc;

    if (params.mode == _NM_SRIOV_ESWITCH_MODE_PRESERVE
        && params.inline_mode == _NM_SRIOV_ESWITCH_INLINE_MODE_PRESERVE
        && params.encap_mode == _NM_SRIOV_ESWITCH_ENCAP_MODE_PRESERVE)
        return TRUE;

    if (!nm_devlink_get_dev_identifier(self, &bus, &addr, error))
        return FALSE;

    msg = devlink_alloc_msg(self, DEVLINK_CMD_ESWITCH_SET, 0);
    NLA_PUT_STRING(msg, DEVLINK_ATTR_BUS_NAME, bus);
    NLA_PUT_STRING(msg, DEVLINK_ATTR_DEV_NAME, addr);

    if (params.mode != _NM_SRIOV_ESWITCH_MODE_PRESERVE)
        NLA_PUT_U16(msg, DEVLINK_ATTR_ESWITCH_MODE, params.mode);
    if (params.inline_mode != _NM_SRIOV_ESWITCH_INLINE_MODE_PRESERVE)
        NLA_PUT_U8(msg, DEVLINK_ATTR_ESWITCH_INLINE_MODE, params.inline_mode);
    if (params.encap_mode != _NM_SRIOV_ESWITCH_ENCAP_MODE_PRESERVE)
        NLA_PUT_U8(msg, DEVLINK_ATTR_ESWITCH_ENCAP_MODE, params.encap_mode);

    rc = devlink_send_and_recv(self, msg, NULL, NULL, &err_msg);
    if (rc < 0) {
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    "devlink: eswitch set failed (%d - %s)",
                    rc,
                    err_msg);
        return FALSE;
    }

    _LOGD("eswitch set success");

    return TRUE;

nla_put_failure:
    g_return_val_if_reached(FALSE);
}
