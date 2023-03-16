/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Pantelis Koukousoulas <pktoss@gmail.com>
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-adsl.h"

#include <sys/socket.h>
#include <linux/atmdev.h>
#include <linux/atmbr2684.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#include "devices/nm-device-private.h"
#include "libnm-platform/nm-platform.h"
#include "nm-manager.h"
#include "nm-setting-adsl.h"
#include "nm-utils.h"
#include "ppp/nm-ppp-mgr.h"

#define _NMLOG_DEVICE_TYPE NMDeviceAdsl
#include "devices/nm-device-logging.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_ATM_INDEX, );

typedef struct {
    guint carrier_poll_id;
    int   atm_index;

    NMPppMgr *ppp_mgr;

    /* RFC 2684 bridging (PPPoE over ATM) */
    int      brfd;
    int      nas_ifindex;
    char    *nas_ifname;
    GSource *nas_update_source;
    guint    nas_update_count;
} NMDeviceAdslPrivate;

struct _NMDeviceAdsl {
    NMDevice            parent;
    NMDeviceAdslPrivate _priv;
};

struct _NMDeviceAdslClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceAdsl, nm_device_adsl, NM_TYPE_DEVICE)

#define NM_DEVICE_ADSL_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceAdsl, NM_IS_DEVICE_ADSL, NMDevice)

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *dev)
{
    return (NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_NONSTANDARD_CARRIER
            | NM_DEVICE_CAP_IS_NON_KERNEL);
}

static gboolean
check_connection_compatible(NMDevice     *device,
                            NMConnection *connection,
                            gboolean      check_properties,
                            GError      **error)
{
    NMSettingAdsl *s_adsl;
    const char    *protocol;

    if (!NM_DEVICE_CLASS(nm_device_adsl_parent_class)
             ->check_connection_compatible(device, connection, check_properties, error))
        return FALSE;

    s_adsl = nm_connection_get_setting_adsl(connection);

    protocol = nm_setting_adsl_get_protocol(s_adsl);
    if (nm_streq0(protocol, NM_SETTING_ADSL_PROTOCOL_IPOATM)) {
        /* FIXME: we don't yet support IPoATM */
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                   "IPoATM protocol is not yet supported");
        return FALSE;
    }

    return TRUE;
}

static gboolean
complete_connection(NMDevice            *device,
                    NMConnection        *connection,
                    const char          *specific_object,
                    NMConnection *const *existing_connections,
                    GError             **error)
{
    NMSettingAdsl *s_adsl;

    /*
     * We can't telepathically figure out the username, so if
     * it wasn't given, we can't complete the connection.
     */
    s_adsl = nm_connection_get_setting_adsl(connection);
    if (s_adsl && !nm_setting_verify(NM_SETTING(s_adsl), NULL, error))
        return FALSE;

    nm_utils_complete_generic(nm_device_get_platform(device),
                              connection,
                              NM_SETTING_ADSL_SETTING_NAME,
                              existing_connections,
                              NULL,
                              _("ADSL connection"),
                              NULL,
                              NULL,
                              FALSE); /* No IPv6 yet by default */
    return TRUE;
}

/*****************************************************************************/

static gboolean
br2684_assign_vcc(NMDeviceAdsl *self, NMSettingAdsl *s_adsl)
{
    NMDeviceAdslPrivate      *priv = NM_DEVICE_ADSL_GET_PRIVATE(self);
    struct sockaddr_atmpvc    addr;
    struct atm_backend_br2684 be;
    struct atm_qos            qos;
    int                       errsv, err, bufsize = 8192;
    const char               *encapsulation;
    gboolean                  is_llc;

    g_return_val_if_fail(priv->brfd == -1, FALSE);
    g_return_val_if_fail(priv->nas_ifname != NULL, FALSE);

    priv->brfd = socket(PF_ATMPVC, SOCK_DGRAM | SOCK_CLOEXEC, ATM_AAL5);
    if (priv->brfd < 0) {
        errsv = errno;
        _LOGE(LOGD_ADSL, "failed to open ATM control socket (%d)", errsv);
        priv->brfd = -1;
        return FALSE;
    }

    err = setsockopt(priv->brfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    if (err != 0) {
        errsv = errno;
        _LOGE(LOGD_ADSL, "failed to set SNDBUF option (%d)", errsv);
        goto error;
    }

    /* QoS */
    memset(&qos, 0, sizeof(qos));
    qos.aal                = ATM_AAL5;
    qos.txtp.traffic_class = ATM_UBR;
    qos.txtp.max_sdu       = 1524;
    qos.txtp.pcr           = ATM_MAX_PCR;
    qos.rxtp               = qos.txtp;

    err = setsockopt(priv->brfd, SOL_ATM, SO_ATMQOS, &qos, sizeof(qos));
    if (err != 0) {
        errsv = errno;
        _LOGE(LOGD_ADSL, "failed to set QoS (%d)", errsv);
        goto error;
    }

    encapsulation = nm_setting_adsl_get_encapsulation(s_adsl);

    /* VPI/VCI */
    memset(&addr, 0, sizeof(addr));
    addr.sap_family   = AF_ATMPVC;
    addr.sap_addr.itf = priv->atm_index;
    addr.sap_addr.vpi = (guint16) nm_setting_adsl_get_vpi(s_adsl);
    addr.sap_addr.vci = (int) nm_setting_adsl_get_vci(s_adsl);

    _LOGD(LOGD_ADSL,
          "assigning address %d.%d.%d encapsulation %s",
          priv->atm_index,
          addr.sap_addr.vpi,
          addr.sap_addr.vci,
          encapsulation ?: "(none)");

    err = connect(priv->brfd, (struct sockaddr *) &addr, sizeof(addr));
    if (err != 0) {
        errsv = errno;
        _LOGE(LOGD_ADSL, "failed to set VPI/VCI (%d)", errsv);
        goto error;
    }

    /* And last attach the VCC to the interface */
    is_llc = (g_strcmp0(encapsulation, "llc") == 0);

    memset(&be, 0, sizeof(be));
    be.backend_num   = ATM_BACKEND_BR2684;
    be.ifspec.method = BR2684_FIND_BYIFNAME;
    nm_utils_ifname_cpy(be.ifspec.spec.ifname, priv->nas_ifname);
    be.fcs_in  = BR2684_FCSIN_NO;
    be.fcs_out = BR2684_FCSOUT_NO;
    be.encaps  = is_llc ? BR2684_ENCAPS_LLC : BR2684_ENCAPS_VC;
    err        = ioctl(priv->brfd, ATM_SETBACKEND, &be);
    if (err != 0) {
        errsv = errno;
        _LOGE(LOGD_ADSL, "failed to attach VCC (%d)", errsv);
        goto error;
    }

    return TRUE;

error:
    nm_close(priv->brfd);
    priv->brfd = -1;
    return FALSE;
}

static void
link_changed_cb(NMPlatform           *platform,
                int                   obj_type_i,
                int                   ifindex,
                const NMPlatformLink *info,
                int                   change_type_i,
                NMDeviceAdsl         *self)
{
    const NMPlatformSignalChangeType change_type = change_type_i;

    if (change_type == NM_PLATFORM_SIGNAL_REMOVED) {
        NMDeviceAdslPrivate *priv   = NM_DEVICE_ADSL_GET_PRIVATE(self);
        NMDevice            *device = NM_DEVICE(self);

        /* This only gets called for PPPoE connections and "nas" interfaces */

        if (priv->nas_ifindex > 0 && ifindex == priv->nas_ifindex) {
            /* NAS device went away for some reason; kill the connection */
            _LOGD(LOGD_ADSL, "br2684 interface disappeared");
            nm_device_state_changed(device,
                                    NM_DEVICE_STATE_FAILED,
                                    NM_DEVICE_STATE_REASON_BR2684_FAILED);
        }
    }
}

static gboolean
pppoe_vcc_config(NMDeviceAdsl *self)
{
    NMDeviceAdslPrivate *priv   = NM_DEVICE_ADSL_GET_PRIVATE(self);
    NMDevice            *device = NM_DEVICE(self);
    NMSettingAdsl       *s_adsl;

    s_adsl = nm_device_get_applied_setting(device, NM_TYPE_SETTING_ADSL);

    g_return_val_if_fail(s_adsl, FALSE);

    /* Set up the VCC */
    if (!br2684_assign_vcc(self, s_adsl))
        return FALSE;

    /* Watch for the 'nas' interface going away */
    g_signal_connect(nm_device_get_platform(device),
                     NM_PLATFORM_SIGNAL_LINK_CHANGED,
                     G_CALLBACK(link_changed_cb),
                     self);

    _LOGD(LOGD_ADSL, "ATM setup successful");

    /* otherwise we're good for stage3 */
    nm_platform_link_change_flags(nm_device_get_platform(device), priv->nas_ifindex, IFF_UP, TRUE);

    return TRUE;
}

static gboolean
nas_update_timeout_cb(gpointer user_data)
{
    NMDeviceAdsl        *self   = NM_DEVICE_ADSL(user_data);
    NMDeviceAdslPrivate *priv   = NM_DEVICE_ADSL_GET_PRIVATE(self);
    NMDevice            *device = NM_DEVICE(self);

    nm_assert(priv->nas_ifname);

    priv->nas_update_count++;

    nm_assert(priv->nas_ifindex <= 0);
    priv->nas_ifindex =
        nm_platform_link_get_ifindex(nm_device_get_platform(device), priv->nas_ifname);

    if (priv->nas_ifindex <= 0 && priv->nas_update_count <= 10) {
        /* Keep waiting for it to appear */
        return G_SOURCE_CONTINUE;
    }

    nm_clear_g_source_inst(&priv->nas_update_source);

    if (priv->nas_ifindex <= 0) {
        _LOGW(LOGD_ADSL,
              "failed to find br2684 interface %s ifindex after timeout",
              priv->nas_ifname);
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_BR2684_FAILED);
        return G_SOURCE_CONTINUE;
    }

    _LOGD(LOGD_ADSL, "using br2684 iface '%s' index %d", priv->nas_ifname, priv->nas_ifindex);

    if (!pppoe_vcc_config(self)) {
        nm_device_state_changed(device,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_BR2684_FAILED);
        return G_SOURCE_CONTINUE;
    }

    nm_device_activate_schedule_stage2_device_config(device, TRUE);
    return G_SOURCE_CONTINUE;
}

static gboolean
br2684_create_iface(NMDeviceAdsl *self)
{
    NMDeviceAdslPrivate    *priv = NM_DEVICE_ADSL_GET_PRIVATE(self);
    struct atm_newif_br2684 ni;
    nm_auto_close int       fd = -1;
    int                     err;
    int                     errsv;
    guint                   num = 0;

    nm_assert(!priv->nas_update_source);

    fd = socket(PF_ATMPVC, SOCK_DGRAM | SOCK_CLOEXEC, ATM_AAL5);
    if (fd < 0) {
        errsv = errno;
        _LOGE(LOGD_ADSL, "failed to open ATM control socket (%d)", errsv);
        return FALSE;
    }

    memset(&ni, 0, sizeof(ni));
    ni.backend_num = ATM_BACKEND_BR2684;
    ni.media       = BR2684_MEDIA_ETHERNET;
    ni.mtu         = 1500;

    /* Loop attempting to create an interface that doesn't exist yet.  The
     * kernel can create one for us automatically, but due to API issues it
     * cannot return that name to us.  Since we want to know the name right
     * away, just brute-force it.
     */
    while (TRUE) {
        memset(&ni.ifname, 0, sizeof(ni.ifname));
        g_snprintf(ni.ifname, sizeof(ni.ifname), "nas%u", num++);

        err = ioctl(fd, ATM_NEWBACKENDIF, &ni);
        if (err != 0) {
            errsv = errno;
            if (errsv == EEXIST)
                continue;

            _LOGW(LOGD_ADSL, "failed to create br2684 interface (%d)", errsv);
            return FALSE;
        }

        nm_strdup_reset(&priv->nas_ifname, ni.ifname);
        _LOGD(LOGD_ADSL, "waiting for br2684 iface '%s' to appear", priv->nas_ifname);
        priv->nas_update_count  = 0;
        priv->nas_update_source = nm_g_timeout_add_source(100, nas_update_timeout_cb, self);
        return TRUE;
    }
}

/*****************************************************************************/

static void
_ppp_mgr_cleanup(NMDeviceAdsl *self)
{
    NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE(self);

    nm_clear_pointer(&priv->ppp_mgr, nm_ppp_mgr_destroy);
}

static void
_ppp_mgr_stage3_maybe_ready(NMDeviceAdsl *self)
{
    NMDevice            *device = NM_DEVICE(self);
    NMDeviceAdslPrivate *priv   = NM_DEVICE_ADSL_GET_PRIVATE(self);
    int                  IS_IPv4;

    for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
        const int             addr_family = IS_IPv4 ? AF_INET : AF_INET6;
        const NMPppMgrIPData *ip_data;

        ip_data = nm_ppp_mgr_get_ip_data(priv->ppp_mgr, addr_family);
        if (ip_data->ip_received)
            nm_device_devip_set_state(device, addr_family, NM_DEVICE_IP_STATE_READY, ip_data->l3cd);
    }

    if (nm_ppp_mgr_get_state(priv->ppp_mgr) >= NM_PPP_MGR_STATE_HAVE_IP_CONFIG)
        nm_device_devip_set_state(device, AF_UNSPEC, NM_DEVICE_IP_STATE_READY, NULL);
}

static void
_ppp_mgr_callback(NMPppMgr *ppp_mgr, const NMPppMgrCallbackData *callback_data, gpointer user_data)
{
    NMDeviceAdsl *self   = NM_DEVICE_ADSL(user_data);
    NMDevice     *device = NM_DEVICE(self);
    NMDeviceState device_state;

    if (callback_data->callback_type != NM_PPP_MGR_CALLBACK_TYPE_STATE_CHANGED)
        return;

    device_state = nm_device_get_state(device);

    if (callback_data->data.state >= _NM_PPP_MGR_STATE_FAILED_START) {
        if (device_state <= NM_DEVICE_STATE_ACTIVATED)
            nm_device_state_changed(device, NM_DEVICE_STATE_FAILED, callback_data->data.reason);
        return;
    }

    if (device_state < NM_DEVICE_STATE_IP_CONFIG) {
        if (callback_data->data.state >= NM_PPP_MGR_STATE_HAVE_IFINDEX) {
            gs_free char         *old_name = NULL;
            gs_free_error GError *error    = NULL;

            if (!nm_device_take_over_link(device, callback_data->data.ifindex, &old_name, &error)) {
                _LOGW(LOGD_DEVICE | LOGD_PPP,
                      "could not take control of link %d: %s",
                      callback_data->data.ifindex,
                      error->message);
                _ppp_mgr_cleanup(self);
                nm_device_state_changed(device,
                                        NM_DEVICE_STATE_FAILED,
                                        NM_DEVICE_STATE_REASON_CONFIG_FAILED);
                return;
            }

            if (old_name)
                nm_manager_remove_device(NM_MANAGER_GET, old_name, NM_DEVICE_TYPE_ADSL);

            nm_device_activate_schedule_stage2_device_config(device, FALSE);
        }
        return;
    }

    _ppp_mgr_stage3_maybe_ready(self);
}

/*****************************************************************************/

static NMActStageReturn
act_stage2_config(NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
    NMDeviceAdsl        *self = NM_DEVICE_ADSL(device);
    NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE(self);

    if (!priv->ppp_mgr) {
        gs_free_error GError *error = NULL;
        NMSettingAdsl        *s_adsl;
        const char           *protocol;
        NMActRequest         *req;
        const char           *ppp_iface;

        req = nm_device_get_act_request(device);
        g_return_val_if_fail(req, NM_ACT_STAGE_RETURN_FAILURE);

        s_adsl = nm_device_get_applied_setting(device, NM_TYPE_SETTING_ADSL);
        g_return_val_if_fail(s_adsl, NM_ACT_STAGE_RETURN_FAILURE);

        protocol = nm_setting_adsl_get_protocol(s_adsl);

        _LOGD(LOGD_ADSL, "using ADSL protocol '%s'", protocol);

        if (nm_streq0(protocol, NM_SETTING_ADSL_PROTOCOL_PPPOA)) {
            /* PPPoA doesn't need anything special */
        } else if (nm_streq0(protocol, NM_SETTING_ADSL_PROTOCOL_PPPOE)) {
            /* PPPoE needs RFC2684 bridging before we can do PPP over it */
            if (priv->nas_ifindex <= 0) {
                if (!priv->nas_update_source) {
                    if (!br2684_create_iface(self)) {
                        NM_SET_OUT(out_failure_reason, NM_DEVICE_STATE_REASON_BR2684_FAILED);
                        return NM_ACT_STAGE_RETURN_FAILURE;
                    }
                }
                return NM_ACT_STAGE_RETURN_POSTPONE;
            }
        } else
            nm_assert(nm_streq0(protocol, NM_SETTING_ADSL_PROTOCOL_IPOATM));

        /* PPPoE uses the NAS interface, not the ATM interface */
        if (nm_streq0(protocol, NM_SETTING_ADSL_PROTOCOL_PPPOE)) {
            nm_assert(priv->nas_ifname);
            ppp_iface = priv->nas_ifname;
            _LOGD(LOGD_ADSL, "starting PPPoE on br2684 interface %s", priv->nas_ifname);
        } else {
            ppp_iface = nm_device_get_iface(device);
            _LOGD(LOGD_ADSL, "starting PPPoA");
        }

        priv->ppp_mgr = nm_ppp_mgr_start(&((const NMPppMgrConfig){
                                             .netns         = nm_device_get_netns(device),
                                             .parent_iface  = ppp_iface,
                                             .callback      = _ppp_mgr_callback,
                                             .user_data     = self,
                                             .act_req       = req,
                                             .ppp_username  = nm_setting_adsl_get_username(s_adsl),
                                             .timeout_secs  = 30,
                                             .baud_override = 0,
                                         }),
                                         &error);
        if (!priv->ppp_mgr) {
            _LOGW(LOGD_DEVICE | LOGD_PPP, "PPPoE failed to start: %s", error->message);
            *out_failure_reason = NM_DEVICE_STATE_REASON_PPP_START_FAILED;
            return NM_ACT_STAGE_RETURN_FAILURE;
        }

        return NM_ACT_STAGE_RETURN_POSTPONE;
    }

    if (nm_ppp_mgr_get_state(priv->ppp_mgr) < NM_PPP_MGR_STATE_HAVE_IFINDEX)
        return NM_ACT_STAGE_RETURN_POSTPONE;

    return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
act_stage3_ip_config(NMDevice *device, int addr_family)
{
    NMDeviceAdsl        *self = NM_DEVICE_ADSL(device);
    NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE(self);
    NMPppMgrState        ppp_state;

    if (!priv->ppp_mgr) {
        nm_assert_not_reached();
        return;
    }

    ppp_state = nm_ppp_mgr_get_state(priv->ppp_mgr);

    nm_assert(NM_IN_SET(ppp_state, NM_PPP_MGR_STATE_HAVE_IFINDEX, NM_PPP_MGR_STATE_HAVE_IP_CONFIG));

    if (ppp_state < NM_PPP_MGR_STATE_HAVE_IP_CONFIG) {
        nm_device_devip_set_state(device, AF_UNSPEC, NM_DEVICE_IP_STATE_PENDING, NULL);
        return;
    }

    _ppp_mgr_stage3_maybe_ready(self);
}

static void
adsl_cleanup(NMDeviceAdsl *self)
{
    NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE(self);

    _ppp_mgr_cleanup(self);

    g_signal_handlers_disconnect_by_func(nm_device_get_platform(NM_DEVICE(self)),
                                         G_CALLBACK(link_changed_cb),
                                         self);

    nm_clear_fd(&priv->brfd);

    nm_clear_g_source_inst(&priv->nas_update_source);

    /* FIXME: kernel has no way of explicitly deleting the 'nasX' interface yet,
     * so it gets leaked.  It does get destroyed when it's no longer in use,
     * but we have no control over that.
     */
    priv->nas_ifindex = 0;
    nm_clear_g_free(&priv->nas_ifname);
}

static void
deactivate(NMDevice *device)
{
    adsl_cleanup(NM_DEVICE_ADSL(device));
}

/*****************************************************************************/

static gboolean
carrier_update_cb(gpointer user_data)
{
    NMDeviceAdsl *self = NM_DEVICE_ADSL(user_data);
    int           carrier;
    char         *path;

    path    = g_strdup_printf("/sys/class/atm/%s/carrier",
                           NM_ASSERT_VALID_PATH_COMPONENT(nm_device_get_iface(NM_DEVICE(self))));
    carrier = (int) nm_platform_sysctl_get_int_checked(nm_device_get_platform(NM_DEVICE(self)),
                                                       NMP_SYSCTL_PATHID_ABSOLUTE(path),
                                                       10,
                                                       0,
                                                       1,
                                                       -1);
    g_free(path);

    if (carrier != -1)
        nm_device_set_carrier(NM_DEVICE(self), carrier);
    return TRUE;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    switch (prop_id) {
    case PROP_ATM_INDEX:
        g_value_set_int(value, NM_DEVICE_ADSL_GET_PRIVATE(object)->atm_index);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    switch (prop_id) {
    case PROP_ATM_INDEX:
        /* construct-only */
        NM_DEVICE_ADSL_GET_PRIVATE(object)->atm_index = g_value_get_int(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_device_adsl_init(NMDeviceAdsl *self)
{}

static void
constructed(GObject *object)
{
    NMDeviceAdsl        *self = NM_DEVICE_ADSL(object);
    NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE(self);

    G_OBJECT_CLASS(nm_device_adsl_parent_class)->constructed(object);

    priv->carrier_poll_id = g_timeout_add_seconds(5, carrier_update_cb, self);

    _LOGD(LOGD_ADSL, "ATM device index %d", priv->atm_index);

    g_return_if_fail(priv->atm_index >= 0);
}

NMDevice *
nm_device_adsl_new(const char *udi, const char *iface, const char *driver, int atm_index)
{
    g_return_val_if_fail(udi != NULL, NULL);
    g_return_val_if_fail(atm_index >= 0, NULL);

    return g_object_new(NM_TYPE_DEVICE_ADSL,
                        NM_DEVICE_UDI,
                        udi,
                        NM_DEVICE_IFACE,
                        iface,
                        NM_DEVICE_DRIVER,
                        driver,
                        NM_DEVICE_ADSL_ATM_INDEX,
                        atm_index,
                        NM_DEVICE_TYPE_DESC,
                        "ADSL",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_ADSL,
                        NULL);
}

static void
dispose(GObject *object)
{
    adsl_cleanup(NM_DEVICE_ADSL(object));

    nm_clear_g_source(&NM_DEVICE_ADSL_GET_PRIVATE(object)->carrier_poll_id);

    G_OBJECT_CLASS(nm_device_adsl_parent_class)->dispose(object);
}

static const NMDBusInterfaceInfoExtended interface_info_device_adsl = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_ADSL,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Carrier", "b", NM_DEVICE_CARRIER), ), ),
};

static void
nm_device_adsl_class_init(NMDeviceAdslClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

    object_class->constructed  = constructed;
    object_class->dispose      = dispose;
    object_class->get_property = get_property;
    object_class->set_property = set_property;

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_adsl);

    device_class->connection_type_check_compatible = NM_SETTING_ADSL_SETTING_NAME;

    device_class->get_generic_capabilities = get_generic_capabilities;

    device_class->check_connection_compatible = check_connection_compatible;
    device_class->complete_connection         = complete_connection;

    device_class->act_stage2_config    = act_stage2_config;
    device_class->act_stage3_ip_config = act_stage3_ip_config;
    device_class->deactivate           = deactivate;

    obj_properties[PROP_ATM_INDEX] =
        g_param_spec_int(NM_DEVICE_ADSL_ATM_INDEX,
                         "",
                         "",
                         -1,
                         G_MAXINT,
                         -1,
                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
