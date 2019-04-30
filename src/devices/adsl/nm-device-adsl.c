/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Pantelis Koukousoulas <pktoss@gmail.com>
 */

#include "nm-default.h"

#include "nm-device-adsl.h"

#include <sys/socket.h>
#include <linux/atmdev.h>
#include <linux/atmbr2684.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#include "nm-ip4-config.h"
#include "devices/nm-device-private.h"
#include "platform/nm-platform.h"
#include "ppp/nm-ppp-manager-call.h"
#include "ppp/nm-ppp-status.h"
#include "nm-setting-adsl.h"
#include "nm-utils.h"

#include "devices/nm-device-logging.h"
_LOG_DECLARE_SELF (NMDeviceAdsl);

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_ATM_INDEX,
);

typedef struct {
	guint         carrier_poll_id;
	int           atm_index;

	/* PPP */
	NMPPPManager *ppp_manager;

	/* RFC 2684 bridging (PPPoE over ATM) */
	int           brfd;
	int           nas_ifindex;
	char *        nas_ifname;
	guint         nas_update_id;
	guint         nas_update_count;
} NMDeviceAdslPrivate;

struct _NMDeviceAdsl {
	NMDevice parent;
	NMDeviceAdslPrivate _priv;
};

struct _NMDeviceAdslClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceAdsl, nm_device_adsl, NM_TYPE_DEVICE)

#define NM_DEVICE_ADSL_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceAdsl, NM_IS_DEVICE_ADSL)

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	return (  NM_DEVICE_CAP_CARRIER_DETECT
	        | NM_DEVICE_CAP_NONSTANDARD_CARRIER
	        | NM_DEVICE_CAP_IS_NON_KERNEL);
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingAdsl *s_adsl;
	const char *protocol;

	if (!NM_DEVICE_CLASS (nm_device_adsl_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

	s_adsl = nm_connection_get_setting_adsl (connection);

	protocol = nm_setting_adsl_get_protocol (s_adsl);
	if (nm_streq0 (protocol, NM_SETTING_ADSL_PROTOCOL_IPOATM)) {
		/* FIXME: we don't yet support IPoATM */
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "IPoATM protocol is not yet supported");
		return FALSE;
	}

	return TRUE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     NMConnection *const*existing_connections,
                     GError **error)
{
	NMSettingAdsl *s_adsl;

	/*
	 * We can't telepathically figure out the username, so if
	 * it wasn't given, we can't complete the connection.
	 */
	s_adsl = nm_connection_get_setting_adsl (connection);
	if (s_adsl && !nm_setting_verify (NM_SETTING (s_adsl), NULL, error))
		return FALSE;

	nm_utils_complete_generic (nm_device_get_platform (device),
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
br2684_assign_vcc (NMDeviceAdsl *self, NMSettingAdsl *s_adsl)
{
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);
	struct sockaddr_atmpvc addr;
	struct atm_backend_br2684 be;
	struct atm_qos qos;
	int errsv, err, bufsize = 8192;
	const char *encapsulation;
	gboolean is_llc;

	g_return_val_if_fail (priv->brfd == -1, FALSE);
	g_return_val_if_fail (priv->nas_ifname != NULL, FALSE);

	priv->brfd = socket (PF_ATMPVC, SOCK_DGRAM | SOCK_CLOEXEC, ATM_AAL5);
	if (priv->brfd < 0) {
		errsv = errno;
		_LOGE (LOGD_ADSL, "failed to open ATM control socket (%d)", errsv);
		return FALSE;
	}

	err = setsockopt (priv->brfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof (bufsize));
	if (err != 0) {
		errsv = errno;
		_LOGE (LOGD_ADSL, "failed to set SNDBUF option (%d)", errsv);
		goto error;
	}

	/* QoS */
	memset (&qos, 0, sizeof (qos));
	qos.aal = ATM_AAL5;
	qos.txtp.traffic_class = ATM_UBR;
	qos.txtp.max_sdu = 1524;
	qos.txtp.pcr = ATM_MAX_PCR;
	qos.rxtp = qos.txtp;

	err = setsockopt (priv->brfd, SOL_ATM, SO_ATMQOS, &qos, sizeof (qos));
	if (err != 0) {
		errsv = errno;
		_LOGE (LOGD_ADSL, "failed to set QoS (%d)", errsv);
		goto error;
	}

	encapsulation = nm_setting_adsl_get_encapsulation (s_adsl);

	/* VPI/VCI */
	memset (&addr, 0, sizeof (addr));
	addr.sap_family = AF_ATMPVC;
	addr.sap_addr.itf = priv->atm_index;
	addr.sap_addr.vpi = (guint16) nm_setting_adsl_get_vpi (s_adsl);
	addr.sap_addr.vci = (int) nm_setting_adsl_get_vci (s_adsl);

	_LOGD (LOGD_ADSL, "assigning address %d.%d.%d encapsulation %s",
	       priv->atm_index, addr.sap_addr.vpi, addr.sap_addr.vci,
	       encapsulation ?: "(none)");

	err = connect (priv->brfd, (struct sockaddr*) &addr, sizeof (addr));
	if (err != 0) {
		errsv = errno;
		_LOGE (LOGD_ADSL, "failed to set VPI/VCI (%d)", errsv);
		goto error;
	}

	/* And last attach the VCC to the interface */
	is_llc = (g_strcmp0 (encapsulation, "llc") == 0);

	memset (&be, 0, sizeof (be));
	be.backend_num = ATM_BACKEND_BR2684;
	be.ifspec.method = BR2684_FIND_BYIFNAME;
	strcpy (be.ifspec.spec.ifname, priv->nas_ifname);
	be.fcs_in = BR2684_FCSIN_NO;
	be.fcs_out = BR2684_FCSOUT_NO;
	be.encaps = is_llc ? BR2684_ENCAPS_LLC : BR2684_ENCAPS_VC;
	err = ioctl (priv->brfd, ATM_SETBACKEND, &be);
	if (err != 0) {
		errsv = errno;
		_LOGE (LOGD_ADSL, "failed to attach VCC (%d)", errsv);
		goto error;
	}

	return TRUE;

error:
	nm_close (priv->brfd);
	priv->brfd = -1;
	return FALSE;
}

static void
link_changed_cb (NMPlatform *platform,
                 int obj_type_i,
                 int ifindex,
                 NMPlatformLink *info,
                 int change_type_i,
                 NMDeviceAdsl *self)
{
	const NMPlatformSignalChangeType change_type = change_type_i;

	if (change_type == NM_PLATFORM_SIGNAL_REMOVED) {
		NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);
		NMDevice *device = NM_DEVICE (self);

		/* This only gets called for PPPoE connections and "nas" interfaces */

		if (priv->nas_ifindex > 0 && ifindex == priv->nas_ifindex) {
			/* NAS device went away for some reason; kill the connection */
			_LOGD (LOGD_ADSL, "br2684 interface disappeared");
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_BR2684_FAILED);
		}
	}
}

static gboolean
pppoe_vcc_config (NMDeviceAdsl *self)
{
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	NMSettingAdsl *s_adsl;

	s_adsl = nm_device_get_applied_setting (device, NM_TYPE_SETTING_ADSL);

	g_return_val_if_fail (s_adsl, FALSE);

	/* Set up the VCC */
	if (!br2684_assign_vcc (self, s_adsl))
		return FALSE;

	/* Watch for the 'nas' interface going away */
	g_signal_connect (nm_device_get_platform (device), NM_PLATFORM_SIGNAL_LINK_CHANGED,
	                  G_CALLBACK (link_changed_cb),
	                  self);

	_LOGD (LOGD_ADSL, "ATM setup successful");

	/* otherwise we're good for stage3 */
	nm_platform_link_set_up (nm_device_get_platform (device), priv->nas_ifindex, NULL);

	return TRUE;
}

static gboolean
nas_update_cb (gpointer user_data)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (user_data);
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);

	g_assert (priv->nas_ifname);

	priv->nas_update_count++;

	if (priv->nas_update_count > 10) {
		priv->nas_update_id = 0;
		_LOGW (LOGD_ADSL, "failed to find br2684 interface %s ifindex after timeout", priv->nas_ifname);
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_BR2684_FAILED);
		return G_SOURCE_REMOVE;
	}

	g_warn_if_fail (priv->nas_ifindex < 0);
	priv->nas_ifindex = nm_platform_link_get_ifindex (nm_device_get_platform (device), priv->nas_ifname);
	if (priv->nas_ifindex < 0) {
		/* Keep waiting for it to appear */
		return G_SOURCE_CONTINUE;
	}

	priv->nas_update_id = 0;
	_LOGD (LOGD_ADSL, "using br2684 iface '%s' index %d", priv->nas_ifname, priv->nas_ifindex);

	if (pppoe_vcc_config (self)) {
		nm_device_activate_schedule_stage3_ip_config_start (device);
	} else {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_BR2684_FAILED);
	}

	return G_SOURCE_REMOVE;
}

static NMActStageReturn
br2684_create_iface (NMDeviceAdsl *self,
                     NMSettingAdsl *s_adsl,
                     NMDeviceStateReason *out_failure_reason)
{
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);
	struct atm_newif_br2684 ni;
	nm_auto_close int fd = -1;
	int err, errsv;
	guint num = 0;

	g_return_val_if_fail (s_adsl != NULL, FALSE);

	if (priv->nas_update_id) {
		g_warn_if_fail (priv->nas_update_id == 0);
		nm_clear_g_source (&priv->nas_update_id);
	}

	fd = socket (PF_ATMPVC, SOCK_DGRAM | SOCK_CLOEXEC, ATM_AAL5);
	if (fd < 0) {
		errsv = errno;
		_LOGE (LOGD_ADSL, "failed to open ATM control socket (%d)", errsv);
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_BR2684_FAILED);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	memset (&ni, 0, sizeof (ni));
	ni.backend_num = ATM_BACKEND_BR2684;
	ni.media = BR2684_MEDIA_ETHERNET;
	ni.mtu = 1500;

	/* Loop attempting to create an interface that doesn't exist yet.  The
	 * kernel can create one for us automatically, but due to API issues it
	 * cannot return that name to us.  Since we want to know the name right
	 * away, just brute-force it.
	 */
	while (num < 10000) {
		memset (&ni.ifname, 0, sizeof (ni.ifname));
		g_snprintf (ni.ifname, sizeof (ni.ifname), "nas%d", num++);

		err = ioctl (fd, ATM_NEWBACKENDIF, &ni);
		if (err == 0) {
			g_free (priv->nas_ifname);
			priv->nas_ifname = g_strdup (ni.ifname);
			_LOGD (LOGD_ADSL, "waiting for br2684 iface '%s' to appear", priv->nas_ifname);

			priv->nas_update_count = 0;
			priv->nas_update_id = g_timeout_add (100, nas_update_cb, self);
			return NM_ACT_STAGE_RETURN_POSTPONE;
		}
		errsv = errno;
		if (errsv != EEXIST) {
			_LOGW (LOGD_ADSL, "failed to create br2684 interface (%d)", errsv);
			break;
		}
	}

	NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_BR2684_FAILED);
	return NM_ACT_STAGE_RETURN_FAILURE;
}

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *out_failure_reason)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (device);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMSettingAdsl *s_adsl;
	const char *protocol;

	s_adsl = nm_device_get_applied_setting (device, NM_TYPE_SETTING_ADSL);

	g_return_val_if_fail (s_adsl, NM_ACT_STAGE_RETURN_FAILURE);

	protocol = nm_setting_adsl_get_protocol (s_adsl);
	_LOGD (LOGD_ADSL, "using ADSL protocol '%s'", protocol);

	if (g_strcmp0 (protocol, NM_SETTING_ADSL_PROTOCOL_PPPOE) == 0) {
		/* PPPoE needs RFC2684 bridging before we can do PPP over it */
		ret = br2684_create_iface (self, s_adsl, out_failure_reason);
	} else if (g_strcmp0 (protocol, NM_SETTING_ADSL_PROTOCOL_PPPOA) == 0) {
		/* PPPoA doesn't need anything special */
		ret = NM_ACT_STAGE_RETURN_SUCCESS;
	} else
		_LOGW (LOGD_ADSL, "unhandled ADSL protocol '%s'", protocol);

	return ret;
}

static void
ppp_state_changed (NMPPPManager *ppp_manager, NMPPPStatus status, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	switch (status) {
	case NM_PPP_STATUS_DISCONNECT:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_DISCONNECT);
		break;
	case NM_PPP_STATUS_DEAD:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_FAILED);
		break;
	default:
		break;
	}
}

static void
ppp_ifindex_set (NMPPPManager *ppp_manager,
                 int ifindex,
                 const char *iface,
                 gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	if (!nm_device_set_ip_ifindex (device, ifindex)) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
	}
}

static void
ppp_ip4_config (NMPPPManager *ppp_manager,
                NMIP4Config *config,
                gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	/* Ignore PPP IP4 events that come in after initial configuration */
	if (nm_device_activate_ip4_state_in_conf (device))
		nm_device_activate_schedule_ip_config_result (device, AF_INET, NM_IP_CONFIG_CAST (config));
}

static NMActStageReturn
act_stage3_ip4_config_start (NMDevice *device,
                             NMIP4Config **out_config,
                             NMDeviceStateReason *out_failure_reason)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (device);
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);
	NMSettingAdsl *s_adsl;
	NMActRequest *req;
	GError *err = NULL;
	const char *ppp_iface;

	req = nm_device_get_act_request (device);

	g_return_val_if_fail (req, NM_ACT_STAGE_RETURN_FAILURE);

	s_adsl = nm_device_get_applied_setting (device, NM_TYPE_SETTING_ADSL);

	g_return_val_if_fail (s_adsl, NM_ACT_STAGE_RETURN_FAILURE);

	/* PPPoE uses the NAS interface, not the ATM interface */
	if (g_strcmp0 (nm_setting_adsl_get_protocol (s_adsl), NM_SETTING_ADSL_PROTOCOL_PPPOE) == 0) {
		g_assert (priv->nas_ifname);
		ppp_iface = priv->nas_ifname;

		_LOGD (LOGD_ADSL, "starting PPPoE on br2684 interface %s", priv->nas_ifname);
	} else {
		ppp_iface = nm_device_get_iface (device);
		_LOGD (LOGD_ADSL, "starting PPPoA");
	}

	priv->ppp_manager = nm_ppp_manager_create (ppp_iface, &err);

	if (priv->ppp_manager) {
		nm_ppp_manager_set_route_parameters (priv->ppp_manager,
		                                     nm_device_get_route_table (device, AF_INET),
		                                     nm_device_get_route_metric (device, AF_INET),
		                                     nm_device_get_route_table (device, AF_INET6),
		                                     nm_device_get_route_metric (device, AF_INET6));
	}

	if (   !priv->ppp_manager
	    || !nm_ppp_manager_start (priv->ppp_manager, req,
	                              nm_setting_adsl_get_username (s_adsl),
	                              30, 0, &err)) {
		_LOGW (LOGD_ADSL, "PPP failed to start: %s", err->message);
		g_error_free (err);

		g_clear_object (&priv->ppp_manager);

		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_PPP_START_FAILED);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	g_signal_connect (priv->ppp_manager, NM_PPP_MANAGER_SIGNAL_STATE_CHANGED,
	                  G_CALLBACK (ppp_state_changed),
	                  self);
	g_signal_connect (priv->ppp_manager, NM_PPP_MANAGER_SIGNAL_IFINDEX_SET,
	                  G_CALLBACK (ppp_ifindex_set),
	                  self);
	g_signal_connect (priv->ppp_manager, NM_PPP_MANAGER_SIGNAL_IP4_CONFIG,
	                  G_CALLBACK (ppp_ip4_config),
	                  self);
	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static NMActStageReturn
act_stage3_ip_config_start (NMDevice *device,
                            int addr_family,
                            gpointer *out_config,
                            NMDeviceStateReason *out_failure_reason)
{
	if (addr_family == AF_INET)
		return act_stage3_ip4_config_start (device, (NMIP4Config **) out_config, out_failure_reason);

	return NM_DEVICE_CLASS (nm_device_adsl_parent_class)->act_stage3_ip_config_start (device, addr_family, out_config, out_failure_reason);
}

static void
adsl_cleanup (NMDeviceAdsl *self)
{
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);

	if (priv->ppp_manager) {
		g_signal_handlers_disconnect_by_func (priv->ppp_manager, G_CALLBACK (ppp_state_changed), self);
		g_signal_handlers_disconnect_by_func (priv->ppp_manager, G_CALLBACK (ppp_ip4_config), self);
		nm_ppp_manager_stop (priv->ppp_manager, NULL, NULL, NULL);
		g_clear_object (&priv->ppp_manager);
	}

	g_signal_handlers_disconnect_by_func (nm_device_get_platform (NM_DEVICE (self)), G_CALLBACK (link_changed_cb), self);

	nm_close (priv->brfd);
	priv->brfd = -1;

	nm_clear_g_source (&priv->nas_update_id);

	/* FIXME: kernel has no way of explicitly deleting the 'nasX' interface yet,
	 * so it gets leaked.  It does get destroyed when it's no longer in use,
	 * but we have no control over that.
	 */
	priv->nas_ifindex = -1;
	g_clear_pointer (&priv->nas_ifname, g_free);
}

static void
deactivate (NMDevice *device)
{
	adsl_cleanup (NM_DEVICE_ADSL (device));
}

/*****************************************************************************/

static gboolean
carrier_update_cb (gpointer user_data)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (user_data);
	int carrier;
	char *path;

	path  = g_strdup_printf ("/sys/class/atm/%s/carrier",
	                         NM_ASSERT_VALID_PATH_COMPONENT (nm_device_get_iface (NM_DEVICE (self))));
	carrier = (int) nm_platform_sysctl_get_int_checked (nm_device_get_platform (NM_DEVICE (self)), NMP_SYSCTL_PATHID_ABSOLUTE (path), 10, 0, 1, -1);
	g_free (path);

	if (carrier != -1)
		nm_device_set_carrier (NM_DEVICE (self), carrier);
	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_ATM_INDEX:
		g_value_set_int (value, NM_DEVICE_ADSL_GET_PRIVATE ((NMDeviceAdsl *) object)->atm_index);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_ATM_INDEX:
		/* construct-only */
		NM_DEVICE_ADSL_GET_PRIVATE ((NMDeviceAdsl *) object)->atm_index = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_device_adsl_init (NMDeviceAdsl *self)
{
}

static void
constructed (GObject *object)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (object);
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);

	G_OBJECT_CLASS (nm_device_adsl_parent_class)->constructed (object);

	priv->carrier_poll_id = g_timeout_add_seconds (5, carrier_update_cb, self);

	_LOGD (LOGD_ADSL, "ATM device index %d", priv->atm_index);

	g_return_if_fail (priv->atm_index >= 0);
}

NMDevice *
nm_device_adsl_new (const char *udi,
                    const char *iface,
                    const char *driver,
                    int atm_index)
{
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (atm_index >= 0, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_ADSL,
	                                  NM_DEVICE_UDI, udi,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_DRIVER, driver,
	                                  NM_DEVICE_ADSL_ATM_INDEX, atm_index,
	                                  NM_DEVICE_TYPE_DESC, "ADSL",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_ADSL,
	                                  NULL);
}

static void
dispose (GObject *object)
{
	adsl_cleanup (NM_DEVICE_ADSL (object));

	nm_clear_g_source (&NM_DEVICE_ADSL_GET_PRIVATE ((NMDeviceAdsl *) object)->carrier_poll_id);

	G_OBJECT_CLASS (nm_device_adsl_parent_class)->dispose (object);
}

static const NMDBusInterfaceInfoExtended interface_info_device_adsl = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_ADSL,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Carrier", "b", NM_DEVICE_CARRIER),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_adsl_class_init (NMDeviceAdslClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->constructed  = constructed;
	object_class->dispose      = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_adsl);

	device_class->connection_type_check_compatible = NM_SETTING_ADSL_SETTING_NAME;

	device_class->get_generic_capabilities = get_generic_capabilities;

	device_class->check_connection_compatible = check_connection_compatible;
	device_class->complete_connection = complete_connection;

	device_class->act_stage2_config = act_stage2_config;
	device_class->act_stage3_ip_config_start = act_stage3_ip_config_start;
	device_class->deactivate = deactivate;

	obj_properties[PROP_ATM_INDEX] =
	     g_param_spec_int (NM_DEVICE_ADSL_ATM_INDEX, "", "",
	                       -1, G_MAXINT, -1,
	                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
