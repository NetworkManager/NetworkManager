/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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

#include "config.h"

#include <sys/socket.h>
#include <linux/atmdev.h>
#include <linux/atmbr2684.h>

#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>

#include "nm-default.h"
#include "nm-device-adsl.h"
#include "nm-device-private.h"
#include "NetworkManagerUtils.h"
#include "nm-enum-types.h"
#include "nm-platform.h"

#include "ppp-manager/nm-ppp-manager.h"
#include "nm-setting-adsl.h"
#include "nm-utils.h"

#include "nm-device-adsl-glue.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF (NMDeviceAdsl);

G_DEFINE_TYPE (NMDeviceAdsl, nm_device_adsl, NM_TYPE_DEVICE)

#define NM_DEVICE_ADSL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_ADSL, NMDeviceAdslPrivate))

/**********************************************/

typedef struct {
	gboolean      disposed;
	guint         carrier_poll_id;
	int           atm_index;

	/* PPP */
	NMPPPManager *ppp_manager;

	/* RFC 2684 bridging (PPPoE over ATM) */
	int           brfd;
	int           nas_ifindex;
	char *        nas_ifname;
} NMDeviceAdslPrivate;

/**************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	return (  NM_DEVICE_CAP_CARRIER_DETECT
	        | NM_DEVICE_CAP_NONSTANDARD_CARRIER
	        | NM_DEVICE_CAP_IS_NON_KERNEL);
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMSettingAdsl *s_adsl;
	const char *protocol;

	if (!NM_DEVICE_CLASS (nm_device_adsl_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_ADSL_SETTING_NAME))
		return FALSE;

	s_adsl = nm_connection_get_setting_adsl (connection);
	if (!s_adsl)
		return FALSE;

	/* FIXME: we don't yet support IPoATM */
	protocol = nm_setting_adsl_get_protocol (s_adsl);
	if (g_strcmp0 (protocol, NM_SETTING_ADSL_PROTOCOL_IPOATM) == 0)
		return FALSE;

	return TRUE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
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

	nm_utils_complete_generic (connection,
	                           NM_SETTING_ADSL_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("ADSL connection"),
	                           NULL,
	                           FALSE); /* No IPv6 yet by default */


	return TRUE;
}

/**************************************************************/

static void
set_nas_iface (NMDeviceAdsl *self, int idx, const char *name)
{
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);

	g_return_if_fail (name != NULL);

	g_warn_if_fail (priv->nas_ifindex <= 0);
	priv->nas_ifindex = idx > 0 ? idx : nm_platform_link_get_ifindex (NM_PLATFORM_GET, name);
	g_warn_if_fail (priv->nas_ifindex > 0);

	g_warn_if_fail (priv->nas_ifname == NULL);
	priv->nas_ifname = g_strdup (name);
}

static gboolean
br2684_create_iface (NMDeviceAdsl *self, NMSettingAdsl *s_adsl)
{
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);
	struct atm_newif_br2684 ni;
	int err, fd, errsv;
	gboolean success = FALSE;
	guint num = 0;

	g_return_val_if_fail (s_adsl != NULL, FALSE);

	fd = socket (PF_ATMPVC, SOCK_DGRAM, ATM_AAL5);
	if (fd < 0) {
		errsv = errno;
		_LOGE (LOGD_ADSL, "failed to open ATM control socket (%d)", errsv);
		return FALSE;
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
		g_snprintf (ni.ifname, sizeof (ni.ifname), "nas%d", num);

		err = ioctl (fd, ATM_NEWBACKENDIF, &ni);
		if (err == 0) {
			set_nas_iface (self, -1, ni.ifname);
			_LOGI (LOGD_ADSL, "using NAS interface %s (%d)",
			       priv->nas_ifname, priv->nas_ifindex);
			success = TRUE;
			break;
		} else {
			errsv = errno;
			if (errsv == -EEXIST) {
				/* Try again */
				num++;
			} else {
				_LOGW (LOGD_ADSL, "failed to create br2684 interface (%d)", errsv);
				break;
			}
		}
	}

	close (fd);
	return success;
}

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

	priv->brfd = socket (PF_ATMPVC, SOCK_DGRAM, ATM_AAL5);
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
	       encapsulation ? encapsulation : "(none)");

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
	close (priv->brfd);
	priv->brfd = -1;
	return FALSE;
}

static void
link_changed_cb (NMPlatform *platform, NMPObjectType obj_type, int ifindex, NMPlatformLink *info, NMPlatformSignalChangeType change_type, NMPlatformReason reason, NMDeviceAdsl *self)
{
	if (change_type == NM_PLATFORM_SIGNAL_REMOVED) {
		NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);
		NMDevice *device = NM_DEVICE (self);

		/* This only gets called for PPPoE connections and "nas" interfaces */

		if (priv->nas_ifindex >= 0 && ifindex == priv->nas_ifindex) {
				/* NAS device went away for some reason; kill the connection */
				_LOGD (LOGD_ADSL, "NAS interface disappeared");
				nm_device_state_changed (device,
				                         NM_DEVICE_STATE_FAILED,
				                         NM_DEVICE_STATE_REASON_BR2684_FAILED);
		}
	}
}

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *out_reason)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (device);
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMSettingAdsl *s_adsl;
	const char *protocol;

	g_assert (out_reason);

	s_adsl = nm_connection_get_setting_adsl (nm_device_get_connection (device));
	g_assert (s_adsl);

	protocol = nm_setting_adsl_get_protocol (s_adsl);
	_LOGD (LOGD_ADSL, "using ADSL protocol '%s'", protocol);

	if (g_strcmp0 (protocol, NM_SETTING_ADSL_PROTOCOL_PPPOE) == 0) {

		/* PPPoE needs RFC2684 bridging before we can do PPP over it */
		if (!br2684_create_iface (self, s_adsl)) {
			*out_reason = NM_DEVICE_STATE_REASON_BR2684_FAILED;
			goto done;
		}

		/* Set up the VCC */
		if (!br2684_assign_vcc (self, s_adsl)) {
			*out_reason = NM_DEVICE_STATE_REASON_BR2684_FAILED;
			goto done;
		}

		/* Watch for the 'nas' interface going away */
		g_signal_connect (nm_platform_get (), NM_PLATFORM_SIGNAL_LINK_CHANGED,
		                  G_CALLBACK (link_changed_cb),
		                  self);

		_LOGD (LOGD_ADSL, "ATM setup successful");

		/* otherwise we're good for stage3 */
		nm_platform_link_set_up (NM_PLATFORM_GET, priv->nas_ifindex, NULL);
		ret = NM_ACT_STAGE_RETURN_SUCCESS;

	} else if (g_strcmp0 (protocol, NM_SETTING_ADSL_PROTOCOL_PPPOA) == 0) {
		/* PPPoA doesn't need anything special */
		ret = NM_ACT_STAGE_RETURN_SUCCESS;
	} else
		_LOGW (LOGD_ADSL, "unhandled ADSL protocol '%s'", protocol);

done:
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
ppp_ip4_config (NMPPPManager *ppp_manager,
                const char *iface,
                NMIP4Config *config,
                gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	/* Ignore PPP IP4 events that come in after initial configuration */
	if (nm_device_activate_ip4_state_in_conf (device)) {
		nm_device_set_ip_iface (device, iface);
		nm_device_activate_schedule_ip4_config_result (device, config);
	}
}

static NMActStageReturn
act_stage3_ip4_config_start (NMDevice *device,
                             NMIP4Config **out_config,
                             NMDeviceStateReason *reason)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (device);
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);
	NMConnection *connection;
	NMSettingAdsl *s_adsl;
	NMActRequest *req;
	GError *err = NULL;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	const char *ppp_iface;

	req = nm_device_get_act_request (device);
	g_assert (req);

	connection = nm_act_request_get_connection (req);
	g_assert (req);

	s_adsl = nm_connection_get_setting_adsl (connection);
	g_assert (s_adsl);

	/* PPPoE uses the NAS interface, not the ATM interface */
	if (g_strcmp0 (nm_setting_adsl_get_protocol (s_adsl), NM_SETTING_ADSL_PROTOCOL_PPPOE) == 0) {
		g_assert (priv->nas_ifname);
		ppp_iface = priv->nas_ifname;

		_LOGD (LOGD_ADSL, "starting PPPoE on NAS interface %s", priv->nas_ifname);
	} else {
		ppp_iface = nm_device_get_iface (device);
		_LOGD (LOGD_ADSL, "starting PPPoA");
	}

	priv->ppp_manager = nm_ppp_manager_new (ppp_iface);
	if (nm_ppp_manager_start (priv->ppp_manager, req, nm_setting_adsl_get_username (s_adsl), 30, &err)) {
		g_signal_connect (priv->ppp_manager, "state-changed",
		                  G_CALLBACK (ppp_state_changed),
		                  self);
		g_signal_connect (priv->ppp_manager, "ip4-config",
		                  G_CALLBACK (ppp_ip4_config),
		                  self);
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else {
		_LOGW (LOGD_ADSL, "PPP failed to start: %s", err->message);
		g_error_free (err);

		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;

		*reason = NM_DEVICE_STATE_REASON_PPP_START_FAILED;
	}

	return ret;
}

static void
deactivate (NMDevice *device)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (device);
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);

	if (priv->ppp_manager) {
		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;
	}

	g_signal_handlers_disconnect_by_func (nm_platform_get (), G_CALLBACK (link_changed_cb), device);

	if (priv->brfd >= 0) {
		close (priv->brfd);
		priv->brfd = -1;
	}

	/* FIXME: kernel has no way of explicitly deleting the 'nasX' interface yet,
	 * so it gets leaked.  It does get destroyed when it's no longer in use,
	 * but we have no control over that.
	 */
	if (priv->nas_ifindex >= 0)
		priv->nas_ifindex = -1;
	g_free (priv->nas_ifname);
	priv->nas_ifname = NULL;
}

/**************************************************************/

static gboolean
carrier_update_cb (gpointer user_data)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (user_data);
	int carrier;
	char *path;

	path  = g_strdup_printf ("/sys/class/atm/%s/carrier",
	                         ASSERT_VALID_PATH_COMPONENT (nm_device_get_iface (NM_DEVICE (self))));
	carrier = (int) nm_platform_sysctl_get_int_checked (NM_PLATFORM_GET, path, 10, 0, 1, -1);
	g_free (path);

	if (carrier != -1)
		nm_device_set_carrier (NM_DEVICE (self), carrier);
	return TRUE;
}

/**************************************************************/

NMDevice *
nm_device_adsl_new (const char *udi,
                    const char *iface,
                    const char *driver)
{
	g_return_val_if_fail (udi != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_ADSL,
	                                  NM_DEVICE_UDI, udi,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_DRIVER, driver,
	                                  NM_DEVICE_TYPE_DESC, "ADSL",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_ADSL,
	                                  NULL);
}

static int
get_atm_index (const char *iface)
{
	char *path;
	int idx;

	path = g_strdup_printf ("/sys/class/atm/%s/atmindex",
	                        ASSERT_VALID_PATH_COMPONENT (iface));
	idx = (int) nm_platform_sysctl_get_int_checked (NM_PLATFORM_GET, path, 10, 0, G_MAXINT, -1);
	g_free (path);

	return idx;
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMDeviceAdsl *self;
	NMDeviceAdslPrivate *priv;

	object = G_OBJECT_CLASS (nm_device_adsl_parent_class)->constructor (type,
	                                                                    n_construct_params,
	                                                                    construct_params);
	if (!object)
		return NULL;

	self = NM_DEVICE_ADSL (object);
	priv = NM_DEVICE_ADSL_GET_PRIVATE (object);

	priv->atm_index = get_atm_index (nm_device_get_iface (NM_DEVICE (object)));
	if (priv->atm_index < 0) {
		_LOGE (LOGD_ADSL, "error reading ATM device index");
		g_object_unref (object);
		return NULL;
	} else
		_LOGD (LOGD_ADSL, "ATM device index %d", priv->atm_index);

	/* Poll the carrier */
	priv->carrier_poll_id = g_timeout_add_seconds (5, carrier_update_cb, object);

	return object;
}

static void
dispose (GObject *object)
{
	NMDeviceAdsl *self = NM_DEVICE_ADSL (object);
	NMDeviceAdslPrivate *priv = NM_DEVICE_ADSL_GET_PRIVATE (self);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_device_adsl_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	if (priv->carrier_poll_id) {
		g_source_remove (priv->carrier_poll_id);
		priv->carrier_poll_id = 0;
	}

	g_signal_handlers_disconnect_by_func (nm_platform_get (), G_CALLBACK (link_changed_cb), self);

	g_free (priv->nas_ifname);
	priv->nas_ifname = NULL;

	G_OBJECT_CLASS (nm_device_adsl_parent_class)->dispose (object);
}

static void
nm_device_adsl_init (NMDeviceAdsl *self)
{
}

static void
nm_device_adsl_class_init (NMDeviceAdslClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceAdslPrivate));

	object_class->constructor  = constructor;
	object_class->dispose      = dispose;

	parent_class->get_generic_capabilities = get_generic_capabilities;

	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->complete_connection = complete_connection;

	parent_class->act_stage2_config = act_stage2_config;
	parent_class->act_stage3_ip4_config_start = act_stage3_ip4_config_start;
	parent_class->deactivate = deactivate;

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        &dbus_glib_nm_device_adsl_object_info);
}
