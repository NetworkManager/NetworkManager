/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 *
 *  Copyright (C) 2011 Red Hat, Inc. All rights reserved.
 *  Copyright (C) 2007-2010  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if.h>

#include <glib.h>

#include <WiMaxType.h>
#include <WiMaxAPI.h>
#include <WiMaxAPIEx.h>

#include "logging/nm-logging.h"
#include "iwmxsdk.h"

static WIMAX_API_DEVICE_ID g_api;
static GMutex add_remove_mutex;

/* Misc utilities */
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

/* Misc values */
enum {
	/*
	 * WARNING!!!!!
	 *
	 * ONLY ONE DEVICE SUPPORTED
	 *
	 * - on removal, there is no way to know which device was
	 *   removed (the removed device is removed from the list and
	 *   the callback doesn't have any more information than the
	 *   index in the list that getlistdevice would return -- racy
	 *   as hell).
	 *
	 * - on insertion, there is not enough information provided.
	 */
	IWMX_SDK_DEV_MAX = 1,
};

/* Yes, this is dirty; see above on IWMX_SDK_DEV_MAX */
static struct wmxsdk *g_iwmx_sdk_devs[IWMX_SDK_DEV_MAX];

static struct wmxsdk *deviceid_to_wmxsdk(WIMAX_API_DEVICE_ID *device_id)
{
	unsigned cnt;
	for (cnt = 0; cnt < IWMX_SDK_DEV_MAX; cnt++) {
		struct wmxsdk *wmxsdk = g_iwmx_sdk_devs[cnt];
		if (wmxsdk &&
		    wmxsdk->device_id.deviceIndex == device_id->deviceIndex)
			return wmxsdk;
	}
	return NULL;
}

static int deviceid_to_index(WIMAX_API_DEVICE_ID *device_id)
{
	unsigned cnt;

	for (cnt = 0; cnt < IWMX_SDK_DEV_MAX; cnt++) {
		struct wmxsdk *wmxsdk = g_iwmx_sdk_devs[cnt];
		if (wmxsdk && wmxsdk->device_id.deviceIndex == device_id->deviceIndex)
			return cnt;
	}
	return -1;
}

struct wmxsdk *iwmx_sdk_get_wmxsdk_for_iface(const char *iface)
{
	unsigned cnt;

	for (cnt = 0; cnt < IWMX_SDK_DEV_MAX; cnt++) {
		struct wmxsdk *wmxsdk = g_iwmx_sdk_devs[cnt];
		if (wmxsdk && !strcmp(wmxsdk->ifname, iface))
			return wmxsdk;
	}
	return NULL;
}

/*
 * FIXME: pulled it it out of some hole
 *
 * the cinr to percentage computation comes from the L3/L4 doc
 *
 * But some other places (L4 code) have a more complex, seemingly
 * logarithmical computation.
 *
 * Oh well...
 *
 */
static int cinr_to_percentage(int cinr)
{
	int strength;
	if (cinr <= -5)
		strength = 0;
	else if (cinr >= 25)
		strength = 100;
	else	/* Calc percentage on the value from -5 to 25 */
		strength = ((100UL * (cinr - -5)) / (25 - -5));
	return strength;
}

/**************************************************************/

typedef struct {
	WimaxNewWmxsdkFunc callback;
	void *user_data;
} NewSdkCallback;

static GMutex new_callbacks_mutex;
static GSList *new_callbacks = NULL;

void iwmx_sdk_new_callback_register(WimaxNewWmxsdkFunc callback, void *user_data)
{
	NewSdkCallback *cb;

	cb = g_malloc0 (sizeof (NewSdkCallback));
	g_assert (cb);
	cb->callback = callback;
	cb->user_data = user_data;

	g_mutex_lock (&new_callbacks_mutex);
	new_callbacks = g_slist_append (new_callbacks, cb);
	g_mutex_unlock (&new_callbacks_mutex);
}

void iwmx_sdk_new_callback_unregister(WimaxNewWmxsdkFunc callback, void *user_data)
{
	GSList *iter;
	NewSdkCallback *found = NULL;

	g_mutex_lock (&new_callbacks_mutex);
	for (iter = new_callbacks; iter; iter = g_slist_next (iter)) {
		NewSdkCallback *cb = iter->data;

		if (cb->callback == callback && cb->user_data == user_data) {
			found = cb;
			break;
		}
	}

	if (found) {
		new_callbacks = g_slist_remove (new_callbacks, found);
		g_free (found);
	}
	g_mutex_unlock (&new_callbacks_mutex);
}

static void iwmx_sdk_call_new_callbacks(struct wmxsdk *wmxsdk)
{
	GSList *iter;

	g_mutex_lock (&new_callbacks_mutex);
	for (iter = new_callbacks; iter; iter = g_slist_next (iter)) {
		NewSdkCallback *cb = iter->data;

		cb->callback (wmxsdk, cb->user_data);
	}
	g_mutex_unlock (&new_callbacks_mutex);
}

/****************************************************************/

typedef struct {
	struct wmxsdk *wmxsdk;
	WIMAX_API_DEVICE_STATUS new_status;
	WIMAX_API_DEVICE_STATUS old_status;
	WIMAX_API_STATUS_REASON reason;
	WIMAX_API_CONNECTION_PROGRESS_INFO progress;
} StateChangeInfo;

static gboolean
state_change_handler(gpointer user_data)
{
	StateChangeInfo *info = user_data;

	if (info->wmxsdk->state_change_cb) {
		info->wmxsdk->state_change_cb(info->wmxsdk,
		                              info->new_status,
		                              info->old_status,
		                              info->reason,
		                              info->progress,
		                              info->wmxsdk->callback_data);
	}
	wmxsdk_unref(info->wmxsdk);
	memset(info, 0, sizeof(*info));
	free(info);
	return FALSE;
}

static void
_schedule_state_change(struct wmxsdk *wmxsdk,
                       WIMAX_API_DEVICE_STATUS new_status,
                       WIMAX_API_DEVICE_STATUS old_status,
                       WIMAX_API_STATUS_REASON reason,
                       WIMAX_API_CONNECTION_PROGRESS_INFO progress)
{
	StateChangeInfo *info;

	info = malloc(sizeof (*info));
	if (!info)
		return;

	memset(info, 0, sizeof(*info));
	info->wmxsdk = wmxsdk;
	info->new_status = new_status;
	info->old_status = old_status;
	info->reason = reason;
	info->progress = progress;

	wmxsdk_ref(wmxsdk);
	g_idle_add(state_change_handler, info);
}

typedef struct {
	struct wmxsdk *wmxsdk;
	WIMAX_API_MEDIA_STATUS media_status;
} MediaStatusInfo;

static gboolean
media_status_change_handler(gpointer user_data)
{
	MediaStatusInfo *info = user_data;

	if (info->wmxsdk->media_status_cb) {
		info->wmxsdk->media_status_cb(info->wmxsdk,
		                              info->media_status,
		                              info->wmxsdk->callback_data);
	}
	wmxsdk_unref(info->wmxsdk);
	memset(info, 0, sizeof(*info));
	free(info);
	return FALSE;
}

static void
_schedule_media_status_change(struct wmxsdk *wmxsdk,
                              WIMAX_API_MEDIA_STATUS media_status)
{
	MediaStatusInfo *info;

	info = malloc(sizeof (*info));
	if (!info)
		return;

	memset(info, 0, sizeof(*info));
	info->wmxsdk = wmxsdk;
	info->media_status = media_status;

	wmxsdk_ref(wmxsdk);
	g_idle_add(media_status_change_handler, info);
}

typedef struct {
	struct wmxsdk *wmxsdk;
	WIMAX_API_NETWORK_CONNECTION_RESP result;
} ConnectResultInfo;

static gboolean
connect_result_handler(gpointer user_data)
{
	ConnectResultInfo *info = user_data;

	if (info->wmxsdk->connect_result_cb) {
		info->wmxsdk->connect_result_cb(info->wmxsdk,
		                                info->result,
		                                info->wmxsdk->callback_data);
	}
	wmxsdk_unref(info->wmxsdk);
	memset(info, 0, sizeof(*info));
	free(info);
	return FALSE;
}

static void
_schedule_connect_result(struct wmxsdk *wmxsdk,
                         WIMAX_API_NETWORK_CONNECTION_RESP resp)
{
	ConnectResultInfo *info;

	info = malloc(sizeof (*info));
	if (!info)
		return;

	memset(info, 0, sizeof(*info));
	info->wmxsdk = wmxsdk;
	info->result = resp;

	wmxsdk_ref(wmxsdk);
	g_idle_add(connect_result_handler, info);
}

typedef struct {
	struct wmxsdk *wmxsdk;
	WIMAX_API_NSP_INFO_EX *nsps;
	guint num_nsps;
} ScanResultInfo;

static gboolean
scan_result_handler(gpointer user_data)
{
	ScanResultInfo *info = user_data;

	if (info->wmxsdk->scan_result_cb) {
		info->wmxsdk->scan_result_cb(info->wmxsdk,
		                             info->nsps,
		                             info->num_nsps,
		                             info->wmxsdk->callback_data);
	}
	wmxsdk_unref(info->wmxsdk);
	free(info->nsps);
	memset(info, 0, sizeof(*info));
	free(info);
	return FALSE;
}

static void
_schedule_scan_result(struct wmxsdk *wmxsdk,
                      WIMAX_API_NSP_INFO_EX *nsps,
                      guint num_nsps)
{
	ScanResultInfo *info;
	size_t nsps_size;
	int i, tmp;

	info = malloc(sizeof (*info));
	if (!info)
		return;

	memset(info, 0, sizeof(*info));
	info->wmxsdk = wmxsdk;

	nsps_size = num_nsps * sizeof (WIMAX_API_NSP_INFO_EX);
	info->nsps = malloc(nsps_size);
	memcpy(info->nsps, nsps, nsps_size);
	info->num_nsps = num_nsps;

	/* CAPI may report link quality as zero -- if it does check if it is a bug
	 * by computing it based on CINR. If it is different, use the computed one.
	 */
	for (i = 0; i < num_nsps; i++) {
		WIMAX_API_NSP_INFO_EX *nsp = &info->nsps[i];

		if (nsp->linkQuality == 0) {
			tmp = cinr_to_percentage(nsp->CINR - 10);
			if (tmp != nsp->linkQuality)
				nsp->linkQuality = tmp;
		}
	}

	wmxsdk_ref(wmxsdk);
	g_idle_add(scan_result_handler, info);
}

static gboolean
removed_handler(gpointer user_data)
{
	struct wmxsdk *wmxsdk = user_data;

	if (wmxsdk->removed_cb)
		wmxsdk->removed_cb(wmxsdk, wmxsdk->callback_data);
	wmxsdk_unref(wmxsdk);
	return FALSE;
}

static void
_schedule_removed(struct wmxsdk *wmxsdk)
{
	wmxsdk_ref(wmxsdk);
	g_idle_add(removed_handler, wmxsdk);
}

/****************************************************************/

/*
 * Convert a WiMAX API status to an string.
 */
const char *iwmx_sdk_dev_status_to_str(WIMAX_API_DEVICE_STATUS status)
{
	switch (status) {
	case WIMAX_API_DEVICE_STATUS_UnInitialized:
		return "uninitialized";
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW_SW:
		return "rf off";
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW:
		return "rf off (hard-block)";
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		return "rf off (soft-block)";
	case WIMAX_API_DEVICE_STATUS_Ready:
		return "ready";
	case WIMAX_API_DEVICE_STATUS_Scanning:
		return "scanning";
	case WIMAX_API_DEVICE_STATUS_Connecting:
		return "connecting";
	case WIMAX_API_DEVICE_STATUS_Data_Connected:
		return "connected";
	default:
		return "unknown";
	}
}

const char *iwmx_sdk_reason_to_str(WIMAX_API_STATUS_REASON reason)
{
	switch (reason) {
	case WIMAX_API_STATUS_REASON_Normal:
		return "normal";

	/**< Failed to complete NW entry with the selected operator (unspecified reason).  */
	case WIMAX_API_STATUS_REASON_Fail_to_connect_to_NW:
		return "unspecified failure";

	/**< Failed to complete ranging */
	case WIMAX_API_STATUS_REASON_Fail_to_connect_Ranging:
		return "ranging failed";

	/**< SBC phase failed */
	case WIMAX_API_STATUS_REASON_Fail_to_connect_SBC:
		return "sbc failed";

	/**< Security error. EAP authentication failed device level */
	case WIMAX_API_STATUS_REASON_Fail_to_connect_EAP_AUTH_Device:
		return "EAP device auth failed";

	/**< Security error. EAP authentication failed user level */
	case WIMAX_API_STATUS_REASON_Fail_to_connect_EAP_AUTH_user:
		return "EAP user auth failed";

	/**< Security error. Handshake failed */
	case WIMAX_API_STATUS_REASON_Fail_to_connect_3_Way_Handshake:
		return "3 way handshake failed";

	/**< Registration failed */
	case WIMAX_API_STATUS_REASON_Fail_to_connect_REG:
		return "registration failed";

	/**< Failed to initialize the data path (failed to perform DSA to one UL and one DL SFs). */
	case WIMAX_API_STATUS_REASON_Fail_to_connect_datapath:
		return "datapath failed";

	default:
		return "unknown";
	}
}

const char *iwmx_sdk_media_status_to_str(WIMAX_API_MEDIA_STATUS status)
{
	switch (status) {
	case WIMAX_API_MEDIA_STATUS_LINK_UP:
		return "link-up";
	case WIMAX_API_MEDIA_STATUS_LINK_DOWN:
		return "link-down";
	case WIMAX_API_MEDIA_STATUS_LINK_RENEW:
		return "link-renew";
	default:
		return "unknown";
	}
}

const char *
iwmx_sdk_con_progress_to_str(WIMAX_API_CONNECTION_PROGRESS_INFO progress)
{
	switch (progress) {

	/**< Device is in Ranging */
	case WIMAX_API_DEVICE_CONNECTION_PROGRESS_Ranging:
		return "ranging";

	/**< Device is in SBC */
	case WIMAX_API_DEVICE_CONNECTION_PROGRESS_SBC:
		return "sbc";

	/**< Device is in EAP authentication Device */
	case WIMAX_API_DEVICE_CONNECTION_PROGRESS_EAP_authentication_Device:
		return "eap-auth-device";

	/**< Device is in EAP authentication User */
	case WIMAX_API_DEVICE_CONNECTION_PROGRESS_EAP_authentication_User:
		return "eap-auth-user";

	/**< Device is in 3-way-handshake */
	case WIMAX_API_DEVICE_CONNECTION_PROGRESS_3_way_handshake:
		return "3way-handshake";

	/**< Device is in Registration */
	case WIMAX_API_DEVICE_CONNECTION_PROGRESS_Registration:
		return "registration";

	/**< Device is in De-registration */
	case WIMAX_API_DEVICE_CONNECTION_PROGRESS_De_registration:
		return "deregistration";

	/**< Device is registered (operational) */
	case WIMAX_API_DEVICE_CONNECTION_PROGRESS_Registered:
		return "registered";

	default:
		return "unknown";
	}
}

/*
 * Get the device's status from the device
 *
 * Does NOT cache the result
 * Does NOT trigger a state change in NetworkManager
 *
 * Returns < 0 errno code on error, status code if ok.
 */
static WIMAX_API_DEVICE_STATUS iwmx_sdk_get_device_status(struct wmxsdk *wmxsdk)
{
	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	WIMAX_API_DEVICE_STATUS dev_status;
	WIMAX_API_CONNECTION_PROGRESS_INFO pi;

	r = GetDeviceStatus(&wmxsdk->device_id, &dev_status, &pi);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot read device state: %d (%s)", r, errstr);
		dev_status = -EIO;
	}
	return dev_status;
}

/*
 * Get the device's status from the device but return a string describing it
 *
 * Same conditions as iwmx_sdk_get_device_status().
 */
static const char *iwmx_sdk_get_device_status_str(struct wmxsdk *wmxsdk)
{
	const char *result;
	WIMAX_API_DEVICE_STATUS dev_status;

	dev_status = iwmx_sdk_get_device_status(wmxsdk);
	if ((int) dev_status < 0)
		result = "cannot read device state";
	else
		result = iwmx_sdk_dev_status_to_str(dev_status);
	return result;
}

/*
 * If the device is connected but we don't know about the network,
 * create the knowledge of it.
 *
 * Asks the WiMAX API to report which NSP we are connected to and we
 * create/update a network_el in the device's network list. Then
 * return it.
 *
 * Returns NULL on error.
 *
 */
WIMAX_API_CONNECTED_NSP_INFO_EX *iwmx_sdk_get_connected_network(struct wmxsdk *wmxsdk)
{
	WIMAX_API_CONNECTED_NSP_INFO_EX *nsp_info = NULL;
	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	nsp_info = malloc(sizeof (*nsp_info));
	if (!nsp_info) {
		nm_log_err(LOGD_WIMAX, "wmxsdk: cannot allocate NSP info");
		return NULL;
	}

	r = GetConnectedNSPEx(&wmxsdk->device_id, nsp_info);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot get connected NSP info: %d (%s)", r, errstr);
		free (nsp_info);
		nsp_info = NULL;
	} else {
		/* Migth be 0 sometimes; fix that up */
		if (nsp_info->linkQuality == 0) {
			int linkq_expected = cinr_to_percentage(nsp_info->CINR - 10);
			if (linkq_expected != nsp_info->linkQuality)
				nsp_info->linkQuality = linkq_expected;
		}
	}

	return nsp_info;
}

/*
 * Asks the WiMAX API to report current link statistics.
 *
 * Returns NULL on error.
 *
 */
WIMAX_API_LINK_STATUS_INFO_EX *iwmx_sdk_get_link_status_info(struct wmxsdk *wmxsdk)
{
	WIMAX_API_LINK_STATUS_INFO_EX *stats = NULL;
	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	/* Only report if connected */
	if (iwmxsdk_status_get(wmxsdk) < WIMAX_API_DEVICE_STATUS_Connecting) {
		nm_log_err(LOGD_WIMAX, "wmxsdk: cannot get link status info unless connected");
		return NULL;
	}

	stats = malloc(sizeof (*stats));
	if (!stats) {
		nm_log_err(LOGD_WIMAX, "wmxsdk: cannot allocate links status info");
		return NULL;
	}

	r = GetLinkStatusEx(&wmxsdk->device_id, stats);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot get link status info: %d (%s)", r, errstr);
		free (stats);
		stats = NULL;
	}

	return stats;
}

/*
 * Callback for a RF State command
 *
 * Called by the WiMAX API when a command sent to change the RF state
 * is completed. This is just a confirmation of what happened with the
 * command.
 *
 * We don't do anything, as when the device changes state, the state
 * change callback is called and that will fiddle with the NetworkManager
 * internals.
 */
static void __iwmx_sdk_rf_state_cb(WIMAX_API_DEVICE_ID *device_id,
				   WIMAX_API_RF_STATE rf_state)
{
	nm_log_dbg(LOGD_WIMAX, "rf_state changed to %d", rf_state);
}

/*
 * Turn the radio on or off
 *
 * First it checks that we are in the right state before doing
 * anything; there might be no need to do anything.
 *
 * Issue a command to the WiMAX API, wait for a callback confirming it
 * is done. Sometimes the callback is missed -- in that case, do force
 * a state change evaluation.
 *
 * Frustration note:
 *
 *      Geezoos efing Xist, they make difficult even the most simple
 *      of the operations
 *
 *      This thing is definitely a pain. If the radio is ON already
 *      and you switch it on again...well, there is no way to tell
 *      because you don't get a callback saying it basically
 *      suceeded. But on the other hand, if the thing was in a
 *      different state and action needs to be taken, you have to wait
 *      for a callback to confirm it's done. However, there is also an
 *      state change callback, which is almost the same, so now you
 *      have to handle things in two "unrelated" threads of execution.
 *
 *      How the shpx are you expected to tell the difference? Check
 *      status first? On timeout? Nice gap (eighteen wheeler size) for
 *      race conditions.
 */
int iwmx_sdk_rf_state_set(struct wmxsdk *wmxsdk, WIMAX_API_RF_STATE rf_state)
{
	int result;

	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);
	WIMAX_API_DEVICE_STATUS dev_status;

	g_assert(rf_state == WIMAX_API_RF_ON || rf_state == WIMAX_API_RF_OFF);

	/* Guess what the current radio state is; if it is ON
	 * already, don't redo it. */
	dev_status = iwmx_sdk_get_device_status(wmxsdk);
	if ((int) dev_status < 0) {
		result = dev_status;
		goto error_get_status;
	}
	switch (dev_status) {
	case WIMAX_API_DEVICE_STATUS_UnInitialized:
		result = -EINVAL;
		goto error_cant_do;
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW_SW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW:
		nm_log_err(LOGD_WIMAX, "wmxsdk: cannot turn on radio: hw switch is off");
		result = -EPERM;
		goto error_cant_do;
		break;
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		if (rf_state == WIMAX_API_RF_OFF) {
			result = 0;
			nm_log_dbg(LOGD_WIMAX, "radio is already off");
			goto out_done;
		}
		break;
	case WIMAX_API_DEVICE_STATUS_Ready:
	case WIMAX_API_DEVICE_STATUS_Scanning:
	case WIMAX_API_DEVICE_STATUS_Connecting:
	case WIMAX_API_DEVICE_STATUS_Data_Connected:
		if (rf_state == WIMAX_API_RF_ON) {
			result = 0;
			nm_log_dbg(LOGD_WIMAX, "radio is already on");
			goto out_done;
		}
		break;
	default:
		g_assert(1);
	}
	/* Ok, flip the radio */
	r = CmdControlPowerManagement(&wmxsdk->device_id, rf_state);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot flip radio to %d: %d (%s) [device is in state %s]",
		           rf_state, r, errstr, iwmx_sdk_get_device_status_str(wmxsdk));
		result = -EIO;
	} else
		result = -EINPROGRESS;
out_done:
error_cant_do:
error_get_status:
	return result;
}

/*
 * Read the cached device status
 */
WIMAX_API_DEVICE_STATUS iwmxsdk_status_get(struct wmxsdk *wmxsdk)
{
	WIMAX_API_DEVICE_STATUS status;

	g_mutex_lock(&wmxsdk->status_mutex);
	status = wmxsdk->status;
	g_mutex_unlock(&wmxsdk->status_mutex);
	return status;
}

/*
 * Callback for a Connect command
 *
 * Called by the WiMAX API when a command sent to connect is
 * completed. This is just a confirmation of what happened with the
 * command.
 *
 * WE DON'T DO MUCH HERE -- the real meat happens when a state change
 * callback is sent, where we detect we move to connected state (or
 * from disconnecting to something else); the state change callback is
 * called and that will fiddle with the NetworkManager internals.
 */
static void __iwmx_sdk_connect_cb(WIMAX_API_DEVICE_ID *device_id,
				  WIMAX_API_NETWORK_CONNECTION_RESP resp)
{
	WIMAX_API_DEVICE_STATUS status;
	struct wmxsdk *wmxsdk = deviceid_to_wmxsdk(device_id);

	status = iwmxsdk_status_get(wmxsdk);
	if (resp == WIMAX_API_CONNECTION_SUCCESS) {
		if (status != WIMAX_API_DEVICE_STATUS_Data_Connected) {
			nm_log_err(LOGD_WIMAX, "wmxsdk: error: connect worked, but state"
			           " didn't change (now it is %d [%s])",
			           status,
			           iwmx_sdk_dev_status_to_str(status));
		}
	} else {
		nm_log_err(LOGD_WIMAX, "wmxsdk: failed to connect (status %d: %s)",
		           status, iwmx_sdk_dev_status_to_str(status));
	}

	_schedule_connect_result(wmxsdk, resp);
}

/*
 * Connect to a network
 *
 * This function starts the connection process to a given network;
 * when the device changes status, the status change callback will
 * tell NetworkManager if the network is finally connected or not.
 *
 * One of the reasons it is done like that is to allow external tools
 * to control the device and the plugin just passing the status so
 * NetworkManager displays the right info.
 */
int iwmx_sdk_connect(struct wmxsdk *wmxsdk, const char *nsp_name)
{
	int result = 0;

	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);
	WIMAX_API_DEVICE_STATUS dev_status;
	char sdk_name[MAX_SIZE_OF_NSP_NAME];

	g_mutex_lock(&wmxsdk->connect_mutex);
	/* Guess what the current radio state is; if it is ON
	 * already, don't redo it. */
	dev_status = iwmxsdk_status_get(wmxsdk);
	if ((int) dev_status < 0) {
		result = dev_status;
		goto error_get_status;
	}
	switch (dev_status) {
	case WIMAX_API_DEVICE_STATUS_UnInitialized:
		nm_log_err(LOGD_WIMAX, "wmxsdk: SW BUG? HW is uninitialized");
		result = -EINVAL;
		goto error_cant_do;
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW_SW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot connect: radio is off");
		result = -EPERM;
		goto error_cant_do;
	case WIMAX_API_DEVICE_STATUS_Ready:
	case WIMAX_API_DEVICE_STATUS_Scanning:
		break;
	case WIMAX_API_DEVICE_STATUS_Connecting:
		nm_log_dbg(LOGD_WIMAX, "Connect already pending, waiting for it");
		result = -EINPROGRESS;
		goto error_cant_do;
	case WIMAX_API_DEVICE_STATUS_Data_Connected:
		nm_log_err(LOGD_WIMAX, "wmxsdk: BUG? need to disconnect?");
		result = -EINVAL;
		goto error_cant_do;
	default:
		g_assert(1);
	}

	/* The SDK treats the network name as wchar_t* while the contents are
	 * actually just UTF-8...  WTF?  Hand it a full buffer to work around
	 * boundary cases where the NSP name contains an odd # of characters.
	 */
	memset(sdk_name, 0, sizeof (sdk_name));
	memcpy(sdk_name, nsp_name, strlen (nsp_name));

	/* Ok, do the connection, wait for a callback */
	r = CmdConnectToNetwork(&wmxsdk->device_id, &sdk_name[0], 0, 0);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot connect to network %s: %d (%s) - device is in state '%s'",
		           nsp_name, r, errstr,
		           iwmx_sdk_get_device_status_str(wmxsdk));
		result = -EIO;
	}

error_cant_do:
error_get_status:
	g_mutex_unlock(&wmxsdk->connect_mutex);
	return result;
}

/*
 * Callback for a Disconnect command
 *
 * Called by the WiMAX API when a command sent to connect is
 * completed. This is just a confirmation of what happened with the
 * command.
 *
 * When the device changes state, the state change callback is called
 * and that will fiddle with the NetworkManager internals.
 *
 * We just update the result of the command and wake up anybody who is
 * waiting for this conditional variable.
 */
static void __iwmx_sdk_disconnect_cb(WIMAX_API_DEVICE_ID *device_id,
				     WIMAX_API_NETWORK_CONNECTION_RESP resp)
{
	struct wmxsdk *wmxsdk = deviceid_to_wmxsdk(device_id);
	WIMAX_API_DEVICE_STATUS status;

	status = iwmxsdk_status_get(wmxsdk);
	if (resp == WIMAX_API_CONNECTION_SUCCESS) {
		if (status == WIMAX_API_DEVICE_STATUS_Data_Connected) {
			nm_log_err(LOGD_WIMAX, "wmxsdk: error: disconnect worked, "
				      "but state didn't change (now it is %d [%s])", status,
				      iwmx_sdk_dev_status_to_str(status));
		}
	} else
		nm_log_err(LOGD_WIMAX, "wmxsdk: failed to disconnect (status %d: %s)",
			      status, iwmx_sdk_dev_status_to_str(status));
}

/*
 * Disconnect from a network
 *
 * This function tells the device to disconnect; the state change
 * callback will take care of inform NetworkManager's internals.
 */
int iwmx_sdk_disconnect(struct wmxsdk *wmxsdk)
{
	int result;

	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);
	WIMAX_API_DEVICE_STATUS dev_status;

	g_mutex_lock(&wmxsdk->connect_mutex);
	/* Guess what the current radio state is; if it is ON
	 * already, don't redo it. */
	dev_status = iwmx_sdk_get_device_status(wmxsdk);
	if ((int) dev_status < 0) {
		result = dev_status;
		goto error_get_status;
	}
	switch (dev_status) {
	case WIMAX_API_DEVICE_STATUS_UnInitialized:
		nm_log_err(LOGD_WIMAX, "wmxsdk: SW BUG? HW is uninitialized");
		result = -EINVAL;
		goto error_cant_do;
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW_SW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		nm_log_dbg(LOGD_WIMAX, "Cannot disconnect, radio is off; ignoring");
		result = 0;
		goto error_cant_do;
	case WIMAX_API_DEVICE_STATUS_Ready:
	case WIMAX_API_DEVICE_STATUS_Scanning:
		nm_log_dbg(LOGD_WIMAX, "Cannot disconnect, already disconnected; ignoring");
		result = 0;
		goto error_cant_do;
	case WIMAX_API_DEVICE_STATUS_Connecting:
	case WIMAX_API_DEVICE_STATUS_Data_Connected:
		break;
	default:
		g_assert(1);
	}
	/* Ok, flip the radio */
	r = CmdDisconnectFromNetwork(&wmxsdk->device_id);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot disconnect from network: %d (%s)", r, errstr);
		result = -EIO;
	} else
		result = -EINPROGRESS;
error_cant_do:
error_get_status:
	g_mutex_unlock(&wmxsdk->connect_mutex);
	return result;
}

/*
 * Turn fast reconnect capability on/off
 *
 * This function tells wimaxd to turn fast reconnect on or off.
 */
int iwmx_sdk_set_fast_reconnect_enabled(struct wmxsdk *wmxsdk, int enabled)
{
	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	r = SetFastReconnectCapabilityStatus(&wmxsdk->device_id, !!enabled);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot set fast reconnect to %d: %d (%s)",
		           enabled, r, errstr);
		return -EIO;
	}
	return 0;
}

static void __iwmx_sdk_media_status_update_cb (WIMAX_API_DEVICE_ID_P device_id,
					WIMAX_API_MEDIA_STATUS mediaStatus)
{
	struct wmxsdk *wmxsdk = deviceid_to_wmxsdk(device_id);

	/* Ignore redundant LINK_UP events */
	if (   mediaStatus == WIMAX_API_MEDIA_STATUS_LINK_UP
	    && wmxsdk->media_status == WIMAX_API_MEDIA_STATUS_LINK_UP)
	    return;

	wmxsdk->media_status = mediaStatus;

	nm_log_dbg(LOGD_WIMAX, "wmxsdk: media status change to (%d) %s",
	           mediaStatus, iwmx_sdk_media_status_to_str (mediaStatus));

	_schedule_media_status_change(wmxsdk, mediaStatus);
}

/*
 * Callback for state change messages
 *
 * Just pass them to the state transition handler
 */
static void __iwmx_sdk_state_change_cb(WIMAX_API_DEVICE_ID *device_id,
					WIMAX_API_DEVICE_STATUS status,
					WIMAX_API_STATUS_REASON reason,
					WIMAX_API_CONNECTION_PROGRESS_INFO pi)
{
	struct wmxsdk *wmxsdk = deviceid_to_wmxsdk(device_id);
	WIMAX_API_DEVICE_STATUS old_status;

	nm_log_dbg(LOGD_WIMAX, "wmxsdk: state change to (%d) %s reason (%d) %s",
	           status, iwmx_sdk_dev_status_to_str (status),
	           reason, iwmx_sdk_reason_to_str (reason));

	g_mutex_lock(&wmxsdk->status_mutex);
	old_status = wmxsdk->status;
	wmxsdk->status = status;
	g_mutex_unlock(&wmxsdk->status_mutex);

	_schedule_state_change(wmxsdk, status, old_status, reason, pi);
}

/*
 * Called by _iwmx_sdk_*scan_cb() when [wide or preferred] scan results
 * are available.
 *
 * From here we update NetworkManager's idea of which networks are available.
 */
static void __iwmx_sdk_scan_common_cb(WIMAX_API_DEVICE_ID *device_id,
				      WIMAX_API_NSP_INFO_EX *nsp_list,
				      UINT32 nsp_list_size)
{
	struct wmxsdk *wmxsdk = deviceid_to_wmxsdk(device_id);

	g_mutex_lock(&wmxsdk->network_mutex);
	_schedule_scan_result(wmxsdk, nsp_list, nsp_list_size);
	g_mutex_unlock(&wmxsdk->network_mutex);
}

/*
 * Called by the WiMAX API when we get a wide scan result
 *
 * We treat them same as wide, so we just call that.
 */
static void __iwmx_sdk_wide_scan_cb(WIMAX_API_DEVICE_ID *device_id,
				    WIMAX_API_NSP_INFO_EX *nsp_list,
				    UINT32 nsp_list_size)
{
	__iwmx_sdk_scan_common_cb(device_id, nsp_list, nsp_list_size);
}

/*
 * Called by the WiMAX API when we get a normal (non wide) scan result
 *
 * We treat them same as wide, so we just call that.
 */
static void __iwmx_sdk_scan_cb(WIMAX_API_DEVICE_ID *device_id,
				WIMAX_API_NSP_INFO_EX *nsp_list,
				UINT32 nsp_list_size, UINT32 searchProgress)
{
	__iwmx_sdk_scan_common_cb(device_id, nsp_list, nsp_list_size);
}

/*
 * Called to ask the device to scan for networks
 *
 * We don't really scan as the WiMAX SDK daemon scans in the
 * background for us. We just get the results and hand them back via
 * the scan_result_cb callback.
 */
int iwmx_sdk_get_networks(struct wmxsdk *wmxsdk)
{
	int result;

	UINT32 nsp_list_length = 10;
	WIMAX_API_NSP_INFO_EX nsp_list[10];	/* FIXME: up to 32? */

	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	r = GetNetworkListEx(&wmxsdk->device_id, nsp_list, &nsp_list_length);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot get network list: %d (%s)", r, errstr);
		result = -EIO;
		goto error_scan;
	}

	if (nsp_list_length == 0) {
		nm_log_dbg(LOGD_WIMAX, "no networks");
	} else
		__iwmx_sdk_scan_common_cb(&wmxsdk->device_id, nsp_list,
					nsp_list_length);
	result = 0;
error_scan:
	return result;
}

/*
 * Initialize the WiMAX API, register with it, setup callbacks
 *
 */
static int iwmx_sdk_setup(struct wmxsdk *wmxsdk)
{
	int result, status;

	WIMAX_API_RET r;

	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	result = -ENFILE;

	/* device_id initialized by iwmx_sdk_dev_add */

	r = WiMaxDeviceOpen(&wmxsdk->device_id);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot open device: %d (%s)", r, errstr);
		goto error_wimaxdeviceopen;
	}

	/*
	 * We scan in auto mode (in the background)
	 *
	 * Otherwise is messy -- if we have NetworkManager triggering a scan
	 * when we call iwmx_nm_scan() -> iwmx_sdk_scan(), most of the
	 * times that causes a race condition when the UI asks for a
	 * scan right before displaying the network menu. As there is
	 * no way to cancel an ongoing scan before connecting, we are
	 * stuck. So we do auto bg and have iwmx_sdk_scan() just return
	 * the current network list.
	 */
	r = SetConnectionMode(&wmxsdk->device_id,
			      WIMAX_API_CONNECTION_AUTO_SCAN_MANUAL_CONNECT);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot set connectin mode to manual: %d (%s)", r, errstr);
		goto error_connection_mode;
	}

	r = SubscribeControlPowerManagement(&wmxsdk->device_id,
					    __iwmx_sdk_rf_state_cb);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot subscribe to radio change events: %u (%s)", r, errstr);
		result = -EIO;
		goto error_subscribe_rf_state;
	}

	r = SubscribeDeviceStatusChange(&wmxsdk->device_id,
					__iwmx_sdk_state_change_cb);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot subscribe to state chaneg events: %d (%s)", r, errstr);
		goto error_subscribe_state_change;
	}

	r = SubscribeNetworkSearchWideScanEx(&wmxsdk->device_id,
					     __iwmx_sdk_wide_scan_cb);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot subscribe to wide scan events: %d (%s)", r, errstr);
		goto error_subscribe_wide_scan;
	}
	r = SubscribeNetworkSearchEx(&wmxsdk->device_id, __iwmx_sdk_scan_cb);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot subscribe to scan events: %d (%s)", r, errstr);
		goto error_subscribe_scan;
	}

	r = SubscribeConnectToNetwork(&wmxsdk->device_id,
				      __iwmx_sdk_connect_cb);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot subscribe to connect events: %d (%s)", r, errstr);
		goto error_subscribe_connect;
	}

	r = SubscribeDisconnectToNetwork(&wmxsdk->device_id,
					 __iwmx_sdk_disconnect_cb);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot subscribe to disconnect events: %d (%s)", r, errstr);
		goto error_subscribe_disconnect;
	}

	r = SubscribeMediaStatusUpdate(&wmxsdk->device_id, __iwmx_sdk_media_status_update_cb);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot subscribe to media status events: %d (%s)", r, errstr);
		goto error_subscribe_media_status;
	}

	status = iwmx_sdk_get_device_status(wmxsdk);
	if ((int) status < 0)
		status = WIMAX_API_DEVICE_STATUS_UnInitialized;

	g_mutex_lock(&wmxsdk->status_mutex);
	wmxsdk->status = status;
	g_mutex_unlock(&wmxsdk->status_mutex);

	_schedule_state_change(wmxsdk,
	                       status,
	                       WIMAX_API_DEVICE_STATUS_UnInitialized,
	                       WIMAX_API_STATUS_REASON_Normal,
	                       WIMAX_API_DEVICE_CONNECTION_PROGRESS_Ranging);

	return 0;

	UnsubscribeMediaStatusUpdate(&wmxsdk->device_id);
error_subscribe_media_status:
	UnsubscribeDisconnectToNetwork(&wmxsdk->device_id);
error_subscribe_disconnect:
	UnsubscribeConnectToNetwork(&wmxsdk->device_id);
error_subscribe_connect:
	UnsubscribeNetworkSearchEx(&wmxsdk->device_id);
error_subscribe_scan:
	UnsubscribeNetworkSearchWideScanEx(&wmxsdk->device_id);
error_subscribe_wide_scan:
	UnsubscribeDeviceStatusChange(&wmxsdk->device_id);
error_subscribe_state_change:
	UnsubscribeControlPowerManagement(&wmxsdk->device_id);
error_subscribe_rf_state:
error_connection_mode:
	WiMaxDeviceClose(&wmxsdk->device_id);
error_wimaxdeviceopen:
	return result;
}

/*
 * Called when a device is torn down
 *
 * Cleanup all that is done in iwmx_sdk_setup(). Remove callbacks,
 * unregister from the WiMAX API.
 */
static void iwmx_sdk_remove(struct wmxsdk *wmxsdk)
{
	UnsubscribeMediaStatusUpdate(&wmxsdk->device_id);
	UnsubscribeDisconnectToNetwork(&wmxsdk->device_id);
	UnsubscribeConnectToNetwork(&wmxsdk->device_id);
	UnsubscribeNetworkSearchEx(&wmxsdk->device_id);
	UnsubscribeNetworkSearchWideScanEx(&wmxsdk->device_id);
	UnsubscribeDeviceStatusChange(&wmxsdk->device_id);
	UnsubscribeControlPowerManagement(&wmxsdk->device_id);
	WiMaxDeviceClose(&wmxsdk->device_id);
}

void iwmx_sdk_set_callbacks(struct wmxsdk *wmxsdk,
                            WimaxStateChangeFunc state_change_cb,
                            WimaxMediaStatusFunc media_status_cb,
                            WimaxConnectResultFunc connect_result_cb,
                            WimaxScanResultFunc scan_result_cb,
                            WimaxRemovedFunc removed_cb,
                            void *user_data)
{
	wmxsdk->state_change_cb = state_change_cb;
	wmxsdk->media_status_cb = media_status_cb;
	wmxsdk->connect_result_cb = connect_result_cb;
	wmxsdk->scan_result_cb = scan_result_cb;
	wmxsdk->removed_cb = removed_cb;
	wmxsdk->callback_data = user_data;
}

/* Initialize a [zeroed] struct wmxsdk */
static struct wmxsdk *wmxsdk_new(void)
{
	struct wmxsdk *wmxsdk;

	wmxsdk = malloc(sizeof(*wmxsdk));
	if (wmxsdk) {
		memset(wmxsdk, 0, sizeof(*wmxsdk));

		wmxsdk->refcount = 1;
		g_mutex_init(&wmxsdk->network_mutex);

		wmxsdk->status = WIMAX_API_DEVICE_STATUS_UnInitialized;
		g_mutex_init(&wmxsdk->status_mutex);

		g_mutex_init(&wmxsdk->connect_mutex);
	}
	return wmxsdk;
}

struct wmxsdk *wmxsdk_ref(struct wmxsdk *wmxsdk)
{
	g_atomic_int_add(&wmxsdk->refcount, 1);
	return wmxsdk;
}

void wmxsdk_unref(struct wmxsdk *wmxsdk)
{
	if (g_atomic_int_dec_and_test(&wmxsdk->refcount)) {
		g_mutex_clear(&wmxsdk->status_mutex);
		g_mutex_clear(&wmxsdk->connect_mutex);
		memset(wmxsdk, 0, sizeof(*wmxsdk));
		free(wmxsdk);
	}
}

static void iwmx_sdk_dev_add(unsigned idx, unsigned api_idx, const char *name)
{
	struct wmxsdk *wmxsdk;
	const char *s;

	if (idx >= IWMX_SDK_DEV_MAX) {
		nm_log_err(LOGD_WIMAX, "BUG! idx (%u) >= IWMX_SDK_DEV_MAX (%u)", idx, IWMX_SDK_DEV_MAX);
		return;
	}
	if (g_iwmx_sdk_devs[idx] != NULL) {
		nm_log_err(LOGD_WIMAX, "BUG! device index %u already enumerated?", idx);
		return;
	}

	wmxsdk = wmxsdk_new();
	if (wmxsdk == NULL) {
		nm_log_err(LOGD_WIMAX, "Can't allocate %zu bytes", sizeof(*wmxsdk));
		return;
	}

	/*
	 * This depends on a hack in the WiMAX Network Service; it has
	 * to return, as part of the device name, a string "if:IFNAME"
	 * where the OS's device name is stored.
	 */
	s = strstr(name, "if:");
	if (s == NULL
	    || sscanf(s, "if:%15[^ \f\n\r\t\v]", wmxsdk->ifname) != 1) {
		nm_log_err(LOGD_WIMAX, "Cannot extract network interface name off '%s'",
			      name);
		goto error;
	}
	nm_log_dbg(LOGD_WIMAX, "network interface name: '%s'", wmxsdk->ifname);

	strncpy(wmxsdk->name, name, sizeof(wmxsdk->name));
	wmxsdk->device_id.privilege = WIMAX_API_PRIVILEGE_READ_WRITE;
	wmxsdk->device_id.deviceIndex = api_idx;

	if (iwmx_sdk_setup(wmxsdk) != 0) {
		nm_log_err(LOGD_WIMAX, "wxmsdk: %s: cannot set up interface", wmxsdk->ifname);
		goto error;
	}

	g_iwmx_sdk_devs[idx] = wmxsdk;

	/* Notify listeners of new devices */
	iwmx_sdk_call_new_callbacks (wmxsdk);
	return;

error:
	wmxsdk_unref(wmxsdk);
	return;
}

static void iwmx_sdk_dev_rm(unsigned idx)
{
	struct wmxsdk *wmxsdk;

	if (idx >= IWMX_SDK_DEV_MAX) {
		nm_log_err(LOGD_WIMAX, "BUG! idx (%u) >= IWMX_SDK_DEV_MAX (%u)", idx, IWMX_SDK_DEV_MAX);
		return;
	}

	wmxsdk = g_iwmx_sdk_devs[idx];
	_schedule_removed(wmxsdk);
	iwmx_sdk_remove(wmxsdk);
	wmxsdk_unref(wmxsdk);
	g_iwmx_sdk_devs[idx] = NULL;
}

static void iwmx_sdk_addremove_cb(WIMAX_API_DEVICE_ID *devid,
				  BOOL presence)
{
	unsigned int cnt;
	WIMAX_API_RET r;
	WIMAX_API_HW_DEVICE_ID device_id_list[5];
	UINT32 device_id_list_size = ARRAY_SIZE(device_id_list);
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	g_mutex_lock(&add_remove_mutex);

	nm_log_dbg(LOGD_WIMAX, "cb: handle %u index #%u is %d", devid->sdkHandle,
	           devid->deviceIndex, presence);

	r = GetListDevice(devid, device_id_list, &device_id_list_size);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(devid, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot obtain list of devices: %d (%s)", r, errstr);
		goto out;
	}

	if (device_id_list_size == 0) {
		nm_log_dbg(LOGD_WIMAX, "No WiMAX devices reported");
	} else {
		for (cnt = 0; cnt < device_id_list_size; cnt++) {
			WIMAX_API_HW_DEVICE_ID *dev =
				device_id_list + cnt;
			nm_log_dbg(LOGD_WIMAX, "#%u index #%u device %s", cnt,
			           dev->deviceIndex, dev->deviceName);
		}
	}

	if (presence) {
		WIMAX_API_HW_DEVICE_ID *dev;

		/* Make sure the wimax NS isn't lying to us */
		if (device_id_list_size < devid->deviceIndex) {
			nm_log_err(LOGD_WIMAX, "wmxsdk: changed device (%u) not in the list? (%u items)",
			           devid->deviceIndex, device_id_list_size);
			goto out;
		}

		/* Add the device to our internal list */
		dev = device_id_list + devid->deviceIndex;
		iwmx_sdk_dev_add(devid->deviceIndex, dev->deviceIndex, dev->deviceName);
	} else {
		/* Remove the device from our internal list */
		int idx = deviceid_to_index(devid);

		if (idx >= 0)
			iwmx_sdk_dev_rm(idx);
	}

out:
	g_mutex_unlock(&add_remove_mutex);
}

/*
 * Initialize the WiMAX API, register with it, setup callbacks for
 * device coming up / dissapearing
 */
int iwmx_sdk_api_init(void)
{
	int result;
	unsigned int cnt;
	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	WIMAX_API_HW_DEVICE_ID device_id_list[5];
	UINT32 device_id_list_size = ARRAY_SIZE(device_id_list);

	memset(&g_api, 0, sizeof(g_api));
	g_api.privilege = WIMAX_API_PRIVILEGE_READ_WRITE;

	result = -EIO;
	r = WiMaxAPIOpen(&g_api);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&g_api, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: WiMaxAPIOpen failed with %d (%s)", r, errstr);
		goto error_wimaxapiopen;
	}

	r = SubscribeDeviceInsertRemove(&g_api, iwmx_sdk_addremove_cb);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&g_api, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: insert/remove subscribe failed with %d (%s)", r, errstr);
		goto error_close;
	}

	r = GetListDevice(&g_api, device_id_list, &device_id_list_size);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&g_api, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: Cannot obtain list of devices: %d (%s)", r, errstr);
		goto error_close;
	}
	if (device_id_list_size < g_api.deviceIndex) {
		nm_log_err(LOGD_WIMAX, "wmxsdk: changed device (%u) not in the list? (%u items)",
		           g_api.deviceIndex, device_id_list_size);
	}

	if (device_id_list_size == 0) {
		nm_log_dbg(LOGD_WIMAX, "No WiMAX devices reported");
	} else {
		for (cnt = 0; cnt < device_id_list_size; cnt++) {
			WIMAX_API_HW_DEVICE_ID *dev = device_id_list + cnt;
			nm_log_dbg(LOGD_WIMAX, "#%u index #%u device %s", cnt, dev->deviceIndex, dev->deviceName);
			iwmx_sdk_dev_add(cnt, dev->deviceIndex, dev->deviceName);
		}
	}
	return 0;

error_close:
	WiMaxAPIClose(&g_api);
error_wimaxapiopen:
	return result;
}

void iwmx_sdk_api_exit(void)
{
	WIMAX_API_RET r;

	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	r = WiMaxAPIClose(&g_api);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&g_api, r, errstr, &errstr_size);
		nm_log_err(LOGD_WIMAX, "wmxsdk: WiMaxAPIClose failed with %d (%s)", r, errstr);
	}
	return;
}
