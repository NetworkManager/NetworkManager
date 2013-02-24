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

#ifndef IWMXSDK_H
#define IWMXSDK_H

#include <wimax/WiMaxType.h>
#include <wimax/WiMaxTypesEx.h>
#include <wimax/WiMaxAPIEx.h>

struct wmxsdk;

typedef void (*WimaxNewWmxsdkFunc) (struct wmxsdk *wmxsdk, void *user_data);

typedef void (*WimaxStateChangeFunc) (struct wmxsdk *wmxsdk,
                                      WIMAX_API_DEVICE_STATUS new_status,
                                      WIMAX_API_DEVICE_STATUS old_status,
                                      WIMAX_API_STATUS_REASON reason,
                                      WIMAX_API_CONNECTION_PROGRESS_INFO info,
                                      void *user_data);

typedef void (*WimaxMediaStatusFunc) (struct wmxsdk *wmxsdk,
                                      WIMAX_API_MEDIA_STATUS media_status,
                                      void *user_data);

typedef void (*WimaxConnectResultFunc) (struct wmxsdk *wmxsdk,
                                        WIMAX_API_NETWORK_CONNECTION_RESP resp,
                                        void *user_data);

typedef void (*WimaxScanResultFunc) (struct wmxsdk *wmxsdk,
                                     WIMAX_API_NSP_INFO_EX *nsps,
                                     guint num_nsps,
                                     void *user_data);

typedef void (*WimaxRemovedFunc) (struct wmxsdk *wmxsdk, void *user_data);

struct wmxsdk {
	gint refcount;

	WIMAX_API_DEVICE_ID device_id;

	WimaxStateChangeFunc state_change_cb;
	WimaxMediaStatusFunc media_status_cb;
	WimaxConnectResultFunc connect_result_cb;
	WimaxScanResultFunc scan_result_cb;
	WimaxRemovedFunc removed_cb;
	void *callback_data;

	GMutex network_mutex;

	WIMAX_API_DEVICE_STATUS status;
	WIMAX_API_MEDIA_STATUS media_status;
	GMutex status_mutex;

	GMutex connect_mutex;

	char name[100];
	char ifname[16];
};

struct wmxsdk *iwmx_sdk_get_wmxsdk_for_iface(const char *iface);

struct wmxsdk *wmxsdk_ref(struct wmxsdk *wmxsdk);
void wmxsdk_unref(struct wmxsdk *wmxsdk);

/* Register/unregister callbacks when a new wmxsdk is set up */
void iwmx_sdk_new_callback_register(WimaxNewWmxsdkFunc callback, void *user_data);
void iwmx_sdk_new_callback_unregister(WimaxNewWmxsdkFunc callback, void *user_data);

void iwmx_sdk_set_callbacks(struct wmxsdk *wmxsdk,
                            WimaxStateChangeFunc state_change_cb,
                            WimaxMediaStatusFunc media_status_func,
                            WimaxConnectResultFunc connect_result_cb,
                            WimaxScanResultFunc scan_result_cb,
                            WimaxRemovedFunc removed_cb,
                            void *user_data);

WIMAX_API_DEVICE_STATUS iwmxsdk_status_get(struct wmxsdk *wmxsdk);
int iwmx_sdk_connect(struct wmxsdk *wmxsdk, const char *nsp_name);
int iwmx_sdk_disconnect(struct wmxsdk *wmxsdk);
int iwmx_sdk_set_fast_reconnect_enabled(struct wmxsdk *wmxsdk, int enabled);
WIMAX_API_CONNECTED_NSP_INFO_EX *iwmx_sdk_get_connected_network(struct wmxsdk *wmxsdk);
WIMAX_API_LINK_STATUS_INFO_EX *iwmx_sdk_get_link_status_info(struct wmxsdk *wmxsdk);
const char *iwmx_sdk_dev_status_to_str(WIMAX_API_DEVICE_STATUS status);
const char *iwmx_sdk_reason_to_str(WIMAX_API_STATUS_REASON reason);
const char *iwmx_sdk_media_status_to_str(WIMAX_API_MEDIA_STATUS status);
const char *iwmx_sdk_con_progress_to_str(WIMAX_API_CONNECTION_PROGRESS_INFO progress);
int iwmx_sdk_rf_state_set(struct wmxsdk *wmxsdk, WIMAX_API_RF_STATE rf_state);
int iwmx_sdk_get_networks(struct wmxsdk *wmxsdk);
int iwmx_sdk_api_init(void);
void iwmx_sdk_api_exit(void);

#endif  /* IWMXSDK_H */
