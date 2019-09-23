// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager -- Network link manager
 *
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NM_BLUEZ5_DUN_H__
#define __NM_BLUEZ5_DUN_H__

typedef struct _NMBluez5DunContext NMBluez5DunContext;

#if WITH_BLUEZ5_DUN

typedef void (*NMBluez5DunConnectCb) (NMBluez5DunContext *context,
                                      const char *rfcomm_dev,
                                      GError *error,
                                      gpointer user_data);

typedef void (*NMBluez5DunNotifyTtyHangupCb) (NMBluez5DunContext *context,
                                              gpointer user_data);

gboolean nm_bluez5_dun_connect (const char *adapter,
                                const char *remote,
                                GCancellable *cancellable,
                                NMBluez5DunConnectCb callback,
                                gpointer callback_user_data,
                                NMBluez5DunNotifyTtyHangupCb notify_tty_hangup_cb,
                                gpointer notify_tty_hangup_user_data,
                                GError **error);

void nm_bluez5_dun_disconnect (NMBluez5DunContext *context);

const char *nm_bluez5_dun_context_get_adapter (const NMBluez5DunContext *context);
const char *nm_bluez5_dun_context_get_remote (const NMBluez5DunContext *context);
const char *nm_bluez5_dun_context_get_rfcomm_dev (const NMBluez5DunContext *context);

#endif /* WITH_BLUEZ5_DUN */

#endif  /* __NM_BLUEZ5_DUN_H__ */
