// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager -- Network link manager
 *
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef _NM_BLUEZ5_ERROR_H_
#define _NM_BLUEZ5_ERROR_H_

typedef enum {
	NM_BT_ERROR_CONNECTION_NOT_BT = 0,   /*< nick=ConnectionNotBt >*/
	NM_BT_ERROR_CONNECTION_INVALID,      /*< nick=ConnectionInvalid >*/
	NM_BT_ERROR_CONNECTION_INCOMPATIBLE, /*< nick=ConnectionIncompatible >*/
	NM_BT_ERROR_DUN_CONNECT_FAILED,      /*< nick=DunConnectFailed >*/
} NMBtError;

#define NM_BT_ERROR (nm_bt_error_quark ())
GQuark nm_bt_error_quark (void);

#endif  /* _NM_BT_ERROR_H_ */

