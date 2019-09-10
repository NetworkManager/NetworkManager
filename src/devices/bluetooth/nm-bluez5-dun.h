// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager -- Network link manager
 *
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef _NM_BLUEZ5_UTILS_H_
#define _NM_BLUEZ5_UTILS_H_

typedef struct _NMBluez5DunContext NMBluez5DunContext;

typedef void (*NMBluez5DunFunc) (NMBluez5DunContext *context,
                                 const char *rfcomm_dev,
                                 GError *error,
                                 gpointer user_data);

NMBluez5DunContext *nm_bluez5_dun_new (const char *adapter,
                                       const char *remote);

void nm_bluez5_dun_connect (NMBluez5DunContext *context,
                            NMBluez5DunFunc callback,
                            gpointer user_data);

/* Clean up connection resources */
void nm_bluez5_dun_cleanup (NMBluez5DunContext *context);

/* Clean up and dispose all resources */
void nm_bluez5_dun_free (NMBluez5DunContext *context);

#endif  /* _NM_BLUEZ5_UTILS_H_ */
