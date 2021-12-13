/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_PRIV_HELPER_CALL_H__
#define __NM_PRIV_HELPER_CALL_H__

#include "../libnm-base/nm-priv-helper-utils.h"

typedef void (*NMPrivHelperCallGetFDCallback)(int fd_take, GError *error, gpointer user_data);

void nm_priv_helper_call_get_fd(NMPrivHelperGetFDType         fd_type,
                                GCancellable                 *cancellable,
                                NMPrivHelperCallGetFDCallback callback,
                                gpointer                      user_data);

#endif /* __NM_PRIV_HELPER_CALL_H__ */
