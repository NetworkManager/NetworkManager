/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_SUDO_CALL_H__
#define __NM_SUDO_CALL_H__

#include "libnm-base/nm-sudo-utils.h"

typedef void (*NMSudoCallGetFDCallback)(int fd_take, GError *error, gpointer user_data);

void nm_sudo_call_get_fd(NMSudoGetFDType         fd_type,
                         GCancellable *          cancellable,
                         NMSudoCallGetFDCallback callback,
                         gpointer                user_data);

#endif /* __NM_SUDO_CALL_H__ */
