/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-sudo-utils.h"

#include <sys/socket.h>
#include <sys/un.h>

/*****************************************************************************/

int
nm_sudo_utils_open_fd(NMSudoGetFDType fd_type, GError **error)
{
    nm_auto_close int fd = -1;
    int               r;
    int               errsv;

    switch (fd_type) {
    case NM_SUDO_GET_FD_TYPE_OVSDB_SOCKET:
    {
        struct sockaddr_un sock;

        memset(&sock, 0, sizeof(sock));
        sock.sun_family = AF_UNIX;
        G_STATIC_ASSERT_EXPR(NM_STRLEN(NM_OVSDB_SOCKET) + 1 < sizeof(sock.sun_path));
        if (g_strlcpy(sock.sun_path, NM_OVSDB_SOCKET, sizeof(sock.sun_path))
            >= sizeof(sock.sun_path))
            nm_assert_not_reached();

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            errsv = NM_ERRNO_NATIVE(errno);
            g_set_error(error, G_IO_ERROR, g_io_error_from_errno(errsv), "error creating socket");
            return -errsv;
        }

        r = connect(fd,
                    (const struct sockaddr *) &sock,
                    G_STRUCT_OFFSET(struct sockaddr_un, sun_path) + NM_STRLEN(NM_OVSDB_SOCKET) + 1);
        if (r != 0) {
            errsv = NM_ERRNO_NATIVE(errno);
            g_set_error(error,
                        G_IO_ERROR,
                        g_io_error_from_errno(errsv),
                        "error connecting socket (%s)",
                        nm_strerror_native(errsv));
            return -errsv;
        }

        return nm_steal_fd(&fd);
    }
    case NM_SUDO_GET_FD_TYPE_NONE:
    default:
        nm_utils_error_set(error, NM_UTILS_ERROR_UNKNOWN, "invalid fd_type");
        return -EINVAL;
    }
}
