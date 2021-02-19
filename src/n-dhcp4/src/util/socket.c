/*
 * Socket Utilities
 */

#include <assert.h>
#include <c-stdaux.h>
#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "socket.h"

/**
 * socket_SIOCGIFNAME() - resolve an ifindex to an ifname
 * @socket:                     socket to operate on
 * @ifindex:                    index of network interface to resolve
 * @ifname:                     buffer to store resolved name
 *
 * This uses the SIOCGIFNAME ioctl to resolve an ifindex to an ifname. The
 * buffer provided in @ifnamep must be at least IFNAMSIZ bytes in size. The
 * maximum ifname length is IFNAMSIZ-1, and this function always
 * zero-terminates the result.
 *
 * This function is similar to if_indextoname(3) provided by glibc, but it
 * allows to specify the target socket explicitly. This allows the caller to
 * control the target network-namespace, rather than relying on the network
 * namespace of the running process.
 *
 * Return: 0 on success, negative kernel error code on failure.
 */
int socket_SIOCGIFNAME(int socket, int ifindex, char (*ifnamep)[IFNAMSIZ]) {
        struct ifreq req = { .ifr_ifindex = ifindex };
        int r;

        r = ioctl(socket, SIOCGIFNAME, &req);
        if (r < 0)
                return -errno;

        /*
         * The linux kernel guarantees that an interface name is always
         * zero-terminated, and it always fully fits into IFNAMSIZ bytes,
         * including the zero-terminator.
         */
        memcpy(ifnamep, req.ifr_name, IFNAMSIZ);
        return 0;
}

/**
 * socket_bind_if() - bind socket to a network interface
 * @socket:                     socket to operate on
 * @ifindex:                    index of network interface to bind to, or 0
 *
 * This binds the socket given via @socket to the network interface specified
 * via @ifindex. It uses the underlying SO_BINDTODEVICE ioctl of the linux
 * kernel. However, if available, if prefers the newer SO_BINDTOIFINDEX ioctl,
 * which avoids resolving the interface name temporarily, and thus does not
 * suffer from a race-condition.
 *
 * Return: 0 on success, negative error code on failure.
 */
int socket_bind_if(int socket, int ifindex) {
        char ifname[IFNAMSIZ] = {};
        int r;

        c_assert(ifindex >= 0);

        /*
         * We first try the newer SO_BINDTOIFINDEX. If it is not available on
         * the running kernel, we fall back to SO_BINDTODEVICE. This, however,
         * requires us to first resolve the ifindex to an ifname. Note that
         * this is racy, since the device name might theoretically change
         * asynchronously.
         *
         * Using 0 as ifindex will remove the device-binding. For
         * SO_BINDTOIFINDEX we simply pass-through the 0 to the kernel, which
         * recognizes this correctly. For SO_BINDTODEVICE we pass the empty
         * string, which the kernel recognizes as a request to remove the
         * binding.
         *
         * The commit introducing SO_BINDTOIFINDEX first appeared in linux-5.1:
         *
         *     commit f5dd3d0c9638a9d9a02b5964c4ad636f06cf7e2c
         *     Author: David Herrmann <dh.herrmann@gmail.com>
         *     Date:   Tue Jan 15 14:42:14 2019 +0100
         *
         *         net: introduce SO_BINDTOIFINDEX sockopt
         *
         * In older kernels, setsockopt(2) is guaranteed to return ENOPROTOOPT
         * for this ioctl.
         */

#ifdef SO_BINDTOIFINDEX
        r = setsockopt(socket,
                       SOL_SOCKET,
                       SO_BINDTOIFINDEX,
                       &ifindex,
                       sizeof(ifindex));
        if (r >= 0)
                return 0;
        else if (errno != ENOPROTOOPT)
                return -errno;
#endif /* SO_BINDTOIFINDEX */

        if (ifindex > 0) {
                r = socket_SIOCGIFNAME(socket, ifindex, &ifname);
                if (r)
                        return r;
        }

        r = setsockopt(socket,
                       SOL_SOCKET,
                       SO_BINDTODEVICE,
                       ifname,
                       strlen(ifname));
        if (r < 0)
                return -errno;

        return 0;
}
