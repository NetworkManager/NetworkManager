#pragma once

/*
 * Socket Utilities
 */

#include <c-stdaux.h>
#include <stdlib.h>

int socket_SIOCGIFNAME(int socket, int ifindex, char (*ifnamep)[IFNAMSIZ]);
int socket_bind_if(int socket, int ifindex);
