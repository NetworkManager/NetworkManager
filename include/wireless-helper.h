/* Hacks necessary to #include wireless.h; yay for WEXT */

#ifndef __user
#define __user
#endif
#include <sys/types.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <wireless.h>

