#ifndef _SRC_AUTOIP_H
#define _SRC_AUTOIP_H

#include "nm-device.h"

extern gboolean get_autoip (NMDevice *dev, struct in_addr *out_ip);

#endif	/* _SRC_AUTOIP_H */
