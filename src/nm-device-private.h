/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#ifndef NM_DEVICE_PRIVATE_H
#define NM_DEVICE_PRIVATE_H

#include "nm-device.h"


void			nm_device_set_udi		(NMDevice *dev,
								 const char *udi);

void			nm_device_set_device_type (NMDevice *self,
								  const NMDeviceType type);

gboolean		nm_device_is_activated (NMDevice *dev);

GMainContext *	nm_device_get_main_context (NMDevice *dev);

#endif	/* NM_DEVICE_PRIVATE_H */
