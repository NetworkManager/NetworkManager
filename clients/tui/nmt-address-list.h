/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_ADDRESS_LIST_H
#define NMT_ADDRESS_LIST_H

#include "nmt-widget-list.h"

#define NMT_TYPE_ADDRESS_LIST            (nmt_address_list_get_type ())
#define NMT_ADDRESS_LIST(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_ADDRESS_LIST, NmtAddressList))
#define NMT_ADDRESS_LIST_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_ADDRESS_LIST, NmtAddressListClass))
#define NMT_IS_ADDRESS_LIST(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_ADDRESS_LIST))
#define NMT_IS_ADDRESS_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_ADDRESS_LIST))
#define NMT_ADDRESS_LIST_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_ADDRESS_LIST, NmtAddressListClass))

typedef struct {
	NmtWidgetList parent;

} NmtAddressList;

typedef struct {
	NmtWidgetListClass parent;

} NmtAddressListClass;

GType nmt_address_list_get_type (void);

typedef enum {
	NMT_ADDRESS_LIST_IP4_WITH_PREFIX,
	NMT_ADDRESS_LIST_IP4,
	NMT_ADDRESS_LIST_IP6_WITH_PREFIX,
	NMT_ADDRESS_LIST_IP6,
	NMT_ADDRESS_LIST_HOSTNAME
} NmtAddressListType;

NmtNewtWidget *nmt_address_list_new (NmtAddressListType list_type);

#endif /* NMT_ADDRESS_LIST_H */
