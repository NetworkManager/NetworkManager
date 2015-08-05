/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef _PLUGIN_H_
#define _PLUGIN_H_

#include "nm-default.h"

#define SC_TYPE_PLUGIN_IBFT            (sc_plugin_ibft_get_type ())
#define SC_PLUGIN_IBFT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SC_TYPE_PLUGIN_IBFT, SCPluginIbft))
#define SC_PLUGIN_IBFT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SC_TYPE_PLUGIN_IBFT, SCPluginIbftClass))
#define SC_IS_PLUGIN_IBFT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SC_TYPE_PLUGIN_IBFT))
#define SC_IS_PLUGIN_IBFT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SC_TYPE_PLUGIN_IBFT))
#define SC_PLUGIN_IBFT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SC_TYPE_PLUGIN_IBFT, SCPluginIbftClass))

typedef struct _SCPluginIbft SCPluginIbft;
typedef struct _SCPluginIbftClass SCPluginIbftClass;

struct _SCPluginIbft {
	GObject parent;
};

struct _SCPluginIbftClass {
	GObjectClass parent;
};

GType sc_plugin_ibft_get_type (void);

#endif	/* _PLUGIN_H_ */

