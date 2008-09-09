/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-vpnc.h : GNOME UI dialogs for configuring vpnc VPN connections
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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
 **************************************************************************/

#ifndef _NM_VPNC_H_
#define _NM_VPNC_H_

#include <glib-object.h>

typedef enum
{
	VPNC_PLUGIN_UI_ERROR_UNKNOWN = 0,
	VPNC_PLUGIN_UI_ERROR_INVALID_PROPERTY,
	VPNC_PLUGIN_UI_ERROR_MISSING_PROPERTY,
	VPNC_PLUGIN_UI_ERROR_INVALID_CONNECTION
} VpncPluginUiError;

#define VPNC_TYPE_PLUGIN_UI_ERROR (vpnc_plugin_ui_error_get_type ()) 
GType vpnc_plugin_ui_error_get_type (void);

#define VPNC_TYPE_PLUGIN_UI            (vpnc_plugin_ui_get_type ())
#define VPNC_PLUGIN_UI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), VPNC_TYPE_PLUGIN_UI, VpncPluginUi))
#define VPNC_PLUGIN_UI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), VPNC_TYPE_PLUGIN_UI, VpncPluginUiClass))
#define VPNC_IS_PLUGIN_UI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), VPNC_TYPE_PLUGIN_UI))
#define VPNC_IS_PLUGIN_UI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), VPNC_TYPE_PLUGIN_UI))
#define VPNC_PLUGIN_UI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), VPNC_TYPE_PLUGIN_UI, VpncPluginUiClass))

typedef struct _VpncPluginUi VpncPluginUi;
typedef struct _VpncPluginUiClass VpncPluginUiClass;

struct _VpncPluginUi {
	GObject parent;
};

struct _VpncPluginUiClass {
	GObjectClass parent;
};

GType vpnc_plugin_ui_get_type (void);


#define VPNC_TYPE_PLUGIN_UI_WIDGET            (vpnc_plugin_ui_widget_get_type ())
#define VPNC_PLUGIN_UI_WIDGET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), VPNC_TYPE_PLUGIN_UI_WIDGET, VpncPluginUiWidget))
#define VPNC_PLUGIN_UI_WIDGET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), VPNC_TYPE_PLUGIN_UI_WIDGET, VpncPluginUiWidgetClass))
#define VPNC_IS_PLUGIN_UI_WIDGET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), VPNC_TYPE_PLUGIN_UI_WIDGET))
#define VPNC_IS_PLUGIN_UI_WIDGET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), VPNC_TYPE_PLUGIN_UI_WIDGET))
#define VPNC_PLUGIN_UI_WIDGET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), VPNC_TYPE_PLUGIN_UI_WIDGET, VpncPluginUiWidgetClass))

typedef struct _VpncPluginUiWidget VpncPluginUiWidget;
typedef struct _VpncPluginUiWidgetClass VpncPluginUiWidgetClass;

struct _VpncPluginUiWidget {
	GObject parent;
};

struct _VpncPluginUiWidgetClass {
	GObjectClass parent;
};

GType vpnc_plugin_ui_widget_get_type (void);

#endif	/* _NM_VPNC_H_ */

