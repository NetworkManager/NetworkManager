/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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

#ifndef NMT_NEWT_TYPES_H
#define NMT_NEWT_TYPES_H

#include <glib-object.h>
#include <newt.h>
#include "nm-glib-compat.h"

G_BEGIN_DECLS

typedef struct _NmtNewtButton        NmtNewtButton;
typedef struct _NmtNewtButtonBox     NmtNewtButtonBox;
typedef struct _NmtNewtCheckbox      NmtNewtCheckbox;
typedef struct _NmtNewtComponent     NmtNewtComponent;
typedef struct _NmtNewtContainer     NmtNewtContainer;
typedef struct _NmtNewtEntry         NmtNewtEntry;
typedef struct _NmtNewtEntryNumeric  NmtNewtEntryNumeric;
typedef struct _NmtNewtForm          NmtNewtForm;
typedef struct _NmtNewtGrid          NmtNewtGrid;
typedef struct _NmtNewtLabel         NmtNewtLabel;
typedef struct _NmtNewtListbox       NmtNewtListbox;
typedef struct _NmtNewtPopup         NmtNewtPopup;
typedef struct _NmtNewtSection       NmtNewtSection;
typedef struct _NmtNewtSectionBorder NmtNewtSectionBorder;
typedef struct _NmtNewtSeparator     NmtNewtSeparator;
typedef struct _NmtNewtStack         NmtNewtStack;
typedef struct _NmtNewtTextbox       NmtNewtTextbox;
typedef struct _NmtNewtToggleButton  NmtNewtToggleButton;
typedef struct _NmtNewtWidget        NmtNewtWidget;

G_END_DECLS

#endif /* NMT_NEWT_COMPONENT_H */
