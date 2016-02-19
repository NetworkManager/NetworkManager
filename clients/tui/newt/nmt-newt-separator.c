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

/**
 * SECTION:nmt-newt-separator
 * @short_description: Separator
 *
 * #NmtNewtSeparator is just a blank label, which is used in a few places
 * where a widget is needed but none is desired, or to add blank space
 * between widgets in containers that don't implement padding.
 */

#include "nm-default.h"

#include "nmt-newt-separator.h"

G_DEFINE_TYPE (NmtNewtSeparator, nmt_newt_separator, NMT_TYPE_NEWT_COMPONENT)

/**
 * nmt_newt_separator_new:
 *
 * Creates a new #NmtNewtSeparator.
 *
 * Returns: a new #NmtNewtSeparator
 */
NmtNewtWidget *
nmt_newt_separator_new (void)
{
	return g_object_new (NMT_TYPE_NEWT_SEPARATOR, NULL);
}

static void
nmt_newt_separator_init (NmtNewtSeparator *separator)
{
}

static newtComponent
nmt_newt_separator_build_component (NmtNewtComponent *component,
                                    gboolean          sensitive)
{
	return newtLabel (-1, -1, " ");
}

static void
nmt_newt_separator_class_init (NmtNewtSeparatorClass *separator_class)
{
	NmtNewtComponentClass *component_class = NMT_NEWT_COMPONENT_CLASS (separator_class);

	/* virtual methods */
	component_class->build_component = nmt_newt_separator_build_component;
}
