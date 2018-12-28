/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2014 - 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-sd.h"

#include "sd-event.h"

/*****************************************************************************
 * Integrating sd_event into glib. Taken and adjusted from
 * https://www.freedesktop.org/software/systemd/man/sd_event_get_fd.html
 *****************************************************************************/

typedef struct SDEventSource {
	GSource source;
	GPollFD pollfd;
	sd_event *event;
	guint *default_source_id;
} SDEventSource;

static gboolean
event_prepare (GSource *source, int *timeout_)
{
	return sd_event_prepare (((SDEventSource *) source)->event) > 0;
}

static gboolean
event_check (GSource *source)
{
	return sd_event_wait (((SDEventSource *) source)->event, 0) > 0;
}

static gboolean
event_dispatch (GSource *source, GSourceFunc callback, gpointer user_data)
{
	return sd_event_dispatch (((SDEventSource *)source)->event) > 0;
}

static void
event_finalize (GSource *source)
{
	SDEventSource *s;

	s = (SDEventSource *) source;
	sd_event_unref (s->event);
	if (s->default_source_id)
		*s->default_source_id = 0;
}

static SDEventSource *
event_create_source (sd_event *event, guint *default_source_id)
{
	static GSourceFuncs event_funcs = {
		.prepare = event_prepare,
		.check = event_check,
		.dispatch = event_dispatch,
		.finalize = event_finalize,
	};
	SDEventSource *source;

	g_return_val_if_fail (event, NULL);

	source = (SDEventSource *) g_source_new (&event_funcs, sizeof (SDEventSource));

	source->event = sd_event_ref (event);
	source->pollfd.fd = sd_event_get_fd (event);
	source->pollfd.events = G_IO_IN | G_IO_HUP | G_IO_ERR;
	source->default_source_id = default_source_id;

	g_source_add_poll ((GSource *) source, &source->pollfd);

	return source;
}

static guint
event_attach (sd_event *event, GMainContext *context)
{
	SDEventSource *source;
	guint id;
	int r;
	sd_event *e = event;
	guint *p_default_source_id = NULL;

	if (!e) {
		static guint default_source_id = 0;

		if (default_source_id) {
			/* The default event cannot be registered multiple times. */
			g_return_val_if_reached (0);
		}

		r = sd_event_default (&e);
		if (r < 0)
			g_return_val_if_reached (0);

		p_default_source_id = &default_source_id;
	}

	source = event_create_source (e, p_default_source_id);
	id = g_source_attach ((GSource *) source, context);
	g_source_unref ((GSource *) source);

	if (!event) {
		*p_default_source_id = id;
		sd_event_unref (e);
	}

	g_return_val_if_fail (id, 0);
	return id;
}

guint
nm_sd_event_attach_default (void)
{
	return event_attach (NULL, NULL);
}

/*****************************************************************************/

const bool mempool_use_allowed = true;

/*****************************************************************************/

/* ensure that defines in nm-sd.h correspond to the internal defines. */

#include "nm-sd-adapt-core.h"
#include "dhcp-lease-internal.h"

/*****************************************************************************/

