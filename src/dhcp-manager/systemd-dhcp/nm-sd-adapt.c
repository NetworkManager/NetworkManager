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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "config.h"

#include <glib.h>
#include <unistd.h>
#include <errno.h>

#include "sd-event.h"
#include "time-util.h"

struct sd_event_source {
	guint refcount;
	guint id;
	gpointer user_data;

	GIOChannel *channel;
	sd_event_io_handler_t io_cb;

	uint64_t usec;
	sd_event_time_handler_t time_cb;
};

int
sd_event_source_set_priority (sd_event_source *s, int64_t priority)
{
	return 0;
}

sd_event_source*
sd_event_source_unref (sd_event_source *s)
{

	if (!s)
		return NULL;

	g_return_val_if_fail (s->refcount, NULL);

	s->refcount--;
	if (s->refcount == 0) {
		if (s->id)
			g_source_remove (s->id);
		if (s->channel) {
			/* Don't shut down the channel since systemd will soon close
			 * the file descriptor itself, which would cause -EBADF.
			 */
			g_io_channel_unref (s->channel);
		}
		g_free (s);
	}
	return NULL;
}

int
sd_event_source_set_description(sd_event_source *s, const char *description)
{
	if (!s)
		return -EINVAL;

	g_source_set_name_by_id (s->id, description);
	return 0;
}

static gboolean
io_ready (GIOChannel *channel, GIOCondition condition, struct sd_event_source *source)
{
	int r, revents = 0;

	if (condition & G_IO_IN)
		revents |= EPOLLIN;
	if (condition & G_IO_OUT)
		revents |= EPOLLOUT;
	if (condition & G_IO_PRI)
		revents |= EPOLLPRI;
	if (condition & G_IO_ERR)
		revents |= EPOLLERR;
	if (condition & G_IO_HUP)
		revents |= EPOLLHUP;

	r = source->io_cb (source, g_io_channel_unix_get_fd (channel), revents, source->user_data);
	if (r < 0) {
		source->id = 0;
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

int
sd_event_add_io (sd_event *e, sd_event_source **s, int fd, uint32_t events, sd_event_io_handler_t callback, void *userdata)
{
	struct sd_event_source *source;
	GIOChannel *channel;
	GIOCondition condition = 0;

	channel = g_io_channel_unix_new (fd);
	if (!channel)
		return -EINVAL;

	source = g_new0 (struct sd_event_source, 1);
	source->refcount = 1;
	source->io_cb = callback;
	source->user_data = userdata;
	source->channel = channel;

	if (events & EPOLLIN)
		condition |= G_IO_IN;
	if (events & EPOLLOUT)
		condition |= G_IO_OUT;
	if (events & EPOLLPRI)
		condition |= G_IO_PRI;
	if (events & EPOLLERR)
		condition |= G_IO_ERR;
	if (events & EPOLLHUP)
		condition |= G_IO_HUP;

	g_io_channel_set_encoding (source->channel, NULL, NULL);
	g_io_channel_set_buffered (source->channel, FALSE);
	source->id = g_io_add_watch (source->channel, condition, (GIOFunc) io_ready, source);

	*s = source;
	return 0;
}

static gboolean
time_ready (struct sd_event_source *source)
{
	int r;

	r = source->time_cb (source, source->usec, source->user_data);
	if (r < 0) {
		source->id = 0;
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

int
sd_event_add_time(sd_event *e, sd_event_source **s, clockid_t clock, uint64_t usec, uint64_t accuracy, sd_event_time_handler_t callback, void *userdata)
{
	struct sd_event_source *source;
	uint64_t n = now (clock);

	source = g_new0 (struct sd_event_source, 1);
	source->refcount = 1;
	source->time_cb = callback;
	source->user_data = userdata;
	source->usec = usec;

	if (usec > 1000)
		usec = n < usec - 1000 ? usec - n : 1000;
	source->id = g_timeout_add (usec / 1000, (GSourceFunc) time_ready, source);

	*s = source;
	return 0;
}

/* sd_event is basically a GMainContext; but since we only
 * ever use the default context, nothing to do here.
 */

int
sd_event_default (sd_event **e)
{
	*e = GUINT_TO_POINTER (1);
	return 0;
}

sd_event*
sd_event_ref (sd_event *e)
{
	return e;
}

sd_event*
sd_event_unref (sd_event *e)
{
	return NULL;
}

int
sd_event_now (sd_event *e, clockid_t clock, uint64_t *usec)
{
	*usec = now (clock);
	return 0;
}

int asynchronous_close(int fd) {
	safe_close(fd);
	return -1;
}

