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
 * SECTION:nmt-page-grid
 * @short_description: Grid widget for #NmtEditorPages
 *
 * #NmtPageGrid is the layout grid used by #NmtEditorPages. It
 * consists of a number of rows, each containing either a single
 * widget that spans the entire width of the row, or else containing a
 * label, a widget, and an optional extra widget.
 *
 * Each row of the grid can take up multiple on-screen rows, if
 * its main widget is multiple rows high. The label and extra widgets
 * will be top-aligned if the row is taller than they are.
 *
 * The #NmtPageGrids in a form behave as though they are all in a
 * "size group" together; they will all use the same column widths,
 * which will be wide enough for the widest labels/widgets in any of
 * the grids. #NmtPageGrid is also specially aware of #NmtNewtSection,
 * and grids inside sections will automatically take the size of the
 * section border into account as well.
 */

#include "config.h"

#include <string.h>

#include "nmt-page-grid.h"

G_DEFINE_TYPE (NmtPageGrid, nmt_page_grid, NMT_TYPE_NEWT_CONTAINER)

#define NMT_PAGE_GRID_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_PAGE_GRID, NmtPageGridPrivate))

typedef struct {
	GArray *rows;
	int *row_heights;
	int indent;
} NmtPageGridPrivate;

typedef struct {
	NmtNewtWidget *label;
	NmtNewtWidget *widget;
	NmtNewtWidget *extra;
	NmtPageGridRowFlags flags;
} NmtPageGridRow;

typedef struct {
	int col_widths[3];
} NmtPageGridFormState;

/**
 * nmt_page_grid_new:
 *
 * Creates a new #NmtPageGrid
 *
 * Returns: a new #NmtPageGrid
 */ 
NmtNewtWidget *
nmt_page_grid_new (void)
{
	return g_object_new (NMT_TYPE_PAGE_GRID,
	                     NULL);
}

static void
nmt_page_grid_init (NmtPageGrid *grid)
{
	NmtPageGridPrivate *priv = NMT_PAGE_GRID_GET_PRIVATE (grid);

	priv->rows = g_array_new (FALSE, TRUE, sizeof (NmtPageGridRow));
}

static void
nmt_page_grid_finalize (GObject *object)
{
	NmtPageGridPrivate *priv = NMT_PAGE_GRID_GET_PRIVATE (object);

	g_array_unref (priv->rows);
	g_clear_pointer (&priv->row_heights, g_free);

	G_OBJECT_CLASS (nmt_page_grid_parent_class)->finalize (object);
}

/**
 * nmt_page_grid_append:
 * @grid: the #NmtPageGrid
 * @label: (allow-none): the label text for @widget, or %NULL
 * @widget: the (main) widget
 * @extra: (allow-none): optional extra widget
 *
 * Adds a row to @grid.
 *
 * If @label is non-%NULL, this will add a three-column row,
 * containing a right-aligned #NmtNewtLabel in the first column,
 * @widget in the second column, and @extra (if non-%NULL) in
 * the third column.
 *
 * If @label is %NULL, then this will add a row with a single
 * grid-spanning column, containing @widget.
 *
 * FIXME: That's sort of weird.
 *
 * See also nmt_page_grid_set_row_flags().
 */
void
nmt_page_grid_append (NmtPageGrid   *grid,
                      const char    *label,
                      NmtNewtWidget *widget,
                      NmtNewtWidget *extra)
{
	NmtPageGridPrivate *priv = NMT_PAGE_GRID_GET_PRIVATE (grid);
	NmtNewtContainerClass *parent_class = NMT_NEWT_CONTAINER_CLASS (nmt_page_grid_parent_class);
	NmtNewtContainer *container = NMT_NEWT_CONTAINER (grid);
	NmtPageGridRow row;

	memset (&row, 0, sizeof (row));

	if (label) {
		row.label = nmt_newt_label_new (label);
		parent_class->add (container, row.label);
	}

	row.widget = widget;
	parent_class->add (container, widget);
	if (row.label) {
		g_object_bind_property (row.widget, "valid",
		                        row.label, "highlight",
		                        G_BINDING_INVERT_BOOLEAN | G_BINDING_SYNC_CREATE);
	}

	if (extra) {
		row.extra = extra;
		parent_class->add (container, extra);
	}

	g_array_append_val (priv->rows, row);
}

static int
nmt_page_grid_find_widget (NmtPageGrid   *grid,
                           NmtNewtWidget *widget)
{
	NmtPageGridPrivate *priv = NMT_PAGE_GRID_GET_PRIVATE (grid);
	NmtPageGridRow *rows = (NmtPageGridRow *) priv->rows->data;
	int i;

	for (i = 0; i < priv->rows->len; i++) {
		if (rows[i].label == widget || rows[i].widget == widget || rows[i].extra == widget)
			return i;
	}

	return -1;
}

/**
 * NmtPageGridRowFlags:
 * @NMT_PAGE_GRID_ROW_LABEL_ALIGN_LEFT: the row's label should be
 *   aligned left instead of right.
 * @NMT_PAGE_GRID_ROW_EXTRA_ALIGN_RIGHT: the row's extra widget
 *   should be aligned right instead of left.
 *
 * Flags to alter an #NmtPageGrid row's layout.
 */

/**
 * nmt_page_grid_set_row_flags:
 * @grid: an #NmtPageGrid
 * @widget: the widget whose row you want to adjust
 * @flags: the flags to set
 *
 * Sets flags to adjust the layout of @widget's row in @grid.
 */
void
nmt_page_grid_set_row_flags (NmtPageGrid         *grid,
                             NmtNewtWidget       *widget,
                             NmtPageGridRowFlags  flags)
{
	NmtPageGridPrivate *priv = NMT_PAGE_GRID_GET_PRIVATE (grid);
	NmtPageGridRow *rows = (NmtPageGridRow *) priv->rows->data;
	int i;

	i = nmt_page_grid_find_widget (grid, widget);
	if (i != -1)
		rows[i].flags = flags;
}

static void
nmt_page_grid_remove (NmtNewtContainer *container,
                      NmtNewtWidget    *widget)
{
	NmtPageGrid *grid = NMT_PAGE_GRID (container);
	NmtPageGridPrivate *priv = NMT_PAGE_GRID_GET_PRIVATE (grid);
	NmtNewtContainerClass *parent_class = NMT_NEWT_CONTAINER_CLASS (nmt_page_grid_parent_class);
	NmtPageGridRow *rows = (NmtPageGridRow *) priv->rows->data;
	int i;

	i = nmt_page_grid_find_widget (grid, widget);
	if (i != -1) {
		if (rows[i].label)
			parent_class->remove (container, rows[i].label);
		parent_class->remove (container, rows[i].widget);
		if (rows[i].extra)
			parent_class->remove (container, rows[i].extra);

		g_array_remove_index (priv->rows, i);
		return;
	}

	// FIXME: shouldn't happen
	parent_class->remove (container, widget);
}

static newtComponent *
nmt_page_grid_get_components (NmtNewtWidget *widget)
{
	NmtPageGridPrivate *priv = NMT_PAGE_GRID_GET_PRIVATE (widget);
	NmtPageGridRow *rows = (NmtPageGridRow *) priv->rows->data;
	newtComponent *child_cos;
	GPtrArray *cos;
	int i, c;

	cos = g_ptr_array_new ();

	for (i = 0; i < priv->rows->len; i++) {
		if (!nmt_newt_widget_get_visible (rows[i].widget))
			continue;

		if (rows[i].label) {
			child_cos = nmt_newt_widget_get_components (rows[i].label);
			g_assert (child_cos[0] && !child_cos[1]);
			g_ptr_array_add (cos, child_cos[0]);
			g_free (child_cos);
		}

		child_cos = nmt_newt_widget_get_components (rows[i].widget);
		for (c = 0; child_cos[c]; c++)
			g_ptr_array_add (cos, child_cos[c]);
		g_free (child_cos);

		if (rows[i].extra) {
			child_cos = nmt_newt_widget_get_components (rows[i].extra);
			for (c = 0; child_cos[c]; c++)
				g_ptr_array_add (cos, child_cos[c]);
			g_free (child_cos);
		}
	}

	g_ptr_array_add (cos, NULL);
	return (newtComponent *) g_ptr_array_free (cos, FALSE);
}

static NmtPageGridFormState *
get_form_state (NmtNewtWidget *widget)
{
	NmtNewtForm *form = nmt_newt_widget_get_form (widget);
	NmtPageGridFormState *state;

	if (!form)
		return NULL;

	state = g_object_get_data (G_OBJECT (form), "NmtPageGridFormState");
	if (state)
		return state;

	state = g_new0 (NmtPageGridFormState, 1);
	g_object_set_data_full (G_OBJECT (form), "NmtPageGridFormState", state, g_free);
	return state;
}

static void
nmt_page_grid_realize (NmtNewtWidget *widget)
{
	NmtPageGridPrivate *priv = NMT_PAGE_GRID_GET_PRIVATE (widget);
	NmtNewtWidget *parent;

	NMT_NEWT_WIDGET_CLASS (nmt_page_grid_parent_class)->realize (widget);

	/* This is a hack, but it's the simplest way to make it work... */
	priv->indent = 0;

	parent = nmt_newt_widget_get_parent (widget);
	while (parent) {
		if (NMT_IS_NEWT_SECTION (parent)) {
			priv->indent = 2;
			break;
		}
		parent = nmt_newt_widget_get_parent (parent);
	}
}

static void
nmt_page_grid_unrealize (NmtNewtWidget *widget)
{
	NmtPageGridFormState *state = get_form_state (widget);

	if (state)
		memset (state->col_widths, 0, sizeof (state->col_widths));

	NMT_NEWT_WIDGET_CLASS (nmt_page_grid_parent_class)->unrealize (widget);
}

static void
nmt_page_grid_size_request (NmtNewtWidget *widget,
                            int           *width,
                            int           *height)
{
	NmtPageGridPrivate *priv = NMT_PAGE_GRID_GET_PRIVATE (widget);
	NmtPageGridRow *rows = (NmtPageGridRow *) priv->rows->data;
	NmtPageGridFormState *state = get_form_state (widget);
	gboolean add_padding = FALSE;
	int i;

	g_free (priv->row_heights);
	priv->row_heights = g_new0 (int, priv->rows->len);

	*height = 0;
	for (i = 0; i < priv->rows->len; i++) {
		int lwidth, lheight, wwidth, wheight, ewidth, eheight;

		if (!nmt_newt_widget_get_visible (rows[i].widget))
			continue;

		if (rows[i].label) {
			nmt_newt_widget_size_request (rows[i].label, &lwidth, &lheight);
			lwidth += priv->indent;
			state->col_widths[0] = MAX (state->col_widths[0], lwidth);

			nmt_newt_widget_size_request (rows[i].widget, &wwidth, &wheight);
			state->col_widths[1] = MAX (state->col_widths[1], wwidth);
			priv->row_heights[i] = wheight;

			add_padding = TRUE;
		} else {
			nmt_newt_widget_size_request (rows[i].widget, &wwidth, &wheight);
			priv->row_heights[i] = wheight;
		}

		if (rows[i].extra) {
			nmt_newt_widget_size_request (rows[i].extra, &ewidth, &eheight);
			state->col_widths[2] = MAX (state->col_widths[2], ewidth);
			priv->row_heights[i] = MAX (priv->row_heights[i], eheight);
		}

		*height += priv->row_heights[i];
	}

	*width = state->col_widths[0] + state->col_widths[1] + state->col_widths[2];
	if (add_padding)
		*width += 2;
}


static void
nmt_page_grid_size_allocate (NmtNewtWidget *widget,
                             int            x,
                             int            y,
                             int            width,
                             int            height)
{
	NmtPageGridPrivate *priv = NMT_PAGE_GRID_GET_PRIVATE (widget);
	NmtPageGridRow *rows = (NmtPageGridRow *) priv->rows->data;
	NmtPageGridFormState *state = get_form_state (widget);
	int col0_width, col1_width, col2_width;
	int i, row;

	col0_width = state->col_widths[0] - priv->indent;
	col1_width = state->col_widths[1];
	col2_width = state->col_widths[2];

	for (i = row = 0; i < priv->rows->len; i++) {
		if (!nmt_newt_widget_get_visible (rows[i].widget))
			continue;

		if (rows[i].label) {
			int lwidth, lheight, lx;

			if (rows[i].flags & NMT_PAGE_GRID_ROW_LABEL_ALIGN_LEFT)
				lx = x;
			else {
				nmt_newt_widget_size_request (rows[i].label, &lwidth, &lheight);
				lx = x + col0_width - lwidth;
			}

			nmt_newt_widget_size_allocate (rows[i].label,
			                               lx,
			                               y + row,
			                               col0_width,
			                               priv->row_heights[i]);

			nmt_newt_widget_size_allocate (rows[i].widget,
			                               x + col0_width + 1,
			                               y + row,
			                               col1_width,
			                               priv->row_heights[i]);
			if (rows[i].extra) {
				int wwidth, wheight, ex;

				if (rows[i].flags & NMT_PAGE_GRID_ROW_EXTRA_ALIGN_RIGHT)
					ex = x + col0_width + col1_width + 2;
				else {
					nmt_newt_widget_size_request (rows[i].widget, &wwidth, &wheight);
					ex = x + col0_width + wwidth + 2;
				}

				nmt_newt_widget_size_allocate (rows[i].extra,
				                               ex,
				                               y + row,
				                               col2_width,
				                               priv->row_heights[i]);
			}
		} else {
			nmt_newt_widget_size_allocate (rows[i].widget,
			                               x,
			                               y + row,
			                               col0_width + col1_width + col2_width + 2,
			                               priv->row_heights[i]);
		}

		row += priv->row_heights[i];
	}
}

static void
nmt_page_grid_class_init (NmtPageGridClass *grid_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (grid_class);
	NmtNewtWidgetClass *widget_class = NMT_NEWT_WIDGET_CLASS (grid_class);
	NmtNewtContainerClass *container_class = NMT_NEWT_CONTAINER_CLASS (grid_class);

	g_type_class_add_private (grid_class, sizeof (NmtPageGridPrivate));

	/* virtual methods */
	object_class->finalize = nmt_page_grid_finalize;

	widget_class->realize        = nmt_page_grid_realize;
	widget_class->unrealize      = nmt_page_grid_unrealize;
	widget_class->get_components = nmt_page_grid_get_components;
	widget_class->size_request   = nmt_page_grid_size_request;
	widget_class->size_allocate  = nmt_page_grid_size_allocate;

	container_class->remove = nmt_page_grid_remove;
}
