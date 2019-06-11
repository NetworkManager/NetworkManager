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
 * SECTION:nmt-newt-grid
 * @short_description: Grid container
 *
 * #NmtNewtGrid is the most general-purpose container widget in NmtNewt.
 *
 * An #NmtNewtGrid consists of a number of rows and columns. There is
 * no pre-established maximum row or columns. Rather, rows and columns
 * exist if and only if there are widgets in them.
 *
 * The width of each column is the width of the widest widget in that
 * column, and the height of each row is the height of the tallest
 * widget in that row. Empty rows and empty columns take up no space,
 * so a grid with a single widget at 0,0 would look exactly the same
 * if the widget was at 5,10 instead.
 *
 * If a widget's cell ends up being larger than the widget's requested
 * size, then by default the widget will be centered in its cell.
 * However, this can be modified by changing its #NmtNewtGridFlags.
 * FIXME: the FILL/ANCHOR flags can be implemented in #NmtNewtWidget
 * and so should move there. Less clear about the EXPAND flags, which
 * must be implemented by the container...
 */

#include "nm-default.h"

#include "nmt-newt-grid.h"

G_DEFINE_TYPE (NmtNewtGrid, nmt_newt_grid, NMT_TYPE_NEWT_CONTAINER)

#define NMT_NEWT_GRID_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_NEWT_GRID, NmtNewtGridPrivate))

typedef struct {
	NmtNewtWidget *widget;
	int x, y;
	NmtNewtGridFlags flags;
	int req_height, req_width;
} NmtNewtGridChild;

typedef struct {
	GArray *children;
	int max_x, max_y;
	int *row_heights, *col_widths;
	gboolean *expand_rows, *expand_cols;
	int n_expand_rows, n_expand_cols;
	int req_height, req_width;
} NmtNewtGridPrivate;

/**
 * nmt_newt_grid_new:
 *
 * Creates a new #NmtNewtGrid
 *
 * Returns: a new #NmtNewtGrid
 */
NmtNewtWidget *
nmt_newt_grid_new (void)
{
	return g_object_new (NMT_TYPE_NEWT_GRID, NULL);
}

static void
nmt_newt_grid_init (NmtNewtGrid *grid)
{
	NmtNewtGridPrivate *priv = NMT_NEWT_GRID_GET_PRIVATE (grid);

	priv->children = g_array_new (FALSE, FALSE, sizeof (NmtNewtGridChild));
}

static void
nmt_newt_grid_finalize (GObject *object)
{
	NmtNewtGridPrivate *priv = NMT_NEWT_GRID_GET_PRIVATE (object);

	g_array_unref (priv->children);
	g_clear_pointer (&priv->row_heights, g_free);
	g_clear_pointer (&priv->col_widths, g_free);
	g_clear_pointer (&priv->expand_rows, g_free);
	g_clear_pointer (&priv->expand_cols, g_free);

	G_OBJECT_CLASS (nmt_newt_grid_parent_class)->finalize (object);
}

static int
child_sort_func (gconstpointer a,
                 gconstpointer b)
{
	NmtNewtGridChild *child_a = (NmtNewtGridChild *)a;
	NmtNewtGridChild *child_b = (NmtNewtGridChild *)b;

	if (child_a->y != child_b->y)
		return child_a->y - child_b->y;
	else
		return child_a->x - child_b->x;
}

static newtComponent *
nmt_newt_grid_get_components (NmtNewtWidget *widget)
{
	NmtNewtGridPrivate *priv = NMT_NEWT_GRID_GET_PRIVATE (widget);
	NmtNewtGridChild *children;
	GPtrArray *cos;
	newtComponent *child_cos;
	int i, c;

	g_array_sort (priv->children, child_sort_func);
	children = (NmtNewtGridChild *)priv->children->data;

	cos = g_ptr_array_new ();

	for (i = 0; i < priv->children->len; i++) {
		if (!nmt_newt_widget_get_visible (children[i].widget))
			continue;

		child_cos = nmt_newt_widget_get_components (children[i].widget);
		for (c = 0; child_cos[c]; c++)
			g_ptr_array_add (cos, child_cos[c]);
		g_free (child_cos);
	}
	g_ptr_array_add (cos, NULL);

	return (newtComponent *) g_ptr_array_free (cos, FALSE);
}

static void
nmt_newt_grid_size_request (NmtNewtWidget *widget,
                            int           *width,
                            int           *height)
{
	NmtNewtGrid *grid = NMT_NEWT_GRID (widget);
	NmtNewtGridPrivate *priv = NMT_NEWT_GRID_GET_PRIVATE (grid);
	NmtNewtGridChild *children = (NmtNewtGridChild *)priv->children->data;
	int row, col, i;

	g_free (priv->row_heights);
	g_free (priv->col_widths);
	g_free (priv->expand_rows);
	g_free (priv->expand_cols);

	priv->row_heights = g_new0 (int, priv->max_y + 1);
	priv->col_widths = g_new0 (int, priv->max_x + 1);
	priv->expand_rows = g_new0 (gboolean, priv->max_y + 1);
	priv->expand_cols = g_new0 (gboolean, priv->max_x + 1);
	priv->n_expand_rows = priv->n_expand_cols = 0;

	for (row = 0; row < priv->max_y + 1; row++) {
		for (col = 0; col < priv->max_x + 1; col++) {
			for (i = 0; i < priv->children->len; i++) {
				if (children[i].x != col || children[i].y != row)
					continue;
				if (!nmt_newt_widget_get_visible (children[i].widget))
					continue;

				nmt_newt_widget_size_request (children[i].widget,
				                              &children[i].req_width,
				                              &children[i].req_height);
				if (children[i].req_height > priv->row_heights[row])
					priv->row_heights[row] = children[i].req_height;
				if (children[i].req_width > priv->col_widths[col])
					priv->col_widths[col] = children[i].req_width;

				if (   (children[i].flags & NMT_NEWT_GRID_EXPAND_X)
				    && !priv->expand_cols[children[i].x]) {
					priv->expand_cols[children[i].x] = TRUE;
					priv->n_expand_cols++;
				}
				if (   (children[i].flags & NMT_NEWT_GRID_EXPAND_Y)
				    && !priv->expand_rows[children[i].y]) {
					priv->expand_rows[children[i].y] = TRUE;
					priv->n_expand_rows++;
				}
			}
		}
	}

	priv->req_height = priv->req_width = 0;
	for (row = 0; row < priv->max_y + 1; row++)
		priv->req_height += priv->row_heights[row];
	for (col = 0; col < priv->max_x + 1; col++)
		priv->req_width += priv->col_widths[col];

	*height = priv->req_height;
	*width = priv->req_width;
}

static void
nmt_newt_grid_size_allocate (NmtNewtWidget *widget,
                             int            x,
                             int            y,
                             int            width,
                             int            height)
{
	NmtNewtGridPrivate *priv = NMT_NEWT_GRID_GET_PRIVATE (widget);
	NmtNewtGridChild *children = (NmtNewtGridChild *)priv->children->data, *child;
	int i, row, col;
	int child_x, child_y, child_width, child_height;
	int extra, extra_all, extra_some;

	extra = width - priv->req_width;
	if (extra > 0 && priv->n_expand_cols) {
		extra_all = extra / priv->n_expand_cols;
		extra_some = extra % priv->n_expand_cols;

		for (col = 0; col < priv->max_x + 1; col++) {
			if (!priv->expand_cols[col])
				continue;
			priv->col_widths[col] += extra_all;
			if (extra_some) {
				priv->col_widths[col]++;
				extra_some--;
			}
		}
	}

	extra = height - priv->req_height;
	if (extra > 0 && priv->n_expand_rows) {
		extra_all = extra / priv->n_expand_rows;
		extra_some = extra % priv->n_expand_rows;

		for (row = 0; row < priv->max_y + 1; row++) {
			if (!priv->expand_rows[row])
				continue;
			priv->row_heights[row] += extra_all;
			if (extra_some) {
				priv->row_heights[row]++;
				extra_some--;
			}
		}
	}

	for (i = 0; i < priv->children->len; i++) {
		child = &children[i];
		if (!nmt_newt_widget_get_visible (child->widget))
			continue;

		child_x = x;
		for (col = 0; col < child->x; col++)
			child_x += priv->col_widths[col];

		if ((child->flags & NMT_NEWT_GRID_FILL_X) == NMT_NEWT_GRID_FILL_X) {
			child_width = priv->col_widths[child->x];
		} else {
			child_width = child->req_width;
			if (child->flags & NMT_NEWT_GRID_ANCHOR_RIGHT)
				child_x += priv->col_widths[child->x] - child->req_width;
			else if (!(child->flags & NMT_NEWT_GRID_ANCHOR_LEFT))
				child_x += (priv->col_widths[child->x] - child->req_width) / 2;
		}

		child_y = y;
		for (row = 0; row < child->y; row++)
			child_y += priv->row_heights[row];

		if ((child->flags & NMT_NEWT_GRID_FILL_Y) == NMT_NEWT_GRID_FILL_Y) {
			child_height = priv->row_heights[child->y];
		} else {
			child_height = child->req_height;
			if (child->flags & NMT_NEWT_GRID_ANCHOR_BOTTOM)
				child_y += priv->row_heights[child->y] - child->req_height;
			else if (!(child->flags & NMT_NEWT_GRID_ANCHOR_TOP))
				child_y += (priv->row_heights[child->y] - child->req_height) / 2;
		}

		nmt_newt_widget_size_allocate (child->widget,
		                               child_x, child_y,
		                               child_width, child_height);
	}
}

static void
nmt_newt_grid_find_size (NmtNewtGrid *grid)
{
	NmtNewtGridPrivate *priv = NMT_NEWT_GRID_GET_PRIVATE (grid);
	NmtNewtGridChild *children = (NmtNewtGridChild *)priv->children->data;
	int i;

	priv->max_x = priv->max_y = 0;
	for (i = 0; i < priv->children->len; i++) {
		if (children[i].x > priv->max_x)
			priv->max_x = children[i].x;
		if (children[i].y > priv->max_y)
			priv->max_y = children[i].y;
	}
}

/**
 * nmt_newt_grid_add:
 * @grid: an #NmtNewtGrid
 * @widget: the widget to add
 * @x: x coordinate
 * @y: y coordinate
 *
 * Adds @widget to @grid at @x, @y. See the discussion above for more
 * details of exactly how this works.
 */
void
nmt_newt_grid_add (NmtNewtGrid   *grid,
                   NmtNewtWidget *widget,
                   int            x,
                   int            y)
{
	NmtNewtGridPrivate *priv = NMT_NEWT_GRID_GET_PRIVATE (grid);
	NmtNewtGridChild child;

	NMT_NEWT_CONTAINER_CLASS (nmt_newt_grid_parent_class)->add (NMT_NEWT_CONTAINER (grid), widget);

	memset (&child, 0, sizeof (child));
	child.widget = widget;
	child.x = x;
	child.y = y;
	child.flags = NMT_NEWT_GRID_FILL_X | NMT_NEWT_GRID_FILL_Y;
	g_array_append_val (priv->children, child);

	if (x > priv->max_x)
		priv->max_x = x;
	if (y > priv->max_y)
		priv->max_y = y;
}

static int
find_child (NmtNewtGrid   *grid,
            NmtNewtWidget *widget)
{
	NmtNewtGridPrivate *priv = NMT_NEWT_GRID_GET_PRIVATE (grid);
	NmtNewtGridChild *children = (NmtNewtGridChild *)priv->children->data;
	int i;

	for (i = 0; i < priv->children->len; i++) {
		if (children[i].widget == widget)
			return i;
	}

	return -1;
}

static void
nmt_newt_grid_remove (NmtNewtContainer *container,
                      NmtNewtWidget    *widget)
{
	NmtNewtGrid *grid = NMT_NEWT_GRID (container);
	NmtNewtGridPrivate *priv = NMT_NEWT_GRID_GET_PRIVATE (grid);
	int i;

	i = find_child (grid, widget);
	if (i != -1) {
		g_array_remove_index (priv->children, i);
		nmt_newt_grid_find_size (grid);
	}

	NMT_NEWT_CONTAINER_CLASS (nmt_newt_grid_parent_class)->remove (container, widget);
}

/**
 * nmt_newt_grid_move:
 * @grid: an #NmtNewtGrid
 * @widget: a child of @grid
 * @x: x coordinate
 * @y: y coordinate
 *
 * Moves @widget to the given new coordinates.
 */
void
nmt_newt_grid_move (NmtNewtGrid   *grid,
                    NmtNewtWidget *widget,
                    int            x,
                    int            y)
{
	NmtNewtGridPrivate *priv = NMT_NEWT_GRID_GET_PRIVATE (grid);
	NmtNewtGridChild *children = (NmtNewtGridChild *)priv->children->data;
	int i;

	i = find_child (grid, widget);
	if (i != -1 && (children[i].x != x || children[i].y != y)) {
		children[i].x = x;
		children[i].y = y;
		nmt_newt_grid_find_size (grid);
		nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (grid));
	}
}

/**
 * NmtNewtGridFlags:
 * @NMT_NEWT_GRID_EXPAND_X: The widget's cell should expand
 *   horizontally if the grid as a whole is given more width than
 *   it requested.
 * @NMT_NEWT_GRID_EXPAND_Y: The widget's cell should expand
 *   vertically if the grid as a whole is given more height than
 *   it requested.
 * @NMT_NEWT_GRID_ANCHOR_LEFT: If the widget's cell is wider than
 *   the widget requested, the widget should be anchored to the
 *   left of its cell rather than being centered.
 * @NMT_NEWT_GRID_ANCHOR_RIGHT: If the widget's cell is wider than
 *   the widget requested, the widget should be anchored to the
 *   right of its cell rather than being centered.
 * @NMT_NEWT_GRID_FILL_X: If the widget's cell is wider than
 *   the widget requested, the widget should be allocated the
 *   full width of the cell; this is equivalent to specifying
 *   both %NMT_NEWT_GRID_ANCHOR_LEFT and %NMT_NEWT_GRID_ANCHOR_RIGHT.
 * @NMT_NEWT_GRID_ANCHOR_TOP: If the widget's cell is taller than
 *   the widget requested, the widget should be anchored to the
 *   top of its cell rather than being centered.
 * @NMT_NEWT_GRID_ANCHOR_BOTTOM: If the widget's cell is taller than
 *   the widget requested, the widget should be anchored to the
 *   bottom of its cell rather than being centered.
 * @NMT_NEWT_GRID_FILL_Y: If the widget's cell is taller than
 *   the widget requested, the widget should be allocated the
 *   full height of the cell; this is equivalent to specifying
 *   both %NMT_NEWT_GRID_ANCHOR_TOP and %NMT_NEWT_GRID_ANCHOR_BOTTOM.
 *
 * Flags describing how a widget is placed within its grid cell.
 */

/**
 * nmt_newt_grid_set_flags:
 * @grid: an #NmtNewtGrid
 * @widget: a child of @grid
 * @flags: #NmtNewtGridFlags for @widget
 *
 * Sets the #NmtNewtGridFlags on @widget
 */
void
nmt_newt_grid_set_flags (NmtNewtGrid      *grid,
                         NmtNewtWidget    *widget,
                         NmtNewtGridFlags  flags)
{
	NmtNewtGridPrivate *priv = NMT_NEWT_GRID_GET_PRIVATE (grid);
	NmtNewtGridChild *children = (NmtNewtGridChild *)priv->children->data;
	int i;

	i = find_child (grid, widget);
	if (i != -1)
		children[i].flags = flags;
}

static void
nmt_newt_grid_class_init (NmtNewtGridClass *grid_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (grid_class);
	NmtNewtWidgetClass *widget_class = NMT_NEWT_WIDGET_CLASS (grid_class);
	NmtNewtContainerClass *container_class = NMT_NEWT_CONTAINER_CLASS (grid_class);

	g_type_class_add_private (grid_class, sizeof (NmtNewtGridPrivate));

	/* virtual methods */
	object_class->finalize = nmt_newt_grid_finalize;

	widget_class->get_components = nmt_newt_grid_get_components;
	widget_class->size_request   = nmt_newt_grid_size_request;
	widget_class->size_allocate  = nmt_newt_grid_size_allocate;

	container_class->remove = nmt_newt_grid_remove;
}
