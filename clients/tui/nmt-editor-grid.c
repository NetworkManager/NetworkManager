// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmt-editor-grid
 * @short_description: Grid widget for #NmtEditorPages
 *
 * #NmtEditorGrid is the layout grid used by #NmtEditorPages. It
 * consists of a number of rows, each containing either a single
 * widget that spans the entire width of the row, or else containing a
 * label, a widget, and an optional extra widget.
 *
 * Each row of the grid can take up multiple on-screen rows, if
 * its main widget is multiple rows high. The label and extra widgets
 * will be top-aligned if the row is taller than they are.
 *
 * The #NmtEditorGrids in a form behave as though they are all in a
 * "size group" together; they will all use the same column widths,
 * which will be wide enough for the widest labels/widgets in any of
 * the grids. #NmtEditorGrid is also specially aware of #NmtNewtSection,
 * and grids inside sections will automatically take the size of the
 * section border into account as well.
 */

#include "nm-default.h"

#include "nmt-editor-grid.h"

G_DEFINE_TYPE (NmtEditorGrid, nmt_editor_grid, NMT_TYPE_NEWT_CONTAINER)

#define NMT_EDITOR_GRID_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_EDITOR_GRID, NmtEditorGridPrivate))

typedef struct {
	GArray *rows;
	int *row_heights;
	int indent;
} NmtEditorGridPrivate;

typedef struct {
	NmtNewtWidget *label;
	NmtNewtWidget *widget;
	NmtNewtWidget *extra;
	NmtEditorGridRowFlags flags;
} NmtEditorGridRow;

typedef struct {
	int col_widths[3];
} NmtEditorGridFormState;

/**
 * nmt_editor_grid_new:
 *
 * Creates a new #NmtEditorGrid
 *
 * Returns: a new #NmtEditorGrid
 */
NmtNewtWidget *
nmt_editor_grid_new (void)
{
	return g_object_new (NMT_TYPE_EDITOR_GRID,
	                     NULL);
}

static void
nmt_editor_grid_init (NmtEditorGrid *grid)
{
	NmtEditorGridPrivate *priv = NMT_EDITOR_GRID_GET_PRIVATE (grid);

	priv->rows = g_array_new (FALSE, TRUE, sizeof (NmtEditorGridRow));
}

static void
nmt_editor_grid_finalize (GObject *object)
{
	NmtEditorGridPrivate *priv = NMT_EDITOR_GRID_GET_PRIVATE (object);

	g_array_unref (priv->rows);
	g_clear_pointer (&priv->row_heights, g_free);

	G_OBJECT_CLASS (nmt_editor_grid_parent_class)->finalize (object);
}

/**
 * nmt_editor_grid_append:
 * @grid: the #NmtEditorGrid
 * @label: (allow-none): the label text for @widget, or %NULL
 * @widget: (allow-none): the (main) widget
 * @extra: (allow-none): optional extra widget
 *
 * Adds a row to @grid.
 *
 * If @label and @widget are both non-%NULL, this will add a three-column row,
 * containing a right-aligned #NmtNewtLabel in the first column, @widget in the
 * second column, and @extra (if non-%NULL) in the third column.
 *
 * If either @label or @widget is %NULL, then the other column will expand into
 * it.
 *
 * See also nmt_editor_grid_set_row_flags().
 */
void
nmt_editor_grid_append (NmtEditorGrid   *grid,
                      const char    *label,
                      NmtNewtWidget *widget,
                      NmtNewtWidget *extra)
{
	NmtEditorGridPrivate *priv = NMT_EDITOR_GRID_GET_PRIVATE (grid);
	NmtNewtContainerClass *parent_class = NMT_NEWT_CONTAINER_CLASS (nmt_editor_grid_parent_class);
	NmtNewtContainer *container = NMT_NEWT_CONTAINER (grid);
	NmtEditorGridRow row;

	g_return_if_fail (label != NULL || widget != NULL);

	memset (&row, 0, sizeof (row));

	if (label && !widget) {
		widget = nmt_newt_label_new (label);
		label = NULL;
	}

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
nmt_editor_grid_find_widget (NmtEditorGrid   *grid,
                           NmtNewtWidget *widget)
{
	NmtEditorGridPrivate *priv = NMT_EDITOR_GRID_GET_PRIVATE (grid);
	NmtEditorGridRow *rows = (NmtEditorGridRow *) priv->rows->data;
	int i;

	for (i = 0; i < priv->rows->len; i++) {
		if (rows[i].label == widget || rows[i].widget == widget || rows[i].extra == widget)
			return i;
	}

	return -1;
}

/**
 * NmtEditorGridRowFlags:
 * @NMT_EDITOR_GRID_ROW_LABEL_ALIGN_LEFT: the row's label should be
 *   aligned left instead of right.
 * @NMT_EDITOR_GRID_ROW_EXTRA_ALIGN_RIGHT: the row's extra widget
 *   should be aligned right instead of left.
 *
 * Flags to alter an #NmtEditorGrid row's layout.
 */

/**
 * nmt_editor_grid_set_row_flags:
 * @grid: an #NmtEditorGrid
 * @widget: the widget whose row you want to adjust
 * @flags: the flags to set
 *
 * Sets flags to adjust the layout of @widget's row in @grid.
 */
void
nmt_editor_grid_set_row_flags (NmtEditorGrid         *grid,
                             NmtNewtWidget       *widget,
                             NmtEditorGridRowFlags  flags)
{
	NmtEditorGridPrivate *priv = NMT_EDITOR_GRID_GET_PRIVATE (grid);
	NmtEditorGridRow *rows = (NmtEditorGridRow *) priv->rows->data;
	int i;

	i = nmt_editor_grid_find_widget (grid, widget);
	if (i != -1)
		rows[i].flags = flags;
}

static void
nmt_editor_grid_remove (NmtNewtContainer *container,
                      NmtNewtWidget    *widget)
{
	NmtEditorGrid *grid = NMT_EDITOR_GRID (container);
	NmtEditorGridPrivate *priv = NMT_EDITOR_GRID_GET_PRIVATE (grid);
	NmtNewtContainerClass *parent_class = NMT_NEWT_CONTAINER_CLASS (nmt_editor_grid_parent_class);
	NmtEditorGridRow *rows = (NmtEditorGridRow *) priv->rows->data;
	int i;

	i = nmt_editor_grid_find_widget (grid, widget);
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
nmt_editor_grid_get_components (NmtNewtWidget *widget)
{
	NmtEditorGridPrivate *priv = NMT_EDITOR_GRID_GET_PRIVATE (widget);
	NmtEditorGridRow *rows = (NmtEditorGridRow *) priv->rows->data;
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

static NmtEditorGridFormState *
get_form_state (NmtNewtWidget *widget)
{
	NmtNewtForm *form = nmt_newt_widget_get_form (widget);
	NmtEditorGridFormState *state;

	if (!form)
		return NULL;

	state = g_object_get_data (G_OBJECT (form), "NmtEditorGridFormState");
	if (state)
		return state;

	state = g_new0 (NmtEditorGridFormState, 1);
	g_object_set_data_full (G_OBJECT (form), "NmtEditorGridFormState", state, g_free);
	return state;
}

static void
nmt_editor_grid_realize (NmtNewtWidget *widget)
{
	NmtEditorGridPrivate *priv = NMT_EDITOR_GRID_GET_PRIVATE (widget);
	NmtNewtWidget *parent;

	NMT_NEWT_WIDGET_CLASS (nmt_editor_grid_parent_class)->realize (widget);

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
nmt_editor_grid_unrealize (NmtNewtWidget *widget)
{
	NmtEditorGridFormState *state = get_form_state (widget);

	if (state)
		memset (state->col_widths, 0, sizeof (state->col_widths));

	NMT_NEWT_WIDGET_CLASS (nmt_editor_grid_parent_class)->unrealize (widget);
}

static void
nmt_editor_grid_size_request (NmtNewtWidget *widget,
                            int           *width,
                            int           *height)
{
	NmtEditorGridPrivate *priv = NMT_EDITOR_GRID_GET_PRIVATE (widget);
	NmtEditorGridRow *rows = (NmtEditorGridRow *) priv->rows->data;
	NmtEditorGridFormState *state = get_form_state (widget);
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
nmt_editor_grid_size_allocate (NmtNewtWidget *widget,
                             int            x,
                             int            y,
                             int            width,
                             int            height)
{
	NmtEditorGridPrivate *priv = NMT_EDITOR_GRID_GET_PRIVATE (widget);
	NmtEditorGridRow *rows = (NmtEditorGridRow *) priv->rows->data;
	NmtEditorGridFormState *state = get_form_state (widget);
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

			if (rows[i].flags & NMT_EDITOR_GRID_ROW_LABEL_ALIGN_LEFT)
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
		} else {
			nmt_newt_widget_size_allocate (rows[i].widget,
			                               x,
			                               y + row,
			                               col0_width + col1_width + 1,
			                               priv->row_heights[i]);
		}

		if (rows[i].extra) {
			int wwidth, wheight, ex;

			if (rows[i].flags & NMT_EDITOR_GRID_ROW_EXTRA_ALIGN_RIGHT)
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

		row += priv->row_heights[i];
	}
}

static void
nmt_editor_grid_class_init (NmtEditorGridClass *grid_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (grid_class);
	NmtNewtWidgetClass *widget_class = NMT_NEWT_WIDGET_CLASS (grid_class);
	NmtNewtContainerClass *container_class = NMT_NEWT_CONTAINER_CLASS (grid_class);

	g_type_class_add_private (grid_class, sizeof (NmtEditorGridPrivate));

	/* virtual methods */
	object_class->finalize = nmt_editor_grid_finalize;

	widget_class->realize        = nmt_editor_grid_realize;
	widget_class->unrealize      = nmt_editor_grid_unrealize;
	widget_class->get_components = nmt_editor_grid_get_components;
	widget_class->size_request   = nmt_editor_grid_size_request;
	widget_class->size_allocate  = nmt_editor_grid_size_allocate;

	container_class->remove = nmt_editor_grid_remove;
}
