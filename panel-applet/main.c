#include <gtk/gtk.h>
#include <libgnomeui/libgnomeui.h>
#include "NMWirelessApplet.h"


int
main (int argc, char *argv[])
{
	NMWirelessApplet *nmwa;

	gnome_program_init ("NMWirelessApplet", VERSION, LIBGNOMEUI_MODULE,
			    argc, argv, 
			    GNOME_PARAM_NONE);

	nmwa = nmwa_new ();

	gtk_widget_show_all (nmwa);

	gtk_main ();
}
