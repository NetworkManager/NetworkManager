# Set the C flags to include the GTK+ and Python libraries
CFLAGS = `pkg-config --cflags gtk+-2.0 pygtk-2.0` -I/usr/include/python2.3/ -I.
LDFLAGS = `pkg-config --libs gtk+-2.0 pygtk-2.0`

# Build the shared object
trayicon.so: trayicon.o eggtrayicon.o trayiconmodule.o 
	$(CC) $(LDFLAGS) -shared $^ -o $@


# The path to the GTK+ python types
DEFS=`pkg-config --variable=defsdir pygtk-2.0`

# Generate the C wrapper from the defs and our override file
trayicon.c: trayicon.defs trayicon.override
	pygtk-codegen-2.0 --prefix trayicon \
	--register $(DEFS)/gdk-types.defs \
	--register $(DEFS)/gtk-types.defs \
	--override trayicon.override \
	trayicon.defs > $@

trayicon.defs: eggtrayicon.h config.h
	python \
	/usr/share/pygtk/2.0/codegen/h2def.py \
	eggtrayicon.h > trayicon.defs

config.h:
	touch config.h
	ln -s ../NetworkManager.py .

# A rule to clean the generated files
clean:
	rm -f trayicon.so *.o trayicon.c trayicon.defs *~ config.h NetworkManager.py*

.PHONY: clean
