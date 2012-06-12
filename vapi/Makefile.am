EXTRA_DIST = \
	NetworkManager-1.0.metadata \
	NMClient-1.0.metadata \
	libnm-util.deps \
	libnm-glib.deps

if ENABLE_VAPIGEN
include $(VAPIGEN_MAKEFILE)

libnm-util.vapi: $(top_srcdir)/libnm-util/NetworkManager-1.0.gir  libnm-util.deps NetworkManager-1.0.metadata
libnm-glib.vapi: $(top_srcdir)/libnm-glib/NMClient-1.0.gir  libnm-glib.deps NMClient-1.0.metadata


libnm_util_vapi_METADATADIRS = $(srcdir)
libnm_util_vapi_FILES = $(top_builddir)/libnm-util/NetworkManager-1.0.gir
libnm_util_vapi_DIRS = $(srcdir)

libnm_glib_vapi_METADATADIRS = $(srcdir)
libnm_glib_vapi_FILES = $(top_builddir)/libnm-glib/NMClient-1.0.gir
libnm_glib_vapi_DIRS = $(srcdir)
libnm_glib_vapi_VAPIDIRS = $(srcdir)

VAPIGEN_VAPIS = libnm-util.vapi libnm-glib.vapi
VAPIGEN_VAPIDIRS = $(srcdir)

vapidir = $(VAPIGEN_VAPIDIR)
vapi_DATA = $(VAPIGEN_VAPIS) $(VAPIGEN_VAPIS:.vapi=.deps)


endif
