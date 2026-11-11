AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-mlex.la
else
plugin_LTLIBRARIES = libstrongswan-mlex.la
endif

libstrongswan_mlex_la_SOURCES = \
	mlex_bitpacker.c mlex_bitpacker.h \
	mlex_kem.c mlex_kem.h \
	mlex_params.c mlex_params.h \
	mlex_plugin.h mlex_plugin.c \
	mlex_poly.c mlex_poly.h \
	mlex_utils.c mlex_utils.h

libstrongswan_mlex_la_LDFLAGS = -module -avoid-version
