### Makefile.am

AM_CPPFLAGS = -D_POSIX_C_SOURCE=200112L -D_XOPEN_SOURCE=600 -D_BSD_SOURCE
AM_LDFLAGS =

bin_PROGRAMS =
noinst_PROGRAMS =
lib_LTLIBRARIES =
noinst_LTLIBRARIES =
noinst_HEADERS =
BUILT_SOURCES =
CLEANFILES =
EXTRA_DIST = $(BUILT_SOURCES)


include_HEADERS = pimmel.h

lib_LTLIBRARIES += libpimmel.la
libpimmel_la_SOURCES =

bin_PROGRAMS += pimmel-noti
pimmel_noti_SOURCES = pimmel-noti.c pimmel-noti-clo.ggo
pimmel_noti_CPPFLAGS = $(AM_CPPFLAGS)
pimmel_noti_CPPFLAGS += $(libev_CFLAGS)
pimmel_noti_LDFLAGS = $(AM_LDFLAGS)
pimmel_noti_LDFLAGS += $(libev_LIBS)
BUILT_SOURCES += pimmel-noti-clo.c pimmel-noti-clo.h

bin_PROGRAMS += pimmel-wait
pimmel_wait_SOURCES = pimmel-wait.c pimmel-wait-clo.ggo
pimmel_wait_CPPFLAGS = $(AM_CPPFLAGS)
pimmel_wait_CPPFLAGS += $(libev_CFLAGS)
pimmel_wait_LDFLAGS = $(AM_LDFLAGS)
pimmel_wait_LDFLAGS += $(libev_LIBS)
BUILT_SOURCES += pimmel-wait-clo.c pimmel-wait-clo.h


## our rule for gengetopt
%.c %.h: %.ggo
	$(AM_V_GEN) gengetopt -l -i $< -F $*

## our rule for gperf
%.c: %.gperf
	$(AM_V_GEN) $(GPERF) $< --output-file $@

# 
# Help the developers get nice post-processed source files

## Create preprocessor output (debugging purposes only)
.c.i:
	$(COMPILE) -E -o $@ $<

## Create assembler output (debugging purposes only)
.c.s:
	$(COMPILE) -S -c $(AM_CFLAGS) $<
