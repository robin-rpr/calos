# Bugs in this Makefile:
#
# 1. $(EXEEXT) not included for scripts.

## C programs

bin_PROGRAMS = charlie
libexec_PROGRAMS = ch-checkns ch-run

charlie_SOURCES = charlie.c
charlie_CFLAGS = -DLIBEXECDIR="\"$(libexecdir)\""

ch_checkns_SOURCES = ch-checkns.c misc.h misc.c

ch_run_SOURCES = ch-run.c core.h core.c misc.h misc.c
if HAVE_LIBSQUASHFUSE
ch_run_SOURCES += fuse.h fuse.c
endif

# additional build flags for ch-run
ch_run_CFLAGS = $(PTHREAD_CFLAGS)
ch_run_LDADD = $(CH_RUN_LIBS)


## Shell scripts - distributed as-is

libexec_SCRIPTS = ch-convert \
                   ch-fromhost \
                   ch-test

# Build Python scripts as C extensions using Cython
libexec_PROGRAMS += ch-image ch-daemon ch-run-oci

ch_image_SOURCES = ch-image.c
ch_run_oci_SOURCES = ch-run-oci.c
ch_daemon_SOURCES = ch-daemon.c
ch_run_oci_CFLAGS = -Wno-unused-function

# Cython compilation rules
ch-image.c: ch-image.py
	rm -f $@
	cython ch-image.py --embed -3 -o ch-image.c --module-name ch_image
	chmod +rx,-w $@  # respects umask

ch-run-oci.c: ch-run-oci.py
	rm -f $@
	cython ch-run-oci.py --embed -3 -o ch-run-oci.c --module-name ch_run_oci
	chmod +rx,-w $@  # respects umask

ch-daemon.c: ch-daemon.py
	rm -f $@
	cython ch-daemon.py --embed -3 -o ch-daemon.c --module-name ch_daemon
	chmod +rx,-w $@  # respects umask

# Link with Python libraries
ch_image_LDADD = $(PYTHON_LIB)
ch_run_oci_LDADD = $(PYTHON_LIB)
ch_daemon_LDADD = $(PYTHON_LIB)

CLEANFILES = ch-image.c ch-daemon.c ch-run-oci.c
