# Bugs in this Makefile:
#
# 1. $(EXEEXT) not included for scripts.

## C programs

bin_PROGRAMS = clearstack
libexec_PROGRAMS = checkns ch-run

clearstack_SOURCES = clearstack.c
clearstack_CFLAGS = -DLIBEXECDIR="\"$(libexecdir)\""

checkns_SOURCES = checkns.c misc.h misc.c

ch_run_SOURCES = ch-run.c core.h core.c misc.h misc.c
if HAVE_LIBSQUASHFUSE
ch_run_SOURCES += fuse.h fuse.c
endif

# additional build flags for ch-run
ch_run_CFLAGS = $(PTHREAD_CFLAGS)
ch_run_LDADD = $(CH_RUN_LIBS)


## Shell scripts - distributed as-is

libexec_SCRIPTS = convert \
                   ch-fromhost \
                   ch-test

# Build Python scripts as C extensions using Cython
libexec_PROGRAMS += image daemon ch-run-oci

image_SOURCES = image.c
ch_run_oci_SOURCES = ch-run-oci.c
daemon_SOURCES = daemon.c
ch_run_oci_CFLAGS = -Wno-unused-function

# Cython compilation rules
image.c: image.py
	rm -f $@
	cython image.py --embed -3 -o image.c --module-name image
	chmod +rx,-w $@  # respects umask

ch-run-oci.c: ch-run-oci.py
	rm -f $@
	cython ch-run-oci.py --embed -3 -o ch-run-oci.c --module-name ch_run_oci
	chmod +rx,-w $@  # respects umask

daemon.c: daemon.py
	rm -f $@
	cython daemon.py --embed -3 -o daemon.c --module-name daemon
	chmod +rx,-w $@  # respects umask

# Link with Python libraries
image_LDADD = $(PYTHON_LIB)
ch_run_oci_LDADD = $(PYTHON_LIB)
daemon_LDADD = $(PYTHON_LIB)

CLEANFILES = image.c daemon.c ch-run-oci.c
