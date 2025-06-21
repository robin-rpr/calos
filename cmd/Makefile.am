# Bugs in this Makefile:
#
# 1. $(EXEEXT) not included for scripts.

## C programs

cmddir = $(pkglibexecdir)
cmd_PROGRAMS = checkns run

checkns_SOURCES = checkns.c misc.h misc.c

run_SOURCES = run.c core.h core.c misc.h misc.c
if HAVE_LIBSQUASHFUSE
run_SOURCES += fuse.h fuse.c
endif

# additional build flags for run
run_CFLAGS = $(PTHREAD_CFLAGS)
run_LDADD = $(CH_RUN_LIBS)


## Shell scripts - distributed as-is

cmd_SCRIPTS = convert \
                   ch-fromhost \
                   ch-test

# Build Python scripts as C extensions using Cython
cmd_PROGRAMS += image daemon run-oci

image_SOURCES = image.c
run_oci_SOURCES = run-oci.c
daemon_SOURCES = daemon.c
run_oci_CFLAGS = -Wno-unused-function

# Cython compilation rules
image.c: image.py
	rm -f $@
	cython image.py -E LIBDIR="$(pkglibdir)" --embed -3 -o image.c --module-name image
	chmod +rx,-w $@  # respects umask

run-oci.c: run-oci.py
	rm -f $@
	cython run-oci.py -E LIBDIR="$(pkglibdir)" --embed -3 -o run-oci.c --module-name run_oci
	chmod +rx,-w $@  # respects umask

daemon.c: daemon.py
	rm -f $@
	cython daemon.py -E LIBDIR="$(pkglibdir)" --embed -3 -o daemon.c --module-name daemon
	chmod +rx,-w $@  # respects umask

# Link with Python libraries
image_LDADD = $(PYTHON_LIB)
run_oci_LDADD = $(PYTHON_LIB)
daemon_LDADD = $(PYTHON_LIB)

CLEANFILES = image.c daemon.c run-oci.c
