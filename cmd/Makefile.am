# Bugs in this Makefile:
#
# 1. $(EXEEXT) not included for scripts.

## C programs

cmddir = $(pkglibexecdir)
cmd_PROGRAMS = check run use logs stop
EXTRA_DIST = convert fromhost test

run_SOURCES = run.c core.h core.c net.h net.c misc.h misc.c
if HAVE_LIBSQUASHFUSE
run_SOURCES += fuse.h fuse.c
endif
run_CFLAGS = $(PTHREAD_CFLAGS) -DLIBEXECDIR="\"$(pkglibexecdir)\"" @LIBNL_CFLAGS@ @JSONC_CFLAGS@
run_LDADD = $(CLEARLY_RUN_LIBS) @LIBMNL_LIBS@ @LIBNFTNL_LIBS@ @LIBNL_LIBS@ @JSONC_LIBS@

check_SOURCES = check.c misc.h misc.c

use_SOURCES = use.c net.h net.c misc.h misc.c
use_CFLAGS = @LIBNL_CFLAGS@
use_LDADD = @LIBMNL_LIBS@ @LIBNFTNL_LIBS@ @LIBNL_LIBS@

## Shell scripts - distributed as-is

cmd_SCRIPTS = convert fromhost test version

# Python modules to compile via Cython
cython_modules = image daemon

# Generated file lists
cython_c_files = $(cython_modules:%=%.c)

# Build Python scripts as C extensions using Cython
cmd_PROGRAMS += $(cython_modules)

# Set sources for all Cython programs
image_SOURCES = image.c
daemon_SOURCES = daemon.c

# Cython compilation rules
SUFFIXES = .py .c

.py.c:
	rm -f $@
	cython $< \
		-E PKGLIBDIR="$(pkglibdir)" \
		-E PKGLIBEXECDIR="$(pkglibexecdir)" \
		-E PKGDATADIR="$(pkgdatadir)" \
		--embed \
		-3 \
		-o $@
	chmod +rx,-w $@ # respects umask

# Version script
version: ../configure
	printf "#!/bin/sh\n" > $@
	printf "echo '@PACKAGE_VERSION@'" >> $@
	chmod +x $@

# Link with Python libraries
image_LDADD = $(PYTHON_LIB)
daemon_LDADD = $(PYTHON_LIB)

CLEANFILES = $(cython_c_files)