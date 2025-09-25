# Bugs in this Makefile:
#
# 1. $(EXEEXT) not included for scripts.

## C programs

cmddir = $(pkglibexecdir)
cmd_PROGRAMS = check run

run_SOURCES = run.c core.h core.c net.h net.c misc.h misc.c
if HAVE_LIBSQUASHFUSE
run_SOURCES += fuse.h fuse.c
endif
run_CFLAGS = $(PTHREAD_CFLAGS) -DLIBEXECDIR="\"$(pkglibexecdir)\"" -DSYSCONFDIR="\"$(sysconfdir)/clearly\"" @LIBNL_CFLAGS@ @JSONC_CFLAGS@
run_LDADD = $(CLEARLY_RUN_LIBS) @LIBMNL_LIBS@ @LIBNFTNL_LIBS@ @LIBNL_LIBS@ @JSONC_LIBS@

check_SOURCES = check.c misc.h misc.c

## Shell scripts - distributed as-is

EXTRA_DIST = convert equip test stop logs version
cmd_SCRIPTS = convert equip test stop logs version

# Python modules to compile via Cython
cython_modules = daemon deploy image list

# Generated file lists
cython_c_files = $(cython_modules:%=%.c)

# Build Python scripts as C extensions using Cython
cmd_PROGRAMS += $(cython_modules)

# Set sources for all Cython programs
daemon_SOURCES = daemon.c
deploy_SOURCES = deploy.c
image_SOURCES = image.c
list_SOURCES = list.c

# Cython compilation rules
SUFFIXES = .py .c

.py.c:
	rm -f $@
	cython $< \
		-E PKGLIBDIR="$(pkglibdir)" \
		-E PKGLIBEXECDIR="$(pkglibexecdir)" \
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
daemon_LDADD = $(PYTHON_LIB)
deploy_LDADD = $(PYTHON_LIB)
image_LDADD = $(PYTHON_LIB)
list_LDADD = $(PYTHON_LIB)

CLEANFILES = $(cython_c_files)