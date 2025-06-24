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
run_CFLAGS = $(PTHREAD_CFLAGS) -DLIBEXECDIR="\"$(pkglibexecdir)\"" @LIBNL_CFLAGS@
run_LDADD = $(CLEARLY_RUN_LIBS) @LIBSLIRP_LIBS@ @LIBNL_LIBS@


## Shell scripts - distributed as-is

cmd_SCRIPTS = convert fromhost test

# Python modules to compile via Cython
cython_modules = image daemon run-oci

# Generated file lists
cython_c_files = $(cython_modules:%=%.c)

# Build Python scripts as C extensions using Cython
cmd_PROGRAMS += $(cython_modules)

# Set sources for all Cython programs
image_SOURCES = image.c
daemon_SOURCES = daemon.c
run_oci_SOURCES = run-oci.c
run_oci_CFLAGS = -Wno-unused-function

# Cython compilation rules
SUFFIXES = .py .c

.py.c:
	rm -f $@
	cython $< \
		-E LIBDIR="$(pkglibdir)" \
		-E LIBEXECDIR="$(pkglibexecdir)" \
		--embed \
		-3 \
		-o $@ \
		--module-name $(subst -,_,$(basename $<))
	chmod +rx,-w $@  # respects umask

# Link with Python libraries
image_LDADD = $(PYTHON_LIB)
daemon_LDADD = $(PYTHON_LIB)
run_oci_LDADD = $(PYTHON_LIB)

CLEANFILES = $(cython_c_files)
