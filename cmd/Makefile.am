# Bugs in this Makefile:
#
# 1. $(EXEEXT) not included for scripts.

## C programs

cmddir = $(pkglibexecdir)
cmd_PROGRAMS = check run link

run_SOURCES = run.c core.h core.c net.h net.c misc.h misc.c
if HAVE_LIBSQUASHFUSE
run_SOURCES += fuse.h fuse.c
endif
run_CFLAGS = $(PTHREAD_CFLAGS) -DLIBEXECDIR="\"$(pkglibexecdir)\"" @LIBNL_CFLAGS@
run_LDADD = $(CLEARLY_RUN_LIBS) @LIBMNL_LIBS@ @LIBNFTNL_LIBS@ @LIBNL_LIBS@

check_SOURCES = check.c misc.h misc.c

link_SOURCES = link.c net.h net.c misc.h misc.c
link_CFLAGS = @LIBNL_CFLAGS@
link_LDADD = @LIBMNL_LIBS@ @LIBNFTNL_LIBS@ @LIBNL_LIBS@

## Shell scripts - distributed as-is

cmd_SCRIPTS = convert fromhost test version

# Python modules to compile via Nuitka
nuitka_modules = image daemon

# Add Nuitka-compiled programs to the list of programs to be built
cmd_PROGRAMS += $(nuitka_modules)

## Tell Automake there are no C sources for Nuitka modules
image_SOURCES =
daemon_SOURCES =

# Nuitka compilation rules
# We use --standalone to create a directory with the binary and its dependencies.
# For a single file executable, --onefile can be used.
$(nuitka_modules): %: %.py
	@echo "Compiling $< with Nuitka..."
	LDFLAGS="$(image_LDADD)" PYTHONPATH=.. python3 -m nuitka \
		--onefile \
		--include-package=lib \
		--output-filename=$(@) \
		--force-runtime-environment-variable=PKGLIBDIR="$(pkglibdir)" \
		--force-runtime-environment-variable=PKGLIBEXECDIR="$(pkglibexecdir)" \
		--force-runtime-environment-variable=PKGDATADIR="$(pkgdatadir)" \
		--force-runtime-environment-variable=HAVE_NUITKA="True" \
		$<

# Version script
version: ../configure
	printf "#!/bin/sh\n" > $@
	printf "echo '@PACKAGE_VERSION@'" >> $@
	chmod +x $@

# Tell make that the targets are not actual files in the source directory
.PHONY: $(nuitka_modules)

# Update CLEANFILES to remove Nuitka build artifacts
CLEANFILES = $(nuitka_modules:=.dist) $(nuitka_modules:=.build)