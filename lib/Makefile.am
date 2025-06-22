# Define an alias for pkglibdir to override Automake helpfulness:
#
#   error: 'pkglibdir' is not a legitimate directory for 'DATA'
#
# See: https://www.gnu.org/software/automake/manual/html_node/Uniform.html
mylibdir = $(pkglibdir)

# Python modules to compile via Cython. These modules contain the core
# functionality of the system and are written in Python with Cython
# extensions for performance. They will be compiled to C and then to
# shared objects for faster execution.

cython_modules = \
  _build _build_cache _clearly _filesystem _misc _pull _push \
  _reference _registry _image _irtree _tree _force _grammar _version


cython_c_files = $(cython_modules:%=%.c)
cython_so_files = $(cython_modules:%=%@PYEXT_SUFFIX@)

dist_mylib_DATA = _base.sh

# SUFFIXES is required by Automake to define custom build rules. Without this
# declaration, Automake will not recognize our .py -> .c -> @PYEXT_SUFFIX@
# transformation chain and will fail to build the Cython modules. This tells
# Automake that we have custom build targets for these file extensions.
SUFFIXES = .py .c @PYEXT_SUFFIX@

mylib_DATA = _contributors.bash _version.py _version.txt 
mylib_SCRIPTS = _version.sh

.py.c:
	cython -E LIBDIR="$(pkglibdir)" -E LIBEXECDIR="$(pkglibexecdir)" -3 -o $@ $<

.c@PYEXT_SUFFIX@:
	$(CC) -shared -fPIC \
	  -I"$(shell python3 -c 'import sysconfig; print(sysconfig.get_path("include"))')" \
	  $< -o $@ $(shell python3-config --ldflags)

all-local: $(cython_so_files)
mylib_DATA += $(cython_so_files)
mylib_LTLIBRARIES =

_contributors.bash: ../README.rst
	rm -f $@
	printf '# shellcheck shell=bash\n' >> $@
	printf 'declare -a ch_contributors\n' >> $@
	sed -En 's/^\*.+<(.+@.+)>.*$$/ch_contributors+=('"'"'\1'"'"')/p' < $< >> $@

_version.txt: ../configure
	printf '@PACKAGE_VERSION@\n' > $@

_version.py: ../configure
	printf "VERSION='@PACKAGE_VERSION@'\n" > $@

_version.sh: ../configure
	printf "# shellcheck shell=sh disable=SC2034\n" > $@
	printf "ch_version='@PACKAGE_VERSION@'\n" >> $@
	chmod +x $@

uninstall-hook:
	rmdir $$(find $(pkglibdir) -type d | sort -r)

CLEANFILES = $(mylib_DATA) $(cython_c_files) $(cython_so_files)