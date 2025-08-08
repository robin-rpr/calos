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
  _build _build_cache _clearly _executor _filesystem _force _grammar _http _image \
  _irtree _misc _proxy _pull _push _reference _registry _storage _tree _zeroconf 

cython_c_files = $(cython_modules:%=%.c)
cython_so_files = $(cython_modules:%=%@PYEXT_SUFFIX@)

dist_mylib_DATA = _base.sh $(cython_so_files)

# SUFFIXES is required by Automake to define custom build rules. Without this
# declaration, Automake will not recognize our .py -> .c -> @PYEXT_SUFFIX@
# transformation chain and will fail to build the Cython modules. This tells
# Automake that we have custom build targets for these file extensions.
SUFFIXES = .py .c @PYEXT_SUFFIX@

.py.c:
	cython \
	-E PKGLIBDIR="$(pkglibdir)" \
	-E PKGLIBEXECDIR="$(pkglibexecdir)" \
	-E PKGDATADIR="$(pkgdatadir)" \
	-3 -o $@ $<

.c@PYEXT_SUFFIX@:
	$(CC) -shared -fPIC \
	  -I"$(shell python3 -c 'import sysconfig; print(sysconfig.get_path("include"))')" \
	  $< -o $@ $(shell python3-config --ldflags)

all-local: $(cython_so_files)
mylib_DATA = $(cython_so_files)
mylib_LTLIBRARIES =

uninstall-hook:
	rmdir $$(find $(pkglibdir) -type d | sort -r)

CLEANFILES = $(mylib_DATA) $(cython_c_files) $(cython_so_files)