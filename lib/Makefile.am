# Define an alias for pkglibdir to override Automake helpfulness:
#
#   error: 'pkglibdir' is not a legitimate directory for 'DATA'
#
# See: https://www.gnu.org/software/automake/manual/html_node/Uniform.html
mylibdir = $(pkglibdir)

# Python modules to compile via Cython
cython_modules = \
  build build_cache charliecloud filesystem misc modify pull \
  push registry image irtree force version

# Generated file lists
cython_c_files = $(cython_modules:%=%.c)
cython_so_files = $(cython_modules:%=%@PYEXT_SUFFIX@)

# Shell + non-Cython files installed as-is
dist_mylib_DATA = base.sh

# Version + metadata files
mylib_DATA = contributors.bash version.py version.sh version.txt

# Cython rules
SUFFIXES = .py .c @PYEXT_SUFFIX@

.py.c:
	cython -3 -o $@ $<

.c@PYEXT_SUFFIX@:
	$(CC) -shared -fPIC \
	  -I"$(shell python3 -c 'import sysconfig; print(sysconfig.get_path("include"))')" \
	  $< -o $@ $(shell python3-config --ldflags)

# Build .so files by default
all-local: $(cython_so_files)

# Install .so files as data files
mylib_DATA += $(cython_so_files)
mylib_LTLIBRARIES =

# Cleanup
CLEANFILES = $(mylib_DATA) $(cython_c_files) $(cython_so_files)

# Contributor extraction
contributors.bash: ../README.rst
	rm -f $@
	printf '# shellcheck shell=bash\n' >> $@
	printf 'declare -a ch_contributors\n' >> $@
	sed -En 's/^\*.+<(.+@.+)>.*$$/ch_contributors+=('"'"'\1'"'"')/p' < $< >> $@

# Remove empty charliecloud directories after uninstallation.
uninstall-hook:
	rmdir $$(find $(pkglibdir) -type d | sort -r)

version.txt: ../configure
	printf '@PACKAGE_VERSION@\n' > $@

version.py: ../configure
	printf "VERSION='@PACKAGE_VERSION@'\n" > $@

version.sh: ../configure
	printf "# shellcheck shell=sh disable=SC2034\n" > $@
	printf "ch_version='@PACKAGE_VERSION@'\n" >> $@