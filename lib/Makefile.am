# Define an alias for pkglibdir to override Automake helpfulness:
#
#   error: 'pkglibdir' is not a legitimate directory for 'DATA'
#
# See: https://www.gnu.org/software/automake/manual/html_node/Uniform.html
mylibdir = $(pkglibdir)

dist_mylib_DATA = base.sh

uninstall-hook:
	rmdir $$(find $(pkglibdir) -type d | sort -r)

CLEANFILES = $(mylib_DATA)