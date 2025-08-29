# This Makefile started with the default Makefile produced by the Sphinx
# initialization process, which we then modified over time. During the
# Automake-ification, I stripped out most of the boilderplate and left only
# the targets that we use.

# We turn off parallel build in doc:
#
#   1. Sphinx handles building the whole documentation internally already, as
#      a unit, so we shouldn't call sphinx-build more than once for different
#      output files at all, let alone in parallel.
#
#   2. Serial build is plenty fast.
#
#   3. There is a race condition in Sphinx < 1.6.6 that's triggered when two
#      instances (e.g., for html and man targets) try to "mkdir doctrees"
#      simultaneously. See issue #115.
#
# This special target was introduced in GNU Make 3.79, in April 2000.
.NOTPARALLEL:

EXTRA_DIST = \
_ext \
_static \
_redirects \
best_practices.rst \
bugs.rst \
clearly.rst \
clearly-check.rst \
clearly-convert.rst \
clearly-deploy.rst \
clearly-fromhost.rst \
clearly-image.rst \
clearly-list.rst \
clearly-logs.rst \
clearly-run.rst \
clearly-stop.rst \
clearly-test.rst \
conf.py \
faq.rst \
favicon.ico \
index.rst \
install.rst \
install.sh \
logo.svg \
man/README \
py_env.rst \
robots.txt \
see_also.rst \
tutorial.rst

if ENABLE_MAN
man_MANS = \
man/clearly.7 \
man/clearly-check.1 \
man/clearly-convert.1 \
man/clearly-deploy.1 \
man/clearly-fromhost.1 \
man/clearly-image.1 \
man/clearly-list.1 \
man/clearly-logs.1 \
man/clearly-run.1 \
man/clearly-stop.1 \
man/clearly-test.1
endif

if ENABLE_HTML
nobase_html_DATA = \
html/_redirects \
html/.buildinfo \
html/best_practices.html \
html/clearly-check.html \
html/clearly-convert.html \
html/clearly-deploy.html \
html/clearly-fromhost.html \
html/clearly-image.html \
html/clearly-list.html \
html/clearly-run.html \
html/clearly-stop.html \
html/clearly-test.html \
html/faq.html \
html/index.html \
html/install.html \
html/install.sh \
html/robots.txt \
html/search.html \
html/searchindex.js \
html/sitemap.xml \
html/tutorial.html
endif


# NOTE: ./html might be a Git checkout to support "make web", so make sure not
# to delete it.
CLEANFILES = $(man_MANS) $(nobase_html_DATA) \
             html/.buildinfo html/.nojekyll
if ENABLE_HTML
endif

# Automake can't install and uninstall directories. _static contains around
# one hundred files in several directories, and I'm pretty sure the contents
# change depending on Sphinx version and other details, so we can't just list
# the files. These targets deal with it as an opaque directory. The _sources
# directory is another generated directory that contains references to the
# input .rst files which we need for searching to work so we give it a similar
# treatment.
if ENABLE_HTML
install-data-hook:
	cp -r html/_sources $(DESTDIR)$(htmldir)/html
	cp -r html/_static $(DESTDIR)$(htmldir)/html
	find $(DESTDIR)$(htmldir)/html/_sources -xtype f -exec chmod 644 {} \;
	find $(DESTDIR)$(htmldir)/html/_static -xtype d -exec chmod 755 {} \;
	find $(DESTDIR)$(htmldir)/html/_static -xtype f -exec chmod 644 {} \;

uninstall-hook:
	   test -d $(DESTDIR)$(htmldir)/html/_sources \
	&& rm -Rf $(DESTDIR)$(htmldir)/html/_sources \;
	   test -d $(DESTDIR)$(htmldir)/html/_static \
	&& rm -Rf $(DESTDIR)$(htmldir)/html/_static \;
	   test -d $(DESTDIR)$(htmldir)/html/_images \
	&& rm -Rf $(DESTDIR)$(htmldir)/html/_images \;
endif

# You can set these variables from the command line.
SPHINXOPTS    = -W
SPHINXBUILD   = @SPHINX@
PAPER         =
BUILDDIR      = .

# Internal variables.
ALLSPHINXOPTS   = -d $(BUILDDIR)/doctrees $(SPHINXOPTS) .

# Since we're not doing anything in parallel anyway, just put the HTML and the
# man pages in the same target, with conditionals. Gotchas:
#
#   1. If we build both, the HTML needs to go first otherwise it doesn't get
#      curly quotes. ¯\_(ツ)_/¯
#
#   2. This not a "grouped target" but rather an "independent target" [1],
#      because the former came in GNU Make 4.3 which is quite new. However it
#      does seem to get run only once.
#
# [1]: https://www.gnu.org/software/make/manual/html_node/Multiple-Targets.html
html-build: $(EXTRA_DIST)
if ENABLE_HTML
#       Build.
	$(SPHINXBUILD) -b html $(ALLSPHINXOPTS) $(BUILDDIR)/html
#       Copy non-linked files.
	cp install.sh $(BUILDDIR)/html/
#       Remove Sphinx made files.
	rm -f $(BUILDDIR)/html/clearly.html \
	      $(BUILDDIR)/html/bugs.html \
	      $(BUILDDIR)/html/objects.inv \
	      $(BUILDDIR)/html/see_also.html
endif

man-build: $(EXTRA_DIST)
if ENABLE_MAN
	$(SPHINXBUILD) -b man $(ALLSPHINXOPTS) $(BUILDDIR)/man
endif

$(nobase_html_DATA): html-build

$(man_MANS): man-build
