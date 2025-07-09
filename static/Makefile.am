imagesdir = $(pkgdatadir)/images
stylesdir = $(pkgdatadir)/styles
templatesdir = $(pkgdatadir)/templates

images_DATA = \
  images/favicon-32x32.png \
  images/favicon-256x256.png \
  images/favicon.svg \
  images/jupyter.svg \
  images/sprite.svg \
  images/tensorflow.svg \
  images/vscode.svg

styles_DATA = \
  styles/base/_mixins.scss \
  styles/base/_variables.scss \
  styles/layout/_header.scss \
  styles/layout/_navigation.scss \
  styles/layout/_searchbar.scss \
  styles/layout/_sidebar.scss \
  styles/pages/_index.scss \
  styles/pages/_studio.scss \
  styles/main.scss

templates_DATA = \
  templates/layout/header.html \
  templates/layout/navigation.html \
  templates/layout/searchbar.html \
  templates/layout/sidebar.html \
  templates/pages/index.html \
  templates/pages/studio.html \
  templates/main.html

EXTRA_DIST = $(images_DATA) $(styles_DATA) $(templates_DATA)

uninstall-local:
	@find "$(DESTDIR)$(pkgdatadir)" -type f -delete
	@find "$(DESTDIR)$(pkgdatadir)" -depth -type d -empty -exec rmdir {} +