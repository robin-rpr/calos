imagesdir = $(pkgdatadir)
stylesdir = $(pkgdatadir)
templatesdir = $(pkgdatadir)

nobase_images_DATA = \
  images/favicon-32x32.png \
  images/favicon-256x256.png \
  images/favicon.svg

nobase_styles_DATA = \
  styles/base/_mixins.scss \
  styles/base/_variables.scss \
  styles/layout/_header.scss \
  styles/layout/_navigation.scss \
  styles/pages/_index.scss \
  styles/pages/_studio.scss \
  styles/main.scss

nobase_templates_DATA = \
  templates/layout/header.html \
  templates/layout/navigation.html \
  templates/pages/index.html \
  templates/pages/studio.html \
  templates/main.html

EXTRA_DIST = $(nobase_images_DATA) $(nobase_styles_DATA) $(nobase_templates_DATA)

uninstall-local:
	@find "$(DESTDIR)$(pkgdatadir)" -type f -delete
	@find "$(DESTDIR)$(pkgdatadir)" -depth -type d -empty -exec rmdir {} +