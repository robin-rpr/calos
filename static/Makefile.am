EXTRA_DIST = images styles templates

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(pkgdatadir)/
	cp -R $(srcdir)/images $(srcdir)/styles $(srcdir)/templates $(DESTDIR)$(pkgdatadir)/

uninstall-hook:
	rm -rf $(DESTDIR)$(pkgdatadir)/images $(DESTDIR)$(pkgdatadir)/styles $(DESTDIR)$(pkgdatadir)/templates