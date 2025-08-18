SUBDIRS = lib bin cmd doc examples misc packaging test static

EXTRA_DIST = LICENSE README.rst VERSION autogen.sh

# Embedded paths are in the source code suitable for running from the source
# directory (i.e., without install). When installing, those paths are often
# wrong, so re-write them with the correct paths we got from configure. Note:
# Some variables are in both Python and sh, so we use syntax valid for both;
# others are just sh.
install-exec-hook:
	@echo '### re-writing embedded paths ###'
	for i in $(DESTDIR)@libexecdir@/clearly/convert \
	         $(DESTDIR)@libexecdir@/clearly/fromhost \
	         $(DESTDIR)@libexecdir@/clearly/test \
			 $(DESTDIR)@libexecdir@/clearly/list \
			 $(DESTDIR)@libexecdir@/clearly/stop \
			 $(DESTDIR)@libexecdir@/clearly/logs \
			 $(DESTDIR)@datadir@/clearly/common.bash \
	         $(DESTDIR)@datadir@/clearly/doctest \
			 $(DESTDIR)@libdir@/clearly/_base.sh; \
	do \
	  if [ -e $$i ]; then \
	    sed -Ei -e 's|^(clearly_lib ?= ?).+/lib"?$$|\1"@libdir@/clearly"|' \
				-e 's|^(clearly_libexec ?= ?).+/libexec"?$$|\1"@libexecdir@/clearly"|' \
	            -e 's|^(TEST_DIR=).+$$|\1@datadir@/clearly|' \
	            -e 's|^(TEST_EXAMPLES_DIR=).+$$|\1@docdir@/examples|' \
                $$i; \
	  fi \
	done
	@echo '### creating paths ###'
	mkdir -p /var/tmp/clearly
	mkdir -p /var/lib/clearly

uninstall-hook:
	@echo '### deleting paths ###'
	rm -rf /var/tmp/clearly
	rm -rf /var/lib/clearly

clean-local:
	@echo '### emptying paths ###'
	rm -rf /var/tmp/clearly/*
	rm -rf /var/lib/clearly/*