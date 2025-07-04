SUBDIRS = lib bin cmd doc examples misc packaging test static

EXTRA_DIST = LICENSE README.rst VERSION autogen.sh clearly.service

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
			 $(DESTDIR)@datadir@/clearly/common.bash \
	         $(DESTDIR)@datadir@/clearly/doctest \
			 $(DESTDIR)@libdir@/clearly/base.sh; \
	do \
	  if [ -e $$i ]; then \
	    sed -Ei -e 's|^(clearly_lib ?= ?).+/lib"?$$|\1"@libdir@/clearly"|' \
				-e 's|^(clearly_libexec ?= ?).+/libexec"?$$|\1"@libexecdir@/clearly"|' \
	            -e 's|^(TEST_DIR=).+$$|\1@datadir@/clearly|' \
	            -e 's|^(TEST_EXAMPLES_DIR=).+$$|\1@docdir@/examples|' \
                $$i; \
	  fi \
	done
	@echo '### installing systemd service ###'
	@if [ -z "$(DESTDIR)" ]; then \
		sed 's|@bindir@|$(bindir)|g' clearly.service > /tmp/clearly.service.tmp; \
		cp /tmp/clearly.service.tmp /etc/systemd/system/clearly.service; \
		rm /tmp/clearly.service.tmp; \
		mkdir -p /tmp/clearly; \
		touch /var/log/clearly.log; \
		chmod 644 /var/log/clearly.log; \
		systemctl daemon-reload; \
		systemctl enable clearly.service; \
		systemctl start clearly.service; \
	fi

uninstall-hook:
	@echo '### uninstalling systemd service ###'
	@if [ -z "$(DESTDIR)" ]; then \
		systemctl stop clearly.service || true; \
		systemctl disable clearly.service || true; \
		rm -f /etc/systemd/system/clearly.service; \
		systemctl daemon-reload; \
		rm -f /var/log/clearly.log; \
		rm -rf /tmp/clearly; \
	fi