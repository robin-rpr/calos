SUBDIRS = lib bin doc examples misc packaging test

EXTRA_DIST = LICENSE README.rst VERSION autogen.sh clearstack.service

# Embedded paths are in the source code suitable for running from the source
# directory (i.e., without install). When installing, those paths are often
# wrong, so re-write them with the correct paths we got from configure. Note:
# Some variables are in both Python and sh, so we use syntax valid for both;
# others are just sh.
install-exec-hook:
	@echo '### re-writing embedded paths ###'
	for i in $(DESTDIR)@bindir@/ch-convert \
	         $(DESTDIR)@bindir@/ch-fromhost \
	         $(DESTDIR)@bindir@/ch-test \
	         $(DESTDIR)@libdir@/charliecloud/base.sh \
	         $(DESTDIR)@libexecdir@/charliecloud/doctest; \
	do \
	  if [ -e $$i ]; then \
	    sed -Ei -e 's|^(ch_lib ?= ?).+/lib"?$$|\1"@libdir@/charliecloud"|'\
	            -e 's|^(CHTEST_DIR=).+$$|\1@libexecdir@/charliecloud|' \
	            -e 's|^(CHTEST_EXAMPLES_DIR=).+$$|\1@docdir@/examples|' \
                $$i; \
	  fi \
	done
	@echo '### installing systemd service ###'
	@if [ -z "$(DESTDIR)" ]; then \
		sed 's|@bindir@|$(bindir)|g' clearstack.service > /tmp/clearstack.service.tmp; \
		cp /tmp/clearstack.service.tmp /etc/systemd/system/clearstack.service; \
		rm /tmp/clearstack.service.tmp; \
		mkdir -p /tmp/clearstack; \
		touch /var/log/clearstack.log; \
		chmod 644 /var/log/clearstack.log; \
		systemctl daemon-reload; \
		systemctl enable clearstack.service; \
		systemctl start clearstack.service; \
	fi

uninstall-hook:
	@echo '### uninstalling systemd service ###'
	@if [ -z "$(DESTDIR)" ]; then \
		systemctl stop clearstack.service || true; \
		systemctl disable clearstack.service || true; \
		rm -f /etc/systemd/system/clearstack.service; \
		systemctl daemon-reload; \
		rm -f /var/log/clearstack.log; \
		rm -rf /tmp/clearstack; \
	fi
