# Clearly fedora package spec file
#
# Contributors:
#    Robin Röper         @robinrpr

# Don't try to compile python3 files with /usr/bin/python.
%{?el7:%global __python %__python3}

# Do not generate a debug package.
%global debug_package %{nil}

# Systemd macros
%{?systemd_requires}
%{?systemd_user_requires}

# Define systemd unit directory if not already defined
%{!?_unitdir: %define _unitdir /usr/lib/systemd/system}

Name:          clearly
Version:       @VERSION@
Release:       @RELEASE@%{?dist}
Summary:       One-stop platform for building and deploying apps at scale.
License:       Proprietary
URL:           https://clearly.run
Source0:       https://clearly.run/releases/downloads/v%{version}/%{name}-%{version}.tar.gz
BuildRequires: gcc rsync bash
BuildRequires: autoconf automake libtool
BuildRequires: libseccomp-devel
BuildRequires: squashfuse-devel
BuildRequires: libmnl-devel
BuildRequires: libnftnl-devel
BuildRequires: libnl3-devel
BuildRequires: libcap-devel
BuildRequires: fuse3-devel
BuildRequires: json-c-devel
BuildRequires: python3-devel
BuildRequires: python3-lark-parser
BuildRequires: python3-requests
BuildRequires: python3-pyyaml
BuildRequires: python3-libsass
BuildRequires: python3-jinja2
BuildRequires: python3-wheel
BuildRequires: python3-Cython
BuildRequires: git

Requires:      squashfuse squashfs-tools
Requires:      libseccomp
Requires:      libmnl
Requires:      libnftnl
Requires:      libnl3
Requires:      libcap
Requires:      fuse3
Requires:      json-c
Requires:      python3
Requires:      python3-lark-parser
Requires:      python3-requests
Requires:      python3-pyyaml
Requires:      python3-libsass
Requires:      python3-jinja2
Requires:      python3-wheel
Requires:      syncthing
Requires:      git

%description
Clearly uses Linux user namespaces to run containers with no privileged
operations or daemons and minimal configuration changes on center resources.
This simple approach avoids most security risks while maintaining access to
the performance and functionality already on offer.

Container images can be built using Docker or anything else that can generate
a standard Linux filesystem tree.

For more information: https://clearly.run

%package        doc
Summary:        Clearly html documentation
License:        Proprietary
BuildArch:      noarch
Obsoletes:      %{name}-doc < %{version}-%{release}
BuildRequires:  python3-sphinx
BuildRequires:  python3-sphinx_rtd_theme
Requires:       python3-sphinx_rtd_theme

%description doc
Html and man page documentation for %{name}.

%package    test
Summary:    Clearly test suite
License:    Proprietary
Requires:   %{name} bats-core
Obsoletes:  %{name}-test < %{version}-%{release}

%description test
Test fixtures for %{name}.

%prep
%setup -q

%if 0%{?el7}
%patch1 -p1
%endif

%build
# Use old inlining behavior, see:
# https://github.com/hpc/charliecloud/issues/735
CFLAGS=${CFLAGS:-%optflags -fgnu89-inline}; export CFLAGS
LDFLAGS="$(python3-config --ldflags --embed)"; export LDFLAGS
%configure --docdir=%{_pkgdocdir} \
           --libdir=%{_prefix}/lib \
%if 0%{?el7}
           --with-sphinx-build=%{_bindir}/sphinx-build-3.6
%else
           --with-sphinx-build=%{_bindir}/sphinx-build
%endif

%install
%make_install

# Create required directories
mkdir -p %{buildroot}/var/tmp/clearly
mkdir -p %{buildroot}/var/lib/clearly

# Create systemd service file
mkdir -p %{buildroot}%{_unitdir}
cat > %{buildroot}%{_unitdir}/clearly.service <<EOF
[Unit]
Description=Clearly Daemon
Documentation=https://clearly.run/docs
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=%{_libexecdir}/%{name}/daemon
Restart=on-failure
RestartSec=5
User=clearly
Group=clearly
StandardOutput=journal
StandardError=journal
SyslogIdentifier=clearly

# Security settings
# ProtectSystem=strict
# ProtectHome=true
# ReadWritePaths=/var/tmp/clearly /var/lib/clearly
# ProtectKernelTunables=true
# ProtectKernelModules=true
# ProtectControlGroups=true
# RestrictRealtime=true
# RestrictSUIDSGID=true
# NoNewPrivileges=true

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

cat > README.EL7 <<EOF
For RHEL7 you must increase the number of available user namespaces to a non-
zero number (note the number below is taken from the default for RHEL8):

  echo user.max_user_namespaces=3171 >/etc/sysctl.d/51-userns.conf
  sysctl -p /etc/sysctl.d/51-userns.conf

Note for versions below RHEL7.6, you will also need to enable user namespaces:

  grubby --args=namespace.unpriv_enable=1 --update-kernel=ALL
  reboot

Please visit https://clearly.run for more information.
EOF

# Remove bundled license and readme (prefer license and doc macros).
%{__rm} -f %{buildroot}%{_pkgdocdir}/LICENSE
%{__rm} -f %{buildroot}%{_pkgdocdir}/README.rst

%pre
getent group clearly >/dev/null 2>&1 || groupadd -r clearly
getent passwd clearly >/dev/null 2>&1 || useradd -r -g clearly -d /var/lib/clearly -s /sbin/nologin clearly

%post
%systemd_post clearly.service

%preun
%systemd_preun clearly.service

%postun
%systemd_postun clearly.service

%files
%license LICENSE
%doc README.rst %{?el7:README.EL7}

%{_bindir}/clearly
%{_unitdir}/clearly.service

%dir %attr(0755,clearly,clearly) /var/tmp/clearly
%dir %attr(0755,clearly,clearly) /var/lib/clearly

%{_libexecdir}/%{name}/check
%{_libexecdir}/%{name}/convert
%{_libexecdir}/%{name}/daemon
%{_libexecdir}/%{name}/fromhost
%{_libexecdir}/%{name}/stop
%{_libexecdir}/%{name}/list
%{_libexecdir}/%{name}/logs
%{_libexecdir}/%{name}/run
%{_libexecdir}/%{name}/use
%{_libexecdir}/%{name}/image
%{_libexecdir}/%{name}/version

%{_mandir}/man1/clearly-check.1*
%{_mandir}/man1/clearly-convert.1*
%{_mandir}/man1/clearly-fromhost.1*
%{_mandir}/man1/clearly-run.1*
%{_mandir}/man1/clearly-image.1*
%{_mandir}/man7/clearly.7*

%{_datadir}/%{name}/templates/
%{_datadir}/%{name}/styles/
%{_datadir}/%{name}/images/

%{_datadir}/%{name}/bucache/
%{_datadir}/%{name}/build/
%{_datadir}/%{name}/fixtures/
%{_datadir}/%{name}/make-auto.d/
%{_datadir}/%{name}/run/
%{_datadir}/%{name}/sotest/
%{_datadir}/%{name}/.dockerignore
%{_datadir}/%{name}/Build.centos7xz
%{_datadir}/%{name}/Build.docker_pull
%{_datadir}/%{name}/Build.missing
%{_datadir}/%{name}/Dockerfile.argenv
%{_datadir}/%{name}/Dockerfile.quick
%{_datadir}/%{name}/approved-trailing-whitespace
%{_datadir}/%{name}/common.bash
%{_datadir}/%{name}/docs-sane
%{_datadir}/%{name}/doctest
%{_datadir}/%{name}/doctest-auto
%{_datadir}/%{name}/force-auto
%{_datadir}/%{name}/force-auto.bats
%{_datadir}/%{name}/make-perms-test
%{_datadir}/%{name}/order-py
%{_datadir}/%{name}/registry-config.yml
%{_datadir}/%{name}/run_first.bats

%{_prefix}/lib/%{name}/_base.sh
%{_prefix}/lib/%{name}/_build_cache.*.so
%{_prefix}/lib/%{name}/_build.*.so
%{_prefix}/lib/%{name}/_clearly.*.so
%{_prefix}/lib/%{name}/_filesystem.*.so
%{_prefix}/lib/%{name}/_force.*.so
%{_prefix}/lib/%{name}/_grammar.*.so
%{_prefix}/lib/%{name}/_http.*.so
%{_prefix}/lib/%{name}/_image.*.so
%{_prefix}/lib/%{name}/_irtree.*.so
%{_prefix}/lib/%{name}/_misc.*.so
%{_prefix}/lib/%{name}/_proxy.*.so
%{_prefix}/lib/%{name}/_pull.*.so
%{_prefix}/lib/%{name}/_push.*.so
%{_prefix}/lib/%{name}/_reference.*.so
%{_prefix}/lib/%{name}/_registry.*.so
%{_prefix}/lib/%{name}/_runtime.*.so
%{_prefix}/lib/%{name}/_tree.*.so
%{_prefix}/lib/%{name}/_zeroconf.*.so
%{?el7:%{_prefix}/lib/%{name}/__pycache__}

%files doc
%license LICENSE
%{_pkgdocdir}/examples
%{_pkgdocdir}/html
%{?el7:%exclude %{_pkgdocdir}/examples/*/__pycache__}

%files test
%{_libexecdir}/%{name}/test
%{_mandir}/man1/clearly-test.1*

%changelog
* Tue Aug 5 2025 <rr@linux.com> - 0.0.0-0
- Add new clearly package.