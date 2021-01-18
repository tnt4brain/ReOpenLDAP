%global systemctl_bin /usr/bin/systemctl
%define packaging_dir contrib/packaging/CentOS/7
%global owner_ssh %(git config --get remote.origin.url | sed -n -e 's!^git@github.com:\\(.*\\)\\/.*$!\\1!p')
%global owner_https %(git config --get remote.origin.url | sed -n -e 's!^https://github.com/\\(.*\\)\\/.*$!\\1!p')
%global owner %{owner_ssh}%{owner_https}
%global commit0 %(git log -n 1 --pretty=format:"%H")
%global gittag0 %(git describe --abbrev=0 --tags)
%global ver %(c=%{gittag0}; echo ${c:1})
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7})
%define namel %(echo "%{name}" | tr '[:upper:]' '[:lower:]')

Name:		ReOpenLDAP
Version:	%{ver}
Release:	%{shortcommit0}%{?dist}
Summary:	The fork of OpenLDAP with a few new features (mostly for highload and multi-master clustering), additional bug fixing and code quality improvement.

Group:		System Environment/Daemons
License:	AGPLv3
URL:		https://github.com/%{owner}/ReOpenLDAP
Source0:	https://github.com/%{owner}/%{name}/archive/%{commit0}.tar.gz

BuildRequires:	cyrus-sasl-devel, krb5-devel, tcp_wrappers-devel, unixODBC-devel libuuid-devel elfutils-libelf-devel
BuildRequires:	glibc-devel, libtool, libtool-ltdl-devel, groff, perl, perl-devel, perl(ExtUtils::Embed)
BuildRequires:	openssl-devel, nss-devel
BuildRequires:	bc git
Requires:	rpm, coreutils, nss-tools, libdb-utils

%description
The fork of OpenLDAP with a few new features (mostly for highload and multi-master clustering), additional bug fixing and code quality improvement.

# Disabled due to request: https://github.com/leo-yuriev/ReOpenLDAP/pull/145#issuecomment-358626660
#%package devel
#Summary: LDAP development libraries and header files
#Group: Development/Libraries
#Requires: %{name}%{?_isa} = %{version}-%{release}, cyrus-sasl-devel%{?_isa}
#
#%description devel
#The openldap-devel package includes the development libraries and
#header files needed for compiling applications that use LDAP
#(Lightweight Directory Access Protocol) internals. LDAP is a set of
#protocols for enabling directory services over the Internet. Install
#this package only if you plan to develop or will need to compile
#customized LDAP clients.

%package servers
Summary: LDAP server
License: AGPLv3
Requires: %{name}%{?_isa} = %{version}-%{release}, libdb-utils
Requires(pre): shadow-utils
Requires(post): systemd, systemd-sysv, chkconfig
Requires(preun): systemd
Requires(postun): systemd
BuildRequires: libdb-devel
BuildRequires: systemd-units
BuildRequires: cracklib-devel
Group: System Environment/Daemons
# migrationtools (slapadd functionality):
Provides: ldif2ldbm

%description servers
OpenLDAP is an open-source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools. LDAP is a set of
protocols for accessing directory services (usually phone book style
information, but other information is possible) over the Internet,
similar to the way DNS (Domain Name System) information is propagated
over the Internet. This package contains the slapd server and related files.

%package clients
Summary: LDAP client utilities
Requires: %{name}%{?_isa} = %{version}-%{release}
Group: Applications/Internet

%description clients
OpenLDAP is an open-source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools. LDAP is a set of
protocols for accessing directory services (usually phone book style
information, but other information is possible) over the Internet,
similar to the way DNS (Domain Name System) information is propagated
over the Internet. The openldap-clients package contains the client
programs needed for accessing and modifying OpenLDAP directories.

%prep
%autosetup -n %{name}-%{commit0}
#setup -q -n %{name}-%{commit0}
# alternative include paths for Mozilla NSS
ln -s %{_includedir}/nss3 include/nss
ln -s %{_includedir}/nspr4 include/nspr

%build
%ifarch s390 s390x
  export CFLAGS="-fPIE"
%else
  export CFLAGS="-fpie"
%endif

# avoid stray dependencies (linker flag --as-needed)
# enable experimental support for LDAP over UDP (LDAP_CONNECTIONLESS)
# export CFLAGS="${CFLAGS} %{optflags} -DLDAP_CONNECTIONLESS"

./bootstrap.sh --dont-cleanup
export LIBTOOL_SUPPRESS_DEFAULT=no
export CFLAGS="${CFLAGS} %{optflags} -Ofast %{?_with_tls} -Wl,--as-needed"
export LDFLAGS="${LDFLAGS} -pie"
%configure \
   --sysconfdir=%{_sysconfdir}/%{namel} \
    \
   --enable-syslog \
   --enable-proctitle \
   --enable-ipv6 \
   --enable-local \
   \
   --enable-slapd \
   --enable-dynacl \
   --disable-aci \
   --enable-cleartext \
   --enable-crypt \
   --enable-lmpasswd=no \
   --enable-spasswd \
   --enable-modules \
   --enable-rewrite \
   --enable-rlookups \
   --enable-slapi \
   --disable-slp \
   --enable-wrappers \
   \
   --enable-backends=mod \
   --enable-mdb=yes \
   --disable-hdb \
   --disable-bdb \
   --disable-dnssrv \
   --enable-ldap=mod \
   --enable-meta=mod \
   --enable-monitor=yes \
   --disable-ndb \
   --enable-null=mod \
   --disable-passwd \
   --disable-perl \
   --disable-relay \
   --disable-shell \
   --disable-sock \
   --disable-sql \
   --disable-wt \
   \
   --enable-overlays=mod \
   --enable-contrib=yes \
   \
   --disable-static \
   --enable-shared \
   \
   --with-cyrus-sasl \
   --with-gssapi \
   --without-fetch \
   --with-pic \
   --with-gnu-ld \
   --with-tls=moznss \
   \
   --prefix=%{_prefix} \
   --libexecdir=%{_libdir}


make %{?_smp_mflags}


%install
mkdir -p %{buildroot}%{_libdir}/
make install DESTDIR=%{buildroot} STRIP=""

# setup directories for TLS certificates
%{__mkdir} -p %{buildroot}%{_sysconfdir}/%{namel}/certs

# setup data and runtime directories
%{__mkdir} -p %{buildroot}%{_sharedstatedir}
%{__mkdir} -p %{buildroot}%{_localstatedir}
%{__install} -m 0700 -d %{buildroot}%{_sharedstatedir}/ldap
%{__install} -m 0755 -d %{buildroot}%{_localstatedir}/run/%{namel}

# setup autocreation of runtime directories on tmpfs
%{__mkdir} -p %{buildroot}%{_tmpfilesdir}/
%{__install} -m 0644 %{packaging_dir}/slapd.tmpfiles %{buildroot}%{_tmpfilesdir}/slapd.conf

# install default ldap.conf (customized)
%{__rm} -f %{buildroot}%{_sysconfdir}/%{namel}/ldap.conf
%{__install} -m 0644 %{packaging_dir}/ldap.conf %{buildroot}%{_sysconfdir}/%{namel}/ldap.conf

## setup maintainance scripts
%{__mkdir} -p %{buildroot}%{_libexecdir}
%{__install} -m 0755 -d %{buildroot}%{_libexecdir}/%{namel}
%{__install} -m 0644 %{packaging_dir}/libexec-functions %{buildroot}%{_libexecdir}/%{namel}/functions
%{__install} -m 0755 %{packaging_dir}/libexec-check-config.sh %{buildroot}%{_libexecdir}/%{namel}/check-config.sh
%{__install} -m 0755 %{packaging_dir}/libexec-upgrade-db.sh %{buildroot}%{_libexecdir}/%{namel}/upgrade-db.sh

# remove build root from config files and manual pages
perl -pi -e "s|%{buildroot}||g" %{buildroot}%{_sysconfdir}/%{namel}/*.conf
perl -pi -e "s|%{buildroot}||g" %{buildroot}%{_mandir}/*/*.*

# install a service definition for the servers
%{__mkdir} -p %{buildroot}%{_unitdir}
%{__install} -m 0644 %{packaging_dir}/slapd.service %{buildroot}%{_unitdir}/slapd.service
%{__sed} -i 's#/usr/libexec/#%{_libexecdir}/#g' %{buildroot}%{_unitdir}/slapd.service

# install sysconfig/slapd
%{__mkdir} -p %{buildroot}%{_sysconfdir}/sysconfig
%{__install} -m 644 %{packaging_dir}/slapd.sysconfig %{buildroot}%{_sysconfdir}/sysconfig/slapd

# ldapadd point to buildroot.
%{__rm} -f %{buildroot}%{_bindir}/ldapadd 
pushd %{buildroot}%{_bindir}
ln -s ldapmodify ldapadd
popd

# tweak permissions on the libraries to make sure they're correct
chmod 0755 %{buildroot}%{_libdir}/%{namel}/lib*.so*
chmod 0644 %{buildroot}%{_libdir}/%{namel}/lib*.*a

# slapd.conf(5) is obsoleted since 2.3, see slapd-config(5)
# new configuration will be generated in %%post
%{__mkdir} -p %{buildroot}%{_datadir}
%{__install} -m 0755 -d %{buildroot}%{_datadir}/%{namel}-servers
%{__install} -m 0644 %{packaging_dir}/slapd.ldif %{buildroot}%{_datadir}/%{namel}-servers/slapd.ldif
%{__install} -m 0644 %{packaging_dir}/DB_CONFIG.example %{buildroot}%{_datadir}/%{namel}-servers/DB_CONFIG.example
%{__install} -m 0700 -d %{buildroot}%{_sysconfdir}/%{namel}/slapd.d
%{__rm} -f %{buildroot}%{_sysconfdir}/%{namel}/slapd.conf
%{__rm} -f %{buildroot}%{_sysconfdir}/%{namel}/slapd.ldif

# move doc files out of _sysconfdir
mv %{buildroot}%{_sysconfdir}/%{namel}/schema/README README.schema
#mv %{buildroot}%{_sysconfdir}/schema %{buildroot}%{_sysconfdir}/%{namel}

# remove files which we don't want packaged
%{__rm} -f %{buildroot}%{_libdir}/%{namel}/*.la
%{__rm} -f %{buildroot}%{_mandir}/man5/ldif.5*
%{__rm} -f %{buildroot}%{_mandir}/man5/ldap.conf.5*

# Now these are being removed due to request: https://github.com/leo-yuriev/ReOpenLDAP/pull/145#issuecomment-358626660
# devel
%{__rm} -f %{buildroot}%{_includedir}/%{namel}/*
%{__rm} -f %{buildroot}%{_mandir}/man3/*


%clean
%{__rm} -rf %{buildroot}

%post
/sbin/ldconfig

%postun -p /sbin/ldconfig

%pre servers
# create ldap user and group
getent group ldap &>/dev/null || groupadd -r -g 55 ldap
getent passwd ldap &>/dev/null || \
   useradd -r -g ldap -u 55 -d %{_sharedstatedir}/ldap -s /sbin/nologin -c "OpenLDAP server" ldap
if [ $1 -eq 2 ]; then
   # package upgrade
   old_version=$(rpm -q --qf=%%{version} %{namel}-servers)
   new_version=%{version}
   if [ "$old_version" != "$new_version" ]; then
       touch %{_sharedstatedir}/ldap/rpm_upgrade_reopenldap &>/dev/null
   fi
fi
exit 0

%post servers

/sbin/ldconfig -n %{_libdir}/%{namel}
%systemd_post slapd.service

# generate configuration if necessary
if [[ ! -f %{_sysconfdir}/%{namel}/slapd.d/cn=config.ldif && \
      ! -f %{_sysconfdir}/%{namel}/slapd.conf
   ]]; then
      # if there is no configuration available, generate one from the defaults
      %{__mkdir} -p %{_sysconfdir}/%{namel}/slapd.d/ &>/dev/null || :
      /usr/sbin/slapadd -F %{_sysconfdir}/%{namel}/slapd.d/ -n0 -l %{_datadir}/%{namel}-servers/slapd.ldif
      %{__chown} -R ldap:ldap %{_sysconfdir}/%{namel}/slapd.d/
      %{systemctl_bin} try-restart slapd.service &>/dev/null
fi
start_slapd=0

# upgrade the database
if [ -f %{_sharedstatedir}/ldap/rpm_upgrade_reopenldap ]; then
   if %{systemctl_bin} --quiet is-active slapd.service; then
       %{systemctl_bin} stop slapd.service
       start_slapd=1
   fi

   %{_libexecdir}/%{namel}/upgrade-db.sh &>/dev/null
   %{__rm} -f %{_sharedstatedir}/ldap/rpm_upgrade_reopenldap
fi

# restart after upgrade
if [ $1 -ge 1 ]; then
   if [ $start_slapd -eq 1 ]; then
       %{systemctl_bin} start slapd.service &>/dev/null || :
   else
       %{systemctl_bin} condrestart slapd.service &>/dev/null || :
   fi
fi
exit 0

%preun servers
%systemd_preun slapd.service

%postun servers
/sbin/ldconfig
%systemd_postun_with_restart slapd.service

%triggerin servers -- libdb

# libdb upgrade (setup for %%triggerun)
if [ $2 -eq 2 ]; then
   # we are interested in minor version changes (both versions of libdb are installed at this moment)
   if [ "$(rpm -q --qf="%%{version}\n" libdb | sed 's/\.[0-9]*$//' | sort -u | wc -l)" != "1" ]; then
       touch %{_sharedstatedir}/ldap/rpm_upgrade_libdb
   else
       %{__rm} -f %{_sharedstatedir}/ldap/rpm_upgrade_libdb
   fi
fi
exit 0
%triggerun servers -- libdb

# libdb upgrade (finish %%triggerin)
if [ -f %{_sharedstatedir}/ldap/rpm_upgrade_libdb ]; then
   if %{systemctl_bin} --quiet is-active slapd.service; then
       %{systemctl_bin} stop slapd.service
       start=1
   else
       start=0
   fi
   %{_libexecdir}/%{namel}/upgrade-db.sh &>/dev/null
   %{__rm} -f %{_sharedstatedir}/ldap/rpm_upgrade_libdb
   [ $start -eq 1 ] && %{systemctl_bin} start slapd.service &>/dev/null
fi
exit 0


%files
%doc ANNOUNCEMENT.OpenLDAP
%doc CHANGES.OpenLDAP
%doc ChangeLog
%doc COPYRIGHT
%doc LICENSE
%doc README
%doc README.md
%doc README.OpenLDAP
%dir %{_sysconfdir}/%{namel}
%dir %{_sysconfdir}/%{namel}/certs
%config(noreplace) %{_sysconfdir}/%{namel}/ldap.conf
%{_libdir}/%{namel}/libreldap*.so*
%{_libdir}/%{namel}/libreslapi*.so*
#%{_mandir}/man5/ldif.5*
#%{_mandir}/man5/ldap.conf.5*

%files servers
%doc contrib/slapd-modules/smbk5pwd/README
%doc README.schema
%config(noreplace) %dir %attr(0750,ldap,ldap) %{_sysconfdir}/%{namel}/slapd.d
%config(noreplace) %{_sysconfdir}/%{namel}/schema
%config(noreplace) %{_sysconfdir}/sysconfig/slapd
%config(noreplace) %{_tmpfilesdir}/slapd.conf
%config(noreplace) %{_sysconfdir}/%{namel}/check_password.conf
%dir %attr(0700,ldap,ldap) %{_sharedstatedir}/ldap
%dir %attr(-,ldap,ldap) %{_localstatedir}/run/%{namel}
%{_unitdir}/slapd.service
%{_bindir}/mdbx_*
%{_datadir}/%{namel}-servers/
%{_libdir}/%{namel}/*.so*
%dir %{_libexecdir}/%{namel}/
%{_libexecdir}/%{namel}/functions
%{_libexecdir}/%{namel}/check-config.sh
%{_libexecdir}/%{namel}/upgrade-db.sh
%{_sbindir}/slap*
%{_mandir}/man5/slap*
%{_mandir}/man8/*
%{_mandir}/ru/man5/*
%{_mandir}/ru/man8/*
# obsolete configuration
%ghost %config(noreplace,missingok) %attr(0640,ldap,ldap) %{_sysconfdir}/%{namel}/slapd.conf
%ghost %config(noreplace,missingok) %attr(0640,ldap,ldap) %{_sysconfdir}/%{namel}/slapd.conf.bak

%files clients
%{_bindir}/ldap*
%{_mandir}/man1/*
%{_mandir}/ru/man1/*
%ghost %config(noreplace,missingok) %attr(0640,ldap,ldap) %{_sysconfdir}/%{namel}/slapd.conf

# https://github.com/leo-yuriev/ReOpenLDAP/pull/145#issuecomment-358626660
#%files devel
#%{_includedir}/%{namel}/*
#%{_mandir}/man3/*


%changelog
* Fri May 19 2017 Sergey Pechenko <s.pechenko@uiscom.ru> - 1.1.5-641ffb2.1
- Initial bootstrapping ReOpenLDAP RPM specfile release. Based on contribution by Ivan Viktorov 
(https://github.com/ReOpen/ReOpenLDAP/issues/33#issuecomment-249861076)


#    --disable-debug --enable-syslog --enable-overlays=mod  --enable-dynacl \
#    --enable-aci --enable-crypt --enable-lmpasswd --enable-spasswd --enable-slapi --enable-rlookups \
#    --enable-wrappers --enable-backends=mod --disable-bdb --disable-hdb --disable-ndb --disable-wt \
#    --with-pic \
#   --with-gnu-ld \
#   --disable-slp \
#   --sysconfdir=%{_sysconfdir}/%{namel} \
#   --libexecdir=%{_libdir} %{?_enable_modules} \
#   --disable-passwd \
#   --disable-perl \
#   --disable-relay \
#   --disable-shell \
#   --disable-sock \
#   --disable-sql \
#   --disable-static \
#   --enable-shared \
#   --enable-mdb=yes \
#   --enable-dnssrv \
#   --enable-rewrite \
#   --enable-slapd \
#   --with-cyrus-sasl \
#   --with-gssapi \
#   --with-tls=moznss \
#   --disable-aci \
#
#
# --enable-maintainer-mode
# --enable-hipagut=always
# --enable-check=always
# --disable-syslog
# --enable-slp
# --disable-modules
# --enable-overlays
# disabled SLP
# enabled syslog
# changed sysconfdir
# changed libexecdir
# disabled debug
# disabled check
# disabled hipagut
# switched overlays to mod
# moved TLS to conditional
# disabled CI-related features
# switched backends to mod
#
