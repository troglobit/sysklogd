# Copyright (c) 2018-2021  Joachim Wiberg <troglobit@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the University nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

doc_DATA       = README.md LICENSE ChangeLog.md syslog.conf
EXTRA_DIST     = README.md LICENSE ChangeLog.md syslog.conf
SUBDIRS        = example man src test
TAG            = $(top_srcdir)/.git/refs/tags/$(PACKAGE_VERSION)

if HAVE_SYSTEMD
systemd_DATA   = syslogd.service
endif

#
# Check if tagged in git
#
$(TAG):
	@printf "\e[1m\e[41mPlease create the \"$(PACKAGE_VERSION)\" tag first\e[0m\n"
	@exit 1

#
# Generate .deb package(s)
#
package:
	@debuild -uc -us -B --lintian-opts --profile debian -i -I --show-overrides

#
# Target to run when building a release
#
release: release-hook distcheck
	@for file in $(DIST_ARCHIVES); do		\
		md5sum    $$file > ../$$file.md5;	\
		sha256sum $$file > ../$$file.sha256;	\
	done
	@mv $(DIST_ARCHIVES) ../
	@echo
	@echo "Resulting release files ======================================================================="
	@for file in $(DIST_ARCHIVES); do						\
		printf "%-30s Distribution tarball\n" $$file;				\
		printf "%-30s " $$file.md5;    cat ../$$file.md5    | cut -f1 -d' ';	\
		printf "%-30s " $$file.sha256; cat ../$$file.sha256 | cut -f1 -d' ';	\
	done

# Workaround for systemd unit file duing distcheck
DISTCHECK_CONFIGURE_FLAGS = --with-systemd=$$dc_install_base/$(systemd)
DISTCLEANFILES = lib/.libs/*
