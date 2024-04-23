#!/usr/bin/python3

# Copyright (c) 2018 SUSE LLC
#
# All Right Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program (see the file COPYING); if not, write to the
# Free Software Foundation, Inc.,
# 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA
#
# Authors:
#
# Matthias Gerstner (matthias.gerstner@suse.com)
#
# See https://doc.opensuse.org/projects/libzypp/HEAD/zypp-plugins.html
# for information about the zypper plugin concept.
#
# Basically we communicate to zypper via stdin/stdout, a special protocol is
# exchanged here.
#
# The COMMITBEGIN and COMMITEND hooks allow to inspect which packages are
# installed or removed. We can't look at individual files, though. Therefore
# we have to blindly call permctl at the end of each transaction that adds one
# or more packages.

import sys
import zypp_plugin


def log(*args, **kwargs):
    args = ("permissions-zypp-plugin:",) + args
    kwargs["file"] = sys.stderr
    print(*args, **kwargs)
    # not sure why sometimes log lines do not appear in zypper.log?
    sys.stderr.flush()


def callCheckstat():
    import subprocess
    # since the plugin's stdout is a communication channel towards zypper we
    # need to avoid outputting anything there that's not part of the protocol.
    #
    # instead redirect stdout to stderr, this should end up in the zypper log
    # instead.

    # --set is not required when passing --system, as long as CHECK_PERMISSIONS
    # is not disabled in /etc/sysconfig/security. If it is then the admin
    # hopefuly knows what they are doing on their own.
    res = subprocess.call(
        ['/usr/bin/permctl', '--system'],
        shell=False,
        close_fds=True,
        stdout=sys.stderr
    )

    if res != 0:
        log("permctl failed with exit code", res)


class PermissionsPlugin(zypp_plugin.Plugin):

    def __init__(self):
        super().__init__()
        # here we keep sets of all files we parsed from /etc/permissions.*
        # files
        #self.m_permissions = {}
        # here we will keep all matches from m_permissions that are actually
        # part of this transaction
        #self.m_matches = set()
        # This is actually not needed currently. In the first place I wanted
        # to only call permctl when a file was added or replaced that is
        # listed in permissions.local. Since this information is not easily
        # available from zypper we always call permctl instead.
        #self._parsePermissions("/etc/permissions.local", "local")

    def _parsePermissions(self, path, label):
        self.m_permissions[label] = set()
        permset = self.m_permissions[label]

        try:
            with open(path, 'r') as fd:

                for line in fd.readlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split()
                    if len(parts) != 3:
                        log("malformed line encountered in", path + ":", line)
                        continue
                    permset.add(parts[0])
        except Exception:
            log("Failed to parse", path)

    def COMMITEND(self, headers, body):
        log("COMMITEND")

        have_new_pkgs = False

        import json
        data = json.loads(body)

        for step in data["TransactionStepList"]:
            log("Processing", str(step))

            _type = step.get("type", None)
            # we're only looking for new packages being installed (this also
            # covers updates).
            if not _type or _type != "+":
                continue

            stage = step.get("stage", None)
            # we're only looking for successful install operations
            if not stage or stage != "ok":
                continue

            have_new_pkgs = True
            break

        if have_new_pkgs:
            callCheckstat()

        self.ack()

    def PLUGINBEGIN(self, headers, body):
        self.ack()

    def PLUGINEND(self, headers, body):
        self.ack()


plugin = PermissionsPlugin()
plugin.main()
