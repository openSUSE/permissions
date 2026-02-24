# SUSE permissions Package

This repository contains the source for the SUSE `Base:System/permissions`
package. This package provides the `permctl` (formerly `chkstat`) utility and
a set of different file permission profiles. These profiles can be changed by
administrators of SUSE Linux distributions. The profiles consist of a list of
privileged file paths whose permissions are managed by the `permctl` program.
The file permissions that can be configured include:

- the octal file mode, including special mode bits like `setuid`, `setgid` and
  sticky bits
- file owner and group
- Linux capabilities
- ACL (access control list) entries

Therefore the permission profiles govern an important aspect of system
security on SUSE distributions. The different profiles allow an administrator
to select a base security level and to customize settings. Refer to the
accompanying man pages for more detailed information.

The permissions package is a base package on SUSE Linux distributions and
`permctl` is also invoked regularly as part of RPM package installations to
apply special privileges to files.

# Building

This project uses Meson for building. A straightforward build is done like
this:

    # create a build tree in the build sub-directory
    meson setup build

    cd build
    # building of the permctl program
    meson compile

    # optional installation
    meson install

# Known Limitations

`permctl` doesn't recognize when formerly managed files are removed from the
profiles. So if an entry is removed like in
<https://github.com/openSUSE/permissions/pull/100>, there needs to be an
update of the package that carries the binary, to take effect. At the moment
we don't see this as major problem and also don't have a good way to solve
this generally. If you have an idea, pull requests are very welcome.

Generally `permctl` is not considered a "monitoring" tool in the sense that it
detects malicious or haphazard changes to file permissions. Using it to
restore permissions to known good values is not recommended, since bad
permissions might already have put the system at risk. Also the root cause for
bad file permission settings can obscured this way, maybe hiding a deeper
rooting problem that should be fixed.

# Race Conditions upon RPM Installation

When an RPM is installed or updated then the permissions of files managed by
`permctl` are initially controlled by the metadata stored in the RPM. Only a
short while after, when the RPM's `%post` scriptlet runs, will `permctl` be
invoked to apply the settings based on runtime configuration. This can mean
that certain privileges are given out to programs for a short time before
`permctl` adjusts them to the desired configuration settings again.

It is difficult to fix this race condition without hooking directly into RPM,
which we decided against until now, to avoid a lot of added complexity.

We don't expect programs carrying e.g. a setuid-root bit for a short time to
easily allow a local root exploit or similar attack vectors. Software with
problematic security is not allowed into SUSE distributions in the first
place. The permissions package intends to establish a security baseline
for daily operation e.g. to avoid users running programs offering unnecessary
extra attack surface. Thus we consider this RPM installation time race
condition an acceptable risk.
