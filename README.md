# SUSE permissions Package

This repository contains the source for the SUSE Base:System/permissions
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
to select a base security level and also allow to customize settings. See the
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
