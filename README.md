# SUSE permissions package

This repository contains the source for the SUSE Base:System/permissions
package. This package provides different permission profiles that can be
changed during runtime of a SUSE Linux installation. Permissions covered are
file mode, owner and group as well as capabilities and `setuid` and `setgid`
bits. Therefore the permission profiles govern an important aspect of system
security.

The different profiles allow to select a base security level and also allow to
customize settings. See the accompanying man pages for more detailed
information.

# Known limitations

chkstat doesn't remove permissions that were removed from the profiles. So if
an entry is removed like with https://github.com/openSUSE/permissions/pull/100
there needs to be an update of the package that caries the binary to take
effect. ATM we don't see this as major problem and also don't have a good way
to solve this generally. If you you have an idea submits are very welcome.
