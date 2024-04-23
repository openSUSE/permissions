# permissions-zypp-plugin

This is a simple zypper commit plugin. Its purpose is to call `permctl
--system` in case a file is installed that is also listed in
`/etc/permissions.local`. This makes it possible to use permissions.local for
applying custom permissions for files that are managed by zypper. Otherwise
the user would need to manually call `chstat` to apply custom permissions
after each zypper update.
