# vim: ts=4 et sw=4 sts=4 :

import argparse
import errno
import glob
import grp
import io
import os
import pwd
import shutil
import stat
import subprocess
import sys
import time
import traceback
from enum import Enum

# the basic test concept is as follows:
#
# running these tests with real root privileges carries the danger of breaking
# the host system and is generally complex to achieve when user privileges
# need to be switched for testing, for example.
#
# permctl on its own supports some switches like `--root` to operate on a
# specific file system subtree. However, this also triggers other, potentially
# uncommon logic in permctl, while we're more interested in the major use
# cases.
#
# a good compromise is to use user and mount namespaces:
#
# - real root privileges are not required
# - damaging the system is less likely, only user data can suffer
# - typical code paths of permctl can largely be kept as-is
# - even some privileged operations like setting setuid-root bits or
# capabilities can be emulated
#
# the downside is that we need to construct a fake root file system from what
# we have on the host. This is what the PermctlRegtest class is caring for.
# Another downside is that we cannot chown() or chgrp() to any other group
# than root (our fake root in the user namespace). Actually: It is possible
# when sub-uids and sub-gids are correctly configured in the host system.
# This, sadly, isn't a given, therefore I'm adding some optional tests that
# only run if the support is available.
#
# for being able to inspect what is going on within the fake root if things go
# bad you can use the `--enter-fakeroot` or `--on-error-enter-shell` options.
#
# another positive thing is that we're basically operating on our own tmpfs
# within the user-/mount namespace, we don't even need to clean a tmp
# directory up, once the test terminates the mount namespace along with its
# tmpfs mounts will be destroyed.


class ColorPrinter:
    """Poor peoples' ANSI color escape sequences handling. I want to avoid
    third-party dependencies as much as possible, but some basic color
    output is really helpful when running a larger test suite. Therefore
    this class handles only the very basics in color output we need."""

    def __init__(self):

        self.m_use_colors = os.isatty(sys.stdout.fileno())
        if not self.m_use_colors and "FORCE_COLOR" in os.environ:
            # allow override via environment, for example when run
            # in Jenkins with ANSI color plugin support.
            self.m_use_colors = True

    def flush(self):
        sys.stdout.flush()

    def reset(self):
        if self.m_use_colors:
            print(u"\u001b[0m", end='')

    def setRed(self):
        if self.m_use_colors:
            print(u"\u001b[31m", end='')

    def setYellow(self):
        if self.m_use_colors:
            print(u"\u001b[33m", end='')

    def setGreen(self):
        if self.m_use_colors:
            print(u"\u001b[32m", end='')

    def setCyan(self):
        if self.m_use_colors:
            print(u"\u001b[36m", end='')

    def setMagenta(self):
        if self.m_use_colors:
            print(u"\u001b[35m", end='')


color_printer = ColorPrinter()


class ConfigLocation(Enum):
    ETC = 1,
    USR = 2


PER_PACKAGE_CONFIG_DIRS = {
    ConfigLocation.ETC: "/etc/permissions.d/",
    ConfigLocation.USR: "/usr/share/permissions/permissions.d/"
}


class PermctlRegtest:
    """The main test execution class. It sets up the fake root using
    namespaces and runs each individual test case."""

    # a couple of environment variable used to communicate namespace setup
    # details to child instances of ourselves
    REEXEC_ENV_MARKER = "PERMCTL_REGTEST_REEXEC"
    WAIT_FOR_SUBID_MAP_ENV_MARKER = "PERMCTL_WAIT_FOR_SUBID_MAP"
    SUB_UID_RANGE_ENV_VAR = "PERMCTL_SUB_UID_RANGE"
    SUB_GID_RANGE_ENV_VAR = "PERMCTL_SUB_GID_RANGE"

    def __init__(self):

        self.setupArgParser()

        perm_root = os.path.realpath(__file__).split(os.path.sep)[:-2]
        self.m_permissions_repo = os.path.sep.join(perm_root)

        if not self.m_args.buildtree.startswith(os.path.sep):
            self.m_args.buildtree = os.path.sep.join([self.m_permissions_repo, self.m_args.buildtree])

        self.m_permctl_orig = os.path.sep.join([self.m_args.buildtree, "permctl"])

    def printDebug(self, *args, **kwargs):

        if not self.m_args.debug:
            return

        color_printer.setCyan()
        print("DEBUG:", *args, **kwargs)
        color_printer.reset()

    def setupArgParser(self):

        self.m_parser = argparse.ArgumentParser(
            description="Regression test suite for the permctl program"
        )

        self.m_parser.add_argument(
            "--enter-fakeroot", action='store_true',
            help="Instead of running tests, just enter a shell in the fake test root file system"
        )

        self.m_parser.add_argument(
            "--on-error-enter-shell", action='store_true',
            help="If any test fails or throws an exception then before continuing execution a shell will be entered in the fake root."
        )

        self.m_parser.add_argument(
            "--after-test-enter-shell", action='store_true',
            help="Enter the fake root after the test(s) finished executing."
        )

        self.m_parser.add_argument(
            "--list-tests", action='store_true',
            help="Just list the available tests"
        )

        self.m_parser.add_argument(
            "--test", type=str,
            help="Instead of all tests tun only the given test. For names see --list-tests."
        )

        self.m_parser.add_argument(
            "--debug", action='store_true',
            help="Add some debugging output regarding the test seuite itself."
        )

        self.m_parser.add_argument(
            "--build-debug", action='store_true',
            help="Build a more debug friendly version of permctl to make tracking down bugs in `gdb` easier"
        )

        self.m_parser.add_argument('buildtree', default='build-regtest',
           help="The meson build tree to use.", nargs='?')

        self.m_parser.add_argument(
            "--skip-build", action='store_true',
            help="By default the regtest tries to (re)build the permctl binary. If this switch is set then whichever binary is currently found will be used."
        )

        self.m_parser.add_argument(
            "--skip-proc", action='store_true',
            help="Run permctl without a mounted /proc to test these special permctl code paths that deal with that condition. This is only really useful in old code streams that attempt to mount their own /proc for backwards compatibility."
        )

        self.m_args = self.m_parser.parse_args()

    def ensureForkedNamespace(self):
        """This function reexecutes the current script in a forked user and
        mount namespace for faking a root file system and root context for
        testing permctl."""

        unshare = shutil.which("unshare")

        if not unshare:
            print("Couldn't find the 'unshare' program", file=sys.stderr)
            sys.exit(1)

        unshare_cmdline = [unshare, "-p", "-f", "-m", "-U"]

        self.m_sub_id_supported = self.checkSubIDSupport()

        if self.m_sub_id_supported:
            # this tells the child process to wait for us to map
            # the sub*ids before actually doing anything
            os.environ[self.WAIT_FOR_SUBID_MAP_ENV_MARKER] = "1"
            # also forward the sub uids and gids to use, to avoid
            # the child having to parse stuff again
            os.environ[self.SUB_UID_RANGE_ENV_VAR] = "{}:{}".format(*self.m_sub_uid_range)
            os.environ[self.SUB_GID_RANGE_ENV_VAR] = "{}:{}".format(*self.m_sub_gid_range)
        else:
            # without sub-*id support let unshare map the root
            # user only
            unshare_cmdline.append("-r")
            color_printer.setYellow()
            print("no user namespace sub-uid/sub-gid support detected:", self.m_sub_id_error)
            print("won't be able to run certain tests reyling on chown()/chgrp()")
            color_printer.reset()

        os.environ[self.REEXEC_ENV_MARKER] = "1"
        unshare_cmdline.extend(sys.argv)
        self.printDebug("Running child instance:", ' '.join(unshare_cmdline))

        # make sure any terminal codes are written out before the
        # child starts, to avoid child output in wrong color and
        # similar
        color_printer.flush()

        proc = subprocess.Popen(
            unshare_cmdline,
            close_fds=True,
            shell=False
        )

        if self.m_sub_id_supported:
            try:
                self.setupChildSubIdMapping(proc)
            except Exception as e:
                color_printer.setRed()
                print("Failed to setup sub-*id mapping:")
                self.printException(e)
                color_printer.reset()
                print("Killing child")
                proc.kill()

        res = proc.wait()
        sys.exit(res)

    def haveSubIdSupport(self):
        return self.m_sub_id_supported

    def haveCapSupport(self):
        return self.m_have_caps_support

    def checkSubIDSupport(self):
        """Checks whether it's basically possible to employ
        newuidmap/newgidmap to establish a number of sub-*id for the
        current user.

        Returns a boolean indicating whether support is available.
        Also sets a couple of instance member variables containing the
        sub-id information on success.
        """
        subuid = "/etc/subuid"
        subgid = "/etc/subgid"

        for f in (subuid, subgid):
            if not os.path.exists(f):
                self.m_sub_id_error = "{} is not existing".format(f)
                return False

        # the setuid-root helpers for sub-*id mappings are also
        # required
        self.m_newuidmap = shutil.which("newuidmap")
        self.m_newgidmap = shutil.which("newgidmap")

        if not self.m_newuidmap or not self.m_newgidmap:
            self.m_sub_id_error = "{} or {} command(s) not existing".format(self.m_newuidmap, self.m_newgidmap)
            return False

        # finally we need an entry for the current user and group in
        # both files
        our_uid = os.getuid()
        our_user = pwd.getpwuid(our_uid).pw_name

        sub_uid_ranges = self.collectSubIDRanges(subuid, our_uid, our_user)
        sub_gid_ranges = self.collectSubIDRanges(subgid, our_uid, our_user)

        if not sub_uid_ranges or not sub_gid_ranges:
            self.m_sub_id_error = "no sub-uid and/or sub-gid range configured for uid {} / username {}".format(our_uid, our_user)
            return False
        elif len(sub_uid_ranges) > 1 or len(sub_gid_ranges) > 1:
            self.m_sub_id_error = "more than one sub-uid/sub-gid entry for this account. Can't decide which one to use. Found uid ranges: {}, gid ranges: {}".format(sub_uid_ranges, sub_gid_ranges)
            return False

        self.m_sub_uid_range = sub_uid_ranges[0]
        self.m_sub_gid_range = sub_gid_ranges[0]

        return True

    def collectSubIDRanges(self, config, number, name):

        ret = []

        with open(config, 'r') as config_fd:
            for line in config_fd.readlines():
                parts = line.strip().split(':')
                if len(parts) != 3:
                    # bad line?
                    continue

                who, start_id, amount = parts

                if who != number and who != name:
                    continue

                ret.append((start_id, amount))

        return ret

    def setupChildSubIdMapping(self, child):
        """For sub*id support this function applies the sub*id uid and
        gid mapping to the already running child process that
        currently lives in a usernamespace without any users
        mapped."""

        for helper, main_id, sub_ids in (
            (self.m_newuidmap, os.getuid(), self.m_sub_uid_range),
            (self.m_newgidmap, os.getgid(), self.m_sub_gid_range)
        ):
            helper_cmdline = [
                helper, str(child.pid),
                # this line maps the current user/group to the
                # root user/group.  this setting is implicitly
                # allowed by new(u/g)idmap, without being
                # configured in /etc/sub(u/g)id.
                "0", str(main_id), "1",
                # this maps the sub-ids starting from USER_NS
                # (u/g) id 1 within the namespace. So all the
                # system users and maybe more will be mapped.
                "1", sub_ids[0], sub_ids[1]
            ]

            self.printDebug("Running sub-uid helper:", ' '.join(helper_cmdline))

            subprocess.check_call(
                helper_cmdline,
                close_fds=True,
                shell=False
            )

    def handleNamespaceChildContext(self):
        """This function deals with any re-executed child instance of
        the test program. It handles details regarding sub*id mapping
        in the user namespace."""

        if self.WAIT_FOR_SUBID_MAP_ENV_MARKER in os.environ:
            # we already re-executed once, but need to wait
            # for the user sub*id mapping by the parent
            self.waitForSubIdMapping()
            # even more complexity here: the capabilities will not
            # be adjusted by the kernel right when uid_map is
            # written, but we have to once again execve() to
            # obtain the capabilities.
            #
            # thus once more re-execute ourselves. To avoid having
            # a long process tree employ os.execve directly here,
            # instead of subprocess
            #
            # clean up the environment to prevent another
            # waitForSubIdMapping()
            self.printDebug("Re-executing child to gain capabilities")
            color_printer.flush()
            os.environ.pop(self.WAIT_FOR_SUBID_MAP_ENV_MARKER)
            os.execve(sys.argv[0], sys.argv, os.environ)
            raise Exception("should never happen")

        # in this case we either have no sub-*id support at all, or
        # have re-executed twice, now owning capabilities and a range
        # of sub-*ids to play with

        try:
            uid_range = os.environ.pop(self.SUB_UID_RANGE_ENV_VAR)
        except KeyError:
            uid_range = None

        try:
            gid_range = os.environ.pop(self.SUB_GID_RANGE_ENV_VAR)
        except KeyError:
            gid_range = None

        self.m_sub_id_supported = uid_range is not None and gid_range is not None

        if not self.m_sub_id_supported:
            self.printDebug("no sub*-id support detected")
            return

        self.m_sub_uid_range = uid_range.split(':')
        self.m_sub_gid_range = gid_range.split(':')
        self.printDebug("Detected sub*-id support, uid range = {}, gid range = {}".format(uid_range, gid_range))

    def waitForSubIdMapping(self):
        """In the context of the child process already running within
        a user namespace, this function waits for the parent to apply
        an actual uid and gid mapping so we can continue executing
        with user namespace privileges."""

        self.printDebug("Child is waiting for sub-id mapping")
        sys.stdout.flush()

        # get*id() actually suddenly changes once the uid/gid map is
        # written by the parent. So lets just poll for that.
        #
        # an alternative would be some kind of IPC (e.g. signals) from
        # the parent. However, since Python is quite fat, it seems
        # like before the new child process hits this spot, the *id
        # mapping is already there anyways.
        while os.getuid() != 0 or os.getgid() != 0:
            time.sleep(0.1)

    def mountTmpFS(self, path):
        subprocess.check_call(
            ["mount", "-t", "tmpfs", "none", path],
            close_fds=True,
            shell=False
        )

    def mountProc(self, path):
        subprocess.check_call(
            ["mount", "-t", "proc", "none", path],
            close_fds=True,
            shell=False
        )

    def bindMount(self, src, dst, recursive=True, read_only=False):
        bind_mode = "--rbind" if recursive else "--bind"
        options = "ro" if read_only else "rw"

        # it would be good to mount most of the directories in the
        # mount namespace read-only, but it turns out to be
        # surprisingly difficult to achieve.
        #
        # a `mount --rbind -oro` fails with EPERM, because this
        # operates on the original bind mount, for which we don't have
        # permissions and also don't want to fiddle with.
        #
        # a `mount --bind /src /tgt` followed by
        # `mount # -oremount,bind,ro /tgt` does work. This operates on
        # a VFS mount pount which is separate from the original one.
        # However, this cannot be applied recursivle to the whole
        # sub-tree mounts.
        #
        # Therefore, for simplicity, we skip this feature for the time
        # being.
        if recursive and read_only:
            raise Exception("--rbind r/o mounts unsupported")

        subprocess.check_call(
            ["mount", bind_mode, src, dst, "-o" + options],
            close_fds=True,
            shell=False
        )

    def unmount(self, mountpoint):
        subprocess.check_call(
            ["umount", "-R", mountpoint],
            close_fds=True,
            shell=False
        )

    def checkCapsSupport(self):
        """In more recent kernels user namespaces are allowed to
        set capabilities on files. These are specially annotated as
        belonging to a certain user namespace. This is only supported
        starting from kernel 4.14.

        If we don't have this support then we can't test certain
        capability related cases.
        """
        import tempfile

        self.m_have_caps_support = False

        setcap = shutil.which("setcap")

        if not setcap:
            print("Can't test for capability support, no setcap found")
            return

        with tempfile.NamedTemporaryFile() as tmpfile:
            try:
                subprocess.check_call(
                    ["setcap", "cap_net_raw+ep", tmpfile.name],
                    close_fds=True,
                    shell=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )

                self.m_have_caps_support = True
            except subprocess.CalledProcessError:
                pass

    def getPermctlPath(self):
        return "/usr/local/bin/permctl"

    def getPermctlConfigRoot(self):
        return "/usr/local"

    def setupFakeRoot(self, skip_proc):

        # simply operate directly in /tmp in a tmpfs, since we're in a
        # mount namespace we don't leave behind garbage this way, we
        # don't even need to unmount.
        self.m_fake_root = "/tmp"
        self.mountTmpFS(self.m_fake_root)

        # for permctl to find a production-like environment, we need
        # to own the root filesystem '/', thus let's chroot into /tmp,
        # where we only bind mount the most important stuff from the
        # root mount namespace
        bind_dirs = ["/bin", "/sbin", "/usr", "/sys", "/dev", "/var", "/etc"]
        # add any /lib32/64 symlinks whatever
        bind_dirs.extend(glob.glob("/lib*"))

        for src in bind_dirs:

            dst = self.m_fake_root + src

            if os.path.islink(src):
                os.symlink(os.readlink(src), dst)
            elif os.path.isdir(src):
                os.makedirs(dst)
                self.bindMount(src, dst)
            else:
                raise Exception("bad mount src " + src)

        # mount a new proc corresponding to our forked pid namespace
        # unless this is disabled, to test permctl behaviour without /proc
        if not skip_proc:
            new_proc = self.m_fake_root + "/proc"
            os.mkdir(new_proc)
            self.mountProc(new_proc)

        # also bind-mount the permissions repo e.g. useful for
        # debugging
        self.mountTmpFS(self.m_fake_root + "/usr/src")
        permissions_repo_dst = self.m_fake_root + "/usr/src/permissions"
        os.makedirs(permissions_repo_dst)
        self.bindMount(
            self.m_permissions_repo, permissions_repo_dst,
        )

        self.mountTmpFS(self.m_fake_root + "/usr/local")
        local_bin = self.m_fake_root + self.getPermctlPath()
        os.makedirs(os.path.dirname(local_bin), exist_ok=True)
        # copy the current permctl into a suitable location of
        # the fake root FS
        shutil.copy(self.m_permctl_orig, local_bin)

        # make a writeable home available for the user namespace root
        # user
        root_home = self.m_fake_root + "/root"
        os.makedirs(root_home)
        self.mountTmpFS(root_home)

        # finally enter the fake root
        os.chroot(self.m_fake_root)
        # use a defined standard umask
        os.umask(0o022)
        # use a defined standard PATH list, include sbin
        # to make sure we also find admin tools
        os.environ["PATH"] = "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin"
        os.environ["HOME"] = "/root"
        os.chdir("/")

        # setup a tmp directory just in case
        os.mkdir("/tmp")
        os.chmod("/tmp", 0o1777)

    def enterShell(self):
        subprocess.call("/bin/bash", close_fds=True, shell=False)

    def printHeading(self, *args, **kwargs):

        stream = io.StringIO()
        kwargs["file"] = stream
        print(*args, **kwargs)

        text = stream.getvalue()
        color_printer.setMagenta()
        print(text, end='')
        print('-' * (len(text) - 1))
        color_printer.reset()

    def printException(self, e):
        _, _, tb = sys.exc_info()
        frame = traceback.extract_tb(tb)[-1]
        fn, ln, _, _ = frame
        print("Exception in {}:{}:".format(fn, ln), str(e), file=sys.stderr)

    def buildPermctl(self):

        if self.m_args.skip_build:
            if not os.path.exists(self.m_permctl_orig):
                print("Couldn't find compiled permctl binary in",
                      self.m_permctl_orig, file=sys.stderr)
                sys.exit(2)

            return

        self.printHeading("Rebuilding test version of permctl")
        print()

        buildtype = "debug" if self.m_args.build_debug else "debugoptimized"
        settings = []
        # this causes a debug version with additional libasan routines
        # to be built for testing
        # asan requires /proc so don't use it if we don't mount it
        if not self.m_args.skip_proc:
            settings.append("-Dtestbuild=true")

        try:
            meson_config_args = ["--buildtype", buildtype] + settings
            if not os.path.exists(self.m_args.buildtree):
                os.makedirs(self.m_args.buildtree)
                subprocess.check_call(
                    ["meson", "setup"] + meson_config_args + [self.m_args.buildtree],
                    cwd=self.m_permissions_repo
                )
            else:
                subprocess.check_call(
                    ["meson", "configure"] + meson_config_args,
                    cwd=self.m_args.buildtree,
                )
            print()
            subprocess.check_call(["meson", "compile"], cwd=self.m_args.buildtree)
            print()
        except subprocess.CalledProcessError:
            color_printer.setRed()
            print("Failed to compile test version of permctl")
            sys.exit(1)

    def run(self, tests):

        if self.m_args.list_tests:
            tests = [T() for T in tests]
            max_len = max([len(t.getName()) for t in tests])
            for test in tests:
                print("{}: {}".format(
                    test.getName().ljust(max_len),
                    test.getDescription()
                ))
            sys.exit(0)

        if self.REEXEC_ENV_MARKER in os.environ:
            self.handleNamespaceChildContext()
        else:
            self.ensureForkedNamespace()
            return

        self.buildPermctl()

        self.setupFakeRoot(self.m_args.skip_proc)
        self.checkCapsSupport()

        if self.m_args.enter_fakeroot:
            print("Entering shell in fake root")
            self.enterShell()
            sys.exit(0)

        tests_run = 0
        tests_failed = 0
        tests_warned = 0

        for Test in tests:

            test = Test()
            test.setMainTestInstance(self)

            if self.m_args.test and test.getName() != self.m_args.test:
                continue

            tests_run += 1

            self.printHeading("Running", test.getName())
            print()
            test.prepare()
            try:
                test.run()
                test.postrun()
                failed = test.getResult() != 0
            except Exception as e:
                self.printException(e)
                failed = True

            if test.getNumErrors() != 0:
                color_printer.setRed()
                sys.stdout.flush()
                print(test.getName(), "encountered", test.getNumErrors(), "errors", file=sys.stderr)
            if test.getNumWarnings() != 0:
                color_printer.setYellow()
                tests_warned += 1
                print(test.getName(), "encountered", test.getNumWarnings(), "warnings")

            color_printer.reset()

            if failed:
                tests_failed += 1
                color_printer.setRed()
                print("Test FAILED")
                color_printer.reset()
                if self.m_args.on_error_enter_shell:
                    print("Entering shell after failed test")
                    self.enterShell()

        if self.m_args.test and tests_run == 0:
            print("No such test", self.m_args.test)
            tests_failed += 1

        if self.m_args.after_test_enter_shell:
            print("Entering shell after test execution")
            self.enterShell()

        print("\n")
        print(str(tests_run).rjust(2), "tests run")
        color_printer.setGreen()
        print(str(tests_run - tests_failed).rjust(2), "tests succeeded")
        if tests_failed != 0:
            color_printer.setRed()
            print(str(tests_failed).rjust(2), "tests failed")
        if tests_warned != 0:
            color_printer.setYellow()
            print(str(tests_warned).rjust(2), "tests had warnings")
        color_printer.reset()

        if tests_failed != 0:
            return 1

        return 0


class TestBase:

    global_init_performed = False

    def __init__(self, desc):

        self.m_profiles = ("easy", "secure", "paranoid")
        self.m_local_profile = "local"

        self.m_test_name = type(self).__name__
        self.m_test_desc = desc
        self.m_result = 0
        self.m_warnings = 0
        self.m_errors = 0
        self.m_main_test_instance = None

    def setMainTestInstance(self, instance):
        self.m_main_test_instance = instance

    def getProfilePath(self, profile):
        base = TestBase.config_root + "/usr/share/permissions/permissions"
        if not profile:
            return base
        return '.'.join((base, profile))

    def getUserProfilePath(self, profile):
        base = TestBase.config_root + "/etc/permissions"
        if not profile:
            return base
        return '.'.join((base, profile))

    def getPackageProfilePath(self, package, profile, location):
        base = TestBase.config_root + PER_PACKAGE_CONFIG_DIRS[location] + package

        if not profile:
            return base

        return '.'.join((base, profile))

    def getVariablesConfPath(self):
        return TestBase.config_root + "/usr/share/permissions/variables.conf"

    def getName(self):
        return self.m_test_name

    def getResult(self):
        return self.m_result

    def setResult(self, code):
        self.m_result = code

    def getNumErrors(self):
        return self.m_errors

    def getNumWarnings(self):
        return self.m_warnings

    def createAndGetTestDir(self, mode):
        d = "/{}".format(self.getName())
        self.createTestDir(d, mode)
        return d

    def createTestFile(self, path, mode):
        with open(path, 'w') as _file:
            os.fchmod(_file.fileno(), mode)

    def createTestDir(self, path, mode):
        os.mkdir(path, mode)
        # perform an explicit chown() to get umask calculations out of
        # the way
        os.chmod(path, mode)

    def getDescription(self):
        return self.m_test_desc

    def prepare(self):
        if not TestBase.global_init_performed:

            TestBase.config_root = self.m_main_test_instance.getPermctlConfigRoot()
            TestBase.permctl = self.m_main_test_instance.getPermctlPath()

            config_root = TestBase.config_root

            # make a convenience symlink to make it feel more
            # natural in /usr/local
            os.symlink(config_root + "/usr/share", config_root + "/share")

            # make sure base dirs exist
            os.makedirs(config_root + "/etc/sysconfig", 0o755, exist_ok=True)
            for package_d in PER_PACKAGE_CONFIG_DIRS.values():
                os.makedirs(config_root + package_d, 0o755, exist_ok=True)
            os.makedirs(config_root + "/usr/share/permissions", 0o755, exist_ok=True)
            TestBase.global_init_performed = True

        self.resetConfigs()

    def postrun(self):

        if self.m_errors != 0:
            self.setResult(1)

    def resetConfigs(self):

        config_root = TestBase.config_root
        sysconfig = config_root + "/etc/sysconfig/security"
        central_perms = config_root + "/usr/share/permissions/permissions"

        candidates = [
            sysconfig,
            central_perms,
        ]

        candidates.append(self.getUserProfilePath(self.m_local_profile))
        for package_d in PER_PACKAGE_CONFIG_DIRS.values():
            candidates.extend(glob.glob(config_root + package_d + "/*"))
        candidates.extend([self.getProfilePath(profile) for profile in self.m_profiles])

        for cand in candidates:
            try:
                os.unlink(cand)
            except FileNotFoundError:
                pass

        # permctl expects the base files to exist, otherwise warnings
        # are emitted
        self.createTestFile(central_perms, 0o644)
        self.createTestFile(sysconfig, 0o644)

    def addProfileEntries(self, entries):
        """Adds entries to /etc/permissions.* according to the
        provided dictionary of the following form:

        {
            "easy": ("/some/file user:group mode"),
            "secure": ("/some/file other:group mode", "/other/file user:group mode"),
            [...]
        }
        """

        def getAgnosticProfilePath(profile):

            if profile == self.m_local_profile:
                return self.getUserProfilePath(profile)
            else:
                return self.getProfilePath(profile)

        for profile, lines in entries.items():

            with open(getAgnosticProfilePath(profile), 'a') as profile_file:
                for line in lines:
                    profile_file.write(line + "\n")

    def addPackageProfileEntries(self, package, entries, location=ConfigLocation.USR):
        """Just like addProfileEntries, but for a specific package in
        permissions.d."""

        for profile, lines in entries.items():

            with open(self.getPackageProfilePath(package, profile, location), 'a') as profile_file:
                for line in lines:
                    profile_file.write(line + "\n")

    def buildProfileLine(self, path, mode, owner="root", group="root", caps=[], acl=[]):
        ret = "{} {}:{} {}".format(
            path, owner, group,
            format(mode, '04o')
        )

        if caps:
            ret += "\n +capabilities {}".format(','.join(caps))

        if acl:
            ret += "\n +acl {}".format(','.join(acl if isinstance(acl, list) else [acl]))

        return ret

    def createSecuritySysconfig(self, permissions_val, fscaps_val=None):
        """Creates a /etc/sysconfig/security configuration using the
        given configuration values.

        :param str permissions_val: the value for the PERMISSION_SECURITY
                                    setting. e.g. "easy local"
        :param str fscaps_val: the value for the PERMISSIONS_FSCAPS
                                    setting. e.g. yes/no
        """

        items = {
            "PERMISSION_SECURITY": permissions_val,
            "PERMISSION_FSCAPS": fscaps_val
        }

        with open(TestBase.config_root + "/etc/sysconfig/security", 'w') as sec_file:

            for key, val in items.items():
                if not val:
                    val = ""
                elif '"' in val:
                    raise Exception("{} must not contain quotes".format(
                        key
                    ))

                sec_file.write("{}=\"{}\"\n".format(key, val))

    def switchSystemProfile(self, profile):
        print("Switching to", profile if profile else "(empty)", "system permissions profile")
        # configure the given profile as default
        self.createSecuritySysconfig(profile)

    def applySystemProfile(self, extra_args=[]):
        print("Applying current system profile using permctl")
        args = ["--set", "--system"] + extra_args
        return self.callPermctl(args)

    def extractPerms(self, s):
        return s.st_mode & ~(stat.S_IFMT(s.st_mode))

    def printMode(self, path):
        s = os.stat(path)
        perms = self.extractPerms(s)

        print("Current status of {path}: {owner}:{group} {mode}".format(
            path=path,
            owner=pwd.getpwuid(s.st_uid).pw_name,
            group=grp.getgrgid(s.st_gid).gr_name,
            mode=str(oct(perms)).replace('o', '')
        ))

    def printError(self, *args, **kwargs):

        color_printer.setRed()
        print("FAILURE:", *args, **kwargs)
        color_printer.reset()
        self.m_errors += 1

    def printWarning(self, *args, **kwargs):

        color_printer.setYellow()
        print("WARNING:", *args, **kwargs)
        color_printer.reset()
        self.m_warnings += 1

    def complainOnMissingSubIdSupport(self):
        if self.m_main_test_instance.haveSubIdSupport():
            return False

        self.printWarning("skipping this test since there is no sub*id support available")
        return True

    def getMode(self, path):
        s = os.stat(path)
        return self.extractPerms(s)

    def assertMode(self, path, expected):
        actual = self.getMode(path)

        if actual != expected:
            self.printError("{}: expected mode {} but encountered mode {}".format(
                path, str(oct(expected)), str(oct(actual))
            ))
            return False

        return True

    def assertOwnership(self, path, user, group):
        s = os.stat(path)

        if s.st_uid != int(user) or s.st_gid != int(group):
            self.printError("{}: expected ownership {}:{} but encountered ownership {}:{}".format(
                path, user, group, s.st_uid, s.st_gid
            ))
            return False

        return True

    def assertNoCaps(self, path):

        try:
            caps = os.getxattr(path, "security.capability")
            if caps:
                self.printError(path, "has capabilities despite --no-fscaps")
        except OSError as e:
            if e.errno != errno.ENODATA:
                raise

    def assertAnyCaps(self, path):
        # the returned data is binary data, don't want to parse that
        # stuff here. using libc wrappers for libcap[-ng] might be
        # another approach for not having to rely on `getcap`

        try:
            caps = os.getxattr(path, "security.capability")
            if caps:
                return
        except OSError as e:
            if e.errno != errno.ENODATA:
                raise

        # either `not caps` or ENODATA
        self.printError(path, "doesn't have capabilities despite expectations!")

    def assertHasCaps(self, path, caps):

        getcap = shutil.which("getcap")

        if not getcap:
            self.printWarning(
                "Couldn't find `getcap` utility, can't fully check capability values. Run `zypper in libcap-progs` to install it."
            )

            # attempt some best effort logic, just checking
            # whether any capability is set at all.
            self.assertAnyCaps(path)
            return

        getcap_out = subprocess.check_output(
            [getcap, "-v", path],
            close_fds=True,
            shell=False,
        )

        expected_caps = ','.join(caps)
        actual_caps = ""

        # until libcap-2.32 the output format looked like this:
        #
        # /usr/bin/ping = cap_net_raw+ep
        #
        # starting from libcap-2.42 it looks like this:
        #
        # /usr/bin/ping cap_net_raw=p
        #
        # see bsc#1175076 comment 2.
        # So let's be agnostic to the output format.

        for line in getcap_out.decode('utf8').splitlines():
            if not line.startswith(path):
                continue

            line = line[len(path):].strip()
            parts = line.split()

            if len(parts) == 2 and parts[0] == '=':
                # the old output format:
                # getcap uses a '+' to indicate capability
                # types, while permissions uses '=', so adjust
                # accordingly
                expected_caps = expected_caps.replace('=', '+')
                actual_caps = parts[1]
                break
            elif len(parts) == 1:
                actual_caps = parts[0]
                break

        if actual_caps != expected_caps:
            self.printError(path, "doesn't have expected capabilities '{}' but '{}' instead".format(
                expected_caps, actual_caps
            ))

    def getACLEntries(self, path):
        """Returns a list of all extended ACL entries."""

        getfacl = shutil.which("getfacl")

        if not getfacl:
            self.printWarning(
                "Couldn't find `getfacl` utility, can't fully check ACL entries. Run `zypper in acl` to install it."
            )
            return []

        getfacl_out = subprocess.check_output(
            [getfacl, "-s", "-c", path],
            stderr=subprocess.DEVNULL,
            close_fds=True,
            shell=False,
        )

        entries = []

        for line in getfacl_out.decode('utf8').splitlines():
            line = line.strip()

            if line.find('::') != -1:
                # skip any basic and mask entries like user::rwx
                continue

            if len(line.split(':')) != 3:
                # skip anything unexpected, we are looking for <type>:<name>:<perm> tuples
                continue

            entries.append(line)

        return entries

    def addACLEntries(self, path, perms):

        setfacl = shutil.which("setfacl")

        if not setfacl:
            self.printWarning(
                "Couldn't find `setfacl` utility, can't fully check ACL entries. Run `zypper in acl` to install it."
            )
            return

        subprocess.check_output( [setfacl, '-m', perms, path])

    def callPermctl(self, args):
        """Calls permctl passing the given command line arguments. The
        function will capture permctl's stdout and stderr via a pipe
        and then print the output on the terminal in a marked up
        fashion.

        The function will return a tuple of (exit_code, list of
        output lines).
        """

        if isinstance(args, str):
            args = [args]

        cmdline = [self.permctl, "--config-root", TestBase.config_root] + args

        print('#', ' '.join(cmdline))

        proc = subprocess.Popen(
            cmdline,
            close_fds=True,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )

        ret = []

        color_printer.setCyan()
        while True:
            line = proc.stdout.readline()
            if not line:
                break

            line = line.decode('utf8')
            ret.append(line)

            print('> {}'.format(line), end='')
        color_printer.reset()

        return proc.wait(), ret

    def extractMessagesFromPermctl(self, output, paths):
        """output is a list of lines as returned from callPermctl(),
        paths is a list of paths for which diagnostic/error messages
        should be extracted from the output.

        Returns a dictionary:

        {
        "path1": [ "diagnostic1", "diagnostic2", ... ],
        ...
        }
        """

        if isinstance(paths, str):
            paths = [paths]

        ret = dict([(p, []) for p in paths])

        for line in output:

            self._checkForASANErrors(line)

            for path in paths:

                if not line.startswith(path):
                    continue

                parts = line.split(':', 1)

                if len(parts) != 2:
                    # something else then
                    continue

                message = parts[1]

                ret[path].append(message)
                break

        return ret

    def _checkForASANErrors(self, line):
        if line.find("LeakSanitizer: detected memory leaks") != -1:
            self.printError("ASAN found memory leaks!")
            self.m_errors += 1
