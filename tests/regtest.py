#!/usr/bin/python3

# sorry, I'm a Python PEP outlaw
# vim: ts=8 noet sw=8 sts=8 :

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
import traceback

# the basic test concept is as follows:
#
# running these tests with real root privileges carries the danger of breaking
# the host system and is generally complex to achieve when user privileges
# need to be switched for testing, for example.
#
# chkstat on its own supports some switches like `--root` to operate on a
# specific file system subtree. However, this also triggers other, potentially 
# uncommon logic in chkstat, while we're more interested in the major use
# cases.
#
# a good compromise is to use user and mount namespaces:
#
# - real root privileges are not required
# - damaging the system is less likely, only user data can suffer
# - typical code paths of chkstat can largely be kept as-is
# - even some privileged operations like setting setuid-root bits or
# capabilities can be emulated
#
# the downside is that we need to construct a fake root file system from what
# we have on the host. This is what the ChkstatRegtest class is caring for.
# Another downside is that we cannot chown() or chgrp() to any other group
# than root (our fake root in the user namespace).
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
			print(u"\u001b[0m", end = '')

	def setRed(self):
		if self.m_use_colors:
			print(u"\u001b[31m", end = '')

	def setYellow(self):
		if self.m_use_colors:
			print(u"\u001b[33m", end = '')

	def setGreen(self):
		if self.m_use_colors:
			print(u"\u001b[32m", end = '')

	def setCyan(self):
		if self.m_use_colors:
			print(u"\u001b[36m", end = '')

	def setMagenta(self):
		if self.m_use_colors:
			print(u"\u001b[35m", end = '')

color_printer = ColorPrinter()


class ChkstatRegtest:
	"""The main test execution class. It sets up the fake root using
	namespaces and runs each individual test case."""

	def __init__(self):

		self.setupArgParser()

		perm_root = os.path.realpath(__file__).split(os.path.sep)[:-2]
		self.m_permissions_repo = os.path.sep.join(perm_root)
		self.m_chkstat_bin = os.path.sep.join([self.m_permissions_repo, "chkstat"])

		if not os.path.exists(self.m_chkstat_bin):
			print("Couldn't find compiled chkstat binary in", self.m_chkstat_bin, file = sys.stderr)
			sys.exit(2)

	def setupArgParser(self):

		self.m_parser = argparse.ArgumentParser(
			description = "Regression test suite for the chkstat program"
		)

		self.m_parser.add_argument(
			"--enter-fakeroot", action = 'store_true',
			help = "Instead of running tests, just enter a shell in the fake test root file system"
		)

		self.m_parser.add_argument(
			"--on-error-enter-shell", action = 'store_true',
			help = "If any test fails or throws an exception then before continuing execution a shell will be entered in the fake root."
		)

		self.m_parser.add_argument(
			"--list-tests", action = 'store_true',
			help = "Just list the available tests"
		)

		self.m_parser.add_argument(
			"--test", type = str,
			help = "Instead of all tests tun only the given test. For names see --list-tests."
		)

		self.m_args = self.m_parser.parse_args()

	def ensureForkedNamespace(self):
		"""This function reexecutes the current script in a forked user and
		mount namespace for faking a root file system and root context for
		testing chkstat."""
		reexec_env_marker = "CHKSTAT_REGTEST_REEXEC"

		if reexec_env_marker in os.environ:
			return

		unshare = shutil.which("unshare")

		if not unshare:
			print("Couldn't find the 'unshare' program", file = sys.stderr)
			sys.exit(1)

		os.environ[reexec_env_marker] = "1"
		res = subprocess.call(
			[unshare, "-m", "-U", "-r"] + sys.argv,
			close_fds = True,
			shell = False
		)
		sys.exit(res)

	def mountTmpFS(self, path):
		subprocess.check_call(
			["mount", "-t", "tmpfs", "none", path],
			close_fds = True,
			shell = False
		)

	def bindMount(self, src, dst, recursive = True, read_only = False):
		bind_mode = "--rbind" if recursive else "--bind"
		options = "ro" if read_only else "rw"
		subprocess.check_call(
			[ "mount", bind_mode, src, dst, "-o" + options ],
			close_fds = True,
			shell = False
		)

	def unmount(self, mountpoint):
		subprocess.check_call(
			[ "umount", "-R", mountpoint ],
			close_fds = True,
			shell = False
		)

	def setupFakeRoot(self):

		# simply operate directly in /tmp in a tmpfs, since we're in a
		# mount namespace we don't leave behind garbage this way, we
		# don't even need to unmount.
		self.m_fake_root = "/tmp"
		self.mountTmpFS(self.m_fake_root)

		# for chkstat to find a production-like environment, we need
		# to own the root filesystem '/', thus let's chroot into /tmp,
		# where we only bind mount the most important stuff from the
		# root mount namespace
		bind_dirs = ["/bin", "/sbin", "/usr", "/sys", "/dev", "/var", "/proc"]
		# add any /lib32/64 symlinks whatever
		bind_dirs.extend( glob.glob("/lib*") )
		# /etc needs to be copied, we need to be able to write in
		# there, to construct fake permissions config files
		copy_dirs = ("/etc",)

		for src in bind_dirs:

			dst = self.m_fake_root + src

			if os.path.islink(src):
				os.symlink(os.readlink(src), dst)
			elif os.path.isdir(src):
				os.makedirs(dst)
				self.bindMount(src, dst)
			else:
				raise Exception("bad mount src " + src)

		for src in copy_dirs:
			dst_dir = self.m_fake_root + src
			try:
				# symlinks here means "copy links as is"
				shutil.copytree(src, dst_dir, symlinks = True)
			except shutil.Error:
				# copying /etc only works partially since
				# we're not really root.
				# this error contains a list of errors in
				# args[0] consisting of (src, dst, error)
				# tuples, but "error" is only a string in this
				# case, not very helpful for evaluation
				pass

		# also bind-mount the permissions repo e.g. useful for
		# debugging
		permissions_repo_dst = self.m_fake_root + "/permissions"
		os.makedirs(permissions_repo_dst)
		# NOTE: would be good mounting this read-only, but trying so
		# fails with
		# `mount: /tmp/permissions: filesystem was mounted, but any subsequent operation failed: Unknown error 5005."
		# reason is that a following MS_REC mount fails with EPERM,
		# not quite sure why that is.
		self.bindMount(
			self.m_permissions_repo, permissions_repo_dst,
		)

		self.mountTmpFS(self.m_fake_root + "/usr/local")
		local_bin = self.m_fake_root + "/usr/local/bin"
		os.makedirs(local_bin, exist_ok = True)
		local_chkstat = os.path.join(local_bin, "chkstat")
		# copy the current chkstat into a suitable location of
		# the fake root FS
		shutil.copy(self.m_chkstat_bin, local_chkstat)

		# finally enter the fake root
		os.chroot(self.m_fake_root)
		# use a defined standard umask
		os.umask(0o022)
		# use a defined standard PATH list, include sbin
		# to make sure we also find admin tools
		os.environ["PATH"] =  "/bin:/sbin:/sbin:/usr/sbin"
		os.chdir("/")

		# setup a tmp directory just in case
		os.mkdir("/tmp")
		os.chmod("/tmp", 0o1777)

	def enterShell(self):
		subprocess.call("/bin/bash", close_fds = True, shell = False)

	def printHeading(self, *args, **kwargs):

		stream = io.StringIO()
		kwargs["file"] = stream
		print(*args, **kwargs)

		text = stream.getvalue()
		color_printer.setMagenta()
		print(text, end = '')
		print('-' * (len(text) - 1))
		color_printer.reset()

	def printException(self, e):
		_, _, tb = sys.exc_info()
		fn, ln, _, _ = frame = traceback.extract_tb(tb)[-1]
		print("Exception in {}:{}:".format(fn, ln), str(e), file = sys.stderr)

	def run(self, tests):

		if self.m_args.list_tests:
			tests = [ T() for T in tests ]
			max_len = max( [ len(t.getName()) for t in tests ] )
			for test in tests:
				print("{}: {}".format(
					test.getName().ljust(max_len),
					test.getDescription()
				))
			sys.exit(0)

		self.ensureForkedNamespace()
		self.setupFakeRoot()

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
				print(test.getName(), "encountered", test.getNumErrors(), "errors")
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

		print("\n")
		print(str(tests_run).rjust(2), "tests run")
		color_printer.setGreen()
		print(str(tests_run - tests_failed).rjust(2), "tests succeeded")
		color_printer.setRed()
		print(str(tests_failed).rjust(2), "tests failed")
		color_printer.setYellow()
		print(str(tests_warned).rjust(2), "tests had warnings")
		color_printer.reset()

		if tests_failed != 0:
			return 1

		return 0

class TestBase:

	global_init_performed = False

	def __init__(self, name, desc):

		self.m_sysconfig = "/etc/sysconfig"
		self.m_sysconfig_security = self.m_sysconfig + "/security"
		self.m_permissions_dir = "/etc/permissions.d"
		self.m_permissions_base = "/etc/permissions"
		self.m_profiles = ("easy", "secure", "paranoid")
		self.m_local_profile = "local"
		self.m_chkstat_bin = "/usr/local/bin/chkstat"

		self.m_test_name = name
		self.m_test_desc = desc
		self.m_result = 0
		self.m_warnings = 0
		self.m_errors = 0
		self.m_main_test_instance = None

	def setMainTestInstance(self, instance):
		self.m_main_test_instance = instance

	def getProfilePath(self, profile):
		if not profile:
			return self.m_permissions_base
		return '.'.join((self.m_permissions_base, profile))

	def getPackageProfilePath(self, package, profile):
		base = os.path.sep.join((self.m_permissions_dir, package))

		if not profile:
			return base

		return '.'.join((base, profile))

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
		if not self.global_init_performed:
			# make sure certain dirs exist
			os.makedirs(self.m_sysconfig, 0o755, exist_ok = True)
			os.makedirs(self.m_permissions_dir, 0o755, exist_ok = True)
			self.global_init_performed = True

		self.resetConfigs()

	def postrun(self):

		if self.m_errors != 0:
			self.setResult(1)

	def resetConfigs(self):

		candidates = [
			self.m_sysconfig_security,
			self.m_permissions_base,
		]

		candidates.append( self.getProfilePath(self.m_local_profile) )
		candidates.extend( glob.glob(self.m_permissions_dir + "/*") )
		candidates.extend( [self.getProfilePath(profile) for profile in self.m_profiles] )

		for cand in candidates:
			try:
				os.unlink(cand)
			except:
				pass

		# chkstat expects the base files to exist, otherwise warnings
		# are emitted
		self.createTestFile(self.m_permissions_base, 0o644)
		self.createTestFile(self.m_sysconfig_security, 0o644)

	def addProfileEntries(self, entries):
		"""Adds entries to /etc/permissions.* according to the
		provided dictionary of the following form:

		{
			"easy": ("/some/file user:group mode"),
			"secure": ("/some/file other:group mode", "/other/file user:group mode"),
			[...]
		}
		"""

		for profile, lines in entries.items():

			with open(self.getProfilePath(profile), 'a') as profile_file:
				for line in lines:
					profile_file.write(line + "\n")

	def addPackageProfileEntries(self, package, entries):
		"""Just like addProfileEntries, but for a specific package in
		permissions.d."""

		for profile, lines in entries.items():

			with open(self.getPackageProfilePath(package, profile), 'a') as profile_file:
				for line in lines:
					profile_file.write(line + "\n")

	def buildProfileLine(self, path, mode, owner = "root", group = "root", caps = []):
		ret = "{} {}:{} {}".format(
			path, owner, group,
			format(mode, '04o')
		)

		if caps:
			ret += "\n +capabilities {}".format( ','.join(caps) )

		return ret

	def createSecuritySysconfig(self, permissions_val, fscaps_val = None):
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

		with open(self.m_sysconfig_security, 'w') as sec_file:

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

	def applySystemProfile(self, extra_args = []):
		print("Applying current system profile using chkstat")
		args = ["--system"] + extra_args
		return self.callChkstat(args)

	def extractPerms(self, s):
		return s.st_mode & ~(stat.S_IFMT(s.st_mode))

	def printMode(self, path):
		s = os.stat(path)
		perms = self.extractPerms(s)

		print("Current status of {path}: {owner}:{group} {mode}".format(
			path = path,
			owner = pwd.getpwuid(s.st_uid).pw_name,
			group = grp.getgrgid(s.st_gid).gr_name,
			mode = str(oct(perms)).replace('o', '')
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

	def callChkstat(self, args):
		"""Calls chkstat passing the given command line arguments. The
		function will capture chkstat's stdout and stderr via a pipe
		and then print the output on the terminal in a marked up
		fashion.

		The function will return a tuple of (exit_code, list of
		output lines).
		"""

		if isinstance(args, str):
			args = [args]

		cmdline = [self.m_chkstat_bin] + args

		print('#', ' '.join(cmdline))

		proc = subprocess.Popen(
			cmdline,
			close_fds = True,
			shell = False,
			stdout = subprocess.PIPE,
			stderr = subprocess.STDOUT
		)

		ret = []

		color_printer.setCyan()
		while True:
			line = proc.stdout.readline()
			if not line:
				break

			line = line.decode('utf8')
			ret.append(line)

			print('> {}'.format(line), end = '')
		color_printer.reset()

		return proc.wait(), ret

	def extractMessagesFromChkstat(self, output, paths):
		"""output is a list of lines as returned from callChkstat(),
		paths is a list of paths for which diagnostic/error messages
		should be extracted from the output.

		Returns a dictionary:

		{
		"path1": [ "diagnostic1", "diagnostic2", ... ],
		...
		}
		"""

		if isinstance(paths, str):
			paths = [ paths ]

		ret = dict( [ (p, []) for p in paths ] )

		for line in output:

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

class TestCorrectMode(TestBase):

	def __init__(self):
		super().__init__("TestCorrectMode", "checks whether file mode assignments are correctly applied as configured")

	def run(self):
		testdir = self.createAndGetTestDir(0o770)
		testfile = os.path.sep.join( (testdir, "testfile") )
		testpaths = (testdir, testfile)
		self.createTestFile(testfile, 0o444)

		modes = {
			"easy": (0o750, 0o740),
			"secure": (0o710, 0o700),
			"paranoid": (0o700, 0o600)
		}

		entries = {}

		for profile, perms in modes.items():
			lines = entries.setdefault(profile, [])
			for path, mode in ( (testdir, perms[0]), (testfile, perms[1])):
				lines.append( self.buildProfileLine(path, mode) )

		self.addProfileEntries(entries)

		for profile, entries in entries.items():

			for p in testpaths:
				self.printMode(p)

			# configure the given profile as default
			self.switchSystemProfile(profile)
			self.applySystemProfile()

			for path, mode in zip(testpaths, modes[profile]):
				self.assertMode(path, mode)

			print()

class TestBasePermissions(TestBase):

	def __init__(self):
		super().__init__("TestBasePermissions", "checks whether entries in /etc/permissions correctly apply")

	def run(self):

		testdir = self.createAndGetTestDir(0o770)
		testfile = os.path.sep.join( (testdir, "testfile") )
		testpaths = (testdir, testfile)
		self.createTestFile(testfile, 0o440)

		modes = {
			testfile: 0o444,
			testdir: 0o777
		}

		lines = [ self.buildProfileLine(path, mode) for path, mode in modes.items() ]

		self.addProfileEntries({
			# an empty string will operate on the base permissions
			# file
			"": lines
		})

		# the mode should be the same for all profiles
		for profile in self.m_profiles:
			for p in testpaths:
				self.printMode(p)

			self.switchSystemProfile(profile)
			self.applySystemProfile()

			for path, mode in modes.items():
				self.assertMode(path, mode)
				# change the mode to something else so we can
				# check that chkstat is always restoring the
				# correct mode, independent of the active
				# profile
				os.chmod(path, mode & 0o111)

		print()

class TestPackagePermissions(TestBase):

	def __init__(self):
		super().__init__("TestPackagePermissions", "checks whether package entries in /etc/permissions.d correctly apply")

	def run(self):

		# for permissions.d the basename of a file and the
		# basename.$profile, where $profile is the currently active
		# profile, should be applied.
		testdir = self.createAndGetTestDir(0o770)
		testfile = os.path.sep.join( (testdir, "testfile") )
		# this file should only be determined by the basename entry
		basefile = os.path.sep.join( (testdir, "basefile") )
		testpaths = (testdir, testfile, basefile)
		self.createTestFile(testfile, 0o440)
		self.createTestFile(basefile, 0o664)
		package = "testpackage"

		modes = {
			"": (0o700, 0o400),
			"easy": (0o775, 0o664),
			"secure": (0o770, 0o660),
			"paranoid": (0o700, 0o600)
		}
		# mode for basefile
		basemode = 0o640

		entries = {}

		for profile, perms in modes.items():
			lines = entries.setdefault(profile, [])
			for path, mode in ( (testdir, perms[0]), (testfile, perms[1]) ):
				lines.append( self.buildProfileLine(path, mode) )

			if profile == "":
				lines.append( self.buildProfileLine(basefile, basemode) )

		self.addPackageProfileEntries(package, entries)

		for profile, entries in entries.items():

			for p in testpaths:
				self.printMode(p)

			# for the "empty" profile we need to choose some
			# non-existing one, otherwise chkstat falls back to
			# "secure"
			self.switchSystemProfile(profile if profile else "fake")
			self.applySystemProfile()

			# for the basefile the mode should always be basemode
			# independently of the active profile
			for path, mode in zip(testpaths, modes[profile] + (basemode,)):
				self.assertMode(path, mode)

			# change mode for the basefile to check whether it's
			# actually restored independently of the active
			# profile
			os.chmod(basefile, 0o444)

			print()

class TestLocalPermissions(TestBase):

	def __init__(self):
		super().__init__("TestLocalPermissions", "checks whether entries in *.local profiles are respected")

	def run(self):

		# entries in *.local should always take precedence over the
		# rest IIUC
		#
		# write arbitrary entries in the standard profiles, they
		# should never apply.
		#
		# then add an entry for testdir in permissions.local and one
		# in testpackage.local
		testdir = self.createAndGetTestDir(0o750)
		testfile = os.path.sep.join( (testdir, "testfile") )
		testpaths = (testdir, testfile)
		self.createTestFile(testfile, 0o640)
		package = "testpackage"

		modes = {
			"": (0o770, 0o660),
			"easy": (0o775, 0o664),
			"secure": (0o710, 0o600),
			"paranoid": (0o700, 0o400),
		}

		local_perms = (0o500, 0o000)

		global_entries = {}
		pkg_entries = {}

		for profile, perms in modes.items():
			global_lines = global_entries.setdefault(profile, [])
			pkg_lines = pkg_entries.setdefault(profile, [])

			line = self.buildProfileLine(testdir, perms[0])
			global_lines.append( line )
			line = self.buildProfileLine(testfile, perms[1])
			pkg_lines.append( line )

		# this should take precendence over all other entries
		line = self.buildProfileLine(testdir, local_perms[0])
		global_entries["local"] = [ line ]
		line = self.buildProfileLine(testfile, local_perms[1])
		pkg_entries["local"] = [ line ]

		self.addProfileEntries(global_entries)
		self.addPackageProfileEntries(package, pkg_entries)

		for profile in modes.keys():

			for p in testpaths:
				self.printMode(p)

			self.switchSystemProfile(profile if profile else "fake")
			self.applySystemProfile()

			for path, mode in zip (testpaths, local_perms):
				self.assertMode(path, mode)
				# corrupt the mode to make sure it's always
				# restored later
				os.chmod(path, 0o555)

			print()

class TestDefaultProfile(TestBase):

	def __init__(self):
		super().__init__("TestDefaultProfile", "checks whether the default profile is correctly selected")
		# if no profile is explicitly configured then this one should
		# be implicitly selected by chkstat
		self.m_default_profile = "secure"

	def run(self):

		testdir = self.createAndGetTestDir(0o770)
		testfile = os.path.sep.join( (testdir, "testfile") )
		testpaths = (testdir, testfile)
		self.createTestFile(testfile, 0o444)
		package = "testpackage"

		modes = {
			"": (0o700, 0o400),
			"easy": (0o775, 0o664),
			"secure": (0o770, 0o660),
			"paranoid": (0o700, 0o600)
		}

		global_entries = {}
		pkg_entries = {}

		for profile, perms in modes.items():
			global_lines = global_entries.setdefault(profile, [])
			pkg_lines = pkg_entries.setdefault(profile, [])

			line = self.buildProfileLine(testdir, perms[0])
			global_lines.append( line )
			line = self.buildProfileLine(testfile, perms[1])
			pkg_lines.append( line )

		self.addProfileEntries(global_entries)
		self.addPackageProfileEntries(package, pkg_entries)

		for path in testpaths:
			self.printMode(path)

		# write an empty profile config, this should cause the default
		# to kick in
		self.switchSystemProfile("")
		self.applySystemProfile()

		for path, mode in zip(testpaths, modes[self.m_default_profile]):
			self.assertMode(path, mode)

		print()

class TestCommandLineBase(TestBase):
	"""A base class for a couple or simpler command line switch tests.
	setupTest() provides a common profile setup for use by
	specializations."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

	def setupTest(self):

		testdir_root = self.createAndGetTestDir(0o755)
		testdir_a = os.path.join(testdir_root, "sub1")
		testfile_a = os.path.join(testdir_a, "file1")
		testdir_b = os.path.join(testdir_root, "sub2")
		testfile_b = os.path.join(testdir_b, "file2")
		for d in (testdir_a, testdir_b):
			os.mkdir(d, 0o755)
		for f in (testfile_a, testfile_b):
			self.createTestFile(f, 0o444)
		package = "testpackage"

		global_testpaths = (testdir_a, testfile_a)
		pkg_testpaths = (testdir_b, testfile_b)

		modes = {
			"": (0o700, 0o400),
			"easy": (0o755, 0o664),
			"secure": (0o770, 0o660),
			"paranoid": (0o700, 0o600)
		}

		entries = {}

		for profile, perms in modes.items():
			lines = entries.setdefault(profile, [])
			for path, mode in zip(global_testpaths, modes[profile]):
				lines.append( self.buildProfileLine(path, mode) )

		self.addProfileEntries(entries)

		entries = {}

		for profile, perms in modes.items():
			lines = entries.setdefault(profile, [])
			for path, mode in zip(pkg_testpaths, modes[profile]):
				lines.append( self.buildProfileLine(path, mode) )

		self.addPackageProfileEntries(package, entries)

		self.m_global_testpaths = global_testpaths
		self.m_pkg_testpaths = pkg_testpaths
		self.m_testpaths = self.m_global_testpaths + self.m_pkg_testpaths
		self.m_modes = modes
		self.m_testdir_root = testdir_root

class TestForceProfile(TestCommandLineBase):

	def __init__(self):

		super().__init__("TestForceProfile", "Tests whether the `--level` override works")

	def run(self):

		self.setupTest()

		forced_level = "paranoid"
		expected_modes = self.m_modes[forced_level] * 2

		for profile in self.m_profiles:
			# independently of the configured system profile, the
			# forced level should always be applied
			self.switchSystemProfile(profile)
			self.applySystemProfile(["--level", forced_level])

			for path, mode in zip(self.m_testpaths, expected_modes):
				self.assertMode(path, mode)

class TestWarnMode(TestCommandLineBase):

	def __init__(self):

		super().__init__("TestWarnMode", "Tests whether the `--warn` switch works as expected")

	def run(self):
		self.setupTest()

		init_profile = "easy"
		expected_modes = self.m_modes[init_profile] * 2
		self.switchSystemProfile(init_profile)
		self.applySystemProfile()

		for profile in self.m_profiles:
			self.switchSystemProfile(profile)
			self.applySystemProfile(["--warn"])

			for path, mode in zip(self.m_testpaths, expected_modes):
				# modes should never change after the initial switch
				self.assertMode(path, mode)

class TestExamineSwitch(TestCommandLineBase):

	def __init__(self):

		super().__init__("TestExamineSwitch", "Tests whether the `--examine` switch works as expected")

	def run(self):
		self.setupTest()

		# first get a defined state
		init_profile = "easy"
		self.switchSystemProfile(init_profile)
		self.applySystemProfile()
		expected_modes = self.m_modes[init_profile] * 2

		# choose an arbitrary config item for the test
		examine_index = 0 # 0 is for the dir, 1 is for the file mode
		examine_path = self.m_testpaths[2]

		for profile in self.m_profiles:
			self.switchSystemProfile(profile)
			self.applySystemProfile(["--examine", examine_path])

			# only examine_path should now be changed, all else
			# should stay at "easy" level
			for path, mode in zip(self.m_testpaths, expected_modes):
				if path != examine_path:
					self.assertMode(path, mode)
				else:
					# the --examine path should be
					# switched to the according profile
					self.assertMode(path, self.m_modes[profile][examine_index])

class TestRootSwitch(TestCommandLineBase):

	def __init__(self):

		super().__init__("TestRootSwitch", "Tests whether the `--root` switch works as expected")

	def run(self):
		self.setupTest()

		init_profile = "easy"
		self.switchSystemProfile(init_profile)
		self.applySystemProfile()
		expected_modes = self.m_modes[init_profile] * 2

		# now only operate on the alternative root directory
		alt_root = "/altroot"
		os.mkdir(alt_root)
		# copy over our configured entries to the alt root
		shutil.copytree(self.m_testdir_root, alt_root + self.m_testdir_root)

		alt_testpaths = [ alt_root + path for path in self.m_testpaths ]

		for profile in self.m_profiles:
			self.switchSystemProfile(profile)
			self.applySystemProfile(["--root", alt_root])

			# the original root should be unaltered
			for path, mode in zip(self.m_testpaths, expected_modes):
				self.assertMode(path, mode)

			# the alternative root should be accordingly adjusted
			for path, mode in zip(alt_testpaths, self.m_modes[profile] * 2):
				self.assertMode(path, mode)

			print()

class TestFilesSwitch(TestCommandLineBase):

	def __init__(self):

		super().__init__("TestFilesSwitch", "Tests whether the `--files` switch works as expected")

	def run(self):
		self.setupTest()

		# this switch actually just reads a list of --examine paths
		# from a file.

		# get a defined start state
		init_profile = "easy"
		self.switchSystemProfile(init_profile)
		self.applySystemProfile()

		# write a custom profile file only affected one of the paths
		# present in the other profiles
		testpath = self.m_testpaths[0]
		mode_index = 0
		files_path = "/tmp/files.list"
		with open(files_path, 'w') as files_file:
			files_file.write(testpath + "\n")

		for profile in self.m_profiles:
			self.switchSystemProfile(profile)
			self.applySystemProfile(["--files", files_path])

			# modes should always be the same: easy profiles for
			# everything but the testpath, which should be at
			# the mode for the current profile
			for path, mode in zip(self.m_testpaths, self.m_modes[init_profile] * 2):
				if path != testpath:
					self.assertMode(path, mode)
				else:
					self.assertMode(path, self.m_modes[profile][mode_index])

			print()

class TestCapabilities(TestBase):

	def __init__(self):

		super().__init__("TestCapabilities", "checks whether capability settings and related command line options works")

	def run(self):

		testfile = "/caps_test"
		self.createTestFile(testfile, 0o755)

		# just test a single profile in this case, we just want to see
		# whether caps work at all
		profile = "easy"
		mode = 0o750
		caps = ["cap_net_admin", "cap_net_raw=ep"]

		entries = {
			profile: [ self.buildProfileLine(testfile, mode, caps = caps) ]
		}

		self.addProfileEntries(entries)

		self.switchSystemProfile(profile)
		# by default caps should be set, if in the sysconfig
		# configuration not value is set (but the variable still needs
		# to be there).
		self.applySystemProfile()

		self.assertHasCaps(testfile, caps)

		os.unlink(testfile)
		self.createTestFile(testfile, 0o755)
		self.applySystemProfile(["--no-fscaps"])

		# this time there should be no extended attribute at all
		self.assertNoCaps(testfile)

	def assertNoCaps(self, path):

		try:
			caps = os.getxattr(path, "security.capability")
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
			if not caps:
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
				"Couldn't find `getcap` utility, can't fully check capability values"
			)

			# attempt some best effort logic, just checking
			# whether any capability is set at all.
			self.assertAnyCaps(path)
			return

		getcap_out = subprocess.check_output(
			[ getcap, "-v", path ],
			close_fds = True,
			shell = False,
		)

		# getcap uses a '+' to indicate capability types, while
		# permissions uses '=', so adjust accordingly
		expected_caps = ','.join(caps).replace('=', '+')
		actual_caps = ""

		# output is something like "/path/to/file = cap_stuff+letters"
		for line in getcap_out.decode('utf8').splitlines():
			# be prudent about possible spaces or equals in paths,
			# even though it should never occur in our test
			# environment
			parts = line.split('=')
			if len(parts) < 2:
				continue

			cap_path = '='.join(parts[:-1]).strip()
			if cap_path != path:
				# not for our file
				continue

			actual_caps = parts[-1].strip()
			break

		if actual_caps != expected_caps:
			self.printError(path, "doesn't have expected capabilities '{}' but '{}' instead".format(
				expected_caps, actual_caps
			))

class TestUnexpectedPathOwner(TestBase):

	def __init__(self):

		super().__init__("TestUnexpectedPathOwner", "checks whether changes are rejected when parent dir owner and target path owner don't match")

	def run(self):

		testdir = self.createAndGetTestDir(0o755)
		baddir = os.path.join( testdir, "dir" )
		badfile = os.path.join( testdir, "file" )

		self.createTestFile(badfile, 0o644)
		self.createTestDir(baddir, 0o755)

		testprofile = "easy"

		entries = {
			testprofile: (
				# add a trailing slash to express that we want
				# a directory here
				self.buildProfileLine(baddir + "/", 0o500),
				self.buildProfileLine(badfile, 0o600)
			)
		}

		self.addProfileEntries(entries)
		# for creating the mixed ownership we need to resort to bind
		# mounts, since we're not really root and can't chown()
		self.m_main_test_instance.bindMount("/bin/bash", badfile)
		self.m_main_test_instance.bindMount("/usr/bin", baddir)
		orig_file_mode = self.getMode(badfile)
		orig_dir_mode = self.getMode(baddir)

		try:
			self.switchSystemProfile(testprofile)
			code, lines = self.applySystemProfile()
			# make sure modes actually didn't change
			# before bind mounts are removed
			self.assertMode(badfile, orig_file_mode)
			self.assertMode(baddir, orig_dir_mode)
		finally:
			self.m_main_test_instance.unmount(badfile)
			self.m_main_test_instance.unmount(baddir)

		found_dir_reject = False
		found_file_reject = False

		# we can't evaluate the exit code in this case, even if the
		# modes aren't corrected chkstat returns 0.
		#
		# instead parse chkstat's output to determine it correctly
		# refused to do anything
		messages = self.extractMessagesFromChkstat(lines, [baddir, badfile])
		needle = "unexpected owner"

		for message in messages[baddir]:
			if message.find(needle) != -1:
				found_dir_reject = True
				break
		for message in messages[badfile]:
			if message.find(needle) != -1:
				found_file_reject = True
				break

		print(baddir, "rejected =", found_dir_reject)
		print(badfile, "rejected =", found_file_reject)

		if found_dir_reject and found_file_reject:
			# all fine
			return

		self.printError("bad directory and/or bad file were not rejected")

class TestRejectWorldWritable(TestBase):

	def __init__(self):

		super().__init__("TestRejectWorldWritable", "checks that world-writable target files aren't touched")

	def run(self):

		testdir = self.createAndGetTestDir(0o755)
		badfile = os.path.join( testdir, "file" )

		self.createTestFile(badfile, 0o666)

		testprofile = "easy"

		entries = {
			testprofile: (
				self.buildProfileLine(badfile, 0o640),
			)
		}

		self.addProfileEntries(entries)

		self.switchSystemProfile(testprofile)
		code, lines = self.applySystemProfile()

		# like in the other cases, don't check the exit code, rely on
		# output parsing
		messages = self.extractMessagesFromChkstat(lines, badfile)
		needle = "world-writable"
		found_rejection = False

		for message in messages[badfile]:
			if message.find(needle) != -1:
				print("found rejection message")
				found_rejection = True
				break

		if not found_rejection:
			self.printError("world-writable file", badfile, "was not rejected")
			return

		self.assertMode(badfile, 0o666)

class TestRejectInsecurePath(TestBase):

	def __init__(self):
		super().__init__("TestRejectInsecurePath", "checks whether paths with insecure inter-mediate ownership are rejected")

	def run(self):

		# to construct this we need a deeper directory hierarchy
		# constructed via bind-mounts, since we can't directly chown()
		# anything

		bind_mountpoints = []
		testroot = self.createAndGetTestDir(0o755)
		testpath = os.path.join( testroot, "middle" )
		self.createTestDir( testpath, 0o755)
		# this will make the path seemingly owned by "nobody"
		self.m_main_test_instance.bindMount("/usr/share", testpath)
		bind_mountpoints.append(testpath)
		# now get our own tmp directory into the game again, seemingly
		# owned by "root"
		testpath = os.path.join( testpath, "man" )
		self.m_main_test_instance.bindMount("/tmp", testpath)
		bind_mountpoints.append(testpath)
		testpath = os.path.join( testpath, "somefile" )
		self.createTestFile( testpath, 0o644 )

		testprofile = "easy"

		entries = {
			testprofile: (
				self.buildProfileLine(testpath, 0o400),
			)
		}

		try:
			self.addProfileEntries(entries)
			self.switchSystemProfile(testprofile)
			code, lines = self.applySystemProfile()
			# make sure the mode really didn't change, before bind
			# mounts are removed again
			self.assertMode(testpath, 0o644)
		finally:
			bind_mountpoints.reverse()
			for mp in bind_mountpoints:
				self.m_main_test_instance.unmount(mp)

		messages = self.extractMessagesFromChkstat(lines, testpath)
		needle = "on an insecure path"
		found_rejection = False

		for message in messages[testpath]:
			if message.find(needle) != -1:
				found_rejection = True
				print("found rejection message")
				break

		if not found_rejection:
			self.printError("insecure path", testpath, "was not rejected")
			return

class TestUnknownOwnership(TestBase):

	def __init__(self):

		super().__init__("TestUnknownOwnership", "checks whether config entries for unknown user/group are rejected")

	def run(self):

		testroot = self.createAndGetTestDir(0o755)
		username = "bad_user"
		groupname = "bad_group"
		baduser_file = os.path.join( testroot, username )
		badgroup_file = os.path.join( testroot, groupname )
		self.createTestFile(baduser_file, 0o400)
		self.createTestFile(badgroup_file, 0o400)

		testprofile = "easy"

		entries = {
			testprofile: (
				self.buildProfileLine(baduser_file, 0o500, owner = username),
				self.buildProfileLine(badgroup_file, 0o600, group = groupname)
			)
		}

		self.addProfileEntries(entries)
		self.switchSystemProfile(testprofile)
		code, lines = self.applySystemProfile()

		messages = self.extractMessagesFromChkstat(lines, (baduser_file, badgroup_file))

		found_baduser_report = False
		baduser_needle = "unknown user {}".format(username)

		for message in messages[baduser_file]:
			if message.find(baduser_needle) != -1:
				found_baduser_report = True
				break

		found_badgroup_report = False
		badgroup_needle = "unknown group {}".format(groupname)

		for message in messages[badgroup_file]:
			if message.find(badgroup_needle) != -1:
				found_badgroup_report = True
				break

		print(baduser_file, "rejected =", found_baduser_report)
		print(badgroup_file, "rejected =", found_badgroup_report)

		if not found_baduser_report or not found_badgroup_report:
			self.printError("bad user and/or group were not rejected")
			return

		# make sure the mode really didn't change
		self.assertMode(baduser_file, 0o400)
		self.assertMode(badgroup_file, 0o400)

test = ChkstatRegtest()
res = test.run((
		TestCorrectMode,
		TestBasePermissions,
		TestPackagePermissions,
		TestLocalPermissions,
		TestDefaultProfile,
		TestForceProfile,
		TestWarnMode,
		TestExamineSwitch,
		TestRootSwitch,
		TestFilesSwitch,
		TestCapabilities,
		TestUnexpectedPathOwner,
		TestRejectWorldWritable,
		TestRejectInsecurePath,
		TestUnknownOwnership
	))
sys.exit(res)
