#!/usr/bin/python3

# sorry, I'm a Python PEP outlaw
# vim: ts=8 noet sw=8 sts=8 :

import os
import sys
import subprocess
import shutil
import argparse
import glob
import io
import traceback
import pwd
import grp
import stat

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
#
# for being able to inspect what is going on within the fake root if things go
# bad you can use the `--enter-fakeroot` or `--on-error-enter-shell` options.
#
# another positive thing is that we're basically operating on our own tmpfs
# within the user-/mount namespace, we don't even need to clean a tmp
# directory up, once the test terminates the mount namespace along with its
# tmpfs mounts will be destroyed.

class ChkstatRegtest:

	def __init__(self):

		self.setupArgParser()

		perm_root = os.path.realpath(__file__).split(os.path.sep)[:-2]
		self.m_permissions_repo = os.path.sep.join(perm_root)
		self.m_chkstat_bin = os.path.sep.join([self.m_permissions_repo, "src/chkstat"])

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
		print(text, end = '')
		print('-' * (len(text) - 1))

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

		for Test in tests:

			test = Test()

			if self.m_args.test and test.getName() != self.m_args.test:
				continue

			tests_run += 1

			self.printHeading("Running", test.getName())
			print()
			test.prepare()
			try:
				test.run()
				failed = test.getResult() != 0
			except Exception as e:
				self.printException(e)
				failed = True

			if failed:
				tests_failed += 1
				print("Test FAILED")
				if self.m_args.on_error_enter_shell:
					print("Entering shell after failed test")
					self.enterShell()

		if self.m_args.test and tests_run == 0:
			print("No such test", self.m_args.test)

		print(str(tests_run).rjust(2), "tests run")
		print(str(tests_failed).rjust(2), "tests failed")

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

	def getProfilePath(self, profile):
		if not profile:
			return self.m_permissions_base
		return '.'.join((self.m_permissions_base, profile))

	def getName(self):
		return self.m_test_name

	def getResult(self):
		return self.m_result

	def setResult(self, code):
		self.m_result = code

	def createAndGetTestDir(self, mode):
		d = "/{}".format(self.getName())
		os.mkdir(d, mode)
		return d

	def createTestFile(self, path, mode):
		with open(path, 'w') as _file:
			os.fchmod(_file.fileno(), mode)

	def getDescription(self):
		return self.m_test_desc

	def prepare(self):
		if not self.global_init_performed:
			# make sure certain dirs exist
			os.makedirs(self.m_sysconfig, 0o755, exist_ok = True)
			os.makedirs(self.m_permissions_dir, 0o755, exist_ok = True)
			self.global_init_performed = True

		self.resetConfigs()

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

	def buildProfileLine(self, path, mode, owner = "root", group = "root"):
		return "{} {}:{} {}".format(
			path, owner, group,
			format(mode, '04o')
		)

	def createSecuritySysconfig(self, permissions_val):
		"""Creates a /etc/sysconfig/security configuration using the
		given configuration values.

		:param str permissions_val: the value for the PERMISSION_SECURITY
		                            setting. e.g. "easy local"
		"""

		permissions_key = "PERMISSION_SECURITY"

		if '"' in permissions_val:
			raise Exception("{} must not contain quotes".format(
				permissions_key
			))

		with open(self.m_sysconfig_security, 'w') as sec_file:
			sec_file.write("{}=\"{}\"\n".format(
				permissions_key,
				permissions_val
			))

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

		print("FAILURE:", *args, **kwargs)

	def assertMode(self, path, expected):
		s = os.stat(path)
		actual = self.extractPerms(s)

		if actual != expected:
			self.printError("{}: expected mode {} but encountered mode {}".format(
				path, str(oct(expected)), str(oct(actual))
			))
			self.setResult(1)

	def callChkstat(self, args):

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

		while True:
			line = proc.stdout.readline()
			if not line:
				break

			line = line.decode('utf8')

			print('> {}'.format(line), end = '')

		return proc.wait()

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

		for profile in modes:
			lines = entries.setdefault(profile, [])
			perms = modes[profile]
			for path, mode in ( (testdir, perms[0]), (testfile, perms[1])):
				lines.append( self.buildProfileLine(path, mode) )

		self.addProfileEntries(entries)

		for profile, entries in entries.items():

			for p in testpaths:
				self.printMode(p)

			print("Switching to", profile, "profile")
			# configure the given profile as default
			self.createSecuritySysconfig(profile)

			self.callChkstat("--system")

			for path, mode in zip(testpaths, modes[profile]):
				self.assertMode(path, mode)

			print()

test = ChkstatRegtest()
res = test.run((
		TestCorrectMode,
	))
sys.exit(res)
