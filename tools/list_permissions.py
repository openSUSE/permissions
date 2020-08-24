#!/usr/bin/python3

# vim: ts=8 noet sw=8 sts=8 :

import argparse
from pathlib import Path

parser = argparse.ArgumentParser("list assembled permissions profile information for individual paths")
parser.add_argument("-p", "--path", type=str, help = "list only information about the given path")

repo_root = (Path(__file__).parent.parent).resolve()
profile_dir = repo_root / "profiles"
etc_dir = repo_root / "etc"

PROFILE_SUFFIXES = ("easy", "secure", "paranoid")

class ProfileParser:

	def __init__(self, paths):
		self.m_paths = paths
		# a dictionary like
		# {
		#   "/some/path": {
		#       "permissions.secure": {
		#             "comments": ["# some comment", ...],
		#             "config": [ "/some/path user:group 0441", "+capability ..." ],
		#       ...
		#   },
		#   ...
		# }
		self.m_entries = {}

	def parse(self):
		for path in self.m_paths:
			label = path.name

			with open(path) as fd:
				self._parseFile(fd, label)

	def _getDictEntry(self, path, label):
		path_entries = self.m_entries.setdefault(path, {})
		return path_entries.setdefault(label, {})

	def _parseFile(self, fd, label):

		comments = []
		current_path = None

		for line in fd.readlines():

			line = line.strip()

			if line.startswith("#"):
				# keep track of a comment block header before
				# a path line appears. empty/other lines cause
				# comment blocks to be reset in the else
				# branch.
				# Also skip empty comment lines.
				if line != "#":
					comments.append(line)
			elif line.startswith("/"):
				path, config = line.split(None, 1)
				current_path = path

				entry = self._getDictEntry(path, label)
				entry["comments"] = comments
				comments = []

				lines = entry.setdefault("config", [])
				lines.append(config)
			elif line.startswith("+"):
				entry = self._getDictEntry(current_path, label)
				entry["config"].append(line)
			else:
				comments = []
				current_path = None

	def getEntries(self):
		return self.m_entries

	def getMaxLabelLen(self):
		return max( len(str(label.name)) for label in self.m_paths )

def extractCommonComments(profiles):
	# merge comments for different profiles if they are present and equal
	ret = []
	while True:
		comments = { entry["comments"][0] if entry["comments"] else "" for entry in profiles.values() }
		line = comments.pop() if len(comments) == 1 else ""
		if line:
			ret.append(line)
			for profile in profiles:
				profiles[profile]["comments"].pop(0)
		else:
			return ret

args = parser.parse_args()

profiles = [profile_dir / "permissions.{}".format(profile) for profile in PROFILE_SUFFIXES]
fixed_config = etc_dir / "permissions"

pp = ProfileParser([fixed_config] + profiles)
pp.parse()

max_label_len = pp.getMaxLabelLen()

for path, profiles in pp.getEntries().items():
	# apply filtering logic from command line
	if args.path and path != args.path:
		continue

	print(path + "\n")

	common_comments = extractCommonComments(profiles)

	if common_comments:
		for comment in common_comments:
			print("\t" + comment)
		print()

	for i, profile in enumerate(profiles):
		entry = profiles[profile]

		for line in entry["comments"]:
			print("\t" + line)

		print("\t" + profile.ljust(max_label_len), end = '')

		# if the config is equal to the previous profile's then don't
		# print it again, to avoid printing redundant information
		if i > 0 and list(profiles.values())[i-1]["config"] == entry["config"]:
			print("\t\t*")
			continue

		# merge the config into a single line to allow for a simpler
		# output structure with a single line per profile
		config = ' '.join(entry["config"])
		print("\t\t" + config)
	print()

