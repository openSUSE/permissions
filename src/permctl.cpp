/* Copyright (c) 2020, 2024 SUSE LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING); if not, write to the
 * Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA
 *
 ****************************************************************
 */

#include <errno.h>
#include <linux/magic.h>
#include <sys/param.h>
#include <sys/vfs.h>
#include <unistd.h>

// local headers
#include "permctl.h"
#include "entryproc.h"
#include "environment.h"
#include "formatting.h"
#include "utility.h"

// C++
#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>

namespace {
    bool allowNoProc() {
        for (const auto envvar: ENVVARS_ALLOW_NO_PROC) {
            if (::secure_getenv(envvar) != nullptr) {
                return true;
            }
        }

        return false;
    }
}

PermCtl::PermCtl(const CmdlineArgs &args) :
            m_args{args},
            m_have_proc{isProcMounted()},
            m_apply_changes{args.apply_changes.getValue()},
            m_allow_no_proc{allowNoProc()},
            m_profile_parser{m_args, m_variable_expansions} {
}

bool PermCtl::processArguments() {
    for (auto path: m_args.examine_paths.getValue()) {
        stripTrailingSlashes(path);
        m_files_to_check.insert(path);
    }

    for (const auto &path: m_args.file_lists.getValue()) {
        std::ifstream fs(path);

        if (!fs) {
            std::cerr << m_args.file_lists.getName() << ": " << path << ": " << std::strerror(errno) << std::endl;
            return false;
        }

        std::string line;

        while (std::getline(fs, line)) {
            if (line.empty())
                continue;
            stripTrailingSlashes(line);
            m_files_to_check.insert(line);
        }
    }

    return true;
}

bool PermCtl::parseSysconfig() {
    auto stripQuotes = [](std::string s) -> std::string {
        strip(s, [](char c) { return c == '"' || c == '\''; });
        return s;
    };

    const auto file = m_args.config_root_path.getValue() + "/etc/sysconfig/security";
    std::ifstream fs(file);

    if (!fs) {
        // NOTE: the original code tolerated this situation and continued.
        // A system would need to be very broken to get here, therefore make
        // it an error condition instead.
        std::cerr << "error opening " << file << ": " << std::strerror(errno) << std::endl;
        return false;
    }

    std::string line;
    size_t linenr = 0;

    while (std::getline(fs, line)) {
        linenr++;
        strip(line);

        if (line.empty() || line[0] == '#')
            continue;

        const auto sep = line.find_first_of('=');
        if (sep == line.npos) {
            // syntax error?
            std::cerr << file << ":" << linenr << ": parse error in '" << line << "'" << std::endl;
            continue;
        }

        const auto key = line.substr(0, sep);
        const auto value = stripQuotes(line.substr(sep + 1));

        if (key == "PERMISSION_SECURITY") {
            if (m_args.force_level_list.isSet())
                // explicit levels are specified on the command line
                continue;

            std::vector<std::string> profiles;
            splitWords(value, profiles);

            for (const auto &profile: profiles) {
                if (profile != "local" && !profile.empty()) {
                    addProfile(profile);
                }
            }
        } else if (key == "PERMISSION_FSCAPS") {
            if (value == "yes") {
                m_profile_parser.setUseFsCaps(true);
            } else if (value == "no") {
                m_profile_parser.setUseFsCaps(false);
            } else if (!value.empty()) {
                // NOTE: this was not a warning/error condition in the original code
                std::cerr << file << ":" << linenr << ": invalid value for " << key << " (expected 'yes' or 'no'). Falling back to default value." << std::endl;
            }
        }
    }

    return true;
}

void PermCtl::addProfile(const std::string &name) {
    for (const auto &profile: m_profiles) {
        if (profile == name)
            // already exists
            return;
    }

    m_profiles.push_back(name);
}

bool PermCtl::tryOpenProfile(const std::string &path) {
    std::ifstream stream{path};

    if (!stream.is_open())
        return false;

    m_profile_streams.emplace_back(std::make_pair(path, std::move(stream)));
    return true;
}

void PermCtl::collectProfilePaths() {
    /*
     * Since configuration files are in the process of being separated between
     * stock configuration files in /usr and editable configuration files in
     * /etc we employ a backward compatibility logic here that prefers files
     * in /usr but also recognizes files in /etc as a fallback.
     */
    const auto usr_root = getUsrRoot();
    const auto etc_root = getEtcRoot();

    // first add the central fixed permissions file
    for (const auto &dir: {usr_root, etc_root}) {
        const auto path = dir + "/permissions";
        if (tryOpenProfile(path))
            // only use the first one found
            break;
    }

    // continue with predefined well-known profiles
    for (const auto &profile: m_profiles) {
        if (!matchesAny(profile, PREDEFINED_PROFILES))
            continue;

        const auto base = std::string("/permissions.") + profile;

        for (const auto &dir: {usr_root, etc_root}) {
            std::string path = dir + base;
            if (tryOpenProfile(path)) {
                // only use the first one found
                break;
            }
        }
    }

    // make sure to start a fresh collection in collectPackageProfilePaths()
    m_package_profiles_seen.clear();

    // move on to package specific permissions
    // these files are owned by the individual packages
    // therefore while files are being moved from /etc to /usr we need to
    // consider both locations. The /usr location is preferred, though, i.e.
    // if a package has files in /usr then possible duplicate conflicting
    // files in /etc are ignored by collectPackageProfilePaths().
    for (const auto &dir: {
            // this should be used for newly added files
            usr_root + "/packages.d",
            // legacy using a bad name
            usr_root + "/permissions.d",
            // legacy still in /etc
            etc_root + "/permissions.d"}) {
        try {
            collectPackageProfilePaths(dir);
        } catch (const std::filesystem::filesystem_error &ex) {
            if (ex.code().value() != ENOENT) {
                throw;
            }
        }
    }

    // finally add user defined permissions including 'local'
    // these should *only* be found in the /etc area.
    for (const auto &profile: m_profiles) {
        if (matchesAny(profile, PREDEFINED_PROFILES))
            continue;

        const auto profile_path = etc_root + "/permissions." + profile;

        tryOpenProfile(profile_path);
    }
}

void PermCtl::collectPackageProfilePaths(const std::string &dir) {
    // First collect a sorted set of base files, skipping unwanted files like
    // backup files or specific profile files. Therefore filter out duplicates
    // using the sorted set.
    std::set<std::string> files;

    for (const auto &entry: std::filesystem::directory_iterator(dir)) {
        if (!entry.is_regular_file())
            continue;

        const auto &basename = entry.path().filename().string();

        bool found_suffix = false;

        /* filter out backup files */
        for (const auto &suffix: {"~", ".rpmnew", ".rpmsave"}) {
            if (hasSuffix(basename, suffix)) {
                found_suffix = true;
                break;
            }
        }

        if (found_suffix)
            continue;

        files.insert(basename);
    }

    // now add the sorted set of files to the profile paths to process later on
    for (const auto &file: files) {
        if (file.find_first_of('.') != file.npos)
            // we're only interested in base profiles
            continue;

        if (m_package_profiles_seen.find(file) != m_package_profiles_seen.end())
            // per-package profiles for this package have already been
            // processed in a location of higher priority. Ignore these
            // duplicate files.
            continue;

        m_package_profiles_seen.insert(file);

        const auto path = dir + "/" + file;

        tryOpenProfile(path);

        /*
         * this is a bit of strange logic here, because we need to add the per
         * package profile files in the order as the profiles appear in m_profiles.
         */
        for (const auto &profile: m_profiles) {
            const auto profile_basename = file + "." + profile;

            if (files.find(profile_basename) != files.end()) {
                tryOpenProfile(path + "." + profile);
            }
        }
    }
}

bool PermCtl::isProcMounted() const {
    if (secure_getenv(ENVVAR_PRETEND_NO_PROC) != nullptr) {
        return false;
    }

    struct statfs proc;
    int r = statfs("/proc", &proc);

    if (r == 0 && proc.f_type == PROC_SUPER_MAGIC) {
        return true;
    }

    return false;
}

void PermCtl::printHeader() {
    if (m_args.no_header.isSet())
        return;

    std::cout << "Checking permissions and ownerships - using the permissions files" << std::endl;

    for (const auto &pair: m_profile_streams) {
        std::cout << "\t" << pair.first << "\n";
    }

    if (!m_args.root_path.getValue().empty()) {
        std::cout << "Using root " << m_args.root_path.getValue() << "\n";
    }
}

int PermCtl::processEntries() {
    size_t errors = 0;
    size_t bad_entries = 0;

    if (m_apply_changes && !m_have_proc) {
        if (m_allow_no_proc) {
            std::cerr << "WARNING: /proc is not available, continuing in insecure mode because " << ENVVARS_ALLOW_NO_PROC[0] << " is set." << std::endl;
        } else {
            std::cerr << "ERROR: /proc is not available - unable to fix policy violations. Will continue in warn-only mode." << std::endl;
            errors++;
            m_apply_changes = false;
        }
    }

    if (!m_have_proc && !m_allow_no_proc) {
        assert(!m_apply_changes);
    }
    for (const auto& [path, entry]: m_profile_parser.entries()) {

        EntryProcessor processor{entry, m_args, m_apply_changes};

        if (!needToCheck(processor.path()))
            continue;

        if (const auto res = processor.process(m_have_proc); res == EntryProcessor::Result::FAILED)
            errors++;
        else if (res == EntryProcessor::Result::ENTRY_BAD)
            bad_entries++;
    }

    if (errors) {
        std::cerr << "ERROR: not all operations were successful." << std::endl;
        return 1;
    } else if (bad_entries && !m_apply_changes) {
        // indicate that entries need fixing if m_args.only_warn is set.
        return 2;
    }

    return 0;
}

int PermCtl::run() {
    if (!processArguments())
        return 1;

    m_variable_expansions.load(getUsrRoot());

    if (m_args.print_variables.isSet()) {
        for (const auto& [var, values]: m_variable_expansions.expansions()) {
            std::cout << var << ":\n";
            for (const auto &val: values) {
                std::cout << "- " << val << "\n";
            }
        }
        return 0;
    }

    if (m_args.system_mode.isSet()) {
        // this overrides --set
        m_apply_changes = m_args.only_warn.isSet() ? false : true;
        if (!parseSysconfig())
            // NOTE: the original code considers this a non-error situation
            return 0;

        if (m_args.force_level_list.isSet()) {
            std::vector<std::string> profiles;
            splitWords(m_args.force_level_list.getValue(), profiles);

            for (const auto &profile: profiles) {
                addProfile(profile);
            }
        }

        if (m_profiles.empty()) {
            addProfile("secure");
        }

        // always add the local profile
        addProfile("local");

        for (auto path: m_args.input_args.getValue()) {
            stripTrailingSlashes(path);
            m_files_to_check.insert(path);
        }

        collectProfilePaths();
    } else {
        // only process the profiles specified on the command line
        for (const auto &path: m_args.input_args.getValue()) {
            tryOpenProfile(path);
        }
    }

    // apply possible command line overrides to force en-/disable fscaps
    if (m_args.force_fscaps.isSet()) {
        m_profile_parser.setUseFsCaps(true);
    } else if (m_args.disable_fscaps.isSet()) {
        m_profile_parser.setUseFsCaps(false);
    }

    for (auto &pair: m_profile_streams) {
        m_profile_parser.parse(pair.first, pair.second);
    }

    // check whether explicitly listed files are actually configured in profiles
    for (const auto &path: m_files_to_check) {
        if (!m_profile_parser.existsEntry(path)) {
            std::cerr << path << ": no configuration entry in active permission profiles found. Cannot check this path." << std::endl;
        }
    }

    printHeader();

    return processEntries();
}

int main(int argc, const char **argv) {
    try {
        CmdlineArgs args;

        if (std::string_view{argv[0]}.find("chkstat") != std::string_view::npos) {
            if (::isatty(STDOUT_FILENO) == 1) {
                std::cerr << "WARNING: `chkstat` has been renamed to `permctl`." << "\n";
            }
        }

        if (auto ret = args.parse(argc, argv); ret != 0) {
            return ret;
        }

        PermCtl permctl{args};
        return permctl.run();
    } catch (const std::exception &ex) {
        std::cerr << "exception occurred: " << ex.what() << std::endl;
        return 1;
    }
}

// vim: et ts=4 sts=4 sw=4 :
