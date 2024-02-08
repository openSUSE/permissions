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

#ifndef _GNU_SOURCE
#   define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/magic.h>
#include <pwd.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

// local headers
#include "chkstat.h"
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

    inline void stripTrailingSlashes(std::string &s) {
        rstrip(s, [](char c) { return c == '/'; });
    }

}

Chkstat::Chkstat(int argc, const char **argv) :
        m_argc{argc},
        m_argv{argv},
        m_parser{"Tool to check and set file permissions"},
        m_system_mode{"", "system", "system mode, act according to /etc/sysconfig/security", m_parser},
        m_force_fscaps{"", "fscaps", "force use of file system capabilities", m_parser},
        m_disable_fscaps{"", "no-fscaps", "disable use of file system capabilities", m_parser},
        m_apply_changes{"s", "set", "actually apply changes (--system mode may imply this depending on file based configuration)", m_parser},
        m_only_warn{"", "warn", "only inform about which changes would be performed but don't actually apply them (which is the default, except in --system mode)", m_parser},
        m_no_header{"n", "noheader", "don't print intro message", m_parser},
        m_verbose{"v", "verbose", "print additional output that might be useful for diagnosis", m_parser},
        m_print_variables{"", "print-variables", "print supported profile variable mappings then exit", m_parser},
        m_examine_paths{"e", "examine", "operate only on the specified path(s)", false, "PATH", m_parser},
        m_force_level_list{"", "level", "force application of the specified space-separated list of security levels (only supported in --system mode)", false, "", "e.g. \"local paranoid\"", m_parser},
        m_file_lists{"f", "files", "read newline separated list of files to check (see --examine) from the specified path", false, "PATH", m_parser},
        m_root_path{"r", "root", "check files relative to the given root directory", false, "", "PATH", m_parser},
        m_config_root_path{"", "config-root", "lookup configuration files relative to the given root directory", false, "", "PATH", m_parser},
        m_input_args{"args", "in --system mode a list of paths to check, otherwise a list of profiles to parse", false, "PATH", m_parser},
        m_euid{geteuid()},
        m_egid{getegid()} {
}

bool Chkstat::validateArguments() {
    // exits on error/usage
    m_parser.parse(m_argc, m_argv);

    // in this case ignore all the rest, we'll just print the variables
    if (m_print_variables.isSet())
        return true;

    // check all parameters and only then return to provide full diagnostic to
    // the user, not just bit by bit complaining.
    bool ret = true;

    // check for mutually exclusive command line arguments
    const auto xor_args = {
        std::make_pair(&m_force_fscaps, &m_disable_fscaps),
        {&m_apply_changes, &m_only_warn}
    };

    for (const auto &args: xor_args) {
        auto &arg1 = *args.first;
        auto &arg2 = *args.second;

        if (arg1.isSet() && arg2.isSet()) {
            std::cerr << arg1.getName() << " and " << arg2.getName()
                << " cannot be set at the same time\n";
            ret = false;
        }
    }

    if (!m_system_mode.isSet() && m_input_args.getValue().empty()) {
        std::cerr << "one or more permission file paths to use are required\n";
        ret = false;
    }

    for (const auto arg: {&m_root_path, &m_config_root_path}) {
        if (!arg->isSet())
            continue;

        auto &path = arg->getValue();

        if (path.empty() || path[0] != '/') {
            std::cerr << arg->getName() << " must begin with '/'" << std::endl;
            ret = false;
        }

        // remove trailing slashes to normalize arguments
        stripTrailingSlashes(path);
    }

    return ret;
}

bool Chkstat::processArguments() {
    for (auto path: m_examine_paths.getValue()) {
        stripTrailingSlashes(path);
        m_files_to_check.insert(path);
    }

    for (const auto &path: m_file_lists.getValue()) {
        std::ifstream fs(path);

        if (!fs) {
            std::cerr << m_file_lists.getName() << ": " << path << ": " << std::strerror(errno) << std::endl;
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

static inline void stripQuotes(std::string &s) {
    strip(s, [](char c) { return c == '"' || c == '\''; });
}

bool Chkstat::parseSysconfig() {
    const auto file = m_config_root_path.getValue() + "/etc/sysconfig/security";
    std::ifstream fs(file);

    if (!fs) {
        // NOTE: the original code tolerated this situation and continued
        // A system would need to be very broken to get here, therefore make
        // it an error condition instead.
        std::cerr << "error opening " << file << ": " << std::strerror(errno) << std::endl;
        return false;
    }

    std::string line;
    size_t linenr = 0;
    bool check_permissions = true;

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

        auto key = line.substr(0, sep);
        auto value = line.substr(sep + 1);
        stripQuotes(value);

        if (key == "PERMISSION_SECURITY") {
            if (m_force_level_list.isSet())
                // explicit levels are specified on the command line
                continue;

            std::vector<std::string> profiles;
            splitWords(value, profiles);

            for (const auto &profile: profiles) {
                if (profile != "local" && !profile.empty()) {
                    addProfile(profile);
                }
            }
        }
        // REMOVEME:
        // this setting was last seen in the config file template in SLE-11
        // but we still support it in the code. The logic behind it is quite
        // complex since it is interlocked with the command line settings
        // (also see logic after the while loop).
        else if (key == "CHECK_PERMISSIONS") {
            if (value == "set") {
                check_permissions = true;
            } else if (value == "no" || value.empty()) {
                check_permissions = false;
            } else if (value != "warn") {
                std::cerr << file << ":" << linenr << ": invalid value for " << key << " (expected 'set', 'no' or 'warn'). Falling back to default value." << std::endl;
            }
        }
        else if (key == "PERMISSION_FSCAPS") {
            if (value == "yes") {
                m_use_fscaps = true;
            } else if (value == "no") {
                m_use_fscaps = false;
            } else if (!value.empty()) {
                // NOTE: this was not a warning/error condition in the
                // original code
                std::cerr << file << ":" << linenr << ": invalid value for " << key << " (expected 'yes' or 'no'). Falling back to default value." << std::endl;
            }
        }
    }

    // apply the complex CHECK_PERMISSIONS logic
    if (!m_apply_changes.isSet() && !m_only_warn.isSet()) {
        if (check_permissions) {
            m_apply_changes.setValue(true);
        } else {
            std::cerr << "permissions handling disabled in " << file << std::endl;
            return false;
        }
    }

    return true;
}

bool Chkstat::checkFsCapsSupport() const {
    // REMOVEME: this check is really old and should be dropped, today's
    // kernels all support capabilities.

    /* check kernel capability support /sys/kernel/fscaps, 2.6.39 */
    std::ifstream fs("/sys/kernel/fscaps");

    if (!fs) {
        // if the file doesn't exist then there's probably no support for it
        return false;
    }

    size_t val = 0;
    fs >> val;

    if (fs.fail()) {
        return false;
    }

    return val == 1;
}

void Chkstat::addProfile(const std::string &name) {
    for (const auto &profile: m_profiles) {
        if (profile == name)
            // already exists
            return;
    }

    m_profiles.push_back(name);
}

bool Chkstat::tryOpenProfile(const std::string &path) {
    std::ifstream stream{path};

    if (!stream.is_open())
        return false;

    m_profile_streams.emplace_back(std::make_pair(path, std::move(stream)));
    return true;
}

void Chkstat::collectProfilePaths() {
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

void Chkstat::collectPackageProfilePaths(const std::string &dir) {
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
            // processed in a location of higher priority. ignore these
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

ProfileEntry&
Chkstat::addProfileEntry(const std::string &file, const std::string &owner, const std::string &group, mode_t mode) {
    // use the full path including a potential alternative root directory as
    // map key
    std::string path = m_root_path.getValue();
    if (!path.empty()) {
        path += '/';
    }
    path += file;

    // this overwrites a possibly already existing entry
    // this is intended behaviour, hence the order in which profiles are
    // applied is important
    return m_profile_entries[path] = ProfileEntry{path, owner, group, mode};
}

static inline void badProfileLine(const std::string &file, const size_t line, const std::string &context) {
    std::cerr << file << ":" << line << ": syntax error in permissions profile (" << context << ")" << std::endl;
}

bool Chkstat::parseCapabilityLine(const std::string &line, const std::vector<std::string> &active_paths) {
    if (!hasPrefix(line, "+capabilities "))
        return false;
    else if (!m_use_fscaps)
        // ignore the content
        return true;

    auto cap_text = line.substr(line.find_first_of(' '));
    if (cap_text.empty())
        // ignore empty capability specification
        return true;

    bool ret = true;

    for (const auto &path: active_paths) {
        auto it = m_profile_entries.find(path);
        if (it == m_profile_entries.end()) {
            std::cerr << "No profile entry for path " << path << "???";
            ret = false;
            continue;
        }

        auto &entry = it->second;

        if (!entry.caps.setFromText(cap_text)) {
            ret = false;
        }
    }

    return ret;
}

void Chkstat::parseProfile(const std::string &path, std::ifstream &fs) {
    size_t linenr = 0;
    std::vector<std::string> active_keys;
    std::string line;
    std::vector<std::string> parts;
    mode_t mode_int;

    // we're parsing lines of the following format here:
    //
    // # comment
    // <path> <user>:<group> <mode>
    // [+capabilities cap_net_raw=ep]

    while (std::getline(fs, line)) {
        linenr++;
        strip(line);

        // don't know exactly why the dollar is also ignored, probably some
        // dark legacy.
        if (line.empty() || line[0] == '#' || line[0] == '$')
            continue;

        // an extra capability line that belongs to the context of the last
        // profile entry seen.
        if (line[0] == '+') {
            if (active_keys.empty()) {
                badProfileLine(path, linenr, "lone capability line");
                continue;
            }

            const auto good = parseCapabilityLine(line, active_keys);

            if (!good) {
                badProfileLine(path, linenr, "bad capability spec or bad +keyword");
            }

            continue;
        }

        // only keep the context for one following non-empty/non-comment line
        // to prevent the context being applied to unintended '+' lines in
        // case of parsing errors later on.
        active_keys.clear();

        splitWords(line, parts);

        if (parts.size() != 3) {
            badProfileLine(path, linenr, "invalid number of whitespace separated words");
            continue;
        }

        const auto &ownership = parts[1];
        std::string user, group;

        // split up user and group from {user}:{group} string. Two different
        // separator types are allowed like with `chmod`
        for (const auto sep: { ':', '.' }) {
            const auto seppos = ownership.find_first_of(sep);
            if (seppos == ownership.npos)
                continue;

            user = ownership.substr(0, seppos);
            group = ownership.substr(seppos + 1);

            break;
        }

        if (user.empty() || group.empty()) {
            badProfileLine(path, linenr, "bad user:group specification");
            continue;
        }

        const auto &location = parts[0];
        const auto &mode = parts[2];

        if (!stringToUnsigned(mode, mode_int, 8) || mode_int > ALLPERMS) {
            badProfileLine(path, linenr, "bad mode specification");
            continue;
        }

        std::vector<std::string> expansions;
        if (!expandProfilePaths(location, expansions)) {
            badProfileLine(path, linenr, "bad variable expansions");
            continue;
        }

        for (const auto &exp_path: expansions) {
            addProfileEntry(exp_path, user, group, mode_int);
            // remember the most recently added entries to allow potential '+'
            // capability lines to be applied to them.
            active_keys.push_back(exp_path);
        }
    }
}

bool Chkstat::expandProfilePaths(const std::string &path, std::vector<std::string> &expansions) {
    std::stringstream ss;
    ss.str(path);
    std::string part;

    // the initial entry
    expansions.clear();
    expansions.push_back("");

    // process each path component.
    //
    // we support variables only as individual
    // path components i.e. something like %{myvar}stuff/suffix is not
    // allowed, only %{myvar}/suffix.
    //
    // multiple variable components in the same path are supported
    while (std::getline(ss, part, '/')) {
        if (hasPrefix(part, "%{") && hasSuffix(part, "}")) {
            // variable found
            const auto variable = part.substr(2, part.length() - 3);
            auto it = m_variable_expansions.find(variable);

            if (it == m_variable_expansions.end()) {
                expansions.clear();
                std::cerr << "Undeclared variable %{" << variable << "} encountered." << std::endl;
                return false;
            }

            // now we need to create additional entries for each possible
            // value of the variable
            std::vector<std::string> new_expansions;

            for (const auto &element: expansions) {
                for (const auto &var_value: it->second) {
                    new_expansions.push_back(element + "/" + var_value);
                }
            }

            expansions = new_expansions;
        } else if (part.empty()) {
            // leading slash, ignore
            continue;
        } else {
            // regular fixed string
            for (auto &element: expansions) {
                element = element + "/" + part;
            }
        }
    }

    return true;
}

bool Chkstat::checkHaveProc() const {
    if (m_proc_mount_avail == ProcMountState::UNKNOWN) {
        m_proc_mount_avail = ProcMountState::UNAVAIL;
        char *pretend_no_proc = secure_getenv("CHKSTAT_PRETEND_NO_PROC");

        struct statfs proc;
        int r = statfs("/proc", &proc);
        if (!pretend_no_proc && r == 0 && proc.f_type == PROC_SUPER_MAGIC) {
            m_proc_mount_avail = ProcMountState::AVAIL;
        }
    }

    return m_proc_mount_avail == ProcMountState::AVAIL;
}

void Chkstat::printHeader() {
    if (m_no_header.isSet())
        return;

    std::cout << "Checking permissions and ownerships - using the permissions files" << std::endl;

    for (const auto &pair: m_profile_streams) {
        std::cout << "\t" << pair.first << "\n";
    }

    if (!m_root_path.getValue().empty()) {
        std::cout << "Using root " << m_root_path.getValue() << "\n";
    }
}

void Chkstat::printEntryDifferences(const ProfileEntry &entry, const EntryContext &ctx) const {
    std::cout << ctx.subpath << ": "
        << (m_apply_changes.isSet() ? "setting to " : "should be ")
        << entry.owner << ":" << entry.group << " "
        << FileModeInt(entry.mode);

    if (ctx.need_fix_caps && entry.hasCaps()) {
        std::cout << " \"" << entry.caps.toText() << "\".";
    }

    bool need_comma = false;

    std::cout << " (";

    if (ctx.need_fix_ownership) {
        std::cout << "wrong owner/group " << FileOwnership(ctx.status);
        need_comma = true;
    }

    if (ctx.need_fix_perms) {
        if (need_comma) {
            std::cout << ", ";
        }
        std::cout << "wrong permissions " << FileModeInt(ctx.status.getModeBits());
        need_comma = true;
    }

    if (ctx.need_fix_caps) {
        if (need_comma) {
            std::cout << ", ";
        }

        if (ctx.caps.hasCaps()) {
            std::cout << "wrong capabilities \"" << ctx.caps.toText() << "\"";
        } else {
            std::cout << "missing capabilities";
        }
    }

    std::cout << ")" << std::endl;
}

bool Chkstat::getCapabilities(ProfileEntry &entry, EntryContext &ctx) {

    if (!ctx.caps.setFromFile(ctx.fd_path)) {
        std::cerr << ctx.subpath << ": " << ctx.caps.lastErrorText() << std::endl;
        return false;
    }

    if (entry.hasCaps()) {
        // don't apply any set*id bits in case we apply capabilities since
        // capabilities are the safer variant of set*id, the set*id bits
        // are only a fallback.
        entry.dropXID();
    }

    return true;
}

bool Chkstat::resolveEntryOwnership(const ProfileEntry &entry, EntryContext &ctx) {
    struct passwd *pwd = getpwnam(entry.owner.c_str());
    struct group *grp = getgrnam(entry.group.c_str());

    bool good = true;

    if (pwd) {
        ctx.uid = pwd->pw_uid;
    } else if (stringToUnsigned(entry.owner, ctx.uid)) {
        // it's a numerical value, lets try it
    } else {
        good = false;
        if (m_verbose.isSet()) {
            std::cerr << ctx.subpath << ": unknown user " << entry.owner << ". ignoring entry." << std::endl;
        }
    }

    if (grp) {
        ctx.gid = grp->gr_gid;
    } else if (stringToUnsigned(entry.group, ctx.gid)) {
        // it's a numerical value, lets try it
    } else {
        good = false;
        if (m_verbose.isSet()) {
            std::cerr << ctx.subpath << ": unknown group " << entry.group << ". ignoring entry." << std::endl;
        }
    }

    return good;
}

bool Chkstat::isSafeToApply(const ProfileEntry &entry, const EntryContext &ctx) const {
    // don't allow high privileges for unusual file types
    if ((entry.hasCaps() || entry.hasSetXID()) && !ctx.status.isRegular() && !ctx.status.isDirectory()) {
        std::cerr << ctx.subpath << ": will only assign capabilities or setXid bits to regular files or directories" << std::endl;
        return false;
    }

    // don't give high privileges to files controlled by non-root users
    if (ctx.traversedInsecure()) {
        if (entry.hasCaps() || (entry.mode & S_ISUID) || ((entry.mode & S_ISGID) && ctx.status.isRegular())) {
            std::cerr << ctx.subpath << ": will not give away capabilities or setXid bits on an insecure path" << std::endl;
            return false;
        }
    }

    return true;
}

bool Chkstat::applyChanges(const ProfileEntry &entry, const EntryContext &ctx) const {
    bool ret = true;

    if (ctx.need_fix_ownership) {
        if (chown(ctx.fd_path.c_str(), ctx.uid, ctx.gid) != 0) {
            std::cerr << ctx.subpath << ": chown: " << std::strerror(errno) << std::endl;
            ret = false;
        }
    }

    // also re-apply the mode if we had to change ownership and a setXid
    // bit was set before, since this resets the setXid bit.
    if (ctx.need_fix_perms || (ctx.need_fix_ownership && entry.hasSetXID())) {
        if (chmod(ctx.fd_path.c_str(), entry.mode) != 0) {
            std::cerr << ctx.subpath << ": chmod: " << std::strerror(errno) << std::endl;
            ret = false;
        }
    }

    // chown and - depending on the file system - chmod clear existing capabilities
    // so apply the intended caps even if they were correct previously
    if (entry.hasCaps() || ctx.need_fix_caps) {
        if (ctx.status.isRegular()) {
            // cap_set_file() tries to be helpful and does an lstat() to check that it isn't called on
            // a symlink. So we have to open() it (without O_PATH) and use cap_set_fd().
            FileDesc cap_fd{open(ctx.fd_path.c_str(), O_NOATIME | O_CLOEXEC | O_RDONLY)};
            if (!cap_fd.valid()) {
                std::cerr << ctx.subpath << ": open() for changing capabilities: " << std::strerror(errno) << std::endl;
                ret = false;
            } else if (!entry.caps.applyToFD(cap_fd.get())) {
                // ignore ENODATA when clearing caps - it just means there were no caps to remove
                if (errno != ENODATA || entry.hasCaps()) {
                    std::cerr << ctx.subpath << ": cap_set_fd: " << std::strerror(errno) << std::endl;
                    ret = false;
                }
            }
        } else {
            std::cerr << ctx.subpath << ": cannot set capabilities: not a regular file" << std::endl;
            ret = false;
        }
    }

    return ret;
}

bool Chkstat::safeOpen(EntryContext &ctx) {
    size_t link_count = 0;
    FileDesc pathfd;
    FileDesc parentfd;
    FileStatus root_status;
    bool is_final_path_element = false;
    const auto &altroot = m_root_path.getValue();
    const auto root = altroot.empty() ? std::string("/") : altroot;
    std::string path_rest = ctx.subpath;
    std::string component;

    ctx.traversed_insecure = false;
    ctx.fd.close();

    while (!is_final_path_element) {
        if (pathfd.invalid()) {
            pathfd.set(open(root.c_str(), O_PATH | O_CLOEXEC));

            if (pathfd.invalid()) {
                std::cerr << root << ": failed to open root directory: " << std::strerror(errno) << std::endl;
                return false;
            }

            if (!root_status.fstat(pathfd)) {
                std::cerr << root << ": failed to fstat root directory: " << root << std::endl;
                return false;
            }
            // status and pathfd must be in sync for the root-escape check below
            ctx.status = root_status;
        }

        // make out the leading path component
        assert(path_rest[0] == '/');
        auto sep = path_rest.find_first_of('/', 1);
        component = path_rest.substr(1, sep - 1);
        // strip the leading path component
        path_rest = path_rest.substr(component.length() + 1);
        // path_rest is empty when we reach the final path element
        is_final_path_element = path_rest.empty() || path_rest == "/";
        const bool is_parent_element = !is_final_path_element;

        // multiple consecutive slashes: ignore
        if (is_parent_element && component.empty())
            continue;

        // never move up from the configured root directory (using the stat result from the previous loop iteration)
        if (component == ".." && !altroot.empty() && ctx.status.sameObject(root_status))
            continue;

        {
            // component is an empty string for trailing slashes, open again with different open_flags.
            auto child = component.empty() ? "." : component.c_str();
            int tmpfd = openat(pathfd.get(), child, O_PATH | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
            if (tmpfd == -1) {
                if (errno != ENOENT) {
                    const auto path = getPathFromProc(pathfd) + "/" + child;
                    std::cerr << "warning: skipping " << ctx.subpath << ": " << path << ": openat(): "
                        << std::strerror(errno) << std::endl;
                }
                return false;
            }
            pathfd.set(tmpfd);
        }

        if (!ctx.status.fstat(pathfd)) {
            const auto path = getPathFromProc(pathfd);
            std::cerr << "warning: skipping  " << ctx.subpath << ": " << path << ": fstat(): "
                << std::strerror(errno) << std::endl;
            return false;
        }

        // owner of directories must be trusted for setuid/setgid/capabilities
        // as we have no way to verify file contents
        if (is_parent_element) {
            // the owner needs to be root or our effective UID
            if (!ctx.status.hasSafeOwner({m_euid})) {
                ctx.traversed_insecure = true;
            // if the dir is group-writable then require the root group or our
            // effective GID.
            } else if (!ctx.status.hasSafeGroup({m_egid})) {
                ctx.traversed_insecure = true;
            }
            // path is in a world-writable directory
            else if (!ctx.status.isLink() && ctx.status.isWorldWritable()) {
                ctx.traversed_insecure = true;
            }
        }

        // if the object is owned by non-root, the owner must match the target
        // user (from the profile entry) or our effective user
        if (!ctx.status.hasSafeOwner({ctx.uid,m_euid})) {
            if (is_final_path_element) {
                std::cerr << ctx.subpath << ": has unexpected owner (" << ctx.status.st_uid << "). refusing to correct due to unknown integrity." << std::endl;
                return false;
            } else {
                const auto path = getPathFromProc(pathfd);
                std::cerr << ctx.subpath << ": on an insecure path - " << path << " has different non-root owner who could tamper with the file." << std::endl;
                return false;
            }
        }

        // same goes for the group, if it is writable
        if(!ctx.status.hasSafeGroup({ctx.gid, m_egid})) {
            if (is_final_path_element) {
                std::cerr << ctx.subpath << ": is group-writable and has unexpected group (" << ctx.status.st_gid << "). refusing to correct due to unknown integrity." << std::endl;
                return false;
            }
            else {
                const auto path = getPathFromProc(pathfd);
                std::cerr << ctx.subpath << ": on an insecure path - " << path << " has different non-root group that could tamper with the file." << std::endl;
                return false;
            }
        }

        if (ctx.status.isLink()) {
            // If the path configured in the permissions configuration is a symlink, we don't follow it.
            // This is to emulate legacy behaviour: old insecure versions of chkstat did a simple lstat(path) as 'protection' against malicious symlinks.
            if (is_final_path_element)
               return false;
            else if (++link_count >= 256) {
                const auto path = getPathFromProc(pathfd);
                std::cerr << ctx.subpath << ": excess link count stopping at " << path << "." << std::endl;
                return false;
            }

            // Don't follow symlinks owned by regular users.
            // In theory, we could also trust symlinks where the owner of the target matches the owner
            // of the link, but we're going the simple route for now.
            if (!ctx.status.hasSafeOwner({m_euid}) || !ctx.status.hasSafeGroup({m_egid})) {
                const auto path = getPathFromProc(pathfd);
                std::cerr << ctx.subpath << ": on an insecure path - " << path << " has different non-root owner who could tamper with the file." << std::endl;
                return false;
            }

            std::string link(PATH_MAX, '\0');
            const auto len = ::readlinkat(pathfd.get(), "", &link[0], link.size());

            if (len <= 0 || static_cast<size_t>(len) >= link.size()) {
                auto path = getPathFromProc(pathfd);
                std::cerr << ctx.subpath << ": " << path << ": readlink(): " << std::strerror(errno) << std::endl;
                return false;
            }

            link.resize(static_cast<size_t>(len));
            stripTrailingSlashes(link);

            if (link[0] == '/') {
                // absolute link, need to continue from a new root
                pathfd.close();
            } else {
                // relative link: continue relative to the parent directory

                // we encountered a link directly below /, simply continue
                // from the root again
                if (parentfd.invalid()) {
                    pathfd.close();
                } else {
                    pathfd.set(dup(parentfd.get()));
                }

                // prefix the path with a slash to fulfill the expectations of
                // the loop body (see assert above)
                link.insert(link.begin(), '/');
            }

            path_rest = link + path_rest;
        } else if (ctx.status.isDirectory()) {
            // parentfd is only needed to find the parent of a symlink.
            // We can't encounter links when resolving '.' or '..' so those don't need any special handling.
            parentfd.set(dup(pathfd.get()));
        }
    }

    // world-writable file: error out due to unknown file integrity
    if (ctx.status.isRegular() && ctx.status.isWorldWritable()) {
        std::cerr << ctx.subpath << ": file has insecure permissions (world-writable)" << std::endl;
        return false;
    }

    ctx.fd.steal(pathfd);

    return true;
}

std::string Chkstat::getPathFromProc(const FileDesc &fd) const {
    std::string linkpath(PATH_MAX, '\0');
    auto procpath = std::string("/proc/self/fd/") + std::to_string(fd.get());

    ssize_t l = readlink(procpath.c_str(), &linkpath[0], linkpath.size());
    if (l > 0) {
        linkpath.resize(std::min(static_cast<size_t>(l), linkpath.size()));
    } else {
        linkpath = "ancestor";
    }

    return linkpath;
}

int Chkstat::processEntries() {
    size_t errors = 0;

    if (m_apply_changes.isSet() && !checkHaveProc()) {
        std::cerr << "ERROR: /proc is not available - unable to fix policy violations. Will continue in warn-only mode." << std::endl;
        errors++;
        m_apply_changes.setValue(false);
    }

    // TODO:
    // entry needs to be non-const currently, because further below the
    // getCapabilities() logic is modifying its properties on the fly.
    //
    // This should be changed, ProfileEntry should only represent the data
    // found in the profiles, not data modified by program logic underway.
    for (auto& [path, entry]: m_profile_entries) {
        EntryContext ctx;
        ctx.subpath = entry.file.substr(m_root_path.getValue().length());

        if (!needToCheck(ctx.subpath))
            continue;

        if (!resolveEntryOwnership(entry, ctx))
            continue;

        if (!safeOpen(ctx))
            continue;

        if (!ctx.fd.valid())
            continue;
        else if (ctx.status.isLink())
            continue;

        // fd is opened with O_PATH, file operations like cap_get_fd() and fchown() don't work with it.
        //
        // We also don't want to do a proper open() of the file, since that doesn't even work for sockets
        // and might have side effects for pipes or devices.
        //
        // So we use path-based operations (yes!) with /proc/self/fd/xxx. (Since safe_open already resolved
        // all symlinks, 'fd' can't refer to a symlink which we'd have to worry might get followed.)
        if (checkHaveProc()) {
            ctx.fd_path = std::string("/proc/self/fd/") + std::to_string(ctx.fd.get());
        } else {
            // fall back to plain path-access for read-only operation. (this
            // much is fine)
            // we only report errors below, m_apply_changes is set to false by
            // the logic above.
            ctx.fd_path = entry.file;
        }

        if (!getCapabilities(entry, ctx)) {
            errors++;
        }

        ctx.check(entry);

        if (!ctx.needsFixing())
            // nothing to do
            continue;

        /*
         * first explain the differences between the encountered state of the
         * file and the desired state of the file
         */
        printEntryDifferences(entry, ctx);

        if (!m_apply_changes.isSet())
            continue;

        if (!isSafeToApply(entry, ctx)) {
            errors++;
            continue;
        }

        if (m_euid != 0) {
            // only attempt to change the owner if we're actually privileged
            // to do so (chkstat also supports to run as a regular user within
            // certain limits)
            ctx.need_fix_ownership = false;
        }

        if (!applyChanges(entry, ctx)) {
            errors++;
            continue;
        }
    }

    if (errors) {
        std::cerr << "ERROR: not all operations were successful." << std::endl;
        return 1;
    }

    return 0;
}

int Chkstat::run() {
    if (!validateArguments())
        return 2;

    if (!processArguments())
        return 1;

    loadVariableExpansions();

    if (m_print_variables.isSet()) {
        for (const auto& [var, values]: m_variable_expansions) {
            std::cout << var << ":\n";
            for (const auto &val: values) {
                std::cout << "- " << val << "\n";
            }
        }
        return 0;
    }

    if (m_system_mode.isSet()) {
        if (!parseSysconfig())
            // NOTE: the original code considers this a non-error situation
            return 0;

        if (m_force_level_list.isSet()) {
            std::vector<std::string> profiles;
            splitWords(m_force_level_list.getValue(), profiles);

            for (const auto &profile: profiles) {
                addProfile(profile);
            }
        }

        if (m_profiles.empty()) {
            addProfile("secure");
        }

        // always add the local profile
        addProfile("local");

        for (auto path: m_input_args.getValue()) {
            stripTrailingSlashes(path);
            m_files_to_check.insert(path);
        }

        collectProfilePaths();
    } else {
        // only process the profiles specified on the command line
        for (const auto &path: m_input_args.getValue()) {
            tryOpenProfile(path);
        }
    }

    // apply possible command line overrides to force en-/disable fscaps
    if (m_force_fscaps.isSet()) {
        m_use_fscaps = true;
    } else if (m_disable_fscaps.isSet()) {
        m_use_fscaps = false;
    }

    if (m_use_fscaps && !checkFsCapsSupport()) {
        std::cerr << "Warning: running kernel does not support fscaps" << std::endl;
    }

    for (auto &pair: m_profile_streams) {
        parseProfile(pair.first, pair.second);
    }

    // check whether explicitly listed files are actually configured in
    // profiles
    for (const auto &path: m_files_to_check) {
        auto full_path = path;

        // we need to add a potential alternative root directory, since
        // addProfileEntry stores entries using the full path.
        if (!m_root_path.getValue().empty()) {
            full_path = m_root_path.getValue() + '/' + path;
        }

        if (m_profile_entries.find(full_path) == m_profile_entries.end()) {
            std::cerr << path << ": no configuration entry in active permission profiles found. Cannot check this path." << std::endl;
        }
    }

    printHeader();

    return processEntries();
}

static inline void badVariablesLine(const std::string &file, const size_t line, const std::string &context) {
    std::cerr << file << ":" << line << ": syntax error in variable configuration (" << context << ")" << std::endl;
}

/// Checks that a path variable identifier contains only valid characters.
static inline bool checkValidVariableIdentifier(const std::string &ident) {
    for (auto ch: ident) {
        if (std::isalnum(ch))
            continue;
        else if (ch == '_')
            continue;

        std::cerr << "Invalid characters encountered in variable name '" << ident << "': '" << ch << "'" << std::endl;

        return false;
    }

    return true;
}

/// Normalizes the given list of path variable values.
/**
 *  Unnecessary path separators will be removed from each value.
 **/
static inline void normalizeVariableValues(std::vector<std::string> &values) {
    for (auto &value: values) {
        // remove leading/trailing separators
        strip(value, chkslash);

        // remove consecutive slashes in two passes:
        // - identify indices of repeated slashes
        // - remove indices starting from the end of the string to avoid
        //   shifting index positions.
        char prev_char = 0;
        size_t pos = 0;
        std::vector<size_t> del_indices;

        for (auto ch: value) {
            if (ch == '/' && prev_char == '/')
                del_indices.push_back(pos);
            else
                prev_char = ch;

            pos++;
        }

        for (auto it = del_indices.rbegin(); it != del_indices.rend(); it++) {
            value.erase(*it, 1);
        }
    }
}

void Chkstat::loadVariableExpansions() {
    auto conf_path = getUsrRoot() + "/variables.conf";

    std::ifstream fs(conf_path);

    if (!fs) {
        std::cerr << "warning: couldn't find variable mapping configuration in " << conf_path << ": " << std::strerror(errno) << std::endl;
        return;
    }

    std::vector<std::string> words;
    size_t linenr = 0;
    std::string line;

    while (std::getline(fs, line)) {
        linenr++;
        strip(line);

        if (line.empty() || line[0] == '#')
            continue;

        auto equal_pos = line.find('=');

        if (equal_pos == line.npos) {
            badVariablesLine(conf_path, linenr, "missing '=' assignment");
            continue;
        }

        auto varname = line.substr(0, equal_pos);
        strip(varname);
        if (!checkValidVariableIdentifier(varname)) {
            badVariablesLine(conf_path, linenr, "bad variable identifier");
            continue;
        }

        auto values = line.substr(equal_pos + 1);
        strip(values);

        splitWords(values, words);

        if (words.empty()) {
            badVariablesLine(conf_path, linenr, "empty assignment");
            continue;
        }

        normalizeVariableValues(words);

        // tolerate words.size() == 1, we could emit a warning, but it could
        // be a valid use case.

        if (m_variable_expansions.find(varname) != m_variable_expansions.end()) {
            badVariablesLine(conf_path, linenr, "duplicate variable entry, ignoring");
            continue;
        }

        m_variable_expansions[varname] = words;
    }
}

int main(int argc, const char **argv) {
    try {
        Chkstat chkstat(argc, argv);
        return chkstat.run();
    } catch (const std::exception &ex) {
        std::cerr << "exception occurred: " << ex.what() << std::endl;
        return 1;
    }
}

// vim: et ts=4 sts=4 sw=4 :
