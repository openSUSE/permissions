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

Chkstat::Chkstat(const CmdlineArgs &args) :
            m_args{args},
            m_apply_changes{args.apply_changes.getValue()},
            m_profile_parser{m_args, m_variable_expansions},
            m_euid{geteuid()},
            m_egid{getegid()} {
}

bool Chkstat::processArguments() {
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

bool Chkstat::parseSysconfig() {
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

ProcMountState Chkstat::procState() const {
    auto ret = ProcMountState::UNAVAIL;

    if (secure_getenv("CHKSTAT_PRETEND_NO_PROC") != nullptr) {
        return ret;
    }

    struct statfs proc;
    int r = statfs("/proc", &proc);

    if (r == 0 && proc.f_type == PROC_SUPER_MAGIC) {
        ret = ProcMountState::AVAIL;
    }

    return ret;
}

void Chkstat::printHeader() {
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

void Chkstat::printEntryDifferences(const ProfileEntry &entry, const EntryContext &ctx) const {
    std::cout << ctx.subpath << ": "
        << (m_apply_changes ? "setting to " : "should be ")
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

bool Chkstat::getCapabilities(const ProfileEntry &entry, EntryContext &ctx) {

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
        if (m_args.verbose.isSet()) {
            std::cerr << ctx.subpath << ": unknown user " << entry.owner << ". ignoring entry." << std::endl;
        }
    }

    if (grp) {
        ctx.gid = grp->gr_gid;
    } else if (stringToUnsigned(entry.group, ctx.gid)) {
        // it's a numerical value, lets try it
    } else {
        good = false;
        if (m_args.verbose.isSet()) {
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
    const auto &altroot = m_args.root_path.getValue();
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

    m_proc_mount_avail = procState();

    if (m_apply_changes && !haveProc()) {
        std::cerr << "ERROR: /proc is not available - unable to fix policy violations. Will continue in warn-only mode." << std::endl;
        errors++;
        m_apply_changes = false;
    }

    for (auto& [path, entry]: m_profile_parser.entries()) {
        EntryContext ctx;
        ctx.subpath = entry.file.substr(m_args.root_path.getValue().length());

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
        if (haveProc()) {
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

        if (!m_apply_changes)
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

        if (auto ret = args.parse(argc, argv); ret != 0) {
            return ret;
        }

        Chkstat chkstat{args};
        return chkstat.run();
    } catch (const std::exception &ex) {
        std::cerr << "exception occurred: " << ex.what() << std::endl;
        return 1;
    }
}

// vim: et ts=4 sts=4 sw=4 :
