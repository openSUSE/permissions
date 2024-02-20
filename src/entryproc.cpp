// system headers
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <sys/stat.h>

// C++
#include <cassert>

// local headers
#include "entryproc.h"
#include "formatting.h"
#include "utility.h"

const uid_t EntryProcessor::m_euid = ::geteuid();
const gid_t EntryProcessor::m_egid = ::getegid();

EntryProcessor::EntryProcessor(const ProfileEntry &entry, const CmdlineArgs &args, const bool apply_changes) :
        m_entry{entry},
        m_args{args},
        m_apply_changes{apply_changes} {
    m_path = entry.file.substr(args.root_path.getValue().length());
}

bool EntryProcessor::process(const bool have_proc) {
        if (!resolveOwnership()) {
            // these don't count as errors currently, could be that some
            // package is just not installed and thus user/groups are missing.
            return true;
        }

        if (!safeOpen()) {
            return false;
        }

        if (!m_fd.valid()) {
            return false;
        } else if (m_file_status.isLink()) {
            return true;
        }

        if (have_proc) {
            // fd is opened with O_PATH, file operations like cap_get_fd() and fchown() don't work with it.
            //
            // We also don't want to do a proper open() of the file, since that doesn't even work for sockets
            // and might have side effects for pipes or devices.
            //
            // So we use path-based operations (yes!) with /proc/self/fd/xxx. (Since safe_open already resolved
            // all symlinks, 'fd' can't refer to a symlink which we'd have to worry might get followed.)
            m_safe_path = std::string("/proc/self/fd/") + std::to_string(m_fd.get());
        } else {
            // fall back to plain path-access for read-only operation. (this much is fine)
            // we only report errors below, m_apply_changes is set to false in this case.
            m_safe_path = m_entry.file;
            assert(!m_apply_changes);
        }

        if (!getCapabilities()) {
            return false;
        }

        if (!checkNeedsFixing()) {
            // nothing to do
            return true;
        }

        /*
         * first explain the differences between the encountered state of the
         * file and the desired state of the file.
         */
        printDifferences();

        if (!m_apply_changes) {
            // we don't need to do anything more
            return true;
        }

        if (!isSafeToApply()) {
            return false;
        }

        if (m_euid != 0) {
            // only attempt to change the owner if we're actually privileged
            // to do so (chkstat also supports to run as a regular user within
            // certain limits)
            m_need_fix_ownership = false;
        }

        return applyChanges();
}

bool EntryProcessor::resolveOwnership() {
    bool good = true;

    if (const auto pwd = getpwnam(m_entry.owner.c_str()); pwd != nullptr) {
        m_file_uid = pwd->pw_uid;
    } else if (stringToUnsigned(m_entry.owner, m_file_uid)) {
        // it's a numerical value, lets try it
    } else {
        good = false;
        if (m_args.verbose.isSet()) {
            std::cerr << m_path << ": unknown user " << m_entry.owner << ". Ignoring entry." << std::endl;
        }
    }

    if (const auto grp = getgrnam(m_entry.group.c_str()); grp != nullptr) {
        m_file_gid = grp->gr_gid;
    } else if (stringToUnsigned(m_entry.group, m_file_gid)) {
        // it's a numerical value, lets try it
    } else {
        good = false;
        if (m_args.verbose.isSet()) {
            std::cerr << m_path << ": unknown group " << m_entry.group << ". Ignoring entry." << std::endl;
        }
    }

    return good;
}

bool EntryProcessor::safeOpen() {
    size_t link_count = 0;
    FileDesc pathfd;
    FileDesc parentfd;
    FileStatus root_status;
    bool is_final_path_element = false;
    const auto &altroot = m_args.root_path.getValue();
    const auto root = altroot.empty() ? std::string("/") : altroot;
    std::string path_rest = m_path;
    std::string component;

    m_traversed_insecure = false;
    m_fd.close();

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
            m_file_status = root_status;
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
        if (component == ".." && !altroot.empty() && m_file_status.sameObject(root_status))
            continue;

        {
            // component is an empty string for trailing slashes, open again with different open_flags.
            auto child = component.empty() ? "." : component.c_str();
            int tmpfd = openat(pathfd.get(), child, O_PATH | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
            if (tmpfd == -1) {
                if (errno != ENOENT) {
                    std::cerr << "warning: skipping " << m_path << ": " << pathfd.path() << ": openat(): "
                        << std::strerror(errno) << std::endl;
                }
                return false;
            }
            pathfd.set(tmpfd);
        }

        if (!m_file_status.fstat(pathfd)) {
            std::cerr << "warning: skipping  " << m_path << ": " << pathfd.path() << ": fstat(): "
                << std::strerror(errno) << std::endl;
            return false;
        }

        // owner of directories must be trusted for setuid/setgid/capabilities
        // as we have no way to verify file contents
        if (is_parent_element) {
            // the owner needs to be root or our effective UID
            if (!m_file_status.hasSafeOwner({m_euid})) {
                m_traversed_insecure = true;
            // if the dir is group-writable then require the root group or our
            // effective GID.
            } else if (!m_file_status.hasSafeGroup({m_egid})) {
                m_traversed_insecure = true;
            }
            // path is in a world-writable directory
            else if (!m_file_status.isLink() && m_file_status.isWorldWritable()) {
                m_traversed_insecure = true;
            }
        }

        // if the object is owned by non-root, the owner must match the target
        // user (from the profile entry) or our effective user
        if (!m_file_status.hasSafeOwner({m_file_uid, m_euid})) {
            if (is_final_path_element) {
                std::cerr << m_path << ": has unexpected owner (" << m_file_status.st_uid << "). Refusing to correct due to unknown integrity." << std::endl;
                return false;
            } else {
                std::cerr << m_path << ": on an insecure path - " << pathfd.path() << " has different non-root owner who could tamper with the file." << std::endl;
                return false;
            }
        }

        // same goes for the group, if it is writable
        if(!m_file_status.hasSafeGroup({m_file_gid, m_egid})) {
            if (is_final_path_element) {
                std::cerr << m_path << ": is group-writable and has unexpected group (" << m_file_status.st_gid << "). Refusing to correct due to unknown integrity." << std::endl;
                return false;
            }
            else {
                std::cerr << m_path << ": on an insecure path - " << pathfd.path() << " has different non-root group that could tamper with the file." << std::endl;
                return false;
            }
        }

        if (m_file_status.isLink()) {
            // If the path configured in the permissions configuration is a symlink, we don't follow it.
            // This is to emulate legacy behaviour: old insecure versions of chkstat did a simple lstat(path) as 'protection' against malicious symlinks.
            if (is_final_path_element)
               return false;
            else if (++link_count >= 256) {
                std::cerr << m_path << ": excess link count stopping at " << pathfd.path() << "." << std::endl;
                return false;
            }

            // Don't follow symlinks owned by regular users.
            // In theory, we could also trust symlinks where the owner of the target matches the owner
            // of the link, but we're going the simple route for now.
            if (!m_file_status.hasSafeOwner({m_euid}) || !m_file_status.hasSafeGroup({m_egid})) {
                std::cerr << m_path << ": on an insecure path - " << pathfd.path() << " has different non-root owner who could tamper with the file." << std::endl;
                return false;
            }

            std::string link(PATH_MAX, '\0');
            const auto len = ::readlinkat(pathfd.get(), "", &link[0], link.size());

            if (len <= 0 || static_cast<size_t>(len) >= link.size()) {
                std::cerr << m_path << ": " << pathfd.path() << ": readlink(): " << std::strerror(errno) << std::endl;
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
        } else if (m_file_status.isDirectory()) {
            // parentfd is only needed to find the parent of a symlink.
            // We can't encounter links when resolving '.' or '..' so those don't need any special handling.
            parentfd.set(dup(pathfd.get()));
        }
    }

    // world-writable file: error out due to unknown file integrity
    if (m_file_status.isRegular() && m_file_status.isWorldWritable()) {
        std::cerr << m_path << ": file has insecure permissions (world-writable)" << std::endl;
        return false;
    }

    m_fd.steal(pathfd);

    return true;
}

bool EntryProcessor::getCapabilities() {

    if (!m_caps.setFromFile(m_safe_path)) {
        std::cerr << m_path << ": " << m_caps.lastErrorText() << std::endl;
        return false;
    }

    if (m_entry.hasCaps()) {
        // don't apply any set*id bits in case we apply capabilities since
        // capabilities are the safer variant of set*id, the set*id bits
        // are only a fallback.
        m_entry.dropXID();
    }

    return true;
}

void EntryProcessor::printDifferences() const {
    std::cout << m_path << ": "
        << (m_apply_changes ? "setting to " : "should be ")
        << m_entry.owner << ":" << m_entry.group << " "
        << FileModeInt(m_entry.mode);

    if (m_need_fix_caps && m_entry.hasCaps()) {
        std::cout << " \"" << m_entry.caps.toText() << "\".";
    }

    bool need_comma = false;

    std::cout << " (";

    if (m_need_fix_ownership) {
        std::cout << "wrong owner/group " << FileOwnership(m_file_status);
        need_comma = true;
    }

    if (m_need_fix_perms) {
        if (need_comma) {
            std::cout << ", ";
        }
        std::cout << "wrong permissions " << FileModeInt(m_file_status.getModeBits());
        need_comma = true;
    }

    if (m_need_fix_caps) {
        if (need_comma) {
            std::cout << ", ";
        }

        if (m_caps.hasCaps()) {
            std::cout << "wrong capabilities \"" << m_caps.toText() << "\"";
        } else {
            std::cout << "missing capabilities";
        }
    }

    std::cout << ")" << std::endl;
}

bool EntryProcessor::isSafeToApply() const {
    // don't allow high privileges for unusual file types
    if ((m_entry.hasCaps() || m_entry.hasSetXID()) && !m_file_status.isRegular() && !m_file_status.isDirectory()) {
        std::cerr << m_path << ": will only assign capabilities or setXid bits to regular files or directories" << std::endl;
        return false;
    }

    // don't give high privileges to files controlled by non-root users
    if (m_traversed_insecure) {
        if (m_entry.hasCaps() || (m_entry.mode & S_ISUID) || ((m_entry.mode & S_ISGID) && m_file_status.isRegular())) {
            std::cerr << m_path << ": will not give away capabilities or setXid bits on an insecure path" << std::endl;
            return false;
        }
    }

    return true;
}

bool EntryProcessor::applyChanges() const {
    bool ret = true;

    if (m_need_fix_ownership) {
        if (::chown(m_safe_path.c_str(), m_file_uid, m_file_gid) != 0) {
            std::cerr << m_path << ": chown(): " << std::strerror(errno) << std::endl;
            ret = false;
        }
    }

    // also re-apply the mode if we had to change ownership and a setXid
    // bit was set before, since this resets the setXid bit.
    if (m_need_fix_perms || (m_need_fix_ownership && m_entry.hasSetXID())) {
        if (::chmod(m_safe_path.c_str(), m_entry.mode) != 0) {
            std::cerr << m_path << ": chmod: " << std::strerror(errno) << std::endl;
            ret = false;
        }
    }

    // chown and - depending on the file system - chmod clear existing capabilities
    // so apply the intended caps even if they were correct previously
    if (m_entry.hasCaps() || m_need_fix_caps) {
        if (m_file_status.isRegular()) {
            // cap_set_file() tries to be helpful and does an lstat() to check that it isn't called on
            // a symlink. So we have to open() it (without O_PATH) and use cap_set_fd().
            FileDesc cap_fd{::open(m_safe_path.c_str(), O_NOATIME | O_CLOEXEC | O_RDONLY)};
            if (!cap_fd.valid()) {
                std::cerr << m_path << ": open() for changing capabilities: " << std::strerror(errno) << std::endl;
                ret = false;
            } else if (!m_entry.caps.applyToFD(cap_fd.get())) {
                // ignore ENODATA when clearing caps - it just means there were no caps to remove
                if (errno != ENODATA || m_entry.hasCaps()) {
                    std::cerr << m_path << ": cap_set_fd(): " << std::strerror(errno) << std::endl;
                    ret = false;
                }
            }
        } else {
            std::cerr << m_path << ": cannot set capabilities: not a regular file" << std::endl;
            ret = false;
        }
    }

    return ret;
}

// vim: et ts=4 sts=4 sw=4 :
