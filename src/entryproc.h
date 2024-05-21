#pragma once

// system headers
#include <unistd.h>

// local headers
#include "cmdline.h"
#include "profparser.h"

/// Process a single ProfileEntry entry potentially performing operations on the file system.
/**
 * This class compares the configuration data with actual file state found on
 * disk. It can act in a read-only mode where it only prints what changes
 * would be performed. Or it can actually apply necessary changes.
 **/
class EntryProcessor {
public: // types

    enum class Result {
        ENTRY_GOOD,    ///< The entry was validated and file status is good.
        ENTRY_BAD,     ///< The entry would need fixing but apply_changes is not set.
        ENTRY_FIXED,   ///< The entry needed fixing and has been fixed.
        ENTRY_SKIPPED, ///< The entry was skipped, because the file is not present or otherwise checking it was not possible.
        FAILED         ///< a fatal error condition was encountered, entry status is unknown.
    };

public: // functions

    EntryProcessor(const ProfileEntry &entry, const CmdlineArgs &args, const bool apply_changes);

    /// Returns the path relative to the altroot that this entry is concerned with
    const auto& path() const {
        return m_path;
    }

    /// Perform the necessary processing logic.
    /**
     * \param[in] have_proc Whether a /proc mount is available. If not then
     * no changes will be applied in the file system for security reasons.
     **/
    Result process(const bool have_proc);

protected: // types

    enum class OpenRes {
        ERROR,
        SKIP,
        CONTINUE
    };

protected: // functions

    /// Resolves the textual user:group in `m_entry` and stores the result in `m_file_uid` and `m_file_gid`.
    bool resolveOwnership();

    /// Safely open the target file taking symlinks and insecure constellations into account.
    /**
     * On success the file descriptor will be stored in m_fd.
     *
     * \return
     *      An indication whether the file could be successfully opened
     **/
    OpenRes safeOpen();

    /// Gets the currently set capabilities from `m_safe_path` and stores them in `m_caps`.
    /**
     * The setXid bits in `m_entry` are potentially modified if capabilities
     * can't be applied. The return value indicates if an operational error
     * occurred but it doesn't indicate whether capabilities are actually set
     * on the file. Check `m_caps.hasCaps()` for this.
     **/
    bool getCapabilities();

    /// Print differences between configuration and reality.
    /**
     * This outputs the operations that will (or should) be performed to
     * arrive at the ProfileEntry configuration.
     **/
    void printDifferences() const;

    /// Checks whether it is safe to adjust the actual file given the collected information.
    bool isSafeToApply() const;

    /// Actually apply changes to the opened file according to `m_entry`.
    bool applyChanges() const;

    /// Based on `m_entry` sets `m_need_fix_*` members as required and returns if any fixing is necessary.
    bool checkNeedsFixing() {
        if (m_entry.hasACL()) {
            // if we are using an ACL then we must not compare the traditional
            // mode bits. The group bits will be mapped to the ACL mask and
            // thus no longer correspond to the basic mode configured in the
            // permissions profile.
            // also doing a regular chmod() is unnecessary, since the basic
            // permissions are also contained in the ACL.
            m_need_fix_perms = false;
        } else {
            m_need_fix_perms = m_file_status.getModeBits() != m_entry.mode;
        }
        m_need_fix_ownership = !m_file_status.matchesOwnership(m_file_uid, m_file_gid);
        m_need_fix_caps = m_entry.caps != m_caps;
        // the right hand check catches the case that no ACL is configured and
        // the entry contains only a representation of the UNIX base mode.
        // Nothing needs to be done in this case.
        m_need_fix_acl = m_acl != m_entry.acl && !(m_acl.isBasicACL() && m_entry.acl.isBasicACL());
        return m_need_fix_perms || m_need_fix_caps || m_need_fix_ownership || m_need_fix_acl;
    }

protected: // data

    uid_t m_file_uid = (uid_t)-1; ///< The resolved user-id corresponding to the active ProfileEntry.
    gid_t m_file_gid = (gid_t)-1; ///< The resolved group-id corresponding to the active ProfileEntry.
    std::string m_path; ///< The path of the current file to check below a potential m_args.root_path.
    std::string m_safe_path; ///< A path for safely opening the target file (typically in /proc/self/fd/...).
    FileCapabilities m_caps; ///< The actual capabilities found on on the file.
    FileAcl m_acl; ///< The actual ACL found on the file.
    FileStatus m_file_status; ///< The actual file status info found on the file.
    bool m_need_fix_perms = false; ///< Indicates whether actual file permissions need to be fixed.
    bool m_need_fix_caps = false; ///< Indicates whether actual file capabilities need to be fixed.
    bool m_need_fix_ownership = false; ///< Indicates whether actual file user:group ownership needs to be fixed.
    bool m_need_fix_acl = false; ///< Indicates whether the actual access ACL needs to be fixed.
    bool m_traversed_insecure = false; ///< An insecure ownership constellation was detected in the file's path.
    FileDesc m_fd; ///< An `O_PATH` file descriptor for the target file which is set in safeOpen().

    const ProfileEntry &m_entry;
    const CmdlineArgs &m_args;
    const bool m_apply_changes;
    static const uid_t m_euid; ///< The effective user ID we're running as.
    static const gid_t m_egid; ///< The effective group ID we're running as.
};

// vim: et ts=4 sts=4 sw=4 :
