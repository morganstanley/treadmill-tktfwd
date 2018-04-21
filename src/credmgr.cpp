#include "credmgr.h"
#include "creds.h"

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include <easylogging/easylogging++.h>

static int safe_move(const std::string& src, const std::string& dst) {
    // Safely cope src to dst by creating tmp file and renaming it.
    std::string dst_template = dst + "XXXXXX";

    char temp[dst_template.size() + 1];
    memset(temp, 0, sizeof(temp));
    strcpy(temp, dst_template.c_str());

    int temp_fd = mkstemp(temp);
    int src_fd = open(src.c_str(), O_RDONLY, 0);

    char buf[BUFSIZ];
    ssize_t bytes_read;
    ssize_t bytes_written;

    int success = 1;
    while ((bytes_read = read(src_fd, buf, BUFSIZ)) > 0) {
        // TODO: need to check for EINTR and retry.
        if (bytes_read == -1) {
            LOG(ERROR) << "read error: " << src << " errno: " << errno;
            success = 0;
            break;
        }
        bytes_written = write(temp_fd, buf, bytes_read);
        // TODO: need to check for EINTR and retry.
        if (bytes_written == -1) {
            LOG(ERROR) << "write error: " << temp << " errno: " << errno;
            success = 0;
            break;
        }
        if (bytes_written != bytes_read) {
            LOG(ERROR) << "partial write: "
                << bytes_written << "/" << bytes_read << " errno: " << errno;
            success = 0;
            break;
        }
    }

    close(temp_fd);
    close(src_fd);

    if (!success) {
        LOG(ERROR) << "Failed to write tickets to: " << dst;
        unlink(temp);
        return 0;
    }

    int rc = rename(temp, dst.c_str());
    if (rc == 0) {
        LOG(INFO) << "Rename: " << temp << " " << dst << ", rc = " << rc;
    } else {
        LOG(INFO) << "Rename: " << temp << " " << dst << ", rc = " << rc
                  << ", "
                  << strerror(errno);
        if(0 != unlink(temp)) {
            LOG(ERROR) << "Unable to unlink: " << temp << " errno: " << errno;
        }
    }

    if(0 != unlink(src.c_str())) {
        LOG(ERROR) << "Unable to unlink: " << src << " errno: " << errno;
    }
    return rc == 0;
}

CredMgr::CredMgr(const std::string& tkt_spool_dir_):
        tkt_spool_dir(tkt_spool_dir_),
        euid(geteuid()) {

    ssh_gssapi_krb5_init(&krb_context);

    struct passwd *pw = getpwuid(euid);
    me.assign(pw->pw_name);
}

CredMgr::~CredMgr() {
}

bool CredMgr::store_creds(const std::string& accepted_princ,
                          gss_cred_id_t client_creds) const {

    LOG(INFO) << "Credential manager running as euid: " << euid
              << ", username: " << me;

    if (euid != 0 && accepted_princ.find(me + "@") != 0) {
        LOG(INFO) << "Ignoring unexpected connection from: "
                  << accepted_princ;
        return false;
    }

    std::string tmp_ccname = ssh_gssapi_krb5_storecreds(
                krb_context,
                client_creds,
                accepted_princ.c_str());
    if (tmp_ccname.empty()) {
        LOG(ERROR) << "Unexpected error storing new creds.";
        return false;
    }

    // Rename temp tmp_ccname into target.
    std::string tgt_ccname = tkt_spool_dir + "/" + accepted_princ;
    if (safe_move(tmp_ccname, tgt_ccname)) {
        LOG(INFO) << "Ticket cache moved: FILE:"
                  << tgt_ccname;
    }
    else {
        LOG(ERROR) << "Error rename: "
                   << tmp_ccname
                   << tgt_ccname;
    }

    LOG(INFO) << "Tickets stored successfully: " << tgt_ccname;
    return true;
}
