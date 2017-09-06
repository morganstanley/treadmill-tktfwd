
#include "cloud/treadmill-tktfwd/gss.h"
#include "cloud/treadmill-tktfwd/creds.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

#include <gssapi/gssapi_generic.h>
#include <krb5.h>
#include <zmq.h>

#include <easylogging/easylogging++.h>

_INITIALIZE_EASYLOGGINGPP

namespace el = easyloggingpp;

void init_log() {
    el::Configurations log_conf;
    log_conf.setToDefault();
    log_conf.setAll(el::ConfigurationType::ToFile, "false");
    log_conf.setAll(el::ConfigurationType::ToStandardOutput, "true");
    el::Loggers::reconfigureAllLoggers(log_conf);
    log_conf.clear();
}

int send_ack(void *socket, uint32_t result) {
    zmq_msg_t req;
    zmq_msg_init(&req);
    int rc = zmq_msg_recv(&req, socket, 0);
    if (rc < 0) {
        LOG(ERROR) << "Error recv ack: " << zmq_strerror(errno);
        return errno;
    }
    zmq_msg_close(&req);

    uint32_t net_result = htonl(result);
    zmq_msg_t rep;
    zmq_msg_init_size(&rep, sizeof(net_result));
    memcpy(zmq_msg_data(&rep), &net_result, sizeof(net_result));
    rc = zmq_msg_send(&rep, socket, 0);
    if (rc < 0) {
        LOG(ERROR) << "Error send ack: " << zmq_strerror(errno);
        return errno;
    }
    zmq_msg_close(&rep);
}

int safe_move(const std::string& src, const std::string& dst) {
    // Safely cope src to dst by creating tmp file and renaming it.
    std::string dst_template = dst + "XXXXXX";

    char temp[dst_template.size() + 1];
    memset(temp, 0, sizeof(temp));
    strcpy(temp, dst_template.c_str());

    int temp_fd = mkstemp(temp);
    int src_fd = open(src.c_str(), O_RDONLY, 0);

    char buf[BUFSIZ];
    size_t size;
    while ((size = read(src_fd, buf, BUFSIZ)) > 0) {
        write(temp_fd, buf, size);
    }

    close(temp_fd);
    close(src_fd);

    int rc = rename(temp, dst.c_str());
    if (rc == 0) {
        LOG(INFO) << "rename: " << temp << " " << dst << ", rc = " << rc;
    } else {
        LOG(INFO) << "rename: " << temp << " " << dst << ", rc = " << rc
                  << ", "
                  << strerror(errno);
    }

    return rc == 0;
}

int main (int argc, char **argv) {
    init_log();

    if (argc < 3) {
        LOG(ERROR) << "Usage: " << " tcp://*:<port> <tkt_spool_dir>";
        return -1;
    }

    std::string endpoint(argv[1]);
    std::string tkt_spool_dir(argv[2]);

    int euid = geteuid();
    struct passwd *pw = getpwuid(euid);
    std::string me(pw->pw_name);
    LOG(INFO) << "Running as: " << me;

    krb5_context krb_context = NULL;
    ssh_gssapi_krb5_init(&krb_context);

    gss_cred_id_t server_creds;
    server_acquire_creds(NULL, &server_creds);

    void *context = zmq_ctx_new ();
    void *socket = zmq_socket(context, ZMQ_REP);
    int rc = zmq_bind(socket, endpoint.c_str());
    if (rc != 0) {
        LOG(FATAL) << "Bind error " << endpoint << ", " << strerror(errno);
        return -1;
    }

    char sock_endpoint[256];
    size_t size = sizeof(sock_endpoint);
    zmq_getsockopt(socket, ZMQ_LAST_ENDPOINT, sock_endpoint, &size);

    while (1) {
        LOG(INFO) << "Listening on: " << sock_endpoint;

        gss_ctx_id_t context;
        gss_name_t client_name;
        gss_OID doid;
        gss_cred_id_t client_creds;

        OM_uint32 ret_flags;
        OM_uint32 maj_stat;
        OM_uint32 min_stat;
        std::string accepted_princ;

        if (server_establish_context(socket, server_creds, &context,
                    &client_name, &doid, &client_creds, &ret_flags)) {
            if (context == GSS_C_NO_CONTEXT) {
                LOG(INFO) << "Unauthenticated connection - ignore.";
                continue;
            }

            gss_buffer_desc client_name_buffer;
            maj_stat = gss_display_name(
                    &min_stat,
                    client_name,
                    &client_name_buffer,
                    &doid);
            if (maj_stat != GSS_S_COMPLETE) {
                display_status("displaying name", maj_stat, min_stat);
                continue;
            }

            accepted_princ.assign((const char *)client_name_buffer.value);
            LOG(INFO) << "Accepted connection: " << accepted_princ;

            maj_stat = gss_release_name(&min_stat, &client_name);
            if (maj_stat != GSS_S_COMPLETE) {
                display_status("releasing name", maj_stat, min_stat);
                continue;
            }

            gss_release_buffer(&min_stat, &client_name_buffer);
            maj_stat = gss_delete_sec_context(&min_stat, &context, NULL);
            if (maj_stat != GSS_S_COMPLETE) {
                display_status("deleting context", maj_stat, min_stat);
                continue;
            }

            if (euid != 0 && accepted_princ.find(me + "@") != 0) {
                LOG(INFO) << "Ignoring unexpected connection from: "
                          << accepted_princ;
                continue;
            }

            std::string tmp_ccname = ssh_gssapi_krb5_storecreds(
                        krb_context,
                        client_creds,
                        accepted_princ.c_str());
            if (tmp_ccname.empty()) {
                LOG(ERROR) << "Unexpected error storing new creds.";
                continue;
            }

            // Rename temp tmp_ccname into target.
            std::string tgt_ccname = tkt_spool_dir + "/" + accepted_princ;
            if (safe_move(tmp_ccname, tgt_ccname)) {
                LOG(INFO) << "ticket cache moved: FILE:"
                          << tgt_ccname;
            }
            else {
                LOG(ERROR) << "Error rename: "
                           << tmp_ccname
                           << tgt_ccname;
            }

            // reply with success.
            send_ack(socket, rc);
        }
    }
    return 0;
}
