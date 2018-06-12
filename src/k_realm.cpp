#include <unistd.h>

#include <iostream>
#include <algorithm>

#include <krb5.h>
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

/**
 * Display kerberos realm of the host.
 *
 * Usage:
 *   k-realm
 *   k-realm <hostname>
 */
int main(int argc, char **argv) {

    init_log();

    char hostname[256];
    if (argc > 1) {
        strncpy(hostname, argv[1], sizeof(hostname));
    } else {
        int rc = gethostname(hostname, sizeof(hostname));
        if (rc != 0) {
            LOG(ERROR) << "gethostname: " << rc;
            exit(-1);
        }
    }

    krb5_error_code retval = 0;

    krb5_context kcontext;
    retval = krb5_init_context(&kcontext);
    if (retval != 0) {
        LOG(ERROR) << "krb5_init_context: " << retval;
        exit(-1);
    }

    char **realm_list = NULL;
    retval = krb5_get_host_realm(kcontext, hostname, &realm_list);
    if (retval != 0) {
        LOG(ERROR) << "krb5_get_host_realm: " << retval;
        exit(-1);
    }

    char **realm = realm_list;
    while (*realm && *realm[0]) {
        std::cout << *realm << std::endl;
        ++realm;
    }
    krb5_free_host_realm(kcontext, realm_list);
    return 0;
}
