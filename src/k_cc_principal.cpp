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
 * Display default principal of the credential cache.
 *
 * Usage:
 *   k-cc-principal
 *   k-cc-principal <credcache>
 */
int main(int argc, char **argv) {

    init_log();

    char krb5ccname[256];
    if (argc > 1) {
        strncpy(krb5ccname, argv[1], sizeof(krb5ccname));
    } else {
        const char *krb5ccname_env = getenv("KRB5CCNAME");
        if (!krb5ccname_env) {
            LOG(ERROR) << "KRB5CCNAME environment variable not set.";
            exit(-1);
        }
        strncpy(krb5ccname, krb5ccname_env, sizeof(krb5ccname));
    }

    krb5_error_code retval = 0;
    krb5_context kcontext;
    retval = krb5_init_context(&kcontext);
    if (retval != 0) {
        LOG(ERROR) << "krb5_init_context: " << retval;
        exit(-1);
    }

    krb5_ccache cache;
    retval = krb5_cc_resolve(kcontext, (const char *)krb5ccname, &cache);
    if (retval != 0) {
        LOG(ERROR) << "krb5_cc_resolve: " << retval;
        exit(-1);
    }

    krb5_principal princ;
    retval = krb5_cc_get_principal(kcontext, cache, &princ);
    if (retval != 0) {
        LOG(ERROR) << "krb5_get_principal: " << retval;
        exit(-1);
    }

    char *name;
    retval = krb5_unparse_name(kcontext, princ, &name);
    if (retval != 0) {
        LOG(ERROR) << "krb5_unparse_name: " << retval;
        exit(-1);
    }

    std::cout << name << std::endl;

    // Cleanup.
    // TODO: replace with resource manager classes? probably overkill for
    //       simple app like that.
    if (name)
        krb5_free_unparsed_name(kcontext, name);
    if (princ)
        krb5_free_principal(kcontext, princ);
    if (cache)
        krb5_cc_close(kcontext, cache);
    if (kcontext)
        krb5_free_context(kcontext);

    return 0;
}
