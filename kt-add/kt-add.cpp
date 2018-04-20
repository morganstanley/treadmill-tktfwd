#include "kt.h"

#include <iostream>
#include <algorithm>

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
 * Add keytab files to target keytab file.
 *
 * Usage:
 *   kt-add <final-keytab> <kt1> [<kt2> ...]
 */
int main(int argc, char **argv) {

    init_log();
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0]
            << " <kt_file_sum> <kt_file> ..." << std::endl;
        exit(-1);
    }

    std::string kt_filename_final(argv[1]);

    krb5_error_code retval = 0;

    krb5_context kcontext;
    retval = krb5_init_context(&kcontext);
    if (retval != 0) {
        LOG(ERROR) << "krb5_init_context: " << retval;
        exit(-1);
    }

    for (int i = 2; i < argc; ++i) {
        std::string kt_filename(argv[i]);
        keytab_entry_list_t kt_list;

        LOG(INFO) << "Reading: " << kt_filename;
        kt_read(kcontext, kt_filename, kt_list);

        LOG(INFO) << "Writing: " << kt_filename_final
            << ", number of entries: " << kt_list.size();
        kt_write(kcontext, kt_filename_final, kt_list);
    }
    return 0;
}
