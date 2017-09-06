#include "cloud/treadmill-tktfwd/kt.h"

#include <iostream>
#include <algorithm>

#include <easylogging/easylogging++.h>
#include <optionparser/optionparser.h>

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

enum optionIndex {UNKNOWN, HELP, DIRECTORY};
const option::Descriptor usage[] = {
    {UNKNOWN, 0, "" , "" , option::Arg::None,
        "USAGE: kt-split [options] <keytab>\n\n"
        "Options:" },
    {HELP, 0, "" , "help", option::Arg::None,
        "  --help                     \tPrint usage and exit." },
    {DIRECTORY, 0, "d", "dir", option::Arg::Optional,
        "  -d<dir>, --dir=<dir>  \tOutput directory." },
    {UNKNOWN, 0, "", "", option::Arg::None,
        "\nExamples:\n"
        "  kt-split --dir=/tmp /etc/krb5.keytab\n" },
    {0, 0, 0, 0, 0, 0}
};

/**
 * Split keytab into mutliple keytab files by principal name.
 *
 * Keytab files are created in current working directory.
 */
int main(int argc, char **argv) {

    init_log();

    // skip program name argv[0] if present
    argc -= (argc > 0);
    argv += (argc > 0);

    option::Stats  stats(usage, argc, argv);
    option::Option* options = new option::Option[stats.options_max];
    option::Option* buffer  = new option::Option[stats.buffer_max];

    option::Parser parse(usage, argc, argv, options, buffer);

    if (parse.error()) {
        return -1;
    }

    if (options[HELP] || argc == 0) {
        option::printUsage(std::cout, usage);
        return -1;
    }

    std::string outdir;
    if (options[DIRECTORY] && options[DIRECTORY].arg) {
        outdir = options[DIRECTORY].arg;
    }


    if (parse.nonOptionsCount() == 0) {
        option::printUsage(std::cout, usage);
        return -1;
    }

    std::string kt_filename(parse.nonOption(0));

    krb5_error_code retval = 0;

    krb5_context kcontext;
    retval = krb5_init_context(&kcontext);
    if (retval != 0) {
        LOG(ERROR) << "krb5_init_context: " << retval;
        exit(-1);
    }

    keytab_entry_list_t kt_list;
    kt_read(kcontext, kt_filename, kt_list);

    for (keytab_entry_list_t::iterator it = kt_list.begin();
            it != kt_list.end(); ++it) {
        krb5_keytab_entry &entry = *it;
        char *name;
        retval = krb5_unparse_name(kcontext, entry.principal, &name);
        krb5_free_unparsed_name(kcontext, name);
    }

    keytab_entry_map_t kt_map;
    kt_groupby(kcontext, kt_list, kt_map);

    for (keytab_entry_map_t::iterator it = kt_map.begin();
            it != kt_map.end(); ++it) {

        std::string kt_filename(it->first);
        std::replace(kt_filename.begin(), kt_filename.end(), '/', '#');
        if (!outdir.empty()) {
            kt_filename = outdir + "/" + kt_filename;
        }
        LOG(INFO) << "Creating keytab: " << kt_filename;
        kt_write(kcontext, kt_filename, it->second);
    }

    return 0;
}
