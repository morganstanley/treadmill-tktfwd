#include "tktrecv.h"
#include <stdio.h>

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

struct event_base* g_evbase = NULL;

enum optionIndex {UNKNOWN, HELP, PORT, SPOOL_DIR};
const option::Descriptor usage[] = {
    {UNKNOWN, 0, "" , "" , option::Arg::None,
        "USAGE: tkt-send [options] <host:port> <user/host>@<host-realm>\n\n"
        "Options:" },
    {HELP, 0, "" , "help", option::Arg::None,
        "  --help                     \tPrint usage and exit." },
    {PORT, 0, "p", "port", option::Arg::Optional,
        "  -p<port>, --port=<port>  \tServer port." },
    {SPOOL_DIR, 0, "d", "dir", option::Arg::Optional,
        "  -d<dir>, --dir=<dir>  \tTicket spool directory." },
    {UNKNOWN, 0, "", "", option::Arg::None,
        "\nExamples:\n"
        "  tkt-recv --port=<port>\n" },
    {0, 0, 0, 0, 0, 0}
};

int main(int argc, char **argv) {
    // Disable stdout buffer.
    setvbuf(stdout, NULL, _IOLBF, 0);

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

    int port = 0;
    if (options[PORT] && options[PORT].arg) {
        port = atoi(options[PORT].arg);
    }

    std::string tkt_spool_dir("/tmp");
    if (options[SPOOL_DIR] && options[SPOOL_DIR].arg) {
        tkt_spool_dir = options[SPOOL_DIR].arg;
    }

    g_evbase = event_base_new();

    LOG(INFO) << "Running tkt-recv server on port: " << port;

    run_server(port, tkt_spool_dir);
    event_base_free(g_evbase);
}
