#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windns.h>
#endif

#include "cloud/treadmill-tktfwd/gss.h"

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#endif

#include <zmq.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <iostream>
#include <string>
#include <sstream>

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

uint32_t
request_ack(void *socket) {
    zmq_msg_t req;
    zmq_msg_init_size(&req, 1);
    memset(zmq_msg_data(&req), 0, 1);
    int rc = zmq_msg_send(&req, socket, 0);
    if (rc < 0) {
        LOG(ERROR) << "Error send ack: " << zmq_strerror(errno);
        return errno;
    }
    zmq_msg_close(&req);

    zmq_msg_t rep;
    zmq_msg_init(&rep);
    rc = zmq_msg_recv(&rep, socket, 0);
    if (rc < 0) {
        LOG(ERROR) << "Error recv ack: " << zmq_strerror(errno);
        return errno;
    }

    uint32_t result;
    if (zmq_msg_size(&rep) != sizeof(result)) {
        LOG(ERROR) << "Unexpected reply size: " << zmq_msg_size(&rep);
        return -1;
    }

    memcpy(&result, zmq_msg_data(&rep), sizeof(result));
    zmq_msg_close(&rep);
    return ntohl(result);
}

int
forward_tickets(void *zmq_context, const std::string& endpoint,
        const std::string& service_name, int timeout) {
    void *socket = zmq_socket(zmq_context, ZMQ_REQ);

    int rc = zmq_setsockopt(socket, ZMQ_SNDTIMEO, &timeout, sizeof(timeout));
    if (rc != 0) {
        LOG(FATAL) << "setsockopt ZMQ_SNDTIMEO failed:" << zmq_strerror(errno);
        return rc;
    }

    rc = zmq_setsockopt(socket, ZMQ_RCVTIMEO, &timeout, sizeof(timeout));
    if (rc != 0) {
        LOG(FATAL) << "setsockopt ZMQ_RCVTIMEO failed:" << zmq_strerror(errno);
        return rc;
    }

    int opt_linger = 0;
    rc = zmq_setsockopt(socket, ZMQ_LINGER, &opt_linger, sizeof(opt_linger));
    if (rc != 0) {
        LOG(FATAL) << "setsockopt ZMQ_LINGER failed:" << zmq_strerror(errno);
        return rc;
    }

    rc = zmq_connect(socket, endpoint.c_str());
    if (rc != 0) {
        LOG(FATAL) << "connect - " << endpoint << ": " << zmq_strerror(errno);
        return rc;
    }

    gss_OID oid = GSS_C_NULL_OID;
    gss_ctx_id_t context;
    OM_uint32 ret_flags;
    OM_uint32 gss_flags = GSS_C_MUTUAL_FLAG |
                          GSS_C_REPLAY_FLAG |
                          GSS_C_DELEG_FLAG;

    LOG(INFO) << "Forwarding creds: " << endpoint << ", " << service_name;
    bool success = client_establish_context(
            socket, service_name.c_str(),
            gss_flags, oid, &context, &ret_flags);

    if (success) {
        rc = request_ack(socket);
    }
    else {
        rc = -1;
    }
    // close socket and context.
    zmq_close(socket);

    if (rc == 0) {
        LOG(INFO) << "Tickets forwarded successfully.";
    }
    else {
        LOG(ERROR) << "Failed to establish context and forward creds.";
    }

    return rc;
}

std::vector<std::string> dns_srv(const std::string& query) {
    std::vector<std::string> result;

#ifndef _WIN32
    res_init();
    union {
        HEADER hdr;
        u_char buf[PACKETSZ];
    } response;

    ns_msg handle;
    int response_len = res_query(
        query.c_str(), C_IN, T_SRV,
        (u_char *)&response, sizeof(response)
    );

    ns_initparse(response.buf, response_len, &handle);
    int count = ns_msg_count(handle, ns_s_an);

    for (int idx = 0; idx < count; ++idx) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, idx, &rr) < 0) {
            LOG(FATAL) << "Unable to parse DNS response: " << idx;
            return result;
        }

        int len = ns_rr_rdlen(rr);
        u_char buf[256];

        memcpy(buf, ns_rr_rdata(rr), len);
        u_char *p = buf;

        int priority = ntohs(*(short *)p);
        p += 2;
        int weight = ntohs(*(short *)p);
        p += 2;
        int port = ntohs(*(short *)p);
        p += 2;

        while (*p > 0) {
            int t = *p;
            *p = '.';
            p += t + 1;
        }
        p = buf + 7;

        std::stringstream hostport;
        hostport << p << ":" << port;
        LOG(INFO) << "Priority: " << priority
                  << ", target: " << hostport.str();
        result.push_back(hostport.str());
    }
#else  // _WIN32
    PDNS_RECORD first_record;
    DNS_STATUS status = ::DnsQuery(query.c_str(), DNS_TYPE_SRV,
        DNS_QUERY_WIRE_ONLY, NULL, &first_record, NULL);

    if (status) {
        LOG(FATAL) << "Unable to query DNS: " << ::GetLastError();
        return result;
    }

    PDNS_RECORD record = first_record;
    while (record) {
        std::stringstream hostport;
        hostport << record->Data.Srv.pNameTarget << ":"
            << record->Data.Srv.wPort;
        LOG(INFO) << "Priority: " << record->Data.Srv.wPriority
            << ", target: " << hostport.str();
        result.push_back(hostport.str());

        record = record->pNext;
    }

    DnsRecordListFree(first_record, DnsFreeRecordList);
#endif  // _WIN32
    return result;
}

enum optionIndex {UNKNOWN, HELP, TIMEOUT, REALM, PRINC, ENDPOINTS, SRVREC};
const option::Descriptor usage[] = {
    {UNKNOWN, 0, "" , "" , option::Arg::None,
        "USAGE: tkt-send [options] <host:port> <user/host>@<host-realm>\n\n"
        "Options:" },
    {HELP, 0, "" , "help", option::Arg::None,
        "  --help                     \tPrint usage and exit." },
    {TIMEOUT, 0, "t", "timeout", option::Arg::Optional,
        "  -t<sec>, --timeout=<sec>  \tConnect timeout." },
    {REALM, 0, "r", "realm", option::Arg::Optional,
        "  -r<realm>, --realm=<realm>  \tKerberos realm of the service." },
    {PRINC, 0, "p", "princ", option::Arg::Optional,
        "  -p<princ>, --princ=<realm>  \tLocker service principal." },
    {ENDPOINTS, 0, "e", "endpoints", option::Arg::Optional,
        "  -e<host:port,host:port>, --endpoints=<host:port,host:port>"
        "  \tLocker service endpoints." },
    {SRVREC, 0, "s", "srvrec", option::Arg::Optional,
        "  -s<srvrec>, --srvrec=<srvrec>"
        "  \tLocker service DNS SRV record." },
    {UNKNOWN, 0, "", "", option::Arg::None,
        "\nExamples:\n"
        "  tkt-send <host:port> <user/host>@<host-realm> --timeout 3\n" },
    {0, 0, 0, 0, 0, 0}
};

int
main(int argc, char **argv) {
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

    int timeout = 5000;
    if (options[TIMEOUT] && options[TIMEOUT].arg) {
        timeout = atoi(options[TIMEOUT].arg) * 1000;
    }

    std::string realm;
    if (options[REALM] && options[REALM].arg) {
        realm = options[REALM].arg;
    }

    std::string princ("host");
    if (options[PRINC] && options[PRINC].arg) {
        princ = options[PRINC].arg;
    }

    std::string endpoints;
    if (options[ENDPOINTS] && options[ENDPOINTS].arg) {
        endpoints = options[ENDPOINTS].arg;
    }

    std::string srvrec;
    if (options[SRVREC] && options[SRVREC].arg) {
        srvrec = options[SRVREC].arg;
    }

    delete[] options;
    options = NULL;

    delete[] buffer;
    buffer = NULL;

    if (!endpoints.size() && !srvrec.size()) {
        LOG(FATAL) << "Must specify either --srvrec=<..> or --endpoints=<...>";
        return -1;
    }

    if (!realm.size()) {
        LOG(FATAL) << "Must specify --realm=<..>";
        return -1;
    }

    std::vector<std::string> hostports;
    if (endpoints.size()) {
        std::string hostport;
        std::stringstream endpoints_stream(endpoints);
        while (std::getline(endpoints_stream, hostport, ',')) {
            hostports.push_back(hostport);
        }
    }

    if (srvrec.size()) {
        std::vector<std::string> dns_records = dns_srv(srvrec);
        hostports.insert(hostports.end(), dns_records.begin(), dns_records.end());
    }

    void *zmq_context = zmq_ctx_new();
    int failures = 0;
    for (std::vector<std::string>::const_iterator hostport = hostports.begin();
             hostport != hostports.end();
             ++hostport) {
        std::string hostname = (*hostport).substr(0, (*hostport).find(':'));
        std::string endpoint = std::string("tcp://") + *hostport;
        std::string service_name = princ + "/" + hostname + "@" + realm;

        int rc = forward_tickets(zmq_context, endpoint, service_name, timeout);
        if (rc != 0) {
            ++failures;
        }
    }
    zmq_ctx_destroy(zmq_context);
    return failures;
}
