#ifdef _WIN32

    // Windows specific includes.
    #include <winsock2.h>
    #include <windows.h>

    #ifndef USE_GSSAPI
        #define USE_SSPI
    #endif

    #ifdef USE_SSPI

        #ifdef UNICODE
        #undef UNICODE
        #endif

        #include <winerror.h>
        #include <rpc.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <io.h>
        #include <fcntl.h>
        #define SECURITY_WIN32
        #include <security.h>
        #include <ntsecapi.h>
        #include <stddef.h>
        #include <sys/types.h>

        typedef unsigned long gss_uint32;
        typedef long gss_int32;

        typedef gss_uint32      OM_uint32;
        typedef OM_uint32       gss_qop_t;

    #endif  // USE_SSPI

    #define socket_errno (GetLastError())

#else  // not _WIN32

    // Linux specific includes.
    #define USE_GSSAPI

    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <netinet/in.h>
    #include <errno.h>

    #define INVALID_SOCKET -1
    #define SOCKET_ERROR   -1

    #define socket_errno errno

#endif  // _WIN32

// Common includes. GSSAPI can be used on both platforms if USE_GSSAPI is
// defined.
#ifdef USE_GSSAPI
    #include <gssapi/gssapi_krb5.h>
#endif  // USE_GSSAPI

#include <string.h>
#include <string>
#include <iostream>

#include <easylogging/easylogging++.h>
#include <optionparser/optionparser.h>

_INITIALIZE_EASYLOGGINGPP

#define ASSERT(cond) \
    if (!(cond)) std::cout << "Fatal: " \
                           << __FILE__ << ":" << __LINE__ << std::endl;

typedef int socket_t;

namespace el = easyloggingpp;

const int _default_recv_timeout = 60;

void init_log() {
    el::Configurations log_conf;
    log_conf.setToDefault();
    log_conf.setAll(el::ConfigurationType::ToFile, "false");
    log_conf.setAll(el::ConfigurationType::ToStandardOutput, "true");
    el::Loggers::reconfigureAllLoggers(log_conf);
    log_conf.clear();
}

static int sendbytes(int sock, const char *buf, int buflen) {
    int bytes_sent = 0;
    int bytes_remaining = buflen;
    while(bytes_remaining > 0) {
        int count = send(sock, buf + bytes_sent, bytes_remaining, 0);
        if (count == SOCKET_ERROR) {
            return -1;
        }

        bytes_sent += count;
        bytes_remaining -= count;
    }

    return buflen;
}

static int readbytes(int sock, char *buf, int buflen) {
    int bytes_read = 0;
    int bytes_remaining = buflen;
    while (bytes_remaining > 0) {
        int count = recv(sock, buf + bytes_read, bytes_remaining, 0);
        if (count == 0) {
            LOG(ERROR) << "Connection closed.";
            return -1;
        }
        if (count == SOCKET_ERROR) {
            LOG(ERROR) << "Socket error, errno: " << socket_errno;
            return -1;
        }
        bytes_read += count;
        bytes_remaining -= count;
    }

    return bytes_read;
}

static bool buffer_write(int sock, const char *value, OM_uint32 len) {

    ASSERT(value);

    OM_uint32 network_order_len = htonl(len);
    int bytes_sent = sendbytes(
        sock,
        (const char *)&network_order_len,
        sizeof(network_order_len)
    );

    if (bytes_sent != sizeof(len)) {
        return false;
    }

    bytes_sent = sendbytes(sock, value, len);
    if (bytes_sent != len) {
        return false;
    }

    return true;
}

static bool buffer_read(int sock, void **buf_value, size_t *buf_size) {

    OM_uint32 len;
    int bytes_read = readbytes(sock, (char *)&len, sizeof(len));
    if (bytes_read <= 0) {
        return false;
    }

    ASSERT(bytes_read == sizeof(len));
    len = ntohl(len);

    char *value = (char *)malloc(len);
    bytes_read = readbytes(sock, value, len);
    if (bytes_read <= 0) {
        free(value);
        return false;
    }

    ASSERT(bytes_read == len);
    *buf_value = (void *)value;
    *buf_size = len;

    return true;
}

struct TktClient {

    TktClient(const std::string& hostname_, int port_,
              const std::string& service_):
        hostname(hostname_),
        port(port_),
        service(service_),
        socket(INVALID_SOCKET)
    {
    }

    ~TktClient() {
        release();
    }

    void closesocket() {
#ifdef _WIN32
        ::closesocket(socket);
#else
        ::close(socket);
#endif
        socket = INVALID_SOCKET;
    }

    void shutdown() {
#ifdef _WIN32
#define SHUT_WR SD_SEND
#endif
        ::shutdown(socket, SHUT_WR);
    }

    void release() {
        closesocket();
    }

    bool connect(int timeout);
    bool handshake();
    bool success();

    std::string hostname;
    int port;

    // connected socket
    socket_t socket;
    std::string service;
    std::string sprinc;
};

bool TktClient::success() {
    OM_uint32 ack;
    int bytes_read = readbytes(socket, (char *)&ack, sizeof(ack));
    if (bytes_read <= 0) {
        return false;
    }

    ack = ntohl(ack);
    return ack == 0;
}

bool TktClient::connect(int timeout) {
    // tbd: need to randomize search
    struct sockaddr_in addressconnect;
    socket = ::socket(AF_INET, SOCK_STREAM, 0);
    memset(&addressconnect, 0, sizeof(addressconnect));

    addressconnect.sin_family = AF_INET;
    addressconnect.sin_addr.s_addr = INADDR_ANY;
    addressconnect.sin_port = htons(port);

    struct hostent *he;
    if ((he = gethostbyname(hostname.c_str())) == NULL) {
        addressconnect.sin_addr.s_addr = inet_addr(hostname.c_str());
    }
    else {
        memcpy(&(addressconnect.sin_addr),
               he->h_addr_list[0],
               (size_t)he->h_length);
    }

    if (::connect(socket,
                  (struct sockaddr *)&addressconnect,
                  sizeof(addressconnect)) != 0) {
        closesocket();
        return false;
    }

#ifndef _WIN32
    struct timeval tv = {timeout, 0};
    setsockopt(
        socket,
        SOL_SOCKET,
        SO_RCVTIMEO,
        (struct timeval *)&tv,
        sizeof(struct timeval)
    );
    sprinc = service + "@" + hostname;
#else
    int timeout_msec = timeout * 1000;
    setsockopt(
        socket,
        SOL_SOCKET,
        SO_RCVTIMEO,
        (const char *)&timeout_msec,
        sizeof(timeout)
    );
    sprinc = service;
#endif

    return true;
}

// GSSAPI specific code.
#ifdef USE_GSSAPI
static int gss_buffer_free(gss_buffer_t gss_buf) {
    if (gss_buf->value) {
        free(gss_buf->value);
        gss_buf->value = NULL;
        gss_buf->length = 0;
    }
}

static int gss_buffer_alloc(gss_buffer_t gss_buf, OM_uint32 len) {
    ASSERT(gss_buf->value == NULL);
    gss_buf->value = malloc(len);
    gss_buf->length = len;
}

static bool gss_buffer_read(int sock, gss_buffer_t gss_buf) {
    return buffer_read(sock, &gss_buf->value, &gss_buf->length);
}

static bool gss_buffer_write(int sock, gss_buffer_t gss_buf) {
    return buffer_write(sock, (const char *)gss_buf->value, gss_buf->length);
}

bool TktClient::handshake() {
	OM_uint32 maj, min;
    gss_buffer_desc	name;
    gss_OID type = GSS_C_NT_HOSTBASED_SERVICE;
    gss_name_t peer_name;

    ASSERT(sprinc.size() > 0);

    name.value  = (void *)sprinc.c_str();
    name.length = sprinc.size();

    maj = gss_import_name(&min, &name, type, &peer_name);

	gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc gss_buf_in;
    gss_buf_in.length = 0;
    gss_buf_in.value = NULL;

    gss_buffer_desc gss_buf_out;
    gss_buf_out.length = 0;
    gss_buf_out.value = NULL;

    OM_uint32 gss_flags = GSS_C_MUTUAL_FLAG |
                          GSS_C_SEQUENCE_FLAG |
                          GSS_C_REPLAY_FLAG |
                          GSS_C_DELEG_FLAG;

    bool status = false;
    do {
        maj = gss_init_sec_context(
                &min,
                GSS_C_NO_CREDENTIAL,
                &ctx,
                peer_name,
                GSS_C_NO_OID,
                gss_flags,
                0,
                GSS_C_NO_CHANNEL_BINDINGS,
                &gss_buf_in,
                NULL,
                &gss_buf_out,
                NULL,
                NULL
                );

        gss_buffer_free(&gss_buf_in);

        if (GSS_ERROR(maj) && ctx == GSS_C_NO_CONTEXT) {
            gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
            ctx = GSS_C_NO_CONTEXT;
            return false;
        }

        if (maj & GSS_S_CONTINUE_NEEDED) {
            bool rc = gss_buffer_write(this->socket, &gss_buf_out);

            OM_uint32 min;
            gss_release_buffer(&min, &gss_buf_out);

            if (!rc) {
                break;
            }

            if (!gss_buffer_read(this->socket, &gss_buf_in)) {
                break;
            }
        }
        else {
            status = true;
            break;
        }

    } while (1);

    gss_buffer_free(&gss_buf_in);
    gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
    return status;
}
#endif  // USE_GSSAPI

#ifdef USE_SSPI

static bool sec_buffer_read(int sock, SecBuffer *sec_buf) {
    size_t buffer_len;
    bool rc = buffer_read(sock, &sec_buf->pvBuffer, &buffer_len);
    sec_buf->cbBuffer = buffer_len;
    return rc;
}

static bool sec_buffer_write(int sock, SecBuffer *sec_buf) {
    return buffer_write(
        sock, (const char *)sec_buf->pvBuffer, sec_buf->cbBuffer
    );
}

bool TktClient::handshake() {
    SecBuffer recv_tok;
    recv_tok.BufferType = SECBUFFER_TOKEN;
    recv_tok.cbBuffer = 0;
    recv_tok.pvBuffer = NULL;

    SecBufferDesc input_desc;
    input_desc.cBuffers = 1;
    input_desc.pBuffers = &recv_tok;
    input_desc.ulVersion = SECBUFFER_VERSION;

    SecBuffer send_tok;
    send_tok.BufferType = SECBUFFER_TOKEN;
    send_tok.cbBuffer = 0;
    send_tok.pvBuffer = NULL;

    SecBufferDesc output_desc;
    output_desc.cBuffers = 1;
    output_desc.pBuffers = &send_tok;
    output_desc.ulVersion = SECBUFFER_VERSION;

    CredHandle cred_handle;
    cred_handle.dwLower = 0;
    cred_handle.dwUpper = 0;

    SEC_WINNT_AUTH_IDENTITY AuthIdentity;
    memset(&AuthIdentity, 0, sizeof(AuthIdentity));
    AuthIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;

    TimeStamp expiry;
    PSEC_WINNT_AUTH_IDENTITY pAuthId = NULL;
    char *mech = "Kerberos";
    OM_uint32 maj_stat = AcquireCredentialsHandle(
        NULL,                       // no principal name
        mech,                       // package name
        SECPKG_CRED_OUTBOUND,
        NULL,                       // no logon id
        pAuthId,                    // no auth data
        NULL,                       // no get key fn
        NULL,                       // noget key arg
        &cred_handle,
        &expiry
    );

    if (maj_stat != SEC_E_OK) {
        LOG(ERROR) << "acquiring credentials, maj: " << maj_stat;
        return false;
    }

    CtxtHandle context;
    context.dwLower = 0;
    context.dwUpper = 0;

    OM_uint32 gss_flags =  (
          ISC_REQ_MUTUAL_AUTH
        | ISC_REQ_ALLOCATE_MEMORY
        | ISC_REQ_CONFIDENTIALITY
        | ISC_REQ_REPLAY_DETECT
        | ISC_REQ_DELEGATE
    );

    PCtxtHandle context_handle = NULL;
    do {
        OM_uint32 ret_flags;
        maj_stat = InitializeSecurityContext(
            &cred_handle,
            context_handle,
            (char *)sprinc.c_str(),
            gss_flags,
            0,          // reserved
            SECURITY_NATIVE_DREP,
            &input_desc,
            0,          // reserved
            &context,
            &output_desc,
            &ret_flags,
            &expiry
        );

        if (recv_tok.pvBuffer) {
            free(recv_tok.pvBuffer);
            recv_tok.pvBuffer = NULL;
            recv_tok.cbBuffer = 0;
        }

        context_handle = &context;

        if (maj_stat != SEC_E_OK && maj_stat != SEC_I_CONTINUE_NEEDED) {
            FreeCredentialsHandle(&cred_handle);
            return false;
        }

        if (!(ret_flags & ISC_RET_DELEGATE)) {
            LOG(ERROR) << "ISC_RET_DELEGATE not set.";
        }

        if (send_tok.cbBuffer != 0) {
            if (!sec_buffer_write(this->socket, &send_tok)) {
                FreeContextBuffer(send_tok.pvBuffer);
                FreeCredentialsHandle(&cred_handle);
                return false;
            }
        }

        FreeContextBuffer(send_tok.pvBuffer);
        send_tok.pvBuffer = NULL;
        send_tok.cbBuffer = 0;

        if (maj_stat == SEC_I_CONTINUE_NEEDED) {
            if (!sec_buffer_read(this->socket, &recv_tok)) {
                LOG(ERROR) << "sec_buffer_read failed.";
                FreeCredentialsHandle(&cred_handle);
                return false;
            }
        }
    } while (maj_stat == SEC_I_CONTINUE_NEEDED);

    FreeCredentialsHandle(&cred_handle);
    return true;
}

#endif  // USE_SSPI

#ifdef _WIN32

static bool purge_tickets() {
    HANDLE logon_handle;

    NTSTATUS status = LsaConnectUntrusted(&logon_handle);
    if (FAILED(status)) {
        LOG(ERROR) << "LsaConnectUntrusted, errno: " << GetLastError();
        return false;
    }

    LSA_STRING lsa_name;
    lsa_name.Buffer = MICROSOFT_KERBEROS_NAME_A;
    lsa_name.Length = strlen(lsa_name.Buffer);
    lsa_name.MaximumLength = lsa_name.Length + 1;

    ULONG package_id;
    status = LsaLookupAuthenticationPackage(
        logon_handle,
        &lsa_name,
        &package_id
    );

    if (status != 0) {
        LOG(ERROR) << "LsaLookupAuthenticationPackage: " << status;
        return false;
    }

    NTSTATUS sub_status = 0;
    KERB_PURGE_TKT_CACHE_REQUEST purge_req;

    purge_req.MessageType = KerbPurgeTicketCacheMessage;
    purge_req.LogonId.LowPart = 0;
    purge_req.LogonId.HighPart = 0;
    purge_req.ServerName.Buffer = L"";
    purge_req.ServerName.Length = 0;
    purge_req.ServerName.MaximumLength = 0;
    purge_req.RealmName.Buffer = L"";
    purge_req.RealmName.Length = 0;
    purge_req.RealmName.MaximumLength = 0;
    status = LsaCallAuthenticationPackage(
        logon_handle,
        package_id,
        &purge_req,
        sizeof(purge_req),
        NULL,
        NULL,
        &sub_status
    );

    if (FAILED(status) || FAILED(sub_status))
        return false;

    LOG(INFO) << "Tickets purged succesfully.";
    return true;
}

#endif

enum optionIndex {
    UNKNOWN,
    HELP,
    SERVICE,
    HOST,
    PORT,
    TIMEOUT,
    PURGE
};

const option::Descriptor usage[] = {
    {UNKNOWN, 0, "" , "" , option::Arg::None,
        "USAGE: tkt-send -h<host> -p<port> [-s<service>]\n\n"
        "Options:" },
    {HELP, 0, "" , "help", option::Arg::None,
        "  --help                     \tPrint usage and exit." },
    {SERVICE, 0, "s", "service", option::Arg::Optional,
        "  -s<service>, --service=<service>  \tLocker service principal." },
    {HOST, 0, "h", "host", option::Arg::Optional,
        "  -h<host>, --host=<host>"
        "  \tLocker service host." },
    {PORT, 0, "p", "port", option::Arg::Optional,
        "  -p<port>, --port=<port>"
        "  \tLocker service port." },
    {TIMEOUT, 0, "t", "timeout", option::Arg::Optional,
        "  -t<sec>, --timeout=<sec>"
        "  \tSocket recv timeout, defaults 60s." },
#ifdef _WIN32
    {PURGE, 0, "" , "purge", option::Arg::None,
        "  --purge                     \tPurge tickets, forcing renew." },
#endif
    {UNKNOWN, 0, "", "", option::Arg::None,
        "\nExamples:\n"
        "  tkt-send -h<host> -p<port> [<service>]\n" },
    {0, 0, 0, 0, 0, 0}
};

int main(int argc, char **argv) {
    init_log();

#ifdef _WIN32
    WSADATA wsaData = {0};
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

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

    std::string service("host");
    if (options[SERVICE] && options[SERVICE].arg) {
        service = options[SERVICE].arg;
    }

    std::string host;
    if (options[HOST] && options[HOST].arg) {
        host = options[HOST].arg;
    }
    else {
        option::printUsage(std::cout, usage);
        return -1;
    }

    int port;
    if (options[PORT] && options[PORT].arg) {
        port = atoi(options[PORT].arg);
    }
    else {
        option::printUsage(std::cout, usage);
        return -1;
    }

    int timeout = _default_recv_timeout;
    if (options[TIMEOUT] && options[TIMEOUT].arg) {
        timeout = atoi(options[TIMEOUT].arg);
    }

#ifdef _WIN32
    if (options[PURGE]) {
        purge_tickets();
    }
#endif

    delete[] options;
    options = NULL;

    delete[] buffer;
    buffer = NULL;

    TktClient tkt_client(host, port, service);

    if (tkt_client.service.size() == 0) {
        option::printUsage(std::cout, usage);
        return -1;
    }

    if(!tkt_client.connect(timeout)) {
        LOG(ERROR) << "Connect failed.";
        return 1;
    }

    if (!tkt_client.handshake()) {
        LOG(ERROR) << "Handshake failed.";
        return 2;
    }

    if (!tkt_client.success()) {
        LOG(ERROR) << "Failed to forward tickets.";
        return 3;
    }

    LOG(INFO) << "Tickets forwarded succesfully.";
    return 0;
}
