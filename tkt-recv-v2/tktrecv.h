#ifndef TKT_RECV_H
#define TKT_RECV_H

#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include <gssapi/gssapi_generic.h>

#include <string>

// libevent
#include <event.h>

class CredMgr;

struct worker {
    // used to schedule handshake callbacks
    //
    const CredMgr *cred_mgr;

    struct event *ev;

    struct bufferevent *buf_network;

    int network_fd;

    // for server
    struct sockaddr_in peeraddr;

    gss_buffer_desc gss_buf_in;
    void  *gss_buf_in_value;
    size_t gss_buf_in_read;

    size_t gss_buf_in_len;
    size_t gss_buf_in_len_read;
    char gss_buf_len_buf[4];

    gss_name_t peer_name;
	gss_ctx_id_t ctx;
};

struct worker *alloc_worker();
void free_worker(struct worker *w);
void release_worker(struct worker *w);
void worker_bufferevent_free(struct worker *w, struct bufferevent *buf);
void worker_fd_close(struct worker *w, int fd);

int  set_so_linger(int socket);
void gss_buffer_write(struct bufferevent *bev, gss_buffer_t gss_buf);
void gss_buffer_read(struct bufferevent *bev, struct worker *w);
void ack_write(struct bufferevent *bev, uint32_t ack);
int run_server(int port, const std::string& tkt_spool_dir);
void display_status(const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat);

extern struct event_base *g_evbase;

#define HANDSHAKE_OK(major, minor, h) \
    if (GSS_ERROR(major)) {     \
        LOG(INFO) << "major: " << major << ", minor: " << minor; \
        close(h->network_fd);   \
        free_worker(h);      \
        return;                 \
    }

#define ASSERT(cond, worker) \
    if (!(cond)) { \
        fprintf(stderr, "fatal: %s:%d: %s\n", __FILE__, __LINE__, __STRING(cond)); \
        if (worker) { \
            free_worker(worker); \
        } \
        return; \
    }

#endif  // #define TKT_RECV_H
