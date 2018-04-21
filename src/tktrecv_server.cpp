#include "tktrecv.h"
#include "creds.h"
#include "credmgr.h"

#include <assert.h>

#include <gssapi/gssapi_krb5.h>
#include <easylogging/easylogging++.h>

// Close connection and free all resources.
void on_server_handshake_complete(int fd, short ev, void *arg) {
    LOG(INFO) << "Closing connection, fd: " << fd;

    struct worker *h = (struct worker *)arg;
    close(h->network_fd);
    free_worker(h);
}

// The callback is invoked when buffer state changes. If there is nothing
// to send, it will remove itself from the callback list and schedule
// connection shutdown.
void schedule_handshake_complete_cb(struct evbuffer *buffer,
                                    const struct evbuffer_cb_info *info,
                                    void *arg) {
    struct worker *h = (struct worker *)arg;
    size_t len = evbuffer_get_length(buffer);

    if (len == 0) {
        evbuffer_remove_cb(buffer, schedule_handshake_complete_cb, h);

        assert(h->ev);
        evtimer_assign(
                h->ev,
                g_evbase,
                on_server_handshake_complete,
                h
                );

        struct timeval t0 = {0, 0};
        evtimer_add(h->ev, &t0);
    }
}

void server_read_handshake_cb(struct bufferevent *bev, void *arg) {
    struct worker *h = (struct worker *)arg;

    gss_buffer_read(bev, h);
    if (h->gss_buf_in.value) {

        OM_uint32 maj, min;
        gss_buffer_desc gss_buf_out;
        gss_cred_id_t client_creds;

	    maj = gss_accept_sec_context(
                &min,
                &(h->ctx),
                GSS_C_NO_CREDENTIAL,
                &(h->gss_buf_in),
                GSS_C_NO_CHANNEL_BINDINGS,
                &(h->peer_name),
                NULL,
                &gss_buf_out,
                NULL,
                NULL,
                &client_creds
                );
        display_status("gss_accept_sec_context: ", maj, min);
        LOG(INFO) << "client_creds: " << client_creds;

        HANDSHAKE_OK(maj, min, h);
        gss_buffer_write(bev, &gss_buf_out);
        gss_release_buffer(&min, &gss_buf_out);

        if (maj & GSS_S_CONTINUE_NEEDED) {
            LOG(INFO) << "Handshake got GSS_S_CONTINUE_NEEDED.";
        }
        else {
            gss_buffer_desc	buf;
	        maj = gss_display_name(&min, h->peer_name, &buf, NULL);
            HANDSHAKE_OK(maj, min, h);

            std::string accepted_princ;

            accepted_princ.assign((const char *)buf.value);

            socklen_t len = sizeof(h->peeraddr);
            getpeername(h->network_fd,(struct sockaddr *)&(h->peeraddr), &len);
            LOG(INFO) << "Accepted connection from: "
                      << accepted_princ
                      << " on " << inet_ntoa(h->peeraddr.sin_addr)
                      << ":" << ntohs(h->peeraddr.sin_port);

		    gss_release_buffer(&min, &buf);
            gss_release_name(&min, &(h->peer_name));
            h->peer_name = NULL;

            if (h->cred_mgr->store_creds(accepted_princ, client_creds)) {
                ack_write(bev, 0);
            }
            else {
                ack_write(bev, 1);
            }

            bufferevent_disable(bev, EV_READ);
            struct evbuffer *output = bufferevent_get_output(bev);
            evbuffer_add_cb(output, schedule_handshake_complete_cb, h);
        }

        h->gss_buf_in_read = 0;
        h->gss_buf_in.length = 0;
        h->gss_buf_in.value = NULL;
    }
}

void server_write_handshake_cb(struct bufferevent *bev, void *arg) {
    struct worker *h = (struct worker *)arg;
}

void server_handshake_err_cb(struct bufferevent *bev, short error, void *arg) {
    LOG(ERROR) << "Handshake error.";

    struct worker *h = (struct worker *)arg;
    close(h->network_fd);
    free_worker(h);
}

void on_server_handshake_begin(int fd, short ev, void *arg) {

    LOG(INFO) << "Begin handshake, fd: " << fd;

    struct worker *h = (struct worker *)arg;

    OM_uint32 maj, min;

    h->ctx = GSS_C_NO_CONTEXT;
    h->gss_buf_in.length  = 0;

    h->buf_network = bufferevent_socket_new(
        g_evbase, h->network_fd, BEV_OPT_CLOSE_ON_FREE);
    assert(h->buf_network);
    bufferevent_setcb(
        h->buf_network,
        server_read_handshake_cb,
        server_write_handshake_cb,
        server_handshake_err_cb, h
    );
    bufferevent_setwatermark(h->buf_network, EV_READ, 4, 0);
    bufferevent_enable(h->buf_network, EV_READ|EV_WRITE);
}

// Accept connection and schedule callback to start GSS handshake.
void on_accept(int fd, short ev, void *arg) {

    LOG(INFO) << "Accepted connection, fd: " << fd;

    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    client_fd = accept(fd, (struct sockaddr *)&client_addr,  &client_len);
    if (client_fd < 0) {
        perror("client: accept() failed");
        return;
    }

    evutil_make_socket_nonblocking(client_fd);
    set_so_linger(client_fd);
    fcntl(client_fd, FD_CLOEXEC);

    struct worker *h = alloc_worker();
    h->network_fd = client_fd;

    assert(h->ev == NULL);
    h->ev = evtimer_new(g_evbase, on_server_handshake_begin, h);

    h->cred_mgr = (const CredMgr *)(arg);

    struct timeval t0 = {0, 0};
    evtimer_add(h->ev, &t0);
}

int run_server(int port, const std::string& tkt_spool_dir) {

    int socketlisten;
    struct sockaddr_in addresslisten;
    struct event *accept_event;
    struct event *gc_event;
    int reuse = 1;

    socketlisten = socket(AF_INET, SOCK_STREAM, 0);

    if (socketlisten < 0) {
        perror("Failed to create listen socket");
        return -1;
    }

    memset(&addresslisten, 0, sizeof(addresslisten));

    addresslisten.sin_family = AF_INET;
    addresslisten.sin_addr.s_addr = INADDR_ANY;
    addresslisten.sin_port = htons(port);

    setsockopt(socketlisten, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    fcntl(socketlisten, FD_CLOEXEC);

    if (bind(socketlisten,
             (struct sockaddr *)&addresslisten,
             sizeof(addresslisten)) < 0) {
        perror("Failed to bind");
        return -1;
    }

    if (listen(socketlisten, 20) < 0) {
        perror("Failed to listen to socket");
        return -1;
    }

    evutil_make_socket_nonblocking(socketlisten);

    CredMgr cred_mgr(tkt_spool_dir);

    accept_event = event_new(
            g_evbase,
            socketlisten,
            EV_READ|EV_PERSIST,
            on_accept,
            (void *)&cred_mgr
            );

    event_add(accept_event, NULL);
    event_base_dispatch(g_evbase);
    return 0;
}
