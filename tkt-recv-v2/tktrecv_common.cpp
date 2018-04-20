#include "tktrecv.h"

#include <assert.h>

#include <gssapi/gssapi_krb5.h>
#include <easylogging/easylogging++.h>

int set_so_linger(int socket) {
    struct linger so_linger;

    so_linger.l_onoff = 1;
    so_linger.l_linger = 30;
    return setsockopt(socket,
            SOL_SOCKET,
            SO_LINGER,
            (const char *)&so_linger,
            sizeof so_linger
            );
}

struct worker *alloc_worker() {
    struct worker *h = (struct worker *)calloc(1, sizeof(struct worker));
    return h;
}

void display_status_1(const char *m, OM_uint32 code, int type) {
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc msg;
    OM_uint32 msg_ctx;

    msg_ctx = 0;
    while (1) {
        maj_stat = gss_display_status(
                &min_stat, code,
                type, GSS_C_NULL_OID,
                &msg_ctx, &msg);
        LOG(INFO) << "GSS-API error " << m << ": " << (const char *)msg.value;
        gss_release_buffer(&min_stat, &msg);

        if (!msg_ctx)
            break;
    }
}

void display_status(const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat) {
     display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
     display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

void release_worker(struct worker *w) {

    OM_uint32 min;
    if (w->ev) {
        event_free(w->ev);
    }

    worker_bufferevent_free(w, w->buf_network);
    worker_fd_close(w, w->network_fd);

    if (w->gss_buf_in_value) {
        free(w->gss_buf_in_value);
        w->gss_buf_in_value = NULL;
    }

    if (w->peer_name) {
        gss_release_name(&min, &(w->peer_name));
    }

    if (w->ctx) {
        gss_delete_sec_context(&min, &(w->ctx), GSS_C_NO_BUFFER);
    }
}

void free_worker(struct worker *w) {
    release_worker(w);
    free(w);
}

void worker_bufferevent_free(struct worker *w, struct bufferevent *buf) {
    if (buf == NULL) {
        return;
    }
    assert(w);
    if(buf == w->buf_network) {
        w->buf_network = NULL;
    }
    else {
        assert("invalid argument");
    }
    bufferevent_free(buf);
}

void worker_fd_close(struct worker *w, int fd) {
    assert(w);
    if (fd == -1) {
        return;
    }

    if(fd == w->network_fd) {
        w->network_fd = -1;
    }
    else {
        assert("invalid argument");
    }
    close(fd);
}

void gss_buffer_read(struct bufferevent *bev, struct worker *w) {
    struct evbuffer *input  = bufferevent_get_input(bev);
    size_t input_len;

    gss_buffer_t gss_buf = &(w->gss_buf_in);
    if (gss_buf->length == 0) {

        size_t in_buffer_len = evbuffer_get_length(input);
        if (in_buffer_len >= 4 - w->gss_buf_in_len_read) {
            evbuffer_remove(input,
                            w->gss_buf_len_buf + w->gss_buf_in_len_read,
                            4 - w->gss_buf_in_len_read);
            w->gss_buf_in_len_read = 4;
        }
        else {
            evbuffer_remove(input,
                            w->gss_buf_len_buf + w->gss_buf_in_len_read,
                            in_buffer_len);
            w->gss_buf_in_len_read += in_buffer_len;
            return;
        }

        if (w->gss_buf_in_len_read == 4) {

            w->gss_buf_in_read = 0;
            w->gss_buf_in_len_read = 0;
            gss_buf->length = ntohl(*(OM_uint32 *)(w->gss_buf_len_buf));

            // allocate memory to receive the buffer
            if (w->gss_buf_in_len < gss_buf->length) {
                w->gss_buf_in_value = realloc(w->gss_buf_in_value,
                                              gss_buf->length);
                ASSERT(w->gss_buf_in_value, w);
                w->gss_buf_in_len = gss_buf->length;
            }
        }
    }

    // at this point memory is allocated for the buffer to be received
    ASSERT(gss_buf->value == NULL, w);
    while(input_len = evbuffer_get_length(input)) {
        size_t bytes_to_remove  = input_len;
        if (input_len > gss_buf->length - w->gss_buf_in_read) {
            bytes_to_remove = gss_buf->length - w->gss_buf_in_read;
        }

        w->gss_buf_in_read += evbuffer_remove(
                input,
                (char *)w->gss_buf_in_value + w->gss_buf_in_read,
                bytes_to_remove
                );

        if (gss_buf->length == w->gss_buf_in_read) {
            gss_buf->value = w->gss_buf_in_value;
            bufferevent_setwatermark(bev, EV_READ, 4, 0);
            break;
        }
    }
}

void gss_buffer_write(struct bufferevent *bev, gss_buffer_t gss_buf) {
    struct evbuffer *output = bufferevent_get_output(bev);
    uint32_t len = gss_buf->length;
    OM_uint32 min;
    int res;

    assert(gss_buf->value);

    len = htonl(len);

    res = evbuffer_add(output, (void *)&len, sizeof(len));
    res = evbuffer_add(output, gss_buf->value, gss_buf->length);

    gss_release_buffer(&min, gss_buf);
}

void ack_write(struct bufferevent *bev, uint32_t ack) {
    struct evbuffer *output = bufferevent_get_output(bev);
    uint32_t ack_network = htonl(ack);
    int res = evbuffer_add(output, (void *)&ack_network, sizeof(ack_network));
}
