
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#endif

#include "cloud/treadmill-tktfwd/gss.h"

#include <zmq.h>
#include <easylogging/easylogging++.h>

void
display_status_1(const char *m, OM_uint32 code, int type) {
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc msg;
    OM_uint32 msg_ctx;

    msg_ctx = 0;
    while (1) {
        maj_stat = gss_display_status(&min_stat, code,
                type, GSS_C_NULL_OID, &msg_ctx, &msg);
        LOG(ERROR) << "GSS-API error - " << m << ": " <<  (char *) msg.value;
        gss_release_buffer(&min_stat, &msg);

        if (!msg_ctx)
            break;
    }
}

void
display_status(const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat) {
    display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
    display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

int
send_token(void *socket, const gss_buffer_desc &token) {
    zmq_msg_t msg;
    zmq_msg_init_size(&msg, token.length);
    memcpy(zmq_msg_data(&msg), token.value, token.length);
    int rc = zmq_msg_send(&msg, socket, 0);
    LOG(INFO) << "Sent token.length: " << token.length << ", rc: " << rc;
    if (rc < 0) {
        LOG(ERROR) << "Error sending message: " << zmq_strerror(errno);
    }

    zmq_msg_close(&msg);
    return rc;
}

int
recv_token(void *socket, gss_buffer_desc *token) {
    zmq_msg_t msg;
    zmq_msg_init(&msg);
    int rc = zmq_msg_recv(&msg, socket, 0);
    if (rc < 0) {
        LOG(ERROR) << "Error sending message: " << zmq_strerror(errno);
        return rc;
    }
    token->length = zmq_msg_size(&msg);
    LOG(INFO) << "token length: " << token->length;

    token->value = (char *) malloc(token->length ? token->length : 1);
    memcpy(token->value, zmq_msg_data(&msg), token->length);

    return token->length;
}

void
release_token(gss_buffer_desc *token) {
    OM_uint32 min_stat;
    gss_release_buffer(&min_stat, token);
}

int
server_acquire_creds(const char *service_name, gss_cred_id_t *server_creds) {
    gss_name_t server_name = GSS_C_NO_NAME;
    OM_uint32 maj_stat, min_stat;

    maj_stat = gss_acquire_cred(&min_stat, server_name, 0,
            GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
            server_creds, NULL, NULL);
    if (maj_stat != GSS_S_COMPLETE) {
        display_status("acquiring credentials", maj_stat, min_stat);
        return false;
    }

    gss_release_name(&min_stat, &server_name);
    return true;
}

int
server_establish_context(
        void *socket,
        gss_cred_id_t server_creds,
        gss_ctx_id_t *context,
        gss_name_t *client_name,
        gss_OID *doid,
        gss_cred_id_t *client_creds,
        OM_uint32 *ret_flags) {

    gss_buffer_desc send_tok;
    gss_buffer_desc recv_tok;
    OM_uint32 maj_stat;
    OM_uint32 min_stat;

    *context = GSS_C_NO_CONTEXT;
    do {
        recv_token(socket, &recv_tok);
        maj_stat = gss_accept_sec_context(
                &min_stat,
                context,
                server_creds,
                &recv_tok,
                GSS_C_NO_CHANNEL_BINDINGS,
                client_name,
                doid,
                &send_tok,
                ret_flags,
                NULL,	/* ignore time_rec */
                client_creds);

        if (recv_tok.value) {
            free(recv_tok.value);
            recv_tok.value = NULL;
        }

        send_token(socket, send_tok);
        release_token(&send_tok);

        if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
            display_status("accepting context", maj_stat, min_stat);
            if (*context != GSS_C_NO_CONTEXT) {
                gss_delete_sec_context(&min_stat, context, GSS_C_NO_BUFFER);
            }
            return false;
        }

    } while (maj_stat == GSS_S_CONTINUE_NEEDED);

    return true;
}

bool
client_establish_context(
        void *socket,
        const char *service_name,
        OM_uint32 gss_flags,
	    gss_OID oid,
        gss_ctx_id_t *gss_context,
        OM_uint32 *ret_flags) {

    gss_buffer_desc send_tok;
    gss_buffer_desc recv_tok;
    gss_buffer_desc *token_ptr;

    gss_name_t target_name = GSS_C_NO_NAME;
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    OM_uint32 init_sec_min_stat;

    /*
     * Import the name into target_name.  Use send_tok to save
     * local variable space.
     */
    send_tok.value = (void *)service_name;
    send_tok.length = strlen(service_name);
    maj_stat = gss_import_name(&min_stat, &send_tok,
			GSS_C_NT_USER_NAME,
            &target_name);
    if (maj_stat != GSS_S_COMPLETE) {
        display_status("parsing name", maj_stat, min_stat);
        return false;
    }

    token_ptr = GSS_C_NO_BUFFER;
    *gss_context = GSS_C_NO_CONTEXT;

    do {
        maj_stat = gss_init_sec_context(
                &init_sec_min_stat,
                GSS_C_NO_CREDENTIAL,
                gss_context,
                target_name,
                oid,
                gss_flags,
                0,
                NULL,	/* no channel bindings */
                token_ptr,
                NULL,	/* ignore mech type */
                &send_tok,
                ret_flags,
                NULL);	/* ignore time_rec */

        if (token_ptr != GSS_C_NO_BUFFER) {
            free(recv_tok.value);
        }

        if (send_tok.length != 0) {
            if (send_token(socket, send_tok) < 0) {
                LOG(ERROR) << "Error sending token.";
                gss_release_buffer(&min_stat, &send_tok);
                gss_release_name(&min_stat, &target_name);
                return false;
            }
        }
        release_token(&send_tok);
        if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
            display_status("initializing context", maj_stat, init_sec_min_stat);
            gss_release_name(&min_stat, &target_name);
            if (*gss_context != GSS_C_NO_CONTEXT) {
                gss_delete_sec_context(&min_stat, gss_context, GSS_C_NO_BUFFER);
            }
            return false;
        }

        if (maj_stat == GSS_S_CONTINUE_NEEDED) {
            if (recv_token(socket, &recv_tok) < 0) {
                LOG(ERROR) << "Error recv_token.";
                gss_release_name(&min_stat, &target_name);
                return false;
            }
            token_ptr = &recv_tok;
        }
    } while (maj_stat == GSS_S_CONTINUE_NEEDED);

    gss_release_name(&min_stat, &target_name);
    return true;
}
