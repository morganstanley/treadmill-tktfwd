#ifndef _CLOUD_TREADMILL_KRB_MISC_H
#define _CLOUD_TREADMILL_KRB_MISC_H

#include <stdlib.h>
#include <string.h>

#include <krb5.h>
#include <gssapi/gssapi_generic.h>

class GssTransport {
    virtual int send(const gss_buffer_desc &token) = 0;
    virtual int recv(gss_buffer_desc *token) = 0;
};

void
display_status_1(const char *m, OM_uint32 code, int type);

void
display_status(const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat);

int
send_token(void *socket, const gss_buffer_desc &token);

int
recv_token(void *socket, gss_buffer_desc *token);

void
release_token(gss_buffer_desc *token);

int
server_acquire_creds(const char *service_name, gss_cred_id_t *server_creds);

int
server_establish_context(
        void *socket,
        gss_cred_id_t server_creds,
        gss_ctx_id_t *context,
        gss_name_t *client_name,
        gss_OID *doid,
        gss_cred_id_t *client_creds,
        OM_uint32 *ret_flags);

bool
client_establish_context(
        void *socket,
        const char *service_name,
        OM_uint32 gss_flags,
	    gss_OID oid,
        gss_ctx_id_t *gss_context,
        OM_uint32 *ret_flags);


#endif  //  _CLOUD_TREADMILL_KRB_MISC_H
