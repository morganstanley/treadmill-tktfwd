
#ifndef _CLOUD_TREADMILL_KRB_CREDS_H
#define _CLOUD_TREADMILL_KRB_CREDS_H

#include <string>

extern "C" {
    #include <gssapi/gssapi_generic.h>
    #include <krb5.h>
}

bool
ssh_gssapi_krb5_init(krb5_context *context);

krb5_error_code
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache);

const std::string
ssh_gssapi_krb5_storecreds(
        krb5_context krb_context,
	    gss_cred_id_t creds,
	    const char *exportedname);

#endif  //  _CLOUD_TREADMILL_KRB_CREDS_H
