#ifndef _WIN32

#include "creds.h"

#include <errno.h>
#include <unistd.h>

#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>
#include <easylogging/easylogging++.h>

#define krb5_get_err_text(context,code) error_message(code)

bool
ssh_gssapi_krb5_init(krb5_context *context) {
	krb5_error_code problem = krb5_init_context(context);
	if (problem) {
        LOG(ERROR) << "Cannot initialize krb5 context: rc = " << problem;
		return false;
	}

	return true;
}

krb5_error_code
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache) {
    char ccname_tmp[40];
	int ret = snprintf(ccname_tmp, sizeof(ccname_tmp),
	    "FILE:/tmp/krb5cc_%d_XXXXXXXXXX", geteuid());
	if (ret < 0 || (size_t)ret >= sizeof(ccname_tmp)) {
		return ENOMEM;
    }

	mode_t old_umask = umask(0177);
	int tmpfd = mkstemp(ccname_tmp + strlen("FILE:"));
	umask(old_umask);
	if (tmpfd == -1) {
        LOG(ERROR) << "mkstemp: " << strerror(errno);
		return errno;
	}

	if (fchmod(tmpfd,S_IRUSR | S_IWUSR) == -1) {
        LOG(ERROR) << "fchmod: " << strerror(errno);
		close(tmpfd);
		return errno;
	}
	close(tmpfd);

    LOG(INFO) << "Ticket file: " << ccname_tmp;
	return krb5_cc_resolve(ctx, ccname_tmp, ccache);
}

const std::string
ssh_gssapi_krb5_storecreds(
        krb5_context krb_context,
	    gss_cred_id_t creds,
	    const char *exportedname) {

    krb5_ccache ccache;
	krb5_error_code problem;
	krb5_principal princ;
	OM_uint32 maj_status, min_status;
	int len;
    std::string empty;

    LOG(INFO) << "About to store creds: " << exportedname;
	if (creds == NULL) {
        LOG(ERROR) << "No credentials storedxx";
		return empty;
	}

#ifdef HEIMDAL
    // TODO(andreik) - keeping the Heimdal code as placeholder.
	if ((problem = krb5_cc_gen_new(krb_context, &krb5_fcc_ops, &ccache))) {
        LOG(ERROR) << "krb5_cc_gen_new: "
                   << krb5_get_err_text(krb_context, problem);
		return empty;
	}
#else
	if ((problem = ssh_krb5_cc_gen(krb_context, &ccache))) {
		LOG(ERROR) << "ssh_krb5_cc_gen: "
		           << krb5_get_err_text(krb_context, problem);
		return empty;
	}
#endif	/* #ifdef HEIMDAL */

	if ((problem = krb5_parse_name(krb_context, exportedname, &princ))) {
		LOG(ERROR) << "krb5_parse_name: "
		           << krb5_get_err_text(krb_context, problem);
		krb5_cc_destroy(krb_context, ccache);
		return empty;
	}

	if ((problem = krb5_cc_initialize(krb_context, ccache, princ))) {
		LOG(ERROR) << "krb5_cc_initialize: "
		           << krb5_get_err_text(krb_context, problem);
		krb5_free_principal(krb_context, princ);
		krb5_cc_destroy(krb_context, ccache);
		return empty;
	}

	krb5_free_principal(krb_context, princ);
	if ((maj_status = gss_krb5_copy_ccache(&min_status, creds, ccache))) {
		LOG(ERROR) << "gss_krb5_copy_ccache failed.";
		krb5_cc_destroy(krb_context, ccache);
		return empty;
	}

	std::string new_ccname = krb5_cc_get_name(krb_context, ccache);

    LOG(INFO) << "Ticket file: " << new_ccname;
	krb5_cc_close(krb_context, ccache);

    return new_ccname;
}

#endif  // #ifndef _WIN32
