#ifndef _CRED_MGR_H
#define _CRED_MGR_H

#include <krb5.h>
#include <gssapi/gssapi_generic.h>

#include <string>

class CredMgr {
public:
    CredMgr(const std::string& tkt_spool_dir_);
    ~CredMgr();

    bool store_creds(const std::string& accepted_princ,
                     gss_cred_id_t client_creds) const;

private:
    krb5_context krb_context;
    std::string tkt_spool_dir;
    std::string me;
    int euid;
};

#endif  // _CRED_MGR_H
