#ifndef _WIN32

#include "kt.h"

#include <easylogging/easylogging++.h>

/**
 * Read keytab file into list of keytab entries.
 */
void kt_read(krb5_context kcontext, const std::string kt_filename,
        std::vector<krb5_keytab_entry> &kt_list) {

    krb5_error_code retval = 0;
    krb5_keytab kt;
    retval = krb5_kt_resolve(kcontext, kt_filename.c_str(), &kt);
    if (retval != 0) {
        LOG(ERROR) << "krb5_kt_resolve: " << retval;
        exit(-1);
    }

    krb5_kt_cursor cursor;
    retval = krb5_kt_start_seq_get(kcontext, kt, &cursor);
    if (retval != 0) {
        LOG(ERROR) << "krb5_kt_start_seq_get: " << retval;
        exit(-1);
    }

    for (;;) {
        krb5_keytab_entry entry;
        retval = krb5_kt_next_entry(kcontext, kt, &entry, &cursor);

        if (retval) {
            break;
        }

        kt_list.push_back(entry);
    }

    krb5_kt_end_seq_get(kcontext, kt, &cursor);
    krb5_kt_close(kcontext, kt);
}

/**
 * Add keytab entries to the keytab file.
 */
void kt_write(krb5_context kcontext, const std::string& kt_filename,
        keytab_entry_list_t& kt_list) {

    krb5_error_code retval = 0;
    krb5_keytab kt;

    std::string kt_filename_w = "WRFILE:" + kt_filename;
    retval = krb5_kt_resolve(kcontext, kt_filename_w.c_str(), &kt);
    if (retval != 0) {
        LOG(ERROR) << "krb5_kt_resolve: " << retval;
        exit(-1);
    }

    for (keytab_entry_list_t::iterator it = kt_list.begin();
            it != kt_list.end(); ++it) {
        krb5_keytab_entry &entry = *it;
        retval = krb5_kt_add_entry(kcontext, kt, &entry);
        if (retval) {
            break;
        }
    }
    krb5_kt_close(kcontext, kt);
}

/**
 * Group keytab entries by principal name.
 */
void kt_groupby(krb5_context kcontext, const keytab_entry_list_t& kt_list,
        keytab_entry_map_t& kt_grouped) {

    krb5_error_code retval = 0;
    for (keytab_entry_list_t::const_iterator it = kt_list.begin();
            it != kt_list.end(); ++it) {

        const krb5_keytab_entry &entry = *it;

        char *name;
        retval = krb5_unparse_name(kcontext, entry.principal, &name);
        std::string princ_name(name);
        kt_grouped[princ_name].push_back(entry);

        krb5_free_unparsed_name(kcontext, name);
    }
}

#endif  // _WIN32
