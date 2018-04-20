#ifndef _CLOUD_TREADMILL_KT_H
#define _CLOUD_TREADMILL_KT_H

#include <string>
#include <vector>
#include <map>
#include <krb5.h>

typedef std::vector<krb5_keytab_entry> keytab_entry_list_t;

typedef std::map<std::string, keytab_entry_list_t> keytab_entry_map_t;

/**
 * Read keytab file into list of keytab entries.
 */
void kt_read(krb5_context kcontext, const std::string kt_filename,
        std::vector<krb5_keytab_entry> &kt_list);

/**
 * Add keytab entries to the keytab file.
 */
void kt_write(krb5_context kcontext, const std::string& kt_filename,
        keytab_entry_list_t& kt_list);

/**
 * Group keytab entries by principal name.
 */
void kt_groupby(krb5_context kcontext, const keytab_entry_list_t& kt_list,
        keytab_entry_map_t& kt_grouped);

#endif  // _CLOUD_TREADMILL_KT_H
