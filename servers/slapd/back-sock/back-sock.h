/* $ReOpenLDAP$ */
/* Copyright 2007-2018 ReOpenLDAP AUTHORS: please see AUTHORS file.
 * All rights reserved.
 *
 * This file is part of ReOpenLDAP.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Brian Candler for inclusion
 * in OpenLDAP Software.
 */

#ifndef SLAPD_SOCK_H
#define SLAPD_SOCK_H

#include "proto-sock.h"

LDAP_BEGIN_DECL

struct sockinfo {
  const char *si_sockpath;
  slap_mask_t si_extensions;
  slap_mask_t si_ops;   /* overlay: operations to act on */
  slap_mask_t si_resps; /* overlay: responses to forward */
  regex_t si_dnpat;     /* overlay: DN pattern to match */
  struct berval si_dnpatstr;
};

#define SOCK_EXT_BINDDN 1
#define SOCK_EXT_PEERNAME 2
#define SOCK_EXT_SSF 4
#define SOCK_EXT_CONNID 8

extern FILE *opensock(const char *sockpath);

extern void sock_print_suffixes(FILE *fp, BackendDB *bd);

extern void sock_print_conn(FILE *fp, Connection *conn, struct sockinfo *si);

extern int sock_read_and_send_results(Operation *op, SlapReply *rs, FILE *fp);

LDAP_END_DECL

#endif
