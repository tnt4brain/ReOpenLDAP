/* python_hook.c - python_hook overlay */
/* $ReOpenLDAP$ */
/* Copyright 1992-2018 ReOpenLDAP AUTHORS: please see AUTHORS file.
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
 * This code was written as a research/excercise in embedding Python into real-world application.
 * It is based on "trace.c" overlay code that was initially developed by Pierangelo Masarati 
 * for inclusion in OpenLDAP Software.
 */



#include "reldap.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "lutil.h"

#include <Python.h>

static int python_hook_op2str(Operation *op, char **op_strp) {
  switch (op->o_tag) {
  case LDAP_REQ_BIND:
    *op_strp = "BIND";
    break;

  case LDAP_REQ_UNBIND:
    *op_strp = "UNBIND";
    break;

  case LDAP_REQ_SEARCH:
    *op_strp = "SEARCH";
    break;

  case LDAP_REQ_MODIFY:
    *op_strp = "MODIFY";
    break;

  case LDAP_REQ_ADD:
    *op_strp = "ADD";
    break;

  case LDAP_REQ_DELETE:
    *op_strp = "DELETE";
    break;

  case LDAP_REQ_MODRDN:
    *op_strp = "MODRDN";
    break;

  case LDAP_REQ_COMPARE:
    *op_strp = "COMPARE";
    break;

  case LDAP_REQ_ABANDON:
    *op_strp = "ABANDON";
    break;

  case LDAP_REQ_EXTENDED:
    *op_strp = "EXTENDED";
    break;

  default:
    assert(0);
  }

  return 0;
}

static int python_hook_op_func(Operation *op, SlapReply *rs) {
  char *op_str = NULL;

  (void)python_hook_op2str(op, &op_str);

  switch (op->o_tag) {
  case LDAP_REQ_EXTENDED:
    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
        "%s trace op=EXTENDED dn=\"%s\" reqoid=%s\n", op->o_log_prefix,
        BER_BVISNULL(&op->o_req_ndn) ? "(null)" : op->o_req_ndn.bv_val,
        BER_BVISNULL(&op->ore_reqoid) ? "" : op->ore_reqoid.bv_val);
    break;

  default:
    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "%s trace op=%s dn=\"%s\"\n",
        op->o_log_prefix, op_str,
        BER_BVISNULL(&op->o_req_ndn) ? "(null)" : op->o_req_ndn.bv_val);
    break;
  }

  return SLAP_CB_CONTINUE;
}

static int python_hook_response(Operation *op, SlapReply *rs) {
  char *op_str = NULL;

  (void)python_hook_op2str(op, &op_str);

  switch (op->o_tag) {
  case LDAP_REQ_EXTENDED:
    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
        "%s trace op=EXTENDED RESPONSE dn=\"%s\" reqoid=%s rspoid=%s err=%d\n",
        op->o_log_prefix,
        BER_BVISNULL(&op->o_req_ndn) ? "(null)" : op->o_req_ndn.bv_val,
        BER_BVISNULL(&op->ore_reqoid) ? "" : op->ore_reqoid.bv_val,
        rs->sr_rspoid == NULL ? "" : rs->sr_rspoid, rs->sr_err);
    break;

  case LDAP_REQ_SEARCH:
    switch (rs->sr_type) {
    case REP_SEARCH:
      Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
          "%s trace op=SEARCH ENTRY dn=\"%s\"\n", op->o_log_prefix,
          rs->sr_entry->e_name.bv_val);
      goto done;

    case REP_SEARCHREF:
      Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
          "%s trace op=SEARCH REFERENCE ref=\"%s\"\n", op->o_log_prefix,
          rs->sr_ref[0].bv_val);
      goto done;

    case REP_RESULT:
      break;

    default:
      assert(0);
    }
    /* fallthru */

  default:
    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
        "%s trace op=%s RESPONSE dn=\"%s\" err=%d\n", op->o_log_prefix, op_str,
        BER_BVISNULL(&op->o_req_ndn) ? "(null)" : op->o_req_ndn.bv_val,
        rs->sr_err);
    break;
  }

done:;
  return SLAP_CB_CONTINUE;
}

static int python_hook_db_init(BackendDB *be, ConfigReply *cr) {
  Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "trace DB_INIT\n");

  return 0;
}

static int python_hook_db_config(BackendDB *be, const char *fname, int lineno,
                           int argc, char **argv) {
  Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
      "trace DB_CONFIG argc=%d argv[0]=\"%s\"\n", argc, argv[0]);

  return 0;
}

static int python_hook_db_open(BackendDB *be, ConfigReply *cr) {
  Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "trace DB_OPEN\n");

  return 0;
}

static int python_hook_db_close(BackendDB *be, ConfigReply *cr) {
  Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "trace DB_CLOSE\n");

  return 0;
}

static int python_hook_db_destroy(BackendDB *be, ConfigReply *cr) {
  Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "trace DB_DESTROY\n");

  return 0;
}

static slap_overinst python_hook;

static int python_hook_initialize() {
  python_hook.on_bi.bi_type = "python_hook";

  python_hook.on_bi.bi_db_init = python_hook_db_init;
  python_hook.on_bi.bi_db_open = python_hook_db_open;
  python_hook.on_bi.bi_db_config = python_hook_db_config;
  python_hook.on_bi.bi_db_close = python_hook_db_close;
  python_hook.on_bi.bi_db_destroy = python_hook_db_destroy;

  python_hook.on_bi.bi_op_add = python_hook_op_func;
  python_hook.on_bi.bi_op_bind = python_hook_op_func;
  python_hook.on_bi.bi_op_unbind = python_hook_op_func;
  python_hook.on_bi.bi_op_compare = python_hook_op_func;
  python_hook.on_bi.bi_op_delete = python_hook_op_func;
  python_hook.on_bi.bi_op_modify = python_hook_op_func;
  python_hook.on_bi.bi_op_modrdn = python_hook_op_func;
  python_hook.on_bi.bi_op_search = python_hook_op_func;
  python_hook.on_bi.bi_op_abandon = python_hook_op_func;
  python_hook.on_bi.bi_extended = python_hook_op_func;

  python_hook.on_response = python_hook_response;

  return overlay_register(&python_hook);
}

SLAP_MODULE_ENTRY(python_hook, modinit)(int argc, char *argv[]) {
  return python_hook_initialize();
}
