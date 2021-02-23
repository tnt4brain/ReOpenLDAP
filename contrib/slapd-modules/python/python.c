/* python.c - Python overlay invocation */
/* $ReOpenLDAP$ */
/* Copyright 1992-2021 ReOpenLDAP AUTHORS: please see AUTHORS file.
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
 * Initially based on trace.c overlay code - the work by
 * Pierangelo Masarati for inclusion in OpenLDAP Software.
 */

#include "reldap.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "lutil.h"

#include <Python.h>

typedef struct python_info_t {
  PyObject *python_funcs[op_last];
  PyObject *python_funcs_response;
} python_info_t;

char *hook_function_names[] = {
  "bind_hook","unbind_hook","search_hook","compare_hook","modify_hook","modrdn_hook",
  "add_hook","delete_hook","abandon_hook","extended_hook","cancel_hook","aux_op_hook",
  "aux_chk_ref_hook","aux_chk_ctrls_hook",
#ifdef LDAP_X_TXN
  "txn_hook",
#endif
  NULL }; // end-of-table NULL
char hook_function_names_response[] = { "response_hook" };

static slap_overinst python;

static PyThreadState *state;

static int python_op2str(Operation *op, char **op_strp) {
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

static int python_op_func(Operation *op, SlapReply *rs) {
  char *op_str = NULL;
  slap_op_t i;
  PyObject *req_ndn, *req_op, *func_res, *func; // *req_oid
  /* retrieve the configuration structures */
  slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
  python_info_t *pi = (python_info_t *)on->on_bi.bi_private;
  (void)python_op2str(op, &op_str);
  switch(op->o_tag) {
    case LDAP_REQ_BIND:     {i=SLAP_OP_BIND; break;}
    case LDAP_REQ_UNBIND:   {i=SLAP_OP_UNBIND; break;}
    case LDAP_REQ_SEARCH:   {i=SLAP_OP_SEARCH; break;}
    case LDAP_REQ_MODIFY:   {i=SLAP_OP_MODIFY; break;}
    case LDAP_REQ_ADD:      {i=SLAP_OP_ADD; break;}
    case LDAP_REQ_DELETE:   {i=SLAP_OP_DELETE; break;}
    case LDAP_REQ_MODRDN:   {i=SLAP_OP_MODRDN; break;}
    case LDAP_REQ_COMPARE:  {i=SLAP_OP_COMPARE; break;}
    case LDAP_REQ_ABANDON:  {i=SLAP_OP_ABANDON; break;}
    // don't want to support extended operations
    case LDAP_REQ_EXTENDED: {i=SLAP_OP_LAST; break;}
    default: {i=SLAP_OP_LAST;}
  }
  Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "python: operation %s dn=\"%s\"\n",
        op_str,
        BER_BVISNULL(&op->o_req_ndn) ? "(null)" : op->o_req_ndn.bv_val);
  // function table should contain NULLs when given function is invalid
  func = (i==SLAP_OP_LAST) ? NULL : pi->python_funcs[i];
  if (func) {
    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "python: calling function %s\n", hook_function_names[i]);
    { PyGILState_STATE gil_state;
    gil_state = PyGILState_Ensure();
    // some operations have empty ndn
//    if  {
//      req_ndn = Py_None;
//    } else {
//      req_ndn = PyUnicode_FromString();
//    }
    //req_ndn = PyUnicode_FromString(BER_BVISNULL(&op->o_req_ndn) ? "(null)" : op->o_req_ndn.bv_val);
    // this relates to extended operations only, as it just fires SIGSEGV with usual request
    // req_oid = PyUnicode_FromString(BER_BVISNULL(&op->ore_reqoid) ? "" : op->ore_reqoid.bv_val);
    // req_op = PyUnicode_FromString(op_str);
    func_res = PyObject_CallFunction(func, "ss",(BER_BVISNULL(&op->o_req_ndn))?op->o_req_ndn.bv_val:NULL, op_str);
    //if (req_ndn != Py_None) { Py_XDECREF(req_ndn);}
    // Py_XDECREF(req_oid);
    //Py_XDECREF(req_op);
    if (func_res != NULL) {
      if (func_res == Py_None) {
          Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "python: function %s returned None\n",hook_function_names[i]);
        }
        else if ((func_res == Py_False) || (func_res == Py_True)) {
          Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
             "python: function %s returned %s\n",
             hook_function_names[i], (func_res == Py_False) ? "False" : "True");
        } else if (PyUnicode_Check(func_res)) {
          const char* newstr = PyUnicode_AsUTF8(func_res);
          Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,"python: function %s returned string '%s'\n",hook_function_names[i],newstr);
        } else if (PyDict_Check(func_res)) {
          PyObject *key, *value;
          Py_ssize_t pos =0;
          Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,"python: function %s returned dict\n",hook_function_names[i]);
          while (PyDict_Next(func_res, &pos, &key, &value)) {
            Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "python: '%s': v%s\n", PyUnicode_AsUTF8(key), PyUnicode_AsUTF8(value));
            }
          Py_DECREF(key);
          Py_DECREF(value);
        } else {
         Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,"python: function %s returned something else\n",hook_function_names[i]);
        //printf("Result of call: %ld\n", PyLong_AsLong(func_res));
        }
        Py_DECREF(func_res);
    }
    PyGILState_Release(gil_state);}
  } else {
    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "python: function not found\n");
  }
  return SLAP_CB_CONTINUE;
}


static int python_response(Operation *op, SlapReply *rs) {
  char *op_str = NULL;

  (void)python_op2str(op, &op_str);

  switch (op->o_tag) {
  case LDAP_REQ_EXTENDED:
    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
        "%s python op=EXTENDED RESPONSE dn=\"%s\" reqoid=%s rspoid=%s err=%d\n",
        op->o_log_prefix,
        BER_BVISNULL(&op->o_req_ndn) ? "(null)" : op->o_req_ndn.bv_val,
        BER_BVISNULL(&op->ore_reqoid) ? "" : op->ore_reqoid.bv_val,
        rs->sr_rspoid == NULL ? "" : rs->sr_rspoid, rs->sr_err);
    break;

  case LDAP_REQ_SEARCH:
    switch (rs->sr_type) {
    case REP_SEARCH:
      Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
          "%s python op=SEARCH ENTRY dn=\"%s\"\n", op->o_log_prefix,
          rs->sr_entry->e_name.bv_val);
      goto done;

    case REP_SEARCHREF:
      Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
          "%s python op=SEARCH REFERENCE ref=\"%s\"\n", op->o_log_prefix,
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
        "%s python op=%s RESPONSE dn=\"%s\" err=%d\n", op->o_log_prefix, op_str,
        BER_BVISNULL(&op->o_req_ndn) ? "(null)" : op->o_req_ndn.bv_val,
        rs->sr_err);
    break;
  }

done:;
  return SLAP_CB_CONTINUE;
}

static int python_db_init(BackendDB *be, ConfigReply *cr) {
  Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "python DB_INIT\n");
  // python_info_t *pi = NULL;
  /* initialize private structure to store configuration */
  //slap_overinst *on = (slap_overinst *)be->bd_info;
  // pi = (python_info_t *)ch_calloc(1, sizeof(python_info_t));
  // on->on_bi.bi_private = (void *)pi;
  // return either SLAP_CONF_UNKNOWN if shit happened or 0 if OK
  return 0;
}

static int python_db_destroy(BackendDB *be, ConfigReply *cr) {
  Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "python DB_DESTROY\n");
  int i=0;
  slap_overinst *on = (slap_overinst *)be->bd_info;
  python_info_t *pi = (python_info_t *)on->on_bi.bi_private;
  if (pi != NULL) {
    while(i<op_last) {
      if (pi->python_funcs[i]!=NULL) {
        Py_XDECREF(pi->python_funcs[i]);
        pi->python_funcs[i] = NULL;
        Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "%s unloaded\n", hook_function_names[i]);
       }
    i++;
    }
  ch_free(pi);
  on->on_bi.bi_private = NULL;
  }
  return 0;
}


static int python_db_config(BackendDB *be, const char *fname, int lineno,
                           int argc, char **argv) {
  Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
      "python DB_CONFIG argc=%d argv[0]=\"%s\"\n", argc, argv[0]);
  return 0;
}

static int python_db_open(BackendDB *be, ConfigReply *cr) {
  Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "python DB_OPEN\n");
  return 0;
}

static int python_db_close(BackendDB *be, ConfigReply *cr) {
  Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "python DB_CLOSE\n");
  return 0;
}

static int python_initialize() {
  char hook_file_path[] = "/usr/lib64/reopenldap/"; // could be a series of paths separated with ":"
  char hook_file[] = "ldap_hooks"; // filename without ".py" extension
  PyObject *pName, *pModule, *pFunc, *sys, *path, *newPaths;
  int i;
  python_info_t *pi = NULL;

  // Overlay configuration structure init
  memset(&python, 0, sizeof(slap_overinst));

  // Python search path init and module import
  Py_InitializeEx(0); // no signal handlers will be registered
  PyEval_InitThreads();

  sys = PyImport_ImportModule("sys");
  path = PyObject_GetAttrString(sys, "path");
  newPaths = PyUnicode_Split(PyUnicode_FromString(hook_file_path), PyUnicode_FromWideChar(L":", 1), -1);
  for(i=0; i<PyList_Size(newPaths); i++) {
    PyList_Append(path, PyList_GetItem(newPaths, i));
  }
  Py_XDECREF(sys);
  Py_XDECREF(path);
  Py_XDECREF(newPaths);
  pName = PyUnicode_DecodeFSDefault(hook_file);
  if (pName == NULL){
    Py_Finalize();
    return 1;
  }
  pModule = PyImport_Import(pName);
  fprintf(stderr, "Module %s found in %s\n", hook_file, hook_file_path);
  Py_DECREF(pName);

  if (pModule != NULL) {
  // Allocate memory area for hook presence table
  pi = (python_info_t *)ch_malloc(sizeof(python_info_t));
  // ... then clear it ...
  memset(pi, 0, sizeof(python_info_t));
  // ... then store pointer into private area (overlay can use it any sane way)
  python.on_bi.bi_private = pi;
  int i=op_bind;
  while(i<op_last) {
    if (hook_function_names[i]!=NULL) {
      pFunc = PyObject_GetAttrString(pModule,hook_function_names[i]);
      if (pFunc && PyCallable_Check(pFunc)) {
        pi->python_funcs[i] = pFunc;
        Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "%s is present\n", hook_function_names[i] );
        } else {
        pi->python_funcs[i] = NULL;
        Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "%s is missing\n", hook_function_names[i] );
        Py_XDECREF(pFunc);
        }
      }
    i++;
    }
  pFunc = PyObject_GetAttrString(pModule, hook_function_names_response);
  if (pFunc && PyCallable_Check(pFunc)) {
    pi->python_funcs_response = pFunc;
    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "%s is present\n", hook_function_names_response);
    }
  else {
    pi->python_funcs_response = NULL;
    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "%s is missing\n", hook_function_names_response);
    Py_XDECREF(pFunc);
    }
  python.on_bi.bi_type = "python";
  python.on_bi.bi_db_init = python_db_init;
  python.on_bi.bi_db_open = python_db_open;
  python.on_bi.bi_db_config = python_db_config;
  python.on_bi.bi_db_close = python_db_close;
  python.on_bi.bi_db_destroy = python_db_destroy;

  python.on_bi.bi_op_add = python_op_func;
  python.on_bi.bi_op_bind = python_op_func;
  python.on_bi.bi_op_unbind = python_op_func;
  python.on_bi.bi_op_compare = python_op_func;
  python.on_bi.bi_op_delete = python_op_func;
  python.on_bi.bi_op_modify = python_op_func;
  python.on_bi.bi_op_modrdn = python_op_func;
  python.on_bi.bi_op_search = python_op_func;
  python.on_bi.bi_op_abandon = python_op_func;
  python.on_bi.bi_extended = python_op_func;

  python.on_response = python_response;
  state = PyEval_SaveThread();
  return overlay_register(&python);
  } else {
  Py_Finalize();
  return 1;}
}

SLAP_MODULE_ENTRY(python, modinit)(int argc, char *argv[]) {
  return python_initialize();
}
