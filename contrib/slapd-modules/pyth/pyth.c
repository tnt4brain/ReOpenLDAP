/* pyth.c - python overlay */
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


// int  pyth_presence[op_last];
// array that stores hook functions
PyObject *pyth_funcs[op_last];
PyObject *pyth_funcs_response;
char *hook_functions[] = {
  "bind_hook","unbind_hook","search_hook","compare_hook","modify_hook","modrdn_hook",
  "add_hook","delete_hook","abandon_hook","extended_hook","cancel_hook","aux_op_hook",
  "aux_chk_ref_hook","aux_chk_ctrls_hook",
#ifdef LDAP_X_TXN
  "txn_hook",
#endif
  NULL }; // end-of-table NULL
char hook_function_response[] = { "response_hook" };

static int pyth_op2str(Operation *op, char **op_strp) {
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

static int pyth_op_func(Operation *op, SlapReply *rs) {
  char *op_str = NULL;
  PyObject *req_ndn, *req_oid, *req_op, *func_res, *func;
  (void)pyth_op2str(op, &op_str);
  slap_op_t i;
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
    case LDAP_REQ_EXTENDED: {i=SLAP_OP_EXTENDED; break;}
    default: {i=SLAP_OP_LAST;}
  }
  fprintf(stderr, "pyth: operation %d\n", i);
  func = (i==SLAP_OP_LAST) ? NULL : pyth_funcs[i];
  if (func) {
    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "Function found\n");
    req_ndn = PyUnicode_FromString(BER_BVISNULL(&op->o_req_ndn) ? "(null)" : op->o_req_ndn.bv_val);
    req_oid = PyUnicode_FromString(BER_BVISNULL(&op->ore_reqoid) ? "" : op->ore_reqoid.bv_val);
    req_op = PyUnicode_FromString(op_str);
    func_res = PyObject_CallFunctionObjArgs(func, req_ndn, req_oid, req_op);
    Py_XDECREF(req_ndn);
    Py_XDECREF(req_oid);
    Py_XDECREF(req_op);
    if (func_res != NULL) {
      if (func_res == Py_None) {
         Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "None result upon return from %s\n",hook_functions[i]);
        }
        else if ((func_res == Py_False) || (func_res == Py_True)) {
         Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
             "Bool result %s upon return from %s\n",
             ((func_res == Py_False) ? "False" : "True"), hook_functions[i]);
        } else if (PyUnicode_Check(func_res)) {
         const char* newstr = PyUnicode_AsUTF8(func_res);
         Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,"String result %s upon return from %s\n",newstr,hook_functions[i]);
        } else if (PyDict_Check(func_res)) {
         PyObject *key, *value;
         Py_ssize_t pos =0;
         Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,"Dict result upon return from %s\n",hook_functions[i]);
         while (PyDict_Next(func_res, &pos, &key, &value)) {
          Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "%s: %s\n", PyUnicode_AsUTF8(key), PyUnicode_AsUTF8(value));
         }
         Py_DECREF(key);
         Py_DECREF(value);
        } else {
        //printf("Result of call: %ld\n", PyLong_AsLong(func_res));
        Py_DECREF(func_res);
        }
    }

    if (op->o_tag == LDAP_REQ_EXTENDED) {
      Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
        "%s hook op=EXTENDED dn=\"%s\" reqoid=%s\n", op->o_log_prefix,
        BER_BVISNULL(&op->o_req_ndn) ? "(null)" : op->o_req_ndn.bv_val,
        BER_BVISNULL(&op->ore_reqoid) ? "" : op->ore_reqoid.bv_val);
    } else {
      Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "%s hook op=%s dn=\"%s\"\n",
        op->o_log_prefix, op_str,
        BER_BVISNULL(&op->o_req_ndn) ? "(null)" : op->o_req_ndn.bv_val);
    }
  } else {
    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "Function not found\n");
  }

  return SLAP_CB_CONTINUE;
}
static int pyth_response(Operation *op, SlapReply *rs) {
  char *op_str = NULL;
  (void)pyth_op2str(op, &op_str);
  switch (op->o_tag) {
  case LDAP_REQ_EXTENDED:
    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
        "%s hook op=EXTENDED RESPONSE dn=\"%s\" reqoid=%s rspoid=%s err=%d\n",
        op->o_log_prefix,
        BER_BVISNULL(&op->o_req_ndn) ? "(null)" : op->o_req_ndn.bv_val,
        BER_BVISNULL(&op->ore_reqoid) ? "" : op->ore_reqoid.bv_val,
        rs->sr_rspoid == NULL ? "" : rs->sr_rspoid, rs->sr_err);
    break;
  case LDAP_REQ_SEARCH:
    switch (rs->sr_type) {
    case REP_SEARCH:
      Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
          "%s hook op=SEARCH ENTRY dn=\"%s\"\n", op->o_log_prefix,
          rs->sr_entry->e_name.bv_val);
      goto done;
    case REP_SEARCHREF:
      Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
          "%s hook op=SEARCH REFERENCE ref=\"%s\"\n", op->o_log_prefix,
          rs->sr_ref[0].bv_val);
      goto done;
    case REP_RESULT:
      break;
    default:
      assert(0);
    }
    // fallthru
  default:
    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
        "%s hook op=%s RESPONSE dn=\"%s\" err=%d\n", op->o_log_prefix, op_str,
        BER_BVISNULL(&op->o_req_ndn) ? "(null)" : op->o_req_ndn.bv_val,
        rs->sr_err);
    break;
  }
done:;
  return SLAP_CB_CONTINUE;
}



static slap_overinst pyth;

static int pyth_initialize() {
  char hook_file_path[] = "/usr/lib64/reopenldap/"; // could be a series of paths separated with ":"
  char hook_file[] = "ldap_hooks"; // filename without ".py" extension

  PyObject *pName, *pModule, *pFunc,
  //*pValue,
  *sys, *path, *newPaths;
  int i;


  // Overlay configuration structure init
  memset(&pyth, 0, sizeof(slap_overinst));

  // Python stuff init
  Py_InitializeEx(0); // no signal handlers will be registered
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
    return 1;
  }
  pModule = PyImport_Import(pName);
  fprintf(stderr, "Module %s found in %s\n", hook_file, hook_file_path);
  Py_DECREF(pName);

  if (pModule != NULL) {

    // Allocate memory area for hook presence table
    // pyth_funcs = ch_malloc(sizeof(pyth_funcs));
    // ... then clear it ...
    memset(pyth_funcs, 0, sizeof(pyth_funcs));
    // ... then store pointer into private area (overlay can use it any sane way)
    pyth.on_bi.bi_private = pyth_funcs;
    int i=op_bind;
    while(i<op_last) {
      if (hook_functions[i]!=NULL) {
        pFunc = PyObject_GetAttrString(pModule,hook_functions[i]);
        if (pFunc && PyCallable_Check(pFunc)) {
          pyth_funcs[i] = pFunc;
          Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "%s is present\n", hook_functions[i] );
          } else {
          pyth_funcs[i] = NULL;
          Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "%s is missing\n", hook_functions[i] );
          Py_XDECREF(pFunc);
          }
      }
      i++;
    }
    pFunc = PyObject_GetAttrString(pModule, hook_function_response);
    if (pFunc && PyCallable_Check(pFunc)) {
      pyth_funcs_response = pFunc;
      Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "%s is present\n", hook_function_response);
      }
    else {
      pyth_funcs_response = NULL;
      Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "%s is missing\n", hook_function_response);
      Py_XDECREF(pFunc);
    }

    pyth.on_bi.bi_type = "pyth";

    pyth.on_bi.bi_op_bind = pyth_funcs[op_bind] ? pyth_op_func : NULL;
    pyth.on_bi.bi_op_unbind = pyth_funcs[op_unbind] ? pyth_op_func : NULL;
    pyth.on_bi.bi_op_search = pyth_funcs[op_search] ? pyth_op_func : NULL;
    pyth.on_bi.bi_op_compare = pyth_funcs[op_compare] ? pyth_op_func : NULL;
    pyth.on_bi.bi_op_modify = pyth_funcs[op_modify] ? pyth_op_func : NULL;
    pyth.on_bi.bi_op_modrdn = pyth_funcs[op_modrdn] ? pyth_op_func : NULL;
    pyth.on_bi.bi_op_add = pyth_funcs[op_add] ? pyth_op_func : NULL;
    pyth.on_bi.bi_op_delete = pyth_funcs[op_delete] ? pyth_op_func : NULL;
    pyth.on_bi.bi_op_abandon = pyth_funcs[op_abandon] ? pyth_op_func : NULL;
    pyth.on_bi.bi_extended = pyth_funcs[op_extended] ? pyth_op_func : NULL;
    pyth.on_response = pyth_funcs_response ? pyth_response : NULL;

    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "pyth: reaching end of init\n");
    for (i=0;i<op_last;i++) {
      if (pyth_funcs[i]) {
        Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "pyth: pyth_funcs[%d]=%p\n", i,pyth_funcs[i]);
      } else {
        Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "pyth: pyth_funcs[%d]=%p\n", i,NULL);
      }
    }
    i = overlay_register(&pyth);
    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "pyth: overlay_register()=%d\n", i);
    return i;
  } else {
  Py_XDECREF(pModule);
  }
  Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "pyth: returning init failure\n");
  return 1;
}

void pyth_finalize() {
  int i=op_bind;
  while (i<op_last) {
    Py_XDECREF(pyth_funcs[i]);
    i++;
  }
  if (pyth_funcs_response) {
    Py_XDECREF(pyth_funcs_response);
  }
  Py_FinalizeEx();
}


SLAP_MODULE_ENTRY(pyth, modinit)(int argc, char *argv[]) {
  return pyth_initialize();
}

SLAP_MODULE_ENTRY(pyth, modterm)(void) {
  pyth_finalize();
  return 0;
}
