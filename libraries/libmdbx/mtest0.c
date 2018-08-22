/* mtest.c - memory-mapped database tester/toy */

/*
 * Copyright 2015-2018 Leonid Yuriev <leo@yuriev.ru>.
 * Copyright 2011-2018 Howard Chu, Symas Corp.
 * Copyright 2015,2016 Peter-Service R&D LLC.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include "mdbx.h"

#include <pthread.h>

#define E(expr) CHECK((rc = (expr)) == MDB_SUCCESS, #expr)
#define RES(err, expr) ((rc = expr) == (err) || (CHECK(!rc, #expr), 0))
#define CHECK(test, msg)                                                       \
  ((test) ? (void)0                                                            \
          : ((void)fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, msg, \
                           mdb_strerror(rc)),                                  \
             abort()))

#ifndef DBPATH
#define DBPATH "./testdb"
#endif

void *thread_entry(void *ctx) {
  MDB_env *env = ctx;
  MDB_txn *txn;
  int rc;

  E(mdb_txn_begin(env, NULL, MDB_RDONLY, &txn));
  mdb_txn_abort(txn);

  return NULL;
}

int main(int argc, char *argv[]) {
  int i = 0, j = 0, rc;
  MDB_env *env;
  MDB_dbi dbi;
  MDB_val key, data;
  MDB_txn *txn;
  MDB_stat mst;
  MDB_cursor *cursor, *cur2;
  MDB_cursor_op op;
  int count;
  int *values;
  char sval[32] = "";
  int env_oflags;
  struct stat db_stat, exe_stat;

  (void)argc;
  (void)argv;
  srand(time(NULL));

  count = (rand() % 384) + 64;
  values = (int *)malloc(count * sizeof(int));

  for (i = 0; i < count; i++) {
    values[i] = rand() % 1024;
  }

  E(mdb_env_create(&env));
  E(mdb_env_set_maxreaders(env, 42));
  E(mdb_env_set_mapsize(env, 10485760));

  E(stat("/proc/self/exe", &exe_stat) ? errno : 0);
  E(stat(DBPATH "/.", &db_stat) ? errno : 0);
  env_oflags = MDB_FIXEDMAP | MDB_NOSYNC;
  if (major(db_stat.st_dev) != major(exe_stat.st_dev)) {
    /* LY: Assume running inside a CI-environment:
     *  1) don't use FIXEDMAP to avoid EBUSY in case collision,
     *     which could be inspired by address space randomisation feature.
     *  2) drop MDB_NOSYNC expecting that DBPATH is at a tmpfs or some dedicated
     * storage.
     */
    env_oflags = 0;
  }
  E(mdb_env_open(env, DBPATH, env_oflags, 0664));

  E(mdb_txn_begin(env, NULL, 0, &txn));
  E(mdb_dbi_open(txn, NULL, 0, &dbi));

  key.mv_size = sizeof(int);
  key.mv_data = sval;

  printf("Adding %d values\n", count);
  for (i = 0; i < count; i++) {
    sprintf(sval, "%03x %d foo bar", values[i], values[i]);
    /* Set <data> in each iteration, since MDB_NOOVERWRITE may modify it */
    data.mv_size = sizeof(sval);
    data.mv_data = sval;
    if (RES(MDB_KEYEXIST, mdb_put(txn, dbi, &key, &data, MDB_NOOVERWRITE))) {
      j++;
      data.mv_size = sizeof(sval);
      data.mv_data = sval;
    }
  }
  if (j)
    printf("%d duplicates skipped\n", j);
  E(mdb_txn_commit(txn));
  E(mdb_env_stat(env, &mst));

  E(mdb_txn_begin(env, NULL, MDB_RDONLY, &txn));
  E(mdb_cursor_open(txn, dbi, &cursor));
  while ((rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0) {
    printf("key: %p %.*s, data: %p %.*s\n", key.mv_data, (int)key.mv_size,
           (char *)key.mv_data, data.mv_data, (int)data.mv_size,
           (char *)data.mv_data);
  }
  CHECK(rc == MDB_NOTFOUND, "mdb_cursor_get");
  mdb_cursor_close(cursor);
  mdb_txn_abort(txn);

  j = 0;
  key.mv_data = sval;
  for (i = count - 1; i > -1; i -= (rand() % 5)) {
    j++;
    txn = NULL;
    E(mdb_txn_begin(env, NULL, 0, &txn));
    sprintf(sval, "%03x ", values[i]);
    if (RES(MDB_NOTFOUND, mdb_del(txn, dbi, &key, NULL))) {
      j--;
      mdb_txn_abort(txn);
    } else {
      E(mdb_txn_commit(txn));
    }
  }
  free(values);
  printf("Deleted %d values\n", j);

  E(mdb_env_stat(env, &mst));
  E(mdb_txn_begin(env, NULL, MDB_RDONLY, &txn));
  E(mdb_cursor_open(txn, dbi, &cursor));
  printf("Cursor next\n");
  while ((rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0) {
    printf("key: %.*s, data: %.*s\n", (int)key.mv_size, (char *)key.mv_data,
           (int)data.mv_size, (char *)data.mv_data);
  }
  CHECK(rc == MDB_NOTFOUND, "mdb_cursor_get");
  printf("Cursor last\n");
  E(mdb_cursor_get(cursor, &key, &data, MDB_LAST));
  printf("key: %.*s, data: %.*s\n", (int)key.mv_size, (char *)key.mv_data,
         (int)data.mv_size, (char *)data.mv_data);
  printf("Cursor prev\n");
  while ((rc = mdb_cursor_get(cursor, &key, &data, MDB_PREV)) == 0) {
    printf("key: %.*s, data: %.*s\n", (int)key.mv_size, (char *)key.mv_data,
           (int)data.mv_size, (char *)data.mv_data);
  }
  CHECK(rc == MDB_NOTFOUND, "mdb_cursor_get");
  printf("Cursor last/prev\n");
  E(mdb_cursor_get(cursor, &key, &data, MDB_LAST));
  printf("key: %.*s, data: %.*s\n", (int)key.mv_size, (char *)key.mv_data,
         (int)data.mv_size, (char *)data.mv_data);
  E(mdb_cursor_get(cursor, &key, &data, MDB_PREV));
  printf("key: %.*s, data: %.*s\n", (int)key.mv_size, (char *)key.mv_data,
         (int)data.mv_size, (char *)data.mv_data);

  mdb_cursor_close(cursor);
  mdb_txn_abort(txn);

  printf("Deleting with cursor\n");
  E(mdb_txn_begin(env, NULL, 0, &txn));
  E(mdb_cursor_open(txn, dbi, &cur2));
  for (i = 0; i < 50; i++) {
    if (RES(MDB_NOTFOUND, mdb_cursor_get(cur2, &key, &data, MDB_NEXT)))
      break;
    printf("key: %p %.*s, data: %p %.*s\n", key.mv_data, (int)key.mv_size,
           (char *)key.mv_data, data.mv_data, (int)data.mv_size,
           (char *)data.mv_data);
    E(mdb_del(txn, dbi, &key, NULL));
  }

  printf("Restarting cursor in txn\n");
  for (op = MDB_FIRST, i = 0; i <= 32; op = MDB_NEXT, i++) {
    if (RES(MDB_NOTFOUND, mdb_cursor_get(cur2, &key, &data, op)))
      break;
    printf("key: %p %.*s, data: %p %.*s\n", key.mv_data, (int)key.mv_size,
           (char *)key.mv_data, data.mv_data, (int)data.mv_size,
           (char *)data.mv_data);
  }
  mdb_cursor_close(cur2);
  E(mdb_txn_commit(txn));

  for (i = 0; i < 41; ++i) {
    pthread_t thread;
    pthread_create(&thread, NULL, thread_entry, env);
  }

  printf("Restarting cursor outside txn\n");
  E(mdb_txn_begin(env, NULL, 0, &txn));
  E(mdb_cursor_open(txn, dbi, &cursor));
  for (op = MDB_FIRST, i = 0; i <= 32; op = MDB_NEXT, i++) {
    if (RES(MDB_NOTFOUND, mdb_cursor_get(cursor, &key, &data, op)))
      break;
    printf("key: %p %.*s, data: %p %.*s\n", key.mv_data, (int)key.mv_size,
           (char *)key.mv_data, data.mv_data, (int)data.mv_size,
           (char *)data.mv_data);
  }
  mdb_cursor_close(cursor);
  mdb_txn_abort(txn);

  mdb_dbi_close(env, dbi);
  mdb_env_close(env);

  return 0;
}
