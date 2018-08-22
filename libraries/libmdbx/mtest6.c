/* mtest6.c - memory-mapped database tester/toy */

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

/* Tests for DB splits and merges */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include "mdbx.h"

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

char dkbuf[1024];

int main(int argc, char *argv[]) {
  int i = 0, rc;
  MDB_env *env;
  MDB_dbi dbi;
  MDB_val key, data, sdata;
  MDB_txn *txn;
  MDB_stat mst;
  MDB_cursor *cursor;
  long kval;
  char *sval;
  int env_oflags;
  struct stat db_stat, exe_stat;

  (void)argc;
  (void)argv;
  srand(time(NULL));

  E(mdb_env_create(&env));
  E(mdb_env_set_mapsize(env, 10485760));
  E(mdb_env_set_maxdbs(env, 4));

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
  if (mdb_dbi_open(txn, "id6", MDB_CREATE, &dbi) == MDB_SUCCESS)
    E(mdb_drop(txn, dbi, 1));
  E(mdb_dbi_open(txn, "id6", MDB_CREATE | MDB_INTEGERKEY, &dbi));
  E(mdb_cursor_open(txn, dbi, &cursor));
  E(mdb_stat(txn, dbi, &mst));

  sval = calloc(1, mst.ms_psize / 4);
  key.mv_size = sizeof(long);
  key.mv_data = &kval;
  sdata.mv_size = mst.ms_psize / 4 - 30;
  sdata.mv_data = sval;

  printf("Adding 12 values, should yield 3 splits\n");
  for (i = 0; i < 12; i++) {
    kval = i * 5;
    sprintf(sval, "%08lx", kval);
    data = sdata;
    (void)RES(MDB_KEYEXIST,
              mdb_cursor_put(cursor, &key, &data, MDB_NOOVERWRITE));
  }
  printf("Adding 12 more values, should yield 3 splits\n");
  for (i = 0; i < 12; i++) {
    kval = i * 5 + 4;
    sprintf(sval, "%08lx", kval);
    data = sdata;
    (void)RES(MDB_KEYEXIST,
              mdb_cursor_put(cursor, &key, &data, MDB_NOOVERWRITE));
  }
  printf("Adding 12 more values, should yield 3 splits\n");
  for (i = 0; i < 12; i++) {
    kval = i * 5 + 1;
    sprintf(sval, "%08lx", kval);
    data = sdata;
    (void)RES(MDB_KEYEXIST,
              mdb_cursor_put(cursor, &key, &data, MDB_NOOVERWRITE));
  }
  E(mdb_cursor_get(cursor, &key, &data, MDB_FIRST));

  do {
    printf("key: %p %s, data: %p %.*s\n", key.mv_data, mdb_dkey(&key, dkbuf),
           data.mv_data, (int)data.mv_size, (char *)data.mv_data);
  } while ((rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0);
  CHECK(rc == MDB_NOTFOUND, "mdb_cursor_get");
  mdb_cursor_close(cursor);
  mdb_txn_commit(txn);

#if 0
	int j=0;
	int count = 333;
	int *values = alloca(sizeof(int) * count);

	for (i= count - 1; i > -1; i-= (rand()%5)) {
		j++;
		txn=NULL;
		E(mdb_txn_begin(env, NULL, 0, &txn));
		sprintf(kval, "%03x", values[i & ~0x0f]);
		sprintf(sval, "%03x %d foo bar", values[i], values[i]);
		key.mv_size = sizeof(int);
		key.mv_data = kval;
		data.mv_size = sizeof(sval);
		data.mv_data = sval;
		if (RES(MDB_NOTFOUND, mdb_del(txn, dbi, &key, &data))) {
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
		printf("key: %.*s, data: %.*s\n",
			(int) key.mv_size,  (char *) key.mv_data,
			(int) data.mv_size, (char *) data.mv_data);
	}
	CHECK(rc == MDB_NOTFOUND, "mdb_cursor_get");
	printf("Cursor prev\n");
	while ((rc = mdb_cursor_get(cursor, &key, &data, MDB_PREV)) == 0) {
		printf("key: %.*s, data: %.*s\n",
			(int) key.mv_size,  (char *) key.mv_data,
			(int) data.mv_size, (char *) data.mv_data);
	}
	CHECK(rc == MDB_NOTFOUND, "mdb_cursor_get");
	mdb_cursor_close(cursor);
	mdb_txn_abort(txn);

	mdb_dbi_close(env, dbi);
#endif
  mdb_env_close(env);
  free(sval);

  return 0;
}
