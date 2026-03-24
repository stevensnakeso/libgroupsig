/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "bap24.h"
#include "groupsig/bap24/mgr_key.h"
#include "misc/misc.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

groupsig_key_t* bap24_mgr_key_init() {

  groupsig_key_t *key;
  bap24_mgr_key_t *bap24_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (bap24_mgr_key_t *) mem_malloc(sizeof(bap24_mgr_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_BAP24_CODE;
  bap24_key = key->key;
  bap24_key->x = NULL;
  bap24_key->y = NULL;
  bap24_key->yy = NULL;
  bap24_key->ask = NULL;
  bap24_key->dsk = NULL;
  return key;

}

int bap24_mgr_key_free(groupsig_key_t *key) {

  bap24_mgr_key_t *bap24_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "bap24_mgr_key_free", __LINE__,
                   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(key->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mgr_key_free", __LINE__, LOGERROR);
    return IERROR;
  }

  if(key->key) {
    bap24_key = key->key;
    if(bap24_key->x) { pbcext_element_Fr_free(bap24_key->x); bap24_key->x = NULL; }
    if(bap24_key->y) { pbcext_element_Fr_free(bap24_key->y); bap24_key->y = NULL; }
     if(bap24_key->yy) { pbcext_element_Fr_free(bap24_key->yy); bap24_key->yy = NULL; }
    if(bap24_key->ask) { pbcext_element_Fr_free(bap24_key->ask); bap24_key->ask = NULL; }
    if(bap24_key->dsk) { pbcext_element_Fr_free(bap24_key->dsk); bap24_key->dsk = NULL; }
    mem_free(key->key); key->key = NULL;
  }

  mem_free(key); key = NULL;

  return IOK;

}

int bap24_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  bap24_mgr_key_t *bap24_dst, *bap24_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_BAP24_CODE ||
     !src || src->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mgr_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  bap24_dst = dst->key;
  bap24_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if(!(bap24_dst->x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_mgr_key_copy);
  if(pbcext_element_Fr_set(bap24_dst->x, bap24_src->x) == IERROR)
    GOTOENDRC(IERROR, bap24_mgr_key_copy);
  if(!(bap24_dst->y = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_mgr_key_copy);
  if(pbcext_element_Fr_set(bap24_dst->y, bap24_src->y) == IERROR)
    GOTOENDRC(IERROR, bap24_mgr_key_copy);
  if(!(bap24_dst->yy = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_mgr_key_copy);
  if(pbcext_element_Fr_set(bap24_dst->yy, bap24_src->yy) == IERROR)
    GOTOENDRC(IERROR, bap24_mgr_key_copy);
  if(!(bap24_dst->ask = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_mgr_key_copy);
  if(pbcext_element_Fr_set(bap24_dst->ask, bap24_src->ask) == IERROR)
    GOTOENDRC(IERROR, bap24_mgr_key_copy);
  if(!(bap24_dst->dsk = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_mgr_key_copy);
  if(pbcext_element_Fr_set(bap24_dst->dsk, bap24_src->dsk) == IERROR)
    GOTOENDRC(IERROR, bap24_mgr_key_copy);

 bap24_mgr_key_copy_end:

  if(rc == IERROR) {
    if (bap24_dst->x) { pbcext_element_Fr_free(bap24_dst->x); bap24_dst->x = NULL; }
    if (bap24_dst->y) { pbcext_element_Fr_free(bap24_dst->y); bap24_dst->y = NULL; }
    if (bap24_dst->yy) { pbcext_element_Fr_free(bap24_dst->yy); bap24_dst->yy = NULL; }
    if (bap24_dst->ask) { pbcext_element_Fr_free(bap24_dst->ask); bap24_dst->ask = NULL; }
    if (bap24_dst->dsk) { pbcext_element_Fr_free(bap24_dst->dsk); bap24_dst->dsk = NULL; }
  }

  return rc;

}

int bap24_mgr_key_get_size(groupsig_key_t *key) {

  bap24_mgr_key_t *bap24_key;
  uint64_t size64, sx, sy,syy, sask, sdsk;

  if(!key || key->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mgr_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  sx = sy = syy = sask = sdsk= 0;

  if(pbcext_element_Fr_byte_size(&sx) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sy) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&syy) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sask) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sdsk) == IERROR) return -1;
  size64 = sizeof(uint8_t)*2 + sizeof(int)*5 + sx + sy + syy + sask + sdsk; // get size problem??

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int bap24_mgr_key_export(byte_t **bytes,
                        uint32_t *size,
                        groupsig_key_t *key) {

  bap24_mgr_key_t *bap24_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;

  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mgr_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  bap24_key = key->key;

  /* Get the number of bytes to represent the key */
  if ((_size = bap24_mgr_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_BAP24_CODE */
  code = GROUPSIG_BAP24_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_MGRKEY;
  _bytes[ctr++] = GROUPSIG_KEY_MGRKEY;

  /* Dump x */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_key->x) == IERROR)
    GOTOENDRC(IERROR, bap24_mgr_key_export);
  ctr += len;

  /* Dump y */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_key->y) == IERROR)
    GOTOENDRC(IERROR, bap24_mgr_key_export);
  ctr += len;

  /* Dump yy */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_key->yy) == IERROR)
    GOTOENDRC(IERROR, bap24_mgr_key_export);
  ctr += len;

  /* Dump ask */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_key->ask) == IERROR)
    GOTOENDRC(IERROR, bap24_mgr_key_export);
  ctr += len;

  /* Dump dsk */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_key->dsk) == IERROR)
    GOTOENDRC(IERROR, bap24_mgr_key_export);
  ctr += len;

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_mgr_key_export", __LINE__,
                      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, bap24_mgr_key_export);
  }

  *size = ctr;

 bap24_mgr_key_export_end:

  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  return rc;

}

groupsig_key_t* bap24_mgr_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  bap24_mgr_key_t *bap24_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mgr_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(key = bap24_mgr_key_init())) {
    return NULL;
  }

  bap24_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_mgr_key_import", __LINE__,
                      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, bap24_mgr_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MGRKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_mgr_key_import", __LINE__,
                      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, bap24_mgr_key_import);
  }

  /* Get x */
  if(!(bap24_key->x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(bap24_key->x, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_mgr_key_import);
  ctr += len;

  /* Get y */
  if(!(bap24_key->y = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(bap24_key->y, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_mgr_key_import);
  ctr += len;

  /* Get yy */
  if(!(bap24_key->yy = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(bap24_key->yy, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_mgr_key_import);
  ctr += len;


  /* Get ask */
  if(!(bap24_key->ask = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(bap24_key->ask, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_mgr_key_import);
  ctr += len;

  /* Get dsk */
  if(!(bap24_key->dsk = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(bap24_key->dsk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_mgr_key_import);
  ctr += len;

 bap24_mgr_key_import_end:

  if(rc == IERROR && key) { bap24_mgr_key_free(key); key = NULL; }
  if(rc == IOK) return key;

  return NULL;

}

char* bap24_mgr_key_to_string(groupsig_key_t *key) {

  bap24_mgr_key_t* bap24_key = (bap24_mgr_key_t*) key->key;
  char *x = NULL, *y = NULL, *yy = NULL, * ask = NULL, *dsk =NULL, *mgr_key = NULL;
  size_t x_size = 0, y_size = 0, yy_size = 0, ask_size = 0, dsk_size = 0, mgr_key_size = 0;

  if(!key || !bap24_key ||key->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mgr_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  if(pbcext_element_Fr_to_string(&x,
                                 &x_size,
                                 10,
                                 bap24_key->x) == IERROR) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mgr_key_to_string", __LINE__, LOGERROR);
    goto mgr_key_to_string_error;
  }

  if(pbcext_element_Fr_to_string(&y,
                                 &y_size,
                                 10,
                                 bap24_key->y) == IERROR) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mgr_key_to_string", __LINE__, LOGERROR);
    goto mgr_key_to_string_error;
  }

  if(pbcext_element_Fr_to_string(&yy,
                                 &yy_size,
                                 10,
                                 bap24_key->yy) == IERROR) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mgr_key_to_string", __LINE__, LOGERROR);
    goto mgr_key_to_string_error;
  }

  if(pbcext_element_Fr_to_string(&ask,
                                 &ask_size,
                                 10,
                                 bap24_key->ask) == IERROR) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mgr_key_to_string", __LINE__, LOGERROR);
    goto mgr_key_to_string_error;
  }

  if(pbcext_element_Fr_to_string(&dsk,
                                 &dsk_size,
                                 10,
                                 bap24_key->dsk) == IERROR) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mgr_key_to_string", __LINE__, LOGERROR);
    goto mgr_key_to_string_error;
  }

  mgr_key_size = x_size + y_size + yy_size + ask_size + dsk_size + strlen("x: \ny: \nyy: \n") + 1;
  if (!(mgr_key = (char*) calloc(mgr_key_size, sizeof(char)))){
    LOG_EINVAL(&logger, __FILE__, "bap24_mgr_key_to_string", __LINE__, LOGERROR);
    goto mgr_key_to_string_error;
  }

  snprintf(mgr_key, mgr_key_size,
          "x: %s\n"
          "y: %s\n",
          "yy: %s\n",
          "ask: %s\n",
          "dsk: %s\n",
          x, y, yy, ask, dsk );

 mgr_key_to_string_error:

  if(x){mem_free(x), x = NULL;}
  if(y){mem_free(y), y = NULL;}
  if(yy){mem_free(yy), yy = NULL;}
  if(ask){mem_free(ask), ask = NULL;}  
  if(dsk){mem_free(dsk), dsk = NULL;}  
  return mgr_key;
}

/* mgr_key.c ends here */
