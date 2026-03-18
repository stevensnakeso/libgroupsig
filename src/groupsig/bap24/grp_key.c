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
#include <math.h>

#include "sysenv.h"
#include "sys/mem.h"
#include "misc/misc.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"

#include "bap24.h"
#include "groupsig/bap24/grp_key.h"

groupsig_key_t* bap24_grp_key_init() {

  groupsig_key_t *key;
  bap24_grp_key_t *bap24_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (bap24_grp_key_t *) mem_malloc(sizeof(bap24_grp_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_BAP24_CODE;
  bap24_key = key->key;
  bap24_key->g = NULL;
  bap24_key->h = NULL;
  bap24_key->gg = NULL;
  bap24_key->hh = NULL;
  bap24_key->X = NULL;
  bap24_key->Y = NULL;
  bap24_key->YY = NULL;
  bap24_key->apk = NULL;
  bap24_key->dpk = NULL;
  bap24_key->acc = NULL;
  return key;

}

int bap24_grp_key_free(groupsig_key_t *key) {

  bap24_grp_key_t *bap24_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "bap24_grp_key_free", __LINE__,
                   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(key->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_grp_key_free", __LINE__, LOGERROR);
    return IERROR;
  }

  if(key->key) {
    bap24_key = key->key;
    if(bap24_key->g) { pbcext_element_G1_free(bap24_key->g); bap24_key->g = NULL; }
    if(bap24_key->h) { pbcext_element_G1_free(bap24_key->h); bap24_key->h = NULL; }
    if(bap24_key->gg) { pbcext_element_G2_free(bap24_key->gg); bap24_key->gg = NULL; }
    if(bap24_key->hh) { pbcext_element_G2_free(bap24_key->hh); bap24_key->hh = NULL; }
    if(bap24_key->X) { pbcext_element_G2_free(bap24_key->X); bap24_key->X = NULL; }
    if(bap24_key->Y) { pbcext_element_G2_free(bap24_key->Y); bap24_key->Y = NULL; }
    if(bap24_key->YY) { pbcext_element_G2_free(bap24_key->YY); bap24_key->YY = NULL; }
    if(bap24_key->apk) { pbcext_element_G2_free(bap24_key->apk); bap24_key->apk = NULL; }
    if(bap24_key->dpk) { pbcext_element_G2_free(bap24_key->dpk); bap24_key->dpk = NULL; }
    if(bap24_key->acc) { pbcext_element_G1_free(bap24_key->acc); bap24_key->acc = NULL; }
    mem_free(key->key); key->key = NULL;
  }

  mem_free(key); key = NULL;

  return IOK;

}

int bap24_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  bap24_grp_key_t *bap24_dst, *bap24_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_BAP24_CODE ||
     !src || src->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_grp_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  bap24_dst = dst->key;
  bap24_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if(!(bap24_dst->g = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(pbcext_element_G1_set(bap24_dst->g, bap24_src->g) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(!(bap24_dst->h = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(pbcext_element_G1_set(bap24_dst->h, bap24_src->h) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(!(bap24_dst->gg = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(pbcext_element_G2_set(bap24_dst->gg, bap24_src->gg) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(!(bap24_dst->hh = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(pbcext_element_G2_set(bap24_dst->hh, bap24_src->hh) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(!(bap24_dst->X = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(pbcext_element_G2_set(bap24_dst->X, bap24_src->X) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(!(bap24_dst->Y = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(pbcext_element_G2_set(bap24_dst->Y, bap24_src->Y) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(!(bap24_dst->YY = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(pbcext_element_G2_set(bap24_dst->YY, bap24_src->YY) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(!(bap24_dst->apk = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(pbcext_element_G2_set(bap24_dst->apk, bap24_src->apk) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(!(bap24_dst->dpk = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(pbcext_element_G2_set(bap24_dst->dpk, bap24_src->dpk) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(!(bap24_dst->acc = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_grp_key_copy);
  if(pbcext_element_G1_set(bap24_dst->acc, bap24_src->acc) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_copy);

 bap24_grp_key_copy_end:

  if(rc == IERROR) {
    if (bap24_dst->g) { pbcext_element_G1_free(bap24_dst->g); bap24_dst->g = NULL; }
    if (bap24_dst->h) { pbcext_element_G1_free(bap24_dst->h); bap24_dst->h = NULL; }
    if (bap24_dst->gg) { pbcext_element_G2_free(bap24_dst->gg); bap24_dst->gg = NULL; }
    if (bap24_dst->hh) { pbcext_element_G2_free(bap24_dst->hh); bap24_dst->hh = NULL; }
    if (bap24_dst->X) { pbcext_element_G2_free(bap24_dst->X); bap24_dst->X = NULL; }
    if (bap24_dst->Y) { pbcext_element_G2_free(bap24_dst->Y); bap24_dst->Y = NULL; }
    if (bap24_dst->YY) { pbcext_element_G2_free(bap24_dst->YY); bap24_dst->YY = NULL; }
    if (bap24_dst->apk) { pbcext_element_G2_free(bap24_dst->apk); bap24_dst->apk = NULL; }
    if (bap24_dst->dpk) { pbcext_element_G2_free(bap24_dst->dpk); bap24_dst->dpk = NULL; }
    if (bap24_dst->acc) { pbcext_element_G1_free(bap24_dst->acc); bap24_dst->acc = NULL; }
  }

  return rc;

}

int bap24_grp_key_get_size(groupsig_key_t *key) {

  bap24_grp_key_t *bap24_key;
  uint64_t size64, sg, sh, sgg, shh, sX, sY,sYY, sapk , sdpk, sacc;

  if(!key || key->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_grp_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  bap24_key = key->key;

  sg = sh = sgg = shh = sX = sY = sYY= sapk= sdpk = sacc=  0;

  if(pbcext_element_G1_byte_size(&sg) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sh) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sgg) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&shh) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sX) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sY) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sYY) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sapk) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sdpk) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sacc) == IERROR) return -1;
  size64 = sizeof(uint8_t)*2 + sizeof(int)*10 + sg + sh + sgg + shh + sX + sY + sY+ sapk + sdpk + sacc;
  if (size64 > INT_MAX) return -1;

  return (int) size64;

}

int bap24_grp_key_export(byte_t **bytes,
                        uint32_t *size,
                        groupsig_key_t *key) {

  bap24_grp_key_t *bap24_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;

  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_grp_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  bap24_key = key->key;

  /* Get the number of bytes to represent the key */
  if ((_size = bap24_grp_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_BAP24_CODE */
  code = GROUPSIG_BAP24_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_GRPKEY;
  _bytes[ctr++] = GROUPSIG_KEY_GRPKEY;

  /* Dump g */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, bap24_key->g) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_export);
  ctr += len;

  /* Dump h */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, bap24_key->h) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_export);
  ctr += len;

  /* Dump gg */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, bap24_key->gg) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_export);
  ctr += len;

  /* Dump hh */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, bap24_key->hh) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_export);
  ctr += len;

  /* Dump X */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, bap24_key->X) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_export);
  ctr += len;

  /* Dump Y */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, bap24_key->Y) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_export);
  ctr += len;

  /* Dump YY */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, bap24_key->YY) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_export);
  ctr += len;

  /* Dump apk */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, bap24_key->apk) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_export);
  ctr += len;

  /* Dump dpk */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, bap24_key->dpk) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_export);
  ctr += len;

  /* Dump acc */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, bap24_key->acc) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_grp_key_export", __LINE__,
                      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, bap24_grp_key_export);
  }

  *size = ctr;

 bap24_grp_key_export_end:

  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  return rc;

}

groupsig_key_t* bap24_grp_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  bap24_grp_key_t *bap24_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "bap24_grp_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(key = bap24_grp_key_init())) {
    return NULL;
  }

  bap24_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_grp_key_import", __LINE__,
                      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, bap24_grp_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_GRPKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_grp_key_import", __LINE__,
                      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, bap24_grp_key_import);
  }

  /* Get g */
  if(!(bap24_key->g = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_grp_key_import);
  if(pbcext_get_element_G1_bytes(bap24_key->g, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_import);
  ctr += len;

  /* Get h */
  if(!(bap24_key->h = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_grp_key_import);
  if(pbcext_get_element_G1_bytes(bap24_key->h, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_import);
  ctr += len;

  /* Get gg */
  if(!(bap24_key->gg = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_grp_key_import);
  if(pbcext_get_element_G2_bytes(bap24_key->gg, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_import);
  ctr += len;

  /* Get hh */
  if(!(bap24_key->hh = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_grp_key_import);
  if(pbcext_get_element_G2_bytes(bap24_key->hh, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_import);
  ctr += len;

  /* Get X */
  if(!(bap24_key->X = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_grp_key_import);
  if(pbcext_get_element_G2_bytes(bap24_key->X, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_import);
  ctr += len;

  /* Get Y */
  if(!(bap24_key->Y = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_grp_key_import);
  if(pbcext_get_element_G2_bytes(bap24_key->Y, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_import);
  ctr += len;

  /* Get YY */
  if(!(bap24_key->YY = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_grp_key_import);
  if(pbcext_get_element_G2_bytes(bap24_key->YY, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_import);
  ctr += len;

  /* Get apk */
  if(!(bap24_key->apk = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_grp_key_import);
  if(pbcext_get_element_G2_bytes(bap24_key->apk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_import);
  ctr += len;

  /* Get dpk */
  if(!(bap24_key->dpk = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, bap24_grp_key_import);
  if(pbcext_get_element_G2_bytes(bap24_key->dpk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_import);
  ctr += len;

  /* Get acc */
  if(!(bap24_key->acc = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_grp_key_import);
  if(pbcext_get_element_G1_bytes(bap24_key->acc, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_grp_key_import);
  ctr += len;

 bap24_grp_key_import_end:

  if(rc == IERROR && key) { bap24_grp_key_free(key); key = NULL; }
  if(rc == IOK) return key;

  return NULL;

}

char* bap24_grp_key_to_string(groupsig_key_t *key) {
  
  char *g, *h, *gg, *hh, *X, *Y,*YY, *skey, *apk, *dpk, *acc;
  uint64_t g_len, h_len, gg_len, hh_len, X_len, Y_len, YY_len, apk_len, dpk_len, acc_len;
  uint32_t skey_len;
  g = NULL; h=NULL; gg = NULL; hh=NULL; X = NULL; Y = NULL; YY=NULL; skey=NULL; apk=NULL; dpk=NULL; acc=NULL;
  bap24_grp_key_t *gkey = (bap24_grp_key_t *) key->key;
  
  if(pbcext_element_G1_to_string(&g,
                                 &g_len,
                                 10,
                                 gkey->g) == IERROR) {
    goto grp_key_to_string_error;
  }

  if(pbcext_element_G1_to_string(&h,
                                 &h_len,
                                 10,
                                 gkey->h) == IERROR) {
    goto grp_key_to_string_error;
  }

  if(pbcext_element_G2_to_string(&gg,
                                 &gg_len,
                                 10,
                                 gkey->gg) == IERROR) {
    goto grp_key_to_string_error;
  }

  if(pbcext_element_G2_to_string(&hh,
                                 &hh_len,
                                 10,
                                 gkey->hh) == IERROR) {
    goto grp_key_to_string_error;
  }

  if(pbcext_element_G2_to_string(&X,
                                 &X_len,
                                 10,
                                 gkey->X) == IERROR) {
    goto grp_key_to_string_error;
  }
  if(pbcext_element_G2_to_string(&Y,
                                 &Y_len,
                                 10,
                                 gkey->Y) == IERROR) {
    goto grp_key_to_string_error;
  }

  if(pbcext_element_G2_to_string(&YY,
                                 &YY_len,
                                 10,
                                 gkey->YY) == IERROR) {
    goto grp_key_to_string_error;
  }

  if(pbcext_element_G2_to_string(&apk,
                                 &apk_len,
                                 10,
                                 gkey->apk) == IERROR) {
    goto grp_key_to_string_error;
  }

  if(pbcext_element_G2_to_string(&dpk,
                                 &dpk_len,
                                 10,
                                 gkey->dpk) == IERROR) {
    goto grp_key_to_string_error;
  }


  if(pbcext_element_G1_to_string(&acc,
                                 &acc_len,
                                 10,
                                 gkey->acc) == IERROR) {
    goto grp_key_to_string_error;
  }

  if (!g || !h || !gg || !hh || !X || !Y || !YY || !apk || !dpk ||!acc) {
    goto grp_key_to_string_error;
  }

  skey_len = strlen(g)+strlen(h)+strlen(gg)+strlen(hh)+strlen(X)+strlen(Y)+strlen(YY)+strlen(apk)+strlen(dpk)+strlen(acc)+strlen("g: \nh: \ngg: \nhh: \nX: \nY: \nYY: \napk: \ndpk: \nacc: \n")+1;
  if (!(skey = (char *) malloc(sizeof(char)*skey_len))) {
    goto grp_key_to_string_error;
  }

  memset(skey, 0, sizeof(char)*skey_len);

  sprintf(skey,
          "g: %s\n"
          "h: %s\n"
          "gg: %s\n"
          "hh: %s\n"
          "X: %s\n"
          "Y: %s\n",
          "YY: %s\n",
          "apk: %s\n",
          "dpk: %s\n",
          "acc: %s\n",
          g, h, gg, hh,  X, Y,YY, apk, dpk, acc);

 grp_key_to_string_error:
  if (g) { mem_free(g); g = NULL; }
  if (h) { mem_free(h); h = NULL; }
  if (gg) { mem_free(gg); gg = NULL; }
  if (hh) { mem_free(hh); hh = NULL; }
  if (X) { mem_free(X); X = NULL; }
  if (Y) { mem_free(Y); Y = NULL; }
  if (YY) { mem_free(YY); YY = NULL; }
  if (apk) { mem_free(apk); apk = NULL; }
  if (dpk) { mem_free(dpk); dpk = NULL; }
  if (acc) { mem_free(acc); acc = NULL; }
  return skey;
}

/* grp_key.c ends here */
