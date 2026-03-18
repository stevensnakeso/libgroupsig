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

#include "bap24.h"
#include "groupsig/bap24/mem_key.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "misc/misc.h"
#include "sys/mem.h"

groupsig_key_t* bap24_mem_key_init() {

  groupsig_key_t *key;
  bap24_mem_key_t *bap24_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (bap24_mem_key_t *) mem_malloc(sizeof(bap24_mem_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_BAP24_CODE;
  bap24_key = key->key;

  bap24_key->sk = NULL;
  bap24_key->sigma1 = NULL;
  bap24_key->sigma2 = NULL;
  bap24_key->e = NULL;
  bap24_key->w = NULL;
  bap24_key->uid = NULL;
  return key;

}

int bap24_mem_key_free(groupsig_key_t *key) {

  bap24_mem_key_t *bap24_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "bap24_mem_key_free", __LINE__,
                   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(key->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mem_key_free", __LINE__, LOGERROR);
    return IERROR;
  }

  if(key->key) {
    bap24_key = key->key;
    if(bap24_key->sk) {
      pbcext_element_Fr_free(bap24_key->sk);
      bap24_key->sk = NULL;
    }
    if(bap24_key->sigma1) {
      pbcext_element_G1_free(bap24_key->sigma1);
      bap24_key->sigma1 = NULL;
    }
    if(bap24_key->sigma2) {
      pbcext_element_G1_free(bap24_key->sigma2);
      bap24_key->sigma2 = NULL;
    }
    if(bap24_key->e) {
      pbcext_element_GT_free(bap24_key->e);
      bap24_key->e = NULL;
    }
    if(bap24_key->w) {
      pbcext_element_G1_free(bap24_key->w);
      bap24_key->w = NULL;
    }
    if(bap24_key->uid) {
      pbcext_element_Fr_free(bap24_key->uid);
      bap24_key->w = NULL;
    }
    mem_free(key->key); key->key = NULL;
    key->key = NULL;
  }

  mem_free(key); key = NULL;

  return IOK;

}

int bap24_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  bap24_mem_key_t *bap24_dst, *bap24_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_BAP24_CODE ||
     !src || src->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mem_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  bap24_dst = dst->key;
  bap24_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if(bap24_src->sk) {
    if(!(bap24_dst->sk = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, bap24_mem_key_copy);
    if(pbcext_element_Fr_set(bap24_dst->sk, bap24_src->sk) == IERROR)
      GOTOENDRC(IERROR, bap24_mem_key_copy);
  }

  if(bap24_src->sigma1) {
    if(!(bap24_dst->sigma1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, bap24_mem_key_copy);
    if(pbcext_element_G1_set(bap24_dst->sigma1, bap24_src->sigma1) == IERROR)
      GOTOENDRC(IERROR, bap24_mem_key_copy);
  }

  if(bap24_src->sigma2) {
    if(!(bap24_dst->sigma2 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, bap24_mem_key_copy);
    if(pbcext_element_G1_set(bap24_dst->sigma2, bap24_src->sigma2) == IERROR)
      GOTOENDRC(IERROR, bap24_mem_key_copy);
  }

  if(bap24_src->e) {
    if(!(bap24_dst->e = pbcext_element_GT_init()))
      GOTOENDRC(IERROR, bap24_mem_key_copy);
    if(pbcext_element_GT_set(bap24_dst->e, bap24_src->e) == IERROR)
      GOTOENDRC(IERROR, bap24_mem_key_copy);
  }

  if(bap24_src->w) {
    if(!(bap24_dst->w = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, bap24_mem_key_copy);
    if(pbcext_element_G1_set(bap24_dst->w, bap24_src->w) == IERROR)
      GOTOENDRC(IERROR, bap24_mem_key_copy);
  }

  if(bap24_src->uid) {
    if(!(bap24_dst->uid = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, bap24_mem_key_copy);
    if(pbcext_element_Fr_set(bap24_dst->uid, bap24_src->uid) == IERROR)
      GOTOENDRC(IERROR, bap24_mem_key_copy);
  }

 bap24_mem_key_copy_end:

  if(rc == IERROR) {
    if(bap24_dst->sk) {
      pbcext_element_Fr_free(bap24_dst->sk);
      bap24_dst->sk = NULL;
    }
    if(bap24_dst->sigma1) {
      pbcext_element_G1_free(bap24_dst->sigma1);
      bap24_dst->sigma1 = NULL;
    }
    if(bap24_dst->sigma2) {
      pbcext_element_G1_free(bap24_dst->sigma2);
      bap24_dst->sigma2 = NULL;
    }
    if(bap24_dst->e) {
      pbcext_element_GT_free(bap24_dst->e);
      bap24_dst->e = NULL;
    }
    if(bap24_dst->w) {
      pbcext_element_G1_free(bap24_dst->w);
      bap24_dst->w = NULL;
    }
    if(bap24_dst->uid) {
      pbcext_element_Fr_free(bap24_dst->uid);
      bap24_dst->w = NULL;
    }
  }

  return rc;

}

int bap24_mem_key_get_size(groupsig_key_t *key) {

  bap24_mem_key_t *bap24_key;
  uint64_t size64, ssk, ssigma1, ssigma2, se, sw, suid;

  if(!key || key->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mem_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  ssk = ssigma1 = ssigma2 = se = 0;
  bap24_key = key->key;

  if(bap24_key->sk) { if(pbcext_element_Fr_byte_size(&ssk) == IERROR) return -1; }
  if(bap24_key->sigma1) { if(pbcext_element_G1_byte_size(&ssigma1) == IERROR) return -1; }
  if(bap24_key->sigma2) { if(pbcext_element_G1_byte_size(&ssigma2) == IERROR) return -1; }
  if(bap24_key->e) { if(pbcext_element_GT_byte_size(&se) == IERROR) return -1; }
  if(bap24_key->w) { if(pbcext_element_G1_byte_size(&sw) == IERROR) return -1; }
  if(bap24_key->uid) { if(pbcext_element_Fr_byte_size(&suid) == IERROR) return -1; }
  size64 = sizeof(uint8_t)*2 + sizeof(int)*6+ ssk + ssigma1 + ssigma2 + se + sw+ suid;

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int bap24_mem_key_export(byte_t **bytes,
                        uint32_t *size,
                        groupsig_key_t *key) {

  bap24_mem_key_t *bap24_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;

  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mem_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  bap24_key = key->key;

  /* Get the number of bytes to represent the key */
  if ((_size = bap24_mem_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_BAP24_CODE */
  code = GROUPSIG_BAP24_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_MEMKEY;
  _bytes[ctr++] = GROUPSIG_KEY_MEMKEY;

  /* Dump sk */
  if (bap24_key->sk) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_key->sk) == IERROR)
      GOTOENDRC(IERROR, bap24_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump sigma1 */
  if (bap24_key->sigma1) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, bap24_key->sigma1) == IERROR)
      GOTOENDRC(IERROR, bap24_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump sigma2 */
  if (bap24_key->sigma2) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, bap24_key->sigma2) == IERROR)
      GOTOENDRC(IERROR, bap24_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }


  /* Dump e */
  if (bap24_key->e) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_GT_bytes(&__bytes, &len, bap24_key->e) == IERROR)
      GOTOENDRC(IERROR, bap24_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump w */
  if (bap24_key->w) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, bap24_key->w) == IERROR)
      GOTOENDRC(IERROR, bap24_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump uid */
  if (bap24_key->uid) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bap24_key->uid) == IERROR)
      GOTOENDRC(IERROR, bap24_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_mem_key_export", __LINE__,
                      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, bap24_mem_key_export);
  }

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = ctr;

 bap24_mem_key_export_end:

  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  return rc;

}

groupsig_key_t* bap24_mem_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  bap24_mem_key_t *bap24_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mem_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(key = bap24_mem_key_init())) {
    return NULL;
  }

  bap24_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_mem_key_import", __LINE__,
                      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, bap24_mem_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MEMKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bap24_mem_key_import", __LINE__,
                      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, bap24_mem_key_import);
  }

  /* Get sk */
  if(!(bap24_key->sk = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_mem_key_import);
  if(pbcext_get_element_Fr_bytes(bap24_key->sk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(bap24_key->sk); bap24_key->sk = NULL;
  } else {
    ctr += len;
  }

  /* Get sigma1 */
  if(!(bap24_key->sigma1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_mem_key_import);
  if(pbcext_get_element_G1_bytes(bap24_key->sigma1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(bap24_key->sigma1); bap24_key->sigma1 = NULL;
  } else {
    ctr += len;
  }

  /* Get sigma2 */
  if(!(bap24_key->sigma2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_mem_key_import);
  if(pbcext_get_element_G1_bytes(bap24_key->sigma2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(bap24_key->sigma2); bap24_key->sigma2 = NULL;
  } else {
    ctr += len;
  }

  /* Get e */
  if(!(bap24_key->e = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, bap24_mem_key_import);
  if(pbcext_get_element_GT_bytes(bap24_key->e, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_GT_free(bap24_key->e); bap24_key->e = NULL;
  } else {
    ctr += len;
  }

  /* Get w */
  if(!(bap24_key->w = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bap24_mem_key_import);
  if(pbcext_get_element_G1_bytes(bap24_key->w, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(bap24_key->w); bap24_key->w = NULL;
  } else {
    ctr += len;
  }

  /* Get uid */
  if(!(bap24_key->uid = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bap24_mem_key_import);
  if(pbcext_get_element_Fr_bytes(bap24_key->uid, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bap24_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(bap24_key->uid); bap24_key->uid = NULL;
  } else {
    ctr += len;
  }


 bap24_mem_key_import_end:

  if(rc == IERROR && key) { bap24_mem_key_free(key); key = NULL; }
  if(rc == IOK) return key;

  return NULL;
}

char* bap24_mem_key_to_string(groupsig_key_t *key) {

  bap24_mem_key_t* bap24_key = (bap24_mem_key_t*) key->key;

  char *sk = NULL, *sigma1 = NULL, *sigma2 = NULL, *e = NULL, *mem_key = NULL, *w=NULL, *uid=NULL;
  size_t sk_size = 0, sigma1_size = 0, sigma2_size = 0, e_size = strlen("(null)"), memkey_size = 0, w_size=0, uid_size=0;

  if(!key || key->scheme != GROUPSIG_BAP24_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mem_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  if(pbcext_element_Fr_to_string(&sk,
                                 &sk_size,
                                 10,
                                 bap24_key->sk) == IERROR) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mem_key_to_string", __LINE__, LOGERROR);
    goto mem_key_to_string_error;
  }
  if(pbcext_element_G1_to_string(&sigma1,
                                 &sigma1_size,
                                 10,
                                 bap24_key->sigma1) == IERROR) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mem_key_to_string", __LINE__, LOGERROR);
    goto mem_key_to_string_error;
  }
  if(pbcext_element_G1_to_string(&sigma2,
                                 &sigma2_size,
                                 10,
                                 bap24_key->sigma2) == IERROR) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mem_key_to_string", __LINE__, LOGERROR);
    goto mem_key_to_string_error;
  }
  if(pbcext_element_GT_to_string(&e,
                                 &e_size,
                                 10,
                                 bap24_key->e) == IERROR) {
    // TODO: e may not be defined sometimes.
    //LOG_EINVAL(&logger, __FILE__, "bap24_mem_key_to_string", __LINE__, LOGERROR);
    //goto mem_key_to_string_error;
  }

  if(pbcext_element_G1_to_string(&w,
                                 &w_size,
                                 10,
                                 bap24_key->w) == IERROR) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mem_key_to_string", __LINE__, LOGERROR);
    goto mem_key_to_string_error;
  }

  if(pbcext_element_Fr_to_string(&uid,
                                 &uid_size,
                                 10,
                                 bap24_key->uid) == IERROR) {
    LOG_EINVAL(&logger, __FILE__, "bap24_mem_key_to_string", __LINE__, LOGERROR);
    goto mem_key_to_string_error;
  }

  memkey_size = sk_size + sigma1_size + sigma2_size + e_size + w_size + uid_size + strlen("sk: \nsigma1: \nsigma2: \ne: \nw: \nuid: \n") + 1;

  if (!(mem_key = (char*) calloc(memkey_size, sizeof(char)))){
    LOG_EINVAL(&logger, __FILE__, "bap24_mem_key_to_string", __LINE__, LOGERROR);
    goto mem_key_to_string_error;
  }

  snprintf(mem_key, memkey_size,
          "sk: %s\n"
          "sigma1: %s\n"
          "sigma2: %s\n"
          "e: %s\n",
          "w: %s\n",
          "uid: %s\n",
          sk, sigma1, sigma2, e, w,uid );

 mem_key_to_string_error:

  if (sk){free(sk), sk = NULL;}
  if (sigma1){free(sigma1), sigma1 = NULL;}
  if (sigma2){free(sigma2), sigma2 = NULL;}
  if (e){free(e), e = NULL;}
  if (w){free(w), w = NULL;}
  if (uid){free(uid), uid = NULL;}  
  return mem_key;
}

/* mem_key.c ends here */
