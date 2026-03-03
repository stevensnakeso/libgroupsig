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

#include "scsl25.h"
#include "groupsig/scsl25/mem_key.h"
#include "shim/base64.h"
#include "misc/misc.h"
#include "sys/mem.h"

groupsig_key_t* scsl25_mem_key_init() {

  groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (scsl25_mem_key_t *) mem_malloc(sizeof(scsl25_mem_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_SCSL25_CODE;
  
  return key;

}

int scsl25_mem_key_free(groupsig_key_t *key) {

  scsl25_mem_key_t *scsl25_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "scsl25_mem_key_free", __LINE__, 
       "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_mem_key_free", __LINE__, LOGERROR);
    return IERROR;         
  }

  if(key->key) {
    scsl25_key = key->key;
    
    /* 抹除并释放敏感分量 */
    if(scsl25_key->u) { pbcext_element_Fr_free(scsl25_key->u); scsl25_key->u = NULL; }
    if(scsl25_key->v) { pbcext_element_G1_free(scsl25_key->v); scsl25_key->v = NULL; }
    
    /* x, e, y 是核心秘密指数，需确保底层 buffer 被 memset */
    if(scsl25_key->x) { pbcext_element_Fr_free(scsl25_key->x); scsl25_key->x = NULL; }
    if(scsl25_key->e) { pbcext_element_Fr_free(scsl25_key->e); scsl25_key->e = NULL; }
    if(scsl25_key->y) { prf_key_free(scsl25_key->y); scsl25_key->y = NULL; }
    if(scsl25_key->yy) { prf_key_free(scsl25_key->yy); scsl25_key->y = NULL; }
    
    if(scsl25_key->U) { pbcext_element_G1_free(scsl25_key->U); scsl25_key->U = NULL; }

    /* 抹除结构体本身 */
    memset(key->key, 0, sizeof(scsl25_mem_key_t));
    mem_free(key->key);
    key->key = NULL;
  }
  
  mem_free(key);
  
  return IOK;

}

/* 深拷贝：确保所有私钥分量独立存储 */
int scsl25_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  scsl25_mem_key_t *scsl25_dst, *scsl25_src;
  int rc;
  
  if(!dst  || dst->scheme != GROUPSIG_SCSL25_CODE || 
     !src  || src->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_mem_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  scsl25_dst = dst->key;
  scsl25_src = src->key;
  rc = IOK;
  
  /* 依次拷贝 u, v, x, e, y, U */
  if(scsl25_src->u) {
    if(!(scsl25_dst->u = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_mem_key_copy);
    if(pbcext_element_Fr_set(scsl25_dst->u, scsl25_src->u) == IERROR) GOTOENDRC(IERROR, scsl25_mem_key_copy);
  }
  if(scsl25_src->v) {
    if(!(scsl25_dst->v = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_mem_key_copy);
    if(pbcext_element_G1_set(scsl25_dst->v, scsl25_src->v) == IERROR) GOTOENDRC(IERROR, scsl25_mem_key_copy);
  }
  if(scsl25_src->x) {
    if(!(scsl25_dst->x = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_mem_key_copy);
    if(pbcext_element_Fr_set(scsl25_dst->x, scsl25_src->x) == IERROR) GOTOENDRC(IERROR, scsl25_mem_key_copy);
  }
  if(scsl25_src->e) {
    if(!(scsl25_dst->e = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_mem_key_copy);
    if(pbcext_element_Fr_set(scsl25_dst->e, scsl25_src->e) == IERROR) GOTOENDRC(IERROR, scsl25_mem_key_copy);
  }
  if(scsl25_src->y) {
    if(!(scsl25_dst->y = prf_key_init())) GOTOENDRC(IERROR, scsl25_mem_key_copy);
    memcpy(scsl25_dst->y->bytes, scsl25_src->y->bytes, scsl25_src->y->len);
  }
  if(scsl25_src->yy) {
    if(!(scsl25_dst->yy = prf_key_init())) GOTOENDRC(IERROR, scsl25_mem_key_copy);
    memcpy(scsl25_dst->yy->bytes, scsl25_src->yy->bytes, scsl25_src->yy->len);
  }
  if(scsl25_src->U) {
    if(!(scsl25_dst->U = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_mem_key_copy);
    if(pbcext_element_G1_set(scsl25_dst->U, scsl25_src->U) == IERROR) GOTOENDRC(IERROR, scsl25_mem_key_copy);
  }
  
scsl25_mem_key_copy_end:
  if (rc == IERROR) scsl25_mem_key_free(dst);
  return rc;

}

/* 计算大小：统计所有分量的字节数 */
int scsl25_mem_key_get_size(groupsig_key_t *key) {

  scsl25_mem_key_t *scsl25_key;
  int size;
  uint64_t su, sv, sx, se, sy, syy, sU;
  if(!key || key->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_mem_key_get_size", __LINE__, LOGERROR);
    return -1;
  }
  
  if(!key || key->scheme != GROUPSIG_SCSL25_CODE) return -1;
  scsl25_key = key->key;
  su = sv = sx = se = sy = sU = syy =  0;

  if(scsl25_key->u) pbcext_element_Fr_byte_size(&su);
  if(scsl25_key->v) pbcext_element_G1_byte_size(&sv);
  if(scsl25_key->x) pbcext_element_Fr_byte_size(&sx);
  if(scsl25_key->e) pbcext_element_Fr_byte_size(&se);
  if (scsl25_key->y && scsl25_key->y->bytes) {
    sy = scsl25_key->y->len;
  } 
  if (scsl25_key->yy && scsl25_key->yy->bytes) {
    syy = scsl25_key->yy->len;
  } 
  if(scsl25_key->U) pbcext_element_G1_byte_size(&sU);
  if((int) su + sv + sx + se + sy + syy +  sU + sizeof(int)*5 + 4 > INT_MAX ) return -1;

  size = (int) su + sv + sx + se + sy + syy+ sU + sizeof(int)*5 + 4;
  
  return size;
  
}

/* 导出：将私钥分量序列化为字节流 */
int scsl25_mem_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key) {

  scsl25_mem_key_t *scsl25_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  uint64_t sy;
  uint32_t _size;
  int ctr = 0, rc = IOK;
  
  if(!key || key->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_mem_key_export", __LINE__, LOGERROR); 
    return IERROR;
  }

  scsl25_key = key->key;

  if ((_size = scsl25_mem_key_get_size(key)) == -1) return IERROR;
  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) return IERROR;

  _bytes[ctr++] = GROUPSIG_SCSL25_CODE;
  _bytes[ctr++] = GROUPSIG_KEY_MEMKEY;

  /* 依次 Dump u, v, x, e, y, U */

  if (scsl25_key->u) {
    __bytes = &_bytes[ctr];    
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, scsl25_key->u) == IERROR)
      GOTOENDRC(IERROR, scsl25_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  if (scsl25_key->v) {
    __bytes = &_bytes[ctr];    
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, scsl25_key->v) == IERROR)
      GOTOENDRC(IERROR, scsl25_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  if (scsl25_key->x) {
    __bytes = &_bytes[ctr];    
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, scsl25_key->x) == IERROR)
      GOTOENDRC(IERROR, scsl25_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  if (scsl25_key->e) {
    __bytes = &_bytes[ctr];    
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, scsl25_key->e) == IERROR)
      GOTOENDRC(IERROR, scsl25_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  if (scsl25_key->y && scsl25_key->y->bytes && scsl25_key->y->len) {
    _bytes[ctr] = scsl25_key->y->len;
    ctr++;
    memcpy(&_bytes[ctr], scsl25_key->y->bytes, scsl25_key->y->len);
    ctr += scsl25_key->y->len;
  } else {
    ctr += sizeof(uint8_t);
  }

   if (scsl25_key->yy && scsl25_key->yy->bytes && scsl25_key->yy->len) {
    _bytes[ctr] = scsl25_key->yy->len;
    ctr++;
    memcpy(&_bytes[ctr], scsl25_key->yy->bytes, scsl25_key->yy->len);
    ctr += scsl25_key->yy->len;
  } else {
    ctr += sizeof(uint8_t);
  }

  if (scsl25_key->U) {
    __bytes = &_bytes[ctr];    
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, scsl25_key->U) == IERROR)
      GOTOENDRC(IERROR, scsl25_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }



  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "scsl25_mem_key_export", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, scsl25_mem_key_export);
  }  

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }
  
  *size = ctr;
  
 scsl25_mem_key_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  
  return rc;    
}

groupsig_key_t* scsl25_mem_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  scsl25_mem_key_t *scsl25_key;
  uint64_t len;
  int rc, ctr;
  uint8_t type, scheme;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_mem_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(key = scsl25_mem_key_init())) {
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  scsl25_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "scsl25_mem_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  } 
  
  /* Next byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MEMKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "scsl25_mem_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  }    

  /* Get u */
  if(!(scsl25_key->u = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  if(pbcext_get_element_Fr_bytes(scsl25_key->u, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(scsl25_key->u); scsl25_key->u = NULL;
  } else {
    ctr += len;
  }

  /* Get v */
  if(!(scsl25_key->v = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  if(pbcext_get_element_G1_bytes(scsl25_key->v, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(scsl25_key->v); scsl25_key->v = NULL;
  } else {
    ctr += len;
  }

   /* Get x */
  if(!(scsl25_key->x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  if(pbcext_get_element_Fr_bytes(scsl25_key->x, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(scsl25_key->x); scsl25_key->x = NULL;
  } else {
    ctr += len;
  }

   /* Get e */
  if(!(scsl25_key->e = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  if(pbcext_get_element_Fr_bytes(scsl25_key->e, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(scsl25_key->e); scsl25_key->e = NULL;
  } else {
    ctr += len;
  }

  /* Get y */
   if(!(scsl25_key->y = prf_key_init()))
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  // Currently, we only support BLAKE2 lengths in PRF. This may change.
  if (source[ctr] && source[ctr] != scsl25_key->y->len)
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  ctr++;

  if (source[ctr-1]) {
    memcpy(scsl25_key->y->bytes, &source[ctr], scsl25_key->y->len);
    ctr += scsl25_key->y->len;
  }

  /* Get yy */
   if(!(scsl25_key->yy = prf_key_init()))
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  // Currently, we only support BLAKE2 lengths in PRF. This may change.
  if (source[ctr] && source[ctr] != scsl25_key->yy->len)
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  ctr++;

  if (source[ctr-1]) {
    memcpy(scsl25_key->y->bytes, &source[ctr], scsl25_key->y->len);
    ctr += scsl25_key->y->len;
  }

  /* Get U */
  if(!(scsl25_key->U = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  if(pbcext_get_element_G1_bytes(scsl25_key->U, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(scsl25_key->U); scsl25_key->U = NULL;
  } else {
    ctr += len;
  }

  
 scsl25_mem_key_import_end:

  if(rc == IERROR && key) { scsl25_mem_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  return NULL;  
  
}

char* scsl25_mem_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_mem_key_to_string",
	       __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* mem_key.c ends here */
