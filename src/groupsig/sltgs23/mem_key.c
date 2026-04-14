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

#include "sltgs23.h"
#include "groupsig/sltgs23/mem_key.h"
#include "shim/base64.h"
#include "misc/misc.h"
#include "sys/mem.h"
  
groupsig_key_t* sltgs23_mem_key_init() {

  groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (sltgs23_mem_key_t *) mem_malloc(sizeof(sltgs23_mem_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_SLTGS23_CODE;
  
  return key;

}

int sltgs23_mem_key_free(groupsig_key_t *key) {

  sltgs23_mem_key_t *sltgs23_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "sltgs23_mem_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_mem_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    sltgs23_key = key->key;
    if(sltgs23_key->A) { pbcext_element_G1_free(sltgs23_key->A); sltgs23_key->A = NULL; }
    if(sltgs23_key->x) { pbcext_element_Fr_free(sltgs23_key->x); sltgs23_key->x = NULL; }
    if(sltgs23_key->y) { pbcext_element_Fr_free(sltgs23_key->y); sltgs23_key->y = NULL; }
    if(sltgs23_key->s) { pbcext_element_Fr_free(sltgs23_key->s); sltgs23_key->s = NULL; }
    if(sltgs23_key->H) { pbcext_element_G1_free(sltgs23_key->H); sltgs23_key->H = NULL; }
    if(sltgs23_key->h2s) {
      pbcext_element_G1_free(sltgs23_key->h2s);
      sltgs23_key->h2s = NULL;
    }
    mem_free(key->key);
    key->key = NULL;
  }
  
  mem_free(key);
  
  return IOK;

}

int sltgs23_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  sltgs23_mem_key_t *sltgs23_dst, *sltgs23_src;
  int rc;
  
  if(!dst  || dst->scheme != GROUPSIG_SLTGS23_CODE || 
     !src  || src->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_mem_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  sltgs23_dst = dst->key;
  sltgs23_src = src->key;

  rc = IOK;
  
  /* Copy the elements */
  if(sltgs23_src->A) {
    if(!(sltgs23_dst->A = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, sltgs23_mem_key_copy);
    if(pbcext_element_G1_set(sltgs23_dst->A, sltgs23_src->A) == IERROR)
      GOTOENDRC(IERROR, sltgs23_mem_key_copy);
  }

  if(sltgs23_src->x) {
    if(!(sltgs23_dst->x = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, sltgs23_mem_key_copy);
    if(pbcext_element_Fr_set(sltgs23_dst->x, sltgs23_src->x) == IERROR)
      GOTOENDRC(IERROR, sltgs23_mem_key_copy);
  }

  if(sltgs23_src->y) {
    if(!(sltgs23_dst->y = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, sltgs23_mem_key_copy);
    if(pbcext_element_Fr_set(sltgs23_dst->y, sltgs23_src->y) == IERROR)
      GOTOENDRC(IERROR, sltgs23_mem_key_copy);
  }

  if(sltgs23_src->s) {
    if(!(sltgs23_dst->s = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, sltgs23_mem_key_copy);
    if(pbcext_element_Fr_set(sltgs23_dst->s, sltgs23_src->s) == IERROR)
      GOTOENDRC(IERROR, sltgs23_mem_key_copy);
  }

  if(sltgs23_src->H) {
    if(!(sltgs23_dst->H = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, sltgs23_mem_key_copy);
    if(pbcext_element_G1_set(sltgs23_dst->H, sltgs23_src->H) == IERROR)
      GOTOENDRC(IERROR, sltgs23_mem_key_copy);
  }

  if(sltgs23_src->h2s) {  
    if(!(sltgs23_dst->h2s = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, sltgs23_mem_key_copy);
    if(pbcext_element_G1_set(sltgs23_dst->h2s, sltgs23_src->h2s) == IERROR)
      GOTOENDRC(IERROR, sltgs23_mem_key_copy);
  }
  
 sltgs23_mem_key_copy_end:
  
  if (rc == IERROR) {
    if(sltgs23_dst->A) { pbcext_element_G1_free(sltgs23_dst->A); sltgs23_dst->A = NULL; }
    if(sltgs23_dst->x) { pbcext_element_Fr_free(sltgs23_dst->x); sltgs23_dst->x = NULL; }
    if(sltgs23_dst->y) { pbcext_element_Fr_free(sltgs23_dst->y); sltgs23_dst->y = NULL; }
    if(sltgs23_dst->s) { pbcext_element_Fr_free(sltgs23_dst->s); sltgs23_dst->s = NULL; }
    if(sltgs23_dst->H) { pbcext_element_G1_free(sltgs23_dst->H); sltgs23_dst->H = NULL; }
    if(sltgs23_dst->h2s) {
      pbcext_element_G1_free(sltgs23_dst->h2s);
      sltgs23_dst->h2s = NULL;
    }
  }
  
  return rc;

}

int sltgs23_mem_key_get_size(groupsig_key_t *key) {

  sltgs23_mem_key_t *sltgs23_key;
  int size;
  uint64_t sA, sx, sy, ss, sd, sH, sh2s;
  
  if(!key || key->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_mem_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  sltgs23_key = key->key;

  sA = sx = sy = ss = sd = sH = sh2s = 0;

  if(sltgs23_key->A) { if(pbcext_element_G1_byte_size(&sA) == -1) return -1; }
  if(sltgs23_key->x) { if(pbcext_element_Fr_byte_size(&sx) == -1) return -1; }
  if(sltgs23_key->y) { if(pbcext_element_Fr_byte_size(&sy) == -1) return -1; }
  if(sltgs23_key->s) { if(pbcext_element_Fr_byte_size(&ss) == -1) return -1; }
  if(sltgs23_key->H) { if(pbcext_element_G1_byte_size(&sH) == -1) return -1; }
  if(sltgs23_key->h2s) { if(pbcext_element_G1_byte_size(&sh2s) == -1) return -1; }

  if ((int) sA + sx + sy + ss + sH + sh2s + sizeof(int)*6+2 > INT_MAX) return -1;
  size = (int) sA + sx + sy + ss + sH + sh2s + sizeof(int)*6+2;

  return size;

}

int sltgs23_mem_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key) {

  sltgs23_mem_key_t *sltgs23_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  uint32_t _size;
  int ctr, rc;
  
  if(!key || key->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_mem_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  sltgs23_key = key->key;

  if ((_size = sltgs23_mem_key_get_size(key)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_SLTGS23_CODE */
  _bytes[ctr++] = GROUPSIG_SLTGS23_CODE;

  /* Dump key type */
  _bytes[ctr++] = GROUPSIG_KEY_MEMKEY;

  /* Dump A */
  if (sltgs23_key->A) {
    __bytes = &_bytes[ctr];    
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, sltgs23_key->A) == IERROR)
      GOTOENDRC(IERROR, sltgs23_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump x */
  if (sltgs23_key->x) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_key->x) == IERROR)
      GOTOENDRC(IERROR, sltgs23_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump y */
  if (sltgs23_key->y) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_key->y) == IERROR)
      GOTOENDRC(IERROR, sltgs23_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }    

  /* Dump s */
  if (sltgs23_key->s) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_key->s) == IERROR)
      GOTOENDRC(IERROR, sltgs23_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump H */
  if (sltgs23_key->H) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, sltgs23_key->H) == IERROR)
      GOTOENDRC(IERROR, sltgs23_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); } 

  /* Dump h2s */
  if (sltgs23_key->h2s) {
    __bytes = &_bytes[ctr];    
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, sltgs23_key->h2s) == IERROR)
      GOTOENDRC(IERROR, sltgs23_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "sltgs23_mem_key_export", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, sltgs23_mem_key_export);
  }  

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }
  
  *size = ctr;
  
 sltgs23_mem_key_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  
  return rc;  
  
}

groupsig_key_t* sltgs23_mem_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  sltgs23_mem_key_t *sltgs23_key;
  uint64_t len;
  int rc, ctr;
  uint8_t type, scheme;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_mem_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(key = sltgs23_mem_key_init())) {
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  sltgs23_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "sltgs23_mem_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, sltgs23_mem_key_import);
  } 
  
  /* Next byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MEMKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "sltgs23_mem_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, sltgs23_mem_key_import);
  }    

  /* Get A */
  if(!(sltgs23_key->A = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_mem_key_import);
  if(pbcext_get_element_G1_bytes(sltgs23_key->A, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(sltgs23_key->A); sltgs23_key->A = NULL;
  } else {
    ctr += len;
  }

  /* Get x */
  if(!(sltgs23_key->x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_mem_key_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_key->x, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(sltgs23_key->x); sltgs23_key->x = NULL;
  } else {
    ctr += len;
  }

  /* Get y */
  if(!(sltgs23_key->y = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_mem_key_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_key->y, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(sltgs23_key->y); sltgs23_key->y = NULL;
  } else {
    ctr += len;
  }

  /* Get s */
  if(!(sltgs23_key->s = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_mem_key_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_key->s, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(sltgs23_key->s); sltgs23_key->s = NULL;
  } else {
    ctr += len;
  }

  /* Get H */
  if(!(sltgs23_key->H = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_mem_key_import);
  if(pbcext_get_element_G1_bytes(sltgs23_key->H, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(sltgs23_key->H); sltgs23_key->H = NULL;
  } else {
    ctr += len;
  }

  /* Get h2s */
  if(!(sltgs23_key->h2s = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_mem_key_import);
  if(pbcext_get_element_G1_bytes(sltgs23_key->h2s, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(sltgs23_key->h2s); sltgs23_key->h2s = NULL;
  } else {
    ctr += len;
  }
  
 sltgs23_mem_key_import_end:

  if(rc == IERROR && key) { sltgs23_mem_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  return NULL;  

}

char* sltgs23_mem_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_mem_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}


/* mem_key.c ends here */
