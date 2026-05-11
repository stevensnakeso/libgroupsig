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

#include "klapseq.h"
#include "groupsig/klapseq/mem_key.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "misc/misc.h"
#include "sys/mem.h"

groupsig_key_t* klapseq_mem_key_init() {
  
  groupsig_key_t *key;
  klapseq_mem_key_t *klapseq_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (klapseq_mem_key_t *) mem_malloc(sizeof(klapseq_mem_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_KLAPSEQ_CODE;
  klapseq_key = key->key;
  
  klapseq_key->alpha = NULL;
  klapseq_key->u = NULL;
  klapseq_key->v = NULL;
  klapseq_key->w = NULL;
  
  return key;

}

int klapseq_mem_key_free(groupsig_key_t *key) {

  klapseq_mem_key_t *klapseq_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "klapseq_mem_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_mem_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    klapseq_key = key->key;
    if(klapseq_key->alpha) {
      pbcext_element_Fr_free(klapseq_key->alpha);
      klapseq_key->alpha = NULL;
    }
    if(klapseq_key->u) {
      pbcext_element_G1_free(klapseq_key->u);
      klapseq_key->u = NULL;
    }
    if(klapseq_key->v) {
      pbcext_element_G1_free(klapseq_key->v);
      klapseq_key->v = NULL;
    }
    if(klapseq_key->w) {
      pbcext_element_G1_free(klapseq_key->w);
      klapseq_key->w = NULL;
    }
    mem_free(key->key); key->key = NULL;
    key->key = NULL;
  }
  
  mem_free(key); key = NULL;

  return IOK;

}

int klapseq_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  klapseq_mem_key_t *klapseq_dst, *klapseq_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_KLAPSEQ_CODE ||
     !src || src->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_mem_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  klapseq_dst = dst->key;
  klapseq_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if(klapseq_src->alpha) {
    if(!(klapseq_dst->alpha = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, klapseq_mem_key_copy);
    if(pbcext_element_Fr_set(klapseq_dst->alpha, klapseq_src->alpha) == IERROR)
      GOTOENDRC(IERROR, klapseq_mem_key_copy);
  }

  if(klapseq_src->u) {
    if(!(klapseq_dst->u = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, klapseq_mem_key_copy); 
    if(pbcext_element_G1_set(klapseq_dst->u, klapseq_src->u) == IERROR)
      GOTOENDRC(IERROR, klapseq_mem_key_copy);
  }

  if(klapseq_src->v) {
    if(!(klapseq_dst->v = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, klapseq_mem_key_copy);
    if(pbcext_element_G1_set(klapseq_dst->v, klapseq_src->v) == IERROR)
      GOTOENDRC(IERROR, klapseq_mem_key_copy);
  }

  if(klapseq_src->w) {
    if(!(klapseq_dst->w = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, klapseq_mem_key_copy);
    if(pbcext_element_G1_set(klapseq_dst->w, klapseq_src->w) == IERROR)
      GOTOENDRC(IERROR, klapseq_mem_key_copy);    
  }
  
 klapseq_mem_key_copy_end:

  if(rc == IERROR) {
    if(klapseq_dst->alpha) {
      pbcext_element_Fr_free(klapseq_dst->alpha);
      klapseq_dst->alpha = NULL;
    }
    if(klapseq_dst->u) {
      pbcext_element_G1_free(klapseq_dst->u);
      klapseq_dst->u = NULL;
    }
    if(klapseq_dst->v) {
      pbcext_element_G1_free(klapseq_dst->v);
      klapseq_dst->v = NULL;
    }
    if(klapseq_dst->w) {
      pbcext_element_G1_free(klapseq_dst->w);
      klapseq_dst->w = NULL;
    }
  }

  return rc;

}

int klapseq_mem_key_get_size(groupsig_key_t *key) {

  klapseq_mem_key_t *klapseq_key;
  uint64_t size64, salpha, su, sv, sw;
  
  if(!key || key->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_mem_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  salpha = su = sv = sw = 0;
  klapseq_key = key->key;
  
  if(klapseq_key->alpha) { if(pbcext_element_Fr_byte_size(&salpha) == IERROR) return -1; }
  if(klapseq_key->u) { if(pbcext_element_G1_byte_size(&su) == IERROR) return -1; }
  if(klapseq_key->v) { if(pbcext_element_G1_byte_size(&sv) == IERROR) return -1; }
  if(klapseq_key->w) { if(pbcext_element_G1_byte_size(&sw) == IERROR) return -1; }

  size64 = sizeof(uint8_t)*2 + sizeof(int)*4+ salpha + su + sv + sw;

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int klapseq_mem_key_export(byte_t **bytes,
			uint32_t *size,
			groupsig_key_t *key) {

  klapseq_mem_key_t *klapseq_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;  
  
  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_mem_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  klapseq_key = key->key;
  
  /* Get the number of bytes to represent the key */
  if ((_size = klapseq_mem_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }
  
  /* Dump GROUPSIG_KLAPSEQ_CODE */
  code = GROUPSIG_KLAPSEQ_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_MEMKEY;
  _bytes[ctr++] = GROUPSIG_KEY_MEMKEY;
  
  /* Dump alpha */
  if (klapseq_key->alpha) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, klapseq_key->alpha) == IERROR) 
      GOTOENDRC(IERROR, klapseq_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump u */
  if (klapseq_key->u) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, klapseq_key->u) == IERROR)
      GOTOENDRC(IERROR, klapseq_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump v */
  if (klapseq_key->v) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, klapseq_key->v) == IERROR)
      GOTOENDRC(IERROR, klapseq_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }
  

  /* Dump w */
  if (klapseq_key->w) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, klapseq_key->w) == IERROR) 
      GOTOENDRC(IERROR, klapseq_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klapseq_mem_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, klapseq_mem_key_export);
  }  

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }
  
  *size = ctr;  
  
 klapseq_mem_key_export_end:
  
  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }  

  return rc;
  
}

groupsig_key_t* klapseq_mem_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  klapseq_mem_key_t *klapseq_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_mem_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = klapseq_mem_key_init())) {
    return NULL;
  }

  klapseq_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klapseq_mem_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, klapseq_mem_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MEMKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klapseq_mem_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, klapseq_mem_key_import);
  }

  /* Get alpha */
  if(!(klapseq_key->alpha = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, klapseq_mem_key_import);
  if(pbcext_get_element_Fr_bytes(klapseq_key->alpha, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klapseq_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(klapseq_key->alpha); klapseq_key->alpha = NULL;
  } else {
    ctr += len;
  }

  /* Get u */
  if(!(klapseq_key->u = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klapseq_mem_key_import);
  if(pbcext_get_element_G1_bytes(klapseq_key->u, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klapseq_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(klapseq_key->u); klapseq_key->u = NULL;
  } else {
    ctr += len;
  }

  /* Get v */  
  if(!(klapseq_key->v = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klapseq_mem_key_import);
  if(pbcext_get_element_G1_bytes(klapseq_key->v, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klapseq_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(klapseq_key->v); klapseq_key->v = NULL;
  } else {
    ctr += len;
  }  

  /* Get w */
  if(!(klapseq_key->w = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klapseq_mem_key_import);
  if(pbcext_get_element_G1_bytes(klapseq_key->w, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klapseq_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(klapseq_key->w); klapseq_key->w = NULL;
  } else {
    ctr += len;
  }  
 

 klapseq_mem_key_import_end:
  
  if(rc == IERROR && key) { klapseq_mem_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  
  return NULL; 
}

char* klapseq_mem_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_mem_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* mem_key.c ends here */
