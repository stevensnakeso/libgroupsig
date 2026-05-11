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

#include "klapseq.h"
#include "groupsig/klapseq/grp_key.h"

groupsig_key_t* klapseq_grp_key_init() {

  groupsig_key_t *key;
  klapseq_grp_key_t *klapseq_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (klapseq_grp_key_t *) mem_malloc(sizeof(klapseq_grp_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_KLAPSEQ_CODE;
  klapseq_key = key->key;
  klapseq_key->g = NULL;
  klapseq_key->gg = NULL;
  klapseq_key->XX = NULL;
  klapseq_key->YY = NULL;
  klapseq_key->ZZ0 = NULL;
  klapseq_key->ZZ1 = NULL;
  
  return key;
  
}

int klapseq_grp_key_free(groupsig_key_t *key) {

  klapseq_grp_key_t *klapseq_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "klapseq_grp_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_grp_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    klapseq_key = key->key;
    if(klapseq_key->g) { pbcext_element_G1_free(klapseq_key->g); klapseq_key->g = NULL; }
    if(klapseq_key->gg) { pbcext_element_G2_free(klapseq_key->gg); klapseq_key->gg = NULL; }
    if(klapseq_key->XX) { pbcext_element_G2_free(klapseq_key->XX); klapseq_key->XX = NULL; }
    if(klapseq_key->YY) { pbcext_element_G2_free(klapseq_key->YY); klapseq_key->YY = NULL; }
    if(klapseq_key->ZZ0) { pbcext_element_G2_free(klapseq_key->ZZ0); klapseq_key->ZZ0 = NULL; }
    if(klapseq_key->ZZ1) { pbcext_element_G2_free(klapseq_key->ZZ1); klapseq_key->ZZ1 = NULL; }    
    mem_free(key->key); key->key = NULL;
  }

  mem_free(key); key = NULL;

  return IOK;

}

int klapseq_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  klapseq_grp_key_t *klapseq_dst, *klapseq_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_KLAPSEQ_CODE ||
     !src || src->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_grp_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  klapseq_dst = dst->key;
  klapseq_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if(!(klapseq_dst->g = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klapseq_grp_key_copy);
  if(pbcext_element_G1_set(klapseq_dst->g, klapseq_src->g) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_copy);
  if(!(klapseq_dst->gg = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klapseq_grp_key_copy);  
  if(pbcext_element_G2_set(klapseq_dst->gg, klapseq_src->gg) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_copy);
  if(!(klapseq_dst->XX = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klapseq_grp_key_copy);  
  if(pbcext_element_G2_set(klapseq_dst->XX, klapseq_src->XX) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_copy);
  if(!(klapseq_dst->YY = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klapseq_grp_key_copy);  
  if(pbcext_element_G2_set(klapseq_dst->YY, klapseq_src->YY) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_copy);
  if(!(klapseq_dst->ZZ0 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klapseq_grp_key_copy);  
  if(pbcext_element_G2_set(klapseq_dst->ZZ0, klapseq_src->ZZ0) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_copy);
  if(!(klapseq_dst->ZZ1 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klapseq_grp_key_copy);  
  if(pbcext_element_G2_set(klapseq_dst->ZZ1, klapseq_src->ZZ1) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_copy);  

 klapseq_grp_key_copy_end:

  if(rc == IERROR) {
    if (klapseq_dst->g) { pbcext_element_G1_free(klapseq_dst->g); klapseq_dst->g = NULL; }
    if (klapseq_dst->gg) { pbcext_element_G2_free(klapseq_dst->gg); klapseq_dst->gg = NULL; }
    if (klapseq_dst->XX) { pbcext_element_G2_free(klapseq_dst->XX); klapseq_dst->XX = NULL; }
    if (klapseq_dst->YY) { pbcext_element_G2_free(klapseq_dst->YY); klapseq_dst->YY = NULL; }
    if (klapseq_dst->ZZ0) { pbcext_element_G2_free(klapseq_dst->ZZ0); klapseq_dst->ZZ0 = NULL; }
    if (klapseq_dst->ZZ1) { pbcext_element_G2_free(klapseq_dst->ZZ1); klapseq_dst->ZZ1 = NULL; }
  }
  
  return rc;

}

int klapseq_grp_key_get_size(groupsig_key_t *key) {

  klapseq_grp_key_t *klapseq_key;
  uint64_t size64, sg, sgg, sXX, sYY, sZZ0, sZZ1;
  
  if(!key || key->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_grp_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  sg = sgg = sXX = sYY = sZZ0 = sZZ1 = 0;

  klapseq_key = key->key;

  if(pbcext_element_G1_byte_size(&sg) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sgg) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sXX) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sYY) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sZZ0) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sZZ1) == IERROR) return -1;  

  size64 = sizeof(uint8_t)*2 + sizeof(int)*6 + sg + sgg + sXX + sYY + sZZ0 + sZZ1;
  if (size64 > INT_MAX) return -1;
  
  return (int) size64;  

}

int klapseq_grp_key_export(byte_t **bytes,
			 uint32_t *size,
			 groupsig_key_t *key) {

  klapseq_grp_key_t *klapseq_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;  

  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_grp_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  klapseq_key = key->key;
  
  /* Get the number of bytes to represent the key */
  if ((_size = klapseq_grp_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }
  
  /* Dump GROUPSIG_KLAPSEQ_CODE */
  code = GROUPSIG_KLAPSEQ_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_GRPKEY;
  _bytes[ctr++] = GROUPSIG_KEY_GRPKEY;

  /* Dump g */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, klapseq_key->g) == IERROR) 
    GOTOENDRC(IERROR, klapseq_grp_key_export);
  ctr += len;
  
  /* Dump gg */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, klapseq_key->gg) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_export);
  ctr += len;
  
  /* Dump XX */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, klapseq_key->XX) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_export);
  ctr += len;

  /* Dump YY */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, klapseq_key->YY) == IERROR)    
    GOTOENDRC(IERROR, klapseq_grp_key_export);
  ctr += len;

  /* Dump XX */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, klapseq_key->ZZ0) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_export);
  ctr += len;

  /* Dump YY */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, klapseq_key->ZZ1) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klapseq_grp_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, klapseq_grp_key_export);
  }

  *size = ctr;  
  
 klapseq_grp_key_export_end:

  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }
  
  return rc;
  
}

groupsig_key_t* klapseq_grp_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  klapseq_grp_key_t *klapseq_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_grp_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = klapseq_grp_key_init())) {
    return NULL;
  }

  klapseq_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klapseq_grp_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, klapseq_grp_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_GRPKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klapseq_grp_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, klapseq_grp_key_import);
  }

  /* Get g */
  if(!(klapseq_key->g = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klapseq_grp_key_import);
  if(pbcext_get_element_G1_bytes(klapseq_key->g, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_import);
  ctr += len;  

  /* Get gg */
  if(!(klapseq_key->gg = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klapseq_grp_key_import);
  if(pbcext_get_element_G2_bytes(klapseq_key->gg, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_import);
  ctr += len;  

  /* Get XX */
  if(!(klapseq_key->XX = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klapseq_grp_key_import);
  if(pbcext_get_element_G2_bytes(klapseq_key->XX, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_import);
  ctr += len;  

  /* Get YY */
  if(!(klapseq_key->YY = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klapseq_grp_key_import);
  if(pbcext_get_element_G2_bytes(klapseq_key->YY, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_import);
  ctr += len;

  /* Get ZZ0 */
  if(!(klapseq_key->ZZ0 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klapseq_grp_key_import);
  if(pbcext_get_element_G2_bytes(klapseq_key->ZZ0, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_import);
  ctr += len;  

  /* Get ZZ1 */
  if(!(klapseq_key->ZZ1 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klapseq_grp_key_import);
  if(pbcext_get_element_G2_bytes(klapseq_key->ZZ1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klapseq_grp_key_import);
  ctr += len;  
  
 klapseq_grp_key_import_end:
  
  if(rc == IERROR && key) { klapseq_grp_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  
  return NULL; 
  
}

char* klapseq_grp_key_to_string(groupsig_key_t *key) { 
  return NULL;
}

/* grp_key.c ends here */
