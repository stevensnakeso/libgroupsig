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

#include "sltgs23.h"
#include "groupsig/sltgs23/grp_key.h"

groupsig_key_t* sltgs23_grp_key_init() {

  groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (sltgs23_grp_key_t *) mem_malloc(sizeof(sltgs23_grp_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_SLTGS23_CODE;
  
  return key;
  
}

int sltgs23_grp_key_free(groupsig_key_t *key) {

  sltgs23_grp_key_t *sltgs23_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "sltgs23_grp_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_grp_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    sltgs23_key = key->key;
    if(sltgs23_key->g1) { pbcext_element_G1_free(sltgs23_key->g1); sltgs23_key->g1 = NULL; }
    if(sltgs23_key->g2) { pbcext_element_G2_free(sltgs23_key->g2); sltgs23_key->g2 = NULL; }
    if(sltgs23_key->h) { pbcext_element_G1_free(sltgs23_key->h); sltgs23_key->h = NULL; }
    if(sltgs23_key->u) { pbcext_element_G1_free(sltgs23_key->u); sltgs23_key->u = NULL; }
    if(sltgs23_key->v) { pbcext_element_G1_free(sltgs23_key->v); sltgs23_key->v = NULL; }
    if(sltgs23_key->w) { pbcext_element_G2_free(sltgs23_key->w); sltgs23_key->w = NULL; }
    if(sltgs23_key->hg2) { pbcext_element_GT_free(sltgs23_key->hg2); sltgs23_key->hg2 = NULL; }
    if(sltgs23_key->hw) { pbcext_element_GT_free(sltgs23_key->hw); sltgs23_key->hw = NULL; }
    if(sltgs23_key->g1g2) { pbcext_element_GT_free(sltgs23_key->g1g2); sltgs23_key->g1g2 = NULL; }
    mem_free(key->key); key->key = NULL;
  }

  mem_free(key); key = NULL;

  return IOK;

}

int sltgs23_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  sltgs23_grp_key_t *sltgs23_dst, *sltgs23_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_SLTGS23_CODE ||
     !src || src->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_grp_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  sltgs23_dst = dst->key;
  sltgs23_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if(!(sltgs23_dst->g1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);
  if(pbcext_element_G1_set(sltgs23_dst->g1, sltgs23_src->g1) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);
  if(!(sltgs23_dst->g2 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);  
  if(pbcext_element_G2_set(sltgs23_dst->g2, sltgs23_src->g2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);
  if(!(sltgs23_dst->h = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);  
  if(pbcext_element_G1_set(sltgs23_dst->h, sltgs23_src->h) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);
  if(!(sltgs23_dst->u = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);  
  if(pbcext_element_G1_set(sltgs23_dst->u, sltgs23_src->u) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);  
  if(!(sltgs23_dst->v = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);  
  if(pbcext_element_G1_set(sltgs23_dst->v, sltgs23_src->v) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);  
  if(!(sltgs23_dst->w = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);  
  if(pbcext_element_G2_set(sltgs23_dst->w, sltgs23_src->w) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);
  if(!(sltgs23_dst->hw = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);  
  if(pbcext_element_GT_set(sltgs23_dst->hw, sltgs23_src->hw) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);  
  if(!(sltgs23_dst->hg2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);  
  if(pbcext_element_GT_set(sltgs23_dst->hg2, sltgs23_src->hg2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);  
  if(!(sltgs23_dst->g1g2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);  
  if(pbcext_element_GT_set(sltgs23_dst->g1g2, sltgs23_src->g1g2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_copy);

 sltgs23_grp_key_copy_end:

  if(rc == IERROR) {
    if (sltgs23_dst->g1) { pbcext_element_G1_free(sltgs23_dst->g1); sltgs23_dst->g1 = NULL; }
    if (sltgs23_dst->g2) { pbcext_element_G2_free(sltgs23_dst->g2); sltgs23_dst->g2 = NULL; }
    if (sltgs23_dst->h) { pbcext_element_G1_free(sltgs23_dst->h); sltgs23_dst->h = NULL; }
    if (sltgs23_dst->u) { pbcext_element_G1_free(sltgs23_dst->u); sltgs23_dst->u = NULL; }
    if (sltgs23_dst->v) { pbcext_element_G1_free(sltgs23_dst->v); sltgs23_dst->v = NULL; }
    if (sltgs23_dst->w) { pbcext_element_G2_free(sltgs23_dst->w); sltgs23_dst->w = NULL; }
    if (sltgs23_dst->hw) { pbcext_element_GT_free(sltgs23_dst->hw); sltgs23_dst->hw = NULL; }
    if (sltgs23_dst->hg2) { pbcext_element_GT_free(sltgs23_dst->hg2); sltgs23_dst->hg2 = NULL; }
    if (sltgs23_dst->g1g2) { pbcext_element_GT_free(sltgs23_dst->g1g2); sltgs23_dst->g1g2 = NULL; }
  }
  
  return rc;

}

int sltgs23_grp_key_get_size(groupsig_key_t *key) {

  sltgs23_grp_key_t *sltgs23_key;
  uint64_t size64, sg1, sg2, sh, su, sv, sw, shw, shg2, sg1g2;
  
  if(!key || key->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_grp_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  sltgs23_key = key->key;

  if(pbcext_element_G1_byte_size(&sg1) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sg2) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sh) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&su) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sv) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sw) == IERROR) return -1;
  if(pbcext_element_GT_byte_size(&shw) == IERROR) return -1;
  if(pbcext_element_GT_byte_size(&shg2) == IERROR) return -1;
  if(pbcext_element_GT_byte_size(&sg1g2) == IERROR) return -1;

  size64 = sizeof(uint8_t)*2 + sizeof(int)*9 +
    sg1 + sg2 + sh + su + sv + sw + shw + shg2 + sg1g2;
  if (size64 > INT_MAX) return -1;
  
  return (int) size64;  

}

int sltgs23_grp_key_export(byte_t **bytes,
			 uint32_t *size,
			 groupsig_key_t *key) {

  sltgs23_grp_key_t *sltgs23_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;  

  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_grp_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  sltgs23_key = key->key;
  
  /* Get the number of bytes to represent the key */
  if ((_size = sltgs23_grp_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }
  
  /* Dump GROUPSIG_SLTGS23_CODE */
  code = GROUPSIG_SLTGS23_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_GRPKEY;
  _bytes[ctr++] = GROUPSIG_KEY_GRPKEY;

  /* Dump g1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, sltgs23_key->g1) == IERROR) 
    GOTOENDRC(IERROR, sltgs23_grp_key_export);
  ctr += len;
  
  /* Dump g2 */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, sltgs23_key->g2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_export);
  ctr += len;
  
  /* Dump h */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, sltgs23_key->h) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_export);
  ctr += len;

  /* Dump u */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, sltgs23_key->u) == IERROR)    
    GOTOENDRC(IERROR, sltgs23_grp_key_export);
  ctr += len;

  /* Dump v */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, sltgs23_key->v) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_export);
  ctr += len;

  /* Dump w */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, sltgs23_key->w) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_export);
  ctr += len;

  /* Dump hw */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_GT_bytes(&__bytes, &len, sltgs23_key->hw) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_export);
  ctr += len;

  /* Dump hg2 */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_GT_bytes(&__bytes, &len, sltgs23_key->hg2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_export);
  ctr += len;

  /* Dump g1g2 */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_GT_bytes(&__bytes, &len, sltgs23_key->g1g2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "sltgs23_grp_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, sltgs23_grp_key_export);
  }

  *size = ctr;  
  
 sltgs23_grp_key_export_end:

  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }
  
  return rc;
  
}

groupsig_key_t* sltgs23_grp_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  sltgs23_grp_key_t *sltgs23_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_grp_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = sltgs23_grp_key_init())) {
    return NULL;
  }

  sltgs23_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "sltgs23_grp_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_GRPKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "sltgs23_grp_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  }

  /* Get g1 */
  if(!(sltgs23_key->g1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  if(pbcext_get_element_G1_bytes(sltgs23_key->g1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  ctr += len;  

  /* Get g2 */
  if(!(sltgs23_key->g2 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  if(pbcext_get_element_G2_bytes(sltgs23_key->g2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  ctr += len;  

  /* Get h */
  if(!(sltgs23_key->h = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  if(pbcext_get_element_G1_bytes(sltgs23_key->h, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  ctr += len;  

  /* Get u */
  if(!(sltgs23_key->u = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  if(pbcext_get_element_G1_bytes(sltgs23_key->u, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  ctr += len;  

  /* Get v */
  if(!(sltgs23_key->v = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  if(pbcext_get_element_G1_bytes(sltgs23_key->v, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  ctr += len;   

  /* Get w */
  if(!(sltgs23_key->w = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  if(pbcext_get_element_G2_bytes(sltgs23_key->w, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  ctr += len;  

  /* Get hw */
  if(!(sltgs23_key->hw = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  if(pbcext_get_element_GT_bytes(sltgs23_key->hw, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  ctr += len;
  
  /* Get hg2 */
  if(!(sltgs23_key->hg2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  if(pbcext_get_element_GT_bytes(sltgs23_key->hg2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  ctr += len;  

  /* Get g1g2 */
  if(!(sltgs23_key->g1g2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  if(pbcext_get_element_GT_bytes(sltgs23_key->g1g2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_grp_key_import);
  ctr += len;  
  
 sltgs23_grp_key_import_end:
  
  if(rc == IERROR && key) { sltgs23_grp_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  
  return NULL; 
  
}

char* sltgs23_grp_key_to_string(groupsig_key_t *key) { 
  return NULL;
}

/* grp_key.c ends here */
