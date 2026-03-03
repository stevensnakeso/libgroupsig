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

#include "sysenv.h"
#include "sys/mem.h"
#include "misc/misc.h"
#include "shim/base64.h"

#include "scsl25.h"
#include "groupsig/scsl25/grp_key.h"

groupsig_key_t* scsl25_grp_key_init() {

  groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (scsl25_grp_key_t *) mem_malloc(sizeof(scsl25_grp_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_SCSL25_CODE;

  return key;
  
}

int scsl25_grp_key_free(groupsig_key_t *key) {

  scsl25_grp_key_t *scsl25_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "scsl25_grp_key_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(key->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_grp_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {

    scsl25_key = key->key;

    if(scsl25_key->n) { pbcext_element_G1_free(scsl25_key->n); scsl25_key->n = NULL; }
    if(scsl25_key->g) { pbcext_element_G1_free(scsl25_key->g); scsl25_key->g = NULL; }
    if(scsl25_key->g1) { pbcext_element_G1_free(scsl25_key->g1); scsl25_key->g1 = NULL; }
    if(scsl25_key->Y) { pbcext_element_G1_free(scsl25_key->Y); scsl25_key->Y = NULL; }
    mem_free(key->key);
    key->key = NULL;
  }

  mem_free(key);  

  return IOK;

}

int scsl25_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  scsl25_grp_key_t *scsl25_dst, *scsl25_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_SCSL25_CODE ||
     !src || src->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_grp_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  scsl25_dst = dst->key;
  scsl25_src = src->key;

  /* Copy the elements */
  if(!(scsl25_dst->n = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_grp_key_copy);
  if(pbcext_element_G1_set(scsl25_dst->n, scsl25_src->n) == IERROR) GOTOENDRC(IERROR, scsl25_grp_key_copy);
  
  if(!(scsl25_dst->g = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_grp_key_copy);
  if(pbcext_element_G1_set(scsl25_dst->g, scsl25_src->g) == IERROR) GOTOENDRC(IERROR, scsl25_grp_key_copy);
  
  if(!(scsl25_dst->g1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_grp_key_copy);
  if(pbcext_element_G1_set(scsl25_dst->g1, scsl25_src->g1) == IERROR) GOTOENDRC(IERROR, scsl25_grp_key_copy);

  if(!(scsl25_dst->Y = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_grp_key_copy);
  if(pbcext_element_G1_set(scsl25_dst->Y, scsl25_src->Y) == IERROR) GOTOENDRC(IERROR, scsl25_grp_key_copy);

  /* 复制标量安全参数 */
  scsl25_dst->lambda = scsl25_src->lambda;
  scsl25_dst->lambda1 = scsl25_src->lambda1;
  scsl25_dst->lambda2 = scsl25_src->lambda2;

 scsl25_grp_key_copy_end:

  if (rc == IERROR) {
    if (rc == IERROR) scsl25_grp_key_free(dst);
  }
  
  return rc;

}

int scsl25_grp_key_get_size(groupsig_key_t *key) {
  scsl25_grp_key_t *scsl_key;
  uint64_t sn, sg, sg1, sY;
  
  if(!key || key->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_grp_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  scsl_key = key->key;

  sn = sg = sg1 = sY = 0;
  if (scsl_key->n) { if(pbcext_element_G1_byte_size(&sn) == IERROR) return -1; } 
  if (scsl_key->g) { if(pbcext_element_G1_byte_size(&sg) == IERROR) return -1; }
  if (scsl_key->g1) { if(pbcext_element_G1_byte_size(&sg1) == IERROR) return -1;}
  if (scsl_key->Y) { if(pbcext_element_G1_byte_size(&sY) == IERROR) return -1; } 

  if(sn + sg + sg1 +sY > INT_MAX)
    return -1;
  // 大小 = 模式头 + 4 pointer + 3个 uint32 安全参数
  return (int) sn + sg + sg1 + sY + (sizeof(int)*4) + 2 + (sizeof(uint32_t)*3); //how to compute the size
}

int scsl25_grp_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key) {
  scsl25_grp_key_t *scsl_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr = 0, rc = IOK;

  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_grp_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  scsl_key = key->key;
  
  if ((_size = scsl25_grp_key_get_size(key)) == -1) return IERROR;
  if(!(_bytes = mem_malloc(_size))) return IERROR;

  _bytes[ctr++] = GROUPSIG_SCSL25_CODE;
  _bytes[ctr++] = GROUPSIG_KEY_GRPKEY;
  
  /* 依次 Dump n, g, g1, Y */
  /* Dump n */
  if(scsl_key->n) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, scsl_key->n) == IERROR)
      GOTOENDRC(IERROR, scsl25_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  if(scsl_key->g) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, scsl_key->g) == IERROR)
      GOTOENDRC(IERROR, scsl25_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  if(scsl_key->g1) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, scsl_key->g1) == IERROR)
      GOTOENDRC(IERROR, scsl25_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  if(scsl_key->Y) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, scsl_key->g1) == IERROR)
      GOTOENDRC(IERROR, scsl25_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }
  


  /* 导出安全参数 */
  memcpy(&_bytes[ctr], &scsl_key->lambda, sizeof(uint32_t)); ctr += sizeof(uint32_t);
  memcpy(&_bytes[ctr], &scsl_key->lambda1, sizeof(uint32_t)); ctr += sizeof(uint32_t);
  memcpy(&_bytes[ctr], &scsl_key->lambda2, sizeof(uint32_t)); ctr += sizeof(uint32_t);



  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "scsl25_grp_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, scsl25_grp_key_export);
  }

  *size = ctr;
  scsl25_grp_key_export_end:

  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  return rc;


}

groupsig_key_t* scsl25_grp_key_import(byte_t *source, uint32_t size) {
  groupsig_key_t *key;
  scsl25_grp_key_t *scsl25_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_grp_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = scsl25_grp_key_init())) {
    return NULL;
  }

  scsl25_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "scsl25_grp_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, scsl25_grp_key_import);
  }

  /* Next byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_GRPKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "scsl25_grp_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, scsl25_grp_key_import);
  }

  /* Get n */
  if(!(scsl25_key->n = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, scsl25_grp_key_import);
  if(pbcext_get_element_G1_bytes(scsl25_key->n, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(scsl25_key->n); scsl25_key->n = NULL;
  } else {
    ctr += len;
  }

  /* Get g */
  if(!(scsl25_key->g = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, scsl25_grp_key_import);
  if(pbcext_get_element_G1_bytes(scsl25_key->g, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(scsl25_key->g); scsl25_key->g = NULL;
  } else {
    ctr += len;
  }

  /* Get g1 */
  if(!(scsl25_key->g1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, scsl25_grp_key_import);
  if(pbcext_get_element_G1_bytes(scsl25_key->g1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(scsl25_key->g1); scsl25_key->g1 = NULL;
  } else {
    ctr += len;
  }

  /* Get Y */
  if(!(scsl25_key->Y = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, scsl25_grp_key_import);
  if(pbcext_get_element_G1_bytes(scsl25_key->Y, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(scsl25_key->Y); scsl25_key->Y = NULL;
  } else {
    ctr += len;
  }


  /* 加载安全参数 */
  memcpy(&scsl25_key->lambda, &source[ctr], sizeof(uint32_t)); ctr += sizeof(uint32_t);
  memcpy(&scsl25_key->lambda1, &source[ctr], sizeof(uint32_t)); ctr += sizeof(uint32_t);
  memcpy(&scsl25_key->lambda2, &source[ctr], sizeof(uint32_t)); ctr += sizeof(uint32_t);
  scsl25_grp_key_import_end:
  
  if(rc == IERROR && key) { scsl25_grp_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  return NULL;    

}

char* scsl25_grp_key_to_string(groupsig_key_t *key) {
  fprintf(stderr, "@TODO scsl25_grp_key_to_string not implemented.\n");
  return NULL;
}
/* grp_key.c ends here */
