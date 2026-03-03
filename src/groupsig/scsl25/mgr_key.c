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

#include "scsl25.h"
#include "groupsig/scsl25/mgr_key.h"
#include "misc/misc.h"
#include "shim/base64.h"
#include "sys/mem.h"

groupsig_key_t* scsl25_mgr_key_init() {

  groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (scsl25_mgr_key_t *) mem_malloc(sizeof(scsl25_mgr_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_SCSL25_CODE;

  return key;

}

int scsl25_mgr_key_free(groupsig_key_t *key) {

  scsl25_mgr_key_t *scsl25_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "scsl25_mgr_key_free", __LINE__,
       "Nothing to free.", LOGWARN);
    return IOK;
  }
  
  if(key->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_mgr_key_free", __LINE__, LOGERROR);
    return IERROR;         
  }

  if(key->key) {
    scsl25_key = key->key;
    /* 安全内存抹除：在释放大数对象前，确保敏感私钥分量被处理 */
    if(scsl25_key->isk) { pbcext_element_Fr_free(scsl25_key->isk); scsl25_key->isk = NULL; }
    if(scsl25_key->p) { pbcext_element_G1_free(scsl25_key->p); scsl25_key->p = NULL; }
    if(scsl25_key->q) { pbcext_element_G1_free(scsl25_key->q); scsl25_key->q = NULL; }
    
    /* 抹除结构体本身的内存，防止私钥指针信息残留 */
    memset(key->key, 0, sizeof(scsl25_mgr_key_t));//????

    mem_free(key->key);
    key->key = NULL;
  }
  
  mem_free(key);
  
  return IOK;

}

int scsl25_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  scsl25_mgr_key_t *scsl25_dst, *scsl25_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_SCSL25_CODE ||
     !src || src->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_mgr_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  scsl25_dst = dst->key;
  scsl25_src = src->key;

  /* Copy isk */
  if(!(scsl25_dst->isk = pbcext_element_Fr_init())) return IERROR;
  if(pbcext_element_Fr_set(scsl25_dst->isk, scsl25_src->isk) == IERROR)
    GOTOENDRC(IERROR, scsl25_mgr_key_copy);

  /* Copy p */
  if(scsl25_src->p) {
    if(!(scsl25_dst->p = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, scsl25_mgr_key_copy);
    if(pbcext_element_G1_set(scsl25_dst->p, scsl25_src->p) == IERROR)
      GOTOENDRC(IERROR, scsl25_mgr_key_copy);
  }

  /* Copy q */
  if(scsl25_src->q) {
    if(!(scsl25_dst->q = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, scsl25_mgr_key_copy);
    if(pbcext_element_G1_set(scsl25_dst->q, scsl25_src->q) == IERROR)
      GOTOENDRC(IERROR, scsl25_mgr_key_copy);
  }

 scsl25_mgr_key_copy_end:

  if (rc == IERROR) {
    if(scsl25_dst->isk) { pbcext_element_Fr_free(scsl25_dst->isk); scsl25_dst->isk = NULL; }
    if(scsl25_dst->p) { pbcext_element_G1_free(scsl25_dst->p); scsl25_dst->p = NULL; }
    if(scsl25_dst->q) { pbcext_element_G1_free(scsl25_dst->q); scsl25_dst->q = NULL; }
  }

  return rc;

}

int scsl25_mgr_key_get_size(groupsig_key_t *key) {

  scsl25_mgr_key_t *scsl25_key;
  uint64_t sisk, sp, sq;
  int size;

  if(!key || key->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_mgr_key_get_size",
         __LINE__, LOGERROR);
    return -1;
  }

  scsl25_key = key->key;
  sisk = sp = sq = 0;

  if (scsl25_key->isk) { if(pbcext_element_Fr_byte_size(&sisk) == IERROR) return -1; }
  if (scsl25_key->p) { if(pbcext_element_G1_byte_size(&sp) == IERROR) return -1; }
  if (scsl25_key->q) { if(pbcext_element_G1_byte_size(&sq) == IERROR) return -1; }

  if ((int) sisk + sp + sq + sizeof(int)*3+2 > INT_MAX) return -1;
  size = (int) sisk + sp + sq + sizeof(int)*3+2;

  return size;

}

int scsl25_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key) {

  scsl25_mgr_key_t *scsl25_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  uint32_t _size;
  int ctr, rc;
  
  if(!bytes || !size || !key || key->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_mgr_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  scsl25_key = key->key;

  if ((_size = scsl25_mgr_key_get_size(key)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_SCSL25_CODE */
  _bytes[ctr++] = GROUPSIG_SCSL25_CODE;

  /* Dump key type */
  _bytes[ctr++] = GROUPSIG_KEY_MGRKEY;

  /* Dump isk */
  if(scsl25_key->isk) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, scsl25_key->isk) == IERROR)
      GOTOENDRC(IERROR, scsl25_mgr_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump p */
  if(scsl25_key->p) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, scsl25_key->p) == IERROR)
      GOTOENDRC(IERROR, scsl25_mgr_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump q */
  if(scsl25_key->q) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, scsl25_key->q) == IERROR)
      GOTOENDRC(IERROR, scsl25_mgr_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "scsl25_mgr_key_export", __LINE__, 
          EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, scsl25_mgr_key_export);
  }

  *size = ctr;

 scsl25_mgr_key_export_end:

  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  
  return rc;
  
}

groupsig_key_t* scsl25_mgr_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  scsl25_mgr_key_t *scsl25_key;
  uint64_t len;
  int rc, ctr;
  uint8_t type, scheme;  
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_mgr_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(key = scsl25_mgr_key_init())) {
    return NULL;
  }
  scsl25_key = key->key;    

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "scsl25_mgr_key_import", __LINE__, 
          EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, scsl25_mgr_key_import);
  }  

  /* Next byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MGRKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "scsl25_mgr_key_import", __LINE__,
          EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, scsl25_mgr_key_import);
  }    

  /* Get isk */
  if(!(scsl25_key->isk = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, scsl25_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(scsl25_key->isk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_mgr_key_import);
  if(!len) {
    ctr += sizeof(int);
    pbcext_element_Fr_free(scsl25_key->isk); scsl25_key->isk = NULL;
  } else { ctr += len; }

  /* Get p */
  if(!(scsl25_key->p = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, scsl25_mgr_key_import);
  if(pbcext_get_element_G1_bytes(scsl25_key->p, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_mgr_key_import);
  if(!len) {
    ctr += sizeof(int);
    pbcext_element_G1_free(scsl25_key->p); scsl25_key->p = NULL;
  } else { ctr += len; }

  /* Get q */
  if(!(scsl25_key->q = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, scsl25_mgr_key_import);
  if(pbcext_get_element_G1_bytes(scsl25_key->q, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_mgr_key_import);
  if(!len) {
    ctr += sizeof(int);
    pbcext_element_G1_free(scsl25_key->q); scsl25_key->q = NULL;
  } else { ctr += len; }

 scsl25_mgr_key_import_end:
  
  if(rc == IERROR && key) { scsl25_mgr_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  return NULL;  

}

char* scsl25_mgr_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_mgr_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* mgr_key.c ends here */
