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
#include <math.h>

#include "types.h"
#include "sysenv.h"
#include "sys/mem.h"
#include "shim/base64.h"
#include "misc/misc.h"
#include "scsl25.h"
#include "groupsig/scsl25/proof.h"
#include "crypto/spk.h"

/* 初始化：分配 SCSL25 证明结构并初始化底层的 SPK */
groupsig_proof_t* scsl25_proof_init() {

  groupsig_proof_t *proof;
  scsl25_proof_t *scsl25_proof;

  if(!(proof = (groupsig_proof_t *) mem_malloc(sizeof(groupsig_proof_t)))) {
    return NULL;
  }

  proof->scheme = GROUPSIG_SCSL25_CODE;
  if(!(scsl25_proof = (scsl25_proof_t *) mem_malloc(sizeof(scsl25_proof_t)))) {
    mem_free(proof); proof = NULL;
    return NULL;
  }
  
  if(!(scsl25_proof->spk = spk_dlog_init())) {
    mem_free(proof); proof = NULL;
    mem_free(scsl25_proof); scsl25_proof = NULL;
    return NULL;
  }

  scsl25_proof->n = 0;
  scsl25_proof->x = NULL;//
  scsl25_proof->xlen = NULL;//
  proof->proof = scsl25_proof;

  return proof;

}

/* 释放内存：递归释放动态数组 x 及其成员，符合安全内存管理要求 */
int scsl25_proof_free(groupsig_proof_t *proof) {

  scsl25_proof_t *scsl25_proof;
  uint64_t i;
  
  if(!proof) {
    LOG_EINVAL_MSG(&logger, __FILE__, "scsl25_proof_free", __LINE__,
       "Nothing to free.", LOGWARN);
    return IERROR;
  }

  scsl25_proof = proof->proof;

  if (scsl25_proof) {

    if (scsl25_proof->spk) {
      spk_dlog_free(scsl25_proof->spk);
      scsl25_proof->spk = NULL;
    }
    
    if (scsl25_proof->x) {
      for (i=0; i<scsl25_proof->n; i++) {
        if (scsl25_proof->x[i]) {
          mem_free(scsl25_proof->x[i]);
          scsl25_proof->x[i] = NULL;
        }
      }
      mem_free(scsl25_proof->x); scsl25_proof->x = NULL;
    }
  
    if (scsl25_proof->xlen) {
      mem_free(scsl25_proof->xlen);
      scsl25_proof->xlen = NULL;
    }

    mem_free(scsl25_proof);//
  }
  //proof->proof = NULL;//
  mem_free(proof);

  return IOK;

}

/* 拷贝：实现证明及其动态分量的深拷贝 */
int scsl25_proof_copy(groupsig_proof_t *dst, groupsig_proof_t *src) {

  scsl25_proof_t *scsl25_dst, *scsl25_src;
  uint64_t i;
  int rc;
  
  if (!dst || !src) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_proof_copy", __LINE__, LOGERROR);
    return IERROR;    
  }

  rc = IOK;
  scsl25_dst = dst->proof;
  scsl25_src = src->proof;
  
  if (scsl25_src->n) {
    scsl25_dst->xlen = mem_malloc(sizeof(uint64_t)*scsl25_src->n);
    if (!scsl25_dst->xlen) GOTOENDRC(IERROR, scsl25_proof_copy);
    scsl25_dst->x = mem_malloc(sizeof(byte_t *)*scsl25_src->n);
    if (!scsl25_dst->x) GOTOENDRC(IERROR, scsl25_proof_copy);

    for (i=0; i<scsl25_src->n; i++) {
      scsl25_dst->x[i] = mem_malloc(sizeof(byte_t)*scsl25_src->xlen[i]);
      if (!scsl25_dst->x[i]) GOTOENDRC(IERROR, scsl25_proof_copy);
      memcpy(scsl25_dst->x[i], scsl25_src->x[i], scsl25_src->xlen[i]);
      scsl25_dst->xlen[i] = scsl25_src->xlen[i];
    }
  }
  scsl25_dst->n = scsl25_src->n;

  if (spk_dlog_copy(scsl25_dst->spk, scsl25_src->spk) == IERROR)
    GOTOENDRC(IERROR, scsl25_proof_copy);

scsl25_proof_copy_end:

  if (rc == IERROR) {
    if (scsl25_dst->xlen) { mem_free(scsl25_dst->xlen); scsl25_dst->xlen = NULL; }
    if (scsl25_dst->x) {
      for (i=0; i<scsl25_dst->n; i++) {
        if (scsl25_dst->x[i]) { mem_free(scsl25_dst->x[i]); scsl25_dst->x[i] = NULL; }
      }
      mem_free(scsl25_dst->x); scsl25_dst->x = NULL;
    }
  }
  
  return rc;
  
}

/* 导出：将链接证明导出为二进制流，支持聚合序列证明项 */
int scsl25_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof) {

  scsl25_proof_t *scsl25_proof;
  byte_t *_bytes, *__bytes;
  int rc, _size;
  uint64_t proof_len, ctr, i;

  if(!proof || proof->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_proof_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  _bytes = NULL;
  scsl25_proof = proof->proof;

  if ((_size = scsl25_proof_get_size(proof)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }  

  /* Dump GROUPSIG_SCSL25_CODE */
  _bytes[0] = GROUPSIG_SCSL25_CODE;
  ctr = 1;

  /* Dump the spk */
  __bytes = &_bytes[ctr];  
  if (spk_dlog_export(&__bytes, &proof_len, scsl25_proof->spk) == IERROR)
    GOTOENDRC(IERROR, scsl25_proof_export);  
  ctr += proof_len;
  
  /* Dump the sequence metadata and elements */
  memcpy(&_bytes[ctr], &scsl25_proof->n, sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  for (i=0; i<scsl25_proof->n; i++) {
    memcpy(&_bytes[ctr], &scsl25_proof->xlen[i], sizeof(uint64_t));
    ctr += sizeof(uint64_t);
    memcpy(&_bytes[ctr], scsl25_proof->x[i], scsl25_proof->xlen[i]);
    ctr += scsl25_proof->xlen[i];
  }

  /* Sanity check */
  if (_size != ctr) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "scsl25_proof_export", __LINE__,
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, scsl25_proof_export);
  }

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, _size);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = _size;  
  
 scsl25_proof_export_end:

  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;
}

/* 导入：重建序列链接证明结构 */
groupsig_proof_t* scsl25_proof_import(byte_t *source, uint32_t size) {

  groupsig_proof_t *proof;
  scsl25_proof_t *scsl25_proof;
  uint64_t proof_len, ctr, i;
  int rc;
  uint8_t scheme;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_proof_import", __LINE__, LOGERROR);
    return NULL;}

  rc = IOK;
  if(!(proof = scsl25_proof_init())) return NULL;
  scsl25_proof = proof->proof;  

  scheme = source[0];
  if (scheme != proof->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "scsl25_proof_import", __LINE__, 
		      EDQUOT, "Unexpected proof scheme.", LOGERROR);
    GOTOENDRC(IERROR, scsl25_proof_import);
  }
  ctr = 1;

  /* Read the spk */
  if (!(scsl25_proof->spk = spk_dlog_import(&source[ctr], &proof_len)))
    GOTOENDRC(IERROR, scsl25_proof_import);
  ctr += proof_len;
  
  /* Read metadata n */
  memcpy(&scsl25_proof->n, &source[ctr], sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  if (scsl25_proof->n) {
    if (!(scsl25_proof->x = (byte_t **) mem_malloc(sizeof(byte_t *)*scsl25_proof->n)))
      GOTOENDRC(IERROR, scsl25_proof_import);
    if (!(scsl25_proof->xlen = (uint64_t *) mem_malloc(sizeof(uint64_t)*scsl25_proof->n)))
      GOTOENDRC(IERROR, scsl25_proof_import);
    
    for (i=0; i<scsl25_proof->n; i++) {
      memcpy(&scsl25_proof->xlen[i], &source[ctr], sizeof(uint64_t));
      ctr += sizeof(uint64_t);
      if (!(scsl25_proof->x[i] = (byte_t *) mem_malloc(scsl25_proof->xlen[i])))
        GOTOENDRC(IERROR, scsl25_proof_import);
      memcpy(scsl25_proof->x[i], &source[ctr], scsl25_proof->xlen[i]);
      ctr += scsl25_proof->xlen[i];
    }
  }

  if (size != ctr) rc = IERROR;
  
scsl25_proof_import_end:

  if(rc == IERROR && proof) { scsl25_proof_free(proof); proof = NULL; }
  return (rc == IOK) ? proof : NULL;  
}

/* 获取大小：计算导出所需的缓冲区总量 */
int scsl25_proof_get_size(groupsig_proof_t *proof) {

  scsl25_proof_t *scsl25_proof;
  uint64_t i;
  int size;
  
  if (!proof) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_proof_get_size", __LINE__, LOGERROR);
    return -1;
  }
  scsl25_proof = proof->proof;

  if ((size = spk_dlog_get_size(scsl25_proof->spk)) == -1) return -1;

  for (i=0; i<scsl25_proof->n; i++) {
    size += scsl25_proof->xlen[i];
  }

  size += (scsl25_proof->n + 1) * sizeof(uint64_t) + 1; // n + xlen[] + scheme

  return size;
}

char* scsl25_proof_to_string(groupsig_proof_t *proof) {

  if(!proof || proof->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_proof_to_string", __LINE__, LOGERROR);
    return NULL;
  }
  /* @TODO: 实现 Base64 编码的证明字符串输出 */
  return NULL;
}

/* proof.c ends here */
