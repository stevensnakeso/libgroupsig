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
#include "groupsig/scsl25/signature.h"

/* 初始化：分配签名容器并设置架构代码 */
groupsig_signature_t* scsl25_signature_init() {

  groupsig_signature_t *sig;
  scsl25_signature_t *scsl25_sig;

  scsl25_sig = NULL;

  if(!(sig = (groupsig_signature_t *) mem_malloc(sizeof(groupsig_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "scsl25_signature_init", __LINE__, errno,
      LOGERROR);
  }

  if(!(scsl25_sig = (scsl25_signature_t *) mem_malloc(sizeof(scsl25_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "scsl25_signature_init", __LINE__, errno,
      LOGERROR);
    return NULL;
  }

  sig->scheme = GROUPSIG_SCSL25_CODE;
  sig->sig = scsl25_sig;

  return sig;

}

/* 释放内存：安全清理所有签名分量、SPK 证明及序列信息 */
int scsl25_signature_free(groupsig_signature_t *sig) {

  scsl25_signature_t *scsl25_sig;

  if(!sig || sig->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "scsl25_signature_free", __LINE__,
       "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(sig->sig) {
    scsl25_sig = sig->sig;
    if(scsl25_sig->w1) { pbcext_element_G1_free(scsl25_sig->w1); scsl25_sig->w1 = NULL; }
    if(scsl25_sig->w2) { pbcext_element_G1_free(scsl25_sig->w2); scsl25_sig->w2 = NULL; }
    if(scsl25_sig->t1) { pbcext_element_Fr_free(scsl25_sig->t1); scsl25_sig->t1 = NULL; }
    if(scsl25_sig->t2) { pbcext_element_Fr_free(scsl25_sig->t2); scsl25_sig->t2 = NULL; }
    if(scsl25_sig->t3) { pbcext_element_Fr_free(scsl25_sig->t3); scsl25_sig->t3 = NULL; }
    // if(scsl25_sig->c) { pbcext_element_Fr_free(scsl25_sig->c); scsl25_sig->c = NULL; }
    if(scsl25_sig->psd) { pbcext_element_G1_free(scsl25_sig->psd); scsl25_sig->psd = NULL; }
    
    if(scsl25_sig->pi) { spk_rep_free(scsl25_sig->pi); scsl25_sig->pi = NULL; }
    
    if (scsl25_sig->seq) {
      if (scsl25_sig->seq->seq1) { mem_free(scsl25_sig->seq->seq1); scsl25_sig->seq->seq1 = NULL; }
      if (scsl25_sig->seq->seq2) { mem_free(scsl25_sig->seq->seq2); scsl25_sig->seq->seq2 = NULL; }
      if (scsl25_sig->seq->seq3) { mem_free(scsl25_sig->seq->seq3); scsl25_sig->seq->seq3 = NULL; }
      mem_free(scsl25_sig->seq);
      scsl25_sig->seq = NULL;
    }
    mem_free(scsl25_sig);
    scsl25_sig = NULL;
  }

  mem_free(sig);

  return IOK;

}

/* 拷贝：深拷贝签名分量和 ZKP 证明 */
int scsl25_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  scsl25_signature_t *scsl25_dst, *scsl25_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_SCSL25_CODE ||
     !src || src->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  scsl25_dst = dst->sig;
  scsl25_src = src->sig;
  rc = IOK;

  /* 拷贝 w1, w2, psd */
  if(!(scsl25_dst->w1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_signature_copy);
  if(pbcext_element_G1_set(scsl25_dst->w1, scsl25_src->w1) == IERROR) GOTOENDRC(IERROR, scsl25_signature_copy);

  if(!(scsl25_dst->w2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_signature_copy);
  if(pbcext_element_G1_set(scsl25_dst->w2, scsl25_src->w2) == IERROR) GOTOENDRC(IERROR, scsl25_signature_copy);

  if(!(scsl25_dst->psd = pbcext_element_G1_init())) GOTOENDRC(IERROR, scsl25_signature_copy);
  if(pbcext_element_G1_set(scsl25_dst->psd, scsl25_src->psd) == IERROR) GOTOENDRC(IERROR, scsl25_signature_copy);

  if(!(scsl25_dst->t1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_signature_copy);
  if(pbcext_element_Fr_set(scsl25_dst->t1, scsl25_src->t1) == IERROR) GOTOENDRC(IERROR, scsl25_signature_copy);

  if(!(scsl25_dst->t2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_signature_copy);
  if(pbcext_element_Fr_set(scsl25_dst->t2, scsl25_src->t2) == IERROR) GOTOENDRC(IERROR, scsl25_signature_copy);

  if(!(scsl25_dst->t3 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_signature_copy);
  if(pbcext_element_Fr_set(scsl25_dst->t3, scsl25_src->t3) == IERROR) GOTOENDRC(IERROR, scsl25_signature_copy);

  if(!(scsl25_dst->c = pbcext_element_Fr_init())) GOTOENDRC(IERROR, scsl25_signature_copy);
  if(pbcext_element_Fr_set(scsl25_dst->c, scsl25_src->c) == IERROR) GOTOENDRC(IERROR, scsl25_signature_copy);

  /* 拷贝 ZKP 证明 pi */
  if(!(scsl25_dst->pi = spk_rep_init(scsl25_src->pi->ns))) GOTOENDRC(IERROR, scsl25_signature_copy);
  if(spk_rep_copy(scsl25_dst->pi, scsl25_src->pi) == IERROR) GOTOENDRC(IERROR, scsl25_signature_copy);

scsl25_signature_copy_end:
  if (rc == IERROR) scsl25_signature_free(dst);
  return rc;

}

/* 计算大小：用于序列化分配 */
int scsl25_signature_get_size(groupsig_signature_t *sig) {

  uint64_t G1, Fr;
  scsl25_signature_t *scsl25_sig;
  int size;

  if (!sig) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_signature_get_size", __LINE__,
	       LOGERROR);
    return -1;
  }
  scsl25_sig = sig->sig;

    // To export the signature, we need to calculate the sizes of dl21seq_signature_t:
  // w1-sz (int), w1 (G1), w2_-sz (int), w2_ (G1), t1-sz (int), t1 (Fr) t2-sz (int), t2 (Fr) t3-sz (int), t3 (Fr) c-sz (int), c (Fr) 
  // psd-sz (int), psd (G1), pi (spk_rep), seq (dl21seq_seqinfo)
  // spk_rep: c-sz (int), c (Fr), n*s-sz (int), n*s (Fr)
  // dl21seq_seqinfo: 3*seq-sz (uint64), 3*seq
  // total:
  // 1 (schema) + 7*int + 3*G1 (w1 , w2, psd) + 4 * Fr (t1, t2, t3, c)
  // int + Fr (c) + n*int + n*Fr (s) + 3*uint64 + 3*seq

  if (pbcext_element_G1_byte_size(&G1) == IERROR) return -1;
  if (pbcext_element_Fr_byte_size(&Fr) == IERROR) return -1;

  /* 计算公式与 dl21seq 保持一致，分量替换为 w1, w2, psd */
  size = 1 + 3*sizeof(int) + 3*G1 + 4*Fr + 4 * sizeof(int)  + Fr+ sizeof(int) + scsl25_sig->pi->ns*sizeof(int) //two c
    + scsl25_sig->pi->ns*Fr + 3*sizeof(uint64_t) + scsl25_sig->seq->len1
    + scsl25_sig->seq->len2 + scsl25_sig->seq->len3;

  if (size > INT_MAX) return -1;
  return size;
}

/* 导出：将签名打包为字节流 */
int scsl25_signature_export(byte_t **bytes, uint32_t *size, groupsig_signature_t *sig) {

  scsl25_signature_t *scsl25_sig;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int rc, ctr, _size;

  if(!sig || sig->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_signature_export", __LINE__, LOGERROR);
    return IERROR;
  }
  rc = IOK; ctr = 0; scsl25_sig = sig->sig;

  if ((_size = scsl25_signature_get_size(sig)) == -1) return IERROR;
  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) return IERROR;

  _bytes[ctr++] = GROUPSIG_SCSL25_CODE;

  /* Dump w1, w2 c*/
  __bytes = &_bytes[ctr];
  pbcext_dump_element_G1_bytes(&__bytes, &len, scsl25_sig->w1); ctr += len;
  __bytes = &_bytes[ctr];
  pbcext_dump_element_G1_bytes(&__bytes, &len, scsl25_sig->w2); ctr += len;

  __bytes = &_bytes[ctr];
  pbcext_dump_element_Fr_bytes(&__bytes, &len, scsl25_sig->c); ctr += len;
  

  /* Dump t1, t2, t3 */
  __bytes = &_bytes[ctr];
  pbcext_dump_element_Fr_bytes(&__bytes, &len, scsl25_sig->t1); ctr += len;
  __bytes = &_bytes[ctr];
  pbcext_dump_element_Fr_bytes(&__bytes, &len, scsl25_sig->t2); ctr += len;
  __bytes = &_bytes[ctr];
  pbcext_dump_element_Fr_bytes(&__bytes, &len, scsl25_sig->t3); ctr += len;

  /* Dump psd */
  __bytes = &_bytes[ctr];
  pbcext_dump_element_G1_bytes(&__bytes, &len, scsl25_sig->psd); ctr += len;


  /* Dump spk: c and s[] */
  __bytes = &_bytes[ctr];
  pbcext_dump_element_Fr_bytes(&__bytes, &len, scsl25_sig->pi->c); ctr += len;
  for(int i = 0; i < scsl25_sig->pi->ns; i++) {
    __bytes = &_bytes[ctr];
    pbcext_dump_element_Fr_bytes(&__bytes, &len, scsl25_sig->pi->s[i]); ctr += len;
  }

  

  /* Dump Sequential info */
  memcpy(&_bytes[ctr], &scsl25_sig->seq->len1, sizeof(uint64_t)); ctr += sizeof(uint64_t);
  memcpy(&_bytes[ctr], scsl25_sig->seq->seq1, scsl25_sig->seq->len1); ctr += scsl25_sig->seq->len1;

  memcpy(&_bytes[ctr], &scsl25_sig->seq->len2, sizeof(uint64_t)); ctr += sizeof(uint64_t);
  memcpy(&_bytes[ctr], scsl25_sig->seq->seq2, scsl25_sig->seq->len2); ctr += scsl25_sig->seq->len2;

  memcpy(&_bytes[ctr], &scsl25_sig->seq->len3, sizeof(uint64_t)); ctr += sizeof(uint64_t);
  memcpy(&_bytes[ctr], scsl25_sig->seq->seq3, scsl25_sig->seq->len3); ctr += scsl25_sig->seq->len3;

  if(!*bytes) *bytes = _bytes;
  else { memcpy(*bytes, _bytes, ctr); mem_free(_bytes); }
  *size = ctr;

scsl25_signature_export_end:
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;
}

/* 导入：从字节流还原签名 */
groupsig_signature_t* scsl25_signature_import(byte_t *source, uint32_t size) {

  groupsig_signature_t *sig;
  scsl25_signature_t *scsl25_sig;
  uint64_t len;
  uint16_t i;
  int rc, ctr;
  uint8_t scheme;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "scsl25_signature_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(sig = scsl25_signature_init())) {
    return NULL;
  }

  scsl25_sig = sig->sig;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != sig->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "scsl25_signature_import", __LINE__,
          EDQUOT, "Unexpected signature scheme.", LOGERROR);
    GOTOENDRC(IERROR, scsl25_signature_import);
  }

  /* Get w1 */
  if(!(scsl25_sig->w1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, scsl25_signature_import);
  if(pbcext_get_element_G1_bytes(scsl25_sig->w1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_signature_import);
  if (!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(scsl25_sig->w1); scsl25_sig->w1 = NULL;
  } else {
    ctr += len;
  }

  /* Get w2 */
  if(!(scsl25_sig->w2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, scsl25_signature_import);
  if(pbcext_get_element_G1_bytes(scsl25_sig->w2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_signature_import);
  if (!len) {
    ctr += sizeof(int);
    pbcext_element_G1_free(scsl25_sig->w2); scsl25_sig->w2 = NULL;
  } else {
    ctr += len;
  }

  /* Get c */
  if(!(scsl25_sig->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, scsl25_signature_import);
  if(pbcext_get_element_Fr_bytes(scsl25_sig->c, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_signature_import);
  if (!len) {
    ctr += sizeof(int);
    pbcext_element_Fr_free(scsl25_sig->c); scsl25_sig->c = NULL;
  } else {
    ctr += len;
  }
  
  /* Get t1 */
  if(!(scsl25_sig->t1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, scsl25_signature_import);
  if(pbcext_get_element_Fr_bytes(scsl25_sig->t1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_signature_import);
  if (!len) {
    ctr += sizeof(int);
    pbcext_element_Fr_free(scsl25_sig->t1); scsl25_sig->t1 = NULL;
  } else {
    ctr += len;
  }

  /* Get t2 */
  if(!(scsl25_sig->t2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, scsl25_signature_import);
  if(pbcext_get_element_Fr_bytes(scsl25_sig->t2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_signature_import);
  if (!len) {
    ctr += sizeof(int);
    pbcext_element_Fr_free(scsl25_sig->t2); scsl25_sig->t2 = NULL;
  } else {
    ctr += len;
  }

  /* Get t3 */
  if(!(scsl25_sig->t3 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, scsl25_signature_import);
  if(pbcext_get_element_Fr_bytes(scsl25_sig->t3, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_signature_import);
  if (!len) {
    ctr += sizeof(int);
    pbcext_element_Fr_free(scsl25_sig->t3); scsl25_sig->t3 = NULL;
  } else {
    ctr += len;
  }

  /* Get psd */
  if(!(scsl25_sig->psd = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, scsl25_signature_import);
  if(pbcext_get_element_G1_bytes(scsl25_sig->psd, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_signature_import);
  if (!len) {
    ctr += sizeof(int);
  } else {
    ctr += len;
  }

  /* Get spk: c (SCSL25 pi contains 4 public SPK variables in this context) */
  if(!(scsl25_sig->pi = spk_rep_init(4)))
    GOTOENDRC(IERROR, scsl25_signature_import);

  if(!(scsl25_sig->pi->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, scsl25_signature_import);
  if(pbcext_get_element_Fr_bytes(scsl25_sig->pi->c, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, scsl25_signature_import);
  if (!len) {
    ctr += sizeof(int);
  } else {
    ctr += len;
  }

  /* Get spk: s */
  for(i=0; i<scsl25_sig->pi->ns; i++) {
    if(!(scsl25_sig->pi->s[i] = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, scsl25_signature_import);
    if(pbcext_get_element_Fr_bytes(scsl25_sig->pi->s[i], &len, &source[ctr]) == IERROR)
      GOTOENDRC(IERROR, scsl25_signature_import);
    if (!len) {
      ctr += sizeof(int);
    } else {
      ctr += len;
    }
  }

  

  /* Allocate sequence information structure */
  scsl25_sig->seq = (scsl25_seqinfo_t *) mem_malloc(sizeof(scsl25_seqinfo_t));
  if (!scsl25_sig->seq) GOTOENDRC(IERROR, scsl25_signature_import);

  /* Get len1 and seq1 */
  memcpy(&scsl25_sig->seq->len1, &source[ctr], sizeof(uint64_t));
  ctr += sizeof(uint64_t);
  if (!(scsl25_sig->seq->seq1 =
  (byte_t *) mem_malloc(sizeof(byte_t)*scsl25_sig->seq->len1)))
    GOTOENDRC(IERROR, scsl25_signature_import);
  memcpy(scsl25_sig->seq->seq1, &source[ctr], scsl25_sig->seq->len1);
  ctr += scsl25_sig->seq->len1;

  /* Get len2 and seq2 */
  memcpy(&scsl25_sig->seq->len2, &source[ctr], sizeof(uint64_t));
  ctr += sizeof(uint64_t);
  if (!(scsl25_sig->seq->seq2 =
  (byte_t *) mem_malloc(sizeof(byte_t)*scsl25_sig->seq->len2)))
    GOTOENDRC(IERROR, scsl25_signature_import);
  memcpy(scsl25_sig->seq->seq2, &source[ctr], scsl25_sig->seq->len2);
  ctr += scsl25_sig->seq->len2;

  /* Get len3 and seq3 */
  memcpy(&scsl25_sig->seq->len3, &source[ctr], sizeof(uint64_t));
  ctr += sizeof(uint64_t);
  if (!(scsl25_sig->seq->seq3 =
  (byte_t *) mem_malloc(sizeof(byte_t)*scsl25_sig->seq->len3)))
    GOTOENDRC(IERROR, scsl25_signature_import);
  memcpy(scsl25_sig->seq->seq3, &source[ctr], scsl25_sig->seq->len3);
  ctr += scsl25_sig->seq->len3;

scsl25_signature_import_end:

  if(rc == IERROR && sig) { scsl25_signature_free(sig); sig = NULL; }
  if(rc == IOK) return sig;
  return NULL;

}

char* scsl25_signature_to_string(groupsig_signature_t *sig) {
  uint32_t size;
  byte_t *bytes = NULL;
  char *str;
  if(!sig || sig->scheme != GROUPSIG_SCSL25_CODE) {
    LOG_EINVAL(&logger, __FILE__, "signature_to_string", __LINE__, LOGERROR);
    return NULL;
  }
  
  if(scsl25_signature_export(&bytes, &size, sig) == IERROR) return NULL;
  str = base64_encode(bytes, size, 1);
  mem_free(bytes);
  return str;
}

/* signature.c ends here */
