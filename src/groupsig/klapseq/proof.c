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
#include <unistd.h>

#include "types.h"
#include "sysenv.h"
#include "sys/mem.h"
#include "shim/pbc_ext.h"
#include "klapseq.h"
#include "groupsig/klapseq/spk.h"
#include "groupsig/klapseq/proof.h"

groupsig_proof_t* klapseq_proof_init() {

  groupsig_proof_t *proof;
  klapseq_spk1_t *spk1; //TYPE1 
  klapseql_proof_t *seq_proof; //TYPE2
  klapseq_proof_t *klap_proof;

  if(!(proof = (groupsig_proof_t *) mem_malloc(sizeof(groupsig_proof_t)))) {
    return NULL;
  }

  proof->scheme = GROUPSIG_KLAPSEQ_CODE;

  if(!(klap_proof = (klapseq_proof_t *) mem_malloc(sizeof(klapseq_proof_t)))) {
    mem_free(proof); proof = NULL;
    return NULL;
  }

  if(!(seq_proof = (klapseql_proof_t *) mem_malloc(sizeof(klapseql_proof_t)))) {
    mem_free(proof); proof = NULL;
    return NULL;
  }
  
  if(!(seq_proof->spk = spk_dlog_init())) {
    mem_free(proof); proof = NULL;
    mem_free(seq_proof); seq_proof = NULL;
    return NULL;
  }

  seq_proof->n = 0;

  klap_proof->spk1 = NULL;
  klap_proof->seq_proof = seq_proof;

  proof->proof = klap_proof;

  return proof;
}

int klapseq_proof_free(groupsig_proof_t *proof) {

  klapseq_proof_t *klapseq_proof;
  uint64_t i;
  if (!proof) {
    LOG_EINVAL_MSG(&logger, __FILE__, "klapseq_proof_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IERROR;
  }

  klapseq_proof = proof->proof;

  if (klapseq_proof) {
    klapseq_spk1_free(klapseq_proof->spk1);

  if (klapseq_proof->seq_proof) {
      if (klapseq_proof->seq_proof->spk) {
        spk_dlog_free(klapseq_proof->seq_proof->spk);
        klapseq_proof->seq_proof->spk = NULL;
      }

     if (klapseq_proof->seq_proof->x) {
      for (i=0; i<klapseq_proof->seq_proof->n; i++) {
	  if (klapseq_proof->seq_proof->x[i]) {
	  mem_free(klapseq_proof->seq_proof->x[i]);
	  klapseq_proof->seq_proof->x[i] = NULL;
	}
      }
      mem_free(klapseq_proof->seq_proof->x); klapseq_proof->seq_proof->x = NULL;
    }
  
    if (klapseq_proof->seq_proof->xlen) {
      mem_free(klapseq_proof->seq_proof->xlen);
      klapseq_proof->seq_proof->xlen = NULL;
    }
  }
  mem_free(klapseq_proof->seq_proof); klapseq_proof->seq_proof = NULL;

  mem_free(proof->proof); proof->proof = NULL;


    klapseq_proof = NULL;
  }
  
  mem_free(proof);

  return IOK;

}


int klapseq_proof_copy(groupsig_proof_t *dst, groupsig_proof_t *src) {

  klapseq_proof_t *klapseq_dst, *klapseq_src;
  uint64_t i;
  int rc;
  
  if (!dst || !src) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_proof_copy", __LINE__, LOGERROR);
    return IERROR;    
  }

  rc = IOK;
  klapseq_dst = dst->proof;
  klapseq_src = src->proof;

  klapseq_spk1_t *spk1_src = klapseq_src->spk1; //TYPE1 
  klapseql_proof_t *seq_proof_src = klapseq_src->seq_proof; //TYPE2

  klapseq_spk1_t *spk1_dst = klapseq_dst->spk1; //TYPE1 
  klapseql_proof_t *seq_proof_dst = klapseq_dst->seq_proof; //TYPE2
  
  spk1_dst = memcpy(spk1_dst, spk1_src, sizeof(klapseq_spk1_t));
  if (!spk1_dst) GOTOENDRC(IERROR, klapseq_proof_copy);

  seq_proof_dst->xlen = mem_malloc(sizeof(uint64_t)*seq_proof_src->n);
  if (!seq_proof_dst->xlen) GOTOENDRC(IERROR, klapseq_proof_copy);
  seq_proof_dst->x = mem_malloc(sizeof(byte_t *)*seq_proof_src->n);
  if (!seq_proof_dst->x) GOTOENDRC(IERROR, klapseq_proof_copy);

  for (i=0; i<seq_proof_dst->n; i++) {
    seq_proof_dst->x[i] = mem_malloc(sizeof(byte_t)*seq_proof_src->xlen[i]);
    if (!seq_proof_dst->x[i]) GOTOENDRC(IERROR, klapseq_proof_copy);
    memcpy(seq_proof_dst->x[i], seq_proof_src->x[i], seq_proof_src->xlen[i]);
    seq_proof_dst->xlen[i] = seq_proof_src->xlen[i];
  }
  seq_proof_dst->n = seq_proof_src->n;

  if (spk_dlog_copy(seq_proof_dst->spk, seq_proof_src->spk) == IERROR)
    GOTOENDRC(IERROR, klapseq_proof_copy);

 klapseq_proof_copy_end:

  if (rc == IERROR) {
    if (seq_proof_dst->xlen) {
      mem_free(seq_proof_dst->xlen);
      seq_proof_dst->xlen = NULL;
    }
    for (i=0; i<seq_proof_src->n; i++) {
      if (seq_proof_dst->x[i]) {
	mem_free(seq_proof_dst->x[i]);
	seq_proof_dst->x[i] = NULL;
      }
    }
    mem_free(seq_proof_dst->x);
    if (seq_proof_dst->spk) {
      spk_dlog_free(seq_proof_dst->spk);
      seq_proof_dst->spk = NULL;
    }
  }
  
  return rc;
  
}


int klapseq_proof_get_size(groupsig_proof_t *proof) {

  klapseq_proof_t *klapseq_proof;
  uint64_t size, proof_len;

  uint64_t spk1_size, spk1_proof_len;
  uint64_t i;
  int seq_size, seq_sx;

  
  if(!proof || proof->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_proof_get_size", __LINE__, LOGERROR);
    return -1;
  }

  klapseq_proof = proof->proof;

  if ((spk1_proof_len = klapseq_spk1_get_size(klapseq_proof->spk1)) == -1)
    return -1;

  size = spk1_proof_len + /* sizeof(int)*1 */ + 1;

  if ((seq_size = spk_dlog_get_size(klapseq_proof->seq_proof->spk)) == -1) {
    return -1;
  }

  size += seq_size;

  for (i=0; i<klapseq_proof->seq_proof->n; i++) {
    if (size + klapseq_proof->seq_proof->xlen[i] > INT_MAX) return -1;
    size += klapseq_proof->seq_proof->xlen[i];
  }

  if (size + sizeof(uint64_t) > INT_MAX) return -1;
  size += (klapseq_proof->seq_proof->n+1)*sizeof(uint64_t);

  if (size > INT_MAX) return -1;
  
  return (int) size;

}

int klapseq_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof) {

  klapseq_proof_t *klapseq_proof;
  byte_t *_bytes, *__bytes;
  int rc, _size;
  uint64_t proof_len, i, ctr=0;
  uint8_t code;

  klapseq_spk1_t *spk1; //TYPE1 
  klapseql_proof_t *seq_proof; //TYPE2
  klapseq_proof = proof->proof;
  spk1 = klapseq_proof->spk1; //TYPE1
  seq_proof = klapseq_proof->seq_proof; //TYPE2

  if(!proof || proof->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_proof_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  klapseq_proof = proof->proof;

  if ((_size = klapseq_proof_get_size(proof)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }  

  /* Dump GROUPSIG_KLAPSEQ_CODE */
  code = GROUPSIG_KLAPSEQ_CODE;
  _bytes[0] = code;

  /* Export the SPK */
  __bytes = &_bytes[1];

  if (klapseq_spk1_export(&__bytes, &proof_len, spk1) == IERROR)
    GOTOENDRC(IERROR, klapseq_proof_export);
  
  ctr += proof_len;

  /* Dump the spk of sequence proof */
  __bytes = &_bytes[1];  
  if (spk_dlog_export(&__bytes,
		      &proof_len,
		      seq_proof->spk) == IERROR)
    GOTOENDRC(IERROR, klapseq_proof_export);  
  ctr += proof_len;
  
  /* Dump the sequence numbers (prepended by their length) */
  memcpy(&_bytes[ctr], &seq_proof->n, sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  for (i=0; i<seq_proof->n; i++) {
    if (!seq_proof->xlen) GOTOENDRC(IERROR, klapseq_proof_export);
    memcpy(&_bytes[ctr], &seq_proof->xlen[i], sizeof(uint64_t));
    ctr += sizeof(uint64_t);
    memcpy(&_bytes[ctr], &seq_proof->x[i], seq_proof->xlen[i]);
    ctr += seq_proof->xlen[i];
  }


  

  /* Sanity check */
  if (_size != proof_len+1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klapseq_proof_export", __LINE__,
  		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, klapseq_proof_export);
  }

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, _size);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = _size;  

 klapseq_proof_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;
}

groupsig_proof_t* klapseq_proof_import(byte_t *source, uint32_t size) {

  groupsig_proof_t *proof;
  klapseql_proof_t *seq_proof;  //
  klapseq_proof_t *klapseq_proof;
  uint64_t proof_len, ctr, i;  //
  int rc;
  uint8_t scheme;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_proof_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  
  if(!(proof = klapseq_proof_init())) {
    return NULL;
  }

  /* First byte: scheme */
  scheme = source[0];
  if (scheme != proof->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klapseq_proof_import", __LINE__, 
		      EDQUOT, "Unexpected proof scheme.", LOGERROR);
    GOTOENDRC(IERROR, klapseq_proof_import);
  }

  ctr = 1;
  klapseq_proof = proof->proof;
  seq_proof = klapseq_proof->seq_proof;

  if (!(klapseq_proof->spk1 = klapseq_spk1_import(&source[1], &proof_len)))
    GOTOENDRC(IERROR, klapseq_proof_import);

  

   /* Read the SPK */
  if (!(seq_proof->spk = spk_dlog_import(&source[1], &proof_len)))
    GOTOENDRC(IERROR, klapseq_proof_import);
  ctr += proof_len;

   /* Read the sequence numbers and metadata */
  memcpy(&seq_proof->n, &source[ctr], sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  if (seq_proof->n) {
    if (!(seq_proof->x =
	  (byte_t **) mem_malloc(sizeof(byte_t *)*seq_proof->n)))
      GOTOENDRC(IERROR, klapseq_proof_import);

    if (!(seq_proof->xlen =
	  (uint64_t *) mem_malloc(sizeof(uint64_t)*seq_proof->n)))
      GOTOENDRC(IERROR, klapseq_proof_import);
    
    for (i=0; i<seq_proof->n; i++) {
      memcpy(&seq_proof->xlen[i], &source[ctr], sizeof(uint64_t));
      ctr += sizeof(uint64_t);
      memcpy(&seq_proof->x, &source[ctr], seq_proof->xlen[i]);
      ctr += seq_proof->xlen[i];
    }

  }
  
  if (size != ctr) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klapseq_proof_import", __LINE__, 
		      EDQUOT, "Unexpected proof size.", LOGERROR);
    GOTOENDRC(IERROR, klapseq_proof_import);
  }

 klapseq_proof_import_end:

  if(rc == IERROR && proof) { klapseq_proof_free(proof); proof = NULL; }
  if(rc == IOK) return proof;
  return NULL;  
  
}

char* klapseq_proof_to_string(groupsig_proof_t *proof) {

  if(!proof || proof->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_proof_to_string", __LINE__, LOGERROR);
    return NULL;
  }
  
  return NULL;

}

/* proof.c ends here */
