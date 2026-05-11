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

  if(!(proof = (groupsig_proof_t *) mem_malloc(sizeof(groupsig_proof_t)))) {
    return NULL;
  }

  proof->scheme = GROUPSIG_KLAPSEQ_CODE;
  proof->proof = NULL;

  return proof;
}

int klapseq_proof_free(groupsig_proof_t *proof) {

  klapseq_proof_t *klapseq_proof;
  
  if (!proof) {
    LOG_EINVAL_MSG(&logger, __FILE__, "klapseq_proof_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IERROR;
  }

  klapseq_proof = proof->proof;

  if (klapseq_proof) {
    klapseq_spk1_free(klapseq_proof);
    klapseq_proof = NULL;
  }
  
  mem_free(proof);

  return IOK;

}

int klapseq_proof_get_size(groupsig_proof_t *proof) {

  klapseq_proof_t *klapseq_proof;
  uint64_t size, proof_len;
  
  if(!proof || proof->scheme != GROUPSIG_KLAPSEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klapseq_proof_get_size", __LINE__, LOGERROR);
    return -1;
  }

  klapseq_proof = proof->proof;

  if ((proof_len = klapseq_spk1_get_size(klapseq_proof)) == -1)
    return -1;

  size = proof_len + /* sizeof(int)*1 */ + 1;

  if (size > INT_MAX) return -1;
  
  return (int) size;

}

int klapseq_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof) {

  klapseq_proof_t *klapseq_proof;
  byte_t *_bytes, *__bytes;
  int rc, _size;
  uint64_t proof_len;
  uint8_t code;

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

  if (klapseq_spk1_export(&__bytes, &proof_len, klapseq_proof) == IERROR)
    GOTOENDRC(IERROR, klapseq_proof_export);

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
  uint64_t proof_len;
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

  if (!(proof->proof = klapseq_spk1_import(&source[1], &proof_len)))
    GOTOENDRC(IERROR, klapseq_proof_import);
  
  if (proof_len != size - 1) {
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
