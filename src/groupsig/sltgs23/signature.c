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
#include "sltgs23.h"
#include "groupsig/sltgs23/signature.h"

groupsig_signature_t* sltgs23_signature_init() {

  groupsig_signature_t *sig;
  sltgs23_signature_t *sltgs23_sig;

  sltgs23_sig = NULL;

  /* Initialize the signature contents */
  if(!(sig = (groupsig_signature_t *) mem_malloc(sizeof(groupsig_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "sltgs23_signature_init", __LINE__, errno,
		  LOGERROR);
  }

  if(!(sltgs23_sig = (sltgs23_signature_t *) mem_malloc(sizeof(sltgs23_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "sltgs23_signature_init", __LINE__, errno,
		  LOGERROR);
    return NULL;
  }

  sig->scheme = GROUPSIG_SLTGS23_CODE;
  sig->sig = sltgs23_sig;

  return sig;

}

int sltgs23_signature_free(groupsig_signature_t *sig) {

  sltgs23_signature_t *sltgs23_sig;

  if(!sig || sig->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "sltgs23_signature_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(sig->sig) {
    sltgs23_sig = sig->sig;
    pbcext_element_G1_free(sltgs23_sig->A1); sltgs23_sig->A1 = NULL;
    pbcext_element_G1_free(sltgs23_sig->A2); sltgs23_sig->A2 = NULL;
    pbcext_element_G1_free(sltgs23_sig->nym1); sltgs23_sig->nym1 = NULL;
    pbcext_element_G1_free(sltgs23_sig->nym2); sltgs23_sig->nym2 = NULL;
    pbcext_element_Fr_free(sltgs23_sig->c); sltgs23_sig->c = NULL;
    pbcext_element_Fr_free(sltgs23_sig->sr1); sltgs23_sig->sr1 = NULL;
    pbcext_element_Fr_free(sltgs23_sig->sr2); sltgs23_sig->sr2 = NULL;
    pbcext_element_Fr_free(sltgs23_sig->szeta1); sltgs23_sig->szeta1 = NULL;
    pbcext_element_Fr_free(sltgs23_sig->szeta2); sltgs23_sig->szeta2 = NULL;
    pbcext_element_Fr_free(sltgs23_sig->sy); sltgs23_sig->sy = NULL;
    if(sltgs23_sig->srho) {
      pbcext_element_Fr_free(sltgs23_sig->srho);
      sltgs23_sig->srho = NULL;
    }
    if(sltgs23_sig->ss) {
      pbcext_element_Fr_free(sltgs23_sig->ss);
      sltgs23_sig->ss = NULL;
    }
    if(sltgs23_sig->s_x) {
      pbcext_element_Fr_free(sltgs23_sig->s_x);
      sltgs23_sig->s_x = NULL;
    }

    sltgs23_sig = NULL;
  }

  mem_free(sig);

  return IOK;

}

int sltgs23_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  sltgs23_signature_t *sltgs23_dst, *sltgs23_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_SLTGS23_CODE ||
     !src || src->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  sltgs23_dst = dst->sig;
  sltgs23_src = src->sig;
  rc = IOK;

  /* Copy the elements */
  if(!(sltgs23_dst->A1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_G1_set(sltgs23_dst->A1, sltgs23_src->A1) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);

  if(!(sltgs23_dst->A2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_G1_set(sltgs23_dst->A2, sltgs23_src->A2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);

  if(!(sltgs23_dst->nym1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_G1_set(sltgs23_dst->nym1, sltgs23_src->nym1) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);

  if(!(sltgs23_dst->nym2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_G1_set(sltgs23_dst->nym2, sltgs23_src->nym2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);

  if(!(sltgs23_dst->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_Fr_set(sltgs23_dst->c, sltgs23_src->c) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);

  if(!(sltgs23_dst->sr1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_Fr_set(sltgs23_dst->sr1, sltgs23_src->sr1) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);

  if(!(sltgs23_dst->sr2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_Fr_set(sltgs23_dst->sr2, sltgs23_src->sr2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);

  if(!(sltgs23_dst->szeta1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_Fr_set(sltgs23_dst->szeta1, sltgs23_src->szeta1) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);

  if(!(sltgs23_dst->szeta2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_Fr_set(sltgs23_dst->szeta2, sltgs23_src->szeta2) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);

  if(!(sltgs23_dst->sy = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_Fr_set(sltgs23_dst->sy, sltgs23_src->sy) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);

  if(!(sltgs23_dst->srho = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_Fr_set(sltgs23_dst->srho, sltgs23_src->srho) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);

  if(!(sltgs23_dst->ss = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_Fr_set(sltgs23_dst->ss, sltgs23_src->ss) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);

  if(!(sltgs23_dst->s_x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_copy);
  if(pbcext_element_Fr_set(sltgs23_dst->s_x, sltgs23_src->s_x) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_copy);

 sltgs23_signature_copy_end:

  if (rc == IERROR) {
    if(sltgs23_dst->A1) {
      pbcext_element_G1_free(sltgs23_dst->A1);
      sltgs23_dst->A1 = NULL;
    }
    if(sltgs23_dst->A2) {
      pbcext_element_G1_free(sltgs23_dst->A2);
      sltgs23_dst->A2 = NULL;
    }
    if(sltgs23_dst->nym1) {
      pbcext_element_G1_free(sltgs23_dst->nym1);
      sltgs23_dst->nym1 = NULL;
    }
    if(sltgs23_dst->nym2) {
      pbcext_element_G1_free(sltgs23_dst->nym2);
      sltgs23_dst->nym2 = NULL;
    }

    if(sltgs23_dst->c) {
      pbcext_element_Fr_free(sltgs23_dst->c);
      sltgs23_dst->c = NULL;
    }

    if(sltgs23_dst->sr1) {
      pbcext_element_Fr_free(sltgs23_dst->sr1);
      sltgs23_dst->sr1 = NULL;
    }
    if(sltgs23_dst->sr2) {
      pbcext_element_Fr_free(sltgs23_dst->sr2);
      sltgs23_dst->sr2 = NULL;
    }
    if(sltgs23_dst->szeta1) {
      pbcext_element_Fr_free(sltgs23_dst->szeta1);
      sltgs23_dst->szeta1 = NULL;

    }
    if(sltgs23_dst->szeta2) {
      pbcext_element_Fr_free(sltgs23_dst->szeta2);
      sltgs23_dst->szeta2 = NULL;
    }
    if(sltgs23_dst->sy) {
      pbcext_element_Fr_free(sltgs23_dst->sy);
      sltgs23_dst->sy = NULL;
    }
    if(sltgs23_dst->srho) {
      pbcext_element_Fr_free(sltgs23_dst->srho);
      sltgs23_dst->srho = NULL;
    }
    if(sltgs23_dst->ss) {
      pbcext_element_Fr_free(sltgs23_dst->ss);
      sltgs23_dst->ss = NULL;
    }
    if(sltgs23_dst->s_x) {
      pbcext_element_Fr_free(sltgs23_dst->s_x);
      sltgs23_dst->s_x = NULL;
    }


  }

  return rc;

}

int sltgs23_signature_get_size(groupsig_signature_t *sig) {

  uint64_t sA1, sA2, snym1, snym2 ,sc, sr1, sr2, szeta1, szeta2, sy, srho, ss, s_x;
  sltgs23_signature_t *sltgs23_sig;
  int size, i;

  if(!sig || sig->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_signature_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }

  sltgs23_sig = sig->sig;

  if(pbcext_element_G1_byte_size(&sA1) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sA2) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&snym1) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&snym2) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sc) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sr1) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sr2) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&szeta1) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&szeta2) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sy) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&srho) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&ss) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&s_x) == IERROR) return -1;


  if ((int) sA1 + sA2   + snym1 + snym2 + sc + sr1 + sr2 + szeta1 + szeta2 + sy + srho + ss + s_x + sizeof(int)*13+1 > INT_MAX) return -1;
  size = (int) sA1 + sA2  + snym1 + snym2 + sc  + sr1 + sr2 + szeta1 + szeta2 + sy + srho + ss + s_x + sizeof(int)*13+1;

  return size;

}

int sltgs23_signature_export(byte_t **bytes,
			  uint32_t *size,
			  groupsig_signature_t *sig) {

  sltgs23_signature_t *sltgs23_sig;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int rc, ctr, _size;
  uint16_t i;

  if(!sig || sig->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_signature_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  sltgs23_sig = sig->sig;

  if ((_size = sltgs23_signature_get_size(sig)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }


   /* Dump GROUPSIG_SLTGS23_CODE */
  _bytes[ctr++] = GROUPSIG_SLTGS23_CODE;

  /* Dump A1 */
  if(sltgs23_sig->A1) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, sltgs23_sig->A1) == IERROR)
      GOTOENDRC(IERROR, sltgs23_signature_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump A2 */
  if(sltgs23_sig->A2) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, sltgs23_sig->A2) == IERROR)
      GOTOENDRC(IERROR, sltgs23_signature_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump nym1 */
  if(sltgs23_sig->nym1) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, sltgs23_sig->nym1) == IERROR)
      GOTOENDRC(IERROR, sltgs23_signature_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump nym2 */
  if(sltgs23_sig->nym2) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, sltgs23_sig->nym2) == IERROR)
      GOTOENDRC(IERROR, sltgs23_signature_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump c */
  if(sltgs23_sig->c) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_sig->c) == IERROR)
      GOTOENDRC(IERROR, sltgs23_signature_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  
  /* Dump sr1 */
  if(sltgs23_sig->sr1) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_sig->sr1) == IERROR)
      GOTOENDRC(IERROR, sltgs23_signature_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump sr2 */
  if(sltgs23_sig->sr2) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_sig->sr2) == IERROR)
      GOTOENDRC(IERROR, sltgs23_signature_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump szeta1 */
  if(sltgs23_sig->szeta1) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_sig->szeta1) == IERROR)
      GOTOENDRC(IERROR, sltgs23_signature_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump szeta2 */
  if(sltgs23_sig->szeta2) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_sig->szeta2) == IERROR)
      GOTOENDRC(IERROR, sltgs23_signature_export);
    ctr += len;
  } else { ctr += sizeof(int); }

    /* Dump sy */
  if(sltgs23_sig->sy) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_sig->sy) == IERROR)
      GOTOENDRC(IERROR, sltgs23_signature_export);
    ctr += len;
  } else { ctr += sizeof(int); }

    /* Dump srho */
  if(sltgs23_sig->srho) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_sig->srho) == IERROR)
      GOTOENDRC(IERROR, sltgs23_signature_export);
    ctr += len;
  } else { ctr += sizeof(int); }

    /* Dump ss */
  if(sltgs23_sig->ss) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_sig->ss) == IERROR)
      GOTOENDRC(IERROR, sltgs23_signature_export);
    ctr += len;
  } else { ctr += sizeof(int); }

    /* Dump s_x */
  if(sltgs23_sig->s_x) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_sig->s_x) == IERROR)
      GOTOENDRC(IERROR, sltgs23_signature_export);
    ctr += len;
  } else { ctr += sizeof(int); }  

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "sltgs23_signature_export", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, sltgs23_signature_export);
  }

  *size = ctr;

 sltgs23_signature_export_end:

  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;

}

groupsig_signature_t* sltgs23_signature_import(byte_t *source, uint32_t size) {

  groupsig_signature_t *sig;
  sltgs23_signature_t *sltgs23_sig;
  uint64_t len;
  uint16_t i;
  int rc, ctr;
  uint8_t scheme;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_signature_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(sig = sltgs23_signature_init())) {
    return NULL;
  }

  sltgs23_sig = sig->sig;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != sig->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "sltgs23_signature_import", __LINE__,
		      EDQUOT, "Unexpected signature scheme.", LOGERROR);
    GOTOENDRC(IERROR, sltgs23_signature_import);
  }

  /* Get A1 */
  if(!(sltgs23_sig->A1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_G1_bytes(sltgs23_sig->A1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get A2 */
  if(!(sltgs23_sig->A2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_G1_bytes(sltgs23_sig->A2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get nym1 */
  if(!(sltgs23_sig->nym1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_G1_bytes(sltgs23_sig->nym1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get nym2 */
  if(!(sltgs23_sig->nym2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_G1_bytes(sltgs23_sig->nym2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get c */
  if(!(sltgs23_sig->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_sig->c, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get sr1 */
  if(!(sltgs23_sig->sr1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_sig->sr1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get sr2 */
  if(!(sltgs23_sig->sr2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_sig->sr2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get szeta1 */
  if(!(sltgs23_sig->szeta1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_sig->szeta1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get szeta2 */
  if(!(sltgs23_sig->szeta2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_sig->szeta2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get sy */
  if(!(sltgs23_sig->sy = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_sig->sy, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get srho */
  if(!(sltgs23_sig->srho = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_sig->srho, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get ss */
  if(!(sltgs23_sig->ss = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_sig->ss, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

  /* Get s_x */
  if(!(sltgs23_sig->s_x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_signature_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_sig->s_x, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_signature_import);
  ctr += len;

sltgs23_signature_import_end:

  if(rc == IERROR && sig) { sltgs23_signature_free(sig); sig = NULL; }
  if(rc == IOK) return sig;
  return NULL;

}

char* sltgs23_signature_to_string(groupsig_signature_t *sig) {

  uint32_t size;
  byte_t *bytes;
  char *str;

  if(!sig || sig->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "signature_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(sltgs23_signature_export(&bytes, &size, sig) == IERROR) return NULL;
  str = base64_encode(bytes, size, 1);
  mem_free(bytes); bytes = NULL;

  return str;

}

/* signature.c ends here */
