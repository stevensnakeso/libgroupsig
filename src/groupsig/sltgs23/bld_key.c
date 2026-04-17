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

#include "sltgs23.h"
#include "logger.h"
#include "groupsig/sltgs23/bld_key.h"
#include "groupsig/sltgs23/grp_key.h"
#include "shim/base64.h"
#include "misc/misc.h"
#include "sys/mem.h"

groupsig_key_t* sltgs23_bld_key_init() {

  groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (sltgs23_bld_key_t *) mem_malloc(sizeof(sltgs23_bld_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_SLTGS23_CODE;

  return key;

}

int sltgs23_bld_key_free(groupsig_key_t *key) {

  sltgs23_bld_key_t *sltgs23_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "sltgs23_bld_key_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(key->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_bld_key_free", __LINE__, LOGERROR);
    return IERROR;
  }

  if(key->key) {
    sltgs23_key = key->key;
    if(sltgs23_key->pk) {
      pbcext_element_G1_free(sltgs23_key->pk);
      sltgs23_key->pk = NULL;
    }

    if(sltgs23_key->sk) {
      pbcext_element_Fr_free(sltgs23_key->sk);
      sltgs23_key->sk = NULL;
    }

    mem_free(key->key);
    key->key = NULL;
  }

  mem_free(key);

  return IOK;

}

groupsig_key_t* sltgs23_bld_key_random(void *param) {

  groupsig_key_t *key;
  sltgs23_bld_key_t *sltgs23_bldkey;
  sltgs23_grp_key_t *sltgs23_grpkey;

  if(!param) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_bld_key_random", __LINE__, LOGERROR);
    return NULL;
  }

  if(((groupsig_key_t *)param)->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_bld_key_random", __LINE__, LOGERROR);
    return NULL;
  }

  if (!(key = sltgs23_bld_key_init())) {
    return NULL;
  }

  sltgs23_grpkey = ((groupsig_key_t *) param)->key;

  if(key->key) {
    sltgs23_bldkey = key->key;

    if(!(sltgs23_bldkey->sk = pbcext_element_Fr_init())) return NULL;
    if(pbcext_element_Fr_random(sltgs23_bldkey->sk) == IERROR) {
      sltgs23_bld_key_free(key); key = NULL;
      return NULL;
    }
    if(!(sltgs23_bldkey->pk = pbcext_element_G1_init())) {
      sltgs23_bld_key_free(key); key = NULL;
      return NULL;
    }
    if(pbcext_element_G1_mul(sltgs23_bldkey->pk,
			     sltgs23_grpkey->g,
			     sltgs23_bldkey->sk) == IERROR) {
      sltgs23_bld_key_free(key); key = NULL;
      return NULL;
    }
  }

  return key;

}

int sltgs23_bld_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  sltgs23_bld_key_t *sltgs23_dst, *sltgs23_src;

  if(!dst  || dst->scheme != GROUPSIG_SLTGS23_CODE ||
     !src  || src->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_bld_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  sltgs23_dst = dst->key;
  sltgs23_src = src->key;

  /* Copy the elements */
  if(!(sltgs23_dst->pk = pbcext_element_G1_init())) return IERROR;
  if(pbcext_element_G1_set(sltgs23_dst->pk, sltgs23_src->pk) == IERROR) {
    pbcext_element_G1_free(sltgs23_dst->pk); sltgs23_dst->pk = NULL;
    return IERROR;
  }

  if(!(sltgs23_dst->sk = pbcext_element_Fr_init())) {
    pbcext_element_G1_free(sltgs23_dst->pk); sltgs23_dst->pk = NULL;
    return IERROR;
  }

  if(pbcext_element_Fr_set(sltgs23_dst->sk, sltgs23_src->sk) == IERROR) {
    pbcext_element_G1_free(sltgs23_dst->pk); sltgs23_dst->pk = NULL;
    pbcext_element_Fr_free(sltgs23_dst->sk); sltgs23_dst->sk = NULL;
    return IERROR;
  }

  return IOK;

}

int sltgs23_bld_key_get_size(groupsig_key_t *key) {

  sltgs23_bld_key_t *sltgs23_key;
  uint64_t spk, ssk;
  int size;

  if(!key || key->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_bld_key_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }

  sltgs23_key =  key->key;

  if(!sltgs23_key->pk && !sltgs23_key->sk) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_bld_key_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }
  spk = ssk = 0;

  if(sltgs23_key->pk) { if(pbcext_element_G1_byte_size(&spk) == IERROR) return -1; }
  if(sltgs23_key->sk) { if(pbcext_element_Fr_byte_size(&ssk) == IERROR) return -1; }

  if (spk+ssk+sizeof(int)*2+2 > INT_MAX) {
    return -1;
  }

  size = (int) spk + ssk + sizeof(int)*2 + 2;

  return size;

}

char* sltgs23_bld_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_bld_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

int sltgs23_bld_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key) {

  uint8_t code, type;
  sltgs23_bld_key_t *sltgs23_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  uint32_t _size;
  int rc, ctr;

  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_bld_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  sltgs23_key = key->key;

  if ((_size = sltgs23_bld_key_get_size(key)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  if(!sltgs23_key->pk && !sltgs23_key->sk) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_bld_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Dump GROUPSIG_SLTGS23_CODE */
  code = GROUPSIG_SLTGS23_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_BLDKEY;
  _bytes[ctr++] = type;

  /* Dump pk, if present */
  if(sltgs23_key->pk) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, sltgs23_key->pk) == IERROR)
      GOTOENDRC(IERROR, sltgs23_bld_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump sk, if present */
  if(sltgs23_key->sk) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, sltgs23_key->sk) == IERROR)
      GOTOENDRC(IERROR, sltgs23_bld_key_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "sltgs23_bld_key_export", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, sltgs23_bld_key_export);
  }

  *size = ctr;

 sltgs23_bld_key_export_end:

  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }

  return rc;

}

int sltgs23_bld_key_export_pub(byte_t **bytes,
                            uint32_t *size,
                            groupsig_key_t *key) {

  groupsig_key_t *pub;
  sltgs23_bld_key_t *sltgs23_pub;
  int rc;

  if (!bytes ||
      !size ||
      !key || key->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_bld_key_export_pub", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Make an internal copy of the key, containing only the public part. */
  if (!(pub = sltgs23_bld_key_init())) return IERROR;
  sltgs23_pub = pub->key;
  if (!(sltgs23_pub->pk = pbcext_element_G1_init())) {
    sltgs23_bld_key_free(pub); pub = NULL;
    return IERROR;
  }
  if (pbcext_element_G1_set(sltgs23_pub->pk,
			    ((sltgs23_bld_key_t *) key->key)->pk) == IERROR) {
    sltgs23_bld_key_free(pub); pub = NULL;
    return IERROR;
  }

  rc =  sltgs23_bld_key_export(bytes, size, pub);
  sltgs23_bld_key_free(pub); pub = NULL;

  return rc;

}

int sltgs23_bld_key_pub(groupsig_key_t *key,
                     groupsig_key_t **pub) {
  sltgs23_bld_key_t *sltgs23_pub;

  if (!key || key->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_bld_key_export_pub", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Make an internal copy of the key, containing only the public part. */
  if (!(*pub = sltgs23_bld_key_init())) return IERROR;
  sltgs23_pub = (*pub)->key;
  if (!(sltgs23_pub->pk = pbcext_element_G1_init())) {
    sltgs23_bld_key_free(*pub); *pub = NULL;
    return IERROR;
  }
  if (pbcext_element_G1_set(sltgs23_pub->pk,
			    ((sltgs23_bld_key_t *) key->key)->pk) == IERROR) {
    sltgs23_bld_key_free(*pub); *pub = NULL;
    return IERROR;
  }

  return IOK;

}

int sltgs23_bld_key_export_prv(byte_t **bytes,
                            uint32_t *size,
                            groupsig_key_t *key) {

  groupsig_key_t *prv;
  sltgs23_bld_key_t *sltgs23_prv;
  int rc;

  if (!bytes ||
      !size ||
      !key || key->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_bld_key_export_prv", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Make an internal copy of the key, containing only the private part. */
  if (!(prv = sltgs23_bld_key_init())) return IERROR;
  sltgs23_prv = prv->key;
  if (!(sltgs23_prv->sk = pbcext_element_Fr_init())) {
    sltgs23_bld_key_free(prv); prv = NULL;
    return IERROR;
  }
  if (pbcext_element_Fr_set(sltgs23_prv->sk,
			    ((sltgs23_bld_key_t *) key->key)->sk) == IERROR) {
    sltgs23_bld_key_free(prv); prv = NULL;
    return IERROR;
  }

  rc =  sltgs23_bld_key_export(bytes, size, prv);
  sltgs23_bld_key_free(prv); prv = NULL;

  return rc;

}

int sltgs23_bld_key_prv(groupsig_key_t *key,
                     groupsig_key_t **prv) {

  sltgs23_bld_key_t *sltgs23_prv;

  if (!key || key->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_bld_key_prv", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Make an internal copy of the key, containing only the private part. */
  if (!(*prv = sltgs23_bld_key_init())) return IERROR;
  sltgs23_prv = (*prv)->key;
  if (!(sltgs23_prv->sk = pbcext_element_Fr_init())) {
    sltgs23_bld_key_free(*prv); *prv = NULL;
    return IERROR;
  }
  if (pbcext_element_Fr_set(sltgs23_prv->sk,
			    ((sltgs23_bld_key_t *) key->key)->sk) == IERROR) {
    sltgs23_bld_key_free(*prv); *prv = NULL;
    return IERROR;
  }

  return IOK;

}

groupsig_key_t* sltgs23_bld_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  sltgs23_bld_key_t *sltgs23_key;
  uint64_t len;
  int rc, ctr;
  byte_t type, scheme;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_bld_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  ctr = 0;
  rc = IOK;

  if(!(key = sltgs23_bld_key_init())) {
    return NULL;
  }
  sltgs23_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "sltgs23_bld_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, sltgs23_bld_key_import);
  }

  /* Next byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_BLDKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "sltgs23_bld_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, sltgs23_bld_key_import);
  }

  /* Get pk, if present */
  if(!(sltgs23_key->pk = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, sltgs23_bld_key_import);
  if(pbcext_get_element_G1_bytes(sltgs23_key->pk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_bld_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(sltgs23_key->pk); sltgs23_key->pk = NULL;
  } else {
    ctr += len;
  }

  /* Get sk, if present */
  if(!(sltgs23_key->sk = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, sltgs23_bld_key_import);
  if(pbcext_get_element_Fr_bytes(sltgs23_key->sk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, sltgs23_bld_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(sltgs23_key->sk); sltgs23_key->sk = NULL;
  } else {
    ctr += len;
  }

 sltgs23_bld_key_import_end:

  if (rc == IERROR) { sltgs23_bld_key_free(key); key = NULL; }
  if (rc == IOK) return key;
  return NULL;

}

/* bld_key.c ends here */
