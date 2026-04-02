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

#include <stdlib.h>

#include "types.h"
#include "sys/mem.h"
#include "misc/misc.h"
#include "groupsig/sltgs23/trapdoor.h"

trapdoor_t* sltgs23_trapdoor_init() {
  
  trapdoor_t *trap;
  sltgs23_trapdoor_t *sltgs23_trap;
  
  if(!(trap = (trapdoor_t *) mem_malloc(sizeof(trapdoor_t)))) {
    return NULL;
  }

  if(!(sltgs23_trap = (sltgs23_trapdoor_t *) mem_malloc(sizeof(sltgs23_trapdoor_t)))) {
    mem_free(trap); trap = NULL;
    return NULL;
  }
  
  /* SLTGS23 does not implement tracing */
  sltgs23_trap->trace = NULL;
  
  /* The sltgs23_trap->open field is of type element_t (pbc library) and the
     pairing is necessary to initialize it, hence, it must be initialized
     and set in the join_mgr function. */
  
  trap->scheme = GROUPSIG_SLTGS23_CODE;
  trap->trap = sltgs23_trap;
  
  return trap;
  
}

int sltgs23_trapdoor_free(trapdoor_t *trap) {
  
  sltgs23_trapdoor_t *sltgs23_trap;
  
  if(!trap || trap->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "sltgs23_trapdoor_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }
  
  if(trap->trap) {
    sltgs23_trap = trap->trap;
    pbcext_element_G1_free(sltgs23_trap->open);
    mem_free(sltgs23_trap); sltgs23_trap = NULL;
  }
  
  mem_free(trap); trap = NULL;
  
  return IOK;
  
}

int sltgs23_trapdoor_copy(trapdoor_t *dst, trapdoor_t *src) {
  
  if(!dst || dst->scheme != GROUPSIG_SLTGS23_CODE ||
     !src || src->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_trapdoor_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(((sltgs23_trapdoor_t *) dst->trap)->open = pbcext_element_G1_init()))
    return IERROR;

  if(pbcext_element_G1_set(((sltgs23_trapdoor_t *) dst->trap)->open, 
			   ((sltgs23_trapdoor_t *) src->trap)->open) == IERROR) {
    pbcext_element_G1_free(((sltgs23_trapdoor_t *) dst->trap)->open);
    ((sltgs23_trapdoor_t *) dst->trap)->open = NULL;
    return IERROR;
  }
  
  return IOK;

}

char* sltgs23_trapdoor_to_string(trapdoor_t *trap) {
  
  char *str;
  
  if(!trap || trap->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_trapdoor_to_string", __LINE__, LOGERROR);
    return NULL;
  }
  
  /* SLTGS23 only has open trapdoors, with type bigz */
  if(!(str = pbcext_element_G1_to_b64(((sltgs23_trapdoor_t *)trap->trap)->open))) {
    return NULL;
  }
  
  return str;
  
}

trapdoor_t* sltgs23_trapdoor_from_string(char *strap) {
  
  trapdoor_t *trap;
  
  if(!strap) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_trapdoor_from_string", __LINE__, LOGERROR);
    return NULL;
  }
  
  if(!(trap = sltgs23_trapdoor_init())) {
    return NULL;
  }

  /* Open trapdoors are the A elements of the member keys */
  if(!(((sltgs23_trapdoor_t *) trap->trap)->open = pbcext_element_G1_init()))
    return NULL;
  if(pbcext_element_G1_from_b64(((sltgs23_trapdoor_t *) trap->trap)->open, strap) == IERROR) {
    sltgs23_trapdoor_free(trap); trap = NULL;
    return NULL;
  }
  
  return trap;
  
}

int sltgs23_trapdoor_cmp(trapdoor_t *t1, trapdoor_t *t2) {
  
  if(!t1 || t1->scheme != GROUPSIG_SLTGS23_CODE ||
     !t2 || t2->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_trapdoor_cmp", __LINE__, LOGERROR);
    return IERROR;
  }

  return pbcext_element_G1_cmp(((sltgs23_trapdoor_t *)t1->trap)->open, 
			       ((sltgs23_trapdoor_t *)t2->trap)->open);

}

/* identity.c ends here */
