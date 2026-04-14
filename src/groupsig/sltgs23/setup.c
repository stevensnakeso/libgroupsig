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
#include <math.h>

#include "sltgs23.h"
#include "groupsig/sltgs23/grp_key.h"
#include "groupsig/sltgs23/mgr_key.h"
#include "sys/mem.h"

int sltgs23_init() {

  if(pbcext_init(BLS12_381) == IERROR) {
    return IERROR;
  }
  
  return IOK;

}

int sltgs23_clear() {
  return IOK;  
}

int sltgs23_setup(groupsig_key_t *grpkey,
	       groupsig_key_t *mgrkey,
	       gml_t *gml) {

  sltgs23_grp_key_t *gkey;
  sltgs23_mgr_key_t *mkey;
  int rc, status;
  uint8_t call;

  if(!grpkey || grpkey->scheme != GROUPSIG_SLTGS23_CODE ||
     !mgrkey || grpkey->scheme != GROUPSIG_SLTGS23_CODE) {
    LOG_EINVAL(&logger, __FILE__, "sltgs23_setup", __LINE__, LOGERROR);
    return IERROR;
  }

  gkey = grpkey->key;
  mkey = mgrkey->key;
  rc = IOK;
  call = 0;

  if(!gkey->g1){

    call = 1;

    /* Initialize the manager key */
    if(!(mkey->isk = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_setup);
    if(pbcext_element_Fr_random(mkey->isk) == IERROR)
      GOTOENDRC(IERROR, sltgs23_setup);

    /* Initialize the group key */
    
    /* Compute random generators g1, h1 and h2 in G1. Since G1 is a cyclic 
      group of prime order, just pick random elements.  */
    if(!(gkey->g = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_setup);
    if(pbcext_element_G1_random(gkey->g) == IERROR)
      GOTOENDRC(IERROR, sltgs23_setup);

    if(!(gkey->g1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_setup);
    if(pbcext_element_G1_random(gkey->g1) == IERROR)
      GOTOENDRC(IERROR, sltgs23_setup);

    if(!(gkey->h1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_setup);
    if(pbcext_element_G1_random(gkey->h1) == IERROR)
      GOTOENDRC(IERROR, sltgs23_setup);

    if(!(gkey->h2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_setup);
    if(pbcext_element_G1_random(gkey->h2) == IERROR)
      GOTOENDRC(IERROR, sltgs23_setup);

    /* Compute random generator g2 in G2. Since G2 is a cyclic group of prime 
      order, just pick a random element. */
    if(!(gkey->g2 = pbcext_element_G2_init())) GOTOENDRC(IERROR, sltgs23_setup);
    if(pbcext_element_G2_random(gkey->g2) == IERROR)
      GOTOENDRC(IERROR, sltgs23_setup);

    /* Set the Issuer public key */
    if(!(gkey->ipk = pbcext_element_G2_init())) GOTOENDRC(IERROR, sltgs23_setup);
    if(pbcext_element_G2_mul(gkey->ipk, gkey->g2, mkey->isk) == IERROR)
      GOTOENDRC(IERROR, sltgs23_setup);

  }
    /*
   * If the group key is not "empty" (gkey->g1 != null), we interpret this as 
   * the second call. In this case, we set the manager's key to an initialized
   * Converter key (using the value of g computed in the first call), and fill
   * the received public key with the public part of the Converter's keypair.
   */

  else {
    call = 2;

    /* Generate the Converter's private key */
    if(!(mkey->csk = pbcext_element_Fr_init())) GOTOENDRC(IERROR, sltgs23_setup);
    if(pbcext_element_Fr_random(mkey->csk) == IERROR)
      GOTOENDRC(IERROR, sltgs23_setup);

    /* Add the Converter's public key to the group key */
    if(!(gkey->cpk = pbcext_element_G1_init())) GOTOENDRC(IERROR, sltgs23_setup);
    if(pbcext_element_G1_mul(gkey->cpk, gkey->g, mkey->csk) == IERROR)
      GOTOENDRC(IERROR, sltgs23_setup);


  }

  
 sltgs23_setup_end:

  if (rc == IERROR) {
    if(call==1)
    {
      if (mkey->isk) { pbcext_element_Fr_free(mkey->isk); mkey->isk = NULL; }
      if (gkey->g1) { pbcext_element_G1_free(gkey->g1); gkey->g1 = NULL; }
      if (gkey->h1) { pbcext_element_G1_free(gkey->h1); gkey->h1 = NULL; }
      if (gkey->h2) { pbcext_element_G1_free(gkey->h2); gkey->h2 = NULL; }
      if (gkey->g2) { pbcext_element_G2_free(gkey->g2); gkey->g2 = NULL; }
      if (gkey->ipk) { pbcext_element_G2_free(gkey->ipk); gkey->ipk = NULL; }
    }
     if(call==2)
     {
      if (mkey->csk) { pbcext_element_Fr_free(mkey->csk); mkey->csk = NULL; }    
      if (gkey->cpk) { pbcext_element_G1_free(gkey->cpk); gkey->cpk = NULL; }
     }

    }

    
  

  return rc;

}

/* setup.c ends here */
