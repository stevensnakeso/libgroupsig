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

#ifndef _SLTGS23_IDENTITY_H
#define _SLTGS23_IDENTITY_H

#include "include/identity.h"
#include "sltgs23.h"
#include "shim/pbc_ext.h"

/**
 * BBS+ signatures used by SLTGS23
 * They are membership credentials, which can be seen as a kind of identity.
 * Hence, I define them here.
 */
typedef struct _sltgs23_cred_t {
  pbcext_element_G1_t *A; /* A component of the credential */
  pbcext_element_Fr_t *x; /* x component of the credential */
  pbcext_element_Fr_t *s; /* s component of the credential */
} sltgs23_cred_t;

/**
 * SLTGS23 identities.
 */
typedef pbcext_element_G1_t sltgs23_identity_t;

/** 
 * @fn void* sltgs23_identity_init()
 * @brief Allocates memory for a SLTGS23 identity and sets its values to defaults.
 * 
 * @return A pointer to the allocated memory or NULL if error.
 */
identity_t* sltgs23_identity_init();

/** 
 * @fn int sltgs23_identity_free(void *id)
 * @brief Frees the memory allocated for a SLTGS23 identity.
 *
 * @param[in,out] id The identity to free.
 * 
 * @return IOK.
 */
int sltgs23_identity_free(identity_t *id);

/** 
 * @fn int sltgs23_identity_copy(identity_t *dst, identity_t *src)
 * @brief Copies the source identity into the destination identity.
 *
 * @param[in,out] dst The destination identity. Initialized by the caller.
 * @param[in] src The source identity.
 * 
 * @return IOK or IERROR.
 */
int sltgs23_identity_copy(identity_t *dst, identity_t *src);

/** 
 * @fn uint8_t sltgs23_identity_cmp(identity_t *id1, identity_t *id2);
 * @brief Returns 0 if both ids are the same, != 0 otherwise.
 *
 * @param[in] id1 The first id to compare. 
 * @param[in] id2 The second id to compare.
 * 
 * @return 0 if both ids are the same, != otherwise. In case of error,
 *  errno is set consequently.
 */
uint8_t sltgs23_identity_cmp(identity_t *id1, identity_t *id2);

/** 
 * @fn char* sltgs23_identity_to_string(identity_t *id)
 * @brief Converts the given SLTGS23 id into a printable string.
 *
 * @param[in] id The ID to convert.
 * 
 * @return A pointer to the produced string or NULL if error.
 */
char* sltgs23_identity_to_string(identity_t *id);

/** 
 * @fn identity_t* sltgs23_identity_from_string(char *sid)
 * @brief Parses the given string as  SLTGS23 identity.
 *
 * @param[in] sid The string containing the SLTGS23 identity.
 * 
 * @return A pointer to the retrieved SLTGS23 identity or NULL if error.
 */
identity_t* sltgs23_identity_from_string(char *sid);

/**
 * @var sltgs23_identity_handle
 * @brief Set of functions to manage SLTGS23 identities.
 */
static const identity_handle_t sltgs23_identity_handle = {
  GROUPSIG_SLTGS23_CODE, /**< Scheme code. */
  &sltgs23_identity_init, /**< Identity initialization. */
  &sltgs23_identity_free, /**< Identity free.*/
  &sltgs23_identity_copy, /**< Copies identities. */
  &sltgs23_identity_cmp, /**< Compares identities. */
  &sltgs23_identity_to_string, /**< Converts identities to printable strings. */
  &sltgs23_identity_from_string /**< Imports identities from strings. */
};

#endif /* _SLTGS23_IDENTITY_H */

/* identity.h ends here */
