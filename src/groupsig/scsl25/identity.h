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

#ifndef _SCSL25_IDENTITY_H
#define _SCSL25_IDENTITY_H

#include "include/identity.h"
#include "scsl25.h"
#include "shim/pbc_ext.h"

/**
 * BBS+ signatures used by SCSL25
 * They are membership credentials, which can be seen as a kind of identity.
 * Hence, I define them here.
 */
typedef struct {
  pbcext_element_G1_t *u; /* u = e * x */
  pbcext_element_G1_t *v; /* v = U^(1/isk) mod n */
  pbcext_element_G1_t *x; /* 秘密值 x (Secret exponent) */
  pbcext_element_G1_t *e; /* 秘密值 e (Secret exponent) */
} scsl25_cred_t;

/**
 * SCSL25 identities.
 */
typedef pbcext_element_G1_t scsl25_identity_t;

/** 
 * @fn void* scsl25_identity_init()
 * @brief Allocates memory for a SCSL25 identity and sets its values to defaults.
 * 
 * @return A pointer to the allocated memory or NULL if error.
 */
identity_t* scsl25_identity_init();

/** 
 * @fn int scsl25_identity_free(void *id)
 * @brief Frees the memory allocated for a SCSL25 identity.
 *
 * @param[in,out] id The identity to free.
 * 
 * @return IOK.
 */
int scsl25_identity_free(identity_t *id);

/** 
 * @fn int scsl25_identity_copy(identity_t *dst, identity_t *src)
 * @brief Copies the source identity into the destination identity.
 *
 * @param[in,out] dst The destination identity. Initialized by the caller.
 * @param[in] src The source identity.
 * 
 * @return IOK or IERROR.
 */
int scsl25_identity_copy(identity_t *dst, identity_t *src);

/** 
 * @fn uint8_t scsl25_identity_cmp(identity_t *id1, identity_t *id2);
 * @brief Returns 0 if both ids are the same, != 0 otherwise.
 *
 * @param[in] id1 The first id to compare. 
 * @param[in] id2 The second id to compare.
 * 
 * @return 0 if both ids are the same, != otherwise. In case of error,
 *  errno is set consequently.
 */
uint8_t scsl25_identity_cmp(identity_t *id1, identity_t *id2);

/** 
 * @fn char* scsl25_identity_to_string(identity_t *id)
 * @brief Converts the given SCSL25 id into a printable string.
 *
 * @param[in] id The ID to convert.
 * 
 * @return A pointer to the produced string or NULL if error.
 */
char* scsl25_identity_to_string(identity_t *id);

/** 
 * @fn identity_t* scsl25_identity_from_string(char *sid)
 * @brief Parses the given string as  SCSL25 identity.
 *
 * @param[in] sid The string containing the SCSL25 identity.
 * 
 * @return A pointer to the retrieved SCSL25 identity or NULL if error.
 */
identity_t* scsl25_identity_from_string(char *sid);

/**
 * @var scsl25_identity_handle
 * @brief Set of functions to manage SCSL25 identities.
 */
static const identity_handle_t scsl25_identity_handle = {
  GROUPSIG_SCSL25_CODE, /**< Scheme code. */
  &scsl25_identity_init, /**< Identity initialization. */
  &scsl25_identity_free, /**< Identity free.*/
  &scsl25_identity_copy, /**< Copies identities. */
  &scsl25_identity_cmp, /**< Compares identities. */
  &scsl25_identity_to_string, /**< Converts identities to printable strings. */
  &scsl25_identity_from_string /**< Imports identities from strings. */
};

#endif /* _SCSL25_IDENTITY_H */

/* identity.h ends here */
