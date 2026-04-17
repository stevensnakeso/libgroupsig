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

#ifndef _SLTGS23_SIGNATURE_H
#define _SLTGS23_SIGNATURE_H

#include <stdint.h>
#include "include/signature.h"
#include "sltgs23.h"
#include "crypto/spk.h"

/**
 * @struct sltgs23_signature_t
 * @brief Defines the structure of a SLTGS23 signature.
 * Defineme.
 */
typedef struct {
  uint8_t scheme; /**< Metainformation: the gs scheme this key belongs to. */
  pbcext_element_G1_t *A1;
  pbcext_element_G1_t *A2;
  pbcext_element_G1_t *nym1;
  pbcext_element_G1_t *nym2;
  pbcext_element_Fr_t *c;
  pbcext_element_Fr_t *sr1, *sr2,  *szeta1, *szeta2, *sy, *srho, *ss, *s_x; //*sx
  // pbcext_element_G1_t *t1, *t2, *t3, *t4;
  // pbcext_element_GT_t *t5;
} sltgs23_signature_t;

/** 
 * @fn groupsig_signature_t* sltgs23_signature_init()
 * @brief Initializes the fields of a SLTGS23 signature.
 * 
 * @return A pointer to the allocated signature, or NULL if error.
 */
groupsig_signature_t* sltgs23_signature_init();

/** 
 * @fn int sltgs23_signature_free(groupsig_signature_t *sig)
 * @brief Frees the alloc'ed fields of the given SLTGS23 signature.
 *
 * @param[in,out] sig The signature to free.
 * 
 * @return IOK or IERROR
 */
int sltgs23_signature_free(groupsig_signature_t *sig);

/** 
 * @fn int sltgs23_signature_copy(groupsig_signature_t *dst, 
 *                              groupsig_signature_t *src)
 * @brief Copies the given source signature into the destination signature.
 *
 * @param[in,out] dst The destination signature. Initialized by the caller.
 * @param[in] src The signature to copy. 
 * 
 * @return IOK or IERROR.
 */
int sltgs23_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src);

/** 
 * @fn int sltgs23_signature_to_string(groupsig_signature_t *sig)
 * @brief Returns a printable string representing the current signature.
 *
 * @param[in] sig The signature o convert.
 * 
 * @return A pointer to the created string or NULL if error.
 */
char* sltgs23_signature_to_string(groupsig_signature_t *sig);

/** 
 * @fn int sltgs23_signature_get_size_in_format(groupsig_signature_t *sig)
 * Returns the size of the signature as an array of bytes.
 *
 * @param[in] sig The signature.
 * 
 * @return -1 if error, the size that this signature would as an array of bytes.
 */
int sltgs23_signature_get_size(groupsig_signature_t *sig);

/** 
 * @fn int sltgs23_signature_export(byte_t **bytes,
 *                               uint32_t *size,
 *                               groupsig_signature_t *signature)
 * @brief Exports the specified signature to as an array of bytes, as follows:
 * 
 *    | SLTGS23_CODE | sizeof(AA) | AA | sizeof(A_) | A_ | sizeof(d) | d | 
 *      sizeof(spk) | spk | sizeof(nym) | nym |
 *
 * @param[in,out] bytes A pointer to the array of bytes. If <i>*bytes</i> is NULL,
 *  memory is internally allocated.
 * @param[in,out] size Will be set to the number of bytes written into <i>*bytes</i>.
 * @param[in] signature The group signature to export.
 * 
 * @return IOK or IERROR
 */
int sltgs23_signature_export(byte_t **bytes,
			  uint32_t *size,
			  groupsig_signature_t *signature);

/** 
 * @fn groupsig_signature_t* sltgs23_signature_import(byte_t *source,
 *                                                 uint32_t size)
 * @brief Imports a signature according to the specified format.
 *
 * @param[in] source The array of bytes to parse.
 * @param[in] size The number of bytes in <i>source</i>.
 * 
 * @return A pointer to the imported signature, or NULL if error.
 */
groupsig_signature_t* sltgs23_signature_import(byte_t *source,
					    uint32_t size);

/**
 * @var sltgs23_signature_handle
 * @brief Set of functions for managing SLTGS23 signatures.
 */
static const groupsig_signature_handle_t sltgs23_signature_handle = {
  .scheme = GROUPSIG_SLTGS23_CODE, /**< The scheme code. */
  .init = &sltgs23_signature_init,  /**< Initializes signatures. */
  .free = &sltgs23_signature_free, /**< Frees signatures. */
  .copy = &sltgs23_signature_copy, /**< Copies signatures. */
  .get_size = &sltgs23_signature_get_size, /**< Gets the size in bytes of a signature. */
  .gexport = &sltgs23_signature_export, /**< Exports signatures. */
  .gimport = &sltgs23_signature_import, /**< Imports signatures. */
  .to_string = &sltgs23_signature_to_string, /**< Converts signatures to printable strings. */
};

#endif

/* signature.h ends here */
