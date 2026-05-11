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

#ifndef _KLAPSEQ_PROOF_H
#define _KLAPSEQ_PROOF_H

#include "groupsig/klapseq/spk.h"
#include "include/proof.h"
#include "klapseq.h"

/**
 * @struct klapseq_proof_t
 * @brief Open proofs for KLAPSEQ.
 */
typedef klapseq_spk1_t klapseq_proof_t;

/** 
 * @fn struct groupsig_proof_t* klapseq_proof_init()
 * @brief Initializes the fields of a KLAPSEQ proof.
 *
 * @return A pointer to the allocated proof or NULL if error.
 */
groupsig_proof_t* klapseq_proof_init();

/** 
 * @fn int klapseq_proof_free(groupsig_proof_t *proof)
 * @brief Frees the alloc'ed fields of the given KLAPSEQ proof.
 *
 * @param[in,out] proof The proof to free.
 * 
 * @return IOK or IERROR
 */
int klapseq_proof_free(groupsig_proof_t *proof);

/** 
 * @fn void* klapseq_proof_copy(void *proof)
 * @brief Copies the given proof into a new one.
 *
 * @param[in] proof The proof to copy. 
 * 
 * @return A newly allocated proof (similar to the one received) or NULL
 *  if error.
 */
void* klapseq_proof_copy(void *proof);

/** 
 * @fn int klapseq_proof_to_string
 * @brief Returns a printable string representing the current proof.
 *
 * @param[in] proof The proof to print.
 * 
 * @return IOK or IERROR
 */
char* klapseq_proof_to_string(groupsig_proof_t *proof);

/** 
 * @fn int klapseq_proof_get_size(groupsig_proof_t *proof)
 * @brief Returns the size of the proof as an array of bytes.
 *
 * @param[in] proof The proof.
 * 
 * @return -1 if error. Otherwise, the size of the proof in bytes.
 */
int klapseq_proof_get_size(groupsig_proof_t *proof);

/** 
 * @fn int klapseq_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof);
 * @brief Writes a bytearray representation of the given signature, with format
 *  | KLAPSEQ_CODE | size_proof | proof |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported 
 *  proof. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] proof The proof to export.
 * 
 * @return IOK or IERROR with errno updated.
 */
int klapseq_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof);

/** 
 * @fn groupsig_proof_t *proof klapseq_proof_import(byte_t *source, uint32_t *size)
 * @brief Imports a KLAPSEQ open proof.
 *
 * Imports a KLAPSEQ open proof from the specified array of bytes.
 *
 * @param[in] source The array of bytes containing the proof to import.
 * @param[in] size The number of bytes in <i>source</i>.
 * 
 * @return A pointer to the imported proof, or NULL if error.
 */
groupsig_proof_t* klapseq_proof_import(byte_t *source, uint32_t size);

/**
 * @var klapseq_proof_handle
 * @brief Set of functions to manage KLAPSEQ proofs.
 */
static const groupsig_proof_handle_t klapseq_proof_handle = {
  .scheme = GROUPSIG_KLAPSEQ_CODE, /**< The scheme code. */
  .init = &klapseq_proof_init, /**< Initalizes proofs. */
  .free = &klapseq_proof_free, /**< Frees proofs. */
  .get_size = &klapseq_proof_get_size, /**< Gets the size, in bytes, of a proof. */
  .gexport = &klapseq_proof_export, /**< Exports proofs. */
  .gimport = &klapseq_proof_import, /**< Imports proofs. */
  .to_string = &klapseq_proof_to_string /**< Gets printable representations of proofs. */
};

#endif /* _KLAPSEQ_PROOF_H */

/* proof.h ends here */
