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

#ifndef _SLTGS23_GRP_KEY_H
#define _SLTGS23_GRP_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "sltgs23.h"
#include "include/grp_key.h"
#include "shim/pbc_ext.h"


/**
 * @struct sltgs23_grp_key_t
 * @brief Structure for SLTGS23 group keys.
 *
 * For convenience, we set a public key of SLTGS23 to contain the instance parameters 
 * as well as the public keys of Issuer and Converter. @TODO We may want to 
 * redesign this at some point...
 */
typedef struct {
   pbcext_element_G1_t *g; /**< Params. Random generator of G1. */ // g
  pbcext_element_G1_t *g1; /**< Params. Random generator of G1. */ // g0
  pbcext_element_G2_t *g2; /**< Params. Random generator of G2. */ // h0
  pbcext_element_G1_t *h1; /**< Params. Random generator of G1. */ // g1
  pbcext_element_G1_t *h2; /**< Params. Random generator of G1. */ // g2
  pbcext_element_G2_t *ipk; /**< Issuer public key. */
  pbcext_element_G1_t *cpk; /**< Converter public key. */ //cpk
} sltgs23_grp_key_t;

/**
 * @def SLTGS23_GRP_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing SLTGS23 group keys
 */
#define SLTGS23_GRP_KEY_BEGIN_MSG "BEGIN SLTGS23 GROUPKEY"

/**
 * @def SLTGS23_GRP_KEY_END_MSG
 * @brief End string to prepend to headers of files containing SLTGS23 group keys
 */
#define SLTGS23_GRP_KEY_END_MSG "END SLTGS23 GROUPKEY"

/** 
 * @fn groupsig_key_t* sltgs23_grp_key_init()
 * @brief Creates a new group key.
 *
 * @return A pointer to the initialized group key or NULL in case of error.
 */
groupsig_key_t* sltgs23_grp_key_init();

/** 
 * @fn int sltgs23_grp_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given group key.
 *
 * @param[in,out] key The group key to initialize.
 * 
 * @return IOK or IERROR
 */
int sltgs23_grp_key_free(groupsig_key_t *key);

/** 
 * @fn int sltgs23_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies a group key.
 *
 * Copies the source key into the destination key (which must be initialized by 
 * the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int sltgs23_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/**
 * @fn int sltgs23_grp_key_get_size_in_format(groupsig_key_t *key)
 * @brief Returns the number of bytes required to export the key.
 *
 * @param[in] key The key.
 *
 * @return The required number of bytes, or -1 if error.
 */
int sltgs23_grp_key_get_size(groupsig_key_t *key);

/** 
 * @fn int sltgs23_grp_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Exports the given group key to a bytearray with the following format:
 *
 *  | SLTGS23_CODE | KEYTYPE | size_g1 | g1 | size_g2 | g2 |
 *    size_h1 | h1 | size_h2 | h2 | size_ipk | ipk |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  group key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The group key to export.
 * 
 * @return IOK or IERROR.
 */
int sltgs23_grp_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* sltgs23_grp_key_import(byte_t *source, uint32_t size)
 * @brief Imports a group key.
 *
 * Imports a SLTGS23 group key from the specified source, of the specified format.
 * 
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported key, or NULL if error.
 */
groupsig_key_t* sltgs23_grp_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* sltgs23_grp_key_to_string(groupsig_key_t *key)
 * @brief Converts the key to a printable string.
 *
 * Returns a printable string associated to the given key.
 *
 * @param[in] key The key to convert.
 * 
 * @return The printable string associated to the key, or NULL if error.
 */
char* sltgs23_grp_key_to_string(groupsig_key_t *key);

/**
 * @var sltgs23_grp_key_handle
 * @brief The set of functions to manage SLTGS23 group keys.
 */
static const grp_key_handle_t sltgs23_grp_key_handle = {
 .code = GROUPSIG_SLTGS23_CODE, /**< Scheme. */
 .init = &sltgs23_grp_key_init, /**< Initialize group keys. */
 .free = &sltgs23_grp_key_free, /**< Free group keys. */
 .copy = &sltgs23_grp_key_copy, /**< Copy group keys. */
 .gexport = &sltgs23_grp_key_export, /**< Export group keys. */
 .gimport = &sltgs23_grp_key_import, /**< Import group keys. */
 .to_string = &sltgs23_grp_key_to_string, /**< Convert to printable strings. */
 .get_size = &sltgs23_grp_key_get_size, /**< Get size of key as bytes. */
};

#endif

/* grp_key.h ends here */
