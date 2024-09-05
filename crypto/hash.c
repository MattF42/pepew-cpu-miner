// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hash-ops.h"
#include "c_keccak.h"

void hash_permutation(union hash_state *state) {
#if defined(USE_ASM) && defined(x86_64)
  keccakf((uint64_t*)state, 24);
#endif
}

void hash_process(union hash_state *state, const uint8_t *buf, int count) {
#if defined(USE_ASM) && defined(x86_64)
  keccak1600(buf, count, (uint8_t*)state);
#endif
}

void cn_fast_hash(const void *data, int len, char *hash) {
  union hash_state state;
  hash_process(&state, data, len);
  memcpy(hash, &state, HASH_SIZE);
}
