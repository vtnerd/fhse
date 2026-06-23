// Copyright (c) 2026, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "private/cbor.h"

#include <cbor/encoding.h>
#include <cbor/ints.h>
#include <stdint.h>
#include <string.h>
#include "fhse/sbytes.h"
#include "private/config.h"
#include "private/utils.h"

int fhse_cbor_increase_capacity(fhse_cbor_t* self, size_t more, fhse_memory_t const* memory)
{
  if (!self)
    return fhse_bad_argument;
  if (SIZE_MAX - more < self->payload.length)
    return fhse_bad_alloc;
  if (self->payload.length < SIZE_MAX / 2 && more < self->payload.length)
    more = self->payload.length;

  size_t offset = self->write_ptr - self->payload.data;
  FHSE_TRY(fhse_sbytes_realloc(&self->payload, self->payload.length + more, memory));
  self->write_ptr = self->payload.data + offset;
  self->remaining += more;
  return fhse_success;
}

size_t fhse_cbor_increment(fhse_cbor_t* self, size_t more, fhse_memory_t const* memory)
{
  if (!self || SIZE_MAX - more < self->remaining)
    return 0;
  if (!more)
  {
    size_t next_length = self->payload.length ?
      self->payload.length : FHSE_CBOR_BUFFER_DEFAULT;
    fhse_cbor_increase_capacity(self, next_length, memory);
    return 0;
  }
  self->write_ptr += more;
  self->remaining -= more;
  return more;
}

int fhse_cbor_field(fhse_cbor_t* self, const char* name, fhse_memory_t const* memory)
{
  if (!self || !name)
    return fhse_bad_argument;

  int rc = fhse_success;
  size_t length = strlen(name);
  FHSE_CBOR_WRITE_(rc, self, memory, cbor_encode_string_start(length, self->write_ptr, self->remaining));
  if (rc != fhse_success)
    return rc;

  if (length && self->remaining < length && fhse_cbor_increase_capacity(self, length, memory) != fhse_success)
    return fhse_bad_alloc;

  memmove(self->write_ptr, name, length);
  fhse_cbor_increment(self, length, memory);
  return fhse_success;
}

int fhse_size_unpack(size_t* self, cbor_item_t* src, fhse_memory_t const* memory)
{
  if (!self || !src)
    return fhse_bad_argument;
  if (cbor_typeof(src) != CBOR_TYPE_UINT)
    return fhse_cbor_failure;

  uint64_t value = cbor_get_int(src);
  if (SIZE_MAX < value)
    return fhse_cbor_failure;

  *self = value;
  return fhse_success;
}

