// Copyright (c) 2024, The Monero Project
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

#include "framework.test.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "fhse.hpp"

namespace
{
  constexpr const char seed1[] = "dummy seed 1";
  constexpr const char seed1_z85[] = "87pkp/U37Q7[{/H0gtN8}nAnp:27mf&P8RCX1[9&";
  constexpr const std::uint8_t seed1_bin[] = {
    0x19, 0x28, 0x86, 0x51, 0xd8, 0xbc, 0xde, 0xbf, 0x18, 0xa1, 0xfa, 0xcb,
    0x00, 0x99, 0x31, 0x92, 0xf9, 0xc4, 0xfe, 0x5b, 0xc7, 0x34, 0xb7, 0x06,
    0xe1, 0xe4, 0x2e, 0x86, 0xb7, 0xa4, 0x74, 0x22
  };

  constexpr const char key1[] = "key 1 hmac secret";
  constexpr const char key2[] = "key 2 hmac secret";
  constexpr const char key3[] = "key 3 hmac secret";
  constexpr const char pass1[] = "pass 1";
  constexpr const char pass2[] = "pass 2";

  template<typename T, std::size_t N>
  fhse_cview_t to_view(const T (&data)[N]) noexcept
  {
    return fhse_cview_t{
      .data = reinterpret_cast<const std::uint8_t*>(data),
      .length = N
    };
  }
}

bool operator==(fhse_cview_t left, fhse_cview_t right) noexcept
{
  return left.length == right.length &&
    std::memcmp(left.data, right.data, left.length) == 0;
}

bool operator!=(fhse_cview_t left, fhse_cview_t right) noexcept
{
  return !(left == right);
}

FHSE_CASE("cpp interface")
{ 
  SETUP("create secret")
  {
    fhse::secret secret{};

    EXPECT(secret.get_ascii_secret() == nullptr);
    EXPECT(secret.get_secret() == fhse_cview_t{});
    EXPECT(secret.fido_userid() == fhse_cview_t{});
    EXPECT(secret.fido_salt() == fhse_cview_t{});
    EXPECT(secret.unlock(to_view(key1)) == fhse::status(fhse_bad_argument));
    {
      std::vector<std::uint8_t> empty;
      EXPECT(secret.store(empty) == fhse::status(fhse_bad_argument));
      EXPECT(empty.empty());
    }

    EXPECT(secret.create(to_view(pass1), to_view(seed1)) == fhse::status::success);
    EXPECT(secret.fido_userid().length == 64);
    EXPECT(secret.fido_salt().length == 32);

    EXPECT(secret.get_ascii_secret() != nullptr);
    EXPECT(secret.get_ascii_secret() == std::string{seed1_z85});
    EXPECT(secret.get_secret() == to_view(seed1_bin));

    const auto same_secrets = [&] (const fhse::secret& compare)
    {
      EXPECT(secret.get_ascii_secret() != nullptr);
      EXPECT(compare.get_ascii_secret() != nullptr);
      EXPECT(std::string{secret.get_ascii_secret()} == std::string{compare.get_ascii_secret()});
      EXPECT(secret.get_secret() == compare.get_secret());
    };

    const auto same_fido = [&](const fhse::secret& compare)
    {
      EXPECT(secret.fido_userid() == compare.fido_userid());
      EXPECT(secret.fido_salt() == compare.fido_salt());
    };

    const auto same_cbor = [&] (const fhse::secret& compare)
    {
      std::vector<std::uint8_t> cbor1;
      std::vector<std::uint8_t> cbor2;
      EXPECT(secret.store(cbor1) == fhse::status::success);
      EXPECT(compare.store(cbor2) == fhse::status::success);
      EXPECT(!cbor1.empty());
      EXPECT(cbor1.size() == cbor2.size());
    };

    SECTION("store no keys")
    {
      std::vector<std::uint8_t> empty;
      EXPECT(secret.store(empty) == fhse::status(fhse_bad_argument));
      EXPECT(empty.empty());
    }

    SECTION("add keys and open")
    {
      std::vector<std::uint8_t> cbor;
      EXPECT(secret.add_key(to_view(key1)) == fhse::status::success);
      EXPECT(secret.add_key(to_view(key1)) == fhse::status(fhse_duplicate_key));
      EXPECT(secret.unlock(to_view(key1)) == fhse::status(fhse_bad_argument));
      EXPECT(secret.store(cbor) == fhse::status::success);
      EXPECT(!cbor.empty());

      fhse::secret secret2{};
      EXPECT(secret2.open(fhse::to_cview(cbor), to_view(pass2)) == fhse::status(fhse_decryption_failure));
      EXPECT(secret2.open(fhse::to_cview(cbor), to_view(pass1)) == fhse::status::success);
      EXPECT(secret2.get_ascii_secret() == nullptr);
      EXPECT(secret2.get_secret() == fhse_cview_t{});
      EXPECT(secret2.fido_userid() == secret.fido_userid());
      EXPECT(secret2.fido_salt() == secret.fido_salt());

      EXPECT(secret2.unlock(to_view(key2)) == fhse::status(fhse_key_unavailable));
      EXPECT(secret2.unlock(to_view(key1)) == fhse::status::success);
      EXPECT(secret2.unlock(to_view(key1)) == fhse::status(fhse_bad_argument));
      same_secrets(secret2);
      same_fido(secret2);
      same_cbor(secret2);
    }

    SECTION("random seed")
    {
      fhse::secret secret2{};
      fhse::secret secret3{};
      EXPECT(secret2.create(to_view(pass2)) == fhse::status::success);
      EXPECT(secret3.create(to_view(pass2)) == fhse::status::success);

      EXPECT(secret2.get_secret().length == 32);
      EXPECT(secret3.get_secret().length == 32);

      EXPECT(secret.get_secret() != secret2.get_secret());
      EXPECT(secret.get_secret() != secret3.get_secret());
      EXPECT(secret2.get_secret() != secret3.get_secret());
    }

    SECTION("remove key")
    {
      std::vector<std::uint8_t> cbor1;
      std::vector<std::uint8_t> cbor2;
      EXPECT(secret.add_key(to_view(key2)) == fhse::status::success);
      EXPECT(secret.add_key(to_view(key3)) == fhse::status::success);
      EXPECT(secret.store(cbor1) == fhse::status::success);
      EXPECT(secret.remove_key(to_view(key2)) == fhse::status::success);
      EXPECT(secret.remove_key(to_view(key2)) == fhse::status(fhse_key_unavailable));
      EXPECT(secret.store(cbor2) == fhse::status::success);
      EXPECT(!cbor2.empty());
      EXPECT(cbor2.size() < cbor1.size());
      EXPECT(secret.remove_key(to_view(key3)) == fhse::status::success);
      EXPECT(secret.remove_key(to_view(key3)) == fhse::status(fhse_key_unavailable));
      EXPECT(secret.store(cbor1) == fhse::status(fhse_bad_argument));
    }

    SECTION("multiple keys")
    {
      EXPECT(secret.add_key(to_view(key1)) == fhse::status::success);
      EXPECT(secret.add_key(to_view(key2)) == fhse::status::success);
      EXPECT(secret.add_key(to_view(key3)) == fhse::status::success);

      std::vector<std::uint8_t> cbor;
      EXPECT(secret.store(cbor) == fhse::status::success);

      fhse::secret secret2{};
      EXPECT(secret2.open(fhse::to_cview(cbor), to_view(pass1)) == fhse::status::success);
      EXPECT(secret2.unlock(to_view(key2)) == fhse::status::success);
      same_secrets(secret2);
      same_fido(secret2);
      same_cbor(secret2);
    }

    SECTION("move")
    {
      std::vector<std::uint8_t> cbor;
      const fhse::secret secret2{std::move(secret)};
      EXPECT(secret.get_ascii_secret() == nullptr);
      EXPECT(secret.get_secret() == fhse_cview_t{});
      EXPECT(secret.fido_userid() == fhse_cview_t{});
      EXPECT(secret.fido_salt() == fhse_cview_t{});
      EXPECT(secret.open(to_view(pass1), to_view(seed1)) == fhse::status(fhse_bad_argument));
      EXPECT(secret.unlock(to_view(seed1_bin)) == fhse::status(fhse_bad_argument));
      EXPECT(secret.store(cbor) == fhse::status(fhse_bad_argument));
 
      EXPECT(secret2.fido_userid().length == 64);
      EXPECT(secret2.fido_salt().length == 32);

      EXPECT(secret2.get_ascii_secret() != nullptr);
      EXPECT(secret2.get_ascii_secret() == std::string{seed1_z85});
      EXPECT(secret2.get_secret() == to_view(seed1_bin));
    }
  } 
}
