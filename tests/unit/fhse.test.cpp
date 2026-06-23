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
#include <string>
#include <vector>
#include "fhse.hpp"

namespace
{
  constexpr const char seed1[] = "dummy seed 1";
  constexpr const char seed1_z85[] = "p)Xw@y*<p-gp81(1zbd.W!?g.cA9zZqdI(uJ.vQ(";
  constexpr const std::uint8_t seed1_bin[] = {
    0x50, 0x97, 0xaf, 0xb9, 0x6c, 0x61, 0xa9, 0x1d, 0x32, 0xb3, 0x72, 0x9d,
    0x04, 0x65, 0xba, 0x1a, 0xb6, 0xfb, 0x20, 0x6b, 0x26, 0xa8, 0x9b, 0x7d,
    0x51, 0x64, 0x3e, 0xd4, 0x8e, 0x4b, 0xcc, 0xf9
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
