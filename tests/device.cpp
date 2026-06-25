#include <cstdint>
#include <cstdio>
#include <cstring>
#ifdef USE_LIBFIDO2
 #include <fido.h>
#else
  constexpr const unsigned FIDO_OK = 0;
  struct fido_dev_info_t;
  fido_dev_info_t* fido_dev_info_new(std::size_t) { return nullptr; }
  void fido_dev_info_free(fido_dev_info_t**, std::size_t) {}
  int fido_dev_info_manifest(fido_dev_info_t*, std::size_t, std::size_t*) { return -1; }
  const char* fido_dev_info_path(fido_dev_info_t*) { return nullptr; }
  fido_dev_info_t* fido_dev_info_ptr(fido_dev_info_t*, std::size_t) { return nullptr; }
#endif
#include <iostream>
#include <memory>
#include "fhse.hpp"

#define FHSE_STATUS(...)             \
  do                                 \
  {                                  \
    if (rc == fhse::status::success) \
      rc = __VA_ARGS__;              \
  } while (0)

namespace
{
  constexpr const std::size_t device_count = 10;
  constexpr const char pass[] = "dummy bad pass";
}


struct free_info
{
  void operator()(fido_dev_info_t* ptr) const noexcept
  { fido_dev_info_free(&ptr, device_count); }
};

int main()
{
  const std::unique_ptr<fido_dev_info_t, free_info> info{
    fido_dev_info_new(device_count)
  };
  if (info)
  {
    std::size_t count = 0;
    if (fido_dev_info_manifest(info.get(), device_count, &count) == FIDO_OK)
    {
      if (count)
      {
        fhse::device device{fido_dev_info_path(fido_dev_info_ptr(info.get(), 0))};
        std::cout << "Press user presence twice" << std::endl;

        char pin_buffer[256] = {0};
        const char* pin = nullptr;
        fhse::secret secret{};
        fhse::status rc = secret.create(fhse::to_cview(std::string{pass}));

        do
        {
          if (rc == fhse::status(fhse_fido_needs_pin))
          {
            count = 0;
            std::cout << "Enter PIN: ";
            static_assert(1 <= sizeof(pin_buffer));
            if (std::fgets(pin_buffer, sizeof(pin_buffer) - 1, stdin))
              rc = fhse::status::success;
            else
              rc = fhse::status(fhse_bad_argument);
          }

          FHSE_STATUS(device.add_to(secret, pin));
        } while (rc == fhse::status(fhse_fido_needs_pin) && count);

        std::vector<std::uint8_t> metadata;
        FHSE_STATUS(secret.store(metadata));

        if (rc == fhse::status::success)
          std::cout << "Verifying secret, press user presence again" << std::endl;

        fhse::secret on_next_open{};
        FHSE_STATUS(on_next_open.open(fhse::to_cview(metadata), fhse::to_cview(std::string{pass})));
        FHSE_STATUS(device.unlock(on_next_open, pin));

        if (rc == fhse::status::success)
        {
          const char* const raw_secret1 = secret.get_ascii_secret();
          const char* const raw_secret2 = on_next_open.get_ascii_secret();
          if (raw_secret1 && raw_secret2 && std::strcmp(raw_secret1, raw_secret2) == 0)
          {
            std::cout << "SUCCESS!" << std::endl;
            return 0;
          }
          else
            std::cerr << "FATAL ERROR, RAW SECRETS DO NOT MATCH!" << std::endl;
        }
        else
          std::cerr << "FHSE error: " << get_string(rc) << std::endl;
      }
      else
        std::cerr << "No FIDO2 devices connected" << std::endl;
    }
    else
      std::cerr << "Failed to get device list" << std::endl;
  }
  else
    std::cerr << "Failed to allocate device info list" << std::endl;
  return -1;
}

