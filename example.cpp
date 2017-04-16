#include <cstdio>
#include "sha256_literal.h"
#include "sha256.h"

int main(int argc, char** argv)
{
  if (argc < 2) {
    fprintf(stderr, "Usage: %s pwd\n", argv[0]);
    return 2;
  }
  
  static constexpr auto PasswordHash = "myverysecretpassword"_sha256;
  const char* pwd = argv[1];
  if (sha256::compute((const uint8_t*) pwd, strlen(pwd)) == PasswordHash) {
    puts("good password!");
    return 0;
  }

  puts("bad password!");
  return 1;
}
