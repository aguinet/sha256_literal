#ifndef SHA256_H
#define SHA256_H

#include <array>

namespace sha256 {

using HashType = std::array<uint8_t, 32>;
HashType compute(const uint8_t* Data, const uint64_t Len);

} // sha256
 
#endif
