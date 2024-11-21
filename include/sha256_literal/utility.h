#pragma once

#include <sha256_literal/sha256_literal.h>
#include <array>
#include <iomanip>
#include <sstream>
#include <string>

namespace sha256_literal {
	std::string to_string(const HashType& hash)
	{
        std::ostringstream oss;
        oss << std::hex << std::setfill('0'); // Set to hex and fill with zeros

        for (const auto& byte : hash) {
            oss << std::setw(2) << static_cast<int>(byte); // Convert each byte to hex
        }

        return oss.str(); // Return the concatenated string
	}
}