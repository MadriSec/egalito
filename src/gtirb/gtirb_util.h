#ifndef GTIRB_UTIL_H
#define GTIRB_UTIL_H

#include "gtirb/gtirb.hpp"

#include <map>

// AuxData schema that's not sanctioned yet
namespace gtirb {
namespace schema {

/**
 * @brief Auxiliary data for extra symbol info.
 */
struct ElfSymbolInfo {
    static constexpr const char* Name = "elfSymbolInfo";
    typedef std::map<gtirb::UUID,
        std::tuple<uint64_t, std::string, std::string, std::string, uint64_t>>
        Type;
};

/**
 * @brief Auxiliary data covering ELF section properties.
 * */
struct ElfSectionProperties {
    static constexpr const char* Name = "elfSectionProperties";
    typedef std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>> Type;
};

/**
 * @brief Auxiliary data listing library dependence.
 */
struct Libraries {
    static constexpr const char* Name = "libraries";
    typedef std::vector<std::string> Type;
};
}
}

/**
 * @brief Register AuxData used in the Egalito/GTIRB integration
 */
void register_gtirb_auxdata();

#endif  // GTIRB_UTIL_H
