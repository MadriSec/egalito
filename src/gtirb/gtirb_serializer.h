#ifndef GTIRB_SERIALIZER_H
#define GTIRB_SERIALIZER_H

#include <string>
#include <gtirb/Module.hpp>

#include "chunk/module.h"

class Program;

/** Highest-level gtirb serialization.
 */
class GtirbSerializer {
private:
    gtirb::Context C;

public:
    /** Output 'program' to gtirb IR */
    void serialize(Program *program, std::string filename);

};

#endif
