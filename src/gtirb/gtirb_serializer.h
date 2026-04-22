#ifndef GTIRB_SERIALIZER_H
#define GTIRB_SERIALIZER_H

#include <string>
#include <gtirb/Module.hpp>

class Program;

/** Highest-level gtirb serialization.
 */
class GtirbSerializer {
public:
    /** Output 'program' to gtirb IR */
    void serialize(Program *program, std::string filename);
};

#endif
