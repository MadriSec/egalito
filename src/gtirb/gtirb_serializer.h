#ifndef GTIRB_SERIALIZER_H
#define GTIRB_SERIALIZER_H

#include <string>

class Program;

/** Highest-level gtirb serialization.
 */
class GtirbSerializer {
public:
    /** Serialize the given program. */
    void serialize(Program *program, std::string filename);

private:
};

#endif
