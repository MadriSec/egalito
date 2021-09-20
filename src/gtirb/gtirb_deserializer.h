
#ifndef GTIRB_DESERIALIZER_H
#define GTIRB_DESERIALIZER_H

#include <string>
#include <memory>

class Program;
namespace gtirb {
    class Context;
    class IR;
}

/** Highest-level gtirb deserialization for a given gtirb file.
*/
class GtirbDeserializer {
public:
    GtirbDeserializer(std::string filename);
    ~GtirbDeserializer();

    /** Preparse the file and determine if it's a valid gtirb file. */
    bool preParse();

    /** Returns the root of the deserialized tree. */
    Program *deserialize();

    /** The filename this deserializer will process */
    std::string getFilename() { return this->filename; }

private:
    std::string filename;
    std::unique_ptr<gtirb::Context> C;
    gtirb::IR *ir;
};

#endif

