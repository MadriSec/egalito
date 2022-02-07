
#ifndef GTIRB_DESERIALIZER_H
#define GTIRB_DESERIALIZER_H

#include <capstone/capstone.h>
#include <gtirb/gtirb.hpp>
#include <string>
#include <memory>

class DataRegionList;
class DisasmHandle;
class ElfMap;
class Function;
class InitFunctionList;
class PLTList;
class Program;
class SymbolList;

/** Highest-level gtirb deserialization for a given gtirb file.
*/
class GtirbDeserializer
{
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
    ElfMap *buildElfMap(const gtirb::Module &module);
    SymbolList *buildSymbolList(const gtirb::Module &module);
    Function *buildFunction(gtirb::UUID sym_uuid, const std::set<gtirb::UUID> &entries, const std::set<gtirb::UUID> &blocks);
    InitFunctionList *buildInitFunctionList();
    InitFunctionList *buildFiniFunctionList();
    DataRegionList *buildDataRegionList();
    PLTList *buildPLTList();
    bool isLoadableGtirbModule(const gtirb::Module &module);

    std::string filename;
    std::unique_ptr<gtirb::Context> C;
    gtirb::IR *ir;
    DisasmHandle *cs_handle;
};

#endif
