
#ifndef GTIRB_DESERIALIZER_H
#define GTIRB_DESERIALIZER_H

#include <capstone/capstone.h>
#include <gtirb/gtirb.hpp>
#include <string>
#include <memory>

// Forward declare all the egalito classes.
class Conductor;
class DataRegionList;
class DisasmHandle;
class ElfMap;
class Function;
class InitFunctionList;
class Library;
class LibraryList;
class Module;
class PLTList;
class Program;
class SymbolList;
class Symbol;

/** Highest-level gtirb deserialization for a given gtirb file.
 */
class GtirbDeserializer {
public:
    GtirbDeserializer(std::string filename);
    ~GtirbDeserializer();

    /** Preparse the file and determine if it's a valid gtirb file. */
    bool preParse();

    /** Returns the root of the deserialized tree. */
    Program *deserialize(Conductor *conductor);

    /** The filename this deserializer will process */
    std::string getFilename() { return this->filename; }

private:
    ElfMap *buildElfMap(const gtirb::Module &module);
    SymbolList *buildSymbolList(const gtirb::Module &module);
    Function *buildFunction(gtirb::UUID sym_uuid,
        const std::set<gtirb::UUID> &entries,
        const std::set<gtirb::UUID> &blocks);
    InitFunctionList *buildInitFunctionList();
    InitFunctionList *buildFiniFunctionList();
    void buildDataRegionList(ElfMap *elf_map, Module *module);
    void buildGlobalVariables(
        const gtirb::Module &gtirb_module, Module *eg_module);
    PLTList *buildPLTList();
    void buildCodeLinks();
    void buildLinkForSymAddrConst(
        Conductor *conductor, Module *module, gtirb::SymAddrConst sac);
    void buildDataLinks(Conductor *conductor, const gtirb::Module &gtirb_module,
        Module *eg_module);
    bool isLoadableGtirbModule(const gtirb::Module &module);
    void addLibDependences(
        const gtirb::Module &module, LibraryList *lib_list, Library *library);

    std::string filename;
    std::unique_ptr<gtirb::Context> C;
    gtirb::IR *ir;
    DisasmHandle *cs_handle;
    std::map<const gtirb::Symbol *, Symbol *> symbol_map;
};

#endif
