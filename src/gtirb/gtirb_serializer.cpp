#include <iostream>
#include <fstream>

#include "gtirb_serializer.h"

#include "log/log.h"

#include "chunk/program.h"
#include "chunk/library.h"
#include "chunk/module.h"
#include "chunk/function.h"
#include "chunk/block.h"
#include "chunk/concrete.h"
#include "chunk/visitor.h"

#include "gtirb/IR.hpp"
#include "gtirb/Context.hpp"

#include "instr/writer.h"
#include "instr/semantic.h"
#include "instr/concrete.h"

#include "elf/symbol.h"
#include "elf/elfspace.h"
#include "elf/elfmap.h"

// For generating UUIDs for AuxData
#include <boost/uuid/uuid_generators.hpp>

// Leverage definitions for the sanctioned AuxData tables.
#include <gtirb/AuxDataSchema.hpp>
using ElfSymbolInfo =
    //         Size      Type         Binding      Visibility   Section index
    std::tuple<uint64_t, std::string, std::string, std::string, uint64_t>;

namespace gtirb {
namespace schema {
/// \brief Auxiliary data for extra symbol info.
struct ElfSymbolInfoAD {
    static constexpr const char *Name = "elfSymbolInfo";
    typedef std::map<gtirb::UUID, ElfSymbolInfo> Type;
};
}
}

/**
 * @brief Serialize chunk hierarchy to gtirb using visitor pattern
 */
class ChunkSerializer : public ChunkVisitor {
protected:
    gtirb::Context &C;
    /// \brief The IR into which the binary is serialized
    gtirb::IR &ir;
    // For debugging:
    // chunk hierarchy logged to this file
    std::ofstream *chunklog;
    // Used to format hierarchy in chunklog
    int chunk_depth = 0;

    // Used to generate unique identifiers for auxData
    boost::uuids::random_generator generate_uuid;

    /**
     * @brief Visit chunks stored in standard iterators
     */
    template <typename ChildT>
    void recurse(auto &parent) {
        chunk_depth += 1;
        for (ChildT child : parent) {
            child->accept(this);
        }
        chunk_depth -= 1;
    }

    /**
     * @brief Recursively visit chunks stored in egalito structures
     * Specifying child type explicitly not necessary,
     * only for readability.
     */
    template <typename ChildT = Chunk *, typename ParentT>
    void recurse(ParentT *parent) {
        chunk_depth += 1;
        for (ChildT child : CIter::children(parent)) {
            child->accept(this);
        }
        chunk_depth -= 1;
    }

    /**
     * @brief Log indented info to the chunklog
     */
    template <typename... Args>
    void log_chunk(Args &&... args) {
        if (!chunklog) {
            return;
        }
        *chunklog << std::string(chunk_depth * 2, ' ');
        (*chunklog << ... << args);
        *chunklog << "\n";
    }

public:
    /**
     * @brief Construct new object to serialize egalito to gtirb
     *
     * @param C The egalito context with which structures are created
     * @param ir The intermediate represntation into which the data is placed
     * @param chunklog If provided, log the chunk hierarchy to this file
     */
    ChunkSerializer(
        gtirb::Context &C, gtirb::IR &ir, std::ofstream *chunklog = nullptr)
        : C(C), ir(ir), chunklog(chunklog){};

    /**
     * There is no context when using the visitor pattern
     * so there isn't a good way of determining, e.g.,
     * which `Module` a `Function` is in.
     *
     * These two data structures store that contextual information
     * for egalito and gtirb as decending the chunk hierarchy.
     *
     * There's probably a better structure to keep track of this information
     * (an actual stack, maybe?).
     */
    struct EStack {
        Program *program = nullptr;
        Library *library = nullptr;
        Module *module = nullptr;
        Function *function = nullptr;
        DataSection *section = nullptr;
        DataRegion *region = nullptr;
    } eStack;

    struct GStack {
        gtirb::Module *module = nullptr;
        gtirb::ByteInterval *byteInterval = nullptr;
        gtirb::CodeBlock *codeBlock = nullptr;
        gtirb::Symbol *symbol = nullptr;
        gtirb::Section *section = nullptr;

        // Per-function AuxData
        std::set<gtirb::UUID> functionBlocks;
        std::set<gtirb::UUID> functionEntries;

        // Per-module AuxData
        std::map<gtirb::UUID, gtirb::UUID> moduleFunctionNames;
        std::map<gtirb::UUID, std::set<gtirb::UUID>> moduleFunctionBlocks;
        std::map<gtirb::UUID, std::set<gtirb::UUID>> moduleFunctionEntries;
        std::map<gtirb::UUID, ElfSymbolInfo> symbolInfo;

    } gStack;

    std::vector<
        std::tuple<gtirb::ByteInterval *, unsigned long, Link *, std::string>>
        links;
    std::unordered_map<DataSection *, gtirb::Section *> section_map;
    std::unordered_map<Chunk *, gtirb::Symbol *> symbol_map;

    virtual void visit(Program *program) {
        eStack.program = program;
        recurse<Library *>(program->getLibraryList());
        recurse<Module *>(program);
    }

    virtual void visit(Module *module) {
        log_chunk("- chunk: !module ", module->getName());
        auto *gModule = gtirb::Module::Create(C, module->getName());
        gModule->setFileFormat(gtirb::FileFormat::ELF);
#ifdef ARCH_X86_64
        // FIXME: Can egalito be compiled for multiple ISA?
        gModule->setISA(gtirb::ISA::X64);
#endif
        ir.addModule(gModule);

        // Set the context for this layer of the hierarchy
        gStack.module = gModule;
        gStack.moduleFunctionNames.clear();
        gStack.moduleFunctionBlocks.clear();
        gStack.moduleFunctionEntries.clear();

        eStack.module = module;

        if (module->getExternalSymbolList()) {
            recurse(module->getExternalSymbolList());
        }
        recurse(module->getDataRegionList());
        recurse(module->getFunctionList());
        recurse(module->getPLTList());
        recurse<JumpTable *>(module->getJumpTableList());

        gModule->addAuxData<gtirb::schema::FunctionNames>(
            std::move(gStack.moduleFunctionNames));

        gModule->addAuxData<gtirb::schema::FunctionEntries>(
            std::move(gStack.moduleFunctionEntries));

        gModule->addAuxData<gtirb::schema::FunctionBlocks>(
            std::move(gStack.moduleFunctionBlocks));

        gModule->addAuxData<gtirb::schema::ElfSymbolInfoAD>(
            std::move(gStack.symbolInfo));

        gStack.module = nullptr;
        eStack.module = nullptr;

        for (auto &[src, offset, link, name] : links) {
            auto targetAddr = link->getTargetAddress();
            gtirb::Addr gAddr(targetAddr);
            auto *target = link->getTarget();

            std::string targetName = "???";
            if (target) {
                targetName = target->getName();
            }
            LOG(0, "Destination for link found from "
                       << name << " " << std::hex
                       << (uint64_t)(*src->getAddress()) << " offset "
                       << std::dec << offset << " to " << std::hex << targetAddr
                       << " (" << targetName << ")");

            const auto gSymbol_it = gModule->findSymbols(targetName);

            if (gSymbol_it.begin() == gSymbol_it.end()) {
                LOG(0, "eSymbol not mapped");
                continue;
            }
            gtirb::Symbol &gSymbol = *gSymbol_it.begin();

            // FIXME IMMEDIATELY:
            // I have not yet found where in egalito to find the byte offset
            // into an instruction at which a 'link' takes place.
            // This buckshot approach adds a symbolic expression for all of the
            // first four bytes in the expression. It happens to work with
            // gtirb-pprinter for now, but is definitely bad.
            for (int i = 0; i < 4; i++) {
                src->addSymbolicExpression<gtirb::SymAddrConst>(
                    offset + i, 0, &gSymbol);
            }

            LOG(0, "Added symbolic expression from "
                       << name << " Offset " << std::dec << offset << " to "
                       << gSymbol.getName());
        }
    }

    virtual void visit(Library *library) {
        // FIXME: Not dealing with this at all yet
        if (library->getModule() == eStack.program->getMain()) {
            log_chunk("  main: True");
            return;
        };
        if (!library->getModule()) {
            log_chunk("  has module: False");
            // TODO: deal with libraries that are not parsed?
            return;
        }
        log_chunk("  has module: True");
        recurse(library->getModule());
    }

    virtual void visit(DataSection *dataSection) {
        log_chunk("- chunk: !section ", dataSection->getName());
        log_chunk("  Section addr: ", dataSection->getAddress());
        log_chunk("  Original offset: ", dataSection->getOriginalOffset());
        log_chunk("  Range: ", dataSection->getRange().getStart(), " - ",
            dataSection->getRange().getEnd());
        log_chunk("  Size: ", dataSection->getSize(), "/",
            dataSection->getRange().getSize());

        // DataSections contains an entry for every section in the file
        // I keep going back and forth on whether we should just use an elfMap
        // for that
        auto *section = gtirb::Section::Create(C, dataSection->getName());
        gStack.module->addSection(section);
        gStack.section = section;
        eStack.section = dataSection;
        section_map[dataSection] = section;

        auto addr = dataSection->getAddress();
        // TODO: I'm not sure if it makes sense to have this byte interval
        // It's only being used to store global variables
        // And will overlap with byteIntervals that functions are stored in.
        auto *interval = gtirb::ByteInterval::Create(
            C, gtirb::Addr(addr), dataSection->getSize());
        gStack.byteInterval = interval;
        recurse<DataVariable *>(dataSection);
        recurse<GlobalVariable *>(dataSection->getGlobalVariables());
        gStack.byteInterval = nullptr;
    }

    virtual void visit(DataVariable *dataVariable) {
        /*
         * From egalito docstring:
         *  'Represents a variable within a global data section that points at
         * another chunk'
         */

        log_chunk("- chunk: !dataVariable ", dataVariable->getName());
        log_chunk("  Variable addr: ", std::hex, dataVariable->getAddress());
        log_chunk("  size: ", dataVariable->getSize());

        uint64_t section_offset = dataVariable->getAddress() -
                                  eStack.section->getAddress();

        log_chunk("  Section offset: ", section_offset);
        uint64_t symbolSize = 0;

        // Store the link so we can make a symbolicReference here later
        if (Link *dest = dataVariable->getDest()) {
            // TODO: I'm not really sure if this use of byteInterval makes sense
            links.push_back(std::make_tuple(gStack.byteInterval, section_offset,
                dest, dataVariable->getName()));
            if (!dest->getTarget()) {
                log_chunk("  Dest name: UNKNOWN");
            }
            else {
                symbolSize = dest->getTarget()->getSize();
                log_chunk("  Dest name: ", dest->getTarget()->getName());
            }
        }

        auto gSymbol = gtirb::Symbol::Create(C,
            gtirb::Addr(dataVariable->getAddress()), dataVariable->getName());
        gStack.module->addSymbol(gSymbol);

        Symbol *target = dataVariable->getTargetSymbol();
        if (!target) {
            log_chunk("  No target: ");
            return;
        }
        log_chunk("  Target name: ", target->getName());
        log_chunk("  Target addr: ", target->getAddress());
        log_chunk("  Target type: ", target->getType());
        log_chunk("  Section Index: ", target->getSectionIndex());
        Symbol *alias = target->getAliasFor();
        if (alias) {
            log_chunk("  Alias for: ", alias->getName());
            log_chunk("  Alias addr: ", alias->getAddress());
        }
        log_chunk("  Aliases: ");
        for (Symbol *aliasTo : target->getAliases()) {
            log_chunk("  - ", aliasTo->getName());
        }

        std::string symType;
        switch (target->getType()) {
            case Symbol::TYPE_NOTYPE:
                symType = "NONE";
                break;
            case Symbol::TYPE_IFUNC:
                log_chunk("  Is ifunc: True");
            case Symbol::TYPE_FUNC:
                symType = "FUNC";
                break;
            case Symbol::TYPE_OBJECT:
                symType = "OBJECT";
                break;
            case Symbol::TYPE_SECTION:
                symType = "SECTION";
                break;
            case Symbol::TYPE_FILE:
                symType = "FILE";
                break;
            case Symbol::TYPE_TLS:
                symType = "TLS";
                break;
            case Symbol::TYPE_UNKNOWN:
                symType = "UNKNOWN";
                break;
            default:
                symType = "INVALID";
                break;
        }
        log_chunk("  type: ", symType);
        std::string binding = "";
        switch (target->getBind()) {
            case Symbol::BIND_LOCAL:
                binding = "LOCAL";
                break;
            case Symbol::BIND_GLOBAL:
                binding = "GLOBAL";
                break;
            case Symbol::BIND_WEAK:
                binding = "WEAK";
                break;
        }
        log_chunk("  binding: ", binding);
        ElfSymbolInfo Info{
            symbolSize, symType, binding, "DEFAULT", target->getSectionIndex()};
        gStack.symbolInfo[gSymbol->getUUID()] = Info;
    }

    virtual void visit(GlobalVariable *globalVariable) {
        /**
         * "Represents a variable that has a symbol of some sort that needs to
         * be preserved"
         */
        // TODO: Most of this is copied verbatim from dataVariable
        // They could probably be combined

        log_chunk("- chunk: !global ", globalVariable->getName());
        log_chunk("  Addr: ", globalVariable->getAddress());
        log_chunk("  size: ", globalVariable->getSize());

        if (globalVariable->getSize()) {
            // This part is different from dataVariable,
            // in that it stores the actual bytes
            auto addr = globalVariable->getAddress();
            auto *interval = gtirb::ByteInterval::Create(
                C, gtirb::Addr(addr), globalVariable->getSize());

            auto intervalBegin = std::as_const(*interval).bytes_begin<char>();

            const std::string &region_bytes = eStack.region->getDataBytes();
            uint64_t section_offset = globalVariable->getAddress() -
                                      eStack.section->getAddress();

            log_chunk("  Section offset: ", section_offset);
            const char *var_start = region_bytes.c_str() +
                                    eStack.section->getOriginalOffset() +
                                    section_offset;
            const char *var_end = var_start + globalVariable->getSize();
            interval->insertBytes(intervalBegin, var_start, var_end);
            auto *dataBlock = gtirb::DataBlock::Create(
                C, globalVariable->getSize());
            uint64_t offset = globalVariable->getAddress() -
                              eStack.region->getAddress();
            interval->addBlock(offset, dataBlock);
            gStack.section->addByteInterval(interval);
        }
        Symbol *target = globalVariable->getSymbol();
        auto gSymbol = gtirb::Symbol::Create(C,
            gtirb::Addr(globalVariable->getAddress()),
            globalVariable->getName());
        gStack.module->addSymbol(gSymbol);

        if (!target) {
            log_chunk(0, "      Symbol: NONE");
            return;
        }
        log_chunk("  Target name: ", target->getName());
        log_chunk("  Target addr: ", target->getAddress());

        std::string symType;
        switch (target->getType()) {
            case Symbol::TYPE_NOTYPE:
                symType = "NONE";
                break;
            case Symbol::TYPE_IFUNC:
                log_chunk("  Is ifunc: True");
            case Symbol::TYPE_FUNC:
                symType = "FUNC";
                break;
            case Symbol::TYPE_OBJECT:
                symType = "OBJECT";
                break;
            case Symbol::TYPE_SECTION:
                symType = "SECTION";
                break;
            case Symbol::TYPE_FILE:
                symType = "FILE";
                break;
            case Symbol::TYPE_TLS:
                symType = "TLS";
                break;
            case Symbol::TYPE_UNKNOWN:
                symType = "UNKNOWN";
                break;
            default:
                symType = "INVALID";
                break;
        }
        log_chunk("  type: ", symType);
        std::string binding = "";
        switch (target->getBind()) {
            case Symbol::BIND_LOCAL:
                binding = "LOCAL";
                break;
            case Symbol::BIND_GLOBAL:
                binding = "GLOBAL";
                break;
            case Symbol::BIND_WEAK:
                binding = "WEAK";
                break;
        }
        log_chunk("  binding: ", binding);
        ElfSymbolInfo Info{globalVariable->getSize(), symType, binding,
            "DEFAULT", target->getSectionIndex()};
        gStack.symbolInfo[gSymbol->getUUID()] = Info;
    }

    DataSection *getEgalitoSection(Function *function) {
        assert(eStack.module != nullptr);
        auto eSymbol = function->getSymbol();
        // It is strange to me that I have to go through these lengths
        // to get the section in which a function is defined.
        // I _could_ assume that it's .text
        // I probably should find it via the address.
        auto elfMap = eStack.module->getElfSpace()->getElfMap();
        auto elfSection = elfMap->findSection(eSymbol->getSectionIndex());
        return eStack.module->getDataRegionList()->findDataSection(
            elfSection->getName());
    }

    virtual void visit(Function *function) {
        log_chunk("- chunk: !function ", function->getName());
        log_chunk("  Addr: ", function->getAddress());
        log_chunk("  Position: ", function->getPosition()->get());

        auto eSymbol = function->getSymbol();
        if (eSymbol == nullptr) {
            log_chunk("  No symbol: !!!");
        }
        log_chunk("  Symbol addr: ", eSymbol->getAddress());

        auto eSection = getEgalitoSection(function);
        auto gSection = section_map[eSection];

        auto addr = function->getAddress();

        // Add a byteInterval for the whole function
        // (codeBlocks are a smaller scale)
        auto *interval = gtirb::ByteInterval::Create(
            C, gtirb::Addr(addr), function->getSize());
        gSection->addByteInterval(interval);

        gStack.byteInterval = interval;
        gStack.functionBlocks.clear();
        gStack.functionEntries.clear();
        eStack.function = function;
        recurse<Block *>(function);
        gStack.byteInterval = nullptr;
        eStack.function = nullptr;

        auto gSymbol = gtirb::Symbol::Create(
            C, gtirb::Addr(addr), eSymbol->getName());
        symbol_map[function] = gSymbol;
        gStack.module->addSymbol(gSymbol);

        gtirb::UUID funcId = generate_uuid();
        gStack.moduleFunctionNames[funcId] = gSymbol->getUUID();
        gStack.moduleFunctionBlocks[funcId] = std::move(gStack.functionBlocks);
        gStack.moduleFunctionEntries[funcId] = std::move(
            gStack.functionEntries);

        // TODO: Same method of gathering symobl info as dataVariable
        std::string binding = "";
        switch (eSymbol->getBind()) {
            case Symbol::BIND_LOCAL:
                binding = "LOCAL";
                break;
            case Symbol::BIND_GLOBAL:
                binding = "GLOBAL";
                break;
            case Symbol::BIND_WEAK:
                binding = "WEAK";
                break;
        }
        ElfSymbolInfo Info = {function->getSize(), "FUNC", binding, "DEFAULT",
            eSymbol->getSectionIndex()};
        gStack.symbolInfo[gSymbol->getUUID()] = Info;
    }

    virtual void visit(Block *block) {
        log_chunk("- Block addr/pos: ", block->getAddress(), "/",
            block->getPosition()->get());
        auto funcAddr = eStack.function->getPosition()->get();
        auto blockOffset = block->getPosition()->get() - funcAddr;

        auto *codeBlock = gtirb::CodeBlock::Create(C, block->getSize());
        gStack.functionBlocks.insert(codeBlock->getUUID());
        // The first codeBlock in a function is the function Entry
        if (gStack.functionEntries.size() == 0) {
            gStack.functionEntries.insert(codeBlock->getUUID());
        }
        gStack.byteInterval->addBlock(blockOffset, codeBlock);

        gStack.codeBlock = codeBlock;
        recurse<Instruction *>(block);
        gStack.codeBlock = nullptr;
    }

    virtual void visit(Instruction *instruction) {
        auto funcAddr = eStack.function->getPosition()->get();
        auto instrOffset = instruction->getPosition()->get() - funcAddr;

        auto intervalBegin = std::as_const(*gStack.byteInterval)
                                 .bytes_begin<char>();
        auto instrPos = intervalBegin + instrOffset;

        // Get the string of bytes in the function here
        auto semantic = instruction->getSemantic();
        std::string data;
        InstrWriterCppString writer(data);
        semantic->accept(&writer);

        gStack.byteInterval->insertBytes(instrPos, data.begin(), data.end());

        auto link = semantic->getLink();
        if (link) {
            if (link->getTarget()) {
                std::string target = link->getTarget()->getName();
                log_chunk("- Link: ", target);
                log_chunk(
                    "  Target Addr: 0x", std::hex, link->getTargetAddress());
                log_chunk("  Target.addr: 0x", std::hex,
                    link->getTarget()->getAddress());
                log_chunk("  Scope: ", link->getScope());
                links.push_back(std::make_tuple(gStack.byteInterval,
                    instrOffset, link, eStack.function->getName()));
            }
        }
    }

    virtual void visit(ExternalSymbol *externalSymbol) {
        // TODO: Have not dealt with this at all yet
        log_chunk("- chunk: !externalSymbol ", externalSymbol->getName());
    }
    virtual void visit(InitFunction *initFunction) {
        // TODO: Entirely unsure if/how to deal with this
    }

    /** Chunks which are simply recursed into */
    virtual void visit(FunctionList *functionList) { recurse(functionList); }
    virtual void visit(PLTList *pltList) { recurse(pltList); }
    virtual void visit(JumpTableList *jumpTableList) {
        log_chunk("- chunk: !jumpTableList ", jumpTableList->getName());
        recurse(jumpTableList);
    }

    virtual void visit(DataRegionList *dataRegionList) {
        recurse(dataRegionList);
    };
    virtual void visit(VTableList *vtableList) { recurse(vtableList); }
    virtual void visit(ExternalSymbolList *externalSymbolList) {
        recurse(externalSymbolList);
    }
    virtual void visit(InitFunctionList *initFunctionList) {
        recurse(initFunctionList);
    }
    virtual void visit(LibraryList *libraryList) { recurse(libraryList); }
    virtual void visit(JumpTable *jumpTable) {
        log_chunk("- chunk: !jumpTable ", jumpTable->getName());
        recurse(jumpTable);
    }
    virtual void visit(DataRegion *dataRegion) {
        eStack.region = dataRegion;
        log_chunk("- chunk: !region ", dataRegion->getName());
        log_chunk("  Addr: ", dataRegion->getAddress());
        log_chunk("  Range: ", dataRegion->getRange().getStart(), " - ",
            dataRegion->getRange().getEnd());
        // log_stackdepth += 1;
        recurse(dataRegion);
        // log_stackdepth -= 1;
    }

    /** Chunks which are currently ignored altogether */
    virtual void visit(PLTTrampoline *trampoline) {
        std::string name = trampoline->getName();
        log_chunk("- chunk: !trampoline ", name);
        // auto *blah = trampoline->getGotPLTEntry();
        // TODO
    }
    virtual void visit(JumpTableEntry *jumpTableEntry) {
        log_chunk("- chunk: !jtentry ", jumpTableEntry->getName());
    }
    virtual void visit(MarkerList *markerList) {}
    virtual void visit(VTable *vtable) {}
    virtual void visit(VTableEntry *vtableEntry) {}
};

class GtirbConverter {
private:
    gtirb::Context C;
    std::map<gtirb::UUID, std::string> typesTable;

public:
    void add_types(gtirb::Module *gModule) {}

    gtirb::IR *convert(Program *program, std::ofstream *chunklog) {
        auto ir = gtirb::IR::Create(C);
        ChunkSerializer(C, *ir, chunklog).visit(program);
        return ir;
    }
};

void GtirbSerializer::serialize(Program *program, std::string filename) {
    gtirb::AuxDataContainer::registerAuxDataType<
        gtirb::schema::FunctionEntries>();
    gtirb::AuxDataContainer::registerAuxDataType<
        gtirb::schema::FunctionBlocks>();
    gtirb::AuxDataContainer::registerAuxDataType<
        gtirb::schema::FunctionNames>();
    gtirb::AuxDataContainer::registerAuxDataType<
        gtirb::schema::ElfSymbolInfoAD>();
    LOG(1, "GTIRB serialization");

    std::ofstream chunklog;
    chunklog.open(filename + "-chunklog.yaml");

    gtirb::Context C;
    auto ir = gtirb::IR::Create(C);
    ChunkSerializer(C, *ir, &chunklog).visit(program);
    chunklog.close();

    std::ofstream file;
    file.open(filename + ".gtirb");
    ir->save(file);
    file.close();
    std::ofstream file2;
    file2.open(filename + ".json");
    ir->saveJSON(file2);
    file2.close();
}
