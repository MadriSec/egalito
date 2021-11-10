#include <iostream>
#include <fstream>

#include "gtirb_serializer.h"

#include "log/log.h"
#include "chunk/program.h"
#include "chunk/module.h"
#include "chunk/visitor.h"
#include "elf/elfspace.h"
#include "chunk/visitor.h"
#include "instr/instr.h"
#include "instr/semantic.h"
#include "instr/writer.h"
#include "instr/concrete.h"

#include "gtirb/IR.hpp"
#include "gtirb/Symbol.hpp"
#include "gtirb/proto/IR.pb.h"
#include "gtirb/Context.hpp"
#include "gtirb/ByteInterval.hpp"
#include "gtirb/SymbolicExpression.hpp"

// Leverage definitions for the sanctioned AuxData tables.
#include <gtirb/AuxDataSchema.hpp>

#include <boost/uuid/uuid_generators.hpp>

using ElfSymbolInfo =
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

template <typename... Args>
std::tuple<Args...> tuple_slice(const std::tuple<int, float, bool> &t) {
    return std::make_tuple(std::get<Args>(t)...);
}

/**
 * Provide a mapping between gtirb and egalito types
 * (and optionally some auxiliary data)
 *
 * TODO: I think this can be maybe simplified to just the
 * forward- and backward- map and drop the aux-data
 * (which is definitely more complicated)
 */
template <typename EType, typename GType, typename... Aux>
struct TypeMap {
    static_assert(std::is_pointer_v<GType>);
    static_assert(std::is_pointer_v<EType>);

    using TupleType = std::tuple<EType, GType, Aux...>;
    std::unordered_map<EType, TupleType> from_egalito;
    std::unordered_map<GType, TupleType> from_gtirb;

    // This makes copies of items every time.
    // Maybe a more efficient way?
    // Mapping etype and gtype to indexes in a vector might be better?
    template <typename... Types>
    std::vector<std::tuple<Types...>> values() {
        std::vector<std::tuple<Types...>> output;
        for (const auto &it : from_egalito) {
            output.emplace_back((std::get<Types>(it.second))...);
        }
        return output;
    }

    std::vector<TupleType> values() {
        std::vector<TupleType> output;
        for (const auto &it : from_egalito) {
            output.push_back(it.second);
        }
        return output;
    }

    // /** Map from egalito type to gtirb type */
    // std::unordered_map<EType, GType> gtirb;
    // /** Map from gtirb type to egalito type */
    // std::unordered_map<GType, EType> egalito;
    // /** Map from gtirb type to additional auxiliary data */
    // std::unordered_map<GType, std::tuple<Aux...>> aux;
    bool contains(EType obj) {
        return from_egalito.find(obj) != from_egalito.end();
        // return from_egalito.find(eobj) != from_egalito.end();
    }
    bool contains(GType obj) {
        return from_gtirb.find(obj) != from_gtirb.end();
        // return from_egalito.find(eobj) != from_egalito.end();
    }

    /** Add a mapping between egalito types and gtirb types */
    void add(EType eobj, GType gobj, Aux... auxobjs) {
        auto info = std::make_tuple(eobj, gobj, auxobjs...);
        assert(contains(eobj) == contains(gobj));
        from_egalito[eobj] = info;
        from_gtirb[gobj] = info;
    }

    template <typename RType>
    RType get(EType eobj) {
        return std::get<RType>(from_egalito[eobj]);
    }

    template <typename RType>
    RType get(GType gobj) {
        return std::get<RType>(from_gtirb[gobj]);
    }

    template <typename T>
    T get_chunk(Chunk *chunk) {
        static_assert(std::is_convertible_v<EType, Chunk *>);
        static_assert(std::is_pointer_v<T>);
        if (EType eobj = dynamic_cast<EType>(chunk)) {
            return get<T>(eobj);
        }
        return nullptr;
    }

    // /**
    //  * Get the auxiliary data associated with a gtirb object
    //  * If T is provided it follows the rules for getting from a tuple
    //  * i.e.
    //  *     get_aux<gtirb::CodeBlock*>(gtirb_obj)
    //  * or
    //  *     get_aux<2>(gtirb_obj)
    //  * Otherwise, it gets the first provided aux data element
    //  *
    //  * TODO: Maybe remove this altogether. I'm not sure it's actually
    //  necessary.
    //  */
    // template <int T = 0>
    // auto get_aux(GType gobj) {
    //     return std::get<T>(aux[gobj]);
    // }
    // template <typename T>
    // auto get_aux(GType gobj) {
    //     return std::get<T>(aux[gobj]);
    // }
};

Module *chunk_module(Chunk *chunk) {
    if (Module *m = dynamic_cast<Module *>(chunk)) {
        return m;
    }
    else if (Chunk *parent = chunk->getParent()) {
        return chunk_module(parent);
    }
    else {
        return nullptr;
    }
}

struct LinkInfo {
    Link *link;
    Module *src_module;
    address_t offset;

    gtirb::CodeBlock *src_block;
    gtirb::ByteInterval *interval;

    // LinkInfo(Link *link, gtirb::CodeBlock *src_block, address_t offset)
    //     : link(link), src_block(src_block), offset(offset) {}
};

/**
 * Holds all of the mapping relationships between egalito objects
 * and their corresponding gtirb objects
 */
struct TypeMapper {
    using FunctionId = gtirb::UUID;

    /**
     * TODO: Remove a lot of this complexity...
     * Swap the priority of linking and flat generation - 
     * everything within a generation pass that can be constructed
     * should be constructed.
     * The TypeMap might still be somewhat necessary,
     * but not to the same extent.
     */
    std::vector<LinkInfo> link_info;

    TypeMap<Module *, gtirb::Module *> modules;
    TypeMap<Library *, gtirb::Module *> libraries;
    TypeMap<DataSection *, gtirb::Section *> sections;
    TypeMap<InitFunction *, gtirb::CodeBlock *> entryPoints;

    TypeMap<Function *, gtirb::Symbol *, gtirb::ByteInterval *,
        std::set<gtirb::CodeBlock *>, FunctionId>
        functions;
    TypeMap<DataVariable *, gtirb::Symbol *, gtirb::ByteInterval *,
        gtirb::DataBlock *>
        dataVariables;
    TypeMap<GlobalVariable *, gtirb::Symbol *, gtirb::ByteInterval *,
        gtirb::DataBlock *>
        globalVariables;
    TypeMap<ExternalSymbol *, gtirb::Symbol *, gtirb::ProxyBlock *>
        externalSymbols;
    TypeMap<PLTTrampoline *, gtirb::ProxyBlock *> pltEntries;

    gtirb::Symbol *getSymbol(Chunk *chunk) {
        gtirb::Symbol *sym;
        if ((sym = dataVariables.get_chunk<gtirb::Symbol *>(chunk))) {
            return sym;
        }
        else if ((sym = globalVariables.get_chunk<gtirb::Symbol *>(chunk))) {
            return sym;
        }
        else if ((sym = externalSymbols.get_chunk<gtirb::Symbol *>(chunk))) {
            return sym;
        }
        else if ((sym = functions.get_chunk<gtirb::Symbol *>(chunk))) {
            return sym;
        }
        else {
            return nullptr;
        }
    }
};

struct InstrLinker : public InstrWriterCppString {
    Link *link = nullptr;
    using InstrWriterCppString::InstrWriterCppString;

    virtual void visit(LinkedInstruction *linked) {
        link = linked->getLink();
        InstrWriterCppString::visit(linked);
    }
};

/**
 * Serialization is done in two steps:
 * First, this class runs through the chunk hierarchy and constructs the
 * necessary objects and their mapping Then, linking is done between the created
 * objects to establish the new hierarchy
 */
class FlatPass : public ChunkVisitor {
protected:
    gtirb::Context &C;
    /**
     * FIXME: This does not function properly if multiple elfMaps are
     * present due to deep-scanning a binary.
     * Having module selection within the type-mapper might be the way to go
     */
    TypeMapper &TM;

    boost::uuids::random_generator Generator;

    /**
     * TODO: set a private variable that holds the parent stack.
     * I was trying to avoid this at first but it wasn't fruitful,
     * and added extra complexity.
     * ElfMap is already doing this anyway.
     */
    ElfMap *elfMap;

    Chunk *parent;
    template <typename Type>
    auto recurse(Type *root) {
        parent = root;
        for (auto child : root->getChildren()->genericIterable()) {
            /* TODO: setParent wasn't super effective */
            child->setParent(root);
            child->accept(this);
        }
    }

    /**
     * TODO: Maybe something like this to automatically get created children while
     * avoiding generic casting.
     * However, I don't love it. I want to be able to get children from parents
     * or vice versa very easily. Not sure how
     */
    // template <typename ParentT, typename ChildT>
    // void recurse(ChildListDecorator<ParentT, ChildT> *root, const std::function<void (ChildT)>& callback) {
    //     for (auto child : root->getChildren()->genericIterable()) {
    //         child->setParent(root);
    //         child->accept(this);
    //     }
    // }

public:
    FlatPass(gtirb::Context &C, TypeMapper &TM) : C(C), TM(TM){};

    virtual void visit(Module *module) {
        auto *gmodule = gtirb::Module::Create(C, module->getName());
        gmodule->setFileFormat(gtirb::FileFormat::ELF);
#ifdef ARCH_X86_64
        // FIXME: Can egalito be compiled for multiple ISA?
        gmodule->setISA(gtirb::ISA::X64);
#endif

        TM.modules.add(module, gmodule);
        elfMap = module->getElfSpace()->getElfMap();
        recurse(module);
    }

    virtual void visit(Function *function) {
        auto addr = function->getAddress();

        auto *interval = gtirb::ByteInterval::Create(
            C, gtirb::Addr(addr), function->getSize());
        auto intervalBegin = std::as_const(*interval).bytes_begin<char>();

        // Maybe codeBlocks should line up with the "block" in the function as
        // well
        std::set<gtirb::CodeBlock *> codeBlocks;

        auto start = function->getPosition()->get();
        for (auto block : CIter::children(function)) {
            auto *codeBlock = gtirb::CodeBlock::Create(C, block->getSize());
            auto blockOffset = block->getPosition()->get() - start;
            interval->addBlock(blockOffset, codeBlock);
            for (auto instruction : CIter::children(block)) {
                auto instrOffset = instruction->getPosition()->get() - start;
                auto semantic = instruction->getSemantic();
                std::string data;
                InstrLinker linker(data);
                semantic->accept(&linker);
                interval->insertBytes(
                    intervalBegin + instrOffset, data.begin(), data.end());
                if (linker.link) {
                    TM.link_info.emplace_back(
                        LinkInfo{linker.link, chunk_module(function), instrOffset, codeBlock, interval});
                }

                // auto link = semantic->getLink();
                // link->getTargetAddress();
            }
        }

        auto symbol = function->getSymbol();
        addr = symbol->getAddress();

        auto gSymbol = gtirb::Symbol::Create(
            C, gtirb::Addr(addr), symbol->getName());

        TM.functions.add(function, gSymbol, interval, codeBlocks, Generator());
        recurse(function);
    }

    virtual void visit(DataSection *dataSection) {
        // DataSections seems to include all of the code sections as well
        auto *section = gtirb::Section::Create(C, dataSection->getName());
        TM.sections.add(dataSection, section);
        recurse(dataSection);
    }

    virtual void visit(DataVariable *variable) {
        LOG(0, "DATA VARIABLE IS " << variable->getName());
        // FIXME: I don't understand the difference between this and
        // GlobalVariable
        auto baseAddr = elfMap->getBaseAddress();
        if (!variable->getDest()) {
            return;
        }
        if (!variable->getDest()->isWithinModule()) {
            return;
        }
        if (!variable->getTargetSymbol()) {
            return;
        }
        auto addr = variable->getDest()->getTargetAddress();
        auto dataBlock = gtirb::DataBlock::Create(C, variable->getSize());
        auto pos = elfMap->getCharmap() + addr;
        auto symbol = gtirb::Symbol::Create(C, dataBlock, variable->getName());
        auto *byteInterval = gtirb::ByteInterval::Create(
            C, gtirb::Addr(addr), variable->getSize());
        TM.dataVariables.add(variable, symbol, byteInterval, dataBlock);
        // auto intervalBegin = std::as_const(*byteInterval).bytes_begin<char>();
        // byteInterval->insertBytes(
        //     intervalBegin, pos, pos + variable->getSize());
    }

    virtual void visit(GlobalVariable *variable) {
        LOG(0, "GLOBAL VARIABLE IS " << variable->getName());
        auto addr = variable->getAddress();
        auto dataBlock = gtirb::DataBlock::Create(C, variable->getSize());
        auto symbol = gtirb::Symbol::Create(C, dataBlock, variable->getName());
        auto *byteInterval = gtirb::ByteInterval::Create(
            C, gtirb::Addr(addr), variable->getSize());
        TM.globalVariables.add(variable, symbol, byteInterval, dataBlock);
    }

    virtual void visit(Library *library) {
        // The simplicity of the other mappings is lost a little here,
        // because I am less sure that this cannot be cyclical
        if (!library->getModule()) {
            return;
        }
        recurse(library->getModule());
        // Also, both libraries and Modules map onto gtirb::Module's
        auto gModule = TM.modules.get<gtirb::Module *>(library->getModule());
        // auto gModule = TM.modules.gtirb[library->getModule()];
        TM.libraries.add(library, gModule);
    }
    virtual void visit(ExternalSymbol *externalSymbol) {
        // TODO:
        if (TM.externalSymbols.contains(externalSymbol)) {
            return;
        }
        auto symbolName = externalSymbol->getName();
        auto proxyBlock = gtirb::ProxyBlock::Create(C);
        auto gSymbol = gtirb::Symbol::Create(C, proxyBlock, symbolName);
        TM.externalSymbols.add(externalSymbol, gSymbol, proxyBlock);
        // auto symbolName = externalSymbol->getName();
        // if (externalSymbols.find(symbolName) != std::end(externalSymbols)) {
        //     return;
        // }
    }
    virtual void visit(InitFunction *initFunction) {
        //     auto function = initFunction->getFunction();
        //     auto mapItem = TM.functions.gtirb.find(function);
        //     if (mapItem == TM.functions.gtirb.end()) {
        //         recurse(function);
        //         mapItem = TM.functions.gtirb.find(function);
        //     }
        //     auto gSymbol = TM.functions.gtirb[function];
        //     auto codeBlock = TM.functions.get_aux<gtirb::CodeBlock
        //     *>(gSymbol); TM.entryPoints.add(initFunction, codeBlock);
    }

    /** Chunks which are simply recursed into */
    virtual void visit(Program *program) {
        recurse(program);
        // visit(program->getMain());
        // visit(program->getLibc());
    }
    virtual void visit(FunctionList *functionList) { recurse(functionList); }
    virtual void visit(PLTList *pltList) { recurse(pltList); }
    virtual void visit(JumpTableList *jumpTableList) { recurse(jumpTableList); }
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
    virtual void visit(JumpTable *jumpTable) { recurse(jumpTable); }
    virtual void visit(DataRegion *dataRegion) { recurse(dataRegion); }
    virtual void visit(Block *block) { recurse(block); }

    /** Chunks which are currently ignored altogether */
    virtual void visit(PLTTrampoline *trampoline) {
        /**
         * TODO: This is the core thing that is still not working
         * I need to look into the implmentations for PLTs in both gtirb and egalito
         */
        LOG(0, "I AM TRAMPOLINE");
        auto eSymbol = trampoline->getExternalSymbol();
        if (TM.externalSymbols.contains(eSymbol)) {
            auto proxyBlock = TM.externalSymbols.get<gtirb::ProxyBlock *>(eSymbol);
            assert(proxyBlock != nullptr);
            TM.pltEntries.add(trampoline, proxyBlock);
        }
    }
    virtual void visit(JumpTableEntry *jumpTableEntry) {}
    virtual void visit(MarkerList *markerList) {}
    virtual void visit(VTable *vtable) {}
    virtual void visit(VTableEntry *vtableEntry) {}
    // Note: Instruction is not totally ignored, but is instead recursed through
    // manually by Function
    virtual void visit(Instruction *instruction) {}
};

class GtirbConverter {
private:
    gtirb::Context C;
    TypeMapper TM;
    std::map<gtirb::UUID, std::string> typesTable;

public:
    void link_sections(gtirb::Module *gModule, Module *eModule) {
        for (auto dataRegion : CIter::children(eModule->getDataRegionList())) {
            for (auto dataSection : CIter::children(dataRegion)) {
                auto gSection = TM.sections.get<gtirb::Section *>(dataSection);
                gModule->addSection(gSection);
            }
        }
    }

    void add_types(gtirb::Module *gModule) {}

    void link_variables(gtirb::Module *gModule, Module *eModule) {
        // auto *elfMap = eModule->getElfSpace()->getElfMap();
        // for (const auto &[eVariable, gSymbol] : TM.globalVariables.gtirb) {
        //     auto eSymbol = eVariable->getSymbol();
        //     auto elfSection =
        //     elfMap->findSection(eSymbol->getSectionIndex()); auto eSection =
        //     eModule->getDataRegionList()->findDataSection(elfSection->getName());
        //     auto gSection = TM.sections.gtirb[eSection];
        //     auto gInterval = TM.globalVariables.get_aux<gtirb::ByteInterval
        //     *>(
        //         gSymbol);
        //     gSection->addByteInterval(gInterval);
        //     gModule->addSymbol(gSymbol);
        //     LOG(0, "Adding global variable " << eVariable->getName());
        // }
        // for (const auto &[eVariable, gSymbol] : TM.dataVariables.gtirb) {
        //     auto eSymbol = eVariable->getTargetSymbol();
        //     auto elfSection =
        //     elfMap->findSection(eSymbol->getSectionIndex()); auto eSection =
        //     eModule->getDataRegionList()->findDataSection(elfSection->getName());
        //     auto gSection = TM.sections.gtirb[eSection];
        //     auto gInterval = TM.globalVariables.get_aux<gtirb::ByteInterval
        //     *>(
        //         gSymbol);
        //     gSection->addByteInterval(gInterval);
        //     gModule->addSymbol(gSymbol);
        //     LOG(0, "Adding data variable " << eVariable->getName());
        // }
    }

    void link_functions(gtirb::Module *gModule, Module *eModule) {
        auto *elfMap = eModule->getElfSpace()->getElfMap();
        std::map<gtirb::UUID, std::set<gtirb::UUID>> functionBlocks;
        std::map<gtirb::UUID, std::set<gtirb::UUID>> functionEntries;
        std::map<gtirb::UUID, gtirb::UUID> functionNames;
        std::map<gtirb::UUID, ElfSymbolInfo> symbolInfo;
        std::map<gtirb::UUID, gtirb::UUID> symbolForwarding;

        auto cfg = gModule->getIR()->getCFG();

        for (auto &[proxyBlock] : TM.pltEntries.values<gtirb::ProxyBlock *>()) {
            gModule->addProxyBlock(proxyBlock);
        }

        for (auto &[eFunction, gSymbol, gInterval, codeBlocks, functionId] :
            TM.functions.values()) {
            auto eSymbol = eFunction->getSymbol();
            // TODO: It's strange to me that I have to go through the elfMap to
            // get the section but it might actually be the case?
            auto elfSection = elfMap->findSection(eSymbol->getSectionIndex());
            auto eSection = eModule->getDataRegionList()->findDataSection(
                elfSection->getName());
            auto gSection = TM.sections.get<gtirb::Section *>(eSection);

            gSection->addByteInterval(gInterval);
            // LOG(0, "Linking symbol " << gSymbol->getName());
            gModule->addSymbol(gSymbol);

            for (auto codeBlock : codeBlocks) {
                functionBlocks[functionId].insert(codeBlock->getUUID());
                functionEntries[functionId].insert(codeBlock->getUUID());
            }
            // LOG(0, "Added functionID mapping from " << gSymbol->getName());
            functionNames[functionId] = gSymbol->getUUID();

            ElfSymbolInfo Info = {0, "FUNC", "GLOBAL", "DEFAULT", 0};
            symbolInfo[gSymbol->getUUID()] = Info;
        }

        // for (auto &[eFunction, gSymbol, gInterval] :
        // TM.functions.values<Function*, gtirb::Symbol*,
        // gtirb::ByteInterval*>()) {
        //     LOG(0, "checking mapping from " << gSymbol->getName());
        //     auto gStart = *gSymbol->getAddress();
        //     auto start = eFunction->getPosition()->get();
        //     for (auto block : CIter::children(eFunction)) {
        //         for (auto instruction : CIter::children(block)) {
        //             auto link = instruction->getSemantic()->getLink();
        //             if (link != nullptr) {
        //                 auto offset = instruction->getPosition()->get() -
        //                 start; auto linkSym = link->getTarget(); if (linkSym
        //                 != nullptr) {
        //                     auto gSym = TM.getSymbol(linkSym);
        //                     if (gSym != nullptr) {
        //                         LOG(0, "adding symbolic expression from "
        //                                    << offset << " in "
        //                                    << gSymbol->getName() << " to "
        //                                    << gSym->getName());

        //                         gtirb::SymAttributeSet attrs;
        //                         if (TM.externalSymbols.contains(gSym)) {
        //                             LOG(0, "This is a symbolic expression!");
        //                             attrs.addFlag(gtirb::SymAttribute::PltRef);
        //                         }
        //                         auto gAddr = gStart + offset;
        //                         const gtirb::CodeBlock *src =
        //                         &*gModule->findCodeBlocksOn(gAddr).begin();
        //                         auto codeBlocks =
        //                         TM.functions.get<std::set<gtirb::CodeBlock*>>(gSym);
        //                         const gtirb::CodeBlock *dst =
        //                         *codeBlocks.begin(); auto cfg =
        //                         gModule->getIR()->getCFG();

        //                         auto edge = *gtirb::addEdge(src, dst, cfg);
        //                         cfg[edge] = std::make_tuple(
        //                             gtirb::ConditionalEdge::OnFalse,
        //                             gtirb::DirectEdge::IsDirect,
        //                             gtirb::EdgeType::Call);
        //                         gInterval->addSymbolicExpression(
        //                             offset, gtirb::SymAddrAddr{0, 0, gSym,
        //                             gSymbol, attrs});
        //                     }
        //                     else {
        //                         LOG(0, "No symbol for link at position "
        //                                    << offset << " in "
        //                                    << gSymbol->getName());
        //                     }
        //                 }
        //             }
        //         }
        //     }
        // }
        gModule->addAuxData<gtirb::schema::FunctionEntries>(
            std::move(functionEntries));
        gModule->addAuxData<gtirb::schema::FunctionBlocks>(
            std::move(functionBlocks));
        gModule->addAuxData<gtirb::schema::FunctionNames>(
            std::move(functionNames));
        gModule->addAuxData<gtirb::schema::ElfSymbolInfoAD>(
            std::move(symbolInfo));
    }

    void link_instructions(gtirb::Module *gModule, Module *eModule) {
        auto *elfMap = eModule->getElfSpace()->getElfMap();
        for (const auto &[eFunction, gInterval, gSymbol] :
            TM.functions
                .values<Function *, gtirb::ByteInterval *, gtirb::Symbol *>()) {
            // for (auto block : CIter::children(eFunction)) {
            //     for (auto instruction: CIter::children(block)) {
            //     }
            // }
            auto eSymbol = eFunction->getDynamicSymbol();
            // TODO: It's strange to me that I have to go through the elfMap
            // to get the section but it might actually be the case?
            auto elfSection = elfMap->findSection(eSymbol->getSectionIndex());
            auto eSection = eModule->getDataRegionList()->findDataSection(
                elfSection->getName());
            auto gSection = TM.sections.get<gtirb::Section *>(eSection);

            gSection->addByteInterval(gInterval);
            LOG(0, "Linking symbol " << gSymbol->getName());
            gModule->addSymbol(gSymbol);
        }
    }

    gtirb::IR *convert(Program *program) {
        FlatPass(C, TM).visit(program);
        auto ir = gtirb::IR::Create(C);

        for (const auto &[eModule, gModule] : TM.modules.values()) {
            ir->addModule(gModule);
            link_sections(gModule, eModule);
            link_variables(gModule, eModule);
            link_functions(gModule, eModule);
        }
        for (auto &info : TM.link_info) {
            gtirb::SymAttributeSet attrs;
            Link *link = info.link;
            if (dynamic_cast<PLTLink *>(link)) {
                LOG(0, "Got a PLT link!");
                attrs.addFlag(gtirb::SymAttribute::PltRef);
            }
            const gtirb::CodeBlock *src_block = info.src_block;

            Chunk *eTarget = link->getTarget();
            if (!eTarget) {
                LOG(0, "TARGET NOT LOADED");
                continue;
            }
            Module *eModule = chunk_module(eTarget);
            gtirb::Module *dst_module = TM.modules.get<gtirb::Module *>(
                eModule);
            gtirb::Addr dst_addr(eTarget->getAddress());

            for (gtirb::CodeBlock &dst : dst_module->findCodeBlocksOn(dst_addr)) {

                auto cfg = dst_module->getIR()->getCFG();
                auto edge = *gtirb::addEdge(src_block, &dst, cfg);
                cfg[edge] = std::make_tuple(
                    gtirb::ConditionalEdge::OnFalse,
                    gtirb::DirectEdge::IsDirect,
                    gtirb::EdgeType::Call);
            }
            // gtirb::SymAttributeSet attrs;
            // if (TM.externalSymbols.contains(gSym)) {
            //     LOG(0, "This is a symbolic expression!");
            //     attrs.addFlag(gtirb::SymAttribute::PltRef);
            // }
            // auto gAddr = gStart + offset;
            // const gtirb::CodeBlock *src =
            // &*gModule->findCodeBlocksOn(gAddr).begin();
            // auto codeBlocks =
            // TM.functions.get<std::set<gtirb::CodeBlock*>>(gSym);
            // const gtirb::CodeBlock *dst =

            // auto edge = *gtirb::addEdge(src, dst, cfg);
            // cfg[edge] = std::make_tuple(
            //     gtirb::ConditionalEdge::OnFalse,
            //     gtirb::DirectEdge::IsDirect,
            //     gtirb::EdgeType::Call);
            // gInterval->addSymbolicExpression(
            //     offset, gtirb::SymAddrAddr{0, 0, gSym,
            //     gSymbol, attrs});
        }

        // for (const auto &[iFunction, codeBlock] : TM.entryPoints.gtirb) {
        //     auto eModule = dynamic_cast<Module
        //     *>(iFunction->getFunction()->getParent()->getParent()); auto
        //     gModule = TM.modules.gtirb[eModule]; LOG(0, "Adding initial
        //     function " << iFunction->getName());
        //     gModule->setEntryPoint(codeBlock);
        // }
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
    GtirbConverter converter;
    auto *converted = converter.convert(program);
    std::ofstream file;
    file.open(filename + ".gtirb");
    converted->save(file);
    file.close();
    std::ofstream file2;
    file2.open(filename + ".json");
    converted->saveJSON(file2);
    file2.close();
}
