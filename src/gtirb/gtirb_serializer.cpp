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

#include "gtirb/IR.hpp"
#include "gtirb/Symbol.hpp"
#include "gtirb/proto/IR.pb.h"
#include "gtirb/Context.hpp"
#include "gtirb/ByteInterval.hpp"

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
    /** Map from egalito type to gtirb type */
    std::unordered_map<EType, GType> gtirb;
    /** Map from gtirb type to egalito type */
    std::unordered_map<GType, EType> egalito;
    /** Map from gtirb type to additional auxiliary data */
    std::unordered_map<GType, std::tuple<Aux...>> aux;

    /** Add a mapping between egalito types and gtirb types */
    void add(EType eobj, GType gobj, Aux... auxobjs) {
        gtirb[eobj] = gobj;
        egalito[gobj] = eobj;
        aux[gobj] = std::make_tuple(auxobjs...);
    }

    /**
     * Get the auxiliary data associated with a gtirb object
     * If T is provided it follows the rules for getting from a tuple
     * i.e.
     *     get_aux<gtirb::CodeBlock*>(gtirb_obj)
     * or
     *     get_aux<2>(gtirb_obj)
     * Otherwise, it gets the first provided aux data element
     *
     * TODO: Maybe remove this altogether. I'm not sure it's actually necessary.
     */
    template <auto T = 0>
    auto get_aux(GType gobj) {
        return std::get<T>(aux[gobj]);
    }
};

/**
 * Holds all of the mapping relationships between egalito objects
 * and their corresponding gtirb objects
 */
struct TypeMapper {
    TypeMap<Module *, gtirb::Module *> modules;
    TypeMap<Library *, gtirb::Module *> libraries;
    TypeMap<DataSection *, gtirb::Section *> sections;
    TypeMap<Function *, gtirb::Symbol *, gtirb::ByteInterval *,
        gtirb::CodeBlock *>
        functions;
    TypeMap<DataVariable *, gtirb::Symbol *, gtirb::ByteInterval *,
        gtirb::DataBlock *>
        dataVariables;
    TypeMap<GlobalVariable *, gtirb::Symbol *, gtirb::ByteInterval *,
        gtirb::DataBlock *>
        globalVariables;
    TypeMap<ExternalSymbol *, gtirb::Symbol *> externalSymbols;
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
    TypeMapper &TM;

    // FIXME: This may not function properly if multiple elfMaps are present due
    // to deep-scanning a binary
    ElfMap *elfMap;
    template <typename Type>
    void recurse(Type *root) {
        for (auto child : root->getChildren()->genericIterable()) {
            child->accept(this);
        }
    }

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
        auto symbol = function->getSymbol();
        assert(symbol->getAddress() == function->getAddress());
        auto addr = symbol->getAddress();

        auto *interval = gtirb::ByteInterval::Create(
            C, gtirb::Addr(addr), symbol->getSize());
        auto intervalBegin = std::as_const(*interval).bytes_begin<char>();

        // Maybe codeBlocks should line up with the "block" in the function as
        // well
        auto *codeBlock = gtirb::CodeBlock::Create(C, symbol->getSize());
        interval->addBlock(0, codeBlock);
        auto *gSymbol = gtirb::Symbol::Create(C, codeBlock, symbol->getName());

        auto start = function->getPosition()->get();
        for (auto block : CIter::children(function)) {
            for (auto instruction : CIter::children(block)) {
                auto offset = instruction->getPosition()->get() - start;
                InstrWriterGetData getter;
                instruction->getSemantic()->accept(&getter);
                std::string data = getter.get();
                auto offsetInterval = intervalBegin + offset;
                interval->insertBytes(offsetInterval, data.begin(), data.end());
            }
            TM.functions.add(function, gSymbol, interval, codeBlock);
            recurse(function);
        }
    }

    virtual void visit(DataSection *dataSection) {
        // DataSections seems to include all of the code sections as well
        auto *section = gtirb::Section::Create(C, dataSection->getName());
        TM.sections.add(dataSection, section);
        recurse(dataSection);
    }

    virtual void visit(DataVariable *variable) {
        // FIXME: I don't understand the difference between this and
        // GlobalVariable
        auto addr = variable->getAddress();
        auto dataBlock = gtirb::DataBlock::Create(C, variable->getSize());
        auto symbol = gtirb::Symbol::Create(C, dataBlock, variable->getName());
        auto *byteInterval = gtirb::ByteInterval::Create(
            C, gtirb::Addr(addr), variable->getSize());
        TM.dataVariables.add(variable, symbol, byteInterval, dataBlock);
    }

    virtual void visit(GlobalVariable *variable) {
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
        auto gModule = TM.modules.gtirb[library->getModule()];
        TM.libraries.add(library, gModule);
    }
    virtual void visit(ExternalSymbol *externalSymbol) {
        // TODO:
        // auto symbolName = externalSymbol->getName();
        // if (externalSymbols.find(symbolName) != std::end(externalSymbols)) {
        //     return;
        // }
    }

    /** Chunks which are simply recursed into */
    virtual void visit(Program *program) { recurse(program); }
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
    virtual void visit(LibraryList *libraryList) { recurse(libraryList); }
    virtual void visit(JumpTable *jumpTable) { recurse(jumpTable); }
    virtual void visit(DataRegion *dataRegion) { recurse(dataRegion); }
    virtual void visit(Block *block) { recurse(block); }

    /** Chunks which are currently ignored altogether */
    virtual void visit(InitFunctionList *initFunctionList) {}
    virtual void visit(PLTTrampoline *trampoline) {}
    virtual void visit(JumpTableEntry *jumpTableEntry) {}
    virtual void visit(MarkerList *markerList) {}
    virtual void visit(VTable *vtable) {}
    virtual void visit(VTableEntry *vtableEntry) {}
    virtual void visit(InitFunction *initFunction) {}
    // Note: Instruction is not totally ignored, but is instead recursed through
    // manually by Function
    virtual void visit(Instruction *instruction) {}
};

class GtirbConverter {
private:
    gtirb::Context C;
    TypeMapper TM;

public:
    void link_sections(gtirb::Module *gModule, Module *eModule) {
        for (auto dataRegion : CIter::children(eModule->getDataRegionList())) {
            for (auto dataSection : CIter::children(dataRegion)) {
                auto gSection = TM.sections.gtirb[dataSection];
                gModule->addSection(gSection);
            }
        }
    }

    void link_functions(gtirb::Module *gModule, Module *eModule) {
        auto *elfMap = eModule->getElfSpace()->getElfMap();
        for (const auto &[eFunction, gSymbol] : TM.functions.gtirb) {
            auto gInterval = TM.functions.get_aux(gSymbol);
            auto eSymbol = eFunction->getSymbol();
            // TODO: It's strange to me that I have to go through the elfMap to
            // get the section but it might actually be the case?
            auto elfSection = elfMap->findSection(eSymbol->getSectionIndex());
            auto eSection = eModule->getDataRegionList()->findDataSection(
                elfSection->getName());
            auto gSection = TM.sections.gtirb[eSection];

            gSection->addByteInterval(gInterval);
            LOG(0, "Adding symbol" << gSymbol->getName());
            gModule->addSymbol(gSymbol);
        }
    }

    gtirb::IR *convert(Program *program) {
        FlatPass(C, TM).visit(program);
        auto ir = gtirb::IR::Create(C);

        for (const auto &[eModule, gModule] : TM.modules.gtirb) {
            ir->addModule(gModule);

            link_sections(gModule, eModule);
            link_functions(gModule, eModule);
        }
        return ir;
    }
};

void GtirbSerializer::serialize(Program *program, std::string filename) {
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
