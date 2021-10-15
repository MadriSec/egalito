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

struct TypeMapping
{
    template <typename... Types>
    using TypeMap = std::unordered_map<std::string, std::tuple<Types...>>;

    TypeMap<Module *, gtirb::Module *> modules;
    TypeMap<Library *, gtirb::Module *> libraries;
    TypeMap<DataSection *, gtirb::Section *> sections;
    TypeMap<Function *, gtirb::Symbol *, gtirb::ByteInterval *, gtirb::CodeBlock *> functions;
    TypeMap<DataVariable *, gtirb::Symbol *, gtirb::ByteInterval *, gtirb::DataBlock *> dataVariables;
    TypeMap<GlobalVariable *, gtirb::Symbol *, gtirb::ByteInterval *, gtirb::DataBlock *> globalVariables;
    TypeMap<ExternalSymbol *, gtirb::Symbol *> externalSymbols;
};

class FlatPass : public ChunkVisitor
{
protected:
    gtirb::Context &C;
    TypeMapping &TM;

    // FIXME: Could be multiple elfMap's if the
    ElfMap *elfMap;
    template <typename Type>
    void recurse(Type *root)
    {
        for (auto child : root->getChildren()->genericIterable())
        {
            child->accept(this);
        }
    }

public:
    FlatPass(gtirb::Context &C, TypeMapping &TM) : C(C), TM(TM){};

    virtual void visit(Chunk *chunk) { recurse(chunk); }

    virtual void visit(Program *program) { recurse(program); }
    virtual void visit(Module *module)
    {
        auto *gmodule = gtirb::Module::Create(C, module->getName());
        gmodule->setFileFormat(gtirb::FileFormat::ELF);
#ifdef ARCH_X86_64
        // FIXME: Can egalito be compiled for multiple ISA?
        gmodule->setISA(gtirb::ISA::X64);
#endif
        TM.modules[module->getName()] = std::make_tuple(module, gmodule);
        elfMap = module->getElfSpace()->getElfMap();
        recurse(module);
    }

    virtual void visit(Function *function)
    {
        auto symbol = function->getSymbol();
        assert(symbol->getAddress() == function->getAddress());
        auto addr = symbol->getAddress();

        auto *interval = gtirb::ByteInterval::Create(C, gtirb::Addr(addr), symbol->getSize());
        auto intervalBegin = std::as_const(*interval).bytes_begin<char>();

        // Maybe codeBlocks should line up with the "block" in the function as well
        auto *codeBlock = gtirb::CodeBlock::Create(C, symbol->getSize());
        interval->addBlock(0, codeBlock);
        auto *gSymbol = gtirb::Symbol::Create(C, codeBlock, symbol->getName());

        auto start = function->getPosition()->get();
        for (auto block : CIter::children(function))
        {
            for (auto instruction : CIter::children(block))
            {
                auto offset = instruction->getPosition()->get() - start;
                InstrWriterGetData getter;
                instruction->getSemantic()->accept(&getter);
                std::string data = getter.get();
                auto offsetInterval = intervalBegin + offset;
                interval->insertBytes(offsetInterval, data.begin(), data.end());
            }
            TM.functions[symbol->getName()] = std::make_tuple(function, gSymbol, interval, codeBlock);
            recurse(function);
        }
    }

    virtual void visit(DataSection *dataSection)
    {
        // DataSections seems to include all of the code sections as well
        auto *section = gtirb::Section::Create(C, dataSection->getName());
        TM.sections[dataSection->getName()] = std::make_tuple(dataSection, section);
        recurse(dataSection);
    }

    virtual void visit(DataVariable *variable)
    {
        // FIXME: I don't understand the difference between this and GlobalVariable
        auto addr = variable->getAddress();
        auto dataBlock = gtirb::DataBlock::Create(C, variable->getSize());
        auto symbol = gtirb::Symbol::Create(C, dataBlock, variable->getName());
        auto *byteInterval = gtirb::ByteInterval::Create(C, gtirb::Addr(addr), variable->getSize());
        TM.dataVariables[variable->getName()] = std::make_tuple(variable, symbol, byteInterval, dataBlock);
    }

    virtual void visit(GlobalVariable *variable)
    {
        auto addr = variable->getAddress();
        auto dataBlock = gtirb::DataBlock::Create(C, variable->getSize());
        auto symbol = gtirb::Symbol::Create(C, dataBlock, variable->getName());
        auto *byteInterval = gtirb::ByteInterval::Create(C, gtirb::Addr(addr), variable->getSize());
        TM.globalVariables[variable->getName()] = std::make_tuple(variable, symbol, byteInterval, dataBlock);
    }

    virtual void visit(Library *library)
    {
        // The simplicity of the other mappings is lost a little here,
        // because I am less sure that this cannot be cyclical
        if (!library->getModule())
        {
            return;
        }
        recurse(library->getModule());
        // Also, both libraries and Modules map onto gtirb::Module's
        auto gModule = std::get<1>(TM.modules[library->getModule()->getName()]);
        TM.libraries[library->getName()] = std::make_tuple(library, gModule);
    }
    virtual void visit(ExternalSymbol *externalSymbol)
    {
        // TODO:
        // auto symbolName = externalSymbol->getName();
        // if (externalSymbols.find(symbolName) != std::end(externalSymbols)) {
        //     return;
        // }
    }

    /** Chunks which are simply recursed into */
    virtual void visit(FunctionList *functionList) { recurse(functionList); }
    virtual void visit(PLTList *pltList) { recurse(pltList); }
    virtual void visit(JumpTableList *jumpTableList) { recurse(jumpTableList); }
    virtual void visit(DataRegionList *dataRegionList) { recurse(dataRegionList); };
    virtual void visit(VTableList *vtableList) { recurse(vtableList); }
    virtual void visit(ExternalSymbolList *externalSymbolList) { recurse(externalSymbolList); }
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
    // Note: Instruction has
    virtual void visit(Instruction *instruction) {}
};

class GtirbConverter
{
private:
    gtirb::Context C;
    TypeMapping TM;

public:
    // void link_modules(gtirb::IR *ir) {
    //     for (const auto &[_, value] : TM.modules) {
    //         const auto &[_, gModule] = value;
    //         ir->addModule(gModule);
    //     }
    // }

    void link_sections(gtirb::Module *gModule, Module *eModule)
    {
        for (auto dataRegion : CIter::children(eModule->getDataRegionList()))
        {
            for (auto dataSection : CIter::children(dataRegion))
            {
                const auto &[_, gSection] = TM.sections[dataSection->getName()];
                gModule->addSection(gSection);
            }
        }
    }

    void link_functions(gtirb::Module *gModule, Module *eModule)
    {
        auto *elfMap = eModule->getElfSpace()->getElfMap();
        // TypeMap<Function *, gtirb::Symbol *, gtirb::ByteInterval *, gtirb::CodeBlock*> functions;
        for (const auto &[fName, fValue] : TM.functions)
        {
            auto [eFunction, gSymbol, gInterval, Block] = fValue;
            auto eSymbol = eFunction->getSymbol();
            auto section = elfMap->findSection(eSymbol->getSectionIndex());
            auto [eSection, gSection] = TM.sections[section->getName()];
            gSection->addByteInterval(gInterval);
            LOG(0, "Adding symbol" << gSymbol->getName());
            gModule->addSymbol(gSymbol);
        }
    }

    gtirb::IR *convert(Program *program)
    {
        FlatPass(C, TM).visit(program);
        auto ir = gtirb::IR::Create(C);

        for (const auto &[name, value] : TM.modules)
        {
            auto [eModule, gModule] = value;
            ir->addModule(gModule);

            link_sections(gModule, eModule);
            link_functions(gModule, eModule);
        }
        return ir;
    }
};

void GtirbSerializer::serialize(Program *program, std::string filename)
{
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
