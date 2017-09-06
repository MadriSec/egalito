#include "elfspace.h"
#include "symbol.h"
#include "elfdynamic.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "chunk/aliasmap.h"
#include "chunk/tls.h"
#include "chunk/dataregion.h"
#include "disasm/disassemble.h"
#include "pass/fallthrough.h"
#include "pass/splitbasicblock.h"
#include "pass/internalcalls.h"
#include "pass/externalcalls.h"
#include "pass/handlerelocs.h"
#include "pass/inferlinks.h"
#include "pass/relocdata.h"
#include "pass/jumptablepass.h"
#include "pass/jumptablebounds.h"
#include "pass/jtoverestimate.h"
#include "analysis/jumptable.h"
#include "log/log.h"

ElfSpace::ElfSpace(ElfMap *elf, SharedLib *library)
    : elf(elf), library(library), module(nullptr),
    symbolList(nullptr), dynamicSymbolList(nullptr),
    relocList(nullptr),
    aliasMap(nullptr) {

}

ElfSpace::~ElfSpace() {
    delete elf;
    delete library;
    delete module;
    delete symbolList;
    delete dynamicSymbolList;
    delete relocList;
    delete aliasMap;
}

void ElfSpace::findDependencies(LibraryList *libraryList) {
    ElfDynamic dynamic(libraryList);
    dynamic.parse(elf, library);
}

void ElfSpace::buildDataStructures(bool hasRelocs) {
    LOG(1, "");
    LOG(1, "=== BUILDING ELF DATA STRUCTURES for [" << getName() << "] ===");

    if(library) {
        this->symbolList = SymbolList::buildSymbolList(library);
    }
    else {
        this->symbolList = SymbolList::buildSymbolList(elf);
    }

    if(elf->isDynamic()) {
        this->dynamicSymbolList = SymbolList::buildDynamicSymbolList(elf);
    }

    Disassemble::init();
    this->module = Disassemble::module(elf, symbolList);
    this->module->setElfSpace(this);

    ChunkDumper dumper;
    module->accept(&dumper);

    FallThroughFunctionPass fallThrough;
    module->accept(&fallThrough);

    InternalCalls internalCalls;
    module->accept(&internalCalls);

    //ChunkDumper dumper;
    //module->accept(&dumper);

    this->relocList = RelocList::buildRelocList(elf, symbolList, dynamicSymbolList);

    DataRegionList::buildDataRegionList(elf, module);

    PLTList::parsePLTList(elf, relocList, module);

    HandleRelocsPass handleRelocsPass(elf, relocList);
    module->accept(&handleRelocsPass);

    if(module->getPLTList()) {
        ExternalCalls externalCalls(module->getPLTList());
        module->accept(&externalCalls);
    }

    JumpTablePass jumpTablePass;
    module->accept(&jumpTablePass);

    JumpTableBounds jumpTableBounds;
    module->accept(&jumpTableBounds);

    JumpTableOverestimate jumpTableOverestimate;
    module->accept(&jumpTableOverestimate);

    // this needs jumptable information and all NormalLinks
    SplitBasicBlock split;
    module->accept(&split);

    // this needs all blocks to be split to basic blocks
    InferLinksPass inferLinksPass(elf);
    module->accept(&inferLinksPass);

    //TLSList::buildTLSList(elf, relocList, module);

    aliasMap = new FunctionAliasMap(module);
}

std::string ElfSpace::getName() const {
    return library ? library->getShortName() : "(executable)";
}
