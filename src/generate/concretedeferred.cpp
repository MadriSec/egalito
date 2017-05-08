#include <cstring>  // for memset
#include "concretedeferred.h"
#include "section.h"
#include "sectionlist.h"
#include "elf/elfspace.h"
#include "elf/symbol.h"
#include "chunk/function.h"
#include "chunk/dataregion.h"
#include "chunk/link.h"
#include "instr/instr.h"
#include "instr/concrete.h"
#include "log/log.h"

SymbolTableContent::DeferredType *SymbolTableContent
    ::add(Function *func, Symbol *sym, size_t strndx) {

    ElfXX_Sym *symbol = new ElfXX_Sym();
    symbol->st_name = static_cast<ElfXX_Word>(strndx);
    symbol->st_info = ELFXX_ST_INFO(
        Symbol::bindFromInternalToElf(sym->getBind()),
        Symbol::typeFromInternalToElf(sym->getType()));
    symbol->st_other = STV_DEFAULT;
    symbol->st_shndx = SHN_UNDEF;
    symbol->st_value = func ? func->getAddress() : 0;
    symbol->st_size = func ? func->getSize() : 0;
    auto value = new DeferredType(symbol);
    DeferredMap<Symbol *, ElfXX_Sym>::add(sym, value);
    return value;
}

void SymbolTableContent::add(Symbol *sym, int index) {
    ElfXX_Sym *symbol = new ElfXX_Sym();
    symbol->st_name = 0;
    symbol->st_info = ELFXX_ST_INFO(
        Symbol::bindFromInternalToElf(sym->getBind()),
        Symbol::typeFromInternalToElf(sym->getType()));
    symbol->st_other = STV_DEFAULT;
    symbol->st_shndx = sym->getSectionIndex();
    symbol->st_value = 0;
    symbol->st_size = 0;

    auto value = new DeferredType(symbol);
    insertAt(this->begin() + index, sym, value);

    auto i = sym->getSectionIndex();
    if(i >= sectionSymbols.size()) sectionSymbols.resize(i + 1);
    sectionSymbols[i] = value;
}

void SymbolTableContent::add(ElfXX_Sym *symbol) {
    DeferredMap<Symbol *, ElfXX_Sym>::add(nullptr,
        new DeferredType(symbol));
}

size_t SymbolTableContent::indexOfSectionSymbol(const std::string &section,
    SectionList *sectionList) {

    size_t index = sectionList->indexOf(section);
    return this->indexOf(sectionSymbols[index]);
}

ShdrTableContent::DeferredType *ShdrTableContent::add(Section *section) {
    auto shdr = new ElfXX_Shdr();
    std::memset(shdr, 0, sizeof(*shdr));

    auto deferred = new DeferredType(shdr);

    deferred->addFunction([this, section] (ElfXX_Shdr *shdr) {
        LOG(1, "generating shdr for section [" << section->getName() << "]");
        auto header = section->getHeader();
        //shdr->sh_name       = 0;
        shdr->sh_type       = header->getShdrType();
        shdr->sh_flags      = header->getShdrFlags();
        shdr->sh_addr       = header->getAddress();
        shdr->sh_offset     = section->getOffset();
        shdr->sh_size       = section->getContent() ?
            section->getContent()->getSize() : 0;
        shdr->sh_link       = header->getSectionLink()
            ? header->getSectionLink()->getIndex() : 0;
        shdr->sh_info       = 0;  // updated later for strtabs
        shdr->sh_addralign  = 1;
        shdr->sh_entsize    = 0;
    });

    DeferredMap<Section *, ElfXX_Shdr>::add(section, deferred);
    return deferred;
}

Section *RelocSectionContent::getTargetSection() {
    return outer->get();
}

RelocSectionContent::DeferredType *RelocSectionContent
    ::add(Chunk *source, Link *link) {

    if(auto v = dynamic_cast<DataOffsetLink *>(link)) {
        return addConcrete(dynamic_cast<Instruction *>(source), v);
    }
    else if(auto v = dynamic_cast<PLTLink *>(link)) {
        return addConcrete(dynamic_cast<Instruction *>(source), v);
    }
    else if(auto v = dynamic_cast<SymbolOnlyLink *>(link)) {
        return addConcrete(dynamic_cast<Instruction *>(source), v);
    }

    return nullptr;
}

RelocSectionContent::DeferredType *RelocSectionContent
    ::makeDeferredForLink(Instruction *source) {

    auto rela = new ElfXX_Rela();
    std::memset(rela, 0, sizeof(*rela));
    auto deferred = new DeferredType(rela);

    auto address = source->getAddress();
    int specialAddendOffset = 0;
#ifdef ARCH_X86_64
    if(auto sem = dynamic_cast<LinkedInstruction *>(source->getSemantic())) {
        address += sem->getDispOffset();
        specialAddendOffset = -(sem->getSize() - sem->getDispOffset());
    }
    else if(auto sem = dynamic_cast<ControlFlowInstruction *>(source->getSemantic())) {
        address += sem->getDispOffset();
        specialAddendOffset = -(sem->getSize() - sem->getDispOffset());
    }
#elif defined(ARCH_AARCH64)
#else
    #error "how do we encode relocation offsets in instructions on arm?"
#endif

    rela->r_offset  = address;
    rela->r_info    = 0;
    rela->r_addend  = specialAddendOffset;

    DeferredMap<address_t, ElfXX_Rela>::add(address, deferred);
    return deferred;
}

RelocSectionContent::DeferredType *RelocSectionContent
    ::addConcrete(Instruction *source, DataOffsetLink *link) {

    auto deferred = makeDeferredForLink(source);
    auto rela = deferred->getElfPtr();

    auto dest = static_cast<DataRegion *>(&*link->getTarget());  // assume != nullptr
    auto destAddress = link->getTargetAddress();

    rela->r_addend += destAddress - dest->getAddress();
    auto rodata = elfSpace->getElfMap()->findSection(".rodata")->getHeader();
    rela->r_addend -= rodata->sh_offset;  // offset of original .rodata

    auto symtab = (*sectionList)[".symtab"]->castAs<SymbolTableContent *>();
    deferred->addFunction([this, symtab] (ElfXX_Rela *rela) {
        size_t index = symtab->indexOfSectionSymbol(".rodata", sectionList);
        rela->r_info = ELFXX_R_INFO(index, R_X86_64_PC32);
    });

    return deferred;
}

RelocSectionContent::DeferredType *RelocSectionContent
    ::addConcrete(Instruction *source, PLTLink *link) {

    auto deferred = makeDeferredForLink(source);

    auto symtab = (*sectionList)[".symtab"]->castAs<SymbolTableContent *>();
    deferred->addFunction([this, symtab, link] (ElfXX_Rela *rela) {
        auto elfSym = symtab->find(
            link->getPLTTrampoline()->getTargetSymbol());
        size_t index = symtab->indexOf(elfSym);
        rela->r_info = ELFXX_R_INFO(index, R_X86_64_PLT32);
    });

    return deferred;
}

RelocSectionContent::DeferredType *RelocSectionContent
    ::addConcrete(Instruction *source, SymbolOnlyLink *link) {

    auto deferred = makeDeferredForLink(source);

    auto symtab = (*sectionList)[".symtab"]->castAs<SymbolTableContent *>();
    deferred->addFunction([this, symtab, link] (ElfXX_Rela *rela) {
        auto elfSym = symtab->find(link->getSymbol());
        size_t index = symtab->indexOf(elfSym);
        rela->r_info = ELFXX_R_INFO(index, R_X86_64_PLT32);
    });

    return deferred;
}