#include "gtirb_deserializer.h"
#include "gtirb_util.h"

#include "chunk/dataregion.h"
#include "chunk/function.h"
#include "chunk/library.h"
#include "chunk/module.h"
#include "chunk/plt.h"
#include "chunk/program.h"
#include "chunk/resolver.h"
#include "disasm/disassemble.h"
#include "disasm/handle.h"
#include "elf/elfdynamic.h"
#include "elf/elfspace.h"
#include "elf/symbol.h"
#include "gtirb/gtirb.hpp"
#include "log/log.h"
#include "operation/mutator.h"

#include <capstone/capstone.h>
#include <cstddef>
#include <elf.h>
#include <filesystem>
#include <fstream>
#include <boost/uuid/uuid_io.hpp>

GtirbDeserializer::GtirbDeserializer(std::string filename)
    : filename(filename), C(new gtirb::Context()), ir(nullptr) {}

GtirbDeserializer::~GtirbDeserializer() = default;

bool GtirbDeserializer::preParse() {
    register_gtirb_auxdata();

    std::ifstream in(this->filename, std::ios::in | std::ios::binary);
    if (!in.is_open()) {
        return false;
    }

    auto err_or_ir = gtirb::IR::load(*this->C, in);
    if (err_or_ir) {
        this->ir = *err_or_ir;
        return true;
    }
    else {
        return false;
    }
}

/**
 * @brief Convert from GTIRB's notion of symbol types to Egalito's notion.
 *
 * @param gtirb_sym_type A string representation of a symbol's type.
 * @return Symbol::SymbolType
 */
static Symbol::SymbolType convertGtirbSymbolType(std::string gtirb_sym_type) {
    using ST = Symbol::SymbolType;

    // There are other types not listed here, but ddisasm
    // doesn't seem to produce them.
    // Specifically: TYPE_SECTION
    static const std::unordered_map<std::string, Symbol::SymbolType>
        type_name_conversion = {
            {"FUNC", ST::TYPE_FUNC},
            {"OBJECT", ST::TYPE_OBJECT},
            {"NOTYPE", ST::TYPE_NOTYPE},
            {"NONE", ST::TYPE_NOTYPE},
            {"TLS", ST::TYPE_TLS},
            {"GNU_IFUNC", ST::TYPE_IFUNC},
            {"FILE", ST::TYPE_FILE},
        };
    auto it = type_name_conversion.find(gtirb_sym_type);
    if (it == type_name_conversion.end()) {
        std::cerr << "Unhandled symbol type: " << gtirb_sym_type << "\n";
        return ST::TYPE_UNKNOWN;
    }
    else {
        return it->second;
    }
}

/**
 * @brief Convert from GTIRB's notion of binding type to Egalito's notion.
 *
 * @param gtirb_bind_type A string representation of a symbol's binding type.
 * @return Symbol::BindingType
 */
static Symbol::BindingType convertGtirbBindingType(
    std::string gtirb_bind_type) {
    using BT = Symbol::BindingType;

    static const std::unordered_map<std::string, Symbol::BindingType>
        // TODO: A couple of these are non-obvious and might bear
        // some further investigation to verify they are the right
        // way to translate things. Specifically: UNIQUE and GNU_UNIQUE.
        type_name_conversion = {
            {"LOCAL", BT::BIND_LOCAL},
            {"GLOBAL", BT::BIND_GLOBAL},
            {"WEAK", BT::BIND_WEAK},
            {"UNIQUE", BT::BIND_GLOBAL},
            {"GNU_UNIQUE", BT::BIND_GLOBAL},
        };
    auto it = type_name_conversion.find(gtirb_bind_type);
    if (it == type_name_conversion.end()) {
        std::cerr << "Unhandled binding type: " << gtirb_bind_type << "\n";
        return BT::BIND_GLOBAL;
    }
    else {
        return it->second;
    }
}

/**
 * @brief Convert from GTIRB's notion of ISA to Egalito's notion.
 *
 * @param isa The GTIRB enum constant representing the ISA.
 * @return size_t
 */
static size_t gtirb_isa_to_machine(gtirb::ISA isa) {
    switch (isa) {
        case gtirb::ISA::X64:
            return EM_X86_64;
        case gtirb::ISA::ARM:
            return EM_ARM;
        default: {
            assert(false && "Unsupported ISA");
            return EM_NONE;
        }
    }
}

/**
 * @brief get the binary type flag for the ELF header.
 *
 * @param module The GTIRB module.
 * @return The ELF header binary type flag.
 */
static size_t getBinaryTypeFlag(const gtirb::Module &module) {
    const std::vector<std::string>
        *bin_types = module.getAuxData<gtirb::schema::BinaryType>();

    if (bin_types->size() != 1) {
        LOG(1, "WARNING: Found "
                   << bin_types->size()
                   << " ELF binary type flags - should be exactly one!");
        assert(false && "Should be exactly 1 ELF binary type flag");
    }

    size_t e_type = ET_EXEC;
    if (bin_types->size() > 0) {
        std::string bin_type = bin_types->front();
        if (bin_type == "DYN") {
            e_type = ET_DYN;
        }
        else if (bin_type == "EXEC") {
            e_type = ET_EXEC;
        }
        else if (bin_type == "REL") {
            e_type = ET_EXEC;
        }
        else {
            LOG(1, "WARNING: unrecognized GTIRB binary type: " << bin_type);
            assert(false && "Unrecoginzed GTIRB binary type");
        }
    }
    return e_type;
}

/**
 * @brief Copy bytes from a GTIRB section to a byte buffer.
 *
 * @param dest Destination for storing the bytes.
 * @param section GTIRB section to copy bytes from.
 *
 * @note Assumes that the ByteIntervals in the section have addresses and are
 * non-overlapping.
 */
static void copySectionBytes(std::byte *dest, const gtirb::Section &section) {
    auto maybe_sec_addr = section.getAddress();
    assert(maybe_sec_addr && "All ByteIntervals must have addresses!");
    size_t sec_addr = size_t(*maybe_sec_addr);

    // Note: this assumes that the ByteIntervals have non-overlapping ranges.
    for (auto it = section.byte_intervals_begin();
         it != section.byte_intervals_end(); ++it) {
        auto maybe_bi_addr = it->getAddress();
        assert(maybe_bi_addr && "All ByteIntervals must have addresses!");
        size_t bi_addr = size_t(*maybe_bi_addr);

        memcpy(dest + (bi_addr - sec_addr), it->rawBytes<std::byte>(),
            it->getInitializedSize());
    }
}

/**
 * @brief Fetch the segment permissions for a section as an ELF-style bitmask.
 *
 * @param section The section to get permissions for.
 * @return uint32_t
 */
static uint32_t get_seg_perms(const gtirb::Section &section) {
    uint32_t rv = 0;
    if (section.isFlagSet(gtirb::SectionFlag::Readable)) {
        rv |= PF_R;
    }
    if (section.isFlagSet(gtirb::SectionFlag::Writable)) {
        rv |= PF_W;
    }
    if (section.isFlagSet(gtirb::SectionFlag::Executable)) {
        rv |= PF_X;
    }
    return rv;
}

/**
 * @brief The name used for the .shstrtab section.
 *
 */
static const std::string shstrtab_name = ".shstrtab";

/**
 * @brief Build an ElfMap from the bytes in a GTIRB Module.
 *
 * @param module The module to build an ElfMap for.
 * @return ElfMap* The resulting ElfMap.
 */
ElfMap *GtirbDeserializer::buildElfMap(const gtirb::Module &module) {
    // We don't have the actual ELF file. This attempts to re-construct enough
    // of one that Egalito is happy with its contents and can get what it needs.

    // First determine size needed and where everything needs to go.

    // Information about sections.
    size_t num_sections = 0;  // Not including shstrtab!
    size_t num_segments = 0;  // Sections covered by segments.
    size_t tot_section_bytes = 0;
    size_t shstrtab_size = 1;  // Inlcudes a start null byte.
    size_t curr_idx = 0;
    for (auto it = module.sections_begin(); it != module.sections_end();
         ++curr_idx, ++it) {
        // Ignore any .shstrtab section. We're going to rebuild
        // our own no matter what.
        if (it->getName() == shstrtab_name) {
            continue;
        }

        ++num_sections;
        auto maybe_size = it->getSize();
        assert(maybe_size &&
               "Should only reach here if isLoadableGtirbModule() has "
               "confirmed all sections have a size.");
        tot_section_bytes += *maybe_size;
        shstrtab_size += it->getName().length() + 1;

        // Should this section be covered by a segment?
        if (it->isFlagSet(gtirb::SectionFlag::Loaded) ||
            it->isFlagSet(gtirb::SectionFlag::ThreadLocal)) {
            num_segments++;
        }
    }

    // Program header table. GTIRB doesn't have this info. For now
    // we'll synthesize segments in a 1-to-1 fashion w/ sections.
    // It should start right after the main header.
    size_t phdr_offset = sizeof(ElfXX_Ehdr);
    size_t phdr_entry_size = sizeof(ElfXX_Phdr);
    size_t phdr_num = num_segments;
    size_t phdr_size = phdr_entry_size * phdr_num;

    // Where sections begin
    size_t secs_offset = phdr_offset + phdr_size;

    // .shstrtab section
    shstrtab_size += shstrtab_name.length() + 1;
    size_t shstrtab_offset = secs_offset + tot_section_bytes;

    // Section header table.
    size_t shdr_offset = shstrtab_offset + shstrtab_size;
    size_t shdr_entry_size = sizeof(ElfXX_Shdr);
    size_t shdr_size = shdr_entry_size * (num_sections + 1);

    // Full sized, zero-initialized chunk of memory.
    size_t map_size = sizeof(ElfXX_Ehdr) + phdr_size + tot_section_bytes +
                      shstrtab_size + shdr_size;
    std::vector<std::byte> bytes(map_size);

    // Main ELF Header
    gtirb::ISA isa = module.getISA();
    ElfXX_Ehdr header;
    header.e_ident[EI_MAG0] = ELFMAG0;
    header.e_ident[EI_MAG1] = ELFMAG1;
    header.e_ident[EI_MAG2] = ELFMAG2;
    header.e_ident[EI_MAG3] = ELFMAG3;
    header.e_ident[EI_CLASS] = ELFCLASSXX;
    header.e_ident[EI_DATA] = ELFDATA2LSB;  // TODO: Account for endianness
    header.e_ident[EI_VERSION] = EV_CURRENT;
    header.e_ident[EI_OSABI] = ELFOSABI_NONE;
    header.e_ident[EI_ABIVERSION] = 0;
    header.e_type = getBinaryTypeFlag(module);
    header.e_machine = gtirb_isa_to_machine(isa);
    header.e_version = EV_CURRENT;

    const gtirb::CodeBlock *entry = module.getEntryPoint();
    if (entry) {
        auto maybe_addr = entry->getAddress();
        assert(maybe_addr && "All ByteIntervals should have addresses!");
        header.e_entry = ElfXX_Addr(*maybe_addr);
    }
    else {
        header.e_entry = 0;
    }

    header.e_phoff = phdr_offset;
    header.e_shoff = shdr_offset;
    header.e_flags = 0;  // Unnecessary for our purposes?
    header.e_ehsize = sizeof(ElfXX_Ehdr);
    header.e_phentsize = phdr_entry_size;
    header.e_phnum = phdr_num;
    header.e_shentsize = shdr_entry_size;
    header.e_shnum = num_sections + 1;
    header.e_shstrndx = num_sections;

    memcpy(bytes.data(), &header, sizeof(ElfXX_Ehdr));

    auto sec_prop_map = module.getAuxData<gtirb::schema::SectionProperties>();
    assert(sec_prop_map && "GTIRB file should have SectionProperties AuxData!");

    // Assumes iteration order is the same as the iteration above.

    curr_idx = 0;
    size_t curr_seg_idx = 0;
    size_t curr_offset = secs_offset;
    size_t curr_shstrtab_offset = shstrtab_offset +
                                  1;  // Index 0 should already be 0
    for (auto it = module.sections_begin(); it != module.sections_end();
         ++curr_idx, ++it) {
        if (it->getName() == ".shstrtab") {
            continue;
        }

        ElfXX_Shdr shdr;
        shdr.sh_name = curr_shstrtab_offset - shstrtab_offset;

        auto props = sec_prop_map->find(it->getUUID());
        if (props != sec_prop_map->end()) {
            shdr.sh_type = std::get<0>(props->second);
            shdr.sh_flags = std::get<1>(props->second);
        }
        else {
            // Possible improvement here: attempt to use
            // the section information from GTIRB's section
            // structure, but that's lossy.
            shdr.sh_type = 0;
            shdr.sh_flags = 0;
        }

        auto maybe_addr = it->getAddress();
        assert(maybe_addr && "All ByteIntervals should have addresses!");
        shdr.sh_addr = ElfXX_Addr(*maybe_addr);

        shdr.sh_offset = curr_offset;

        auto maybe_size = it->getSize();
        assert(maybe_size &&
               "Should only reach here if isLoadableGtirbModule() has "
               "confirmed all sections have a size.");
        shdr.sh_size = *maybe_size;

        shdr.sh_link = 0;       // Don't care.
        shdr.sh_info = 0;       // Don't care.
        shdr.sh_addralign = 0;  // Don't care?
        shdr.sh_entsize = sizeof(ElfXX_Rela);
        // Need a way to set this to 2 for the version table
        if (it->getName() == ".gnu.version") {
            shdr.sh_entsize = sizeof(ElfXX_Versym);
        }

        memcpy(bytes.data() + shdr_offset + curr_idx * shdr_entry_size, &shdr,
            sizeof(ElfXX_Shdr));
        copySectionBytes(bytes.data() + curr_offset, *it);

        size_t sec_name_length = it->getName().length() + 1;
        memcpy(bytes.data() + curr_shstrtab_offset, it->getName().c_str(),
            sec_name_length);

        if (it->isFlagSet(gtirb::SectionFlag::Loaded) ||
            it->isFlagSet(gtirb::SectionFlag::ThreadLocal)) {
            ElfXX_Phdr phdr;

            phdr.p_type = it->isFlagSet(gtirb::SectionFlag::ThreadLocal)
                              ? PT_TLS
                              : PT_LOAD;
            phdr.p_flags = get_seg_perms(*it);
            phdr.p_offset = curr_offset;
            phdr.p_vaddr = ElfXX_Addr(*maybe_addr);
            phdr.p_paddr = 0;
            phdr.p_filesz = *maybe_size;
            phdr.p_memsz = *maybe_size;
            phdr.p_align = 0;  // Don't care?

            memcpy(bytes.data() + phdr_offset + curr_seg_idx * phdr_entry_size,
                &phdr, sizeof(ElfXX_Phdr));

            curr_seg_idx++;
        }

        curr_offset += *maybe_size;
        curr_shstrtab_offset += sec_name_length;
    }
    assert(curr_offset == shstrtab_offset);

    // Section header for shstrtab
    ElfXX_Shdr shdr;
    shdr.sh_name = curr_shstrtab_offset;
    shdr.sh_type = SHT_STRTAB;
    shdr.sh_flags = 0;
    shdr.sh_addr = 0;
    shdr.sh_offset = shstrtab_offset;
    shdr.sh_size = shstrtab_size;
    shdr.sh_link = 0;       // Don't care.
    shdr.sh_info = 0;       // Don't care.
    shdr.sh_addralign = 0;  // Don't care.
    shdr.sh_entsize = 0;    // Don't care.

    memcpy(bytes.data() + shdr_offset + curr_idx * shdr_entry_size, &shdr,
        sizeof(ElfXX_Shdr));
    memcpy(bytes.data() + curr_shstrtab_offset, shstrtab_name.c_str(),
        shstrtab_name.length() + 1);

    return new ElfMap(std::move(bytes));
}

/**
 * @brief Build the SymbolList for all symbols in the given GTIRB Module.
 *
 * @param module The Module to build the SymbolList for.
 * @return SymbolList*
 */
SymbolList *GtirbDeserializer::buildSymbolList(const gtirb::Module &module) {
    // TODO: The constructor for SymbolList optionally takes an ElfMap.
    // Do we need/want to provide one?
    SymbolList *sym_list = new SymbolList();
    const auto *si_table = module.getAuxData<gtirb::schema::ElfSymbolInfo>();

    for (auto &sym : module.symbols()) {
        auto maybe_addr = sym.getAddress();
        address_t address = maybe_addr ? address_t(*maybe_addr) : 0;
        std::string name = sym.getName();
        size_t size = 0;
        Symbol::SymbolType type = Symbol::SymbolType::TYPE_UNKNOWN;
        Symbol::BindingType bind = Symbol::BindingType::BIND_GLOBAL;
        size_t index = 0;
        size_t shndx = 0;

        auto sym_info_it = si_table->find(sym.getUUID());
        if (sym_info_it != si_table->end()) {
            auto sym_info = sym_info_it->second;
            size = std::get<0>(sym_info);
            type = convertGtirbSymbolType(std::get<1>(sym_info));
            bind = convertGtirbBindingType(std::get<2>(sym_info));
        }

        Symbol *symbol = new Symbol(
            address, size, name.c_str(), type, bind, index, shndx);
        LOG(5, "GTIRB symbol #" << sym_list->getCount() << ", index " << index
                                << ", [" << name.c_str() << "] " << std::hex
                                << address << std::dec << ", type " << type
                                << "\n");
        sym_list->add(symbol, index);
        this->symbol_map.insert(std::make_pair(&sym, symbol));
    }

    return sym_list;
}

/**
 * @brief Build an Egalito function for the given GTIRB notion of function.
 *
 * @param sym_uuid The UUID of the symbol designated as carrying the function's
 * name.
 * @param entries The set of UUIDs of CodeBlocks that are entry points to the
 * function.
 * @param blocks The set of UUIDs of CodeBlocks that make up the body of the
 * function.
 * @return Function* The resulting function.
 */
Function *GtirbDeserializer::buildFunction(gtirb::Module &gtirb_module,
    gtirb::UUID sym_uuid, const std::set<gtirb::UUID> &entries,
    const std::set<gtirb::UUID> &blocks) {
    // Fetch the symbol
    const gtirb::Symbol *sym = dyn_cast<const gtirb::Symbol>(
        gtirb::Node::getByUUID(*this->C, sym_uuid));
    if (!sym) {
        return nullptr;
    }

    // Fetch the address for the function from the symbol
    const gtirb::CodeBlock *entry = sym->getReferent<const gtirb::CodeBlock>();
    auto maybe_addr = entry->getAddress();
    if (!maybe_addr) {
        LOG(1, "Function " << sym->getName() << " has no address. Skipping.");
        return nullptr;
    }
    gtirb::Addr addr = *maybe_addr;
    auto gtirb_sections = gtirb_module.findSectionsOn(addr);
    // If we don't have a section, let's skip for now.
    if (gtirb_sections.begin() == gtirb_sections.end()) {
        LOG(1, "Function " << sym->getName() << " has no section. Skipping.");
        return nullptr;
    }
    const gtirb::Section *gtirb_section = &(*gtirb_sections.begin());
    // Do not add functions in PLT sections
    if (gtirb_section->getName().find(".plt") != std::string::npos) {
        LOG(1, "Function " << sym->getName() << " is in PLT. Skipping.");
        return nullptr;
    }

    Function *function = new Function();
    function->setName(sym->getName());
    function->setPosition(new AbsolutePosition(static_cast<address_t>(addr)));

    // Process the CodeBlocks
    // Note: it appears that Egalito's blocks are linked in address order.
    // It's unclear whether or not it requires this, but we'll follow this
    // pattern by sorting gtirb's CodeBlocks first.
    std::vector<std::pair<address_t, const gtirb::CodeBlock *>> sorted_blocks;
    for (gtirb::UUID block_uuid : blocks) {
        const gtirb::CodeBlock *cb = dyn_cast<const gtirb::CodeBlock>(
            gtirb::Node::getByUUID(*this->C, block_uuid));
        if (!cb) {
            LOG(1, "Function " << sym->getName()
                               << " has invalid CodeBlock. Skipping block.");
            continue;
        }
        auto maybe_addr = cb->getAddress();
        if (!maybe_addr) {
            LOG(1, "Function "
                       << sym->getName()
                       << " has CodeBlock with no address. Skipping block.");
            continue;
        }
        address_t addr = static_cast<address_t>(*maybe_addr);
        sorted_blocks.push_back(std::make_pair(addr, cb));
    }
    std::sort(sorted_blocks.begin(), sorted_blocks.end(),
        [](auto lhs, auto rhs) { return lhs.first < rhs.first; });

    PositionFactory *positionFactory = PositionFactory::getInstance();

    for (auto [addr, gtirb_block] : sorted_blocks) {
        Block *curr_block = new Block();
        curr_block->setPosition(positionFactory->makeAbsolutePosition(addr));

        cs_insn *insn;
        size_t count = cs_disasm(this->cs_handle->raw(),
            gtirb_block->rawBytes<uint8_t>(), gtirb_block->getSize(), addr, 0,
            &insn);

        for (size_t i = 0; i < count; ++i) {
            auto instr = DisassembleInstruction(*this->cs_handle, true)
                             .instruction(&insn[i]);
            instr->setPosition(positionFactory->makeAbsolutePosition(
                addr + curr_block->getSize()));
            ChunkMutator(curr_block, false).append(instr);
        }

        cs_free(insn, count);

        ChunkMutator(function, false).append(curr_block);
    }

    return function;
}

/**
 * @brief Build the init function list.
 *
 * @note This is currently unimplemented.
 *
 * @return InitFunctionList*
 */
InitFunctionList *GtirbDeserializer::buildInitFunctionList() {
    return new InitFunctionList();
}

/**
 * @brief Build the fini function list.
 *
 * @note This is currently unimplemented.
 *
 * @return InitFunctionList*
 */
InitFunctionList *GtirbDeserializer::buildFiniFunctionList() {
    return new InitFunctionList();
}

/**
 * @brief Build the list of data regions covering the module.
 *
 * @param elf_map The ElfMap for the Module.
 * @param module The Egalito Module object.
 */
void GtirbDeserializer::buildDataRegionList(ElfMap *elf_map, Module *module) {
    // This will build the data sections using Egalito's
    // normal process that scans the elf contents. It attaches
    // it directly to the module.
    // Question: do we need to do anything gtirb-specific here?
    DataRegionList::buildDataRegionList(elf_map, module);
    module->getChildren()->add(module->getDataRegionList());
}

/**
 * @brief Build global variables for a module.
 *
 * @param gtirb_module The GTIRB version of the module.
 * @param eg_module The Egalito version of the module.
 */
void GtirbDeserializer::buildGlobalVariables(
    const gtirb::Module &gtirb_module, Module *eg_module) {
    DataRegionList *eg_regions = eg_module->getDataRegionList();
    for (auto it = gtirb_module.sections_begin();
         it != gtirb_module.sections_end(); ++it) {
        // Find the corresponding Egalito section
        std::string sec_name = it->getName();
        DataSection *eg_section = eg_regions->findDataSection(sec_name);
        assert(eg_section && "Should have sections mirrored here!");

        for (auto jt = it->data_blocks_begin(); jt != it->data_blocks_end();
             ++jt) {
            // Address of the block
            auto maybe_addr = jt->getAddress();
            assert(maybe_addr &&
                   "Should have checked already that all ByteIntervals have "
                   "addresses.");
            gtirb::Addr gtirb_addr = *maybe_addr;
            address_t eg_addr = address_t(gtirb_addr);

            // Find the symbol to attach to this block. We'll just take the
            // first symbol associated with it. For later: What to do if there
            // is more than one symbol?
            auto gtirb_symbols = gtirb_module.findSymbols(*jt);

            // If we don't have a symbol, let's skip for now.
            if (gtirb_symbols.begin() == gtirb_symbols.end()) {
                continue;
            }

            const gtirb::Symbol *gtirb_sym = &(*gtirb_symbols.begin());
            auto maybe_eg_symbol = this->symbol_map.find(gtirb_sym);
            assert(maybe_eg_symbol != this->symbol_map.end() &&
                   "All gtirb symbols should have corresponding eg symbols");
            Symbol *eg_symbol = maybe_eg_symbol->second;

            // Create a global variable always.
            GlobalVariable::createSymtab(eg_section, eg_addr, eg_symbol);

            // Do we need to create a DataVariable?
        }
    }
}

/**
 * @brief Build the PLT list.
 *
 * @note This is currently unimplemented.
 *
 * @return PLTList*
 */
PLTList *GtirbDeserializer::buildPLTList() {
    return new PLTList();
}

/**
 * @brief Build code-based links.
 *
 * @note This is a placeholder. Currently code-based links are built by invoking
 * an Egalito pass after deserialization. This is probably less than ideal but
 * currently works well enough.
 */
void GtirbDeserializer::buildCodeLinks() {}

/**
 * @brief Build a link for a SymAddrConst SymbolicExpression.
 *
 * @param conductor The Conductor context for IR construction.
 * @param module The Egalito module.
 * @param sac A SymAddrConst instance representing the symbolic expression for
 * the link.
 */
void GtirbDeserializer::buildLinkForSymAddrConst(
    Conductor *conductor, Module *module, gtirb::SymAddrConst sac) {
    std::optional<address_t> target = std::nullopt;
    auto maybe_addr = sac.Sym->getAddress();
    Function *func = nullptr;
    if (maybe_addr) {
        target = address_t(*maybe_addr);
        func = CIter::spatial(module->getFunctionList())
                   ->findContaining(*target);
        if (func) {
            // FIXME: This probably needs to be expanded to support
            // external references? Also, assumes any data reference
            // is absolute?
            LOG(10, "resolved to a function");
            LinkFactory::makeNormalLink(func, false, false);
        }
        else {
            LOG(1, "Unable to resolve symbolic expression target at: "
                       << std::hex << *target << std::dec);
        }
    }
    else {
        // No address, likely this is an external symbol.
        // See if we can find a function based on the symbol.
        auto find_symbol = this->symbol_map.find(sac.Sym);
        if (find_symbol == this->symbol_map.end()) {
            LOG(1, "Unable to find symbol in gtirb->eg symbol map: "
                       << sac.Sym->getName());
            return;
        }

        PerfectLinkResolver().resolveExternally(
            find_symbol->second, conductor, module, false, false);
    }
}

/**
 * @brief Template magic to support use of std::visit.
 *
 * @tparam Ts
 */
template <class... Ts>
struct overload : Ts... {
    using Ts::operator()...;
};
template <class... Ts>
overload(Ts...)->overload<Ts...>;

/**
 * @brief Build data-based links for a module.
 *
 * @param conductor The conductor context for IR construction.
 * @param gtirb_module The GTIRB version of the module.
 * @param eg_module The Egalito version of the module.
 */
void GtirbDeserializer::buildDataLinks(Conductor *conductor,
    const gtirb::Module &gtirb_module, Module *eg_module) {
    // Traverse all the DataBlocks and see if any have SymbolicExpressions
    // within them.
    DataRegionList *eg_regions = eg_module->getDataRegionList();
    for (auto it = gtirb_module.sections_begin();
         it != gtirb_module.sections_end(); ++it) {
        // Find the corresponding Egalito section
        std::string sec_name = it->getName();
        DataSection *eg_section = eg_regions->findDataSection(sec_name);
        assert(eg_section && "Should have sections mirrored here!");

        for (auto jt = it->data_blocks_begin(); jt != it->data_blocks_end();
             ++jt) {
            const gtirb::ByteInterval *bi = jt->getByteInterval();

            auto maybe_addr = jt->getAddress();
            assert(maybe_addr && "All blocks should have addresses!");
            gtirb::Addr start_addr = *maybe_addr;
            gtirb::Addr end_addr = start_addr + jt->getSize();

            auto ses = bi->findSymbolicExpressionsAt(start_addr, end_addr);
            if (ses.begin() == ses.end()) {
                // No symbolic expressions, skip to the next data block
                continue;
            }

            // Grab the first. TODO: What do we do about the rest?
            // FIXME: Make this a reference when we have a fix in gtirb.
            const gtirb::SymbolicExpression se = ses.begin()
                                                     ->getSymbolicExpression();

            std::visit(overload{[&](const gtirb::SymAddrConst &sac) {
                                    buildLinkForSymAddrConst(
                                        conductor, eg_module, sac);
                                },
                           [&](const gtirb::SymAddrAddr &sac) {
                               // TODO!
                           }},
                se);
        }
    }
}

/**
 * @brief Determine if the given GTIRB file exhibits certain properties needed
 * for Egalito deserialization.
 *
 * @param module The GTIRB module to be deserialized.
 * @return true Deserializable module.
 * @return false Module missing some property that makes it not deserializable.
 *
 * @note This is a gate-keeper function to detect certain problematic constructs
 * that are valid in GTIRB files but that the Egalito importer is not capable
 * of handling.
 */
bool GtirbDeserializer::isLoadableGtirbModule(const gtirb::Module &module) {
    // Do we have addresses on all ByteIntervals. Can be checked
    // just by checking for having a size on all Sections.
    for (auto it = module.sections_begin(); it != module.sections_end(); ++it) {
        if (!it->getSize()) {
            LOG(0,
                "GTIRB Module contains ByteIntervals without addresses "
                "(required by Egalito import.)");
            return false;
        }
    }

    // Do we have all the AuxData we need?
    if (!module.getAuxData<gtirb::schema::FunctionNames>()) {
        LOG(0, "GTIRB missing needed FunctionNames AuxData for Egalito import");
        return false;
    }
    if (!module.getAuxData<gtirb::schema::FunctionEntries>()) {
        LOG(0,
            "GTIRB missing needed FunctionEntries AuxData for Egalito import");
        return false;
    }
    if (!module.getAuxData<gtirb::schema::FunctionBlocks>()) {
        LOG(0,
            "GTIRB missing needed FunctionBlocks AuxData for Egalito import");
        return false;
    }
    if (!module.getAuxData<gtirb::schema::ElfSymbolInfo>()) {
        LOG(0, "GTIRB missing needed ElfSymbolInfo AuxData for Egalito import");
        return false;
    }
    if (!module.getAuxData<gtirb::schema::SectionProperties>()) {
        LOG(0,
            "GTIRB missing needed SectionProperties AuxData for Egalito "
            "import");
        return false;
    }

    return true;
}

/**
 * @brief Add dynamic (.so) library dependences to the Egalito library list.
 *
 * @param module The GTIRB module.
 * @param lib_list The library list to be added to.
 * @param library The library representing the "main" module.
 */
void GtirbDeserializer::addLibDependences(
    const gtirb::Module &module, LibraryList *lib_list, Library *library) {
    // This uses the ElfDynamic utility but avoids calling it's parse() routine,
    // since that requires having populated the dynstrtab section in the ELF
    // map.
    ElfDynamic ed(lib_list);

    // We need to tell ElfDynamic what rpath to use when resolving library
    // names.
    std::string rpath;
    const std::vector<std::string>
        *lib_paths = module.getAuxData<gtirb::schema::LibraryPaths>();
    std::filesystem::path binpath = module.getBinaryPath();
    std::filesystem::path bindir = binpath.parent_path();
    bool using_cwd = false;
    if (bindir == "") {
        bindir = std::filesystem::current_path();
        using_cwd = true;
    }

    for (auto p : *lib_paths) {
        // Egalito expects $ORIGIN to be resolved.
        if (rpath.size() > 0) {
            rpath.push_back(':');
        }

        size_t pos = p.find("$ORIGIN");
        if (pos != p.npos) {
            std::string scratch = p;
            scratch.replace(pos, strlen("$ORIGIN"), bindir);
            if (using_cwd) {
                LOG(1,
                    "Note: no binary path information, using cwd for $ORIGIN "
                    "in rpath");
            }
            rpath.append(scratch);
        }
        else {
            rpath.append(p);
        }
    }
    ed.setRPath(rpath);

    const std::vector<std::string>
        *gtirb_libs = module.getAuxData<gtirb::schema::Libraries>();
    for (const std::string &dep : *gtirb_libs) {
        ed.addDependency(library, dep);
    }
}

Program *GtirbDeserializer::deserialize(Conductor *conductor) {
    LOG(1, "GTIRB deserialization");
    register_gtirb_auxdata();

    if (!this->ir) {
        this->preParse();
        if (!this->ir) {
            LOG(1, "Failed to load GTIRB IR in file " << this->filename);
            return nullptr;
        }
    }

    // Translate IR to Egalito...

    // Note: doing this for single Module IR's at present. Need to
    // expand to multi-Module IR's at some point.
    if (this->ir->modules_begin() == this->ir->modules_end()) {
        LOG(1, "GTIRB IR has no modules: " << this->filename);
        return nullptr;
    }
    gtirb::Module &gtirb_module = *this->ir->modules_begin();

    // Check that the IR is something we support loading
    // Note that we require certain things like having addresses
    // attached to all ByteIntervals.
    if (!isLoadableGtirbModule(gtirb_module)) {
        LOG(1, "GTIRB IR not supported by Egalito: " << this->filename);
        return nullptr;
    }

    Program *program = new Program();
    LibraryList *lib_list = new LibraryList();
    program->setLibraryList(lib_list);

    // Initialize our capstone engine handle for this ir.
    gtirb::ISA isa = gtirb_module.getISA();

    // Note: Egalito is conditionally compiled specifically
    // for the ISA it's intended to target. Until we change
    // to support multiple ISAs dynamically, we have to
    // bomb out of here anytime we trying processing a gtirb
    // file for an ISA that this wasn't compiled for.
#ifdef ARCH_X86_64
    if (isa != gtirb::ISA::X64) {
        LOG(1, "Egalito is compiled to only work for x64 binaries!");
        return nullptr;
    }
#elif defined(ARCH_AARCH64)
    if (isa != gtirb::ISA::ARM64) {
        LOG(1, "Egalito is compiled to only work for arm64 binaries!");
        return nullptr;
    }
#elif defined(ARCH_ARM)
    if (isa != gtirb::ISA::ARM) {
        LOG(1, "Egalito is compiled to only work for arm32 binaries!");
        return nullptr;
    }
#endif

    // The DisasmHandle constructor can potentially throw an exception
    try {
        this->cs_handle = new DisasmHandle(true);
    }
    catch (...) {
        LOG(1, "Failed to allocate capstone engine!");
    }

    // Create a Library for the module
    Library::Role role = Library::ROLE_MAIN;
    auto library = new Library(
        Library::determineInternalName(gtirb_module.getName(), role), role);
    library->setResolvedPath(gtirb_module.getBinaryPath());
    program->add(library);

    // Create the Module
    Module *eg_module = new Module();
    eg_module->setName("module-" + gtirb_module.getName());
    program->add(eg_module);
    eg_module->setParent(program);
    eg_module->setLibrary(library);
    library->setModule(eg_module);
    FunctionList *functionList = new FunctionList();
    eg_module->getChildren()->add(functionList);
    eg_module->setFunctionList(functionList);
    functionList->setParent(eg_module);

    // Create a stand-in for the original ELF file and build the elfmap.
    ElfMap *elf_map = buildElfMap(gtirb_module);

    // Create an elfspace for the module
    // Question: how much does it need to be populated?
    ElfSpace *elf_space = new ElfSpace(
        elf_map, gtirb_module.getName(), gtirb_module.getBinaryPath());
    eg_module->setElfSpace(elf_space);
    elf_space->setModule(eg_module);

    // Build the list of symbols
    SymbolList *sym_list = buildSymbolList(gtirb_module);
    elf_space->setSymbolList(sym_list);

    // Add functions
    auto func_names = gtirb_module.getAuxData<gtirb::schema::FunctionNames>();
    auto func_entries = gtirb_module
                            .getAuxData<gtirb::schema::FunctionEntries>();
    auto func_blocks = gtirb_module.getAuxData<gtirb::schema::FunctionBlocks>();
    if (func_names && func_entries && func_blocks) {
        for (const auto &[func_uuid, blocks] : *func_blocks) {
            auto maybe_name = func_names->find(func_uuid);
            if (maybe_name == func_names->end()) {
                // TODO: Perhaps synthesize a name here?
                gtirb::UUID uuid = func_uuid;
                LOG(1, "Missing func name for function uuid: "
                           << uuid << " - skipping!");
                continue;
            }
            const gtirb::UUID sym_uuid = maybe_name->second;

            auto maybe_entries = func_entries->find(func_uuid);
            if (maybe_entries == func_entries->end()) {
                // TODO: Perhaps synthesize a name here?
                gtirb::UUID uuid = func_uuid;
                LOG(1, "Missing func name for function uuid: "
                           << uuid << " - skipping!");
                continue;
            }
            const std::set<gtirb::UUID> entries = maybe_entries->second;

            Function *func = buildFunction(
                gtirb_module, sym_uuid, entries, blocks);
            if (!func) {
                continue;
            }

            functionList->getChildren()->add(func);
            func->setParent(functionList);
            if (func->getName() == "_start") {
                program->setEntryPoint(func);
            }
            LOG(1, "adding function " << func->getName() << " at " << std::hex
                                      << func->getAddress() << " size "
                                      << func->getSize());
        }
    }
    else {
        LOG(1, "Missing function information in GTIRB file: " << filename);
    }

    // init/fini function lists
    InitFunctionList *init_func_list = buildInitFunctionList();
    eg_module->setInitFunctionList(init_func_list);

    InitFunctionList *fini_func_list = buildFiniFunctionList();
    eg_module->setFiniFunctionList(fini_func_list);

    // Data
    buildDataRegionList(elf_map, eg_module);
    buildGlobalVariables(gtirb_module, eg_module);

    // PLT
    PLTList *plt_list = buildPLTList();
    eg_module->setPLTList(plt_list);

    // Now go back over and build cross-links
    buildCodeLinks();
    buildDataLinks(conductor, gtirb_module, eg_module);

    // Add dependent libraries
    addLibDependences(gtirb_module, lib_list, library);

    delete this->cs_handle;

    return program;
}
