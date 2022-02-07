#include "gtirb_deserializer.h"
#include "gtirb_util.h"

#include "chunk/dataregion.h"
#include "chunk/function.h"
#include "chunk/library.h"
#include "chunk/module.h"
#include "chunk/plt.h"
#include "chunk/program.h"
#include "disasm/disassemble.h"
#include "disasm/handle.h"
#include "elf/elfspace.h"
#include "elf/symbol.h"
#include "gtirb/gtirb.hpp"
#include "log/log.h"
#include "operation/mutator.h"

#include <capstone/capstone.h>
#include <cstddef>
#include <fstream>
#include <boost/uuid/uuid_io.hpp>

GtirbDeserializer::GtirbDeserializer(std::string filename)
    : filename(filename), C(new gtirb::Context()), ir(nullptr)
{
}

GtirbDeserializer::~GtirbDeserializer() = default;

bool GtirbDeserializer::preParse()
{
    register_gtirb_auxdata();

    std::ifstream in(this->filename, std::ios::in | std::ios::binary);
    if (!in.is_open())
    {
        return false;
    }

    auto err_or_ir = gtirb::IR::load(*this->C, in);
    if (err_or_ir)
    {
        this->ir = *err_or_ir;
        return true;
    }
    else
    {
        return false;
    }
}

Symbol::SymbolType convertGtirbSymbolType(std::string gtirb_sym_type)
{
    using ST = Symbol::SymbolType;

    // There are other types not listed here, but ddisasm
    // doesn't seem to produce them.
    // Specifically: TYPE_SECTION, TYPE_FILE
    static const std::unordered_map<std::string, Symbol::SymbolType>
        type_name_conversion = {
            {"FUNC", ST::TYPE_FUNC},
            {"OBJECT", ST::TYPE_OBJECT},
            {"NOTYPE", ST::TYPE_NOTYPE},
            {"NONE", ST::TYPE_NOTYPE},
            {"TLS", ST::TYPE_TLS},
            {"GNU_IFUNC", ST::TYPE_IFUNC},
        };
    auto it = type_name_conversion.find(gtirb_sym_type);
    if (it == type_name_conversion.end())
    {
        std::cerr << "Unhandled symbol type: " << gtirb_sym_type << "\n";
        return ST::TYPE_UNKNOWN;
    }
    else
    {
        return it->second;
    }
}

Symbol::BindingType convertGtirbBindingType(std::string gtirb_bind_type)
{
    using BT = Symbol::BindingType;

    static const std::unordered_map<std::string, Symbol::BindingType>
        type_name_conversion = {
            {"LOCAL", BT::BIND_LOCAL},
            {"GLOBAL", BT::BIND_GLOBAL},
            {"WEAK", BT::BIND_WEAK},
            {"UNIQUE", BT::BIND_GLOBAL},     // ?
            {"GNU_UNIQUE", BT::BIND_GLOBAL}, // ?
        };
    auto it = type_name_conversion.find(gtirb_bind_type);
    if (it == type_name_conversion.end())
    {
        std::cerr << "Unhandled binding type: " << gtirb_bind_type << "\n";
        return BT::BIND_GLOBAL;
    }
    else
    {
        return it->second;
    }
}

static size_t gtirb_isa_to_machine(gtirb::ISA isa)
{
    switch (isa)
    {
    case gtirb::ISA::X64:
        return EM_X86_64;
    case gtirb::ISA::ARM:
        return EM_ARM;
    default:
    {
        assert(false && "Unsupported ISA");
        return EM_NONE;
    }
    }
}

static void copySectionBytes(std::byte *dest, const gtirb::Section &section)
{
    auto maybe_sec_addr = section.getAddress();
    assert(maybe_sec_addr && "All ByteIntervals must have addresses!");
    size_t sec_addr = size_t(*maybe_sec_addr);

    // Note: this assumes that the ByteIntervals have non-overlapping ranges.
    for (auto it = section.byte_intervals_begin(); it != section.byte_intervals_end(); ++it)
    {
        auto maybe_bi_addr = it->getAddress();
        assert(maybe_bi_addr && "All ByteIntervals must have addresses!");
        size_t bi_addr = size_t(*maybe_bi_addr);

        memcpy(dest + (bi_addr - sec_addr), it->rawBytes<std::byte>(), it->getInitializedSize());
    }
}

static const std::string shstrtab_name = ".shstrtab";

ElfMap *GtirbDeserializer::buildElfMap(const gtirb::Module &module)
{
    // We don't have the actual ELF file. This attempts to re-construct enough of one
    // that Egalito is happy with its contents and can get what it needs.

    // First determine size needed and where everything needs to go.

    // Program header table. GTIRB doesn't have this info. For now
    // we'll try to get by w/ having no segments.
    // It should start right after the main header.
    size_t phdr_offset = sizeof(ElfXX_Ehdr);
    size_t phdr_entry_size = sizeof(ElfXX_Phdr);
    size_t phdr_num = 0;
    size_t phdr_size = phdr_entry_size * phdr_num;

    // Where sections begin
    size_t secs_offset = phdr_offset + phdr_size;
    size_t num_sections = 0; // Not including shstrtab!
    size_t tot_section_bytes = 0;
    std::optional<size_t> shstrtab_idx;
    size_t shstrtab_size = 1; // Inlcudes a start null byte.
    size_t curr_idx = 0;
    for (auto it = module.sections_begin(); it != module.sections_end(); ++curr_idx, ++it)
    {
        // Ignore any .shstrtab section. We're going to rebuild
        // our own no matter what.
        if (it->getName() == shstrtab_name)
        {
            continue;
        }

        ++num_sections;
        auto maybe_size = it->getSize();
        assert(maybe_size && "Should only reach here if isLoadableGtirbModule() has confirmed all sections have a size.");
        tot_section_bytes += *maybe_size;
        shstrtab_size += it->getName().length() + 1;
    }

    // .shstrtab section
    shstrtab_size += shstrtab_name.length() + 1;
    size_t shstrtab_offset = secs_offset + tot_section_bytes;

    // Section header table.
    size_t shdr_offset = shstrtab_offset + shstrtab_size;
    size_t shdr_entry_size = sizeof(ElfXX_Shdr);
    size_t shdr_size = shdr_entry_size * (num_sections + 1);

    // Full sized, zero-initialized chunk of memory.
    size_t map_size = sizeof(ElfXX_Ehdr) + phdr_size + tot_section_bytes + shstrtab_size + shdr_size;
    std::vector<std::byte> bytes(map_size);

    // Main ELF Header
    gtirb::ISA isa = module.getISA();
    ElfXX_Ehdr header;
    header.e_ident[EI_MAG0] = ELFMAG0;
    header.e_ident[EI_MAG1] = ELFMAG1;
    header.e_ident[EI_MAG2] = ELFMAG2;
    header.e_ident[EI_MAG3] = ELFMAG3;
    header.e_ident[EI_CLASS] = ELFCLASSXX;
    header.e_ident[EI_DATA] = ELFDATA2LSB; // TODO: Account for endianness
    header.e_ident[EI_VERSION] = EV_CURRENT;
    header.e_ident[EI_OSABI] = ELFOSABI_NONE;
    header.e_ident[EI_ABIVERSION] = 0;
    header.e_type = ELFCLASSXX;
    header.e_machine = gtirb_isa_to_machine(isa);
    header.e_version = EV_CURRENT;

    const gtirb::CodeBlock *entry = module.getEntryPoint();
    if (entry)
    {
        auto maybe_addr = entry->getAddress();
        assert(maybe_addr && "All ByteIntervals should have addresses!");
        header.e_entry = ElfXX_Addr(*maybe_addr);
    }
    else
    {
        header.e_entry = 0;
    }

    header.e_phoff = phdr_offset;
    header.e_shoff = shdr_offset;
    header.e_flags = 0; // Unnecessary for our purposes?
    header.e_ehsize = sizeof(ElfXX_Ehdr);
    header.e_phentsize = phdr_entry_size;
    header.e_phnum = phdr_num;
    header.e_shentsize = shdr_entry_size;
    header.e_shnum = num_sections + 1;
    header.e_shstrndx = num_sections;

    memcpy(bytes.data(), &header, sizeof(ElfXX_Ehdr));

    // Assumes iteration order is the same as the iteration above.
    curr_idx = 0;
    size_t curr_offset = secs_offset;
    size_t curr_shstrtab_offset = shstrtab_offset + 1; // Index 0 should already be 0
    for (auto it = module.sections_begin(); it != module.sections_end(); ++curr_idx, ++it)
    {
        if (it->getName() == ".shstrtab")
        {
            continue;
        }

        ElfXX_Shdr shdr;
        shdr.sh_name = curr_shstrtab_offset;
        shdr.sh_type = 0;  // TODO!
        shdr.sh_flags = 0; // TODO!

        auto maybe_addr = it->getAddress();
        assert(maybe_addr && "All ByteIntervals should have addresses!");
        shdr.sh_addr = ElfXX_Addr(*maybe_addr);

        shdr.sh_offset = curr_offset;

        auto maybe_size = it->getSize();
        assert(maybe_size && "Should only reach here if isLoadableGtirbModule() has confirmed all sections have a size.");
        shdr.sh_size = *maybe_size;

        shdr.sh_link = 0;      // Don't care.
        shdr.sh_info = 0;      // Don't care.
        shdr.sh_addralign = 0; // Don't care?
        shdr.sh_entsize = 0;   // Don't care?

        memcpy(bytes.data() + shdr_offset + curr_idx * shdr_entry_size, &shdr, sizeof(ElfXX_Shdr));
        copySectionBytes(bytes.data() + curr_offset, *it);

        size_t sec_name_length = it->getName().length() + 1;
        memcpy(bytes.data() + curr_shstrtab_offset, it->getName().c_str(), sec_name_length);

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
    shdr.sh_link = 0;      // Don't care.
    shdr.sh_info = 0;      // Don't care.
    shdr.sh_addralign = 0; // Don't care.
    shdr.sh_entsize = 0;   // Don't care.

    memcpy(bytes.data() + shstrtab_offset, &shdr, sizeof(ElfXX_Shdr));
    memcpy(bytes.data() + curr_shstrtab_offset, shstrtab_name.c_str(), shstrtab_name.length() + 1);

    return new ElfMap(std::move(bytes));
}

SymbolList *GtirbDeserializer::buildSymbolList(const gtirb::Module &module)
{
    // TODO: The constructor for SymbolList optionally takes an ElfMap.
    // Do we need/want to provide one?
    SymbolList *sym_list = new SymbolList();
    const auto *si_table = module.getAuxData<gtirb::schema::ElfSymbolInfo>();

    for (auto &sym : module.symbols())
    {
        auto maybe_addr = sym.getAddress();
        address_t address = maybe_addr ? address_t(*maybe_addr) : 0;
        std::string name = sym.getName();
        size_t size = 0;
        Symbol::SymbolType type = Symbol::SymbolType::TYPE_UNKNOWN;
        Symbol::BindingType bind = Symbol::BindingType::BIND_GLOBAL;
        size_t index = 0;
        size_t shndx = 0;

        auto sym_info_it = si_table->find(sym.getUUID());
        if (sym_info_it != si_table->end())
        {
            auto sym_info = sym_info_it->second;
            size = std::get<0>(sym_info);
            type = convertGtirbSymbolType(std::get<1>(sym_info));
            bind = convertGtirbBindingType(std::get<2>(sym_info));
        }

        Symbol *symbol = new Symbol(address, size, name.c_str(), type, bind, index, shndx);
        LOG(5, "GTIRB symbol #" << sym_list->getCount()
                                << ", index " << index
                                << ", [" << name.c_str()
                                << "] " << std::hex << address << std::dec
                                << ", type " << type << "\n");
        sym_list->add(symbol, index);
    }

    return sym_list;
}

// Note: This function is copied from <egalito>/src/disasm/disassemble.cpp.
// It's not clear how easy it would be to refactor to avoid the copy, given it's a protected
// member function of the DisassembleFunctionBase. Possibly the thing
// to do would be to make a local derived class of DisassembleFunctionBase that
// gives us access to this?
static Block *makeBlock(Function *function, Block *prev)
{
    PositionFactory *positionFactory = PositionFactory::getInstance();

    if (prev == nullptr)
    {
        if (function->getChildren()->getIterable()->getCount() > 0)
        {
            prev = function->getChildren()->getIterable()->getLast();
        }
    }
    Block *block = new Block();
    block->setPosition(
        positionFactory->makePosition(prev, block,
                                      function->getSize()));
    return block;
}

Function *GtirbDeserializer::buildFunction(gtirb::UUID sym_uuid, const std::set<gtirb::UUID> &entries, const std::set<gtirb::UUID> &blocks)
{
    // Fetch the symbol
    const gtirb::Symbol *sym = dyn_cast<const gtirb::Symbol>(gtirb::Node::getByUUID(*this->C, sym_uuid));
    if (!sym)
    {
        return nullptr;
    }

    // Fetch the address for the function from the symbol
    const gtirb::CodeBlock *entry = sym->getReferent<const gtirb::CodeBlock>();
    auto maybe_addr = entry->getAddress();
    if (!maybe_addr)
    {
        LOG(1, "Function " << sym->getName() << " has no address. Skipping.");
        return nullptr;
    }
    gtirb::Addr addr = *maybe_addr;

    Function *function = new Function();
    function->setName(sym->getName());
    function->setPosition(new AbsolutePosition(static_cast<address_t>(addr)));

    // Process the CodeBlocks
    // Note: it appears that Egalito's blocks are linked in address order.
    // It's unclear whether or not it requires this, but we'll follow this pattern
    // by sorting gtirb's CodeBlocks first.
    std::vector<std::pair<address_t, const gtirb::CodeBlock *>> sorted_blocks;
    for (gtirb::UUID block_uuid : blocks)
    {
        const gtirb::CodeBlock *cb = dyn_cast<const gtirb::CodeBlock>(gtirb::Node::getByUUID(*this->C, block_uuid));
        if (!cb)
        {
            LOG(1, "Function " << sym->getName() << " has invalid CodeBlock. Skipping block.");
            continue;
        }
        auto maybe_addr = cb->getAddress();
        if (!maybe_addr)
        {
            LOG(1, "Function " << sym->getName() << " has CodeBlock with no address. Skipping block.");
            continue;
        }
        address_t addr = static_cast<address_t>(*maybe_addr);
        sorted_blocks.push_back(std::make_pair(addr, cb));
    }
    std::sort(sorted_blocks.begin(), sorted_blocks.end(),
              [](auto lhs, auto rhs)
              { return lhs.first < rhs.first; });

    Block *prev = nullptr;
    PositionFactory *positionFactory = PositionFactory::getInstance();

    for (auto [addr, gtirb_block] : sorted_blocks)
    {
        Block *curr_block = makeBlock(function, prev);

        cs_insn *insn;
        size_t count = cs_disasm(this->cs_handle->raw(),
                                 gtirb_block->rawBytes<uint8_t>(),
                                 gtirb_block->getSize(), addr, 0, &insn);

        for (size_t i = 0; i < count; ++i)
        {

            auto instr = DisassembleInstruction(*this->cs_handle, true).instruction(&insn[i]);

            Chunk *prevChunk = nullptr;
            if (curr_block->getChildren()->getIterable()->getCount() > 0)
            {
                prevChunk = curr_block->getChildren()->getIterable()->getLast();
            }
            else if (function->getChildren()->getIterable()->getCount() > 0)
            {
                prevChunk = function->getChildren()->getIterable()->getLast();
            }
            else
            {
                prevChunk = nullptr;
            }
            instr->setPosition(
                positionFactory->makePosition(prevChunk, instr, curr_block->getSize()));
            ChunkMutator(curr_block, false).append(instr);
        }

        cs_free(insn, count);

        ChunkMutator(function, false).append(curr_block);
        prev = curr_block;
    }

    return function;
}

InitFunctionList *GtirbDeserializer::buildInitFunctionList()
{
    return new InitFunctionList();
}

InitFunctionList *GtirbDeserializer::buildFiniFunctionList()
{
    return new InitFunctionList();
}

DataRegionList *GtirbDeserializer::buildDataRegionList()
{
    return new DataRegionList();
}

PLTList *GtirbDeserializer::buildPLTList()
{
    return new PLTList();
}

bool GtirbDeserializer::isLoadableGtirbModule(const gtirb::Module &module)
{
    // Do we have addresses on all ByteIntervals. Can be checked
    // just by checking for having a size on all Sections.
    for (auto it = module.sections_begin(); it != module.sections_end(); ++it)
    {
        if (!it->getSize())
        {
            LOG(1, "GTIRB Module contains ByteIntervals without addresses (required by Egalito import.)");
            return false;
        }
    }

    return true;
}

/** Returns the root of the deserialized tree. */
Program *GtirbDeserializer::deserialize()
{
    LOG(1, "GTIRB deserialization");
    register_gtirb_auxdata();

    if (!this->ir)
    {
        this->preParse();
        if (!this->ir)
        {
            LOG(1, "Failed to load GTIRB IR in file " << this->filename);
            return nullptr;
        }
    }

    // Translate IR to Egalito...

    // Note: doing this for single Module IR's at present. Need to
    // expand to multi-Module IR's at some point.
    if (this->ir->modules_begin() == this->ir->modules_end())
    {
        LOG(1, "GTIRB IR has no modules: " << this->filename);
        return nullptr;
    }
    gtirb::Module &gtirb_module = *this->ir->modules_begin();

    // Check that the IR is something we support loading
    // Note that we require certain things like having addresses
    // attached to all ByteIntervals.
    if (!isLoadableGtirbModule(gtirb_module))
    {
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
    if (isa != gtirb::ISA::X64)
    {
        LOG(1, "Egalito is compiled to only work for x64 binaries!");
        return nullptr;
    }
#elif defined(ARCH_AARCH64)
    if (isa != gtirb::ISA::ARM64)
    {
        LOG(1, "Egalito is compiled to only work for arm64 binaries!");
        return nullptr;
    }
#elif defined(ARCH_ARM)
    if (isa != gtirb::ISA::ARM)
    {
        LOG(1, "Egalito is compiled to only work for arm32 binaries!");
        return nullptr;
    }
#endif

    // The DisasmHandle constructor can potentially throw an exception
    try
    {
        this->cs_handle = new DisasmHandle(true);
    }
    catch (...)
    {
        LOG(1, "Failed to allocate capstone engine!");
    }

    // Create a Library for the module
    auto library = new Library(gtirb_module.getName(), Library::ROLE_MAIN);
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
    ElfSpace *elf_space = new ElfSpace(elf_map, gtirb_module.getName(), gtirb_module.getBinaryPath());
    eg_module->setElfSpace(elf_space);
    elf_space->setModule(eg_module);

    // Build the list of symbols
    SymbolList *sym_list = buildSymbolList(gtirb_module);
    elf_space->setSymbolList(sym_list);

    // Add functions
    auto func_names = gtirb_module.getAuxData<gtirb::schema::FunctionNames>();
    auto func_entries = gtirb_module.getAuxData<gtirb::schema::FunctionEntries>();
    auto func_blocks = gtirb_module.getAuxData<gtirb::schema::FunctionBlocks>();
    if (func_names && func_entries && func_blocks)
    {
        for (const auto &[func_uuid, blocks] : *func_blocks)
        {

            auto maybe_name = func_names->find(func_uuid);
            if (maybe_name == func_names->end())
            {
                // TODO: Perhaps synthesize a name here?
                gtirb::UUID uuid = func_uuid;
                LOG(1, "Missing func name for function uuid: " << uuid << " - skipping!");
                continue;
            }
            const gtirb::UUID sym_uuid = maybe_name->second;

            auto maybe_entries = func_entries->find(func_uuid);
            if (maybe_entries == func_entries->end())
            {
                // TODO: Perhaps synthesize a name here?
                gtirb::UUID uuid = func_uuid;
                LOG(1, "Missing func name for function uuid: " << uuid << " - skipping!");
                continue;
            }
            const std::set<gtirb::UUID> entries = maybe_entries->second;

            Function *func = buildFunction(sym_uuid, entries, blocks);
            if (!func)
            {
                continue;
            }

            functionList->getChildren()->add(func);
            func->setParent(functionList);
            LOG(1, "adding function " << func->getName()
                                      << " at " << std::hex << func->getAddress()
                                      << " size " << func->getSize());
        }
    }
    else
    {
        LOG(1, "Missing function information in GTIRB file: " << filename);
    }

    // init/fini function lists
    InitFunctionList *init_func_list = buildInitFunctionList();
    eg_module->setInitFunctionList(init_func_list);

    InitFunctionList *fini_func_list = buildFiniFunctionList();
    eg_module->setFiniFunctionList(fini_func_list);

    // Data
    DataRegionList *data_regions = buildDataRegionList();
    eg_module->setDataRegionList(data_regions);

    // PLT
    PLTList *plt_list = buildPLTList();
    eg_module->setPLTList(plt_list);

    delete this->cs_handle;

    return program;
}
