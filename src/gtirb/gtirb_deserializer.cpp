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

SymbolList *GtirbDeserializer::buildSymbolList(gtirb::Module &module)
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

InitFunctionList *GtirbDeserializer::buildInitFunctionList() {
    return new InitFunctionList();
}

InitFunctionList *GtirbDeserializer::buildFiniFunctionList() {
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

    Program *program = new Program();
    program->setLibraryList(new LibraryList());

    gtirb::Module &gtirb_module = *this->ir->modules_begin();

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
    auto library = new Library("(executable)", Library::ROLE_MAIN);
    library->setResolvedPath(gtirb_module.getBinaryPath());
    program->add(library);

    // TODO: Load the bytes?

    // Create the Module
    Module *eg_module = new Module();
    eg_module->setName("module-" + gtirb_module.getName());
    program->add(eg_module);
    eg_module->setParent(program);
    eg_module->setLibrary(library);
    FunctionList *functionList = new FunctionList();
    eg_module->getChildren()->add(functionList);
    eg_module->setFunctionList(functionList);
    functionList->setParent(eg_module);

    // Build the list of symbols
    SymbolList *sym_list = buildSymbolList(gtirb_module);

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
