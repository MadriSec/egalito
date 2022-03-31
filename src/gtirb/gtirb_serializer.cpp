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

#include "disasm/makesemantic.h"

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

/// \brief Auxiliary data that includes names of necessary libraries.
struct Libraries {
    static constexpr const char *Name = "libraries";
    typedef std::vector<std::string> Type;
};

/// \brief Auxiliary data that includes names of necessary library paths.
struct LibraryPaths {
    static constexpr const char *Name = "libraryPaths";
    typedef std::vector<std::string> Type;
};

/// \brief Auxiliary data describing a binary's type.
struct BinaryType {
    static constexpr const char *Name = "binaryType";
    typedef std::vector<std::string> Type;
};
}
}

std::string eSymTypeStr(Symbol::SymbolType eSymType) {
    switch (eSymType) {
        case Symbol::TYPE_NOTYPE:
            return "NONE";
        case Symbol::TYPE_IFUNC:
            // TODO: Is this correct, that "IFUNC" is "FUNC"?
            return "FUNC";
        case Symbol::TYPE_FUNC:
            return "FUNC";
        case Symbol::TYPE_OBJECT:
            return "OBJECT";
        case Symbol::TYPE_SECTION:
            return "SECTION";
        case Symbol::TYPE_FILE:
            return "FILE";
        case Symbol::TYPE_TLS:
            return "TLS";
        case Symbol::TYPE_UNKNOWN:
            return "UNKNOWN";
        default:
            throw(std::runtime_error("Unknown symbol type"));
    }
}

std::string eSymBindingStr(Symbol::BindingType eBindType) {
    switch (eBindType) {
        case Symbol::BIND_LOCAL:
            return "LOCAL";
        case Symbol::BIND_GLOBAL:
            return "GLOBAL";
        case Symbol::BIND_WEAK:
            return "WEAK";
        default:
            throw(std::runtime_error("Unknown bind type"));
    }
}

/**
 * @brief When called, generates a new unique identifier for gtirb objects
 */
boost::uuids::random_generator generateUUID;

/**
 * @brief Serialize chunk hierarchy to gtirb using visitor pattern
 *
 * TODO: I'm not certain that actually using the egalito visitor makes sense
 * here. It ensures that we cover all the types that egalito thinks we should
 * visit, but it might be better to explicitly visit a single type at a time,
 * which eliminates the need for the double-dispatch and simplifies the code a
 * bit.
 */
class ChunkSerializer : public ChunkVisitor {
protected:
    /// \brief The context used to generate and track gtirb objects
    gtirb::Context &C;
    /// \brief The IR into which the binary is serialized
    gtirb::IR &ir;

    // For debugging:
    // chunk hierarchy logged to this file
    std::ostream *chunklog;
    // Used to format hierarchy in chunklog
    int chunk_depth = 0;

    /**
     * @brief Visit chunks stored in standard iterators
     */
    template <typename ChildT, typename IterT>
    void recurse(IterT &parent) {
        chunk_depth += 1;
        for (ChildT child : parent) {
            visit(child);
            // child->accept(this);
        }
        chunk_depth -= 1;
    }

    /**
     * @brief Recursively visit chunks stored in egalito structures
     * Specifying child type explicitly not necessary,
     * it is only for readability.
     */
    template <typename ChildT = Chunk *, typename ParentT>
    void recurse(ParentT *parent) {
        if (!parent) {
            return;
        }
        chunk_depth += 1;
        for (ChildT child : CIter::children(parent)) {
            child->accept(this);
        }
        chunk_depth -= 1;
    }

    /**
     * @brief Log strings into the 'chunklog' file.
     * These strings are indented with the chunk hierarchy
     * (assuming that 'recurse' is used)
     * which makes for a bit easier tracking of the nesting
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
     * for egalito (eCtx) and gtirb (gCtx) as decending the chunk hierarchy.
     *
     * There's probably a better structure to keep track of this information,
     * e.g:
     * - using a stack that has these structures nested
     * - using a closure or RAII to automatically unset these values after
     * traversal
     * - *NOT* using the visitor pattern, which could make RAII a bit simpler as
     * context can be passed as an argument to downstream function calls.
     *
     * eCtx and gCtx are only kept separate because it simplified namespaces
     * and made it clearer which type of structure was being referred to
     * (egalito/gtirb) without having the 'g/e' prefix before each field
     */
    struct {
        Program *program;
        Module *module;
        Function *function;
        DataRegion *region;
        DataSection *section;
        JumpTable *jtable;
    } eCtx;

    struct {
        gtirb::Module *module;
        gtirb::ByteInterval *byteInterval;
        gtirb::CodeBlock *codeBlock;
        gtirb::Section *section;
        std::optional<gtirb::UUID> functionId = std::nullopt;

        // Originally this was just a place to store gtirb-related context while
        // traversing But dependence on the module context made it a reasonable
        // place to put aux data addition. The helper functions here all depend
        // on 'module' being set properly

        /**
         * @brief Generate a UUID for a symbol that is registered as a function
         * in gtirb's auxData
         *
         * @param symbol A symbol that points to a function
         * @return gtirb::UUID The UUID for the function identifier in gtirb's
         * aux data
         */
        gtirb::UUID assignFunctionId(gtirb::Symbol *symbol) {
            assert(module);
            gtirb::UUID functionId = generateUUID();
            auto &funcNames = *(
                module->getAuxData<gtirb::schema::FunctionNames>());
            funcNames[functionId] = symbol->getUUID();
            return functionId;
        }

        /**
         * @brief Add a gtirb codeBlock to the set of blocks associated with the
         * current functionId
         *
         * @param codeBlock A code block to be associated with the currently set
         * functionId
         */
        void addBlockToFunction(gtirb::CodeBlock *codeBlock) {
            assert(module);
            assert(functionId);
            // Blocks must be added in order
            auto &funcBlocks =
                *module->getAuxData<gtirb::schema::FunctionBlocks>();
            funcBlocks[*functionId].emplace(codeBlock->getUUID());
            auto &funcEntry =
                *module->getAuxData<gtirb::schema::FunctionEntries>();
            if (funcEntry[*functionId].empty()) {
                funcEntry[*functionId].emplace(codeBlock->getUUID());
            }
        }

        /**
         * @brief Add aux data signaling symbol forwarding from src to dst
         *
         * @param src The source symbol in the symbol forwarding entry
         * @param dst The destination symbol in the symbol forwarding entry
         */
        void addSymbolForwarding(gtirb::Symbol *src, gtirb::Symbol *dst) {
            assert(module);
            auto &forwarding =
                *module->getAuxData<gtirb::schema::SymbolForwarding>();
            forwarding[src->getUUID()] = dst->getUUID();
        }

        /**
         * @brief Add elf symbol info to the aux data associated with a gtirb
         * symbol
         */
        void addSymbolInfo(gtirb::Symbol *gSymbol, uint64_t size,
            std::string type, std::string binding = "GLOBAL",
            std::string visibility = "DEFAULT", uint64_t section_idx = 0) {
            assert(module);
            auto &auxInfo = *module
                                 ->getAuxData<gtirb::schema::ElfSymbolInfoAD>();
            auxInfo[gSymbol->getUUID()] = ElfSymbolInfo{
                size, type, binding, visibility, section_idx};
        }

        /**
         * @brief Add a library as a dependency of the current module
         */
        void addLibrary(std::string libraryName) {
            assert(module);
            auto &libraries = *module->getAuxData<gtirb::schema::Libraries>();
            libraries.push_back(libraryName);
        }

        /**
         * @brief Add a library search path for the current module
         */
        void addLibraryPath(std::string libraryPath) {
            assert(module);

            auto &libraryPaths =
                *module->getAuxData<gtirb::schema::LibraryPaths>();
            libraryPaths.push_back(libraryPath);
        }

        void setBinaryType(ElfMap *elfMap) {
            assert(module);
            auto &binType = *module->getAuxData<gtirb::schema::BinaryType>();
            if (elfMap->isExecutable()) {
                binType.push_back("EXEC");
            }
            if (elfMap->isSharedLibrary()) {
                binType.push_back("DYN");
            }
            if (elfMap->isObjectFile()) {
                binType.push_back("REL");
            }
        }

        void setSectionAlignment(size_t alignment) {
            assert(module);
            assert(section);
            auto &Alignment = *module->getAuxData<gtirb::schema::Alignment>();
            Alignment[section->getUUID()] = alignment;
        }
    } gCtx;

    /**
     * @brief Info about a symbolic reference (egalito refers to them as
     * 'links')
     *
     * These data structures are filled out on a first pass thorugh the code.
     * Additional data structures or symbols may need to be added before the
     * gtirb symbolicReference can be initialized.
     *
     * TODO: Direct attribute access is convenient for the moment
     * (accessing linkInfo.src_addr e.g.), but attributes should likley be
     * hidden eventually
     */
    struct LinkInfo {
        /// \brief The address from which the symbolic reference originates
        address_t src_addr;
        /// \brief A name for the block of the origin of the symbolic refernece
        // (only used for labeling/debugging)
        std::optional<std::string> src_name = std::nullopt;
        /// \brief The address that a link is referring to
        std::optional<address_t> dst_addr = std::nullopt;
        /// \brief The name of the symbol that a link refers to
        std::optional<std::string> dst_name = std::nullopt;

        /// \brief The address of the base symbol that a link refers to
        /// \details Required for symbolic references of the form [(Sym1 - Sym2)
        /// / Scale + Offset].
        std::optional<address_t> base_dst_addr = std::nullopt;
        /// \brief The name of the base symbol that a link refers to
        /// \details Required for symbolic references of the form [(Sym1 - Sym2)
        /// / Scale + Offset].
        std::optional<std::string> base_dst_name = std::nullopt;

        /// If a 'sym + offset' type link, stores the offset from the target
        /// symbol
        size_t dst_offset = 0;

        /// If a [(Sym1 - Sym2) / Scale + Offset] type link, stores the scale
        /// from the target symbol
        size_t dst_scale = 1;

        /// \brief The (gtirb) attributes of the symbolic reference
        gtirb::SymAttributeSet attrs{};

        // A link must have at least one of an destination address or name
        LinkInfo(address_t src_addr, std::optional<std::string> src_name,
            address_t dst_addr)
            : src_addr(src_addr), src_name(src_name), dst_addr(dst_addr) {}

        LinkInfo(address_t src_addr, std::optional<std::string> src_name,
            std::string dst_name)
            : src_addr(src_addr), src_name(src_name), dst_name(dst_name) {}

        LinkInfo(address_t src_addr, std::optional<std::string> src_name,
            address_t dst_addr, std::string dst_name)
            : src_addr(src_addr),
              src_name(src_name),
              dst_addr(dst_addr),
              dst_name(dst_name) {}

        static LinkInfo from_link(address_t src_addr, Link *link,
            std::optional<std::string> src_name = std::nullopt,
            std::optional<address_t> base_addr = std::nullopt,
            std::optional<std::string> base_name = std::nullopt) {
            LinkInfo li(src_addr, src_name, link->getTargetAddress());
            li.base_dst_addr = base_addr;
            li.base_dst_name = base_name;
            if (auto *target = link->getTarget()) {
                li.dst_name = target->getName();
            }
            if (dynamic_cast<PLTLink *>(link)) {
                li.attrs.addFlag(gtirb::SymAttribute::PltRef);
            }
            if (dynamic_cast<OffsetLink *>(link)) {
                auto *target = link->getTarget();
                li.dst_addr = target->getAddress();
                li.dst_offset = link->getTargetAddress() - target->getAddress();
            }
            if (dynamic_cast<DataOffsetLink *>(link)) {
                // The output still functions if DataOffsetLinks are stored as
                // sym+offsets here, but ddisasm appears makes separate symbols
                // instead, so creating a separate symbol matches behavior best
                li.dst_name = symAddrName(*li.dst_addr);
                if (link->getTarget()->getName() == ".got") {
                    li.attrs.addFlag(gtirb::SymAttribute::GotRelPC);
                }
            }
            // TODO: How do each of these map onto gtirb constructs?
            // if (dynamic_cast<JumpTableLink *>(link)) {
            //     This might map onto symAddrAddr, at least in the one test
            //     case I looked at
            //     // log_chunk("  Type: JumpTableLink");
            // }
            // if (dynamic_cast<CopyRelocLink *>(link)) {
            //     // log_chunk("  Type: CopyRelocLink");
            // }
            // if (dynamic_cast<SymbolOnlyLink *>(link)) {
            //     // log_chunk("  Type: CopyRelocLink");
            // }
            // if (dynamic_cast<AbsoluteDataLink *>(link)) {
            //     // log_chunk("  Type: AbsoluteDataLink");
            // }
            // if (dynamic_cast<TLSDataOffsetLink *>(link)) {
            //     // log_chunk("  Type: TLSDataOffsetLink");
            // }
            // if (link->isRIPRelative()) {
            //     // log_chunk("  RIPRelative: True");
            // }
            return li;
        }

        /**
         * @brief Generate a name based on the destination symbol's address
         */
        static std::string symAddrName(address_t dst_addr) {
            std::stringstream ss;
            ss << ".L_" << std::hex << dst_addr;
            return ss.str();
        }

        /**
         * @brief Fetches the symbol associated with the given name if it
         * exists
         *
         * @param sym_name The name of the symbol to search for
         * @param sym_addr The address of the symbol to search for
         * @param module The module in which the gtirb symbol would reside
         * @return gtirb::Symbol* A symbol with the name of the link's
         * destination (or nullptr)
         */
        static gtirb::Symbol *symbol_from_name(
            std::optional<std::string> sym_name,
            std::optional<address_t> sym_addr, gtirb::Module *module) {
            if (!sym_name) return nullptr;

            for (gtirb::Symbol &symbol : module->findSymbols(*sym_name)) {
                if (sym_addr &&
                    (*symbol.getAddress() != gtirb::Addr(*sym_addr))) {
                    // TODO: Until/unless PLT trampolines are resolved,
                    // this happens every time there is a link to a plt
                    // reference
                    std::cerr << "WARNING: Mismatched addresses. "
                              << label(sym_addr, sym_name);
                    std::cerr << " points to 0x" << symbol.getAddress() << "\n";
                }
                return &symbol;
            }
            return nullptr;
        }

        /**
         * @brief Fetches the symbol associated with the given address if it
         * exists
         *
         * @param sym_addr The address of the symbol to search for
         * @param sym_name The name of the symbol to search for
         * @param module The module in which the gtirb symbol would reside
         * @return gtirb::Symbol *A symbol with the address of the link's
         * destination (or nullptr)
         */
        static gtirb::Symbol *symbol_from_addr(
            std::optional<address_t> sym_addr,
            std::optional<std::string> sym_name, gtirb::Module *module) {
            if (!sym_addr) return nullptr;
            gtirb::Addr gAddr(*sym_addr);
            for (gtirb::Symbol &symbol : module->findSymbols(gAddr)) {
                if (sym_name and symbol.getName() != *sym_name) {
                    LOG(10, "Mismatched names in " << label(sym_addr, sym_name)
                                                   << " (points to "
                                                   << symbol.getName() << ")");
                }
                return &symbol;
            }
            return nullptr;
        }

        /**
         * @brief Check if a symbol name is using Egalito's internal jump
         * syntax.
         *
         * @param symName Symbol name to check
         * @return true Symbol name contains invalid '/' character used in
         * Egalito's internal jump names
         * @return false Otherwise
         */
        static bool symbolNameIsIJump(std::string symName) {
            return symName.find('/') != std::string::npos;
        }

        /**
         * @brief Create a gtirb symbol with the name and address matching
         * the link's destination
         *
         * @param sym_addr The address of the symbol to create
         * @param sym_name The name of the symbol to create
         * @param C The gtrib context in which the symbol is to be created
         * @param module The module where the symbol will be added
         * @return gtirb::Symbol* The newly created gtirb symbol
         */
        static gtirb::Symbol *create_symbol(std::optional<address_t> sym_addr,
            std::optional<std::string> sym_name, gtirb::Context &C,
            gtirb::Module *module) {
            if ((!sym_name) && (!sym_addr)) {
                return nullptr;
            }
            LOG(10, "Creating symbol for " << label(sym_addr, sym_name));
            if (sym_addr && sym_name && !symbolNameIsIJump(*sym_name)) {
                return module->addSymbol(C, gtirb::Addr(*sym_addr), *sym_name);
            }
            else if (sym_addr) {
                return module->addSymbol(
                    C, gtirb::Addr(*sym_addr), symAddrName(*sym_addr));
            }
            return module->addSymbol(C, *sym_name);
        }

        /**
         * @brief Generate a label (used only for debugging) for a symbolic
         * reference
         */
        static std::string label(std::optional<address_t> sym_addr,
            std::optional<std::string> sym_name) {
            std::stringstream ss;
            std::string name_string = sym_name ? *sym_name : "<UNKNOWN NAME>";

            if (sym_addr)
                ss << "0x" << std::hex << *sym_addr;
            else
                ss << "<UNKNOWN ADDR>";
            ss << " (" << name_string << ")";
            return ss.str();
        }

        /**
         * @brief Generate a label (used only for debugging) for this symbolic
         * reference
         */
        std::string label() {
            std::stringstream ss;
            ss << label(src_addr, src_name) << " -> [";
            ss << label(dst_addr, dst_name) << ", ";
            ss << label(base_dst_addr, base_dst_name) << "]";
            return ss.str();
        }
    };

    /// \brief Filled out with information about unresolved symbolic references
    /// in a first pass
    std::vector<LinkInfo> links;
    /// \brief Addresses where block addresses start or need to start
    // If the block is already created this maps the address to the size of the
    // block Otherwise, it maps the address to a block of size 0
    std::map<address_t, size_t> block_addrs;

    /**
     * @brief Abstraction of LinkInfo::create_symbol that prevents duplicate
     * symbols from being created.
     *
     * @param sym_addr The address of the symbol to create
     * @param sym_name The name of the symbol to create
     * @param module The module in which the gtirb symbol would reside
     * @return gtirb::Symbol *A symbol with the address and name provided
     */
    gtirb::Symbol *get_unique_symbol(std::optional<address_t> sym_addr,
        std::string sym_name, gtirb::Module *module) {
        for (gtirb::Symbol &symbol : module->findSymbols(sym_name)) {
            if (!sym_addr || (*symbol.getAddress() == gtirb::Addr(*sym_addr))) {
                return &symbol;
            }
        }

        // Create the symbol if a matching one does not exist
        return LinkInfo::create_symbol(sym_addr, sym_name, C, module);
    }

    /**
     * @brief Get the symbol associated with the given name/address if it
     * exists. Create a new symbol if necessary.
     *
     * @param sym_addr The address of the symbol to search for
     * @param sym_name The name of the symbol to search for
     * @param module The module in which the gtirb symbol would reside
     * @return gtirb::Symbol *A symbol with the address or name provided
     */
    gtirb::Symbol *get_symbol_from_link(std::optional<address_t> sym_addr,
        std::optional<std::string> sym_name, gtirb::Module *module) {
        // If there is a symbol with a matching name, use it even if the
        // address is wrong
        gtirb::Symbol *sym_out = LinkInfo::symbol_from_name(
            sym_name, sym_addr, module);
        // If there is no name, but there is an address, use the existing
        // symbol if it matches
        if (!sym_out) {
            sym_out = LinkInfo::symbol_from_addr(sym_addr, sym_name, module);
        }
        // Otherwise, create the symbol if necessary
        if (!sym_out) {
            sym_out = LinkInfo::create_symbol(sym_addr, sym_name, C, module);
            if ((sym_out) && (sym_out->getAddress())) {
                // If the symbol points to an address,
                // we will later ensure that a code/data block starts on
                // that address.
                // (Insert has no effect if the key is already mapped)
                block_addrs.insert({address_t(*sym_out->getAddress()), 0});
            }
            else {
                LOG(0, "NO ADDRESS ON CREATED SYBMOL");
            }
        }
        else {
            log_chunk("    synthetic: false");
        }
        return sym_out;
    }

    /**
     * @brief Get a gtirb symbol associated with the given link's destination.
     *
     * @param link LinkInfo used to obtain the symbol
     * @param module The module in which the gtirb symbol would reside
     * @return gtirb::Symbol *A symbol with the address of the link's
     * destination (or nullptr)
     */
    gtirb::Symbol *get_dst_from_link(LinkInfo &link, gtirb::Module *gModule) {
        return get_symbol_from_link(link.dst_addr, link.dst_name, gModule);
    }

    /**
     * @brief Get a gtirb symbol associated with the given link's base
     * destination.
     * @details Used for symbolic references of the form [(Sym1 - Sym2) / Scale
     * + Offset].
     *
     * @param link LinkInfo used to obtain the symbol
     * @param module The module in which the gtirb symbol would reside
     * @return gtirb::Symbol *A symbol with the address of the link's
     * base destination (or nullptr)
     */
    gtirb::Symbol *get_base_from_link(LinkInfo &link, gtirb::Module *gModule) {
        return get_symbol_from_link(
            link.base_dst_addr, link.base_dst_name, gModule);
    }

    /**
     * @brief Wrapper function for adding a data block to a byte interval.
     * @details Prefer using this function to calling addBlock, since this
     * function prevents adding invalid data blocks.
     *
     * @param interval Byte interval to add the block to.
     * @param blockAddr Program-relative address of the data block.
     * @param blockSize Size of the data block in bytes.
     */
    void try_adding_data_block(
        gtirb::ByteInterval *interval, address_t blockAddr, size_t blockSize) {
        auto section = eCtx.section
                           ? eCtx.section
                           : eCtx.module->getDataRegionList()
                                 ->findDataSectionContaining(blockAddr);

        // Do not add data blocks for dynamic sections.
        // TODO: We may not want to skip unknown sections too.
        if (section && ((section->getType() == DataSection::TYPE_DYNAMIC) ||
                           (section->getType() == DataSection::TYPE_UNKNOWN))) {
            log_chunk("    Dynamic: True");
            return;
        }
        gtirb::Addr intervalStart = *interval->getAddress();
        interval->addBlock<gtirb::DataBlock>(
            C, gtirb::Addr(blockAddr) - intervalStart, blockSize);
    }

    void visit(Program *eProgram) {
        eCtx.program = eProgram;

        recurse<Module *>(eProgram);
        // This has to come after parsing the module,
        // because library usage is added to the gtirb::module's auxData
        // (which doesn't exist until module parsing)
        // FIXME: This will not work with a deep scan of dependencies
        visit(eProgram->getLibraryList());
    }

    void visit(Module *eModule) {
        log_chunk("- Chunk: !module ", eModule->getName());

        gtirb::Module *gModule = ir.addModule(C, eModule->getName());

        // TODO: gCtx might be a more appropriate place to add these?
        // Empty versions of each auxData type are added and then filled out
        // later (it made the flow of code much simpler)
        gModule->addAuxData<gtirb::schema::FunctionNames>(
            gtirb::schema::FunctionNames::Type());
        gModule->addAuxData<gtirb::schema::FunctionEntries>(
            gtirb::schema::FunctionEntries::Type());
        gModule->addAuxData<gtirb::schema::FunctionBlocks>(
            gtirb::schema::FunctionBlocks::Type());
        gModule->addAuxData<gtirb::schema::ElfSymbolInfoAD>(
            gtirb::schema::ElfSymbolInfoAD::Type());
        gModule->addAuxData<gtirb::schema::SymbolForwarding>(
            gtirb::schema::SymbolForwarding::Type());
        gModule->addAuxData<gtirb::schema::Libraries>(
            gtirb::schema::Libraries::Type());
        gModule->addAuxData<gtirb::schema::LibraryPaths>(
            gtirb::schema::LibraryPaths::Type());
        gModule->addAuxData<gtirb::schema::BinaryType>(
            gtirb::schema::BinaryType::Type());
        gModule->addAuxData<gtirb::schema::Alignment>(
            gtirb::schema::Alignment::Type());

        // TODO: There's probably a real place to get this info within egalito
        gModule->setFileFormat(gtirb::FileFormat::ELF);
#ifdef ARCH_X86_64
        // TODO: Can egalito be compiled for multiple ISA?
        gModule->setISA(gtirb::ISA::X64);
#endif

        // Set the context for this layer of the hierarchy
        eCtx.module = eModule;
        gCtx.module = gModule;

        // Set the elf binary type
        gCtx.setBinaryType(eModule->getElfSpace()->getElfMap());

        // Revert address offsets before parsing
        // TODO: Make sure this does not interfere with Egaltio rewriting
        eCtx.module->setBaseAddress(0);
        for (auto region : CIter::regions(eCtx.module)) {
            region->updateAddressFor(0);
        }

        // Cannot simply call
        //   recurse(eModule);
        // because the order of traversal matters here.
        // Data regions/sections have to be traversed first,
        // because otherwise sections haven't been created before the functions
        // they are within I think this completely negates the potential benefit
        // of using the visitor pattern...

        // The types in the recurse<...> calls are totally optional here
        // They just make grepping around the code a little easier, so I left
        // them in.
        if (eModule->getExternalSymbolList()) {
            recurse<ExternalSymbol *>(eModule->getExternalSymbolList());
        }
        recurse<DataRegion *>(eModule->getDataRegionList());
        recurse<Function *>(eModule->getFunctionList());
        recurse<PLTTrampoline *>(eModule->getPLTList());
        recurse<VTable *>(eModule->getVTableList());
        recurse<JumpTable *>(eModule->getJumpTableList());
        recurse<Marker *>(eModule->getMarkerList());

        // Once functions and symbols have been traversed,
        // add information about the symbolic references witin the code/data
        // blocks
        for (LinkInfo &linkInfo : links) {
            auto dst = get_dst_from_link(linkInfo, gModule);
            if (!dst) {
                continue;
            }
            auto base = get_base_from_link(linkInfo, gModule);
            auto byteIntervals = gModule->findByteIntervalsOn(
                gtirb::Addr(linkInfo.src_addr));
            auto interval = byteIntervals.begin();
            // Ensure that there is exactly one interval on this address
            assert(interval != byteIntervals.end());
            assert(std::next(interval) == byteIntervals.end());
            auto offset = gtirb::Addr(linkInfo.src_addr) -
                          *interval->getAddress();
            if (base) {
                interval->addSymbolicExpression<gtirb::SymAddrAddr>(
                    offset, linkInfo.dst_scale, linkInfo.dst_offset, dst, base);
            }
            else {
                interval->addSymbolicExpression<gtirb::SymAddrConst>(
                    offset, linkInfo.dst_offset, dst, linkInfo.attrs);
            }
            LOG(10, "Added symbolic expression for " << linkInfo.label()
                                                     << " at " << offset);
        }

        // Add data blocks for regions that aren't covered by existing ones

        // Keep a pointer to the current location in each byte interval,
        // then run through the created blocks in ascending order,
        // filling in gaps in the blocks as you go

        std::unordered_map<gtirb::ByteInterval *, gtirb::Addr> addrCursors;
        for (auto &[blockAddr, blockSize] : block_addrs) {
            // Should be exactly one interval on this address at this point
            auto intervals = gModule->findByteIntervalsOn(
                gtirb::Addr(blockAddr));
            if (intervals.begin() == intervals.end()) {
                std::cerr << "WARNING: No interval covering " << std::hex
                          << blockAddr << std::endl;
                continue;
            }
            gtirb::ByteInterval &interval = *intervals.begin();
            gtirb::Addr intervalStart = *interval.getAddress();

            // If there is an existing cursor for this byte interval, use it
            // Otherwise, advance it from 0 (the default value for addrCursors)
            // to the start address of this interval
            gtirb::Addr &cursor = addrCursors[&interval];
            cursor = std::max(cursor, intervalStart);

            gtirb::Addr gAddr(blockAddr);
            if (cursor < gAddr) {
                try_adding_data_block(
                    &interval, (address_t)cursor, (size_t)(gAddr - cursor));
                log_chunk("- filler:");
                log_chunk("    start: ", cursor);
                log_chunk("    end: ", blockAddr);
                cursor = gAddr + blockSize;
            }
            else {
                // If blockAddr is behind the cursor addr,
                // that means that the new block falls in the middle of
                // a previously created one.
                // Right now we just skip over the overlap to the next block.
                // TODO: Creating overlap or splitting the existing block might
                // be better.
                cursor = std::max(cursor, gtirb::Addr(blockAddr + blockSize));
            }
        }

        log_chunk("  Closing blocks: ");
        // Add extra datablocks to end of intervals
        // (might not be necessary)
        for (auto &[interval, cursor] : addrCursors) {
            gtirb::Addr intervalAddr = *interval->getAddress();
            gtirb::Addr intervalEnd = intervalAddr + interval->getSize();
            if (intervalEnd > cursor) {
                try_adding_data_block(interval, (address_t)cursor,
                    (size_t)(intervalEnd - cursor));
                log_chunk("  - start: ", cursor);
                log_chunk("    end: ", intervalEnd);
                log_chunk("    offset: ", cursor - intervalAddr);
                log_chunk("    size: ", intervalEnd - cursor);
            }
        }
    }

    void visit(LibraryList *libraryList) {
        log_chunk("- LibraryList ");
        for (auto path : libraryList->getSearchPaths()) {
            log_chunk("- Search Path: ", path);
            gCtx.addLibraryPath(path);
        }
        recurse(libraryList);
    }

    void visit(Library *library) {
        log_chunk("- Library: ", library->getName());
        log_chunk("  path: ", library->getResolvedPath());
        if (library->getModule() == eCtx.program->getMain()) {
            // The main library is parsed elsewhere
            // so it can be skipped here
            log_chunk("  Main: True");
            return;
        };
        gCtx.addLibrary(library->getName());
        if (!library->getModule()) {
            log_chunk("  Has module: False");
            // TODO: do other aspects of the library have to be dealt with?
            // e.g. that library's dependencies or the resolved_path attribute?
            return;
        }
        log_chunk("  Has module: True");
        return;
        // TODO: Recurse into parsed libraries?
        // recurse(library->getModule());
    }

    void visit(DataRegion *dataRegion) {
        // A dataRegion is a contiguous set of bytes which may hold parts of one
        // or more dataSections
        eCtx.region = dataRegion;
        log_chunk("- Chunk: !region ", dataRegion->getName());
        log_chunk("  Addr: ", std::hex, dataRegion->getAddress());
        log_chunk("  Original addr: ", dataRegion->getOriginalAddress());
        log_chunk("  Range: ", std::hex, dataRegion->getRange().getStart(),
            " - ", dataRegion->getRange().getEnd());
        recurse(dataRegion);
    }

    void visit(DataSection *eSection) {
        // TODO: If sections are not contiguous, this will likely break

        // A dataSection is an elfSection that is within a single region
        log_chunk("- Chunk: !section ", eSection->getName());
        log_chunk("  IsCode: ", eSection->isCode());
        log_chunk("  Listed addr: ", std::hex, eSection->getAddress());
        log_chunk("  Original offset: ", eSection->getOriginalOffset());
        log_chunk("  Range: ", eSection->getRange().getStart(), " - ",
            eSection->getRange().getEnd());
        log_chunk("  Size: ", eSection->getSize());

        // DataSections contains an entry for every section in the file
        // (not just sections of type 'data')
        auto *gSection = gCtx.module->addSection(C, eSection->getName());
        if (eCtx.region->readable()) {
            gSection->addFlag(gtirb::SectionFlag::Readable);
        }
        if (eCtx.region->writable()) {
            gSection->addFlag(gtirb::SectionFlag::Writable);
        }
        if (eCtx.region->executable()) {
            gSection->addFlag(gtirb::SectionFlag::Executable);
        }

        gCtx.section = gSection;
        eCtx.section = eSection;
        gCtx.setSectionAlignment(eSection->getAlignment());

        if (eSection->getSize()) {
            // Attempt to create a single byte interval per section
            // (further gtirb analyses can split this up if desired)
            // Some functions in the .text section may have addresses
            // that are outside of these section bounds,  in which case
            // they get their own byte intervals
            log_chunk("  Byte interval: ", eSection->getAddress(), " - ",
                eSection->getAddress() + eSection->getSize());
            gCtx.byteInterval = gSection->addByteInterval(
                C, gtirb::Addr(eSection->getAddress()), eSection->getSize());
            log_chunk("  Byte interval size: ", gCtx.byteInterval->getSize());
        }

        if (!eSection->isCode()) {
            // If it is not a code section, add all of the bytes for the section
            // now. Bytes from code sections will be added function by function
            // later.
            // TODO: Code sections might contain variables as well,
            // which is likely to cause issues if we never copy over the bytes.
            const std::string &region_bytes = eCtx.region->getDataBytes();
            const char *sec_start = region_bytes.c_str() +
                                    eSection->getOriginalOffset();
            const char *sec_end = sec_start + eSection->getSize();
            auto intervalBegin = gCtx.byteInterval->bytes_begin<char>();
            if (eSection->isBss()) {
                std::fill(
                    intervalBegin, intervalBegin + eSection->getSize(), '\0');
            }
            else {
                // FIXME: This is copying directly from the memory map
                // (which may not be completely filled out in egalito)
                std::copy(sec_start, sec_end, intervalBegin);
            }
        }
        recurse<DataVariable *>(eSection);
        recurse<GlobalVariable *>(eSection->getGlobalVariables());

        gCtx.byteInterval = nullptr;
        eCtx.section = nullptr;
    }

    /**
     * @brief Add a data block for a variable, or register the address for
     * future addition
     *
     * @param varAddr The address at which the data block will start
     * @param varSize The length of the data block, or 0 if the length is not
     * important
     */
    void registerDataBlock(address_t varAddr, size_t varSize) {
        // Check if we have to create a block at this address
        size_t curSize = block_addrs[varAddr];
        if (curSize > 0 && varSize > 0) {
            // If there is already a sized data block registered at this
            // address, attempt to create a new block that covers the difference
            // in the sizes.
            if (curSize < varSize) {
                // Create block from end of existing variable to end of the new
                // one.
                registerDataBlock(varAddr + curSize, varSize - curSize);
            }
            else if (curSize > varSize) {
                // Decrease size of existing block, and create block to fill the
                // space.
                block_addrs[varAddr] = varSize;
                registerDataBlock(varAddr + varSize, curSize - varSize);
            }
            // If the sizes are the same there is nothing to be done
        }
        else if (varSize > 0) {
            // If a block needs to cover this whole set of bytes, add it now.
            try_adding_data_block(gCtx.byteInterval, varAddr, varSize);
            block_addrs[varAddr] = varSize;
        }
        // If there isn't a set size for the variable,
        // it can just extend from here to the start of the next block.
        // Accessing block_addrs[...] above added an value '0' to that slot in
        // the map, so no more action is needed.
    }

    /**
     * Data variable description:
     * "Represents a variable within a global data section that points at
     * another Chunk"
     */
    void visit(DataVariable *variable) {
        log_chunk("- Chunk: !dataVariable ", variable->getName());
        log_chunk("  Address: ", std::hex, variable->getAddress());
        log_chunk("  Size: ", variable->getSize());

        // Ensure a data block will start at this address
        registerDataBlock(variable->getAddress(), variable->getSize());

        // There seem to be two types of data variables:
        // - variables with a 'dest' link
        // - variables with a 'target' symbol
        std::string varName = variable->getName();
        Link *dest = variable->getDest();
        if (dest && !variable->getIsCopy()) {
            // "Dest" variables don't seem to need a symbol,
            // we just need to create a symbolic reference from this address
            log_chunk("  Type: Link");
            if (dest->getTarget()) {
                log_chunk("  Dest name: ", dest->getTarget()->getName());
            }
            log_chunk("  Dest addr: ", dest->getTargetAddress());
            if (dest->getTarget() && dest->getTargetAddress()) {
                links.push_back(LinkInfo::from_link(
                    variable->getAddress(), dest, variable->getName()));
            }
            return;
        }
        else if (variable->getIsCopy()) {
            // This is not necessary for a working binary, but it is useful to
            // differentiate between target vars and copy relocs for debugging
            variable->setName(variable->getName() + "_copy");
        }
        else {
            variable->setName(LinkInfo::symAddrName(variable->getAddress()));
        }

        // 'Target' variables *seem* to be GOT references,
        // In this case, generate a name for the symbol at this address,
        // and add forwarding to a non-addressed symbol with the target name.
        Symbol *target = variable->getTargetSymbol();
        // ('target' seems to always be specified if 'dest' is not)
        assert(target);

        // The symbol has to be created so the symbol forwarding table can be
        // made
        gtirb::Symbol *gSymbol = get_unique_symbol(
            variable->getAddress(), variable->getName(), gCtx.module);

        log_chunk("  Type: Target");
        log_chunk("  Target name: ", target->getName());
        log_chunk("  Target addr: ", target->getAddress());
        log_chunk("  Target type: ", target->getType());
        log_chunk("  Symbol name: ", gSymbol->getName());

        // TODO: Deal with aliases?

        // Create a separate symbol for the target if there isn't already one of
        // this name.
        // TODO: I _think_ this is the only place that certain symbols (e.g.
        // __cxa_finalize) are listed
        //       but I am not 100% sure that they don't have a less ambiguous
        //       reference elsewhere
        auto existingTargets = gCtx.module->findSymbols(target->getName());
        if (existingTargets.begin() != existingTargets.end()) {
            // TODO: Is this '&*' syntax to get a pointer to the underlying
            // object of an iterator okay? it looks abnormal.
            gCtx.addSymbolForwarding(gSymbol, &*existingTargets.begin());
        }
        else {
            gtirb::Symbol *gTarget = get_unique_symbol(
                std::nullopt, target->getName(), gCtx.module);
            gCtx.addSymbolInfo(gTarget, target->getSize(),
                eSymTypeStr(target->getType()),
                eSymBindingStr(target->getBind()), "DEFAULT",
                target->getSectionIndex());
            gCtx.addSymbolForwarding(gSymbol, gTarget);
        }
    }

    /**
     * Global variable description:
     * "Represents a variable that has a symbol of some sort that needs to be
     * preserved"
     */
    void visit(GlobalVariable *variable) {
        log_chunk("- Chunk: !globalVariable ", variable->getName());
        log_chunk("  Addr: ", std::hex, variable->getAddress());
        log_chunk("  Size: ", variable->getSize());

        // Ensure a data block will start at this address
        registerDataBlock(variable->getAddress(), variable->getSize());

        // Dynamic symbols are handled through externalSymbol, except in cases
        // where binaries are expected to export symbols.
        if (auto *dynSym = variable->getDynamicSymbol()) {
            // Make sure at least one instance of the symbol exists
            auto existingTargets = gCtx.module->findSymbols(dynSym->getName());
            if (existingTargets.begin() != existingTargets.end()) {
                return;
            }
        }

        Symbol *target = variable->getNonNullSymbol();
        gtirb::Symbol *gSymbol = get_unique_symbol(
            variable->getAddress(), variable->getName(), gCtx.module);

        gCtx.addSymbolInfo(gSymbol, variable->getSize(),
            eSymTypeStr(target->getType()), eSymBindingStr(target->getBind()),
            "DEFAULT", target->getSectionIndex());

        log_chunk("  Type: ", target->getType());
        log_chunk("  Section Index: ", target->getSectionIndex());
    }

    DataSection *getEgalitoSection(Function *function) {
        assert(eCtx.module != nullptr);
        auto eSymbol = function->getSymbol();
        if (!eSymbol) {
            return eCtx.module->getDataRegionList()->findDataSectionContaining(
                function->getAddress());
        }
        // It is strange to me that I have to go through these lengths
        // to get the section in which a function is defined.
        // I may be able to just get it with the address instead
        auto elfMap = eCtx.module->getElfSpace()->getElfMap();
        auto elfSection = elfMap->findSection(eSymbol->getSectionIndex());
        return eCtx.module->getDataRegionList()->findDataSection(
            elfSection->getName());
    }

    void visit(Function *function) {
        log_chunk("- Chunk: !function ", function->getName());
        log_chunk("  Addr: ", function->getAddress());
        log_chunk("  Position: ", function->getPosition()->get());
        log_chunk("  Size: ", function->getSize());

        eCtx.section = getEgalitoSection(function);
        gCtx.section = nullptr;

        auto addr = function->getAddress();

        auto sections = gCtx.module->findSections(eCtx.section->getName());
        // The section must exist
        // And there must be only one section by that name
        assert(sections.begin() != sections.end());
        assert(std::next(sections.begin()) == sections.end());

        gCtx.section = &*sections.begin();

        auto intervals = gCtx.section->findByteIntervalsOn(gtirb::Addr(addr));
        if (intervals.begin() == intervals.end()) {
            // Create the byte interval if it doesn't exist
            gCtx.byteInterval = gCtx.section->addByteInterval(
                C, gtirb::Addr(function->getAddress()), function->getSize());
        }
        else {
            // Otherwise, there should be only one byte interval on this address
            assert(std::next(intervals.begin()) == intervals.end());
            gCtx.byteInterval = &*intervals.begin();
        }

        log_chunk("  Symbol Section: ", gCtx.section->getName());
        eCtx.function = function;
        std::string symName = function->getName();
        auto symSize = function->getSize();
        auto symType = Symbol::SymbolType::TYPE_FUNC;
        auto symBind = Symbol::BindingType::BIND_LOCAL;
        if (function->getAddress() == eCtx.program->getEntryPointAddress()) {
            // Make sure we keep the defined entry point
            symName = "_start";
            function->setName(symName);
            symBind = Symbol::BindingType::BIND_GLOBAL;
        }
        else if (function->getSymbol()) {
            auto eSymbol = function->getSymbol();
            symName = eSymbol->getName();
            symSize = eSymbol->getSize();
            symType = eSymbol->getType();
            symBind = eSymbol->getBind();
        }
        else {
            // In case of fuzzyfunc, make sure we use proper assembly naming
            std::replace(symName.begin(), symName.end(), '-', '_');
        }
        gtirb::Symbol *gSymbol = get_unique_symbol(addr, symName, gCtx.module);
        gCtx.functionId = gCtx.assignFunctionId(gSymbol);
        gCtx.addSymbolInfo(
            gSymbol, symSize, eSymTypeStr(symType), eSymBindingStr(symBind));

        recurse<Block *>(function);

        gCtx.byteInterval = nullptr;
        eCtx.function = nullptr;
        eCtx.section = nullptr;
    }

    void visit(Block *block) {
        uint64_t blockOffset = block->getAddress() -
                               (uint64_t)*gCtx.byteInterval->getAddress();
        log_chunk("- Block addr: ", block->getAddress());
        log_chunk("  Block size: ", block->getSize());
        log_chunk("  Block offset: ", blockOffset);

        if (blockOffset + block->getSize() > gCtx.byteInterval->getSize()) {
            std::cout << "ERROR: End of block at " << block->getAddress()
                      << " falls outside of bounds of byte interval for "
                      << eCtx.function->getName() << std::endl;
            return;
        }

        gtirb::CodeBlock *codeBlock = gCtx.byteInterval
                                          ->addBlock<gtirb::CodeBlock>(
                                              C, blockOffset, block->getSize());
        block_addrs[block->getAddress()] = block->getSize();

        gCtx.addBlockToFunction(codeBlock);

        gCtx.codeBlock = codeBlock;
        log_chunk("  Instructions:");
        recurse<Instruction *>(block);
        gCtx.codeBlock = nullptr;
    }

    void visit(Instruction *instruction) {
        // Instructions within functions are deserialized one at a time
        auto instrAddr = instruction->getAddress();

        auto instrOffset = instrAddr -
                           (uint64_t)*gCtx.byteInterval->getAddress();

        auto intervalBegin = gCtx.byteInterval->bytes_begin<char>();
        auto instrPos = intervalBegin + instrOffset;

        // Get the string of bytes in the function
        auto semantic = instruction->getSemantic();
        std::string data;
        InstrWriterCppString writer(data);
        semantic->accept(&writer);

        log_chunk("- Intruction len: ", data.size());
        if (data.size() > gCtx.byteInterval->getSize() - instrOffset) {
            std::cerr << "ERROR: Instruction at " << instrAddr
                      << " falls outside of bounds of byte interval"
                      << std::endl;
            return;
        }
        log_chunk("  Instruction offset: ", instrOffset);
        std::copy(data.begin(), data.end(), instrPos);

        auto link = semantic->getLink();
        if (link) {
            int op_offset = 0;
            if (auto *cfi = dynamic_cast<ControlFlowInstructionBase *>(
                    semantic)) {
                op_offset = cfi->getOpcode().size();
                log_chunk("  Link Type: CFI");
                log_chunk("  Mnemonic: ", cfi->getMnemonic());
            }
            else if (auto *li = dynamic_cast<LinkedInstructionBase *>(
                         semantic)) {
                op_offset = li->getDispOffset();
                log_chunk("  Link Type: LinkedInstruction");
            }
            else {
                throw(std::runtime_error("Cannot determine link type"));
            }
            log_chunk("  Link offset: ", op_offset);

            links.push_back(LinkInfo::from_link(
                instrAddr + op_offset, link, eCtx.function->getName()));
        }
    }

    void visit(ExternalSymbol *eSymbol) {
        // Just adding a symbol with this name appears to be enough
        log_chunk("- Chunk: !externalSymbol ", eSymbol->getName());
        gtirb::Symbol *gSymbol = get_unique_symbol(
            std::nullopt, eSymbol->getName(), gCtx.module);
        gCtx.addSymbolInfo(gSymbol, eSymbol->getSize(),
            eSymTypeStr(eSymbol->getType()),
            eSymBindingStr(eSymbol->getBind()));
    }
    void visit(InitFunction *initFunction) {
        // TODO: Entirely unsure if/how to deal with this
    }

    /** The following chunksa are simply recursed into */
    void visit(FunctionList *functionList) { recurse(functionList); }
    void visit(PLTList *pltList) { recurse(pltList); }
    void visit(JumpTableList *jumpTableList) {
        log_chunk("- Chunk: !jumpTableList ", jumpTableList->getName());
        recurse(jumpTableList);
    }

    void visit(DataRegionList *dataRegionList) { recurse(dataRegionList); };
    void visit(VTableList *vtableList) { recurse(vtableList); }
    void visit(ExternalSymbolList *externalSymbolList) {
        recurse(externalSymbolList);
    }
    void visit(InitFunctionList *initFunctionList) {
        recurse(initFunctionList);
    }

    void visit(JumpTable *jumpTable) {
        log_chunk("- Chunk: !jumpTable ", jumpTable->getName());
        log_chunk("  Location: ", jumpTable->getAddress());
        eCtx.jtable = jumpTable;
        recurse(jumpTable);
        eCtx.jtable = nullptr;
    }

    void visit(PLTTrampoline *trampoline) {
        std::string name = trampoline->getName();
        log_chunk("- Chunk: !trampoline ", name);
        log_chunk("  Location: ", trampoline->getAddress());
        log_chunk("  GotPLTEntry: ", trampoline->getGotPLTEntry());
        get_unique_symbol(std::nullopt, name, gCtx.module);
    }

    void visit(JumpTableEntry *jumpTableEntry) {
        log_chunk("- Chunk: !jtentry ", jumpTableEntry->getName());

        auto entryAddr = jumpTableEntry->getAddress();
        auto entryName = jumpTableEntry->getName();
        auto link = jumpTableEntry->getLink();
        auto baseAddress = eCtx.jtable->getAddress();
        auto baseName = eCtx.jtable->getName();
        links.push_back(LinkInfo::from_link(
            entryAddr, link, entryName, baseAddress, baseName));
    }

    void visit(MarkerList *markerList) {
        log_chunk("- Chunk: !markerList ", markerList->getName());
        recurse(markerList);
    }
    void visit(Marker *marker) {
        // TODO: SectionStartMarker and SectionEndMarker don't call visit() in
        // their accept function so if this is needed, it won't ever get called
        log_chunk("- Chunk: !marker ", marker->getName());
    }
    void visit(VTable *vtable) {}
    void visit(VTableEntry *vtableEntry) {
        log_chunk("- Chunk: !vTableEntry ", vtableEntry->getName());
    }
};

/**
 * @brief Converts the egalito program to gtirb and generates three outputs:
 * <filename>-chunklog.yaml - a record of the parsed egalito hierarchy
 * <filename>.gtirb - the protobuf format gtirb IR
 * <filename>.json - the json-formatted gtirb IR
 *
 * @param program The egalito program to convert
 * @param filename The basename into which the output will be written
 */
void GtirbSerializer::serialize(Program *program, std::string filename) {
    gtirb::AuxDataContainer::registerAuxDataType<
        gtirb::schema::FunctionEntries>();
    gtirb::AuxDataContainer::registerAuxDataType<
        gtirb::schema::FunctionBlocks>();
    gtirb::AuxDataContainer::registerAuxDataType<
        gtirb::schema::FunctionNames>();
    gtirb::AuxDataContainer::registerAuxDataType<
        gtirb::schema::ElfSymbolInfoAD>();
    gtirb::AuxDataContainer::registerAuxDataType<
        gtirb::schema::SymbolForwarding>();
    gtirb::AuxDataContainer::registerAuxDataType<gtirb::schema::Libraries>();
    gtirb::AuxDataContainer::registerAuxDataType<gtirb::schema::LibraryPaths>();
    gtirb::AuxDataContainer::registerAuxDataType<gtirb::schema::BinaryType>();
    gtirb::AuxDataContainer::registerAuxDataType<gtirb::schema::Alignment>();
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
