#include <iostream>
#include <fstream>

#include "gtirb_serializer.h"
#include "gtirb_util.h"

#include "analysis/jumptable.h"
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

// Handle symbolic attributes from protobuf versions 3 or 4
#if GTIRB_PROTOBUF_VERSION < 4
#define GTIRB_PROTOBUF_4
#endif

std::string eSymTypeStr(Symbol::SymbolType eSymType) {
    switch (eSymType) {
        case Symbol::TYPE_NOTYPE:
            return "NONE";
        case Symbol::TYPE_IFUNC:
            return "GNU_IFUNC";
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

    /// \brief A list of symbols that need to have their referrents set
    /// after the ChunkSerializer performs its visit() pass.
    std::vector<std::pair<gtirb::Symbol *, gtirb::Addr>> delayed_referrents;

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
        // Save the current Egalito/GTIRB context state
        auto eCtx_saved = eCtx;
        auto gCtx_saved = gCtx;
        for (ChildT child : CIter::children(parent)) {
            child->accept(this);
            // Restore the Egalito/GTIRB context state
            eCtx = eCtx_saved;
            gCtx = gCtx_saved;
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
        Program *program = nullptr;
        Module *module = nullptr;
        Function *function = nullptr;
        DataRegion *region = nullptr;
        DataSection *section = nullptr;
        JumpTable *jtable = nullptr;
    } eCtx;

    struct {
        gtirb::Module *module = nullptr;
        gtirb::ByteInterval *byteInterval = nullptr;
        gtirb::CodeBlock *codeBlock = nullptr;
        gtirb::Section *section = nullptr;
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
         * @param previousBlock The code block directly preceding codeBlock, if
         * adding out-of-order
         */
        void addBlockToFunction(gtirb::CodeBlock *codeBlock,
            gtirb::CodeBlock *previousBlock = nullptr) {
            assert(module);
            assert(functionId);
            // Blocks must be added in order, unless a previousBlock is provided
            auto &funcBlocks =
                *module->getAuxData<gtirb::schema::FunctionBlocks>();

            auto insert_iter = funcBlocks[*functionId].end();
            if (previousBlock) {
                auto previous_iter = funcBlocks[*functionId].find(
                    previousBlock->getUUID());
                assert(previous_iter != funcBlocks[*functionId].end());
                insert_iter = std::next(previous_iter);
            }
            funcBlocks[*functionId].insert(insert_iter, codeBlock->getUUID());
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
         * @brief Check if symbol info already exists for a GTIRB symbol
         */
        bool symbolInfoExists(gtirb::Symbol *gSymbol) {
            assert(module);
            auto &auxInfo = *module->getAuxData<gtirb::schema::ElfSymbolInfo>();
            return auxInfo.count(gSymbol->getUUID()) != 0;
        }

        /**
         * @brief Add elf symbol info to the aux data associated with a gtirb
         * symbol
         */
        void addSymbolInfo(gtirb::Symbol *gSymbol, uint64_t size,
            std::string type, std::string binding = "GLOBAL",
            std::string visibility = "DEFAULT", uint64_t section_idx = 0) {
            assert(module);
            auto &auxInfo = *module->getAuxData<gtirb::schema::ElfSymbolInfo>();
            auxInfo[gSymbol->getUUID()] = {
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

        /**
         * @brief Define the binary type (used to differentiate between PIE and
         * NOPIE builds)
         */
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

        /**
         * @brief Set the section alignment
         */
        void setSectionAlignment(size_t alignment) {
            assert(module);
            assert(section);
            auto &Alignment = *module->getAuxData<gtirb::schema::Alignment>();
            Alignment[section->getUUID()] = alignment;
        }

        /**
         * @brief Convert the Egalito section type to an sh_type value
         */
        uint64_t getSectionType(DataSection *eSection) {
            switch (eSection->getType()) {
                case DataSection::TYPE_BSS:
                    return SHT_NOBITS;
                case DataSection::TYPE_DATA:
                    return SHT_PROGBITS;
                case DataSection::TYPE_CODE:
                    return SHT_PROGBITS;
                case DataSection::TYPE_INIT_ARRAY:
                    return SHT_INIT_ARRAY;
                case DataSection::TYPE_FINI_ARRAY:
                    return SHT_FINI_ARRAY;
                case DataSection::TYPE_DYNAMIC:
                    return SHT_DYNAMIC;
                default:
                    return SHT_NULL;
            }
        }

        /**
         * @brief Set the section type and flags in the section properties table
         */
        void setSectionProperties(DataSection *eSection) {
            assert(module);
            assert(section);

            uint64_t type = getSectionType(eSection);
            uint64_t flags = eSection->getPermissions();
            auto &sectionProperties =
                *module->getAuxData<gtirb::schema::SectionProperties>();
            sectionProperties[section->getUUID()] = {type, flags};
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
        enum Type {
            TYPE_CONST,
            TYPE_ADDR,
            TYPE_FORWARD,
        } type = TYPE_CONST;

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

        static LinkInfo from_link(address_t src_addr, Link *link,
            std::optional<std::string> src_name) {
            LinkInfo li(src_addr, src_name, link->getTargetAddress());
            if (auto *target = link->getTarget()) {
                li.dst_name = target->getName();
            }

            if (dynamic_cast<PLTLink *>(link)) {
#ifdef GTIRB_PROTOBUF_4
                li.attrs.insert(gtirb::SymAttribute::PLT);
#else
                li.attrs.addFlag(gtirb::SymAttribute::PltRef);
#endif
            }
            else if (dynamic_cast<OffsetLink *>(link)) {
                auto *target = link->getTarget();
                li.dst_addr = target->getAddress();
                li.dst_offset = link->getTargetAddress() - target->getAddress();
            }
            else if (dynamic_cast<DataOffsetLink *>(link)) {
                // Storing all links as base + offset causes some binaries to
                // segfault, and does not match the behavior of ddisasm.
                // Creating a separate symbol matches behavior best.
                li.dst_name = symAddrName(*li.dst_addr);

                // We do not make data blocks for dynamic sections, so we need
                // to use symbol offsets to reach the target
                auto *section = dynamic_cast<DataSection *>(link->getTarget());
                if (section->getType() == DataSection::TYPE_DYNAMIC) {
                    li.dst_addr = section->getAddress();
                    li.dst_offset = link->getTargetAddress() -
                                    section->getAddress();
                }
                // External jumps should point to the local copy of the external
                // symbol they will be forwarded to
                else if (link->isExternalJump()) {
                    auto ext_target = section->findVariableContaining(
                        link->getTargetAddress());
                    if (ext_target && ext_target->getIsCopy()) {
                        li.dst_name = ext_target->getName();
                        li.dst_addr = ext_target->getAddress();
                        li.dst_offset = link->getTargetAddress() - *li.dst_addr;
                    }
                }

                if (section->getName() == ".got") {
#ifdef GTIRB_PROTOBUF_4
                    li.attrs.insert(gtirb::SymAttribute::GOT);
#else
                    li.attrs.addFlag(gtirb::SymAttribute::GotRelPC);
#endif
                }
            }
            else if (auto extSymLink = dynamic_cast<ExternalSymbolLink *>(
                         link)) {
                auto extSym = extSymLink->getExternalSymbol();
                li.dst_name = extSym->getName();
                li.dst_addr = std::nullopt;
                li.dst_offset = extSymLink->getOffset();
            }
            else if (auto extSymLink =
                         dynamic_cast<InternalAndExternalDataLink *>(link)) {
                auto extSym = extSymLink->getExternalSymbol();
                li.dst_name = extSym->getName();
                li.dst_addr = std::nullopt;
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

        static LinkInfo from_link(address_t src_addr, Link *link,
            std::optional<std::string> src_name,
            std::optional<address_t> base_addr,
            std::optional<std::string> base_name) {
            LinkInfo li = from_link(src_addr, link, src_name);
            li.base_dst_addr = base_addr;
            li.base_dst_name = base_name;
            li.type = TYPE_ADDR;
            return li;
        }

        static LinkInfo forward_from_link(address_t src_addr, Link *link,
            std::optional<std::string> src_name) {
            LinkInfo li = from_link(src_addr, link, src_name);
            // Do not use offsets for symbol forwarding
            li.dst_addr = link->getTargetAddress();
            li.dst_offset = 0;
            li.type = TYPE_FORWARD;
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
         * @brief Generate a non-ambiguous name based on the destination
         * symbol's name and address
         */
        static std::string disambigName(
            std::string dst_name, address_t dst_addr) {
            std::stringstream ss;
            ss << dst_name << "_disambig_" << dst_addr;
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
        static gtirb::Symbol *symbol_from_name(std::string sym_name,
            std::optional<address_t> sym_addr, gtirb::Module *module) {
            for (gtirb::Symbol &symbol : module->findSymbols(sym_name)) {
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
        static gtirb::Symbol *symbol_from_addr(address_t sym_addr,
            std::optional<std::string> sym_name, gtirb::Module *module) {
            gtirb::Addr gAddr(sym_addr);
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
            std::string sym_name, gtirb::Context &C, gtirb::Module *module) {
            LOG(10, "Creating symbol for " << label(sym_addr, sym_name));
            if (sym_addr) {
                return module->addSymbol(C, gtirb::Addr(*sym_addr), sym_name);
            }
            return module->addSymbol(C, sym_name);
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
    /// \brief Record of duplicate symbol names in need of disambiguation.
    std::map<std::string, bool> duplicate_sym_names;

    struct EdgeInfo {
        gtirb::Addr source;
        std::optional<gtirb::Addr> dest;
        gtirb::EdgeType type;
        gtirb::ConditionalEdge conditional;
        gtirb::DirectEdge direct;

        EdgeInfo(gtirb::Addr source, std::optional<gtirb::Addr> dest,
            gtirb::EdgeType type, gtirb::ConditionalEdge conditional,
            gtirb::DirectEdge direct)
            : source(source),
              dest(dest),
              type(type),
              conditional(conditional),
              direct(direct) {}

        static std::optional<EdgeInfo> from_assembly(AssemblyPtr assembly,
            gtirb::Addr source, std::optional<gtirb::Addr> dest) {
            auto direct = (dest == std::nullopt) ? gtirb::DirectEdge::IsIndirect
                                                 : gtirb::DirectEdge::IsDirect;

            switch (assembly->getId()) {
                case X86_INS_CALL:
                    return EdgeInfo(source, dest, gtirb::EdgeType::Call,
                        gtirb::ConditionalEdge::OnFalse, direct);
                case X86_INS_SYSCALL:
                    return EdgeInfo(source, dest, gtirb::EdgeType::Syscall,
                        gtirb::ConditionalEdge::OnFalse, direct);
                case X86_INS_SYSRET:
                    // Marking this as direct to reflect return edge behavior
                    return EdgeInfo(source, dest, gtirb::EdgeType::Sysret,
                        gtirb::ConditionalEdge::OnFalse,
                        gtirb::DirectEdge::IsDirect);
                case X86_INS_JO:
                case X86_INS_JS:
                case X86_INS_JE:
                case X86_INS_JB:
                case X86_INS_JAE:
                case X86_INS_JBE:
                case X86_INS_JA:
                case X86_INS_JL:
                case X86_INS_JGE:
                case X86_INS_JLE:
                case X86_INS_JG:
                case X86_INS_JP:
                case X86_INS_JCXZ:
                case X86_INS_JECXZ:
                case X86_INS_JRCXZ:
                    return EdgeInfo(source, dest, gtirb::EdgeType::Branch,
                        gtirb::ConditionalEdge::OnTrue, direct);
                case X86_INS_JMP:
                case X86_INS_LJMP:
                case X86_INS_JNE:
                case X86_INS_JNO:
                case X86_INS_JNP:
                case X86_INS_JNS:
                    return EdgeInfo(source, dest, gtirb::EdgeType::Branch,
                        gtirb::ConditionalEdge::OnFalse, direct);
                default:
                    LOG(0, "WARNING: Unknown asm edge at " << source);
                    return std::nullopt;
            }
        }

        static std::optional<EdgeInfo> from_control_flow(
            ControlFlowInstructionBase *instruction, gtirb::Addr source,
            std::optional<gtirb::Addr> dest) {
            auto mnemonic = instruction->getMnemonic();
            std::optional<EdgeInfo> output = std::nullopt;
            auto direct = (dest == std::nullopt) ? gtirb::DirectEdge::IsIndirect
                                                 : gtirb::DirectEdge::IsDirect;

            if (mnemonic == "callq") {
                output = EdgeInfo(source, dest, gtirb::EdgeType::Call,
                    gtirb::ConditionalEdge::OnFalse, direct);
            }
            else if ((mnemonic == "jo") || (mnemonic == "js") ||
                     (mnemonic == "je") || (mnemonic == "jb") ||
                     (mnemonic == "jae") || (mnemonic == "jbe") ||
                     (mnemonic == "ja") || (mnemonic == "jl") ||
                     (mnemonic == "jge") || (mnemonic == "jle") ||
                     (mnemonic == "jg") || (mnemonic == "jp") ||
                     (mnemonic == "jcxz") || (mnemonic == "jecxz") ||
                     (mnemonic == "jrcxz")) {
                output = EdgeInfo(source, dest, gtirb::EdgeType::Branch,
                    gtirb::ConditionalEdge::OnTrue, direct);
            }
            else if ((mnemonic == "jmp") || (mnemonic == "ljmp") ||
                     (mnemonic == "jne") || (mnemonic == "jno") ||
                     (mnemonic == "jnp") || (mnemonic == "jns")) {
                output = EdgeInfo(source, dest, gtirb::EdgeType::Branch,
                    gtirb::ConditionalEdge::OnFalse, direct);
            }
            else {
                LOG(0, "WARNING: Unknown cfi edge at " << source);
            }
            return output;
        }

        static std::vector<EdgeInfo> from_jumptable(
            IndirectJumpInstruction *instruction, gtirb::Addr source) {
            auto output = std::vector<EdgeInfo>();
            for (auto jumptable : instruction->getJumpTables()) {
                for (JumpTableEntry *entry : CIter::children(jumptable)) {
                    auto link = entry->getLink();
                    auto dest = gtirb::Addr(link->getTargetAddress());
                    output.push_back(
                        EdgeInfo(source, dest, gtirb::EdgeType::Branch,
                            gtirb::ConditionalEdge::OnFalse,
                            gtirb::DirectEdge::IsIndirect));
                }
            }
            return output;
        }

        static std::vector<EdgeInfo> from_instruction(
            Instruction *instruction) {
            auto output = std::vector<EdgeInfo>();
            auto semantic = instruction->getSemantic();
            if ((!semantic) || (!semantic->isControlFlow())) {
                return output;
            }

            auto source = gtirb::Addr(instruction->getAddress());
            std::optional<gtirb::Addr> dest = std::nullopt;
            if (auto *link = semantic->getLink()) {
                dest = gtirb::Addr(link->getTargetAddress());
            }

            if (dynamic_cast<ReturnInstruction *>(semantic)) {
                output.push_back(EdgeInfo(source, dest, gtirb::EdgeType::Return,
                    gtirb::ConditionalEdge::OnFalse,
                    gtirb::DirectEdge::IsDirect));
            }
            else if (dynamic_cast<IndirectCallInstruction *>(semantic)) {
                output.push_back(EdgeInfo(source, dest, gtirb::EdgeType::Call,
                    gtirb::ConditionalEdge::OnFalse,
                    gtirb::DirectEdge::IsIndirect));
            }
            else if (auto ijmp = dynamic_cast<IndirectJumpInstruction *>(
                         semantic)) {
                if (ijmp->isForJumpTable()) {
                    output = from_jumptable(ijmp, source);
                }
                else {
                    output.push_back(
                        EdgeInfo(source, dest, gtirb::EdgeType::Branch,
                            gtirb::ConditionalEdge::OnFalse,
                            gtirb::DirectEdge::IsIndirect));
                }
            }
            else if (auto assembly = semantic->getAssembly()) {
                if (auto dest_info = from_assembly(assembly, source, dest)) {
                    output.push_back(*dest_info);
                }
            }
            else if (auto *cfi = dynamic_cast<ControlFlowInstructionBase *>(
                         semantic)) {
                if (auto dest_info = from_control_flow(cfi, source, dest)) {
                    output.push_back(*dest_info);
                }
            }
            else {
                LOG(0, "WARNING: Unknown edge at " << source);
            }
            return output;
        }
    };
    std::vector<EdgeInfo> edges;
    bool is_fallthrough_function = true;
    /// \brief Map GTIRB block UUID's to their function UUID's
    std::map<gtirb::UUID, gtirb::UUID> block_to_function;

    /**
     * @brief Check if a symbol name is using Egalito's internal jump
     * syntax.
     *
     * @param symName Symbol name to check
     * @return true Symbol name contains invalid '/' character used in
     * Egalito's internal jump names
     * @return false Otherwise
     */
    inline bool symbolNameIsIJump(std::string symName) {
        return symName.find('/') != std::string::npos;
    }

    /**
     * @brief Get a valid GTIRB symbol name from a symbol name and/or address
     *
     * @param sym_name Name of the symbol. May be an internal jump or fuzzyfunc.
     * @param sym_addr Address of the symbol
     * @return std::string Valid symbol name
     */
    std::string get_gtirb_name(std::optional<std::string> sym_name,
        std::optional<address_t> sym_addr) {
        if (!sym_name || symbolNameIsIJump(*sym_name)) {
            return LinkInfo::symAddrName(*sym_addr);
        }
        else if (sym_addr && duplicate_sym_names[*sym_name]) {
            // Disambiguate symbol names marked as duplicate
            return LinkInfo::disambigName(*sym_name, *sym_addr);
        }

        // For fuzzyfunc, make sure we replace the invalid '-' char
        std::replace(sym_name->begin(), sym_name->end(), '-', '_');
        return *sym_name;
    }

    /**
     * @brief Get the byte interval containing the given address/size if it
     * exists. Create a new interval if necessary.
     *
     * @note If ival_size is set to 0, this function will search for an existing
     * interval without trying to create a new interval.
     *
     * @param ival_addr Address contained in the byte interval
     * @param ival_size Minimum interval size required (starting at ival_addr)
     * @return gtirb::ByteInterval *A byte interval containing the specified
     * address and size. Nullptr if the interval could not be found/created.
     */
    gtirb::ByteInterval *get_canonical_interval(
        address_t ival_addr, size_t ival_size = 0) {
        assert(gCtx.module);

        auto gSection = gCtx.section;
        if (!gSection || gtirb::Addr(ival_addr) < *gSection->getAddress() ||
            gtirb::Addr(ival_addr) >=
                (*gSection->getAddress() + *gSection->getSize())) {
            DataSection *eSection = nullptr;
            if (!eSection) {
                eSection = eCtx.module->getDataRegionList()
                               ->findDataSectionContaining(ival_addr);
            }
            if (!eSection) {
                LOG(0, "WARNING: No section containing 0x" << std::hex
                                                           << ival_addr);
                return nullptr;
            }
            auto sections = gCtx.module->findSections(eSection->getName());
            // Exactly one section must exist by this name
            assert(sections.begin() != sections.end());
            assert(std::next(sections.begin()) == sections.end());
            gSection = &*sections.begin();
        }

        gtirb::ByteInterval *interval = nullptr;
        auto intervals = gSection->findByteIntervalsOn(gtirb::Addr(ival_addr));
        if (intervals.begin() == intervals.end()) {
            interval = gSection->addByteInterval(
                C, gtirb::Addr(ival_addr), ival_size);
            log_chunk("  Byte interval: 0x", ival_addr);
            log_chunk("  Byte interval size: ", ival_size);
        }
        else {
            // Make sure there is only one interval per address
            assert(std::next(intervals.begin()) == intervals.end());
            interval = &*intervals.begin();
        }
        return interval;
    }

    /**
     * @brief Set the referent for a GTIRB symbol.
     *
     * @note This function assumes a block already exists for the GTIRB symbol
     * referent if it is on an existing byte interval.
     *
     * @param symbol Symbol to add the referent to.
     * @param ref_address Address of the referent.
     */
    void set_symbol_ref(gtirb::Symbol *symbol, gtirb::Addr ref_address) {
        bool dump = symbol->getName() == "environ";
        if (dump) {
            LOG(0, "*** in ssr for " << symbol->getName());
            LOG(0, "***   looking up gci at addr: " << ref_address);
        }

        auto interval = get_canonical_interval((address_t)ref_address);
        if (!interval) {
            LOG(0, "WARNING: No interval for ref at 0x" << std::hex
                                                        << ref_address);
            return;
        }

        gtirb::Node *block = nullptr;
        auto blocks = interval->findBlocksAt(ref_address);
        assert(blocks.begin() != blocks.end());
        block = &*blocks.begin();

        if (gtirb::CodeBlock *codeBlock = dyn_cast_or_null<gtirb::CodeBlock>(
                block)) {
            symbol->setReferent(codeBlock);
        }
        else if (gtirb::DataBlock
                     *dataBlock = dyn_cast_or_null<gtirb::DataBlock>(block)) {
            symbol->setReferent(dataBlock);
        }
    }

    /**
     * @brief Get the symbol associated with the given name/address if it
     * exists. Create a new symbol if necessary.
     *
     * @param sym_addr Egalito-given address of the symbol to search for
     * @param sym_name Egalito-given name of the symbol to search for
     * @param module The module in which the gtirb symbol would reside
     * @return gtirb::Symbol *A symbol with the address or name provided
     */
    gtirb::Symbol *get_canonical_symbol(std::optional<address_t> sym_addr,
        std::optional<std::string> sym_name, gtirb::Module *module) {
        if (!sym_addr && !sym_name) {
            return nullptr;
        }

        gtirb::Symbol *sym_out = nullptr;

        // Do we have a name?
        if (sym_name) {
            sym_name = get_gtirb_name(sym_name, sym_addr);

            // See if there is a symbol with a matching name
            // (Even if that symbol is at the wrong address.)
            sym_out = LinkInfo::symbol_from_name(*sym_name, sym_addr, module);

            // If we didn't find a symbol, create one.
            if (!sym_out) {
                sym_out = LinkInfo::create_symbol(
                    sym_addr, *sym_name, C, module);
                if (sym_addr) {
                    delayed_referrents.push_back(
                        std::make_pair(sym_out, gtirb::Addr(*sym_addr)));
                }
            }
            else if (sym_out->getAddress() && sym_addr &&
                     ((address_t)*sym_out->getAddress() != *sym_addr)) {
                // If we found the symbol, but the address is mismatched,
                // flag the duplicate name and disambiguate the symbols
                duplicate_sym_names[*sym_name] = true;

                auto original_disambig = LinkInfo::disambigName(
                    *sym_name, (address_t)*sym_out->getAddress());
                sym_out->setName(original_disambig);

                sym_name = LinkInfo::disambigName(*sym_name, *sym_addr);
                sym_out = LinkInfo::create_symbol(
                    sym_addr, *sym_name, C, module);
                if (sym_addr) {
                    delayed_referrents.push_back(
                        std::make_pair(sym_out, gtirb::Addr(*sym_addr)));
                }
            }
        }
        else {
            assert(sym_addr);
            // Don't have a name, see if we can find a symbol by address.
            sym_out = LinkInfo::symbol_from_addr(
                *sym_addr, std::nullopt, module);

            // Don't have one? Create one.
            if (!sym_out) {
                std::string name = LinkInfo::symAddrName(*sym_addr);
                sym_out = LinkInfo::create_symbol(sym_addr, name, C, module);
                delayed_referrents.push_back(
                    std::make_pair(sym_out, gtirb::Addr(*sym_addr)));
            }
        }

        assert(sym_out);
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
        return get_canonical_symbol(link.dst_addr, link.dst_name, gModule);
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
        return get_canonical_symbol(
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
    gtirb::DataBlock *try_adding_data_block(
        gtirb::ByteInterval *interval, address_t blockAddr, size_t blockSize) {
        auto section = eCtx.section
                           ? eCtx.section
                           : eCtx.module->getDataRegionList()
                                 ->findDataSectionContaining(blockAddr);

        // Dynamic section blocks must be empty.
        if (section && (section->getType() == DataSection::TYPE_DYNAMIC)) {
            log_chunk("    Dynamic: True");
            blockSize = 0;
        }
        gtirb::Addr intervalStart = *interval->getAddress();
        return interval->addBlock<gtirb::DataBlock>(
            C, gtirb::Addr(blockAddr) - intervalStart, blockSize);
    }

    /**
     * @brief Resize functions to prevent overlap during parsing.
     *
     * FIXME: This process has two loops through function list sized
     * collections, which is not very efficient.
     */
    void remove_function_overlap() {
        assert(eCtx.module);

        // Map out the intervals required for each function
        std::map<address_t, Function *> interval_addrs;
        for (auto &function : CIter::children(eCtx.module->getFunctionList())) {
            interval_addrs[function->getAddress()] = function;
        }

        // Resize functions
        std::unordered_map<DataSection *, Function *> functionCursors;
        for (auto &[ivalAddr, function] : interval_addrs) {
            auto eSection = eCtx.module->getDataRegionList()
                                ->findDataSectionContaining(ivalAddr);
            if (!eSection) {
                std::cerr << "WARNING: No section containing " << std::hex
                          << ivalAddr << std::endl;
                continue;
            }
            // Skip the first function (we need the next one to detect overlap)
            if (!functionCursors[eSection]) {
                functionCursors[eSection] = function;
                continue;
            }
            auto lastFunction = functionCursors[eSection];

            // We don't want to add any extra bytes to functions, just remove
            // overlap
            auto lastFunctionSize = std::min(
                function->getAddress() - lastFunction->getAddress(),
                lastFunction->getSize());
            lastFunction->setSize(lastFunctionSize);

            functionCursors[eSection] = function;
        }
        // No need to resize the last function in each section.
        // Section spillover should already be handled by byte interval sizing.
    }

    /**
     * @brief Split an existing code block at a specified address
     *
     * @param interval Byte interval the original block exists on
     * @param block CodeBlock to split
     * @param addr Program-relative address where block should be split
     */
    void split_code_block_on(gtirb::ByteInterval *interval,
        gtirb::CodeBlock *block, address_t addr) {
        auto original_addr = address_t(*block->getAddress());
        if (original_addr == addr) {
            // Nothing to split
            return;
        }
        auto original_size = block->getSize();
        auto original_resize = addr - original_addr;
        block->setSize(original_resize);

        auto new_size = original_size - original_resize;
        uint64_t new_offset = addr - (uint64_t)*interval->getAddress();
        gtirb::CodeBlock *new_block = interval->addBlock<gtirb::CodeBlock>(
            C, new_offset, new_size);

        // Add the new block to a function
        gCtx.functionId = block_to_function[block->getUUID()];
        gCtx.addBlockToFunction(new_block, block);
        block_to_function[new_block->getUUID()] = *gCtx.functionId;

        log_chunk("- Split (Code): ", original_addr, " -> ",
            original_addr + original_size);
        log_chunk("    First: ", block->getAddress(), " -> ",
            (address_t)(*block->getAddress()) + block->getSize());
        log_chunk("    Second: ", new_block->getAddress(), " -> ",
            (address_t)(*new_block->getAddress()) + new_block->getSize());
    }

    /**
     * @brief Split an existing data block at a specified address
     *
     * @param interval Byte interval the original block exists on
     * @param block DataBlock to split
     * @param addr Program-relative address where block should be split
     */
    void split_data_block_on(gtirb::ByteInterval *interval,
        gtirb::DataBlock *block, address_t addr) {
        if (block->getAddress() == gtirb::Addr(addr)) {
            // Nothing to split
            return;
        }
        auto original_size = block->getSize();
        auto original_addr = address_t(*block->getAddress());
        auto original_resize = addr - original_addr;
        block->setSize(original_resize);

        auto new_size = original_size - original_resize;
        auto new_block = try_adding_data_block(interval, addr, new_size);

        log_chunk("- Split (Data): ", original_addr, " -> ",
            original_addr + original_size);
        log_chunk("    First: ", block->getAddress(), " -> ",
            (address_t)(*block->getAddress()) + block->getSize());
        log_chunk("    Second: ", new_block->getAddress(), " -> ",
            (address_t)(*new_block->getAddress()) + new_block->getSize());
    }

    /**
     * @brief Split an existing block at a specified address
     *
     * @note If no blocks are found at the specified address, a 0-sized data
     * block will be created at the address
     *
     * @param interval Byte interval the original block exists on
     * @param addr Program-relative address where block should be split
     */
    void split_block_on(gtirb::ByteInterval *interval, address_t addr) {
        auto blocks = interval->findBlocksOn(gtirb::Addr(addr));
        if (blocks.begin() == blocks.end()) {
            LOG(0, "WARNING: No blocks to split at " << std::hex << addr);
            try_adding_data_block(interval, addr, 0);
            return;
        }
        auto block = &*blocks.begin();
        if (gtirb::CodeBlock *codeBlock = dyn_cast_or_null<gtirb::CodeBlock>(
                block)) {
            split_code_block_on(interval, codeBlock, addr);
        }
        else if (gtirb::DataBlock
                     *dataBlock = dyn_cast_or_null<gtirb::DataBlock>(block)) {
            split_data_block_on(interval, dataBlock, addr);
        }
    }

    void visit(Program *eProgram) {
        eCtx.program = eProgram;

        // FIXME: We should be recursing into all program modules, not just the
        // main one. However, that currently breaks the program.
        visit(eProgram->getMain());

        // After traversal, we have to go back and set referrents for
        // symbols created. This is done here since during the traversal
        // a symbol could refer to an object that hasn't be constructed
        // yet.
        for (auto [sym, addr] : delayed_referrents) {
            set_symbol_ref(sym, addr);
        }
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
        gModule->addAuxData<gtirb::schema::ElfSymbolInfo>(
            gtirb::schema::ElfSymbolInfo::Type());
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
        gModule->addAuxData<gtirb::schema::SectionProperties>(
            gtirb::schema::SectionProperties::Type());

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
        // Remove any function overlap created during parsing
        remove_function_overlap();

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
            visit(eModule->getExternalSymbolList());
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

            // Ensure that there is at at least one interval on this address
            auto interval = get_canonical_interval(linkInfo.src_addr);
            assert(interval);

            auto offset = gtirb::Addr(linkInfo.src_addr) -
                          *interval->getAddress();

            switch (linkInfo.type) {
                case LinkInfo::TYPE_ADDR: {
                    auto base = get_base_from_link(linkInfo, gModule);
                    interval->addSymbolicExpression<gtirb::SymAddrAddr>(offset,
                        linkInfo.dst_scale, linkInfo.dst_offset, dst, base);
                } break;
                case LinkInfo::TYPE_CONST: {
                    interval->addSymbolicExpression<gtirb::SymAddrConst>(
                        offset, linkInfo.dst_offset, dst, linkInfo.attrs);
                } break;
                case LinkInfo::TYPE_FORWARD: {
                    gtirb::Symbol *src = get_canonical_symbol(
                        linkInfo.src_addr, linkInfo.src_name, gCtx.module);
                    gCtx.addSymbolForwarding(src, dst);
                } break;
            }
            LOG(10, "Added symbolic expression for " << linkInfo.label()
                                                     << " at " << offset);
        }

        // Add callgraph edges
        auto &gtirb_cfg = gModule->getIR()->getCFG();
        for (auto info : edges) {
            const gtirb::CodeBlock
                *src = &*gModule->findCodeBlocksOn(info.source).begin();

            const gtirb::CfgNode *dest = nullptr;
            if (info.dest) {
                auto dest_blocks = gModule->findCodeBlocksOn(*info.dest);
                if (dest_blocks.begin() != dest_blocks.end()) {
                    dest = &*dest_blocks.begin();
                }
            }
            if (dest == nullptr) {
                // XXX: We may be able to only use a single proxyblock for all
                // edges. Taking the conservative approach for now.
                dest = gModule->addProxyBlock(C);
            }

            auto E = addEdge(src, dest, gtirb_cfg);
            gtirb_cfg[*E] = std::make_tuple(
                info.conditional, info.direct, info.type);
        }

        // Make sure we add blocks required by symbol referents
        for (auto [sym, ref_address] : delayed_referrents) {
            auto blocks = gCtx.module->findBlocksAt(ref_address);
            if (blocks.begin() == blocks.end()) {
                log_chunk("- Referent Block: ", ref_address);
                registerDataBlock(address_t(ref_address), 0);
            }
        }

        // Add data blocks for regions that aren't covered by existing ones

        // Keep a pointer to the current location in each byte interval,
        // then run through the created blocks in ascending order,
        // filling in gaps in the blocks as you go

        std::unordered_map<gtirb::ByteInterval *, gtirb::Addr> addrCursors;
        for (auto &[blockAddr, blockSize] : block_addrs) {
            // Should be exactly one interval on this address at this point
            auto interval = get_canonical_interval(blockAddr);
            if (!interval) {
                std::cerr << "WARNING: No interval covering " << std::hex
                          << blockAddr << std::endl;
                continue;
            }
            gtirb::Addr intervalStart = *interval->getAddress();

            // If there is an existing cursor for this byte interval, use it
            // Otherwise, advance it from 0 (the default value for addrCursors)
            // to the start address of this interval
            gtirb::Addr &cursor = addrCursors[interval];
            cursor = std::max(cursor, intervalStart);

            gtirb::Addr gAddr(blockAddr);
            if (cursor < gAddr) {
                log_chunk("- filler:");
                log_chunk("    start: ", cursor);
                log_chunk("    end: ", blockAddr);
                try_adding_data_block(
                    interval, (address_t)cursor, (size_t)(gAddr - cursor));
                cursor = gAddr + blockSize;
            }
            else {
                // If blockAddr is behind the cursor addr,
                // that means that the new block falls in the middle of
                // a previously created one.
                // Handle this by splitting the existing block
                split_block_on(interval, blockAddr);
                cursor = std::max(cursor, gtirb::Addr(blockAddr + blockSize));
            }
        }

        log_chunk("  Closing blocks: ");
        // Add extra datablocks to end of intervals
        for (auto &[interval, cursor] : addrCursors) {
            gtirb::Addr intervalAddr = *interval->getAddress();
            gtirb::Addr intervalEnd = intervalAddr + interval->getSize();
            if (intervalEnd > cursor) {
                log_chunk("  - start: ", cursor);
                log_chunk("    end: ", intervalEnd);
                log_chunk("    offset: ", cursor - intervalAddr);
                log_chunk("    size: ", intervalEnd - cursor);
                try_adding_data_block(interval, (address_t)cursor,
                    (size_t)(intervalEnd - cursor));
            }
        }

        // This has to come after parsing the module,
        // because library usage is added to the gtirb::module's auxData
        // (which doesn't exist until module parsing)
        // FIXME: This will not work with a deep scan of dependencies
        visit(eCtx.program->getLibraryList());
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
        auto tls_ld_flag = gtirb::SectionFlag::Loaded;
        if (auto *tls = eCtx.module->getDataRegionList()->getTLS()) {
            if (tls->containsData(eSection->getAddress())) {
                tls_ld_flag = gtirb::SectionFlag::ThreadLocal;
            }
        }
        gSection->addFlag(tls_ld_flag);
        // Make sure we don't create a symbol with the same name as a section
        duplicate_sym_names[eSection->getName()] = true;

        gCtx.section = gSection;
        eCtx.section = eSection;
        gCtx.setSectionAlignment(eSection->getAlignment());
        gCtx.setSectionProperties(eSection);

        if (eSection->getSize()) {
            // Attempt to create a single byte interval per section
            // (further gtirb analyses can split this up if desired)
            gCtx.byteInterval = get_canonical_interval(
                eSection->getAddress(), eSection->getSize());
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
     * @brief Determine if a DataVariable is a forwarded symbol.
     *
     * @details According to ddisasm, the following symbols should be added to
     * the symbol forwarding table:
     *          - Copy relocations
     *          - ABI-specific artifacts
     *          - PLT entries
     *          - GOT entries
     *
     * @param variable DataVariable to check
     * @return true variable is a forwarded symbol
     * @return false Otherwise
     */
    inline bool is_forwarded_symbol(DataVariable *variable) {
        auto sectionName = variable->getParent()->getName();
        return (variable->getIsCopy() ||
                (sectionName.find(".plt") != std::string::npos) ||
                (sectionName.find(".got") != std::string::npos));
    }

    inline bool is_weak_symbol(Symbol *sym) {
        return sym->getBind() == Symbol::BindingType::BIND_WEAK;
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

        Link *dest = variable->getDest();
        if (dest && !is_forwarded_symbol(variable)) {
            // "Dest" variables don't seem to need a symbol,
            // we just need to create a symbolic reference from this address
            log_chunk("  Type: Link");
            if (dest->getTarget()) {
                log_chunk("  Dest name: ", dest->getTarget()->getName());
            }
            log_chunk("  Dest addr: ", dest->getTargetAddress());
            links.push_back(LinkInfo::from_link(
                variable->getAddress(), dest, variable->getName()));
            return;
        }
        else if (variable->getIsCopy()) {
            // pprinter identifies copy relocations by searching for symbols
            // with a "_copy" suffix.
            variable->setName(variable->getName() + "_copy");
        }
        else {
            variable->setName(LinkInfo::symAddrName(variable->getAddress()));
        }

        // The symbol has to be created so the symbol forwarding table can be
        // made
        gtirb::Symbol *gSymbol = get_canonical_symbol(
            variable->getAddress(), variable->getName(), gCtx.module);

        log_chunk("  Type: Target");
        log_chunk("  Symbol name: ", gSymbol->getName());

        // Generate a name for the symbol at this address, and add forwarding to
        // a non-addressed symbol with the target name.
        Symbol *target = variable->getTargetSymbol();
        if (!target) {
            log_chunk("  No Target");
            links.push_back(LinkInfo::forward_from_link(
                variable->getAddress(), dest, variable->getName()));
            return;
        }
        log_chunk("  Target name: ", target->getName());
        log_chunk("  Target addr: ", target->getAddress());
        log_chunk("  Target type: ", target->getType());

        // TODO: Deal with aliases?

        // Create a separate symbol for the target if there isn't already one of
        // this name.
        // TODO: I _think_ this is the only place that certain symbols (e.g.
        // __cxa_finalize) are listed
        //       but I am not 100% sure that they don't have a less ambiguous
        //       reference elsewhere
        gtirb::Symbol *gTarget = get_canonical_symbol(
            std::nullopt, target->getName(), gCtx.module);

        if (is_weak_symbol(target)) {
            delayed_referrents.push_back(
                std::make_pair(gTarget, gtirb::Addr(target->getAddress())));
        }
        // Prefer adding symbols for local copies over weak instnces.
        // This information is used when generating dummy SO files.
        if (variable->getIsCopy()) {
            if (!gCtx.symbolInfoExists(gSymbol)) {
                gCtx.addSymbolInfo(gSymbol, variable->getSize(),
                    eSymTypeStr(target->getType()),
                    eSymBindingStr(target->getBind()), "DEFAULT",
                    target->getSectionIndex());
            }
        }
        else if (!gCtx.symbolInfoExists(gTarget)) {
            gCtx.addSymbolInfo(gTarget, target->getSize(),
                eSymTypeStr(target->getType()),
                eSymBindingStr(target->getBind()), "DEFAULT",
                target->getSectionIndex());
        }
        gCtx.addSymbolForwarding(gSymbol, gTarget);
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
        gtirb::Symbol *gSymbol = get_canonical_symbol(
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

        auto addr = function->getAddress();

        gCtx.byteInterval = get_canonical_interval(addr, function->getSize());
        gCtx.section = gCtx.byteInterval->getSection();
        log_chunk("  Symbol Section: ", gCtx.section->getName());
        eCtx.function = function;
        std::string symName = function->getName();
        auto symSize = function->getSize();
        auto symType = Symbol::SymbolType::TYPE_FUNC;
        auto symBind = Symbol::BindingType::BIND_LOCAL;
        if (function->getRange().contains(
                eCtx.program->getEntryPointAddress())) {
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

        gtirb::Symbol *gSymbol = get_canonical_symbol(
            addr, symName, gCtx.module);

        // Ignore duplicate function definitions
        if (gCtx.symbolInfoExists(gSymbol)) {
            log_chunk("  Duplicate");
            return;
        }
        gCtx.functionId = gCtx.assignFunctionId(gSymbol);
        gCtx.addSymbolInfo(
            gSymbol, symSize, eSymTypeStr(symType), eSymBindingStr(symBind));

        is_fallthrough_function = true;
        recurse<Block *>(function);
        if (is_fallthrough_function) {
            auto block = function->getChildren()->getIterable()->getLast();
            auto instr = block->getChildren()->getIterable()->getLast();
            auto targetAddress = instr->getAddress() + instr->getSize();

            auto edge = EdgeInfo(gtirb::Addr(instr->getAddress()),
                gtirb::Addr(targetAddress), gtirb::EdgeType::Fallthrough,
                gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsDirect);
            edges.push_back(edge);
        }
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
        if (block->getAddress() + block->getSize() >
            eCtx.function->getAddress() + eCtx.function->getSize()) {
            std::cout << "WARNING: End of block at " << block->getAddress()
                      << " falls outside of bounds of function "
                      << eCtx.function->getName() << std::endl;
            return;
        }

        gtirb::CodeBlock *codeBlock = gCtx.byteInterval
                                          ->addBlock<gtirb::CodeBlock>(
                                              C, blockOffset, block->getSize());
        block_addrs[block->getAddress()] = block->getSize();
        block_to_function[codeBlock->getUUID()] = *gCtx.functionId;
        if (block->getRange().contains(eCtx.program->getEntryPointAddress())) {
            log_chunk("  EntryPoint");
            gCtx.module->setEntryPoint(codeBlock);
        }

        gCtx.addBlockToFunction(codeBlock);

        gCtx.codeBlock = codeBlock;
        log_chunk("  Instructions:");
        recurse<Instruction *>(block);
    }

    /**
     * @brief Function for obtaining the displacement offset from a linked
     * instruction.
     *
     * @param linked_instr Instruction to search
     * @return int Displacement offset (std::string::npos if not found)
     */
    int findLinkOffset(LinkedInstructionBase *linked_instr) {
        auto *semantic = dynamic_cast<InstructionSemantic *>(linked_instr);

        auto assembly = semantic->getAssembly();
        auto operand = assembly->getAsmOperands()
                           ->getOperands()[linked_instr->getIndex()];
        std::string disp_str((char *)&operand.mem.disp);
        auto instr_string = semantic->getData();

        auto disp_offset = instr_string.find(disp_str);
        // Make sure there is only one byte sequence matching the displacement
        // value.
        if ((disp_offset != std::string::npos) &&
            (instr_string.find(disp_str, disp_offset + 1) ==
                std::string::npos)) {
            return disp_offset;
        }
        return std::string::npos;
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

        auto instr_edges = EdgeInfo::from_instruction(instruction);
        if (!instr_edges.empty()) {
            log_chunk("  Edge: ", instr_edges[0].type);
            is_fallthrough_function = false;
            edges.insert(edges.end(), instr_edges.begin(), instr_edges.end());
        }

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

                // NOTE: One known cause of this error is a failure to correctly
                // parse the displacement size in
                // MakeSemantic::determineDisplacementSize
                if (op_offset == data.size()) {
                    op_offset = findLinkOffset(li);
                    if (op_offset == std::string::npos) {
                        std::cerr << "ERROR: Instruction at " << instrAddr
                                  << " contains an invalid link offset"
                                  << std::endl;
                        return;
                    }
                }
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
        gtirb::Symbol *gSymbol = get_canonical_symbol(
            std::nullopt, eSymbol->getName(), gCtx.module);
        // Symbol info for local instances of weak external symbols will be
        // added in the DataVariable visitor
        if (!eSymbol->getLocalWeakInstance()) {
            gCtx.addSymbolInfo(gSymbol, eSymbol->getSize(),
                eSymTypeStr(eSymbol->getType()),
                eSymBindingStr(eSymbol->getBind()));
        }
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
        // Organize external symbols by library.
        // This is required for pprinter to correctly assign external symbols
        // when creating dummy so's.
        // Warning: This may be a workaround for a deeper issue
        std::map<std::string, std::vector<ExternalSymbol *>> extSymMap;
        const std::string defaultLib = "__default__";
        for (ExternalSymbol *extSym : CIter::children(externalSymbolList)) {
            std::string libName = defaultLib;
            if (auto resolvedLib = extSym->getResolvedModule()) {
                libName = resolvedLib->getName();
                // Remove "module-" prefix
                libName.erase(0, 7);
            }
            extSymMap[libName].push_back(extSym);
        }

        for (auto *lib : CIter::children(eCtx.program->getLibraryList())) {
            auto symbols = extSymMap[lib->getName()];
            for (ExternalSymbol *extSym : symbols) {
                visit(extSym);
            }
        }
        // Add any symbols that were not assigned to a library
        for (ExternalSymbol *extSym : extSymMap[defaultLib]) {
            visit(extSym);
        }
    }
    void visit(InitFunctionList *initFunctionList) {
        recurse(initFunctionList);
    }

    void visit(JumpTable *jumpTable) {
        log_chunk("- Chunk: !jumpTable ", jumpTable->getName());
        log_chunk("  Location: ", jumpTable->getAddress());
        eCtx.jtable = jumpTable;
        recurse(jumpTable);
    }

    void visit(PLTTrampoline *trampoline) {
        std::string name = trampoline->getName();
        log_chunk("- Chunk: !trampoline ", name);
        log_chunk("  Location: ", trampoline->getAddress());
        log_chunk("  GotPLTEntry: ", trampoline->getGotPLTEntry());
        auto gSymbol = get_canonical_symbol(
            trampoline->getAddress(), name, gCtx.module);

        auto eTarget = trampoline->getExternalSymbol();
        gtirb::Symbol *gTarget = get_canonical_symbol(
            std::nullopt, eTarget->getName(), gCtx.module);
        if (!gCtx.symbolInfoExists(gTarget)) {
            gCtx.addSymbolInfo(gTarget, eTarget->getSize(),
                eSymTypeStr(eTarget->getType()),
                eSymBindingStr(eTarget->getBind()));
        }

        gCtx.addSymbolForwarding(gSymbol, gTarget);
    }

    void visit(JumpTableEntry *jumpTableEntry) {
        log_chunk("- Chunk: !jtentry ", jumpTableEntry->getName());

        auto entryAddr = jumpTableEntry->getAddress();
        auto entryName = jumpTableEntry->getName();
        auto link = jumpTableEntry->getLink();
        auto baseLink = eCtx.jtable->getDescriptor()->getTargetBaseLink();
        auto baseAddress = baseLink->getTargetAddress();
        auto baseName = baseLink->getTarget()->getName();

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
    register_gtirb_auxdata();
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
