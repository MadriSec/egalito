#include "gtirb_util.h"

#include "gtirb/AuxDataContainer.hpp"
#include "gtirb/AuxDataSchema.hpp"

// Register AuxData used in the Egalito/GTIRB integration
void register_gtirb_auxdata()
{
    using namespace gtirb;
    using namespace gtirb::schema;

    static bool initialized = false;
    if(initialized) {
        return;
    }

    AuxDataContainer::registerAuxDataType<FunctionEntries>();
    AuxDataContainer::registerAuxDataType<FunctionBlocks>();
    AuxDataContainer::registerAuxDataType<FunctionNames>();
    AuxDataContainer::registerAuxDataType<ElfSymbolInfo>();
    initialized = true;
}
