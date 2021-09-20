#include "gtirb_deserializer.h"

#include "gtirb/gtirb.hpp"
#include "log/log.h"

#include <fstream>

GtirbDeserializer::GtirbDeserializer(std::string filename)
    : filename(filename)
    , C(new gtirb::Context())
    , ir(nullptr)
{}

GtirbDeserializer::~GtirbDeserializer() = default;

bool GtirbDeserializer::preParse() {
    std::ifstream in(this->filename, std::ios::in | std::ios::binary);
    if(!in.is_open()) {
        return false;
    }

    auto err_or_ir = gtirb::IR::load(*this->C, in);
    if(err_or_ir) {
        this->ir = *err_or_ir;
        return true;
    }
    else {
        return false;
    }
}

/** Returns the root of the deserialized tree. */
Program *GtirbDeserializer::deserialize() {
    LOG(1, "GTIRB deserialization");

    if(this->ir == NULL) {
        this->preParse();
        if(this->ir == NULL) {
            LOG(1, "Failed to load GTIRB IR in file " << this->filename);
            return NULL;
        }
    }

    // Translate IR to Egalito...

    return NULL;
}
