#include <cassert>
#include "position.h"
#include "chunk.h"

address_t RelativePosition::get() const {
    assert(object != nullptr);
    assert(object->getParent() != nullptr);
    return object->getParent()->getPosition()->get() + offset;
}

void RelativePosition::set(address_t value) {
    assert(object != nullptr);
    assert(object->getParent() != nullptr);
    assert(value >= object->getParent()->getPosition()->get());
    setOffset(value - object->getParent()->getPosition()->get());
}

address_t CachedRelativePosition::get() const {
    if(cache.isValid()) return cache.get();

    auto value = RelativePosition::get();
    cache.set(value);
    return value;
}

void CachedRelativePosition::set(address_t value) {
    RelativePosition::set(value);
    cache.set(value);
}

void CachedRelativePosition::setOffset(address_t offset) {
    RelativePosition::setOffset(offset);
    cache.invalidate();
}

void ComputedSize::adjustBy(diff_t add) {
    assert(static_cast<diff_t>(size + add) >= 0);
    size += add;
}