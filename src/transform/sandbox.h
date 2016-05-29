#ifndef EGALITO_SANDBOX_H
#define EGALITO_SANDBOX_H

#include <vector>
#include <new>
#include "types.h"

#define MAX_SANDBOX_SIZE (100 * 0x1000 * 0x1000)

class Slot {
private:
    address_t address;
    size_t available;
public:
    Slot(address_t address, size_t size)
        : address(address), available(size) {}
    uint8_t *read() { return 0; }
    bool append(uint8_t *data, size_t size);
};

class AnyLengthSlot {
private:
    std::vector<uint8_t> buffer;
public:
    uint8_t *read() { return buffer.data(); }
    bool append(uint8_t *data, size_t size);
};

class ReadOnlySlot {
private:
    uint8_t *address;
public:
    ReadOnlySlot(uint8_t *address) : address(address) {}

    uint8_t *read() { return address; }
    bool append(uint8_t *data, size_t size) { return false; }
};

class SandboxBacking {
private:
    size_t size;
public:
    SandboxBacking(size_t size) : size(size) {}

    address_t getBase() const;
    size_t getSize() const { return size; }

    void finalize();
};

class MemoryBacking : public SandboxBacking {
private:
    address_t base;
public:
    /** May throw std::bad_alloc. */
    MemoryBacking(size_t size);
    address_t getBase() const { return base; }

    void finalize();
};

class ELFBacking : public MemoryBacking {
private:
    std::string filename;
public:
    ELFBacking(std::string filename);

    void finalize();
};

template <typename Backing>
class SandboxAllocator {
protected:
    Backing *backing;
public:
    SandboxAllocator(Backing *backing) : backing(backing) {}

    /** May throw std::bad_alloc. */
    Slot allocate(size_t request);
};

template <typename Backing>
class WatermarkAllocator : public SandboxAllocator<Backing> {
private:
    address_t watermark;
public:
    WatermarkAllocator(SandboxBacking *backing) : SandboxAllocator<Backing>(backing), watermark(backing->getBase()) {}

    Slot allocate(size_t request);
};

template <typename Backing>
Slot WatermarkAllocator<Backing>::allocate(size_t request) {
    size_t max = this->backing->getBase()
        + this->backing->getSize();

    if(watermark + request > max) {
        throw std::bad_alloc();
    }

    address_t region = watermark;
    watermark += request;
    return Slot(region, request);
}

class Sandbox {
public:
    virtual ~Sandbox() {}

    /** May throw std::bad_alloc. */
    virtual Slot allocate(size_t request) = 0;
    virtual void finalize() = 0;
};

template <typename Backing, typename Allocator>
class SandboxImpl : public Sandbox {
private:
    Backing backing;
    Allocator alloc;
public:
    SandboxImpl(const SandboxBacking &&backing)
        : backing(backing), alloc(Allocator(backing)) {}

    virtual Slot allocate(size_t request)
        { return alloc.allocate(request); }
    virtual void finalize() { backing.finalize(); }
};

#endif