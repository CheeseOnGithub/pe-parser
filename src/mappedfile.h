#pragma once

#include <cstddef>
#include <span>
#include <stdexcept>

class MappedFile {
public:
    explicit MappedFile(const char* path);
    ~MappedFile();

    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    std::span<const std::byte> bytes() const;

    template<typename T>
    const T* as(size_t offset = 0) const {
        auto view = bytes();
        if (offset + sizeof(T) > view.size())
            throw std::out_of_range("struct read out of bounds");
        return reinterpret_cast<const T*>(view.data() + offset);
    }
private:
    int m_fd = -1;
    size_t m_size = 0;
    std::byte* data = nullptr;
};