#include "mappedfile.h"
#include <filesystem>
#include <format>
#include <stdexcept>
#include <unistd.h>

// linux only headers
#include <fcntl.h>
#include <sys/mman.h>


MappedFile::MappedFile(const char* path) {
    m_fd = open(path, O_RDONLY);
    if (m_fd < 0) throw std::runtime_error(std::format("failed to open: {}", path));

    m_size = std::filesystem::file_size(path);

    void* map = mmap(nullptr, m_size, PROT_READ, MAP_PRIVATE, m_fd, 0);
    if (map == MAP_FAILED) throw std::runtime_error("mmap failed");

    data = static_cast<std::byte*>(map);
}

MappedFile::~MappedFile() {
    if (data) munmap(data, m_size);
    if (m_fd >= 0) close(m_fd);
}

std::span<const std::byte> MappedFile::bytes() const {
    return {data, m_size};
}