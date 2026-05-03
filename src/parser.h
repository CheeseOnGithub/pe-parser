#pragma once

#include "mappedfile.h"
#include "winTypes.h"
#include <cstdint>
#include <vector>

struct ImportEntry {
    std::string dllName;
    std::vector<std::string> functions;
};

class PEParser {    
public:
    explicit PEParser(const MappedFile& _file);
    const IMAGE_NT_HEADERS* NtHeaders() const;
    const std::span<const IMAGE_SECTION_HEADER> Sections() const;
    std::vector<ImportEntry> Imports() const;
    std::span<const std::byte> SectionData(const IMAGE_SECTION_HEADER& section) const;
    static float Entropy(std::span<const std::byte> bytes); // shannon entropy

private:
    const MappedFile& file;
    struct PEData {
        const IMAGE_NT_HEADERS* ntHeaders = nullptr;
        std::span<const IMAGE_SECTION_HEADER> sections;
    } data;

    bool IsPEFile();
    void Parse(const MappedFile& file);
    template<typename T> 
    void WalkLookupTable(uint32_t iltOffset, ImportEntry& entry) const;

    const uint32_t RvaToOffset(uint32_t rva) const;
};