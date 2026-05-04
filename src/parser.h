#pragma once

#include "mappedfile.h"
#include "winTypes.h"
#include <cstdint>
#include <vector>

struct ImportEntry {
    std::string dllName;
    std::vector<std::string> functions;
};

struct ExportEntry {
    std::string name;
    uint32_t ordinal;
    uint32_t rva;
    std::string forwarder;
};

class PEParser {    
public:
    explicit PEParser(const MappedFile& _file);
    const IMAGE_NT_HEADERS* NtHeaders() const;
    const std::span<const IMAGE_SECTION_HEADER> Sections() const;
    std::vector<ImportEntry> Imports() const;
    std::vector<ExportEntry> Exports() const;
    std::span<const std::byte> SectionData(const IMAGE_SECTION_HEADER& section) const;
    static float Entropy(std::span<const std::byte> bytes); // shannon entropy

private:
    const MappedFile& file;
    struct PEData {
        bool isPE32Plus = false;
        const IMAGE_NT_HEADERS* ntHeaders = nullptr;
        const IMAGE_NT_HEADERS64* ntHeaders64 = nullptr;
        std::span<const IMAGE_SECTION_HEADER> sections;
    } data;

    bool IsPEFile() const;
    void Parse(const MappedFile& file);
    template<typename T> 
    void WalkLookupTable(uint32_t iltOffset, ImportEntry& entry) const;
    const IMAGE_DATA_DIRECTORY& GetDataDirectory(uint32_t index) const;

    uint32_t RvaToOffset(uint32_t rva) const;
};