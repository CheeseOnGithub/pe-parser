#include "parser.h"
#include "winTypes.h"
#include <cmath>
#include <cstdint>
#include <exception>
#include <format>
#include <stdexcept>

PEParser::PEParser(const MappedFile& _file) : file(_file) {
    if (!IsPEFile()) throw std::runtime_error("file is not pe file");
    Parse(file);
}

const IMAGE_NT_HEADERS* PEParser::NtHeaders() const {
    return data.ntHeaders;
}

const std::span<const IMAGE_SECTION_HEADER> PEParser::Sections() const {
    return data.sections;
}

template<typename T> // just to handle x32 and x64 Mate
void PEParser::WalkLookupTable(uint32_t iltOffset, ImportEntry& entry) const {
    constexpr T ORDINAL = (sizeof(T) == 8) ? T(0x8000000000000000ULL) : T(0x80000000U); // flags
    constexpr T NAME = (sizeof(T) == 8) ? T(0x7FFFFFFFFFFFFFFFULL) : T(0x7FFFFFFFU);
    constexpr T ORDINAL_MASK = 0xFFFF;

    auto* lookupEntry = file.as<T>(iltOffset);
    
    while (*lookupEntry != 0) {
        if (*lookupEntry & ORDINAL) {
            entry.functions.push_back(std::format("ordinal {}", *lookupEntry & ORDINAL_MASK));
        } else {
            uint32_t nameOffset = RvaToOffset(static_cast<uint32_t>(*lookupEntry & NAME));
            // struct IMAGE_IMPORT_BY_NAME {
            //     uint16_t Hint; 
            //     char     Name[]; 
            // };

            entry.functions.push_back(file.as<char>(nameOffset + sizeof(uint16_t)));
        }

        ++lookupEntry;
    }
}

std::vector<ImportEntry> PEParser::Imports() const {
    auto& importDir = data.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    uint32_t arrOffset = RvaToOffset(importDir.VirtualAddress);
    auto descriptor = file.as<IMAGE_IMPORT_DESCRIPTOR>(arrOffset);

    std::vector<ImportEntry> imports;

    bool isPE32Plus = data.ntHeaders->OptionalHeader.Magic == 0x20B;

    while(descriptor->Name != 0) {
        ImportEntry entry;
        entry.dllName = file.as<char>(RvaToOffset(descriptor->Name));

        uint32_t iltOffset = RvaToOffset(descriptor->ImportLookupTable);
        if (isPE32Plus) {
            WalkLookupTable<uint64_t>(iltOffset, entry);
        } else {
            WalkLookupTable<uint32_t>(iltOffset, entry);
        }
        imports.push_back(std::move(entry));
        ++descriptor;
    }
    return imports;
}

// res is 0.0 -> 8.0
float PEParser::Entropy(std::span<const std::byte> bytes) {
    if (bytes.empty()) return 0.f;

    int counts[256]{};
    for (auto b : bytes) {
        counts[static_cast<uint8_t>(b)] += 1;
    }

    float total = static_cast<float>(bytes.size());
    float entropy = 0.f;

    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;

        float p = counts[i] / total;
        entropy -= p * std::log2(p); // - is here cos log will return negative and we want positive (p is 0 -> 1)
    }

    return entropy;
}

std::span<const std::byte> PEParser::SectionData(const IMAGE_SECTION_HEADER& section) const {
    return file.bytes().subspan(section.PointerToRawData, section.SizeOfRawData);
}

void PEParser::Parse(const MappedFile& file) {
    auto* dos = file.as<IMAGE_DOS_HEADER>();
    auto* ntHeaders = file.as<IMAGE_NT_HEADERS>(dos->e_lfanew);

    data.ntHeaders = ntHeaders;

    size_t sectionOffset = dos->e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + ntHeaders->FileHeader.SizeOfOptionalHeader; // retarded
    data.sections = std::span<const IMAGE_SECTION_HEADER>(
        file.as<const IMAGE_SECTION_HEADER>(sectionOffset),
        ntHeaders->FileHeader.NumberOfSections
    );
}

const uint32_t PEParser::RvaToOffset(uint32_t rva) const {
    for (auto& s : data.sections) {
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.Misc.VirtualSize) {
            return rva - s.VirtualAddress + s.PointerToRawData;
        }
    }

    throw std::runtime_error("rva not found in sections");
}

bool PEParser::IsPEFile() {
    auto* dos = file.as<IMAGE_DOS_HEADER>();
    if (dos->e_magic != 0x5A4D) return false; // "MZ"
    auto* nt = file.as<IMAGE_NT_HEADERS>(dos->e_lfanew);
    return nt->Signature == 0x00004550; // PE\0\0
}
