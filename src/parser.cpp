#include "parser.h"
#include "winTypes.h"
#include <cmath>
#include <cstdint>
#include <format>
#include <stdexcept>

PEParser::PEParser(const MappedFile& _file) : file(_file) {
    if (!IsPEFile()) throw std::runtime_error("file is not pe file");
    Parse(file);
}

const IMAGE_NT_HEADERS* PEParser::NtHeaders() const {
    return data.ntHeaders;
}

const IMAGE_NT_HEADERS64* PEParser::NtHeaders64() const {
    return data.ntHeaders64;
}

bool PEParser::IsPE32Plus() const {
    return data.isPE32Plus;
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
    auto& importDir = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT);

    if (importDir.VirtualAddress == 0) return {};

    uint32_t arrOffset = RvaToOffset(importDir.VirtualAddress);
    auto descriptor = file.as<IMAGE_IMPORT_DESCRIPTOR>(arrOffset);

    std::vector<ImportEntry> imports;

    while(descriptor->Name != 0) {
        ImportEntry entry;
        entry.dllName = file.as<char>(RvaToOffset(descriptor->Name));

        uint32_t iltOffset = RvaToOffset(descriptor->ImportLookupTable);
        if (data.isPE32Plus) {
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
    uint16_t magic = *file.as<uint16_t>(dos->e_lfanew + sizeof(LONG) + sizeof(IMAGE_FILE_HEADER)); // peek to check if x64 or x32
    data.isPE32Plus = (magic == 0x20B);

    size_t sectionOffset;

    if (data.isPE32Plus) {
        auto* nt = file.as<IMAGE_NT_HEADERS64>(dos->e_lfanew);
        data.ntHeaders64 = nt;
        sectionOffset = dos->e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
    } else {
        auto* nt = file.as<IMAGE_NT_HEADERS>(dos->e_lfanew);
        data.ntHeaders = nt;
        sectionOffset = dos->e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
    }

    auto* first = file.as<IMAGE_SECTION_HEADER>(sectionOffset);
    uint16_t numSections = data.isPE32Plus ? data.ntHeaders64->FileHeader.NumberOfSections : data.ntHeaders->FileHeader.NumberOfSections;
    data.sections = std::span<const IMAGE_SECTION_HEADER>(first, numSections);
}

std::vector<ExportEntry> PEParser::Exports() const { // i had to add like 10223489204 checks because it kept crashing
    auto& exportDir = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT);

    if (exportDir.VirtualAddress == 0) return {};

    auto* exports = file.as<IMAGE_EXPORT_DIRECTORY>(RvaToOffset(exportDir.VirtualAddress));

    auto offset = RvaToOffset(exportDir.VirtualAddress);

    auto* raw = file.bytes().data() + offset;

    if (exports->AddressOfNames == 0 || 
        exports->AddressOfFunctions == 0 || 
        exports->AddressOfOrdinals == 0) return {};

    if (exports->NumberOfNames == 0 || 
        exports->NumberOfFunctions == 0) return {};

    auto* names    = file.as<uint32_t>(RvaToOffset(exports->AddressOfNames)); // this crashes
    auto* funcs    = file.as<uint32_t>(RvaToOffset(exports->AddressOfFunctions));
    auto* ordinals = file.as<uint16_t>(RvaToOffset(exports->AddressOfOrdinals));

    std::vector<ExportEntry> ret;

    for (uint32_t i = 0; i < exports->NumberOfNames && i < exports->NumberOfFunctions; i++) {
        if (names[i] == 0) continue;

        uint16_t ordinalIndex = ordinals[i];
        if (ordinalIndex >= exports->NumberOfFunctions) continue;

        ExportEntry entry;

        try {
            entry.name = file.as<char>(RvaToOffset(names[i]));
        } catch (...) {
            entry.name = std::format("<invalid name rva: 0x{:08X}>", names[i]);
        }

        uint32_t funcRva = funcs[ordinalIndex];
        bool isForwarder = funcRva >= exportDir.VirtualAddress && 
                        funcRva <  exportDir.VirtualAddress + exportDir.Size;

        try {
            if (isForwarder) {
                entry.forwarder = file.as<char>(RvaToOffset(funcRva));
            } else {
                entry.rva = funcRva;
            }
        } catch (...) {
            entry.rva = funcRva;
        }

        ret.push_back(std::move(entry));
    }

    return ret;
}

uint32_t PEParser::RvaToOffset(uint32_t rva) const {
    if (rva == 0) return 0;

    for (auto& s : data.sections) {
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.Misc.VirtualSize)
            return rva - s.VirtualAddress + s.PointerToRawData;
    }
    
    if (rva < data.sections[0].VirtualAddress)
        return rva;

    throw std::runtime_error(std::format("rva 0x{:08X} not found in sections", rva));
}

bool PEParser::IsPEFile() const {
    auto* dos = file.as<IMAGE_DOS_HEADER>();
    if (dos->e_magic != 0x5A4D) return false; // "MZ"
    auto* nt = file.as<IMAGE_NT_HEADERS>(dos->e_lfanew);
    return nt->Signature == 0x00004550; // PE\0\0
}

const IMAGE_DATA_DIRECTORY& PEParser::GetDataDirectory(uint32_t index) const {
    if (data.isPE32Plus) return data.ntHeaders64->OptionalHeader.DataDirectory[index];
    return data.ntHeaders->OptionalHeader.DataDirectory[index];
}
