// im making this on linux so i have to use this instead of windows.h
#pragma once

#include <cstdint>

typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint32_t ULONG; // 4 bytes
typedef int32_t LONG;
typedef int16_t SHORT;
typedef uint8_t UCHAR;
typedef uint8_t BYTE;

constexpr int IMAGE_SIZEOF_SHORT_NAME = 8;
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
constexpr uint32_t IMAGE_SCN_MEM_READ    = 0x40000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE   = 0x80000000;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_IMPORT = 1;

typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DOS_HEADER
{
  WORD e_magic;
  WORD e_cblp;
  WORD e_cp;
  WORD e_crlc;
  WORD e_cparhdr;
  WORD e_minalloc;
  WORD e_maxalloc;
  WORD e_ss;
  WORD e_sp;
  WORD e_csum;
  WORD e_ip;
  WORD e_cs;
  WORD e_lfarlc;
  WORD e_ovno;
  WORD e_res[4];
  WORD e_oemid;
  WORD e_oeminfo;
  WORD e_res2[10];
  LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER
{
  WORD Magic;
  UCHAR MajorLinkerVersion;
  UCHAR MinorLinkerVersion;
  ULONG SizeOfCode;
  ULONG SizeOfInitializedData;
  ULONG SizeOfUninitializedData;
  ULONG AddressOfEntryPoint;
  ULONG BaseOfCode;
  ULONG BaseOfData;
  ULONG ImageBase;
  ULONG SectionAlignment;
  ULONG FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  ULONG Win32VersionValue;
  ULONG SizeOfImage;
  ULONG SizeOfHeaders;
  ULONG CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  ULONG SizeOfStackReserve;
  ULONG SizeOfStackCommit;
  ULONG SizeOfHeapReserve;
  ULONG SizeOfHeapCommit;
  ULONG LoaderFlags;
  ULONG NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS
{
  ULONG Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_IMPORT_DESCRIPTOR { // PE Docs said 4 bytes for each and i couldnt find on msdn 
  uint32_t ImportLookupTable;
  uint32_t TimeDateStamp;
  uint32_t ForwarderChain;
  uint32_t Name;
  uint32_t ImportAddrTable;  
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;