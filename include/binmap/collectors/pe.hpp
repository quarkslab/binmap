//
//   Copyright 2014 QuarksLab
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//

#ifndef PE_HPP_INCLUDED
#define PE_HPP_INCLUDED

#include <vector>
#include "binmap/collector.hpp"

#include <boost/cstdint.hpp>
using namespace boost;

#define WINDOWS_APISETSCHEMA_API_START "api-ms-win-"
#define WINDOWS_APISETSCHEMA_EXT_START "ext-ms-win-"

/* Les structures internes du format PE sont pas isolés, du coup on
 * est obligé de les «recoder». Ici j'en profite pour ajouter des méthodes
 * pour faciliter la manipulation.
 */

struct PeDosHeader {
  enum {
    kSignature = 0x5A4D
  };

  uint16_t e_magic;
  uint16_t e_cblp;
  uint16_t e_cp;
  uint16_t e_crlc;
  uint16_t e_cparhdr;
  uint16_t e_minalloc;
  uint16_t e_maxalloc;
  uint16_t e_ss;
  uint16_t e_sp;
  uint16_t e_csuintm;
  uint16_t e_ip;
  uint16_t e_cs;
  uint16_t e_lfarlc;
  uint16_t e_ovno;
  uint16_t e_res[4];
  uint16_t e_oemid;
  uint16_t e_oeminfo;
  uint16_t e_res2[10];
  uint32_t e_lfanew;

  bool is_valid(void) const { return e_magic == kSignature; }
};

struct PeFileHeader {
  enum machine_type{
    kMachineI386 = 0x014c,
    kMachineAmd64 = 0x8664
  } ;

  typedef machine_type machine_type_t;

  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
};

struct PeDataDirectory {
  enum image_directory_entry{
    kEntryExport        = 0,
    kEntryImport        = 1,
    kEntryResource      = 2,
    kEntryException     = 3,
    kEntrySecurity      = 4,
    kEntryBaseReloc     = 5,
    kEntryDebug         = 6,
    kEntryCopyright     = 7,
    kEntryArchitecture  = 7,
    kEntryGlobalPtr     = 8,
    kEntryTls           = 9,
    kEntryLoadConfig    = 10,
    kEntryBoundImport   = 11,
    kEntryIat           = 12,
    kEntryDelayImport   = 13,
    kEntryComDescriptor = 14,
  };
  typedef image_directory_entry image_directory_entry_t;

  uint32_t VirtualAddress;
  uint32_t Size;
};

struct PeOptionalHeader32 {
    enum {
        kNumberOfDirectoryEntries = 0x10
    };
    enum {
        kSignature = 0x010b
    };

    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    PeDataDirectory DataDirectory[kNumberOfDirectoryEntries];

    bool is_valid(void) const { return Magic == kSignature; }
};

struct PeOptionalHeader64 {
    enum {
        kNumberOfDirectoryEntries = 0x10
    };
    enum {
        kSignature = 0x020b
    };

    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    PeDataDirectory DataDirectory[kNumberOfDirectoryEntries];

    bool is_valid(void) const { return Magic == kSignature; }
};

// DllCharacteristics Entries

//      IMAGE_LIBRARY_PROCESS_INIT            0x0001     // Reserved.
//      IMAGE_LIBRARY_PROCESS_TERM            0x0002     // Reserved.
//      IMAGE_LIBRARY_THREAD_INIT             0x0004     // Reserved.
//      IMAGE_LIBRARY_THREAD_TERM             0x0008     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA    0x0020  // Image can handle a high entropy 64-bit virtual address space.
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040     // DLL can move.
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY    0x0080     // Code Integrity Image
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT    0x0100     // Image is NX compatible
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200     // Image understands isolation and doesn't want it
#define IMAGE_DLLCHARACTERISTICS_NO_SEH       0x0400     // Image does not use SEH.  No SE handler may reside in this image
#define IMAGE_DLLCHARACTERISTICS_NO_BIND      0x0800     // Do not bind this image.
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER 0x1000     // Image should execute in an AppContainer
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER   0x2000     // Driver uses WDM model
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF     0x4000     // Image supports Control Flow Guard.
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE     0x8000

struct PeImportDescriptor {
    union {
        uint32_t Characteristics;
        uint32_t OriginalFirstThunk; // Import Name Table offset
    };
    uint32_t TimeDateStamp;  //
    uint32_t ForwarderChain; //
    uint32_t Name;           // Dll Name offset
    uint32_t FirstThunk;     // Import Address Table offset
};

struct PeSectionHeader {
    enum {
        SizeOfShortName = 0x8
    };

    uint8_t Name[SizeOfShortName];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

typedef std::vector<PeSectionHeader> PeSectionHeaderVector;

/***************
Load configuration
****************/
struct PeImageLoadConfigDirectory32 {
    uint32_t Size;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t GlobalFlagsClear;
    uint32_t GlobalFlagsSet;
    uint32_t CriticalSectionDefaultTimeout;
    uint32_t DeCommitFreeBlockThreshold;
    uint32_t DeCommitTotalFreeThreshold;
    uint32_t LockPrefixTable;                // VA
    uint32_t MaximumAllocationSize;
    uint32_t VirtualMemoryThreshold;
    uint32_t ProcessHeapFlags;
    uint32_t ProcessAffinityMask;
    uint16_t CSDVersion;
    uint16_t Reserved1;
    uint32_t EditList;                       // VA
    uint32_t SecurityCookie;                 // VA
    uint32_t SEHandlerTable;                 // VA
    uint32_t SEHandlerCount;
    uint32_t GuardCFCheckFunctionPointer;    // VA
    uint32_t Reserved2;
    uint32_t GuardCFFunctionTable;           // VA
    uint32_t GuardCFFunctionCount;
    uint32_t GuardFlags;
};

struct PeImageLoadConfigDirectory64 {
    uint32_t Size;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t GlobalFlagsClear;
    uint32_t GlobalFlagsSet;
    uint32_t CriticalSectionDefaultTimeout;
    uint64_t DeCommitFreeBlockThreshold;
    uint64_t DeCommitTotalFreeThreshold;
    uint64_t LockPrefixTable;             // VA
    uint64_t MaximumAllocationSize;
    uint64_t VirtualMemoryThreshold;
    uint64_t ProcessAffinityMask;
    uint32_t ProcessHeapFlags;
    uint16_t CSDVersion;
    uint16_t Reserved1;
    uint64_t EditList;                    // VA
    uint64_t SecurityCookie;              // VA
    uint64_t SEHandlerTable;              // VA
    uint64_t SEHandlerCount;
    uint64_t GuardCFCheckFunctionPointer; // VA
    uint64_t Reserved2;
    uint64_t GuardCFFunctionTable;        // VA
    uint64_t GuardCFFunctionCount;
    uint32_t GuardFlags;
};

template <typename _Bits> struct PeImageLoadConfigDirectoryTraits {};

template <> struct PeImageLoadConfigDirectoryTraits<uint32_t> {
    PeImageLoadConfigDirectory32 ImageLoadConfigDirectory;
};

template <> struct PeImageLoadConfigDirectoryTraits<uint64_t> {
    PeImageLoadConfigDirectory64 ImageLoadConfigDirectory;
};

/***************
    resources 
****************/
#ifndef RT_MANIFEST
    #define RT_MANIFEST 24
#endif

struct PeImageResourceDirectoryEntry {
    typedef enum{
        NameIsId = 0,
        NameIsOffset = 1
    }NameType;
    typedef enum{
        DataTypeIsEntry = 0,
        DataTypeIsDirectory = 1
    }DataType;

    union {
        struct {
            uint32_t NameOffset : 31;
            uint32_t NameIsString : 1;
        } DUMMYSTRUCTNAME;
        uint32_t   Name;
        uint16_t    Id;
    } NAMEORIDUNION;
    union {
        uint32_t   OffsetToData;
        struct {
            uint32_t   OffsetToDirectory : 31;
            uint32_t   DataIsDirectory : 1;
        } DUMMYSTRUCTNAME2;
    } OFFSETTODATAUNION;

    NameType name_type(void) const {
        // if MSB is 1 then Name is an offset, otherwise it's an ID.
        if ((NAMEORIDUNION.Name & 0x80000000) != 0){
            return NameIsOffset; 
        }
        else { return NameIsId; }
    }

    DataType data_type(void) const {
        if ((OFFSETTODATAUNION.OffsetToData & 0x80000000) != 0){
            return DataTypeIsDirectory;
        }
        else{
            return DataTypeIsEntry;
        }
    }
};

struct ImageResourceDirStringU{
    uint16_t length;
    wchar_t NameString[1];
};

struct PeImageResourceDirectory {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint16_t NumberOfNamedEntries;
    uint16_t NumberOfIdEntries;

    // PeImageResourceDirectory is followed by an array of PeImageResourceDirectoryEntry
    // the number of entries = NumberOfNamedEntries + NumberOfIdEntries
    // first come the named entries followed by the ID entries
    //PeImageResourceDirectoryEntry DirectoryEntries[];
};

struct PeImageResourceDataEntry {
    uint32_t   OffsetToData;
    uint32_t   Size;
    uint32_t   CodePage;
    uint32_t   ResourceHandle;
};

/***************
    export
****************/
struct PeImageExportDirectory {
    uint32_t   Characteristics;
    uint32_t   TimeDateStamp;
    uint16_t   MajorVersion;
    uint16_t   MinorVersion;
    uint32_t   Name;
    uint32_t   Base;
    uint32_t   NumberOfFunctions;
    uint32_t   NumberOfNames;
    uint32_t   AddressOfFunctions;     // RVA from base of image
    uint32_t   AddressOfNames;         // RVA from base of image
    uint32_t   AddressOfNameOrdinals;  // RVA from base of image
};

/************

  templates

*************/

template <typename _Bits> struct PeNtHeadersTraits {
    bool is_valid(void) const { return false; }
};

template <> struct PeNtHeadersTraits<uint32_t> {
    enum {
        kSignature = 0x00004550
    };

    uint32_t Signature;
    PeFileHeader FileHeader;
    PeOptionalHeader32 OptionalHeader;

    bool is_valid(void) const { return Signature == kSignature; }

};

template <> struct PeNtHeadersTraits<uint64_t> {
    enum {
        kSignature = 0x00004550
    };

    uint32_t Signature;
    PeFileHeader FileHeader;
    PeOptionalHeader64 OptionalHeader;

    bool is_valid(void) const { return Signature == kSignature; }
};

#endif
