# The Portable Executable (PE) Format

### Table of Contents

    - [Structure of PE](#structure-of-pe)
    - [C/C++ Structs to Deal with the PE Structure](#c-c-structs-to-deal-with-the-pe-structure)
    - [References](#references)

### Structure of PE

![](https://drive.google.com/uc?export=download&id=1R9FEmC2QbK5L4Y7alRLGuLl9Cr3jK8-K)
   
### C/C++ Structs to Deal with the PE Structure

    - **DOS STUB HEADER**
        **WINNT.H**
        ```
        typedef struct _IMAGE_DOS_HEADER {  // PIMAGE_DOS_HEADER
            USHORT e_magic;         // Magic number
            USHORT e_cblp;          // Bytes on last page of file
            USHORT e_cp;            // Pages in file
            USHORT e_crlc;          // Relocations
            USHORT e_cparhdr;       // Size of header in paragraphs
            USHORT e_minalloc;      // Minimum extra paragraphs needed
            USHORT e_maxalloc;      // Maximum extra paragraphs needed
            USHORT e_ss;            // Initial (relative) SS value
            USHORT e_sp;            // Initial SP value
            USHORT e_csum;          // Checksum
            USHORT e_ip;            // Initial IP value
            USHORT e_cs;            // Initial (relative) CS value
            USHORT e_lfarlc;        // File address of relocation table
            USHORT e_ovno;          // Overlay number
            USHORT e_res[4];        // Reserved words
            USHORT e_oemid;         // OEM identifier (for e_oeminfo)
            USHORT e_oeminfo;       // OEM information; e_oemid specific
            USHORT e_res2[10];      // Reserved words
            LONG   e_lfanew;        // NT File Headers offset
        } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
        ```

    - **NT FILE HEADERS**
        **WINNT.H**
        ```
        typedef struct _IMAGE_NT_HEADERS{
            DWORD Signature;
            IMAGE_FILE_HEADER FileHeader;
            IMAGE_OPTIONAL_HEADER OptionalHeader;
        }IMAGE_NT_HEADERS,*PIMAGE_NT_HEADERS;
        ```

    - **PE IMAGE FILE HEADER**
        **WINNT.H**
        ```
        typedef struct _IMAGE_FILE_HEADER { // PIMAGE_FILE_HEADER
            USHORT  Machine;
            USHORT  NumberOfSections;
            ULONG   TimeDateStamp;
            ULONG   PointerToSymbolTable;
            ULONG   NumberOfSymbols;
            USHORT  SizeOfOptionalHeader;
            USHORT  Characteristics;
        } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

        #define IMAGE_SIZEOF_FILE_HEADER             20
        ```

    - **PE IMAGE OPTIONAL HEADER**
        **WINNT.H**
        ```
        typedef struct _IMAGE_OPTIONAL_HEADER {
            //
            // Standard fields.
            //
            USHORT  Magic;
            UCHAR   MajorLinkerVersion;
            UCHAR   MinorLinkerVersion;
            ULONG   SizeOfCode;
            ULONG   SizeOfInitializedData;
            ULONG   SizeOfUninitializedData;
            ULONG   AddressOfEntryPoint; // RVA
            ULONG   BaseOfCode;
            ULONG   BaseOfData;
            //
            // NT additional fields.
            //
            ULONG   ImageBase;
            ULONG   SectionAlignment;
            ULONG   FileAlignment;
            USHORT  MajorOperatingSystemVersion;
            USHORT  MinorOperatingSystemVersion;
            USHORT  MajorImageVersion;
            USHORT  MinorImageVersion;
            USHORT  MajorSubsystemVersion;
            USHORT  MinorSubsystemVersion;
            ULONG   Reserved1;
            ULONG   SizeOfImage;
            ULONG   SizeOfHeaders;
            ULONG   CheckSum;
            USHORT  Subsystem;
            USHORT  DllCharacteristics;
            ULONG   SizeOfStackReserve;
            ULONG   SizeOfStackCommit;
            ULONG   SizeOfHeapReserve;
            ULONG   SizeOfHeapCommit;
            ULONG   LoaderFlags;
            ULONG   NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
        } IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

        typedef struct _IMAGE_DATA_DIRECTORY {
            ULONG   VirtualAddress;
            ULONG   Size;
        } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

        IMAGE_DATA_DIRECTORY[0] -> Export table address and size
        IMAGE_DATA_DIRECTORY[1] -> Import table address and size
        IMAGE_DATA_DIRECTORY[2] -> Resource table address and size
        IMAGE_DATA_DIRECTORY[3] -> Exception table address and size
        IMAGE_DATA_DIRECTORY[4] -> Certificate table address and size
        IMAGE_DATA_DIRECTORY[5] -> Base relocation table address and size
        IMAGE_DATA_DIRECTORY[6] -> Debugging information starting address and size
        IMAGE_DATA_DIRECTORY[7] -> Architecture-specific data address and size
        IMAGE_DATA_DIRECTORY[8] -> Global pointer register relative virtual address
        IMAGE_DATA_DIRECTORY[9] -> Thread local storage (TLS) table address and size
        IMAGE_DATA_DIRECTORY[10] -> Load configuration table address and size
        IMAGE_DATA_DIRECTORY[11] -> Bound import table address and size
        IMAGE_DATA_DIRECTORY[12] -> Import address table address and size
        IMAGE_DATA_DIRECTORY[13] -> Delay import descriptor address and size
        IMAGE_DATA_DIRECTORY[14] -> The CLR header address and size
        IMAGE_DATA_DIRECTORY[15] -> Reserved
        ```

    - **SECTION HEADER** (To arrive at first section header, use macro IMAGE_FIRST_SECTION(NtHeaderP);)
        **WINNT.H**
        ```
        #define IMAGE_SIZEOF_SHORT_NAME              8

        typedef struct _IMAGE_SECTION_HEADER {
            UCHAR   Name[IMAGE_SIZEOF_SHORT_NAME];
            union {
                    ULONG   PhysicalAddress;
                    ULONG   VirtualSize; // Size of Section in memory
            } Misc;
            ULONG   VirtualAddress; // RVA to first in-memory bytes of the section loaded in memory
            ULONG   SizeOfRawData; // Size of section in file
            ULONG   PointerToRawData; // RVA to first in-memory bytes of the section in file
            ULONG   PointerToRelocations;
            ULONG   PointerToLinenumbers;
            USHORT  NumberOfRelocations;
            USHORT  NumberOfLinenumbers;
            ULONG   Characteristics;
        } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
        ```
    - **Sections**

        - **.rsrc** : *Arranged like a tree*
            **WINNT.H**
            ```
            typedef struct _IMAGE_RESOURCE_DIRECTORY { // Non-leaf nodes
                ULONG   Characteristics;
                ULONG   TimeDateStamp;
                USHORT  MajorVersion;
                USHORT  MinorVersion;
                USHORT  NumberOfNamedEntries;
                USHORT  NumberOfIdEntries;
                IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[]
            } IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

            typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
                ULONG   Name;
                ULONG   OffsetToData; // Points to a sibling in the tree, either a directory node or a leaf node.
            } IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

            typedef struct _IMAGE_RESOURCE_DATA_ENTRY { // Leaf node
                ULONG   OffsetToData; // An RVA
                ULONG   Size;
                ULONG   CodePage;
                ULONG   Reserved;
            } IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;
            ```

        - **.edata** : *Export data section*
             **WINNT.H**
            ```
            typedef struct _IMAGE_EXPORT_DIRECTORY {
                ULONG   Characteristics;
                ULONG   TimeDateStamp;
                USHORT  MajorVersion;
                USHORT  MinorVersion;
                ULONG   Name;
                ULONG   Base;
                ULONG   NumberOfFunctions;
                ULONG   NumberOfNames;
                PULONG  *AddressOfFunctions; // RVA
                PULONG  *AddressOfNames; // RVA
                PUSHORT *AddressOfNameOrdinals; // RVA
            } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
            ```
    
        - **.idata** : *Import data section*
            ```
            typedef struct _IMAGE_IMPORT_DESCRIPTOR
            {
                DWORD Characteristics;  // RVA to null terminated array of pointers IMAGE_IMPORT_BY_NAME structs, DON'T USE
                DWORD TimeDateStamp;
                DWORD ForwarderChain;
                DWORD Name; // RVA to a NULL-terminated ASCII string containing the imported DLL's name
                PIMAGE_THUNK_DATA FirstThunk; // RVA to null terminated array of pointers to IMAGE_THUNK_DATA / IMAGE_IMPORT_BY_NAME structs, USE THIS
            } IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

            // FirstThunk is overwritten by the PE loader. The loader iterates through each pointer in the array, parses the IMAGE_THUNK_DATA, and finds the address of the function that has the same name as the 'u1.AddressOfData' field in the IMAGE_THUNK_DATA. The loader then overwrites the u1.Function pointer with the found function's address, thus resolving the import for this function.            

            typedef struct _IMAGE_THUNK_DATA
            {
                ULONGLONG u1.AddressOfData; // RVA to a IMAGE_IMPORT_BY_NAME structure, NULL for last element
                ULONGLONG u1.ForwarderString;
                ULONGLONG u1.Function; // Holds the imported function's address
                ULONGLONG u1.Ordinal;
            } IMAGE_THUNK_DATA, PIMAGE_THUNK_DATA;

            typedef struct _IMAGE_IMPORT_BY_NAME
            {
                WORD    Hint;
                BYTE    Name[?];
            } IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

            // To get the array of IMAGE_IMPORT_DESCRIPTORS, you need to read from the file (not the image in memory) from a certain offset. This offset has to be calculated.
            
            // First, you need to find out in which Section does the RVA in the Import Data Directory lie. Simply iterate over all Section headers in the image, and check whether the aforementioned RVA falls within the range of the current section's RVA (SectionHeader.VirtualAddress) and current section's RVA+VirtualSize (meaning, within the section).

            // Now that you have the section, find the difference between the aforementioned RVA and the found Section's RVA. This difference in the image is also mirrored in the file. So, if you have the location to the same Section but in the file, you can add this offset to it and obtain the address to the IMAGE_IMPORT_DESCRIPTORs in the file. You do have the location to the same Section in the file in the form of the SectionHeader.PointerToRawData of the found Section. Use this entire offset on the file's bytes, and read the IMAGE_IMPORT_DESCRIPTORs!
            
            // To know whether the import is meant to be done by ordinal or name, use the macro IMAGE_SNAP_BY_ORDINAL(u1.Ordinal), which returns True if by ordinal.

            // To get function name from ordinal, use macro IMAGE_ORDINAL(u1.Ordinal), which returns LPCSTR to function name.
            ```

        - **.debug**
            **WINNT.H**
            ```                
            typedef struct _IMAGE_DEBUG_DIRECTORY {
                ULONG   Characteristics;
                ULONG   TimeDateStamp;
                USHORT  MajorVersion;
                USHORT  MinorVersion;
                ULONG   Type;
                ULONG   SizeOfData;
                ULONG   AddressOfRawData;
                ULONG   PointerToRawData;
            } IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;
            ```

        - **.reloc**
            **WINNT.H**
            ```
                typedef struct _IMAGE_BASE_RELOCATION {
                    DWORD VirtualAddress; // RVA to this block
                    DWORD SizeOfBlock; // Size of this entire block
                    // RELOC_PAGE TypeOffset[(SizeOfBlock-sizeof(DWORD)*2)/sizeof(WORD)];
                } IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION

                typedef struct _RELOC_PAGE {
                    WORD AllocationType : 4;
                    WORD AllocationAddress : 12;
                } *PRELOC_PAGE, RELOC_PAGE;

                // The bottom 12 bits of each TypeOffset element are a relocation offset, and need to be added to the value of the Virtual Address field from this relocation block's header and Image base address to get the address where the relocation has to be done. The high 4 bits of each WORD are a relocation type. (3 is for IMAGE_REL_BASED_HIGHLOW, commonly used)
            ```
    

### References
    - [blog.kowalczyk.info/articles/pefileformat.html](https://blog.kowalczyk.info/articles/pefileformat.html)
    - [docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN)