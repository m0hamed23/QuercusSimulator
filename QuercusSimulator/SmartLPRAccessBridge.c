typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

typedef struct _s_HandlerType HandlerType;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

typedef int ptrdiff_t;

struct TypeDescriptor {
    void *pVFTable;
    void *spare;
    char name[0];
};

struct _s_HandlerType {
    uint adjectives;
    struct TypeDescriptor *pType;
    ptrdiff_t dispCatchObj;
    void *addressOfHandler;
};

typedef struct _s__RTTIBaseClassDescriptor _s__RTTIBaseClassDescriptor, *P_s__RTTIBaseClassDescriptor;

typedef struct _s__RTTIBaseClassDescriptor RTTIBaseClassDescriptor;

typedef struct PMD PMD, *PPMD;

typedef struct _s__RTTIClassHierarchyDescriptor _s__RTTIClassHierarchyDescriptor, *P_s__RTTIClassHierarchyDescriptor;

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

struct PMD {
    ptrdiff_t mdisp;
    ptrdiff_t pdisp;
    ptrdiff_t vdisp;
};

struct _s__RTTIBaseClassDescriptor {
    struct TypeDescriptor *pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    dword numContainedBases; // count of extended classes in BaseClassArray (RTTI 2)
    struct PMD where; // member displacement structure
    dword attributes; // bit flags
    RTTIClassHierarchyDescriptor *pClassHierarchyDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3) for class
};

struct _s__RTTIClassHierarchyDescriptor {
    dword signature;
    dword attributes; // bit flags
    dword numBaseClasses; // number of base classes (i.e. rtti1Count)
    RTTIBaseClassDescriptor **pBaseClassArray; // ref to BaseClassArray (RTTI 2)
};

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef int __ehstate_t;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    void (*action)(void);
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

struct _s_TryBlockMapEntry {
    __ehstate_t tryLow;
    __ehstate_t tryHigh;
    __ehstate_t catchHigh;
    int nCatches;
    HandlerType *pHandlerArray;
};

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

typedef struct _s__RTTICompleteObjectLocator _s__RTTICompleteObjectLocator, *P_s__RTTICompleteObjectLocator;

struct _s__RTTICompleteObjectLocator {
    dword signature;
    dword offset; // offset of vbtable within class
    dword cdOffset; // constructor displacement offset
    struct TypeDescriptor *pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    RTTIClassHierarchyDescriptor *pClassDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3)
};

typedef struct _s_ESTypeList _s_ESTypeList, *P_s_ESTypeList;

struct _s_ESTypeList {
    int nCount;
    HandlerType *pTypeArray;
};

typedef struct _s_ESTypeList ESTypeList;

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

typedef struct _s_FuncInfo FuncInfo;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    UnwindMapEntry *pUnwindMap;
    uint nTryBlocks;
    TryBlockMapEntry *pTryBlockMap;
    uint nIPMapEntries;
    void *pIPToStateMap;
    ESTypeList *pESTypeList;
    int EHFlags;
};

typedef struct _s__RTTICompleteObjectLocator RTTICompleteObjectLocator;

typedef struct tagMSG tagMSG, *PtagMSG;

typedef struct tagMSG MSG;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

typedef uint UINT;

typedef uint UINT_PTR;

typedef UINT_PTR WPARAM;

typedef long LONG_PTR;

typedef LONG_PTR LPARAM;

typedef ulong DWORD;

typedef struct tagPOINT tagPOINT, *PtagPOINT;

typedef struct tagPOINT POINT;

typedef long LONG;

struct tagPOINT {
    LONG x;
    LONG y;
};

struct tagMSG {
    HWND hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    POINT pt;
};

struct HWND__ {
    int unused;
};

typedef struct tagPAINTSTRUCT tagPAINTSTRUCT, *PtagPAINTSTRUCT;

typedef struct tagPAINTSTRUCT PAINTSTRUCT;

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ *HDC;

typedef int BOOL;

typedef struct tagRECT tagRECT, *PtagRECT;

typedef struct tagRECT RECT;

typedef uchar BYTE;

struct HDC__ {
    int unused;
};

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

struct tagPAINTSTRUCT {
    HDC hdc;
    BOOL fErase;
    RECT rcPaint;
    BOOL fRestore;
    BOOL fIncUpdate;
    BYTE rgbReserved[32];
};

typedef struct tagMSG *LPMSG;

typedef struct tagWNDCLASSEXA tagWNDCLASSEXA, *PtagWNDCLASSEXA;

typedef struct tagWNDCLASSEXA WNDCLASSEXA;

typedef LONG_PTR LRESULT;

typedef LRESULT (*WNDPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

typedef struct HICON__ HICON__, *PHICON__;

typedef struct HICON__ *HICON;

typedef HICON HCURSOR;

typedef struct HBRUSH__ HBRUSH__, *PHBRUSH__;

typedef struct HBRUSH__ *HBRUSH;

typedef char CHAR;

typedef CHAR *LPCSTR;

struct HBRUSH__ {
    int unused;
};

struct HICON__ {
    int unused;
};

struct tagWNDCLASSEXA {
    UINT cbSize;
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HCURSOR hCursor;
    HBRUSH hbrBackground;
    LPCSTR lpszMenuName;
    LPCSTR lpszClassName;
    HICON hIconSm;
};

struct HINSTANCE__ {
    int unused;
};

typedef struct tagPAINTSTRUCT *LPPAINTSTRUCT;

typedef struct _cpinfoexA _cpinfoexA, *P_cpinfoexA;

typedef wchar_t WCHAR;

struct _cpinfoexA {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
    WCHAR UnicodeDefaultChar;
    UINT CodePage;
    CHAR CodePageName[260];
};

typedef struct _cpinfoexA *LPCPINFOEXA;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef CHAR *LPSTR;

typedef ushort WORD;

typedef BYTE *LPBYTE;

typedef void *HANDLE;

struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void *LPVOID;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _WIN32_FIND_DATAA _WIN32_FIND_DATAA, *P_WIN32_FIND_DATAA;

typedef struct _WIN32_FIND_DATAA *LPWIN32_FIND_DATAA;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    CHAR cFileName[260];
    CHAR cAlternateFileName[14];
};

typedef struct _STARTUPINFOA *LPSTARTUPINFOA;

typedef enum _GET_FILEEX_INFO_LEVELS {
    GetFileExInfoStandard=0,
    GetFileExMaxInfoLevel=1
} _GET_FILEEX_INFO_LEVELS;

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
};

typedef enum _GET_FILEEX_INFO_LEVELS GET_FILEEX_INFO_LEVELS;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;

typedef ulong ULONG_PTR;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION *CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (*PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT *PCONTEXT;

typedef void *PVOID;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

struct _FLOATING_SAVE_AREA {
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

struct _CONTEXT {
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _SYSTEMTIME *LPSYSTEMTIME;

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

typedef double LONGLONG;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER, *P_IMAGE_SECTION_HEADER;

typedef union _union_226 _union_226, *P_union_226;

union _union_226 {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
};

struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    union _union_226 Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
};

typedef WCHAR *LPWSTR;

typedef struct _IMAGE_SECTION_HEADER *PIMAGE_SECTION_HEADER;

typedef WCHAR *LPCWSTR;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef struct tm tm, *Ptm;

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[75];
};

typedef struct tagPOINT *LPPOINT;

typedef DWORD *LPDWORD;

typedef HINSTANCE HMODULE;

typedef long *LPLONG;

typedef struct HMENU__ HMENU__, *PHMENU__;

typedef struct HMENU__ *HMENU;

struct HMENU__ {
    int unused;
};

typedef struct _FILETIME *LPFILETIME;

typedef int (*FARPROC)(void);

typedef WORD ATOM;

typedef BOOL *LPBOOL;

typedef BYTE *PBYTE;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_30 IMAGE_RESOURCE_DIR_STRING_U_30, *PIMAGE_RESOURCE_DIR_STRING_U_30;

struct IMAGE_RESOURCE_DIR_STRING_U_30 {
    word Length;
    wchar16 NameString[15];
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY32 IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

struct IMAGE_LOAD_CONFIG_DIRECTORY32 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    dword DeCommitFreeBlockThreshold;
    dword DeCommitTotalFreeThreshold;
    pointer32 LockPrefixTable;
    dword MaximumAllocationSize;
    dword VirtualMemoryThreshold;
    dword ProcessHeapFlags;
    dword ProcessAffinityMask;
    word CsdVersion;
    word DependentLoadFlags;
    pointer32 EditList;
    pointer32 SecurityCookie;
    pointer32 SEHandlerTable;
    dword SEHandlerCount;
};

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char *_ptr;
    int _cnt;
    char *_base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char *_tmpfname;
};

typedef struct _iobuf FILE;

typedef char *va_list;

typedef uint uintptr_t;

typedef struct WSAData WSAData, *PWSAData;

typedef struct WSAData WSADATA;

struct WSAData {
    WORD wVersion;
    WORD wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    ushort iMaxSockets;
    ushort iMaxUdpDg;
    char *lpVendorInfo;
};

typedef WSADATA *LPWSADATA;

typedef UINT_PTR SOCKET;

typedef ushort u_short;

typedef struct sockaddr sockaddr, *Psockaddr;

struct sockaddr {
    u_short sa_family;
    char sa_data[14];
};

typedef struct fd_set fd_set, *Pfd_set;

typedef uint u_int;

struct fd_set {
    u_int fd_count;
    SOCKET fd_array[64];
};

typedef struct timeval timeval, *Ptimeval;

struct timeval {
    long tv_sec;
    long tv_usec;
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct _NOTIFYICONDATAA _NOTIFYICONDATAA, *P_NOTIFYICONDATAA;

typedef struct _NOTIFYICONDATAA *PNOTIFYICONDATAA;

struct _NOTIFYICONDATAA {
    DWORD cbSize;
    HWND hWnd;
    UINT uID;
    UINT uFlags;
    UINT uCallbackMessage;
    HICON hIcon;
    CHAR szTip[64];
};

typedef int (*_onexit_t)(void);

typedef longlong __time64_t;

typedef uint size_t;

typedef int errno_t;

typedef struct _startupinfo _startupinfo, *P_startupinfo;

struct _startupinfo {
    int newmode;
};




void ** __thiscall FUN_00401000(void *this,void **param_1)

{
  void *pvVar1;
  
                    // WARNING: Load size is inaccurate
  if (*param_1 != *this) {
    FUN_00401910(this,(uint)param_1[1]);
                    // WARNING: Load size is inaccurate
    memcpy(*this,*param_1,(size_t)param_1[1]);
    pvVar1 = param_1[1];
                    // WARNING: Load size is inaccurate
    *(void **)((int)this + 4) = pvVar1;
    *(undefined *)((int)pvVar1 + *this) = 0;
  }
  return (void **)this;
}



char ** __thiscall FUN_00401040(void *this,char *param_1)

{
  char cVar1;
  char *pcVar2;
  uint _Size;
  
  if (param_1 == (char *)0x0) {
                    // WARNING: Load size is inaccurate
    *(undefined4 *)((int)this + 4) = 0;
    if (*this != (undefined *)0x0) {
      **this = 0;
    }
  }
  else {
                    // WARNING: Load size is inaccurate
    if (param_1 != *this) {
      pcVar2 = param_1;
      do {
        cVar1 = *pcVar2;
        pcVar2 = pcVar2 + 1;
      } while (cVar1 != '\0');
      _Size = (int)pcVar2 - (int)(param_1 + 1);
      FUN_00401910(this,_Size);
                    // WARNING: Load size is inaccurate
      memcpy(*this,param_1,_Size);
                    // WARNING: Load size is inaccurate
      *(uint *)((int)this + 4) = _Size;
      *(undefined *)(_Size + *this) = 0;
      return (char **)this;
    }
  }
  return (char **)this;
}



void __fastcall FUN_004010a0(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[2] = 0;
  param_1[1] = 0;
  return;
}



void ** __thiscall FUN_004010b0(void *this,void **param_1)

{
  void *pvVar1;
  
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  if (*param_1 != (void *)0x0) {
    FUN_00401910(this,(uint)param_1[1]);
                    // WARNING: Load size is inaccurate
    memcpy(*this,*param_1,(size_t)param_1[1]);
    pvVar1 = param_1[1];
                    // WARNING: Load size is inaccurate
    *(void **)((int)this + 4) = pvVar1;
    *(undefined *)((int)pvVar1 + *this) = 0;
  }
  return (void **)this;
}



void ** __thiscall FUN_00401100(void *this,char *param_1,char *param_2)

{
  char cVar1;
  char *pcVar2;
  char *_Size;
  
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  if (param_1 != (char *)0x0) {
    pcVar2 = param_1;
    do {
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    _Size = pcVar2 + -(int)(param_1 + 1);
    if ((int)param_2 < (int)(pcVar2 + -(int)(param_1 + 1))) {
      _Size = param_2;
    }
    if (_Size != (char *)0x0) {
      FUN_00401910(this,(uint)_Size);
                    // WARNING: Load size is inaccurate
      memcpy(*this,param_1,(size_t)_Size);
                    // WARNING: Load size is inaccurate
      *(char **)((int)this + 4) = _Size;
      _Size[*this] = '\0';
    }
    return (void **)this;
  }
  return (void **)this;
}



void __fastcall FUN_00401170(void **param_1)

{
  if (*param_1 != (void *)0x0) {
    free(*param_1);
  }
  return;
}



int __fastcall FUN_00401180(char **param_1)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  uint3 uVar4;
  char *pcVar5;
  
  pcVar5 = *param_1;
  if (pcVar5 == (char *)0x0) {
    pcVar5 = &DAT_0042b55c;
  }
  pcVar2 = pcVar5;
  do {
    cVar1 = *pcVar2;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  iVar3 = (int)pcVar2 - (int)(pcVar5 + 1);
  if (iVar3 != 0) {
    cVar1 = *pcVar5;
    iVar3 = CONCAT31((int3)((uint)iVar3 >> 8),cVar1);
    if ((cVar1 == '-') || (cVar1 == '+')) {
      pcVar5 = pcVar5 + 1;
    }
  }
  cVar1 = *pcVar5;
  uVar4 = (uint3)((uint)iVar3 >> 8);
  while( true ) {
    if (cVar1 == '\0') {
      return CONCAT31(uVar4,1);
    }
    iVar3 = isdigit((int)cVar1);
    uVar4 = (uint3)((uint)iVar3 >> 8);
    if (iVar3 == 0) break;
    cVar1 = pcVar5[1];
    pcVar5 = pcVar5 + 1;
  }
  return (uint)uVar4 << 8;
}



undefined1 * __fastcall FUN_004011f0(undefined4 *param_1)

{
  undefined1 *puVar1;
  
  puVar1 = (undefined1 *)*param_1;
  if (puVar1 == (undefined1 *)0x0) {
    puVar1 = &DAT_0042b55c;
  }
  return puVar1;
}



void __thiscall FUN_00401200(void *this,void **param_1)

{
  FUN_00401910(this,*(int *)((int)this + 4) + (int)param_1[1]);
                    // WARNING: Load size is inaccurate
  memcpy((void *)(*(int *)((int)this + 4) + *this),*param_1,(size_t)param_1[1]);
  *(int *)((int)this + 4) = *(int *)((int)this + 4) + (int)param_1[1];
                    // WARNING: Load size is inaccurate
  *(undefined *)(*(int *)((int)this + 4) + *this) = 0;
  return;
}



void __thiscall FUN_00401240(void *this,char *param_1)

{
  char cVar1;
  char *pcVar2;
  size_t _Size;
  
  pcVar2 = param_1;
  do {
    cVar1 = *pcVar2;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  _Size = (int)pcVar2 - (int)(param_1 + 1);
  FUN_00401910(this,*(int *)((int)this + 4) + _Size);
                    // WARNING: Load size is inaccurate
  memcpy((void *)(*this + *(int *)((int)this + 4)),param_1,_Size);
  *(int *)((int)this + 4) = *(int *)((int)this + 4) + _Size;
                    // WARNING: Load size is inaccurate
  *(undefined *)(*(int *)((int)this + 4) + *this) = 0;
  return;
}



int __thiscall FUN_00401290(void *this,byte *param_1)

{
  byte bVar1;
  byte *pbVar2;
  bool bVar3;
  
                    // WARNING: Load size is inaccurate
  pbVar2 = *this;
  if (pbVar2 == (byte *)0x0) {
    if (param_1 == (byte *)0x0) {
      return 0;
    }
    if (*param_1 != 0) {
      return -1;
    }
  }
  else {
    if ((*pbVar2 != 0) && (param_1 == (byte *)0x0)) {
      return 1;
    }
    if ((pbVar2 != (byte *)0x0) && (*pbVar2 != 0)) goto LAB_004012d0;
  }
  if (param_1 == (byte *)0x0) {
    return 0;
  }
  if (*param_1 == 0) {
    return 0;
  }
LAB_004012d0:
  while( true ) {
    bVar1 = *pbVar2;
    bVar3 = bVar1 < *param_1;
    if (bVar1 != *param_1) break;
    if (bVar1 == 0) {
      return 0;
    }
    bVar1 = pbVar2[1];
    bVar3 = bVar1 < param_1[1];
    if (bVar1 != param_1[1]) break;
    pbVar2 = pbVar2 + 2;
    param_1 = param_1 + 2;
    if (bVar1 == 0) {
      return 0;
    }
  }
  return (1 - (uint)bVar3) - (uint)(bVar3 != 0);
}



void * __thiscall FUN_00401300(void *this,void *param_1,int param_2,char *param_3)

{
  int iVar1;
  
  if (param_3 == (char *)0x7fffffff) {
    param_3 = (char *)(*(int *)((int)this + 4) - param_2);
  }
  iVar1 = *(int *)((int)this + 4);
  if (iVar1 < (int)(param_3 + param_2)) {
    param_3 = (char *)(iVar1 - param_2);
  }
  if (iVar1 < param_2) {
    param_3 = (char *)0x0;
  }
                    // WARNING: Load size is inaccurate
  FUN_00401100(param_1,(char *)(*this + param_2),param_3);
  return param_1;
}



void __fastcall FUN_00401350(char *param_1,char **param_2)

{
  void *unaff_ESI;
  
  if ((int)param_2[1] < (int)param_1) {
    param_1 = param_2[1];
  }
  FUN_00401100(unaff_ESI,*param_2,param_1);
  return;
}



void __fastcall FUN_00401370(undefined4 param_1,int *param_2)

{
  char *pcVar1;
  char *pcVar2;
  void *unaff_ESI;
  
  pcVar1 = (char *)param_2[1];
  pcVar2 = (char *)0x1;
  if ((int)pcVar1 < 1) {
    pcVar2 = pcVar1;
  }
  FUN_00401100(unaff_ESI,pcVar1 + (*param_2 - (int)pcVar2),pcVar2);
  return;
}



void ** __thiscall FUN_00401390(void *this,void **param_1)

{
  char cVar1;
  void *_Dst;
  int iVar2;
  void *_Size;
  char *pcVar3;
  char *_Src;
  char *local_c;
  undefined4 local_8;
  undefined4 local_4;
  
  _Src = (char *)0x0;
  _Size = (void *)0x0;
                    // WARNING: Load size is inaccurate
  local_c = (char *)0x0;
  local_4 = 0;
  local_8 = 0;
  if (*this != 0) {
    FUN_00401910(&local_c,*(uint *)((int)this + 4));
    _Src = local_c;
                    // WARNING: Load size is inaccurate
    memcpy(local_c,*this,*(size_t *)((int)this + 4));
    _Size = *(void **)((int)this + 4);
    _Src[(int)_Size] = '\0';
    if (_Src != (char *)0x0) {
      cVar1 = *_Src;
      pcVar3 = _Src;
      while (cVar1 != '\0') {
        iVar2 = toupper((int)*pcVar3);
        *pcVar3 = (char)iVar2;
        pcVar3 = pcVar3 + 1;
        cVar1 = *pcVar3;
      }
    }
  }
  *param_1 = (void *)0x0;
  param_1[2] = (void *)0x0;
  param_1[1] = (void *)0x0;
  if (_Src != (char *)0x0) {
    FUN_00401910(param_1,(uint)_Size);
    _Dst = *param_1;
    memcpy(_Dst,_Src,(size_t)_Size);
    param_1[1] = _Size;
    *(undefined *)((int)_Dst + (int)_Size) = 0;
    free(_Src);
  }
  return param_1;
}



void ** __thiscall FUN_00401440(void *this,void **param_1)

{
  char cVar1;
  void *_Dst;
  int iVar2;
  void *_Size;
  char *pcVar3;
  char *_Src;
  char *local_c;
  undefined4 local_8;
  undefined4 local_4;
  
  _Src = (char *)0x0;
  _Size = (void *)0x0;
                    // WARNING: Load size is inaccurate
  local_c = (char *)0x0;
  local_4 = 0;
  local_8 = 0;
  if (*this != 0) {
    FUN_00401910(&local_c,*(uint *)((int)this + 4));
    _Src = local_c;
                    // WARNING: Load size is inaccurate
    memcpy(local_c,*this,*(size_t *)((int)this + 4));
    _Size = *(void **)((int)this + 4);
    _Src[(int)_Size] = '\0';
    if (_Src != (char *)0x0) {
      cVar1 = *_Src;
      pcVar3 = _Src;
      while (cVar1 != '\0') {
        iVar2 = tolower((int)*pcVar3);
        *pcVar3 = (char)iVar2;
        pcVar3 = pcVar3 + 1;
        cVar1 = *pcVar3;
      }
    }
  }
  *param_1 = (void *)0x0;
  param_1[2] = (void *)0x0;
  param_1[1] = (void *)0x0;
  if (_Src != (char *)0x0) {
    FUN_00401910(param_1,(uint)_Size);
    _Dst = *param_1;
    memcpy(_Dst,_Src,(size_t)_Size);
    param_1[1] = _Size;
    *(undefined *)((int)_Dst + (int)_Size) = 0;
    free(_Src);
  }
  return param_1;
}



byte ** __thiscall FUN_004014f0(void *this,char param_1)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  
  if (*(int *)((int)this + 4) == 0) {
    return (byte **)this;
  }
  if (param_1 == '\0') {
                    // WARNING: Load size is inaccurate
    if (0x7e < **this) {
      return (byte **)this;
    }
    iVar2 = isspace((uint)**this);
    if (iVar2 == 0) {
      return (byte **)this;
    }
                    // WARNING: Load size is inaccurate
    for (iVar2 = 1;
        ((*(byte *)(iVar2 + *this) < 0x7f &&
         (iVar3 = isspace((uint)*(byte *)(iVar2 + *this)), iVar3 != 0)) &&
        (iVar2 < *(int *)((int)this + 4))); iVar2 = iVar2 + 1) {
    }
    if (*(int *)((int)this + 4) != iVar2) {
                    // WARNING: Load size is inaccurate
      memmove(*this,(void *)((int)*this + iVar2),*(int *)((int)this + 4) - iVar2);
                    // WARNING: Load size is inaccurate
      *(int *)((int)this + 4) = *(int *)((int)this + 4) - iVar2;
      *(undefined *)(*(int *)((int)this + 4) + *this) = 0;
      return (byte **)this;
    }
  }
  else {
                    // WARNING: Load size is inaccurate
    bVar1 = *(byte *)(*(int *)((int)this + 4) + -1 + *this);
    if (0x7e < bVar1) {
      return (byte **)this;
    }
    iVar2 = isspace((uint)bVar1);
    if (iVar2 == 0) {
      return (byte **)this;
    }
    iVar2 = *(int *)((int)this + 4) + -2;
                    // WARNING: Load size is inaccurate
    while (((-1 < iVar2 && (*(byte *)(iVar2 + *this) < 0x7f)) &&
           (iVar3 = isspace((uint)*(byte *)(iVar2 + *this)), iVar3 != 0))) {
      iVar2 = iVar2 + -1;
    }
    iVar2 = iVar2 + 1;
    *(int *)((int)this + 4) = iVar2;
    if (iVar2 != 0) {
                    // WARNING: Load size is inaccurate
      *(undefined *)(iVar2 + *this) = 0;
      return (byte **)this;
    }
  }
                    // WARNING: Load size is inaccurate
  *(undefined4 *)((int)this + 4) = 0;
  if (*this == (undefined *)0x0) {
    return (byte **)this;
  }
  **this = 0;
  return (byte **)this;
}



int __thiscall FUN_004015f0(void *this,char *param_1)

{
  char *pcVar1;
  
                    // WARNING: Load size is inaccurate
  pcVar1 = strstr(*this,param_1);
  if (pcVar1 == (char *)0x0) {
    return -1;
  }
                    // WARNING: Load size is inaccurate
  return (int)pcVar1 - *this;
}



uint __fastcall FUN_00401620(char *param_1)

{
  char cVar1;
  char **in_EAX;
  char *pcVar2;
  uint uVar3;
  char *pcVar4;
  char *_Memory;
  char *pcVar5;
  char *pcVar6;
  uint _Size;
  char *local_18;
  char *local_14;
  char *local_10;
  char *pcStack_c;
  uint uStack_8;
  undefined4 uStack_4;
  
  local_14 = *in_EAX;
  local_18 = local_14;
  if (local_14 == (char *)0x0) {
    local_18 = &DAT_0042b55c;
  }
  local_10 = (char *)0x0;
  do {
    cVar1 = *param_1;
    pcVar2 = (char *)CONCAT31((int3)((uint)local_14 >> 8),cVar1);
    local_14 = (char *)0x0;
    pcVar5 = param_1;
    param_1 = local_10;
    while (local_10 = pcVar5, cVar1 != '\0') {
      cVar1 = (char)pcVar2;
      pcVar5 = local_10;
      if (cVar1 == '*') {
        while( true ) {
          cVar1 = *pcVar5;
          pcVar2 = (char *)CONCAT31((int3)((uint)pcVar2 >> 8),cVar1);
          if ((cVar1 != '*') && (cVar1 != '?')) break;
          pcVar5 = pcVar5 + 1;
        }
        if (*pcVar5 == '\0') goto LAB_0040177f;
        pcVar2 = strpbrk(pcVar5,"*?");
        if (pcVar2 == (char *)0x0) {
          pcVar2 = pcVar5;
          do {
            cVar1 = *pcVar2;
            pcVar2 = pcVar2 + 1;
          } while (cVar1 != '\0');
          uVar3 = (int)pcVar2 - (int)(pcVar5 + 1);
        }
        else {
          uVar3 = (int)pcVar2 - (int)pcVar5;
        }
        pcStack_c = (char *)0x0;
        uStack_4 = 0;
        uStack_8 = 0;
        pcVar2 = pcVar5;
        do {
          cVar1 = *pcVar2;
          pcVar2 = pcVar2 + 1;
        } while (cVar1 != '\0');
        _Size = (int)pcVar2 - (int)(pcVar5 + 1);
        if ((int)uVar3 < (int)pcVar2 - (int)(pcVar5 + 1)) {
          _Size = uVar3;
        }
        _Memory = (char *)0x0;
        if (_Size == 0) {
LAB_0040170f:
          pcVar2 = &DAT_0042b55c;
        }
        else {
          FUN_00401910(&pcStack_c,_Size);
          pcVar2 = pcStack_c;
          memcpy(pcStack_c,pcVar5,_Size);
          pcVar2[_Size] = '\0';
          _Memory = pcVar2;
          uStack_8 = _Size;
          if (pcVar2 == (char *)0x0) goto LAB_0040170f;
        }
        pcVar2 = strstr(local_18,pcVar2);
        if (pcVar2 == (char *)0x0) {
          if (_Memory != (char *)0x0) {
            free(_Memory);
          }
          goto LAB_00401797;
        }
        pcVar4 = pcVar2 + (uVar3 - 1);
        pcVar6 = pcVar5 + (uVar3 - 1);
        local_14 = local_18;
        if (_Memory != (char *)0x0) {
          free(_Memory);
        }
      }
      else {
        pcVar4 = local_18;
        pcVar6 = local_10;
        if (cVar1 == '?') {
          local_10 = param_1;
          if (*local_18 == '\0') goto LAB_00401797;
        }
        else {
          local_10 = param_1;
          if (cVar1 != *local_18) goto LAB_00401797;
        }
      }
      cVar1 = pcVar6[1];
      pcVar2 = (char *)CONCAT31((int3)((uint)pcVar2 >> 8),cVar1);
      local_18 = pcVar4 + 1;
      pcVar5 = pcVar6 + 1;
      param_1 = local_10;
    }
    if (*local_18 == '\0') {
LAB_0040177f:
      return CONCAT31((int3)((uint)pcVar2 >> 8),1);
    }
    pcVar2 = local_14;
    if (local_14 == (char *)0x0) {
LAB_00401797:
      return (uint)pcVar2 & 0xffffff00;
    }
    local_14 = local_14 + 1;
    local_18 = local_14;
    local_10 = param_1;
  } while( true );
}



undefined4 __thiscall FUN_004017b0(void *this,long *param_1,char *param_2)

{
  long lVar1;
  char *_Str;
  
                    // WARNING: Load size is inaccurate
  _Str = *this;
  if (_Str == (char *)0x0) {
    _Str = &DAT_0042b55c;
  }
  lVar1 = strtol(_Str,&param_2,(int)param_2);
  *param_1 = lVar1;
  if ((*param_2 == '\0') && (param_2 != _Str)) {
    return 1;
  }
  return 0;
}



char * FUN_00401800(char *param_1,va_list param_2)

{
  uint uVar1;
  char cVar2;
  uint uVar3;
  char *pcVar4;
  char *pcVar5;
  size_t _Count;
  char **unaff_ESI;
  int iVar6;
  
  _Count = 0x400;
  while( true ) {
    uVar1 = _Count + 1;
    if ((int)unaff_ESI[2] <= (int)uVar1) {
      if (*unaff_ESI == (char *)0x0) {
        uVar3 = uVar1 & 0x8000001f;
        if ((int)uVar3 < 0) {
          uVar3 = (uVar3 - 1 | 0xffffffe0) + 1;
        }
        iVar6 = uVar1 - uVar3;
        pcVar4 = (char *)malloc(iVar6 + 0x21);
      }
      else {
        uVar3 = uVar1 & 0x8000001f;
        if ((int)uVar3 < 0) {
          uVar3 = (uVar3 - 1 | 0xffffffe0) + 1;
        }
        iVar6 = uVar1 - uVar3;
        pcVar4 = (char *)realloc(*unaff_ESI,iVar6 + 0x21);
      }
      *unaff_ESI = pcVar4;
      unaff_ESI[2] = (char *)(iVar6 + 0x20);
      pcVar4[uVar1] = '\0';
    }
    pcVar4 = *unaff_ESI;
    if (pcVar4 == (char *)0x0) break;
    iVar6 = _vsnprintf(pcVar4,_Count,param_1,param_2);
    pcVar4[_Count] = '\0';
    pcVar5 = *unaff_ESI;
    pcVar4 = pcVar5 + 1;
    do {
      cVar2 = *pcVar5;
      pcVar5 = pcVar5 + 1;
    } while (cVar2 != '\0');
    unaff_ESI[1] = pcVar5 + -(int)pcVar4;
    if ((-1 < iVar6) && (iVar6 <= (int)_Count)) {
      pcVar4 = (char *)realloc(*unaff_ESI,(size_t)(pcVar5 + -(int)pcVar4 + 1));
      *unaff_ESI = pcVar4;
      unaff_ESI[2] = unaff_ESI[1];
      return unaff_ESI[1];
    }
    _Count = _Count * 2;
  }
  return (char *)0xffffffff;
}



undefined4 * __cdecl FUN_004018e0(undefined4 *param_1,char *param_2)

{
  *param_1 = 0;
  param_1[2] = 0;
  param_1[1] = 0;
  FUN_00401800(param_2,&stack0x0000000c);
  return param_1;
}



void __thiscall FUN_00401910(void *this,uint param_1)

{
  uint uVar1;
  void *pvVar2;
  
  if (*(int *)((int)this + 8) <= (int)param_1) {
                    // WARNING: Load size is inaccurate
    if (*this == (void *)0x0) {
      uVar1 = param_1 & 0x8000001f;
      if ((int)uVar1 < 0) {
        uVar1 = (uVar1 - 1 | 0xffffffe0) + 1;
      }
      pvVar2 = malloc((param_1 - uVar1) + 0x21);
      *(uint *)((int)this + 8) = (param_1 - uVar1) + 0x20;
      *(void **)this = pvVar2;
      *(undefined *)(param_1 + (int)pvVar2) = 0;
      return;
    }
    uVar1 = param_1 & 0x8000001f;
    if ((int)uVar1 < 0) {
      uVar1 = (uVar1 - 1 | 0xffffffe0) + 1;
    }
    pvVar2 = realloc(*this,(param_1 - uVar1) + 0x21);
    *(uint *)((int)this + 8) = (param_1 - uVar1) + 0x20;
    *(void **)this = pvVar2;
    *(undefined *)(param_1 + (int)pvVar2) = 0;
  }
  return;
}



void ** __cdecl FUN_00401990(void **param_1,void **param_2,void **param_3)

{
  void *pvVar1;
  void *pvVar2;
  
  pvVar2 = *param_2;
  *param_1 = (void *)0x0;
  param_1[2] = (void *)0x0;
  param_1[1] = (void *)0x0;
  if (pvVar2 != (void *)0x0) {
    FUN_00401910(param_1,(uint)param_2[1]);
    pvVar2 = *param_1;
    memcpy(pvVar2,*param_2,(size_t)param_2[1]);
    pvVar1 = param_2[1];
    param_1[1] = pvVar1;
    *(undefined *)((int)pvVar1 + (int)pvVar2) = 0;
  }
  FUN_00401910(param_1,(int)param_1[1] + (int)param_3[1]);
  pvVar2 = *param_1;
  memcpy((void *)((int)param_1[1] + (int)pvVar2),*param_3,(size_t)param_3[1]);
  param_1[1] = (void *)((int)param_1[1] + (int)param_3[1]);
  *(undefined *)((int)param_1[1] + (int)pvVar2) = 0;
  return param_1;
}



void ** __cdecl FUN_00401a20(void **param_1,void **param_2,char *param_3)

{
  char cVar1;
  void *pvVar2;
  void *pvVar3;
  char *pcVar4;
  size_t _Size;
  
  pvVar2 = *param_2;
  *param_1 = (void *)0x0;
  param_1[2] = (void *)0x0;
  param_1[1] = (void *)0x0;
  if (pvVar2 != (void *)0x0) {
    FUN_00401910(param_1,(uint)param_2[1]);
    pvVar2 = *param_1;
    memcpy(pvVar2,*param_2,(size_t)param_2[1]);
    pvVar3 = param_2[1];
    param_1[1] = pvVar3;
    *(undefined *)((int)pvVar3 + (int)pvVar2) = 0;
  }
  pcVar4 = param_3;
  do {
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  _Size = (int)pcVar4 - (int)(param_3 + 1);
  FUN_00401910(param_1,(int)param_1[1] + _Size);
  pvVar2 = *param_1;
  memcpy((void *)((int)param_1[1] + (int)pvVar2),param_3,_Size);
  param_1[1] = (void *)((int)param_1[1] + _Size);
  *(undefined *)((int)param_1[1] + (int)pvVar2) = 0;
  return param_1;
}



int * __cdecl FUN_00401ab0(int *param_1,char *param_2,void **param_3)

{
  FUN_00401100(param_1,param_2,(char *)0x7fffffff);
  FUN_00401910(param_1,(int)param_3[1] + param_1[1]);
  memcpy((void *)(*param_1 + param_1[1]),*param_3,(size_t)param_3[1]);
  param_1[1] = param_1[1] + (int)param_3[1];
  *(undefined *)(param_1[1] + *param_1) = 0;
  return param_1;
}



undefined4 * __thiscall
FUN_00401b10(void *this,undefined param_1,undefined param_2,void *param_3,uint param_4,
            undefined4 param_5,undefined4 param_6)

{
  void **this_00;
  void **this_01;
  uint uVar1;
  
  *(undefined ***)this = aLog::vftable;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  this_00 = (void **)((int)this + 8);
  this_01 = (void **)((int)this + 0x1c);
  *this_01 = (void *)0x0;
  *(undefined4 *)((int)this + 0x24) = 0;
  *(undefined4 *)((int)this + 0x20) = 0;
  *(undefined ***)((int)this + 0x2c) = aCriticalSection::vftable;
  *(undefined4 *)((int)this + 0x30) = 0xffffffff;
  *(undefined4 *)((int)this + 0x34) = 0;
  InitializeCriticalSection((LPCRITICAL_SECTION)((int)this + 0x38));
  *(undefined *)((int)this + 0x18) = param_1;
  *(undefined *)((int)this + 0x19) = param_2;
  if (param_3 != *this_00) {
    FUN_00401910(this_00,param_4);
    memcpy(*this_00,param_3,param_4);
    *(uint *)((int)this + 0xc) = param_4;
    *(undefined *)(param_4 + (int)*this_00) = 0;
  }
  *(undefined4 *)((int)this + 0x14) = param_6;
  if (DAT_0042b564 != *this_01) {
    FUN_00401910(this_01,DAT_0042b568);
    memcpy(*this_01,DAT_0042b564,DAT_0042b568);
    uVar1 = DAT_0042b568;
    *(uint *)((int)this + 0x20) = DAT_0042b568;
    *(undefined *)(uVar1 + (int)*this_01) = 0;
  }
  *(undefined *)((int)this + 0x28) = 1;
  *(undefined4 *)((int)this + 4) = 2;
  DAT_0042b540 = this;
  if (param_3 != (void *)0x0) {
    free(param_3);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_00401c10(void *this,byte param_1)

{
  DAT_0042b540 = -(uint)((undefined *)this != &DAT_0042b570) & 0x42b570;
  *(undefined ***)this = aLog::vftable;
  *(undefined ***)((int)this + 0x2c) = aCriticalSection::vftable;
  DeleteCriticalSection((LPCRITICAL_SECTION)((int)this + 0x38));
  if (*(void **)((int)this + 0x1c) != (void *)0x0) {
    free(*(void **)((int)this + 0x1c));
  }
  if (*(void **)((int)this + 8) != (void *)0x0) {
    free(*(void **)((int)this + 8));
  }
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void FUN_00401c80(undefined4 param_1)

{
  int *piVar1;
  int in_EAX;
  DWORD DVar2;
  
  DVar2 = GetCurrentThreadId();
  if (*(DWORD *)(in_EAX + 0x30) == DVar2) {
    *(int *)(in_EAX + 0x34) = *(int *)(in_EAX + 0x34) + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)(in_EAX + 0x38));
    *(undefined4 *)(in_EAX + 0x34) = 1;
    DVar2 = GetCurrentThreadId();
    *(DWORD *)(in_EAX + 0x30) = DVar2;
  }
  *(undefined4 *)(in_EAX + 4) = param_1;
  DVar2 = GetCurrentThreadId();
  if (*(DWORD *)(in_EAX + 0x30) == DVar2) {
    piVar1 = (int *)(in_EAX + 0x34);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      *(undefined4 *)(in_EAX + 0x30) = 0xffffffff;
      LeaveCriticalSection((LPCRITICAL_SECTION)(in_EAX + 0x38));
    }
  }
  return;
}



void FUN_00401ce0(void *param_1,uint param_2)

{
  void **this;
  int *piVar1;
  int in_EAX;
  DWORD DVar2;
  int iVar3;
  code *pcVar4;
  
  pcVar4 = GetCurrentThreadId_exref;
  DVar2 = GetCurrentThreadId();
  if (*(DWORD *)(in_EAX + 0x30) == DVar2) {
    *(int *)(in_EAX + 0x34) = *(int *)(in_EAX + 0x34) + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)(in_EAX + 0x38));
    *(undefined4 *)(in_EAX + 0x34) = 1;
    DVar2 = GetCurrentThreadId();
    *(DWORD *)(in_EAX + 0x30) = DVar2;
  }
  this = (void **)(in_EAX + 0x1c);
  if (param_1 != *(void **)(in_EAX + 0x1c)) {
    FUN_00401910(this,param_2);
    memcpy(*this,param_1,param_2);
    *(uint *)(in_EAX + 0x20) = param_2;
    *(undefined *)(param_2 + (int)*this) = 0;
    pcVar4 = GetCurrentThreadId_exref;
  }
  iVar3 = (*pcVar4)();
  if (*(int *)(in_EAX + 0x30) == iVar3) {
    piVar1 = (int *)(in_EAX + 0x34);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      *(undefined4 *)(in_EAX + 0x30) = 0xffffffff;
      LeaveCriticalSection((LPCRITICAL_SECTION)(in_EAX + 0x38));
    }
  }
  if (param_1 != (void *)0x0) {
    free(param_1);
  }
  return;
}



uint __fastcall FUN_00401d80(void *param_1)

{
  undefined1 *puVar1;
  uint uVar2;
  undefined4 uVar3;
  void *pvVar4;
  void **ppvVar5;
  undefined *local_54;
  void *local_50;
  undefined4 local_4c;
  undefined4 local_48;
  void *local_44 [3];
  int local_38;
  char local_34;
  void *local_14;
  undefined *puStack_10;
  undefined4 local_c;
  
  puStack_10 = &LAB_0041cff0;
  local_14 = ExceptionList;
  ExceptionList = &local_14;
  local_50 = (void *)0x0;
  local_48 = 0;
  local_4c = 0;
  local_c = 0;
  FUN_00404730(param_1,&local_38);
  local_c._0_1_ = 1;
  if (local_34 == '\0') {
                    // WARNING: Load size is inaccurate
    puVar1 = *param_1;
    if (puVar1 == (undefined1 *)0x0) {
      puVar1 = &DAT_0042b55c;
    }
    FUN_004028b0("aLog.ReadIniFile: Error parsing ini file \'%s\'",(char)puVar1);
    local_c = (uint)local_c._1_3_ << 8;
    uVar2 = FUN_00401f60((int)&local_38);
    ExceptionList = local_14;
    return uVar2 & 0xffffff00;
  }
  FUN_00401100(local_44,"Global/LogFilter",(char *)0x7fffffff);
  ppvVar5 = local_44;
  pvVar4 = (void *)0x401e3d;
  uVar3 = FUN_00405440(&local_38,(int *)ppvVar5,&local_50);
  if (local_44[0] != (void *)0x0) {
    ppvVar5 = (void **)0x401e50;
    free(local_44[0]);
  }
  if ((char)uVar3 != '\0') {
    local_54 = &stack0xffffff90;
    FUN_004010b0(&stack0xffffff90,&local_50);
    FUN_00401ce0(pvVar4,(uint)ppvVar5);
  }
  FUN_00401100(local_44,"Global/LogLevel",(char *)0x7fffffff);
  uVar3 = FUN_004057e0(&local_38,(int *)local_44,(long *)&local_54);
  if (local_44[0] != (void *)0x0) {
    free(local_44[0]);
  }
  if ((char)uVar3 == '\0') {
LAB_00401f19:
    local_c = (uint)local_c._1_3_ << 8;
    FUN_00401f60((int)&local_38);
    if (local_50 != (void *)0x0) {
      free(local_50);
    }
    ExceptionList = local_14;
    return (uint)local_50 & 0xffffff00;
  }
  switch(local_54) {
  case (undefined *)0x0:
    uVar3 = 1;
    break;
  case (undefined *)0x1:
    uVar3 = 2;
    break;
  case (undefined *)0x2:
    uVar3 = 3;
    break;
  case (undefined *)0x3:
    uVar3 = 4;
    break;
  case (undefined *)0xffffffff:
    uVar3 = 0;
    break;
  default:
    FUN_004028b0("Log: Invalid configuration parameter (Global/LogLevel=%d)",(char)local_54);
    goto LAB_00401f19;
  }
  FUN_00401c80(uVar3);
  local_c = (uint)local_c._1_3_ << 8;
  FUN_00401f60((int)&local_38);
  if (local_50 != (void *)0x0) {
    free(local_50);
  }
  ExceptionList = local_14;
  return CONCAT31((int3)((uint)local_50 >> 8),1);
}



void __fastcall FUN_00401f60(int param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041ccdb;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004028d0((int *)(param_1 + 0x14));
  if (*(void **)(param_1 + 8) != (void *)0x0) {
    free(*(void **)(param_1 + 8));
  }
  ExceptionList = local_c;
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void FUN_00401fc0(void)

{
  int *piVar1;
  va_list unaff_EBX;
  char *unaff_EDI;
  char local_1004 [4096];
  uint local_4;
  
  piVar1 = DAT_0042b540;
  local_4 = DAT_00428400 ^ (uint)local_1004;
  if (DAT_0042b540[1] < 2) {
    memset(local_1004,0,0x1000);
    _vsnprintf(local_1004,0x1000,unaff_EDI,unaff_EBX);
    (**(code **)(*piVar1 + 4))(1,local_1004);
  }
  ___security_check_cookie_4(local_4 ^ (uint)local_1004);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void FUN_00402040(void)

{
  int *piVar1;
  va_list unaff_EBX;
  char *unaff_EDI;
  char local_1004 [4096];
  uint local_4;
  
  piVar1 = DAT_0042b540;
  local_4 = DAT_00428400 ^ (uint)local_1004;
  if (DAT_0042b540[1] < 3) {
    memset(local_1004,0,0x1000);
    _vsnprintf(local_1004,0x1000,unaff_EDI,unaff_EBX);
    (**(code **)(*piVar1 + 4))(2,local_1004);
  }
  ___security_check_cookie_4(local_4 ^ (uint)local_1004);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void FUN_004020c0(void)

{
  int *piVar1;
  va_list unaff_EBX;
  char *unaff_EDI;
  char local_1004 [4096];
  uint local_4;
  
  piVar1 = DAT_0042b540;
  local_4 = DAT_00428400 ^ (uint)local_1004;
  if (DAT_0042b540[1] < 4) {
    memset(local_1004,0,0x1000);
    _vsnprintf(local_1004,0x1000,unaff_EDI,unaff_EBX);
    (**(code **)(*piVar1 + 4))(3,local_1004);
  }
  ___security_check_cookie_4(local_4 ^ (uint)local_1004);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void FUN_00402140(void)

{
  int *piVar1;
  va_list unaff_EBX;
  char *unaff_EDI;
  char local_1004 [4096];
  uint local_4;
  
  piVar1 = DAT_0042b540;
  local_4 = DAT_00428400 ^ (uint)local_1004;
  if (DAT_0042b540[1] < 5) {
    memset(local_1004,0,0x1000);
    _vsnprintf(local_1004,0x1000,unaff_EDI,unaff_EBX);
    (**(code **)(*piVar1 + 4))(4,local_1004);
  }
  ___security_check_cookie_4(local_4 ^ (uint)local_1004);
  return;
}



void __thiscall FUN_004021c0(void *this,undefined4 param_1,char *param_2)

{
  char cVar1;
  bool bVar2;
  DWORD DVar3;
  byte *pbVar4;
  int iVar5;
  uint uVar6;
  undefined1 *puVar7;
  void **ppvVar8;
  FILE *pFVar9;
  char *pcVar10;
  tm *ptVar11;
  int *piVar12;
  void *_Size;
  undefined8 local_a4;
  undefined1 *local_9c;
  void *local_98;
  undefined4 local_94;
  undefined1 *local_90;
  undefined4 local_8c;
  undefined4 local_88;
  void *local_84;
  void *local_80 [3];
  void *pvStack_74;
  ushort uStack_66;
  void *pvStack_64;
  int aiStack_58 [10];
  tm tStack_30;
  uint uStack_c;
  
  local_a4._0_4_ = (undefined1 *)0x0;
  local_90 = (undefined1 *)0x0;
  local_88 = 0;
  local_8c = 0;
  local_9c = (undefined1 *)0x0;
  local_94 = 0;
  local_98 = (void *)0x0;
  local_84 = this;
  DVar3 = GetCurrentThreadId();
  if (*(DWORD *)((int)this + 0x30) == DVar3) {
    *(int *)((int)this + 0x34) = *(int *)((int)this + 0x34) + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)((int)this + 0x38));
    *(undefined4 *)((int)this + 0x34) = 1;
    DVar3 = GetCurrentThreadId();
    *(DWORD *)((int)this + 0x30) = DVar3;
  }
  pbVar4 = DAT_0042b564;
  if (DAT_0042b564 == (byte *)0x0) {
    pbVar4 = &DAT_0042b55c;
  }
  iVar5 = FUN_00401290((char **)((int)this + 0x1c),pbVar4);
  if (iVar5 != 0) {
    pcVar10 = *(char **)((int)this + 0x1c);
    local_a4._0_4_ = (undefined1 *)0x1;
    if (pcVar10 == (char *)0x0) {
      pcVar10 = &DAT_0042b55c;
    }
    FUN_00401100(local_80,param_2,(char *)0x7fffffff);
    uVar6 = FUN_00401620(pcVar10);
    bVar2 = true;
    if ((char)uVar6 == '\0') goto LAB_00402273;
  }
  bVar2 = false;
LAB_00402273:
  if ((((uint)(undefined1 *)local_a4 & 1) != 0) && (local_80[0] != (void *)0x0)) {
    free(local_80[0]);
  }
  if (bVar2) {
    DVar3 = GetCurrentThreadId();
    if (*(DWORD *)((int)this + 0x30) == DVar3) {
      piVar12 = (int *)((int)this + 0x34);
      *piVar12 = *piVar12 + -1;
      if (*piVar12 == 0) {
        *(undefined4 *)((int)this + 0x30) = 0xffffffff;
        LeaveCriticalSection((LPCRITICAL_SECTION)((int)this + 0x38));
        return;
      }
    }
  }
  else {
    switch(param_1) {
    case 0:
      pcVar10 = "Debug   ";
      break;
    case 1:
      pcVar10 = "Verbose ";
      break;
    case 2:
      pcVar10 = "Message ";
      break;
    case 3:
      pcVar10 = "Warning ";
      break;
    case 4:
      pcVar10 = "Error   ";
      break;
    default:
      pcVar10 = "Unknown ";
    }
    FUN_00401040(&local_90,pcVar10);
    GetSystemTime((LPSYSTEMTIME)&pvStack_74);
    local_a4 = _time64((__time64_t *)0x0);
    _localtime64_s(&tStack_30,&local_a4);
    cVar1 = *(char *)((int)this + 0x28);
    uStack_c = (uint)uStack_66;
    ptVar11 = &tStack_30;
    piVar12 = aiStack_58;
    for (iVar5 = 10; iVar5 != 0; iVar5 = iVar5 + -1) {
      *piVar12 = ptVar11->tm_sec;
      ptVar11 = (tm *)&ptVar11->tm_min;
      piVar12 = piVar12 + 1;
    }
    if (cVar1 == '\0') {
      local_a4._0_4_ = &DAT_0042b55c;
      if (local_90 != (undefined1 *)0x0) {
        local_a4._0_4_ = local_90;
      }
      FUN_00403120();
      FUN_004030f0();
      ppvVar8 = (void **)FUN_004018e0((undefined4 *)&pvStack_74,"%s %s.%.3d | %s | %s\n");
      if (*ppvVar8 != (void *)0x0) {
        FUN_00401910(&local_9c,(uint)ppvVar8[1]);
        puVar7 = local_9c;
        memcpy(local_9c,*ppvVar8,(size_t)ppvVar8[1]);
        local_98 = ppvVar8[1];
        *(undefined *)((int)local_98 + (int)puVar7) = 0;
      }
      if (pvStack_74 != (void *)0x0) {
        free(pvStack_74);
      }
      if (pvStack_64 != (void *)0x0) {
        free(pvStack_64);
      }
      if (local_80[0] != (void *)0x0) {
        free(local_80[0]);
      }
    }
    else {
      puVar7 = (undefined1 *)GetCurrentThreadId();
      local_a4._0_4_ = puVar7;
      FUN_00403120();
      FUN_004030f0();
      ppvVar8 = (void **)FUN_004018e0(local_80,"%s %s.%.3d | %s | %.5lu | %s\n");
      if (*ppvVar8 != (void *)0x0) {
        FUN_00401910(&local_9c,(uint)ppvVar8[1]);
        puVar7 = local_9c;
        memcpy(local_9c,*ppvVar8,(size_t)ppvVar8[1]);
        local_98 = ppvVar8[1];
        *(undefined *)((int)local_98 + (int)puVar7) = 0;
      }
      if (local_80[0] != (void *)0x0) {
        free(local_80[0]);
      }
      if (pvStack_64 != (void *)0x0) {
        free(pvStack_64);
      }
      this = local_84;
      if (pvStack_74 != (void *)0x0) {
        free(pvStack_74);
        this = local_84;
      }
    }
    _Size = local_98;
    if (*(char *)((int)this + 0x18) != '\0') {
      puVar7 = local_9c;
      if (local_9c == (undefined1 *)0x0) {
        puVar7 = &DAT_0042b55c;
      }
      pFVar9 = __iob_func();
      _Size = local_98;
      fwrite(puVar7,(size_t)local_98,1,pFVar9 + 2);
    }
    if (*(char *)((int)this + 0x19) != '\0') {
      puVar7 = local_9c;
      if (local_9c == (undefined1 *)0x0) {
        puVar7 = &DAT_0042b55c;
      }
      pFVar9 = __iob_func();
      fwrite(puVar7,(size_t)_Size,1,pFVar9 + 1);
    }
    pbVar4 = DAT_0042b564;
    if (DAT_0042b564 == (byte *)0x0) {
      pbVar4 = &DAT_0042b55c;
    }
    iVar5 = FUN_00401290((void *)((int)this + 8),pbVar4);
    if (iVar5 != 0) {
      pFVar9 = FUN_00402670();
      if (pFVar9 == (FILE *)0x0) {
        if (*(char *)((int)this + 0x18) != '\0') {
          pcVar10 = "Can\'t open log file\n";
          pFVar9 = __iob_func();
          fprintf(pFVar9 + 2,pcVar10);
        }
        if (*(char *)((int)this + 0x19) != '\0') {
          pcVar10 = "Can\'t open log file\n";
          pFVar9 = __iob_func();
          fprintf(pFVar9 + 1,pcVar10);
        }
      }
      else {
        puVar7 = local_9c;
        if (local_9c == (undefined1 *)0x0) {
          puVar7 = &DAT_0042b55c;
        }
        fwrite(puVar7,(size_t)_Size,1,pFVar9);
        fclose(pFVar9);
      }
    }
    DVar3 = GetCurrentThreadId();
    if (*(DWORD *)((int)this + 0x30) == DVar3) {
      piVar12 = (int *)((int)this + 0x34);
      *piVar12 = *piVar12 + -1;
      if (*piVar12 == 0) {
        *(undefined4 *)((int)this + 0x30) = 0xffffffff;
        LeaveCriticalSection((LPCRITICAL_SECTION)((int)this + 0x38));
      }
    }
    if (local_9c != (undefined1 *)0x0) {
      free(local_9c);
    }
    if (local_90 != (undefined1 *)0x0) {
      free(local_90);
    }
  }
  return;
}



FILE * FUN_00402670(void)

{
  undefined *puVar1;
  bool bVar2;
  int in_EAX;
  LPCSTR lpFileName;
  BOOL BVar3;
  void **ppvVar4;
  char *_OldFilename;
  char *pcVar5;
  FILE *pFVar6;
  char *pcVar7;
  LPCSTR pCVar8;
  int iVar9;
  undefined4 uVar10;
  undefined **ppuVar11;
  int *piVar12;
  undefined *puStack_40;
  char *local_3c;
  undefined4 local_38;
  undefined4 local_34;
  LPCSTR local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined local_24 [36];
  
  local_3c = (char *)0x0;
  local_34 = 0;
  local_38 = 0;
  local_30 = (LPCSTR)0x0;
  local_28 = 0;
  local_2c = 0;
  pCVar8 = (LPCSTR)0x0;
  if (*(int *)(in_EAX + 8) != 0) {
    FUN_00401910(&local_30,*(uint *)(in_EAX + 0xc));
    lpFileName = local_30;
    memcpy(local_30,*(void **)(in_EAX + 8),*(size_t *)(in_EAX + 0xc));
    lpFileName[*(int *)(in_EAX + 0xc)] = '\0';
    pCVar8 = lpFileName;
    if (lpFileName != (LPCSTR)0x0) goto LAB_004026d0;
  }
  lpFileName = &DAT_0042b55c;
LAB_004026d0:
  BVar3 = GetFileAttributesExA(lpFileName,GetFileExInfoStandard,local_24);
  if (pCVar8 != (LPCSTR)0x0) {
    free(pCVar8);
  }
  if (BVar3 != 0) {
    piVar12 = (int *)0x0;
    ppuVar11 = &puStack_40;
    puStack_40 = &stack0xffffff9c;
    pCVar8 = (LPCSTR)0x0;
    uVar10 = 0;
    iVar9 = 0;
    puVar1 = &stack0xffffff9c;
    if (*(int *)(in_EAX + 8) != 0) {
      FUN_00401910(&stack0xffffff9c,*(uint *)(in_EAX + 0xc));
      memcpy(pCVar8,*(void **)(in_EAX + 8),*(size_t *)(in_EAX + 0xc));
      iVar9 = *(int *)(in_EAX + 0xc);
      pCVar8[iVar9] = '\0';
      puVar1 = puStack_40;
    }
    puStack_40 = puVar1;
    bVar2 = FUN_004036e0(pCVar8,iVar9,uVar10,(uint *)ppuVar11,piVar12);
    if (bVar2) {
      pcVar7 = local_3c;
      if ((0 < *(int *)(in_EAX + 0x14)) && (*(int *)(in_EAX + 0x14) < (int)puStack_40)) {
        ppvVar4 = (void **)FUN_004018e0(&local_30,"%s.old");
        FUN_00401000(&local_3c,ppvVar4);
        if (local_30 != (LPCSTR)0x0) {
          free(local_30);
        }
        pcVar7 = local_3c;
        pcVar5 = &DAT_0042b55c;
        if (local_3c != (char *)0x0) {
          pcVar5 = local_3c;
        }
        _unlink(pcVar5);
        pcVar5 = &DAT_0042b55c;
        if (pcVar7 != (char *)0x0) {
          pcVar5 = pcVar7;
        }
        _OldFilename = *(char **)(in_EAX + 8);
        if (_OldFilename == (char *)0x0) {
          _OldFilename = &DAT_0042b55c;
        }
        rename(_OldFilename,pcVar5);
      }
      pcVar5 = *(char **)(in_EAX + 8);
      if (pcVar5 == (char *)0x0) {
        pcVar5 = &DAT_0042b55c;
      }
      pFVar6 = fopen(pcVar5,"a+");
      if (pcVar7 != (char *)0x0) {
        free(pcVar7);
      }
      return pFVar6;
    }
  }
  pcVar7 = *(char **)(in_EAX + 8);
  if (pcVar7 == (char *)0x0) {
    pcVar7 = &DAT_0042b55c;
  }
  pFVar6 = fopen(pcVar7,"a+");
  return pFVar6;
}



uint __cdecl FUN_00402830(void *param_1)

{
  uint in_EAX;
  uint uVar1;
  
  if (DAT_0042b540 == 0) {
    return in_EAX & 0xffffff00;
  }
  uVar1 = FUN_00401d80(param_1);
  return uVar1;
}



void FUN_00402850(undefined4 param_1,undefined1 param_2)

{
  if (DAT_0042b540 != 0) {
    FUN_00401fc0();
  }
  return;
}



void FUN_00402870(undefined4 param_1,undefined1 param_2)

{
  if (DAT_0042b540 != 0) {
    FUN_00402040();
  }
  return;
}



void FUN_00402890(undefined4 param_1,undefined1 param_2)

{
  if (DAT_0042b540 != 0) {
    FUN_004020c0();
  }
  return;
}



void FUN_004028b0(undefined4 param_1,undefined1 param_2)

{
  if (DAT_0042b540 != 0) {
    FUN_00402140();
  }
  return;
}



void __fastcall FUN_004028d0(int *param_1)

{
  undefined4 *puVar1;
  void *pvVar2;
  
  if (*param_1 < 2) {
    if ((*param_1 != 0) && (pvVar2 = (void *)param_1[2], pvVar2 != (void *)0x0)) {
      if (*(void **)((int)pvVar2 + 8) != (void *)0x0) {
        free(*(void **)((int)pvVar2 + 8));
      }
      operator_delete(pvVar2);
      return;
    }
  }
  else {
    for (puVar1 = *(undefined4 **)param_1[1]; puVar1 != (undefined4 *)0x0;
        puVar1 = (undefined4 *)*puVar1) {
      pvVar2 = (void *)puVar1[1];
      if (pvVar2 != (void *)0x0) {
        if (*(void **)((int)pvVar2 + 8) != (void *)0x0) {
          free(*(void **)((int)pvVar2 + 8));
        }
        operator_delete(pvVar2);
      }
    }
    pvVar2 = (void *)param_1[2];
    if (pvVar2 != (void *)0x0) {
      if (*(void **)((int)pvVar2 + 8) != (void *)0x0) {
        free(*(void **)((int)pvVar2 + 8));
      }
      operator_delete(pvVar2);
    }
  }
  return;
}



undefined4 * __fastcall FUN_00402960(undefined4 *param_1)

{
  *param_1 = aThread::vftable;
  FUN_00404050();
  param_1[2] = aCondition::vftable;
  *(undefined *)(param_1 + 0xb) = 0;
  *param_1 = aTimer::vftable;
  FUN_00404050();
  param_1[0xf] = aCondition::vftable;
  *(undefined *)(param_1 + 0x18) = 0;
  param_1[0x1a] = aCriticalSection::vftable;
  param_1[0x1b] = 0xffffffff;
  param_1[0x1c] = 0;
  InitializeCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x1d));
  return param_1;
}



undefined4 * __thiscall FUN_004029c0(void *this,byte param_1)

{
  *(undefined ***)this = aTimer::vftable;
  *(undefined ***)((int)this + 0x68) = aCriticalSection::vftable;
  DeleteCriticalSection((LPCRITICAL_SECTION)((int)this + 0x74));
  *(undefined ***)((int)this + 0x3c) = aSyncObj::vftable;
  *(undefined ***)((int)this + 0x44) = aMap<int,class_aLocker*>::vftable;
  FUN_00403d00((void **)((int)this + 0x48));
  *(undefined ***)this = aThread::vftable;
  *(undefined ***)((int)this + 8) = aSyncObj::vftable;
  *(undefined ***)((int)this + 0x10) = aMap<int,class_aLocker*>::vftable;
  FUN_00403d00((void **)((int)this + 0x14));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_00402a30(undefined4 *param_1)

{
  *param_1 = aTimer::vftable;
  param_1[0x1a] = aCriticalSection::vftable;
  DeleteCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x1d));
  param_1[0xf] = aSyncObj::vftable;
  param_1[0x11] = aMap<int,class_aLocker*>::vftable;
  FUN_00403d00((void **)(param_1 + 0x12));
  *param_1 = aThread::vftable;
  param_1[2] = aSyncObj::vftable;
  param_1[4] = aMap<int,class_aLocker*>::vftable;
  FUN_00403d00((void **)(param_1 + 5));
  return;
}



undefined4 __thiscall FUN_00402a80(void *this,DWORD param_1,undefined4 param_2,undefined4 param_3)

{
  HANDLE pvVar1;
  
  *(DWORD *)((int)this + 0x9c) = param_1;
  *(undefined4 *)((int)this + 0x98) = param_3;
  *(undefined4 *)((int)this + 100) = 0;
  *(undefined4 *)((int)this + 0x8c) = 0xffffffff;
  *(undefined4 *)((int)this + 0x94) = param_2;
  *(undefined *)((int)this + 0x35) = 1;
  *(undefined4 *)((int)this + 0x30) = param_2;
  *(undefined *)((int)this + 4) = 0;
  *(undefined *)((int)this + 0x34) = 0;
  FUN_00406270((int)this + 8);
  pvVar1 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_004032b0,this,0,
                        &param_1);
  *(HANDLE *)((int)this + 0x38) = pvVar1;
  if (pvVar1 != (HANDLE)0x0) {
    pvVar1 = (HANDLE)((uint)pvVar1 & 0xffffff00);
  }
  return CONCAT31((int3)((uint)pvVar1 >> 8),1);
}



void __thiscall FUN_00402af0(void *this,undefined4 param_1,undefined param_2)

{
  int *piVar1;
  DWORD DVar2;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041cdc8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  DVar2 = GetCurrentThreadId();
  if (*(DWORD *)((int)this + 0x6c) == DVar2) {
    *(int *)((int)this + 0x70) = *(int *)((int)this + 0x70) + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)((int)this + 0x74));
    *(undefined4 *)((int)this + 0x70) = 1;
    DVar2 = GetCurrentThreadId();
    *(DWORD *)((int)this + 0x6c) = DVar2;
  }
  local_4 = 0;
  *(undefined4 *)((int)this + 0x8c) = param_1;
  *(undefined *)((int)this + 0x90) = param_2;
  *(undefined4 *)((int)this + 100) = 1;
  FUN_004062e0();
  DVar2 = GetCurrentThreadId();
  if (*(DWORD *)((int)this + 0x6c) == DVar2) {
    piVar1 = (int *)((int)this + 0x70);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      *(undefined4 *)((int)this + 0x6c) = 0xffffffff;
      LeaveCriticalSection((LPCRITICAL_SECTION)((int)this + 0x74));
    }
  }
  ExceptionList = local_c;
  return;
}



void __fastcall FUN_00402bb0(int param_1)

{
  int *piVar1;
  DWORD DVar2;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041cdc8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  DVar2 = GetCurrentThreadId();
  if (*(DWORD *)(param_1 + 0x6c) == DVar2) {
    *(int *)(param_1 + 0x70) = *(int *)(param_1 + 0x70) + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x74));
    *(undefined4 *)(param_1 + 0x70) = 1;
    DVar2 = GetCurrentThreadId();
    *(DWORD *)(param_1 + 0x6c) = DVar2;
  }
  local_4 = 0;
  *(undefined4 *)(param_1 + 0x8c) = 0xffffffff;
  *(undefined4 *)(param_1 + 100) = 0;
  *(undefined *)(param_1 + 0x90) = 0;
  FUN_004062e0();
  DVar2 = GetCurrentThreadId();
  if (*(DWORD *)(param_1 + 0x6c) == DVar2) {
    piVar1 = (int *)(param_1 + 0x70);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      *(undefined4 *)(param_1 + 0x6c) = 0xffffffff;
      LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x74));
    }
  }
  ExceptionList = local_c;
  return;
}



void __fastcall FUN_00402c60(int param_1)

{
  int *piVar1;
  int iVar2;
  char cVar3;
  DWORD DVar4;
  undefined4 unaff_EDI;
  
  cVar3 = *(char *)(param_1 + 4);
  do {
    if (cVar3 != '\0') {
      return;
    }
    cVar3 = (**(code **)(*(int *)(param_1 + 0x3c) + 0x10))(*(undefined4 *)(param_1 + 0x8c));
    if ((cVar3 == '\0') && (*(int *)(param_1 + 100) == 1)) {
      DVar4 = GetCurrentThreadId();
      if (*(DWORD *)(param_1 + 0x6c) == DVar4) {
        *(int *)(param_1 + 0x70) = *(int *)(param_1 + 0x70) + 1;
      }
      else {
        EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x74));
        *(undefined4 *)(param_1 + 0x70) = 1;
        DVar4 = GetCurrentThreadId();
        *(DWORD *)(param_1 + 0x6c) = DVar4;
      }
      *(undefined4 *)(param_1 + 100) = 2;
      DVar4 = GetCurrentThreadId();
      if (*(DWORD *)(param_1 + 0x6c) == DVar4) {
        piVar1 = (int *)(param_1 + 0x70);
        *piVar1 = *piVar1 + -1;
        if (*piVar1 == 0) {
          *(undefined4 *)(param_1 + 0x6c) = 0xffffffff;
          LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x74));
        }
      }
    }
    if (*(int *)(param_1 + 100) == 1) {
      DVar4 = GetCurrentThreadId();
      if (*(DWORD *)(param_1 + 0x6c) == DVar4) {
        *(int *)(param_1 + 0x70) = *(int *)(param_1 + 0x70) + 1;
      }
      else {
        EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x74));
        *(undefined4 *)(param_1 + 0x70) = 1;
        DVar4 = GetCurrentThreadId();
        *(DWORD *)(param_1 + 0x6c) = DVar4;
      }
      *(undefined4 *)(param_1 + 100) = 2;
      DVar4 = GetCurrentThreadId();
      if (*(DWORD *)(param_1 + 0x6c) == DVar4) {
        piVar1 = (int *)(param_1 + 0x70);
        *piVar1 = *piVar1 + -1;
        iVar2 = *piVar1;
joined_r0x00402d7e:
        if (iVar2 == 0) {
          *(undefined4 *)(param_1 + 0x6c) = 0xffffffff;
          LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x74));
        }
      }
    }
    else if (*(int *)(param_1 + 100) == 2) {
      if (*(undefined4 **)(param_1 + 0x9c) == (undefined4 *)0x0) {
        FUN_00402890("aTimer: There is no event handler installed.",(char)unaff_EDI);
      }
      else {
        (**(code **)**(undefined4 **)(param_1 + 0x9c))(*(undefined4 *)(param_1 + 0x98));
      }
      DVar4 = GetCurrentThreadId();
      if (*(DWORD *)(param_1 + 0x6c) == DVar4) {
        *(int *)(param_1 + 0x70) = *(int *)(param_1 + 0x70) + 1;
      }
      else {
        EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x74));
        *(undefined4 *)(param_1 + 0x70) = 1;
        DVar4 = GetCurrentThreadId();
        *(DWORD *)(param_1 + 0x6c) = DVar4;
      }
      if ((*(char *)(param_1 + 0x90) == '\0') && (*(int *)(param_1 + 100) == 2)) {
        *(undefined4 *)(param_1 + 100) = 0;
      }
      DVar4 = GetCurrentThreadId();
      if (*(DWORD *)(param_1 + 0x6c) == DVar4) {
        piVar1 = (int *)(param_1 + 0x70);
        *piVar1 = *piVar1 + -1;
        iVar2 = *piVar1;
        goto joined_r0x00402d7e;
      }
    }
    cVar3 = *(char *)(param_1 + 4);
  } while( true );
}



void __fastcall FUN_00402db0(int param_1)

{
  int *piVar1;
  DWORD DVar2;
  
  DVar2 = GetCurrentThreadId();
  if (*(DWORD *)(param_1 + 0x6c) == DVar2) {
    *(int *)(param_1 + 0x70) = *(int *)(param_1 + 0x70) + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x74));
    *(undefined4 *)(param_1 + 0x70) = 1;
    DVar2 = GetCurrentThreadId();
    *(DWORD *)(param_1 + 0x6c) = DVar2;
  }
  *(undefined4 *)(param_1 + 100) = 0;
  FUN_004061b0((int *)(param_1 + 0x3c));
  DVar2 = GetCurrentThreadId();
  if (*(DWORD *)(param_1 + 0x6c) == DVar2) {
    piVar1 = (int *)(param_1 + 0x70);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      *(undefined4 *)(param_1 + 0x6c) = 0xffffffff;
      LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x74));
    }
  }
  return;
}



void __cdecl FUN_00402e10(undefined4 *param_1,int param_2,int param_3)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)operator_new(param_2 * param_3 + 4);
  *puVar1 = *param_1;
  *param_1 = puVar1;
  return;
}



void __fastcall FUN_00402e30(int *param_1)

{
  int *piVar1;
  
  if (param_1 != (int *)0x0) {
    do {
      piVar1 = (int *)*param_1;
      operator_delete__(param_1);
      param_1 = piVar1;
    } while (piVar1 != (int *)0x0);
  }
  return;
}



undefined4 * __fastcall FUN_00402e50(undefined4 *param_1)

{
  *param_1 = aCriticalSection::vftable;
  param_1[1] = 0xffffffff;
  param_1[2] = 0;
  InitializeCriticalSection((LPCRITICAL_SECTION)(param_1 + 3));
  return param_1;
}



undefined4 * __thiscall FUN_00402e80(void *this,byte param_1)

{
  *(undefined ***)this = aCriticalSection::vftable;
  DeleteCriticalSection((LPCRITICAL_SECTION)((int)this + 0xc));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_00402eb0(undefined4 *param_1)

{
  *param_1 = aCriticalSection::vftable;
  DeleteCriticalSection((LPCRITICAL_SECTION)(param_1 + 3));
  return;
}



void __fastcall FUN_00402ed0(int param_1)

{
  DWORD DVar1;
  
  DVar1 = GetCurrentThreadId();
  if (*(DWORD *)(param_1 + 4) == DVar1) {
    *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0xc));
  *(undefined4 *)(param_1 + 8) = 1;
  DVar1 = GetCurrentThreadId();
  *(DWORD *)(param_1 + 4) = DVar1;
  return;
}



void __fastcall FUN_00402f10(int param_1)

{
  int *piVar1;
  DWORD DVar2;
  
  DVar2 = GetCurrentThreadId();
  if (*(DWORD *)(param_1 + 4) == DVar2) {
    piVar1 = (int *)(param_1 + 8);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      *(undefined4 *)(param_1 + 4) = 0xffffffff;
      LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 0xc));
    }
  }
  return;
}



int * __thiscall FUN_00402f40(void *this,int param_1)

{
  DWORD DVar1;
  
  *(int *)this = param_1;
  DVar1 = GetCurrentThreadId();
  if (*(DWORD *)(param_1 + 4) == DVar1) {
    *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    return (int *)this;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0xc));
  *(undefined4 *)(param_1 + 8) = 1;
  DVar1 = GetCurrentThreadId();
  *(DWORD *)(param_1 + 4) = DVar1;
  return (int *)this;
}



void __fastcall FUN_00402f90(int *param_1)

{
  int *piVar1;
  int iVar2;
  DWORD DVar3;
  
  iVar2 = *param_1;
  DVar3 = GetCurrentThreadId();
  if (*(DWORD *)(iVar2 + 4) == DVar3) {
    piVar1 = (int *)(iVar2 + 8);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      *(undefined4 *)(iVar2 + 4) = 0xffffffff;
      LeaveCriticalSection((LPCRITICAL_SECTION)(iVar2 + 0xc));
    }
  }
  return;
}



undefined4 __fastcall FUN_00402fc0(undefined4 param_1)

{
  return param_1;
}



int __fastcall FUN_00402fd0(int param_1)

{
  return *(int *)(param_1 + 0x14) + 0x76c;
}



int __fastcall FUN_00402fe0(int param_1)

{
  return *(int *)(param_1 + 0x10) + 1;
}



undefined4 __fastcall FUN_00402ff0(int param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}



undefined4 __fastcall FUN_00403000(int param_1)

{
  return *(undefined4 *)(param_1 + 8);
}



undefined4 __fastcall FUN_00403010(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



undefined4 __fastcall FUN_00403020(undefined4 *param_1)

{
  return *param_1;
}



undefined4 __fastcall FUN_00403030(int param_1)

{
  return *(undefined4 *)(param_1 + 0x24);
}



__time64_t __fastcall FUN_00403040(tm *param_1)

{
  __time64_t _Var1;
  
  _Var1 = _mktime64(param_1);
  return _Var1;
}



longlong __fastcall FUN_00403050(tm *param_1)

{
  __time64_t _Var1;
  longlong lVar2;
  
  _Var1 = _mktime64(param_1);
  lVar2 = __allmul((uint)_Var1,(int)(uint)_Var1 >> 0x1f,1000,0);
  return lVar2 + param_1[1].tm_sec;
}



tm * __cdecl FUN_00403080(tm *param_1)

{
  __time64_t _Stack_20;
  _SYSTEMTIME local_18;
  
  GetSystemTime(&local_18);
  _Stack_20 = _time64((__time64_t *)0x0);
  _localtime64_s(param_1,&_Stack_20);
  param_1[1].tm_sec = (uint)local_18.wMilliseconds;
  return param_1;
}



void __fastcall FUN_004030d0(tm *param_1,undefined param_2,undefined param_3)

{
  _localtime64_s(param_1,(__time64_t *)&param_3);
  param_1[1].tm_sec = 0;
  return;
}



void FUN_004030f0(void)

{
  undefined4 *unaff_ESI;
  
  FUN_004018e0(unaff_ESI,"%.4d-%.2d-%.2d");
  return;
}



void FUN_00403120(void)

{
  undefined4 *unaff_ESI;
  
  FUN_004018e0(unaff_ESI,"%.2d:%.2d:%.2d");
  return;
}



void FUN_00403140(undefined4 *param_1)

{
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  uint local_4;
  
  local_4 = DAT_00428400 ^ (uint)&local_50;
  local_34 = 0x6e614a;
  local_30 = 0x626546;
  local_2c = 0x72614d;
  local_28 = 0x727041;
  local_24 = 0x79614d;
  local_20 = 0x6e754a;
  local_1c = 0x6c754a;
  local_18 = 0x677541;
  local_14 = 0x706553;
  local_10 = 0x74634f;
  local_c = 0x766f4e;
  local_8 = 0x636544;
  local_50 = 0x6e7553;
  local_4c = 0x6e6f4d;
  local_48 = 0x657554;
  local_44 = 0x646557;
  local_40 = 0x756854;
  local_3c = 0x697246;
  local_38 = 0x746153;
  __timezone();
  FUN_004018e0(param_1,"%s, %.2d %s %.4d %.2d:%.2d:%.2d +%.2d%.2d");
  ___security_check_cookie_4(local_4 ^ (uint)&local_50);
  return;
}



undefined4 * __fastcall FUN_004032d0(undefined4 *param_1)

{
  *param_1 = aThread::vftable;
  FUN_00404050();
  param_1[2] = aCondition::vftable;
  *(undefined *)(param_1 + 0xb) = 0;
  return param_1;
}



undefined4 * __thiscall FUN_00403300(void *this,byte param_1)

{
  *(undefined ***)this = aThread::vftable;
  *(undefined ***)((int)this + 8) = aSyncObj::vftable;
  *(undefined ***)((int)this + 0x10) = aMap<int,class_aLocker*>::vftable;
  FUN_00403d00((void **)((int)this + 0x14));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_00403340(undefined4 *param_1)

{
  *param_1 = aThread::vftable;
  param_1[2] = aSyncObj::vftable;
  param_1[4] = aMap<int,class_aLocker*>::vftable;
  FUN_00403d00((void **)(param_1 + 5));
  return;
}



undefined __thiscall FUN_00403360(void *this,char param_1,undefined4 param_2,undefined param_3)

{
  HANDLE pvVar1;
  void *local_4;
  
  *(undefined *)((int)this + 0x34) = param_3;
  *(undefined *)((int)this + 0x35) = 1;
  *(undefined4 *)((int)this + 0x30) = param_2;
  *(undefined *)((int)this + 4) = 0;
  local_4 = this;
  FUN_00406270((int)(int *)((int)this + 8));
  pvVar1 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_004032b0,this,0,
                        (LPDWORD)&local_4);
  *(HANDLE *)((int)this + 0x38) = pvVar1;
  if (pvVar1 == (HANDLE)0x0) {
    return 0;
  }
  if (param_1 != '\0') {
    (**(code **)(*(int *)((int)this + 8) + 0x10))(0xffffffff);
  }
  return *(undefined *)((int)this + 0x35);
}



void __fastcall FUN_004033d0(int *param_1)

{
  code *pcVar1;
  
  FUN_004061b0(param_1 + 2);
  pcVar1 = *(code **)(*param_1 + 4);
  *(undefined *)(param_1 + 1) = 1;
  (*pcVar1)();
  if (*(char *)(param_1 + 0xd) == '\0') {
    WaitForSingleObject((HANDLE)param_1[0xe],0xffffffff);
    CloseHandle((HANDLE)param_1[0xe]);
  }
  return;
}



undefined __fastcall FUN_00403410(int param_1)

{
  return *(undefined *)(param_1 + 4);
}



void __thiscall FUN_00403420(void *this,undefined param_1)

{
  *(undefined *)((int)this + 0x35) = param_1;
  FUN_004061b0((int *)((int)this + 8));
  return;
}



undefined4 * __thiscall
FUN_00403440(void *this,void *param_1,LPCSTR param_2,undefined4 param_3,void *param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  void *this_00;
  int iVar1;
  LPCSTR *ppCVar2;
  void **ppvVar3;
  undefined4 *puVar4;
  LPCSTR lpFileName;
  HANDLE pvVar5;
  DWORD DVar6;
  void *extraout_ECX;
  LPCSTR _Memory;
  LPCSTR local_30;
  LPCSTR local_2c;
  undefined4 local_28;
  void *local_24 [3];
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041cfb8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  _Memory = (LPCSTR)0x0;
  local_30 = (LPCSTR)0x0;
  local_28 = 0;
  local_2c = (LPCSTR)0x0;
  local_4 = 2;
  if (param_1 != (void *)0x0) {
    FUN_00401910(&local_30,(uint)param_2);
    _Memory = local_30;
    memcpy(local_30,param_1,(size_t)param_2);
    local_2c = param_2;
    param_2[(int)_Memory] = '\0';
    this = extraout_ECX;
  }
  this_00 = (void *)FUN_00401370(this,(int *)&local_30);
  iVar1 = FUN_00401290(this_00,&DAT_00423834);
  if (local_24[0] != (void *)0x0) {
    free(local_24[0]);
  }
  if (iVar1 == 0) {
    ppCVar2 = (LPCSTR *)FUN_00401990(local_24,&local_30,&param_4);
    local_18[0] = local_24[0];
    if (*ppCVar2 != _Memory) {
      FUN_00401910(&local_30,(uint)ppCVar2[1]);
      _Memory = local_30;
      memcpy(local_30,*ppCVar2,(size_t)ppCVar2[1]);
      local_2c = ppCVar2[1];
      local_2c[(int)_Memory] = '\0';
      local_18[0] = local_24[0];
    }
  }
  else {
    ppvVar3 = FUN_00401a20(local_18,&local_30,"\\");
    ppCVar2 = (LPCSTR *)FUN_00401990(local_24,ppvVar3,&param_4);
    if (*ppCVar2 != _Memory) {
      FUN_00401910(&local_30,(uint)ppCVar2[1]);
      _Memory = local_30;
      memcpy(local_30,*ppCVar2,(size_t)ppCVar2[1]);
      local_2c = ppCVar2[1];
      local_2c[(int)_Memory] = '\0';
    }
    if (local_24[0] != (void *)0x0) {
      free(local_24[0]);
    }
  }
  if (local_18[0] != (void *)0x0) {
    free(local_18[0]);
  }
  puVar4 = (undefined4 *)operator_new(0x14c);
  puVar4[0x52] = param_7;
  *puVar4 = 0;
  lpFileName = &DAT_0042b55c;
  if (_Memory != (LPCSTR)0x0) {
    lpFileName = _Memory;
  }
  pvVar5 = FindFirstFileA(lpFileName,(LPWIN32_FIND_DATAA)(puVar4 + 2));
  puVar4[1] = pvVar5;
  if ((pvVar5 == (HANDLE)0xffffffff) && (DVar6 = GetLastError(), DVar6 == 2)) {
    *puVar4 = 1;
  }
  else if (puVar4[1] == -1) {
    operator_delete(puVar4);
    puVar4 = (undefined4 *)0x0;
  }
  if (_Memory != (LPCSTR)0x0) {
    free(_Memory);
  }
  if (param_1 != (void *)0x0) {
    free(param_1);
  }
  if (param_4 != (void *)0x0) {
    free(param_4);
  }
  ExceptionList = local_c;
  return puVar4;
}



uint __cdecl FUN_00403650(int **param_1,void *param_2,uint *param_3)

{
  int **in_EAX;
  BOOL BVar1;
  
  if (*param_1 == (int *)0x0) {
    do {
      if (((param_1[0x52] != (int *)0x1) ||
          (in_EAX = param_1 + 2, (*(byte *)(param_1 + 2) & 0x10) != 0)) &&
         ((param_1[0x52] != (int *)0x0 ||
          (in_EAX = param_1 + 2, (*(byte *)(param_1 + 2) & 0x10) == 0)))) break;
      BVar1 = FindNextFileA(param_1[1],(LPWIN32_FIND_DATAA)(param_1 + 2));
      in_EAX = (int **)(uint)(BVar1 == 0);
      *param_1 = (int *)in_EAX;
    } while (in_EAX == (int **)0x0);
    if (*param_1 == (int *)0x0) {
      FUN_00401040(param_2,(char *)(param_1 + 0xd));
      *param_3 = *(byte *)(param_1 + 2) >> 4 & 1;
      BVar1 = FindNextFileA(param_1[1],(LPWIN32_FIND_DATAA)(param_1 + 2));
      *param_1 = (int *)(uint)(BVar1 == 0);
      return 1;
    }
  }
  return (uint)in_EAX & 0xffffff00;
}



bool __cdecl
FUN_004036e0(LPCSTR param_1,undefined4 param_2,undefined4 param_3,uint *param_4,int *param_5)

{
  LPCSTR lpFileName;
  BOOL BVar1;
  undefined local_24 [28];
  int iStack_8;
  uint uStack_4;
  
  lpFileName = &DAT_0042b55c;
  if (param_1 != (LPCSTR)0x0) {
    lpFileName = param_1;
  }
  BVar1 = GetFileAttributesExA(lpFileName,GetFileExInfoStandard,local_24);
  if (0x7fffffff < uStack_4) {
    uStack_4 = uStack_4 & 0x7fffffff;
    iStack_8 = iStack_8 * 2;
  }
  if (param_4 != (uint *)0x0) {
    *param_4 = uStack_4;
  }
  if (param_5 != (int *)0x0) {
    *param_5 = iStack_8;
  }
  if (param_1 != (LPCSTR)0x0) {
    free(param_1);
  }
  return BVar1 != 0;
}



bool __cdecl FUN_00403760(LPCSTR param_1)

{
  LPCSTR lpFileName;
  BOOL BVar1;
  undefined local_24 [36];
  
  lpFileName = &DAT_0042b55c;
  if (param_1 != (LPCSTR)0x0) {
    lpFileName = param_1;
  }
  BVar1 = GetFileAttributesExA(lpFileName,GetFileExInfoStandard,local_24);
  if (param_1 != (LPCSTR)0x0) {
    free(param_1);
  }
  return BVar1 != 0;
}



bool __cdecl FUN_004037a0(LPCSTR param_1)

{
  LPCSTR lpPathName;
  BOOL BVar1;
  
  lpPathName = &DAT_0042b55c;
  if (param_1 != (LPCSTR)0x0) {
    lpPathName = param_1;
  }
  BVar1 = CreateDirectoryA(lpPathName,(LPSECURITY_ATTRIBUTES)0x0);
  if (param_1 != (LPCSTR)0x0) {
    free(param_1);
  }
  return BVar1 == 1;
}



bool __cdecl FUN_004037e0(LPCSTR param_1)

{
  LPCSTR lpPathName;
  BOOL BVar1;
  
  lpPathName = &DAT_0042b55c;
  if (param_1 != (LPCSTR)0x0) {
    lpPathName = param_1;
  }
  BVar1 = RemoveDirectoryA(lpPathName);
  if (param_1 != (LPCSTR)0x0) {
    free(param_1);
  }
  return BVar1 == 1;
}



bool __cdecl FUN_00403820(char *param_1)

{
  char *_Filename;
  int iVar1;
  
  _Filename = &DAT_0042b55c;
  if (param_1 != (char *)0x0) {
    _Filename = param_1;
  }
  iVar1 = remove(_Filename);
  if (param_1 != (char *)0x0) {
    free(param_1);
  }
  return iVar1 == 0;
}



undefined4 * __thiscall FUN_00403860(void *this,byte param_1)

{
  *(undefined ***)this = aSyncObj::vftable;
  *(undefined ***)((int)this + 8) = aMap<int,class_aLocker*>::vftable;
  FUN_00403d00((void **)((int)this + 0xc));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_00403890(void *this,undefined4 param_1,undefined4 param_2)

{
  FUN_00404050();
  *(undefined4 *)((int)this + 0x24) = param_1;
  *(undefined ***)this = aSemaphore::vftable;
  *(undefined4 *)((int)this + 0x28) = param_2;
  return (undefined4 *)this;
}



void __fastcall FUN_004038c0(int *param_1)

{
  (**(code **)(*param_1 + 8))(0);
  return;
}



void __fastcall FUN_004038d0(int *param_1)

{
                    // WARNING: Could not recover jumptable at 0x004038d5. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 8))();
  return;
}



void __fastcall FUN_004038e0(int *param_1)

{
                    // WARNING: Could not recover jumptable at 0x004038e5. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x10))();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool __fastcall FUN_004038f0(int param_1)

{
  int iVar1;
  DWORD DVar2;
  
  DVar2 = GetCurrentThreadId();
  if (DAT_00429028 == DVar2) {
    _DAT_0042902c = _DAT_0042902c + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    _DAT_0042902c = 1;
    DAT_00429028 = GetCurrentThreadId();
  }
  iVar1 = *(int *)(param_1 + 0x24);
  DVar2 = GetCurrentThreadId();
  if ((DAT_00429028 == DVar2) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
    DAT_00429028 = 0xffffffff;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
  }
  return 0 < iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool __fastcall FUN_00403960(int *param_1,undefined param_2,undefined4 param_3)

{
  bool bVar1;
  DWORD DVar2;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041cdc8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  DVar2 = GetCurrentThreadId();
  if (DAT_00429028 == DVar2) {
    _DAT_0042902c = _DAT_0042902c + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    _DAT_0042902c = 1;
    DAT_00429028 = GetCurrentThreadId();
  }
  local_4 = 0;
  if (param_1[9] != 0) {
    param_1[9] = param_1[9] + -1;
    DVar2 = GetCurrentThreadId();
    if ((DAT_00429028 == DVar2) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
      DAT_00429028 = 0xffffffff;
      LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    }
    ExceptionList = local_c;
    return true;
  }
  bVar1 = FUN_00404170(param_1);
  DVar2 = GetCurrentThreadId();
  if ((DAT_00429028 == DVar2) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
    DAT_00429028 = 0xffffffff;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
  }
  ExceptionList = local_c;
  return bVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __thiscall FUN_00403a70(void *this,int *param_1)

{
  int *piVar1;
  DWORD DVar2;
  uint uVar3;
  uint extraout_EAX;
  undefined4 uVar4;
  DWORD extraout_EAX_00;
  int **ppiVar5;
  int *piVar6;
  int **ppiVar7;
  void *local_14;
  undefined *puStack_10;
  undefined4 local_c;
  
  local_c = 0xffffffff;
  puStack_10 = &LAB_0041ce60;
  local_14 = ExceptionList;
  ExceptionList = &local_14;
  DVar2 = GetCurrentThreadId();
  if (DAT_00429028 == DVar2) {
    _DAT_0042902c = _DAT_0042902c + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    _DAT_0042902c = 1;
    DAT_00429028 = GetCurrentThreadId();
  }
  local_c = 1;
  if (param_1 != (int *)0x0) {
    *param_1 = *(int *)((int)this + 0x24);
  }
  if ((*(int *)((int)this + 0x28) != 0) &&
     (*(int *)((int)this + 0x24) == *(int *)((int)this + 0x28))) {
    local_c = 0;
    FUN_00403c90();
    uVar3 = GetCurrentThreadId();
    if ((DAT_00429028 == uVar3) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
      DAT_00429028 = 0xffffffff;
      LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
      uVar3 = extraout_EAX;
    }
    ExceptionList = local_14;
    return uVar3 & 0xffffff00;
  }
  *(int *)((int)this + 0x24) = *(int *)((int)this + 0x24) + 1;
  ppiVar7 = (int **)((int)this + 0xc);
  piVar1 = (int *)0x0;
  if (*(int *)((int)this + 0x14) != 0) {
    uVar3 = 0;
    if (*(uint *)((int)this + 0x10) != 0) {
      ppiVar5 = (int **)*ppiVar7;
      do {
        piVar1 = *ppiVar5;
        if (piVar1 != (int *)0x0) break;
        uVar3 = uVar3 + 1;
        ppiVar5 = ppiVar5 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  do {
    piVar6 = piVar1;
    if ((ppiVar7 == (int **)0x0) || (piVar6 == (int *)0x0)) goto LAB_00403bd4;
    uVar4 = FUN_00406bb0(piVar6[3]);
    if ((char)uVar4 != '\0') {
      FUN_00406cf0((int *)this);
LAB_00403bd4:
      DVar2 = GetCurrentThreadId();
      if ((DAT_00429028 == DVar2) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
        DAT_00429028 = 0xffffffff;
        LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
        DVar2 = extraout_EAX_00;
      }
      ExceptionList = local_14;
      return CONCAT31((int3)(DVar2 >> 8),1);
    }
    piVar1 = (int *)*piVar6;
    if (piVar1 == (int *)0x0) {
      uVar3 = piVar6[1] + 1;
      if (uVar3 < *(uint *)((int)this + 0x10)) {
        ppiVar5 = (int **)(*ppiVar7 + uVar3);
        do {
          piVar1 = *ppiVar5;
          if (piVar1 != (int *)0x0) break;
          uVar3 = uVar3 + 1;
          ppiVar5 = ppiVar5 + 1;
        } while (uVar3 < *(uint *)((int)this + 0x10));
      }
    }
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00403c20(int param_1)

{
  DWORD DVar1;
  
  DVar1 = GetCurrentThreadId();
  if (DAT_00429028 == DVar1) {
    _DAT_0042902c = _DAT_0042902c + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    _DAT_0042902c = 1;
    DAT_00429028 = GetCurrentThreadId();
  }
  *(int *)(param_1 + 0x24) = *(int *)(param_1 + 0x24) + -1;
  DVar1 = GetCurrentThreadId();
  if ((DAT_00429028 == DVar1) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
    DAT_00429028 = 0xffffffff;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
  }
  return;
}



void FUN_00403c90(void)

{
  undefined4 *puVar1;
  int *unaff_EDI;
  
  if (*unaff_EDI < 2) {
    if (*unaff_EDI != 0) {
      operator_delete((void *)unaff_EDI[2]);
    }
    return;
  }
  for (puVar1 = *(undefined4 **)unaff_EDI[1]; puVar1 != (undefined4 *)0x0;
      puVar1 = (undefined4 *)*puVar1) {
    operator_delete((void *)puVar1[1]);
  }
  operator_delete((void *)unaff_EDI[2]);
  return;
}



undefined4 * __thiscall FUN_00403cd0(void *this,byte param_1)

{
  *(undefined ***)this = aMap<int,class_aLocker*>::vftable;
  FUN_00403d00((void **)((int)this + 4));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_00403d00(void **param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  void *pvVar4;
  
  puVar1 = (undefined4 *)*param_1;
  if ((puVar1 != (undefined4 *)0x0) && (param_1[1] != (void *)0x0)) {
    pvVar4 = param_1[1];
    puVar3 = puVar1;
    do {
      for (puVar2 = (undefined4 *)*puVar3; puVar2 != (undefined4 *)0x0;
          puVar2 = (undefined4 *)*puVar2) {
      }
      puVar3 = puVar3 + 1;
      pvVar4 = (void *)((int)pvVar4 + -1);
    } while (pvVar4 != (void *)0x0);
  }
  operator_delete__(puVar1);
  *param_1 = (void *)0x0;
  param_1[2] = (void *)0x0;
  param_1[3] = (void *)0x0;
  puVar1 = (undefined4 *)param_1[4];
  while (puVar1 != (undefined4 *)0x0) {
    puVar3 = (undefined4 *)*puVar1;
    operator_delete__(puVar1);
    puVar1 = puVar3;
  }
  param_1[4] = (void *)0x0;
  return;
}



undefined4 * __thiscall FUN_00403d60(void *this,void *param_1,uint param_2,undefined param_3)

{
  void *_Dst;
  
  *(undefined ***)this = aMultiLock::vftable;
  *(uint *)((int)this + 8) = param_2;
  _Dst = operator_new(-(uint)((int)((ulonglong)param_2 * 4 >> 0x20) != 0) |
                      (uint)((ulonglong)param_2 * 4));
  *(void **)((int)this + 4) = _Dst;
  memcpy(_Dst,param_1,param_2 * 4);
  *(undefined *)((int)this + 0xc) = param_3;
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_00403db0(void *this,byte param_1)

{
  *(undefined ***)this = aMultiLock::vftable;
  if (*(void **)((int)this + 4) != (void *)0x0) {
    operator_delete__(*(void **)((int)this + 4));
  }
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_00403de0(undefined4 *param_1)

{
  *param_1 = aMultiLock::vftable;
  if ((void *)param_1[1] != (void *)0x0) {
    operator_delete__((void *)param_1[1]);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __thiscall FUN_00403e00(void *this,DWORD param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  DWORD DVar3;
  int iVar4;
  undefined4 *puVar5;
  HANDLE pvVar6;
  undefined4 *puVar7;
  int iVar8;
  int iVar9;
  int *piVar10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041ce28;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  DVar3 = GetCurrentThreadId();
  if (DAT_00429028 == DVar3) {
    _DAT_0042902c = _DAT_0042902c + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    _DAT_0042902c = 1;
    DAT_00429028 = GetCurrentThreadId();
  }
  local_4 = 0;
  iVar4 = FUN_00403fd0();
  if (iVar4 < 0) {
    puVar5 = (undefined4 *)operator_new(0x24);
    if (puVar5 == (undefined4 *)0x0) {
      puVar5 = (undefined4 *)0x0;
    }
    else {
      DVar3 = GetCurrentThreadId();
      *puVar5 = aLocker::vftable;
      pvVar6 = CreateSemaphoreA((LPSECURITY_ATTRIBUTES)0x0,0,1,(LPCSTR)0x0);
      puVar5[2] = pvVar6;
      *(undefined *)(puVar5 + 3) = 1;
      puVar5[5] = 0;
      puVar5[6] = 0;
      puVar5[7] = 0;
      puVar5[1] = DVar3;
      *(undefined *)(puVar5 + 8) = 1;
    }
    *(undefined *)(puVar5 + 8) = *(undefined *)((int)this + 0xc);
    iVar4 = 0;
    if (0 < *(int *)((int)this + 8)) {
      do {
        uVar1 = puVar5[7];
        uVar2 = *(undefined4 *)(*(int *)((int)this + 4) + iVar4 * 4);
        puVar7 = (undefined4 *)operator_new(0xc);
        puVar7[1] = uVar1;
        *puVar7 = 0;
        puVar7[2] = uVar2;
        if ((undefined4 *)puVar5[7] == (undefined4 *)0x0) {
          puVar5[6] = puVar7;
        }
        else {
          *(undefined4 *)puVar5[7] = puVar7;
        }
        puVar5[5] = puVar5[5] + 1;
        puVar5[7] = puVar7;
        (**(code **)(**(int **)(*(int *)((int)this + 4) + iVar4 * 4) + 0x18))(puVar5);
        iVar4 = iVar4 + 1;
      } while (iVar4 < *(int *)((int)this + 8));
    }
    iVar8 = FUN_00406e10(param_1);
    (**(code **)*puVar5)(1);
    iVar4 = iVar8;
    if (-1 < iVar8) {
      iVar9 = 0;
      if (0 < *(int *)((int)this + 8)) {
        piVar10 = *(int **)((int)this + 4);
        do {
          iVar4 = iVar9;
          if (*(int *)(*piVar10 + 4) == iVar8) break;
          iVar9 = iVar9 + 1;
          piVar10 = piVar10 + 1;
          iVar4 = iVar8;
        } while (iVar9 < *(int *)((int)this + 8));
      }
    }
    DVar3 = GetCurrentThreadId();
    if ((DAT_00429028 == DVar3) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
      DAT_00429028 = 0xffffffff;
      LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    }
  }
  else {
    DVar3 = GetCurrentThreadId();
    if ((DAT_00429028 == DVar3) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
      DAT_00429028 = 0xffffffff;
      LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    }
  }
  ExceptionList = local_c;
  return iVar4;
}



int FUN_00403fd0(void)

{
  char cVar1;
  int unaff_ESI;
  int iVar2;
  
  if (*(char *)(unaff_ESI + 0xc) != '\0') {
    if (0 < *(int *)(unaff_ESI + 8)) {
      iVar2 = 0;
      do {
        cVar1 = (**(code **)(**(int **)(*(int *)(unaff_ESI + 4) + iVar2 * 4) + 4))();
        if (cVar1 == '\0') {
          return -1;
        }
        iVar2 = iVar2 + 1;
      } while (iVar2 < *(int *)(unaff_ESI + 8));
    }
    iVar2 = 0;
    if (0 < *(int *)(unaff_ESI + 8)) {
      do {
        (**(code **)(**(int **)(*(int *)(unaff_ESI + 4) + iVar2 * 4) + 0xc))();
        iVar2 = iVar2 + 1;
      } while (iVar2 < *(int *)(unaff_ESI + 8));
    }
    return 0;
  }
  if (0 < *(int *)(unaff_ESI + 8)) {
    iVar2 = 0;
    do {
      cVar1 = (**(code **)(**(int **)(*(int *)(unaff_ESI + 4) + iVar2 * 4) + 4))();
      if (cVar1 != '\0') {
        (**(code **)(**(int **)(*(int *)(unaff_ESI + 4) + iVar2 * 4) + 0xc))();
        return iVar2;
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 < *(int *)(unaff_ESI + 8));
  }
  return -1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00404050(void)

{
  DWORD DVar1;
  undefined4 *unaff_ESI;
  
  *unaff_ESI = aSyncObj::vftable;
  unaff_ESI[2] = aMap<int,class_aLocker*>::vftable;
  unaff_ESI[3] = 0;
  unaff_ESI[4] = 0x11;
  unaff_ESI[5] = 0;
  unaff_ESI[6] = 0;
  unaff_ESI[7] = 0;
  unaff_ESI[8] = 10;
  DVar1 = GetCurrentThreadId();
  if (DAT_00429028 == DVar1) {
    _DAT_0042902c = _DAT_0042902c + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    _DAT_0042902c = 1;
    DAT_00429028 = GetCurrentThreadId();
  }
  DAT_0042b560 = DAT_0042b560 + 1;
  unaff_ESI[1] = DAT_0042b560;
  DVar1 = GetCurrentThreadId();
  if ((DAT_00429028 == DVar1) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
    DAT_00429028 = 0xffffffff;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
  }
  return;
}



void __thiscall FUN_004040f0(void *this,int param_1)

{
  void *pvVar1;
  int *piVar2;
  int *piVar3;
  uint uVar4;
  int *piVar5;
  
  pvVar1 = *(void **)((int)this + 0xc);
  if (pvVar1 != (void *)0x0) {
    uVar4 = (*(uint *)(param_1 + 4) >> 4) % *(uint *)((int)this + 0x10);
    piVar2 = *(int **)((int)pvVar1 + uVar4 * 4);
    piVar5 = (int *)((int)pvVar1 + uVar4 * 4);
    if (piVar2 != (int *)0x0) {
      while (piVar3 = piVar2, piVar3[2] != *(uint *)(param_1 + 4)) {
        piVar2 = (int *)*piVar3;
        piVar5 = piVar3;
        if ((int *)*piVar3 == (int *)0x0) {
          return;
        }
      }
      *piVar5 = *piVar3;
      *piVar3 = *(int *)((int)this + 0x18);
      piVar2 = (int *)((int)this + 0x14);
      *piVar2 = *piVar2 + -1;
      *(int **)((int)this + 0x18) = piVar3;
      if (*piVar2 == 0) {
        FUN_00403d00((void **)((int)this + 0xc));
      }
    }
  }
  return;
}



void FUN_00404150(int param_1)

{
  int *piVar1;
  
  piVar1 = FUN_00404230(*(uint *)(param_1 + 4));
  *piVar1 = param_1;
  return;
}



bool __fastcall FUN_00404170(int *param_1)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  DWORD DVar3;
  HANDLE pvVar4;
  undefined4 *puVar5;
  int iVar6;
  DWORD unaff_retaddr;
  
  puVar2 = (undefined4 *)operator_new(0x24);
  if (puVar2 == (undefined4 *)0x0) {
    puVar2 = (undefined4 *)0x0;
  }
  else {
    DVar3 = GetCurrentThreadId();
    *puVar2 = aLocker::vftable;
    pvVar4 = CreateSemaphoreA((LPSECURITY_ATTRIBUTES)0x0,0,1,(LPCSTR)0x0);
    puVar2[2] = pvVar4;
    *(undefined *)(puVar2 + 3) = 1;
    puVar2[5] = 0;
    puVar2[6] = 0;
    puVar2[7] = 0;
    puVar2[1] = DVar3;
    *(undefined *)(puVar2 + 8) = 1;
  }
  (**(code **)(*param_1 + 0x18))(puVar2);
  uVar1 = puVar2[7];
  puVar5 = (undefined4 *)operator_new(0xc);
  puVar5[1] = uVar1;
  *puVar5 = 0;
  puVar5[2] = param_1;
  if ((undefined4 *)puVar2[7] == (undefined4 *)0x0) {
    puVar2[6] = puVar5;
  }
  else {
    *(undefined4 *)puVar2[7] = puVar5;
  }
  puVar2[5] = puVar2[5] + 1;
  puVar2[7] = puVar5;
  iVar6 = FUN_00406e10(unaff_retaddr);
  if (puVar2 != (undefined4 *)0x0) {
    (**(code **)*puVar2)(1);
  }
  return -1 < iVar6;
}



undefined4 * FUN_00404230(uint param_1)

{
  int *in_EAX;
  undefined4 *puVar1;
  uint uVar2;
  
  uVar2 = (param_1 >> 4) % (uint)in_EAX[1];
  if (*in_EAX == 0) {
    FUN_00404290();
  }
  else {
    for (puVar1 = *(undefined4 **)(*in_EAX + uVar2 * 4); puVar1 != (undefined4 *)0x0;
        puVar1 = (undefined4 *)*puVar1) {
      if (puVar1[2] == param_1) goto LAB_0040427e;
    }
  }
  puVar1 = (undefined4 *)FUN_004042e0();
  puVar1[1] = uVar2;
  puVar1[2] = param_1;
  *puVar1 = *(undefined4 *)(*in_EAX + uVar2 * 4);
  *(undefined4 **)(*in_EAX + uVar2 * 4) = puVar1;
LAB_0040427e:
  return puVar1 + 3;
}



void FUN_00404290(void)

{
  void *_Dst;
  void **unaff_ESI;
  void *unaff_EDI;
  
  if (*unaff_ESI != (void *)0x0) {
    operator_delete__(*unaff_ESI);
    *unaff_ESI = (void *)0x0;
  }
  _Dst = operator_new(-(uint)((int)(ZEXT48(unaff_EDI) * 4 >> 0x20) != 0) |
                      (uint)(ZEXT48(unaff_EDI) * 4));
  *unaff_ESI = _Dst;
  memset(_Dst,0,(int)unaff_EDI * 4);
  unaff_ESI[1] = unaff_EDI;
  return;
}



void FUN_004042e0(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  int unaff_ESI;
  
  if (*(int *)(unaff_ESI + 0xc) == 0) {
    puVar3 = (undefined4 *)operator_new(*(int *)(unaff_ESI + 0x14) * 0x10 + 4);
    *puVar3 = *(undefined4 *)(unaff_ESI + 0x10);
    *(undefined4 **)(unaff_ESI + 0x10) = puVar3;
    iVar1 = *(int *)(unaff_ESI + 0x14);
    puVar3 = puVar3 + iVar1 * 4 + -3;
    while (iVar1 = iVar1 + -1, -1 < iVar1) {
      *puVar3 = *(undefined4 *)(unaff_ESI + 0xc);
      *(undefined4 **)(unaff_ESI + 0xc) = puVar3;
      puVar3 = puVar3 + -4;
    }
  }
  puVar3 = *(undefined4 **)(unaff_ESI + 0xc);
  uVar2 = *puVar3;
  *(int *)(unaff_ESI + 8) = *(int *)(unaff_ESI + 8) + 1;
  *(undefined4 *)(unaff_ESI + 0xc) = uVar2;
  puVar3[2] = 0;
  puVar3[3] = 0;
  return;
}



undefined4 * __thiscall FUN_00404340(void *this,void **param_1)

{
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  FUN_00404370(param_1);
  return (undefined4 *)this;
}



void __fastcall FUN_00404370(void **param_1)

{
  void **this;
  void *pvVar1;
  void **in_EAX;
  void **unaff_ESI;
  
  if (*in_EAX != *unaff_ESI) {
    FUN_00401910(unaff_ESI,(uint)in_EAX[1]);
    memcpy(*unaff_ESI,*in_EAX,(size_t)in_EAX[1]);
    pvVar1 = in_EAX[1];
    unaff_ESI[1] = pvVar1;
    *(undefined *)((int)pvVar1 + (int)*unaff_ESI) = 0;
  }
  this = unaff_ESI + 3;
  if (*param_1 != unaff_ESI[3]) {
    FUN_00401910(this,(uint)param_1[1]);
    memcpy(*this,*param_1,(size_t)param_1[1]);
    pvVar1 = param_1[1];
    unaff_ESI[4] = pvVar1;
    *(undefined *)((int)pvVar1 + (int)*this) = 0;
  }
  unaff_ESI[6] = (void *)0x0;
  *(bool *)(unaff_ESI + 7) = unaff_ESI[4] != (void *)0x0;
  return;
}



uint __fastcall FUN_004043f0(char **param_1)

{
  char *_Control;
  
  _Control = *param_1;
  if (_Control == (char *)0x0) {
    _Control = &DAT_0042b55c;
  }
  if (0 < (int)param_1[4]) {
    _Control = (char *)strspn(param_1[3],_Control);
    if (((int)_Control < (int)param_1[4]) && (_Control != (char *)0xffffffff)) {
      return CONCAT31((int3)((uint)_Control >> 8),1);
    }
  }
  return (uint)_Control & 0xffffff00;
}



int __fastcall FUN_00404430(char **param_1)

{
  char **this;
  char *_Control;
  size_t sVar1;
  char *_Src;
  char *_Size;
  int local_10;
  char *local_c;
  undefined4 local_8;
  undefined4 local_4;
  
  _Src = (char *)0x0;
  this = param_1 + 3;
  _Size = (char *)0x0;
  local_10 = 0;
  local_c = (char *)0x0;
  local_4 = 0;
  local_8 = 0;
  if (*this != (char *)0x0) {
    FUN_00401910(&local_c,(uint)param_1[4]);
    _Src = local_c;
    memcpy(local_c,*this,(size_t)param_1[4]);
    _Size = param_1[4];
    _Src[(int)_Size] = '\0';
  }
  while( true ) {
    _Control = *param_1;
    if (_Control == (char *)0x0) {
      _Control = &DAT_0042b55c;
    }
    if ((int)param_1[4] < 1) break;
    sVar1 = strspn(*this,_Control);
    if (((int)param_1[4] <= (int)sVar1) || (sVar1 == 0xffffffff)) break;
    local_10 = local_10 + 1;
    FUN_00404520(param_1,&local_c);
    if (local_c != (char *)0x0) {
      free(local_c);
    }
  }
  if (_Src != *this) {
    FUN_00401910(this,(uint)_Size);
    memcpy(*this,_Src,(size_t)_Size);
    param_1[4] = _Size;
    (*this)[(int)_Size] = '\0';
  }
  param_1[6] = (char *)0x0;
  *(bool *)(param_1 + 7) = param_1[4] != (char *)0x0;
  if (_Src != (char *)0x0) {
    free(_Src);
  }
  return local_10;
}



// WARNING: Type propagation algorithm not settling

char ** __thiscall FUN_00404520(void *this,char **param_1)

{
  char **this_00;
  char cVar1;
  char *pcVar2;
  size_t sVar3;
  char **ppcVar4;
  char *pcVar5;
  char *_Size;
  char *pcVar6;
  char *_Size_00;
  char *pcStack_24;
  char *pcStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  void *apvStack_c [3];
  
  *param_1 = (char *)0x0;
  param_1[2] = (char *)0x0;
  param_1[1] = (char *)0x0;
  this_00 = (char **)((int)this + 0xc);
  while( true ) {
                    // WARNING: Load size is inaccurate
    pcVar2 = *this;
    if (pcVar2 == (char *)0x0) {
      pcVar2 = &DAT_0042b55c;
    }
    if (*(int *)((int)this + 0x10) < 1) {
      return param_1;
    }
    sVar3 = strspn(*this_00,pcVar2);
    if (*(int *)((int)this + 0x10) <= (int)sVar3) {
      return param_1;
    }
    if (sVar3 == 0xffffffff) break;
                    // WARNING: Load size is inaccurate
    pcVar2 = *this;
    if (pcVar2 == (char *)0x0) {
      pcVar2 = &DAT_0042b55c;
    }
    if (((*(int *)((int)this + 0x10) < 1) ||
        (pcVar2 = strpbrk(*this_00,pcVar2), pcVar2 == (char *)0x0)) ||
       (pcVar2 = pcVar2 + -(int)*this_00, pcVar2 == (char *)0xffffffff)) {
      if (*this_00 != *param_1) {
        FUN_00401910(param_1,*(uint *)((int)this + 0x10));
        pcVar2 = *param_1;
        memcpy(pcVar2,*this_00,*(size_t *)((int)this + 0x10));
        pcVar5 = *(char **)((int)this + 0x10);
        param_1[1] = pcVar5;
        pcVar5[(int)pcVar2] = '\0';
      }
      *(int *)((int)this + 0x18) = *(int *)((int)this + 0x18) + *(int *)((int)this + 0x10);
      *(undefined4 *)((int)this + 0x10) = 0;
      if (*this_00 != (char *)0x0) {
        **this_00 = '\0';
      }
      *(undefined *)((int)this + 0x1c) = 0;
    }
    else {
      pcStack_24 = *this_00;
      if (pcStack_24 == (char *)0x0) {
        pcStack_24 = &DAT_0042b55c;
      }
      pcVar5 = (char *)0x0;
      pcStack_18 = (char *)0x0;
      uStack_10 = 0;
      uStack_14 = 0;
      _Size = (char *)0x0;
      if (pcStack_24 != (char *)0x0) {
        pcVar6 = pcStack_24;
        do {
          cVar1 = *pcVar6;
          pcVar6 = pcVar6 + 1;
        } while (cVar1 != '\0');
        _Size_00 = pcVar6 + -(int)(pcStack_24 + 1);
        if ((int)pcVar2 < (int)(pcVar6 + -(int)(pcStack_24 + 1))) {
          _Size_00 = pcVar2;
        }
        if (_Size_00 != (char *)0x0) {
          FUN_00401910(&pcStack_18,(uint)_Size_00);
          pcVar5 = pcStack_18;
          memcpy(pcStack_18,pcStack_24,(size_t)_Size_00);
          pcVar5[(int)_Size_00] = '\0';
          _Size = _Size_00;
        }
      }
      if (pcVar5 != *param_1) {
        FUN_00401910(param_1,(uint)_Size);
        pcVar6 = *param_1;
        memcpy(pcVar6,pcVar5,(size_t)_Size);
        param_1[1] = _Size;
        pcVar6[(int)_Size] = '\0';
      }
      if (pcVar5 != (char *)0x0) {
        free(pcVar5);
      }
      ppcVar4 = (char **)FUN_00401300(this_00,apvStack_c,(int)(pcVar2 + 1),(char *)0x7fffffff);
      if (*ppcVar4 != *this_00) {
        FUN_00401910(this_00,(uint)ppcVar4[1]);
        memcpy(*this_00,*ppcVar4,(size_t)ppcVar4[1]);
        pcVar5 = ppcVar4[1];
        *(char **)((int)this + 0x10) = pcVar5;
        pcVar5[(int)*this_00] = '\0';
      }
      if (apvStack_c[0] != (void *)0x0) {
        free(apvStack_c[0]);
      }
      *(char **)((int)this + 0x18) = *(char **)((int)this + 0x18) + (int)(pcVar2 + 1);
    }
    if (param_1[1] != (char *)0x0) {
      return param_1;
    }
  }
  return param_1;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void __thiscall FUN_00404730(void *this,int *param_1)

{
  char **this_00;
  byte bVar1;
  bool bVar2;
  char cVar3;
  undefined uVar4;
  uint uVar5;
  char *pcVar6;
  FILE *_File;
  int iVar7;
  undefined *_Memory;
  undefined1 *puVar9;
  undefined4 *puVar10;
  int *piVar11;
  void **ppvVar12;
  int **ppiVar13;
  int *piVar14;
  undefined *puVar15;
  int iVar16;
  byte *pbVar17;
  int *piVar18;
  LPCSTR in_stack_fffbff3c;
  undefined4 in_stack_fffbff40;
  undefined4 uVar19;
  char *in_stack_fffbff44;
  FILE *pFVar20;
  void *pvVar21;
  undefined **ppuVar22;
  uint uVar23;
  int *piStack_4009c;
  int *piStack_40098;
  int iStack_40094;
  undefined *puStack_40090;
  int *piStack_4008c;
  int iStack_40088;
  int **ppiStack_40084;
  int **ppiStack_40080;
  int iStack_4007c;
  undefined1 *puStack_40078;
  undefined4 uStack_40074;
  undefined4 uStack_40070;
  undefined **ppuStack_4006c;
  FILE *pFStack_40068;
  void *pvStack_40064;
  void *pvStack_40060;
  undefined4 uStack_4005c;
  undefined *puStack_40058;
  int iStack_40054;
  undefined *puStack_40050;
  byte *pbStack_4004c;
  undefined *puStack_40048;
  undefined4 uStack_40044;
  undefined4 uStack_40040;
  undefined4 uStack_4003c;
  void *apvStack_40038 [3];
  void *apvStack_4002c [3];
  void *apvStack_40020 [3];
  undefined auStack_40014 [131072];
  byte abStack_20014 [131080];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  undefined1 *puVar8;
  
  puStack_8 = &LAB_0041cf6e;
  local_c = ExceptionList;
  uVar5 = DAT_00428400 ^ (uint)&piStack_4009c;
  ExceptionList = &local_c;
  this_00 = (char **)(param_1 + 2);
  piStack_4008c = param_1;
  *this_00 = (char *)0x0;
  param_1[4] = 0;
  param_1[3] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  ppuStack_4006c = aDiskFile::vftable;
  pFStack_40068 = (FILE *)0x0;
  piStack_4009c = (int *)0x0;
  iStack_40094 = 0;
  piStack_40098 = (int *)0x0;
  uStack_40044 = 0;
  uStack_4003c = 0;
  uStack_40040 = 0;
  pvStack_40064 = (void *)0x0;
  uStack_4005c = 0;
  pvStack_40060 = (void *)0x0;
  puStack_40078 = (undefined1 *)0x0;
  uStack_40070 = 0;
  uStack_40074 = 0;
  iStack_40088 = 0;
  ppiStack_40084 = (int **)0x0;
  ppiStack_40080 = (int **)0x0;
  local_4._0_1_ = 7;
  local_4._1_3_ = 0;
  *(undefined *)(param_1 + 1) = 1;
                    // WARNING: Load size is inaccurate
  if (*this != *this_00) {
    FUN_00401910(this_00,*(uint *)((int)this + 4));
                    // WARNING: Load size is inaccurate
    in_stack_fffbff44 = *this_00;
    in_stack_fffbff40 = 0x40480d;
    memcpy(in_stack_fffbff44,*this,*(size_t *)((int)this + 4));
    iVar7 = *(int *)((int)this + 4);
    param_1[3] = iVar7;
    (*this_00)[iVar7] = '\0';
  }
  piVar11 = &iStack_4007c;
  ppuVar22 = &puStack_40090;
  pcVar6 = *this_00;
  if (pcVar6 == (char *)0x0) {
    pcVar6 = &DAT_0042b55c;
  }
  puStack_40090 = &stack0xfffbff3c;
  FUN_00401100(&stack0xfffbff3c,pcVar6,(char *)0x7fffffff);
  bVar2 = FUN_004036e0(in_stack_fffbff3c,in_stack_fffbff40,in_stack_fffbff44,(uint *)ppuVar22,
                       piVar11);
  puVar15 = (undefined *)0x0;
  if ((bVar2) && (puVar15 = puStack_40090, (int)puStack_40090 < 1)) {
    puVar15 = (undefined *)0x0;
  }
  memset(auStack_40014,0,0x20000);
  pcVar6 = *this_00;
  if (pcVar6 == (char *)0x0) {
    pcVar6 = &DAT_0042b55c;
  }
  _File = fopen(pcVar6,"rb");
  pFVar20 = _File;
  fread(auStack_40014,(size_t)puVar15,1,_File);
  fclose(_File);
  iVar7 = FUN_00405890();
  *piStack_4008c = iVar7;
  if ((((iVar7 == 3) || (iVar7 == 4)) || (iVar7 == 5)) || ((iVar7 == 6 || (iVar7 == 7)))) {
    switch(iVar7) {
    case 3:
      pcVar6 = "UTF-8";
      break;
    case 4:
      pcVar6 = "UTF-16BE";
      break;
    case 5:
      pcVar6 = "UTF-16LE";
      break;
    case 6:
      pcVar6 = "UTF-32BE";
      break;
    case 7:
      pcVar6 = "UTF-32LE";
      break;
    default:
      goto LAB_00404a25;
    }
    FUN_00401040(&puStack_40078,pcVar6);
LAB_00404a25:
    puVar9 = puStack_40078;
    _Memory = (undefined *)FUN_00406f50();
    puStack_40090 = _Memory;
    if (_Memory == (undefined *)0xffffffff) {
      *(undefined *)(piStack_4008c + 1) = 0;
      puVar8 = &DAT_0042b55c;
      if (puVar9 != (undefined1 *)0x0) {
        puVar8 = puVar9;
      }
      uVar4 = SUB41(puVar8,0);
      pcVar6 = "Config.Config(enconding): invalid iconv_open %s  \'%s\'";
    }
    else {
      pbStack_4004c = abStack_20014;
      puStack_40048 = auStack_40014;
      iStack_40054 = 0x20000;
      puStack_40050 = puVar15;
      memset(pbStack_4004c,0,0x20000);
      iVar7 = (**(code **)(_Memory + 8))();
      piVar11 = (int *)(**(code **)(_Memory + 0xc))();
      piVar18 = _errno();
      *piVar18 = *piVar11;
      if (iVar7 != -1) {
        FUN_00401040(&piStack_4009c,"");
        iVar7 = 0x20000 - iStack_40054;
        iVar16 = 0;
        piVar11 = piStack_4009c;
        iStack_4007c = iVar7;
        if (0 < iVar7) {
          do {
            piVar18 = piStack_40098;
            bVar1 = abStack_20014[iVar16];
            if (bVar1 == 10) {
              puStack_40058 = &stack0xfffbff44;
              pvVar21 = (void *)0x0;
              piVar14 = (int *)0x0;
              puVar15 = &stack0xfffbff44;
              if (piVar11 != (int *)0x0) {
                FUN_00401910(&stack0xfffbff44,(uint)piStack_40098);
                memcpy(pvVar21,piVar11,(size_t)piVar18);
                *(byte *)((int)piVar18 + (int)pvVar21) = 0;
                piVar14 = piVar18;
                puVar15 = puStack_40058;
              }
              puStack_40058 = puVar15;
              FUN_00405a90(&iStack_40088,pvVar21,(uint)piVar14);
              FUN_00401040(&piStack_4009c,"");
              iVar7 = iStack_4007c;
              piVar11 = piStack_4009c;
            }
            else {
              if ((int)(byte *)((int)piStack_40098 + 1U) < iStack_40094) {
                ((byte *)((int)piStack_40098 + 1))[(int)piVar11] = 0;
              }
              else {
                FUN_00401910(&piStack_4009c,(uint)(byte *)((int)piStack_40098 + 1U));
                iVar7 = iStack_4007c;
                piVar11 = piStack_4009c;
              }
              *(byte *)((int)piStack_40098 + (int)piVar11) = bVar1;
              piStack_40098 = (int *)((int)piStack_40098 + 1);
            }
            iVar16 = iVar16 + 1;
            _Memory = puStack_40090;
          } while (iVar16 < iVar7);
        }
        piVar18 = piStack_40098;
        if (piStack_40098 != (int *)0x0) {
          puStack_40058 = &stack0xfffbff44;
          pvVar21 = (void *)0x0;
          piVar14 = (int *)0x0;
          puVar15 = &stack0xfffbff44;
          if (piVar11 != (int *)0x0) {
            FUN_00401910(&stack0xfffbff44,(uint)piStack_40098);
            memcpy(pvVar21,piVar11,(size_t)piVar18);
            *(byte *)((int)piVar18 + (int)pvVar21) = 0;
            piVar14 = piVar18;
            puVar15 = puStack_40058;
          }
          puStack_40058 = puVar15;
          FUN_00405a90(&iStack_40088,pvVar21,(uint)piVar14);
        }
        (**(code **)(_Memory + 4))();
        piVar14 = (int *)(**(code **)(_Memory + 0xc))();
        iVar7 = *piVar14;
        free(_Memory);
        piVar14 = _errno();
        *piVar14 = iVar7;
        goto joined_r0x00404ca3;
      }
      *(undefined *)(piStack_4008c + 1) = 0;
      puVar9 = &DAT_0042b55c;
      if (puStack_40078 != (undefined1 *)0x0) {
        puVar9 = puStack_40078;
      }
      uVar4 = SUB41(puVar9,0);
      pcVar6 = "Config.Config(enconding): invalid iconv %s  \'%s\'";
      puVar9 = puStack_40078;
    }
    FUN_004028b0(pcVar6,uVar4);
    local_4 = CONCAT31(local_4._1_3_,6);
    FUN_004028d0(&iStack_40088);
    if (puVar9 != (undefined1 *)0x0) {
      free(puVar9);
    }
  }
  else {
    puStack_40090 = &stack0xfffbff44;
    uVar19 = 0x7fffffff;
    puVar15 = &DAT_00423938;
    pcVar6 = (char *)0x404907;
    FUN_00401100(&stack0xfffbff44,"rt",(char *)0x7fffffff);
    puStack_40090 = &stack0xfffbff38;
    FUN_004010b0(&stack0xfffbff38,this_00);
    bVar2 = FUN_00406770(&ppuStack_4006c,pcVar6,puVar15,uVar19,(char *)pFVar20);
    if (!bVar2) {
      *(bool *)(piStack_4008c + 1) = bVar2;
      pcVar6 = *this_00;
      if (pcVar6 == (char *)0x0) {
        pcVar6 = &DAT_0042b55c;
      }
      FUN_004028b0("Config.Config(enconding): path not found %s",(char)pcVar6);
      local_4 = CONCAT31(local_4._1_3_,6);
      FUN_004028d0(&iStack_40088);
      FUN_00406740(&ppuStack_4006c);
      goto LAB_00404a8b;
    }
    cVar3 = FUN_00406880(&ppuStack_4006c,&piStack_4009c);
    while (cVar3 != '\0') {
      FUN_004014f0(&piStack_4009c,'\x01');
      uVar23 = 0x404996;
      FUN_004014f0(&piStack_4009c,'\0');
      puStack_40090 = &stack0xfffbff44;
      FUN_004010b0(&stack0xfffbff44,&piStack_4009c);
      FUN_00405a90(&iStack_40088,pFVar20,uVar23);
      cVar3 = FUN_00406880(&ppuStack_4006c,&piStack_4009c);
    }
    FUN_004067d0((int)&ppuStack_4006c);
    piVar11 = piStack_4009c;
    piVar18 = piStack_40098;
joined_r0x00404ca3:
    if (0 < iStack_40088) {
      puVar10 = (undefined4 *)FUN_00405b60(&iStack_40088,&puStack_40058);
      ppiVar13 = (int **)*puVar10;
      if (ppiVar13[2] != piVar11) {
        piVar18 = ppiVar13[3];
        if (iStack_40094 <= (int)piVar18) {
          if (piVar11 == (int *)0x0) {
            uVar23 = (uint)piVar18 & 0x8000001f;
            if ((int)uVar23 < 0) {
              uVar23 = (uVar23 - 1 | 0xffffffe0) + 1;
            }
            iVar7 = (int)piVar18 - uVar23;
            piVar11 = (int *)malloc(iVar7 + 0x21);
          }
          else {
            uVar23 = (uint)piVar18 & 0x8000001f;
            if ((int)uVar23 < 0) {
              uVar23 = (uVar23 - 1 | 0xffffffe0) + 1;
            }
            iVar7 = (int)piVar18 - uVar23;
            piVar11 = (int *)realloc(piVar11,iVar7 + 0x21);
          }
          iStack_40094 = iVar7 + 0x20;
          *(byte *)((int)piVar11 + (int)piVar18) = 0;
          piStack_4009c = piVar11;
        }
        memcpy(piVar11,ppiVar13[2],(size_t)ppiVar13[3]);
        piVar18 = ppiVar13[3];
        *(byte *)((int)piVar18 + (int)piVar11) = 0;
        piStack_40098 = piVar18;
      }
      if (1 < iStack_40088) {
        if (ppiVar13 == ppiStack_40084) {
          ppiStack_40084 = (int **)*ppiStack_40084;
          ppiStack_40084[1] = (int *)0x0;
        }
        else if (ppiVar13 == ppiStack_40080) {
          ppiStack_40080 = (int **)ppiStack_40080[1];
          *ppiStack_40080 = (int *)0x0;
        }
        else {
          *ppiVar13[1] = (int)*ppiVar13;
          (*ppiVar13)[1] = (int)ppiVar13[1];
        }
      }
      if (ppiVar13 != (int **)0x0) {
        if (ppiVar13[2] != (int *)0x0) {
          free(ppiVar13[2]);
        }
        operator_delete(ppiVar13);
      }
      iStack_40088 = iStack_40088 + -1;
      if (iStack_40088 == 0) {
        ppiStack_40080 = (int **)0x0;
        ppiStack_40084 = (int **)0x0;
      }
      if (piVar18 != (int *)0x0) {
        if ((((byte *)((int)piVar18 + -1))[(int)piVar11] < 0x7f) &&
           (iVar7 = isspace((uint)((byte *)((int)piVar18 + -1))[(int)piVar11]), iVar7 != 0)) {
          pbVar17 = (byte *)((int)piVar18 + -2);
          while (((-1 < (int)pbVar17 && (pbVar17[(int)piVar11] < 0x7f)) &&
                 (iVar7 = isspace((uint)pbVar17[(int)piVar11]), iVar7 != 0))) {
            pbVar17 = pbVar17 + -1;
          }
          piVar18 = (int *)(pbVar17 + 1);
          if (piVar18 == (int *)0x0) {
            piVar18 = (int *)0x0;
            piStack_40098 = (int *)0x0;
            if (piVar11 != (int *)0x0) {
              *(byte *)piVar11 = 0;
            }
            goto joined_r0x00404ca3;
          }
          *(byte *)((int)piVar18 + (int)piVar11) = 0;
          piStack_40098 = piVar18;
        }
        if ((*(byte *)piVar11 < 0x7f) && (iVar7 = isspace((uint)*(byte *)piVar11), iVar7 != 0)) {
          for (piVar14 = (int *)0x1;
              ((*(byte *)((int)piVar14 + (int)piVar11) < 0x7f &&
               (iVar7 = isspace((uint)*(byte *)((int)piVar14 + (int)piVar11)), iVar7 != 0)) &&
              ((int)piVar14 < (int)piVar18)); piVar14 = (int *)((int)piVar14 + 1)) {
          }
          if (piVar18 == piVar14) {
            piVar18 = (int *)0x0;
            piStack_40098 = (int *)0x0;
            *(byte *)piVar11 = 0;
            goto joined_r0x00404ca3;
          }
          piVar18 = (int *)((int)piVar18 - (int)piVar14);
          memmove(piVar11,(byte *)((int)piVar14 + (int)piVar11),(size_t)piVar18);
          *(byte *)((int)piVar18 + (int)piVar11) = 0;
          piStack_40098 = piVar18;
        }
        if (piVar18 != (int *)0x0) {
          if (*(byte *)piVar11 == 0x5b) {
            pcVar6 = strchr((char *)piVar11,0x5d);
            if (pcVar6 == (char *)0x0) {
              iVar7 = -1;
            }
            else {
              iVar7 = (int)pcVar6 - (int)piVar11;
            }
            ppvVar12 = (void **)FUN_00401300(&piStack_4009c,apvStack_4002c,1,(char *)(iVar7 + -1));
            if (*ppvVar12 != pvStack_40064) {
              FUN_00401910(&pvStack_40064,(uint)ppvVar12[1]);
              pvVar21 = pvStack_40064;
              memcpy(pvStack_40064,*ppvVar12,(size_t)ppvVar12[1]);
              pvStack_40060 = ppvVar12[1];
              *(undefined *)((int)pvStack_40060 + (int)pvVar21) = 0;
            }
            if (apvStack_4002c[0] != (void *)0x0) {
              free(apvStack_4002c[0]);
            }
          }
          else if (*(byte *)piVar11 != 0x23) {
            if (pvStack_40060 != (void *)0x0) {
              ppvVar12 = FUN_00401a20(apvStack_40038,&pvStack_40064,"/");
              ppiVar13 = (int **)FUN_00401990(apvStack_40020,ppvVar12,&piStack_4009c);
              if (*ppiVar13 != piVar11) {
                FUN_00401910(&piStack_4009c,(uint)ppiVar13[1]);
                piVar11 = piStack_4009c;
                memcpy(piStack_4009c,*ppiVar13,(size_t)ppiVar13[1]);
                piVar18 = ppiVar13[1];
                *(byte *)((int)piVar18 + (int)piVar11) = 0;
                piStack_40098 = piVar18;
              }
              if (apvStack_40020[0] != (void *)0x0) {
                free(apvStack_40020[0]);
              }
              if (apvStack_40038[0] != (void *)0x0) {
                free(apvStack_40038[0]);
              }
            }
            puStack_40090 = &stack0xfffbff44;
            pvVar21 = (void *)0x0;
            piVar14 = (int *)0x0;
            puVar15 = &stack0xfffbff44;
            if (piVar11 != (int *)0x0) {
              FUN_00401910(&stack0xfffbff44,(uint)piVar18);
              memcpy(pvVar21,piVar11,(size_t)piVar18);
              *(byte *)((int)piVar18 + (int)pvVar21) = 0;
              piVar14 = piVar18;
              puVar15 = puStack_40090;
            }
            puStack_40090 = puVar15;
            FUN_00405a90(piStack_4008c + 5,pvVar21,(uint)piVar14);
          }
        }
      }
      goto joined_r0x00404ca3;
    }
    local_4 = CONCAT31(local_4._1_3_,6);
    FUN_004028d0(&iStack_40088);
    if (puStack_40078 != (undefined1 *)0x0) {
      free(puStack_40078);
    }
    if (pvStack_40064 != (void *)0x0) {
      free(pvStack_40064);
    }
    if (piVar11 != (int *)0x0) {
      free(piVar11);
    }
    if (pFStack_40068 != (FILE *)0x0) {
      fclose(pFStack_40068);
    }
  }
LAB_00404a8b:
  ExceptionList = local_c;
  ___security_check_cookie_4(uVar5 ^ (uint)&piStack_4009c);
  return;
}



// WARNING: Removing unreachable block (ram,0x004051d5)

int __thiscall FUN_00405070(int param_1,void **param_2)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  int iVar4;
  void **ppvVar5;
  char **ppcVar6;
  char *pcVar7;
  undefined1 *puVar8;
  char *pcVar9;
  bool bVar10;
  void *pvVar11;
  undefined **local_50;
  FILE *pFStack_4c;
  char *local_48;
  char *local_44;
  undefined4 local_40;
  void *local_3c;
  void *local_38;
  undefined4 local_34;
  char *local_30;
  undefined4 local_2c;
  undefined4 local_28;
  char *local_24 [3];
  void *apvStack_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041ceee;
  local_c = ExceptionList;
  uVar2 = DAT_00428400 ^ (uint)&stack0xffffff9c;
  ExceptionList = &local_c;
  ppvVar5 = (void **)(param_1 + 8);
  *ppvVar5 = (void *)0x0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x1c) = 0;
  local_50 = aDiskFile::vftable;
  local_48 = (char *)0x0;
  local_40 = 0;
  local_44 = (char *)0x0;
  local_3c = (void *)0x0;
  local_34 = 0;
  local_38 = (void *)0x0;
  local_4 = 4;
  if (*param_2 != *ppvVar5) {
    FUN_00401910(ppvVar5,(uint)param_2[1]);
    memcpy(*ppvVar5,*param_2,(size_t)param_2[1]);
    pvVar11 = param_2[1];
    *(void **)(param_1 + 0xc) = pvVar11;
    *(undefined *)((int)pvVar11 + (int)*ppvVar5) = 0;
  }
  *(undefined *)(param_1 + 4) = 1;
  FUN_00401100(local_24,"rt",(char *)0x7fffffff);
  pcVar9 = (char *)0x0;
  local_30 = (char *)0x0;
  local_28 = 0;
  local_2c = 0;
  if (*ppvVar5 != (void *)0x0) {
    FUN_00401910(&local_30,*(uint *)(param_1 + 0xc));
    pcVar9 = local_30;
    memcpy(local_30,*ppvVar5,*(size_t *)(param_1 + 0xc));
    pcVar9[*(int *)(param_1 + 0xc)] = '\0';
  }
  pcVar7 = local_24[0];
  if (local_24[0] == (char *)0x0) {
    pcVar7 = &DAT_0042b55c;
  }
  pcVar3 = &DAT_0042b55c;
  if (pcVar9 != (char *)0x0) {
    pcVar3 = pcVar9;
  }
  pFStack_4c = fopen(pcVar3,pcVar7);
  bVar10 = pFStack_4c != (FILE *)0x0;
  if (pcVar9 != (char *)0x0) {
    free(pcVar9);
  }
  if (local_24[0] != (char *)0x0) {
    free(local_24[0]);
  }
  if (bVar10) {
    cVar1 = FUN_00406880(&local_50,&local_48);
    pcVar7 = local_48;
    pcVar9 = local_44;
    while (local_48 = pcVar7, local_44 = pcVar9, cVar1 != '\0') {
      if (((pcVar9 != (char *)0x0) && ((byte)(pcVar9 + -1)[(int)pcVar7] < 0x7f)) &&
         (iVar4 = isspace((uint)(byte)(pcVar9 + -1)[(int)pcVar7]), iVar4 != 0)) {
        pcVar9 = pcVar9 + -2;
        while (((-1 < (int)pcVar9 && ((byte)pcVar9[(int)pcVar7] < 0x7f)) &&
               (iVar4 = isspace((uint)(byte)pcVar9[(int)pcVar7]), iVar4 != 0))) {
          pcVar9 = pcVar9 + -1;
        }
        local_44 = pcVar9 + 1;
        if (local_44 == (char *)0x0) {
          local_44 = (char *)0x0;
          if (pcVar7 != (char *)0x0) {
            *pcVar7 = '\0';
          }
        }
        else {
          local_44[(int)pcVar7] = '\0';
        }
      }
      FUN_004014f0(&local_48,'\0');
      pcVar9 = local_44;
      pcVar7 = local_48;
      if (local_44 != (char *)0x0) {
        if (*local_48 == '[') {
          pcVar9 = strchr(local_48,0x5d);
          if (pcVar9 == (char *)0x0) {
            iVar4 = -1;
          }
          else {
            iVar4 = (int)pcVar9 - (int)pcVar7;
          }
          ppvVar5 = (void **)FUN_00401300(&local_48,local_24,1,(char *)(iVar4 + -1));
          if (*ppvVar5 != local_3c) {
            FUN_00401910(&local_3c,(uint)ppvVar5[1]);
            pvVar11 = local_3c;
            memcpy(local_3c,*ppvVar5,(size_t)ppvVar5[1]);
            local_38 = ppvVar5[1];
            *(undefined *)((int)local_38 + (int)pvVar11) = 0;
          }
          if (local_24[0] != (char *)0x0) {
            free(local_24[0]);
          }
        }
        else if (*local_48 != '#') {
          if (local_38 != (void *)0x0) {
            ppvVar5 = FUN_00401a20(apvStack_18,&local_3c,"/");
            ppcVar6 = (char **)FUN_00401990(&local_30,ppvVar5,&local_48);
            if (*ppcVar6 != pcVar7) {
              FUN_00401910(&local_48,(uint)ppcVar6[1]);
              pcVar7 = local_48;
              memcpy(local_48,*ppcVar6,(size_t)ppcVar6[1]);
              pcVar9 = ppcVar6[1];
              pcVar7[(int)pcVar9] = '\0';
              local_44 = pcVar9;
            }
            if (local_30 != (char *)0x0) {
              free(local_30);
            }
            if (apvStack_18[0] != (void *)0x0) {
              free(apvStack_18[0]);
            }
          }
          pvVar11 = (void *)0x0;
          pcVar3 = (char *)0x0;
          if (pcVar7 != (char *)0x0) {
            FUN_00401910(&stack0xffffff8c,(uint)pcVar9);
            memcpy(pvVar11,pcVar7,(size_t)pcVar9);
            *(char *)((int)pvVar11 + (int)pcVar9) = '\0';
            pcVar3 = pcVar9;
          }
          FUN_00405a90((void *)(param_1 + 0x14),pvVar11,(uint)pcVar3);
        }
      }
      cVar1 = FUN_00406880(&local_50,&local_48);
      pcVar7 = local_48;
      pcVar9 = local_44;
    }
    fclose(pFStack_4c);
    if (local_3c != (void *)0x0) {
      free(local_3c);
    }
    if (local_48 != (char *)0x0) {
      free(local_48);
    }
  }
  else {
    *(bool *)(param_1 + 4) = bVar10;
    puVar8 = (undefined1 *)*ppvVar5;
    if (puVar8 == (undefined1 *)0x0) {
      puVar8 = &DAT_0042b55c;
    }
    FUN_004028b0("Config.Config(): path not found %s",(char)puVar8);
  }
  ExceptionList = local_c;
  return uVar2;
}



uint __thiscall FUN_00405440(void *this,int *param_1,void **param_2)

{
  byte bVar1;
  uint uVar2;
  void **ppvVar3;
  int **ppiVar4;
  char *pcVar5;
  void *pvVar6;
  byte **ppbVar7;
  int iVar8;
  byte *pbVar9;
  byte *pbVar10;
  uint uVar11;
  byte *pbVar12;
  char *_Str;
  byte *pbVar13;
  bool bVar14;
  undefined4 uStack_40;
  byte *local_3c;
  byte *local_38;
  undefined4 local_34;
  byte *local_30;
  void *local_2c;
  undefined4 local_28;
  char *local_24;
  int iStack_20;
  int iStack_1c;
  void *apvStack_18 [3];
  void *apvStack_c [3];
  
  local_30 = (byte *)0x0;
  local_28 = 0;
  local_2c = (void *)0x0;
  local_3c = (byte *)0x0;
  local_34 = 0;
  local_38 = (byte *)0x0;
  ppvVar3 = FUN_00401440(param_1,&local_24);
  pbVar13 = (byte *)0x0;
  if (*ppvVar3 != (void *)0x0) {
    FUN_00401910(&local_30,(uint)ppvVar3[1]);
    pbVar13 = local_30;
    memcpy(local_30,*ppvVar3,(size_t)ppvVar3[1]);
    local_2c = ppvVar3[1];
    *(byte *)((int)local_2c + (int)pbVar13) = 0;
    pbVar13 = local_3c;
  }
  if (local_24 != (char *)0x0) {
    free(local_24);
  }
  FUN_004014f0(&local_30,'\x01');
  FUN_004014f0(&local_30,'\0');
  param_2[1] = (void *)0x0;
  if ((undefined *)*param_2 != (undefined *)0x0) {
    *(undefined *)*param_2 = 0;
  }
  ppiVar4 = (int **)FUN_00405b60((void *)((int)this + 0x14),&uStack_40);
  param_1 = *ppiVar4;
  if (param_1 != (int *)0x0) {
    pbVar12 = (byte *)0x0;
    do {
      _Str = (char *)0x0;
      local_24 = (char *)0x0;
      iStack_1c = 0;
      iStack_20 = 0;
      if (param_1[2] != 0) {
        uVar2 = param_1[3];
        if (-1 < (int)uVar2) {
          uVar11 = uVar2 & 0x8000001f;
          if ((int)uVar11 < 0) {
            uVar11 = (uVar11 - 1 | 0xffffffe0) + 1;
          }
          local_24 = (char *)malloc((uVar2 - uVar11) + 0x21);
          iStack_1c = (uVar2 - uVar11) + 0x20;
          local_24[uVar2] = '\0';
          pbVar13 = local_3c;
        }
        _Str = local_24;
        memcpy(local_24,(void *)param_1[2],param_1[3]);
        iStack_20 = param_1[3];
        _Str[iStack_20] = '\0';
      }
      pcVar5 = strchr(_Str,0x3d);
      if ((pcVar5 != (char *)0x0) && (pcVar5 = pcVar5 + -(int)_Str, -1 < (int)pcVar5)) {
        ppvVar3 = apvStack_18;
        pvVar6 = (void *)FUN_00401350(pcVar5,&local_24);
        ppbVar7 = (byte **)FUN_00401440(pvVar6,ppvVar3);
        if (*ppbVar7 != pbVar13) {
          FUN_00401910(&local_3c,(uint)ppbVar7[1]);
          pbVar13 = local_3c;
          memcpy(local_3c,*ppbVar7,(size_t)ppbVar7[1]);
          pbVar12 = ppbVar7[1];
          pbVar12[(int)pbVar13] = 0;
          local_38 = pbVar12;
        }
        if (apvStack_18[0] != (void *)0x0) {
          free(apvStack_18[0]);
        }
        if (apvStack_c[0] != (void *)0x0) {
          free(apvStack_c[0]);
        }
        if (((pbVar12 != (byte *)0x0) && ((pbVar12 + -1)[(int)pbVar13] < 0x7f)) &&
           (iVar8 = isspace((uint)(pbVar12 + -1)[(int)pbVar13]), iVar8 != 0)) {
          pbVar12 = pbVar12 + -2;
          while (((-1 < (int)pbVar12 && (pbVar12[(int)pbVar13] < 0x7f)) &&
                 (iVar8 = isspace((uint)pbVar12[(int)pbVar13]), iVar8 != 0))) {
            pbVar12 = pbVar12 + -1;
          }
          local_38 = pbVar12 + 1;
          if (local_38 == (byte *)0x0) {
            if (pbVar13 != (byte *)0x0) {
              *pbVar13 = 0;
            }
          }
          else {
            local_38[(int)pbVar13] = 0;
          }
        }
        FUN_004014f0(&local_3c,'\0');
        pbVar13 = local_3c;
        pbVar10 = &DAT_0042b55c;
        if (local_3c != (byte *)0x0) {
          pbVar10 = local_3c;
        }
        pbVar9 = local_30;
        pbVar12 = local_38;
        if (local_30 == (byte *)0x0) {
          if (pbVar10 == (byte *)0x0) goto LAB_00405708;
          if (*pbVar10 == 0) goto LAB_0040569a;
        }
        else {
          if (*local_30 == 0) {
LAB_0040569a:
            if ((pbVar10 == (byte *)0x0) || (*pbVar10 == 0)) goto LAB_00405708;
          }
          else if (pbVar10 == (byte *)0x0) goto LAB_004056df;
          do {
            bVar1 = *pbVar9;
            bVar14 = bVar1 < *pbVar10;
            if (bVar1 != *pbVar10) {
LAB_004056ce:
              iVar8 = (1 - (uint)bVar14) - (uint)(bVar14 != 0);
              goto LAB_004056d3;
            }
            if (bVar1 == 0) break;
            bVar1 = pbVar9[1];
            bVar14 = bVar1 < pbVar10[1];
            if (bVar1 != pbVar10[1]) goto LAB_004056ce;
            pbVar10 = pbVar10 + 2;
            pbVar9 = pbVar9 + 2;
          } while (bVar1 != 0);
          iVar8 = 0;
LAB_004056d3:
          if (iVar8 == 0) {
LAB_00405708:
            ppvVar3 = (void **)FUN_00401300(&local_24,apvStack_c,(int)(pcVar5 + 1),
                                            (char *)0x7fffffff);
            if (*ppvVar3 != *param_2) {
              FUN_00401910(param_2,(uint)ppvVar3[1]);
              memcpy(*param_2,*ppvVar3,(size_t)ppvVar3[1]);
              pvVar6 = ppvVar3[1];
              param_2[1] = pvVar6;
              *(undefined *)((int)pvVar6 + (int)*param_2) = 0;
            }
            if (apvStack_c[0] != (void *)0x0) {
              free(apvStack_c[0]);
            }
            FUN_004014f0(param_2,'\x01');
            FUN_004014f0(param_2,'\0');
            if (_Str != (char *)0x0) {
              free(_Str);
            }
            if (pbVar13 != (byte *)0x0) {
              free(pbVar13);
            }
            if (local_30 != (byte *)0x0) {
              free(local_30);
            }
            return CONCAT31((int3)((uint)local_30 >> 8),1);
          }
        }
      }
LAB_004056df:
      param_1 = (int *)*param_1;
      if (_Str != (char *)0x0) {
        free(_Str);
      }
    } while (param_1 != (int *)0x0);
    if (pbVar13 != (byte *)0x0) {
      free(pbVar13);
    }
  }
  if (local_30 != (byte *)0x0) {
    free(local_30);
  }
  return (uint)local_30 & 0xffffff00;
}



uint __thiscall FUN_004057e0(void *this,int *param_1,long *param_2)

{
  int *_Memory;
  undefined4 uVar1;
  uint uVar2;
  int *_Str;
  int *local_c;
  undefined4 local_8;
  undefined4 local_4;
  
  local_c = (int *)0x0;
  local_4 = 0;
  local_8 = 0;
  uVar1 = FUN_00405440(this,param_1,&local_c);
  _Memory = local_c;
  if ((char)uVar1 == '\0') {
    if (local_c != (int *)0x0) {
      free(local_c);
    }
    return (uint)local_c & 0xffffff00;
  }
  _Str = (int *)&DAT_0042b55c;
  if (local_c != (int *)0x0) {
    _Str = local_c;
  }
  uVar2 = strtol((char *)_Str,(char **)&param_1,10);
  if ((*(char *)param_1 == '\0') && (param_1 != _Str)) {
    *param_2 = uVar2;
    if (_Memory != (int *)0x0) {
      free(_Memory);
    }
    return CONCAT31((int3)(uVar2 >> 8),1);
  }
  if (_Memory != (int *)0x0) {
    free(_Memory);
  }
  return uVar2 & 0xffffff00;
}



undefined4 FUN_00405890(void)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int *piVar5;
  uint unaff_EBX;
  int *unaff_EDI;
  
  if (2 < unaff_EBX) {
    iVar1 = *(byte *)unaff_EDI - 0xef;
    if (((iVar1 == 0) && (iVar1 = *(byte *)((int)unaff_EDI + 1) - 0xbb, iVar1 == 0)) &&
       (iVar1 = *(byte *)((int)unaff_EDI + 2) - 0xbf, iVar1 == 0)) {
      iVar3 = 0;
    }
    else {
      iVar3 = 1;
      if (iVar1 < 1) {
        iVar3 = -1;
      }
    }
    if (iVar3 == 0) {
      return 3;
    }
  }
  if (unaff_EBX < 4) goto LAB_00405a08;
  uVar2 = 4;
  piVar4 = (int *)&DAT_00423864;
  piVar5 = unaff_EDI;
  do {
    if (*piVar5 != *piVar4) goto LAB_0040590e;
    uVar2 = uVar2 - 4;
    piVar4 = piVar4 + 1;
    piVar5 = piVar5 + 1;
  } while (3 < uVar2);
  if (uVar2 == 0) {
LAB_0040596b:
    iVar3 = 0;
  }
  else {
LAB_0040590e:
    iVar1 = (uint)*(byte *)piVar5 - (uint)*(byte *)piVar4;
    if (iVar1 == 0) {
      if (uVar2 == 1) goto LAB_0040596b;
      iVar1 = (uint)*(byte *)((int)piVar5 + 1) - (uint)*(byte *)((int)piVar4 + 1);
      if (iVar1 == 0) {
        if (uVar2 == 2) goto LAB_0040596b;
        iVar1 = (uint)*(byte *)((int)piVar5 + 2) - (uint)*(byte *)((int)piVar4 + 2);
        if (iVar1 == 0) {
          if ((uVar2 == 3) ||
             (iVar1 = (uint)*(byte *)((int)piVar5 + 3) - (uint)*(byte *)((int)piVar4 + 3),
             iVar1 == 0)) goto LAB_0040596b;
        }
      }
    }
    iVar3 = 1;
    if (iVar1 < 1) {
      iVar3 = -1;
    }
  }
  if (iVar3 == 0) {
    return 7;
  }
  uVar2 = 4;
  piVar4 = (int *)&DAT_0042386c;
  piVar5 = unaff_EDI;
  do {
    if (*piVar5 != *piVar4) goto LAB_0040599d;
    uVar2 = uVar2 - 4;
    piVar4 = piVar4 + 1;
    piVar5 = piVar5 + 1;
  } while (3 < uVar2);
  if (uVar2 == 0) {
LAB_004059fa:
    iVar3 = 0;
  }
  else {
LAB_0040599d:
    iVar1 = (uint)*(byte *)piVar5 - (uint)*(byte *)piVar4;
    if (iVar1 == 0) {
      if (uVar2 == 1) goto LAB_004059fa;
      iVar1 = (uint)*(byte *)((int)piVar5 + 1) - (uint)*(byte *)((int)piVar4 + 1);
      if (iVar1 == 0) {
        if (uVar2 == 2) goto LAB_004059fa;
        iVar1 = (uint)*(byte *)((int)piVar5 + 2) - (uint)*(byte *)((int)piVar4 + 2);
        if (iVar1 == 0) {
          if ((uVar2 == 3) ||
             (iVar1 = (uint)*(byte *)((int)piVar5 + 3) - (uint)*(byte *)((int)piVar4 + 3),
             iVar1 == 0)) goto LAB_004059fa;
        }
      }
    }
    iVar3 = 1;
    if (iVar1 < 1) {
      iVar3 = -1;
    }
  }
  if (iVar3 == 0) {
    return 6;
  }
LAB_00405a08:
  if (1 < unaff_EBX) {
    iVar1 = *(byte *)unaff_EDI - 0xff;
    if ((iVar1 == 0) && (iVar1 = *(byte *)((int)unaff_EDI + 1) - 0xfe, iVar1 == 0)) {
      iVar3 = 0;
    }
    else {
      iVar3 = 1;
      if (iVar1 < 1) {
        iVar3 = -1;
      }
    }
    if (iVar3 == 0) {
      return 5;
    }
    iVar1 = *(byte *)unaff_EDI - 0xfe;
    if ((iVar1 == 0) && (iVar1 = *(byte *)((int)unaff_EDI + 1) - 0xff, iVar1 == 0)) {
      iVar3 = 0;
    }
    else {
      iVar3 = 1;
      if (iVar1 < 1) {
        iVar3 = -1;
      }
    }
    if (iVar3 == 0) {
      return 4;
    }
  }
  return 2;
}



void __thiscall FUN_00405a90(void *this,void *param_1,uint param_2)

{
  void **this_00;
  undefined4 uVar1;
  undefined4 *puVar2;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041cdf8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  uVar1 = *(undefined4 *)((int)this + 8);
  puVar2 = (undefined4 *)operator_new(0x14);
  if (puVar2 == (undefined4 *)0x0) {
    puVar2 = (undefined4 *)0x0;
  }
  else {
    puVar2[2] = 0;
    puVar2[4] = 0;
    puVar2[3] = 0;
  }
  puVar2[1] = uVar1;
  this_00 = (void **)(puVar2 + 2);
  *puVar2 = 0;
  if (param_1 != *this_00) {
    FUN_00401910(this_00,param_2);
    memcpy(*this_00,param_1,param_2);
    puVar2[3] = param_2;
    *(undefined *)(param_2 + (int)*this_00) = 0;
  }
  if (*(undefined4 **)((int)this + 8) == (undefined4 *)0x0) {
    *(undefined4 **)((int)this + 4) = puVar2;
  }
  else {
    **(undefined4 **)((int)this + 8) = puVar2;
  }
                    // WARNING: Load size is inaccurate
  *(int *)this = *this + 1;
  *(undefined4 **)((int)this + 8) = puVar2;
  if (param_1 != (void *)0x0) {
    free(param_1);
  }
  ExceptionList = local_c;
  return;
}



void __thiscall FUN_00405b60(void *this,undefined4 *param_1)

{
  *param_1 = *(undefined4 *)((int)this + 4);
  return;
}



undefined4 * __fastcall FUN_00405b70(undefined4 *param_1)

{
  *param_1 = aTcpSocket::vftable;
  FUN_00408680();
  param_1[1] = 0;
  return param_1;
}



undefined4 * __thiscall FUN_00405b90(void *this,byte param_1)

{
  SOCKET s;
  
  s = *(SOCKET *)((int)this + 4);
  *(undefined ***)this = aTcpSocket::vftable;
  if ((s != 0) && (s != 0xffffffff)) {
    closesocket(s);
  }
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined ***)((int)this + 8) = aIpAddr::vftable;
  if (*(void **)((int)this + 0xc) != (void *)0x0) {
    free(*(void **)((int)this + 0xc));
  }
  *(undefined ***)this = aCommChannel::vftable;
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_00405bf0(undefined4 *param_1)

{
  SOCKET s;
  
  s = param_1[1];
  *param_1 = aTcpSocket::vftable;
  if ((s != 0) && (s != 0xffffffff)) {
    closesocket(s);
  }
  param_1[1] = 0;
  param_1[2] = aIpAddr::vftable;
  if ((void *)param_1[3] != (void *)0x0) {
    free((void *)param_1[3]);
  }
  *param_1 = aCommChannel::vftable;
  return;
}



bool __fastcall FUN_00405c40(int param_1)

{
  return *(int *)(param_1 + 4) != 0;
}



void __thiscall FUN_00405c50(void *this,u_short param_1,int param_2,char param_3)

{
  u_short uVar1;
  SOCKET SVar2;
  int iVar3;
  undefined4 local_1c;
  undefined4 local_18;
  sockaddr local_14;
  uint local_4;
  
  local_4 = DAT_00428400 ^ (uint)&local_1c;
  SVar2 = *(SOCKET *)((int)this + 4);
  if ((SVar2 != 0) && (SVar2 != 0xffffffff)) {
    closesocket(SVar2);
  }
  *(undefined4 *)((int)this + 4) = 0;
  SVar2 = socket(2,1,0);
  *(SOCKET *)((int)this + 4) = SVar2;
  if (SVar2 == 0xffffffff) goto LAB_00405cec;
  local_14.sa_data[2] = '\0';
  local_14.sa_data[3] = '\0';
  local_14.sa_data[4] = '\0';
  local_14.sa_data[5] = '\0';
  local_14.sa_data[6] = '\0';
  local_14.sa_data[7] = '\0';
  local_14.sa_data[8] = '\0';
  local_14.sa_data[9] = '\0';
  local_14.sa_data[10] = '\0';
  local_14.sa_data[0xb] = '\0';
  local_14.sa_data[0xc] = '\0';
  local_14.sa_data[0xd] = '\0';
  local_14.sa_family = 2;
  local_14.sa_data[0] = '\0';
  local_14.sa_data[1] = '\0';
  uVar1 = htons(param_1);
  local_14.sa_data._0_2_ = uVar1;
  local_14.sa_data[2] = '\0';
  local_14.sa_data[3] = '\0';
  local_14.sa_data[4] = '\0';
  local_14.sa_data[5] = '\0';
  local_18 = 1;
  iVar3 = setsockopt(*(SOCKET *)((int)this + 4),0xffff,-5,(char *)&local_18,4);
  if (iVar3 == 0) {
    if (param_3 != '\0') {
      local_1c = 1;
      iVar3 = setsockopt(*(SOCKET *)((int)this + 4),0xffff,4,(char *)&local_1c,4);
      if (iVar3 != 0) goto LAB_00405cda;
    }
    iVar3 = bind(*(SOCKET *)((int)this + 4),&local_14,0x10);
    if (iVar3 == 0) {
      iVar3 = listen(*(SOCKET *)((int)this + 4),param_2);
      if (iVar3 != 0) {
        FUN_00406140();
        ___security_check_cookie_4(local_4 ^ (uint)&local_1c);
        return;
      }
      ___security_check_cookie_4(local_4 ^ (uint)&local_1c);
      return;
    }
  }
LAB_00405cda:
  SVar2 = *(SOCKET *)((int)this + 4);
  if ((SVar2 != 0) && (SVar2 != 0xffffffff)) {
    closesocket(SVar2);
  }
LAB_00405cec:
  *(undefined4 *)((int)this + 4) = 0;
  ___security_check_cookie_4(local_4 ^ (uint)&local_1c);
  return;
}



void __thiscall FUN_00405d90(void *this,int param_1)

{
  timeval *timeout;
  int iVar1;
  SOCKET SVar2;
  undefined4 *puVar3;
  void *_Memory;
  undefined **local_148;
  void *local_144;
  uint local_140;
  undefined4 local_13c;
  undefined4 local_138;
  undefined4 local_134;
  int local_130;
  timeval local_12c;
  fd_set local_124;
  sockaddr local_20;
  uint local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041ce8b;
  local_c = ExceptionList;
  local_10 = DAT_00428400 ^ (uint)&local_148;
  ExceptionList = &local_c;
  _Memory = (void *)0x0;
  local_148 = aIpAddr::vftable;
  local_144 = (void *)0x0;
  local_13c = 0;
  local_140 = 0;
  if (DAT_0042b564 != (void *)0x0) {
    FUN_00401910(&local_144,DAT_0042b568);
    _Memory = local_144;
    memcpy(local_144,DAT_0042b564,DAT_0042b568);
    local_140 = DAT_0042b568;
    *(undefined *)(DAT_0042b568 + (int)_Memory) = 0;
  }
  local_138 = 0;
  local_4 = 0;
  SVar2 = *(SOCKET *)((int)this + 4);
  if (SVar2 != 0) {
    local_124.fd_count = 1;
    if (param_1 < 0) {
      timeout = (timeval *)0x0;
    }
    else {
      local_12c.tv_sec = param_1 / 1000;
      local_12c.tv_usec = (param_1 % 1000) * 1000;
      timeout = &local_12c;
    }
    local_124.fd_array[0] = SVar2;
    iVar1 = select(SVar2 + 1,&local_124,(fd_set *)0x0,(fd_set *)0x0,timeout);
    if ((iVar1 != 0) && (iVar1 != -1)) {
      local_130 = 0x10;
      SVar2 = accept(*(SOCKET *)((int)this + 4),&local_20,&local_130);
      if (SVar2 != 0xffffffff) {
        local_134._0_1_ = local_20.sa_data[2];
        local_134._1_1_ = local_20.sa_data[3];
        local_134._2_1_ = local_20.sa_data[4];
        local_134._3_1_ = local_20.sa_data[5];
        FUN_00408700((int)&local_148);
        puVar3 = (undefined4 *)operator_new(0x1c);
        if (puVar3 != (undefined4 *)0x0) {
          FUN_004060e0(puVar3,SVar2);
        }
        if (local_144 != (void *)0x0) {
          free(local_144);
        }
        goto LAB_00405f1d;
      }
    }
  }
  if (_Memory != (void *)0x0) {
    free(_Memory);
  }
LAB_00405f1d:
  ExceptionList = local_c;
  ___security_check_cookie_4(local_10 ^ (uint)&local_148);
  return;
}



undefined4 * __thiscall FUN_00405f50(void *this,byte param_1)

{
  *(undefined ***)this = aIpAddr::vftable;
  if (*(void **)((int)this + 4) != (void *)0x0) {
    free(*(void **)((int)this + 4));
  }
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



int __thiscall FUN_00405f80(void *this,char *param_1,int param_2,int param_3)

{
  timeval *timeout;
  int iVar1;
  timeval local_10c;
  fd_set local_104;
  
  local_104.fd_array[0] = *(SOCKET *)((int)this + 4);
  local_104.fd_count = 1;
  if (param_3 < 0) {
    timeout = (timeval *)0x0;
  }
  else {
    local_10c.tv_sec = param_3 / 1000;
    local_10c.tv_usec = (param_3 % 1000) * 1000;
    timeout = &local_10c;
  }
  iVar1 = select(local_104.fd_array[0] + 1,&local_104,(fd_set *)0x0,(fd_set *)0x0,timeout);
  if (iVar1 < 1) {
    return 0;
  }
  iVar1 = recv(*(SOCKET *)((int)this + 4),param_1,param_2,0);
  return iVar1;
}



int __thiscall FUN_00406020(void *this,char *param_1,int param_2,int param_3)

{
  timeval *timeout;
  int iVar1;
  timeval local_10c;
  fd_set local_104;
  
  local_104.fd_array[0] = *(SOCKET *)((int)this + 4);
  local_104.fd_count = 1;
  if (param_3 < 0) {
    timeout = (timeval *)0x0;
  }
  else {
    local_10c.tv_sec = param_3 / 1000;
    local_10c.tv_usec = (param_3 % 1000) * 1000;
    timeout = &local_10c;
  }
  iVar1 = select(local_104.fd_array[0] + 1,(fd_set *)0x0,&local_104,(fd_set *)0x0,timeout);
  if (iVar1 < 1) {
    return 0;
  }
  iVar1 = send(*(SOCKET *)((int)this + 4),param_1,param_2,0);
  return iVar1;
}



void __fastcall FUN_004060c0(int param_1)

{
  SOCKET s;
  
  s = *(SOCKET *)(param_1 + 4);
  if ((s != 0) && (s != 0xffffffff)) {
    closesocket(s);
  }
  *(undefined4 *)(param_1 + 4) = 0;
  return;
}



undefined4 * FUN_004060e0(undefined4 *param_1,undefined4 param_2)

{
  void **this;
  int iVar1;
  int unaff_EBX;
  
  *param_1 = aTcpSocket::vftable;
  FUN_00408680();
  param_1[1] = param_2;
  this = (void **)(param_1 + 3);
  if (*(int *)(unaff_EBX + 4) != param_1[3]) {
    FUN_00401910(this,*(uint *)(unaff_EBX + 8));
    memcpy(*this,*(void **)(unaff_EBX + 4),*(size_t *)(unaff_EBX + 8));
    iVar1 = *(int *)(unaff_EBX + 8);
    param_1[4] = iVar1;
    *(undefined *)(iVar1 + (int)*this) = 0;
  }
  param_1[6] = *(undefined4 *)(unaff_EBX + 0x10);
  return param_1;
}



uint FUN_00406140(void)

{
  SOCKET s;
  int unaff_ESI;
  
  s = *(SOCKET *)(unaff_ESI + 4);
  if ((s != 0) && (s != 0xffffffff)) {
    s = closesocket(s);
  }
  *(undefined4 *)(unaff_ESI + 4) = 0;
  return s & 0xffffff00;
}



void __cdecl FUN_00406160(DWORD param_1)

{
  Sleep(param_1);
  return;
}



undefined4 * __fastcall FUN_00406170(undefined4 *param_1)

{
  FUN_00404050();
  *param_1 = aCondition::vftable;
  *(undefined *)(param_1 + 9) = 0;
  return param_1;
}



void __fastcall FUN_00406190(undefined4 *param_1)

{
  *param_1 = aSyncObj::vftable;
  param_1[2] = aMap<int,class_aLocker*>::vftable;
  FUN_00403d00((void **)(param_1 + 3));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined __fastcall FUN_004061b0(int *param_1)

{
  code *pcVar1;
  undefined uVar2;
  uint uVar3;
  DWORD DVar4;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041cdc8;
  local_c = ExceptionList;
  uVar3 = DAT_00428400 ^ (uint)&stack0xffffffe4;
  ExceptionList = &local_c;
  DVar4 = GetCurrentThreadId();
  if (DAT_00429028 == DVar4) {
    _DAT_0042902c = _DAT_0042902c + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    _DAT_0042902c = 1;
    DAT_00429028 = GetCurrentThreadId();
  }
  local_4 = 0;
  *(undefined *)((int)param_1 + 0x25) = 0;
  pcVar1 = *(code **)(*param_1 + 8);
  *(undefined *)(param_1 + 9) = 1;
  uVar2 = (*pcVar1)(0,uVar3);
  DVar4 = GetCurrentThreadId();
  if ((DAT_00429028 == DVar4) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
    DAT_00429028 = 0xffffffff;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
  }
  ExceptionList = &PTR_vftable_00429024;
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __fastcall FUN_00406270(int param_1)

{
  DWORD DVar1;
  DWORD extraout_EAX;
  
  DVar1 = GetCurrentThreadId();
  if (DAT_00429028 == DVar1) {
    _DAT_0042902c = _DAT_0042902c + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    _DAT_0042902c = 1;
    DAT_00429028 = GetCurrentThreadId();
  }
  *(undefined *)(param_1 + 0x24) = 0;
  *(undefined *)(param_1 + 0x25) = 0;
  DVar1 = GetCurrentThreadId();
  if ((DAT_00429028 == DVar1) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
    DAT_00429028 = 0xffffffff;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    DVar1 = extraout_EAX;
  }
  return CONCAT31((int3)(DVar1 >> 8),1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined FUN_004062e0(void)

{
  code *pcVar1;
  undefined uVar2;
  uint uVar3;
  DWORD DVar4;
  int *unaff_ESI;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041cd98;
  local_c = ExceptionList;
  uVar3 = DAT_00428400 ^ (uint)&stack0xffffffe8;
  ExceptionList = &local_c;
  DVar4 = GetCurrentThreadId();
  if (DAT_00429028 == DVar4) {
    _DAT_0042902c = _DAT_0042902c + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    _DAT_0042902c = 1;
    DAT_00429028 = GetCurrentThreadId();
  }
  local_4 = 0;
  pcVar1 = *(code **)(*unaff_ESI + 8);
  *(undefined *)(unaff_ESI + 9) = 1;
  *(undefined *)((int)unaff_ESI + 0x25) = 1;
  uVar2 = (*pcVar1)(0,uVar3);
  DVar4 = GetCurrentThreadId();
  if ((DAT_00429028 == DVar4) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
    DAT_00429028 = 0xffffffff;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
  }
  ExceptionList = &PTR_vftable_00429024;
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined __fastcall FUN_004063a0(int param_1)

{
  undefined uVar1;
  DWORD DVar2;
  
  DVar2 = GetCurrentThreadId();
  if (DAT_00429028 == DVar2) {
    _DAT_0042902c = _DAT_0042902c + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    _DAT_0042902c = 1;
    DAT_00429028 = GetCurrentThreadId();
  }
  uVar1 = *(undefined *)(param_1 + 0x24);
  DVar2 = GetCurrentThreadId();
  if ((DAT_00429028 == DVar2) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
    DAT_00429028 = 0xffffffff;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool __fastcall FUN_00406410(int *param_1,undefined param_2,undefined4 param_3)

{
  bool bVar1;
  DWORD DVar2;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041cdc8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  DVar2 = GetCurrentThreadId();
  if (DAT_00429028 == DVar2) {
    _DAT_0042902c = _DAT_0042902c + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    _DAT_0042902c = 1;
    DAT_00429028 = GetCurrentThreadId();
  }
  local_4 = 0;
  if (*(char *)(param_1 + 9) != '\0') {
    DVar2 = GetCurrentThreadId();
    if ((DAT_00429028 == DVar2) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
      DAT_00429028 = 0xffffffff;
      LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    }
    ExceptionList = local_c;
    return true;
  }
  bVar1 = FUN_00404170(param_1);
  DVar2 = GetCurrentThreadId();
  if ((DAT_00429028 == DVar2) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
    DAT_00429028 = 0xffffffff;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
  }
  ExceptionList = local_c;
  return bVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __fastcall FUN_00406510(int *param_1)

{
  int **ppiVar1;
  int *piVar2;
  int iVar3;
  undefined4 *puVar4;
  DWORD DVar5;
  uint uVar6;
  undefined4 *puVar7;
  undefined4 uVar8;
  DWORD extraout_EAX;
  int **ppiVar9;
  int *piVar10;
  int local_24;
  undefined4 *local_20;
  undefined4 *local_1c;
  void *local_14;
  undefined *puStack_10;
  uint local_c;
  
  local_c = 0xffffffff;
  puStack_10 = &LAB_0041cd70;
  local_14 = ExceptionList;
  ExceptionList = &local_14;
  DVar5 = GetCurrentThreadId();
  if (DAT_00429028 == DVar5) {
    _DAT_0042902c = _DAT_0042902c + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    _DAT_0042902c = 1;
    DAT_00429028 = GetCurrentThreadId();
  }
  local_24 = 0;
  local_20 = (undefined4 *)0x0;
  local_1c = (undefined4 *)0x0;
  local_c = 1;
  *(undefined *)(param_1 + 9) = 1;
  ppiVar1 = (int **)(param_1 + 3);
  piVar2 = (int *)0x0;
  if (param_1[5] != 0) {
    uVar6 = 0;
    if (param_1[4] != 0) {
      ppiVar9 = (int **)*ppiVar1;
      do {
        piVar2 = *ppiVar9;
        if (piVar2 != (int *)0x0) break;
        uVar6 = uVar6 + 1;
        ppiVar9 = ppiVar9 + 1;
      } while (uVar6 < (uint)param_1[4]);
    }
  }
  do {
    piVar10 = piVar2;
    puVar4 = local_1c;
    if ((ppiVar1 == (int **)0x0) || (piVar10 == (int *)0x0)) break;
    iVar3 = piVar10[3];
    local_1c = (undefined4 *)operator_new(0xc);
    local_1c[1] = puVar4;
    *local_1c = 0;
    local_1c[2] = iVar3;
    puVar7 = local_1c;
    if (puVar4 != (undefined4 *)0x0) {
      *puVar4 = local_1c;
      puVar7 = local_20;
    }
    local_20 = puVar7;
    piVar2 = (int *)*piVar10;
    local_24 = local_24 + 1;
    if (piVar2 == (int *)0x0) {
      uVar6 = piVar10[1] + 1;
      if (uVar6 < (uint)param_1[4]) {
        ppiVar9 = (int **)(*ppiVar1 + uVar6);
        do {
          piVar2 = *ppiVar9;
          if (piVar2 != (int *)0x0) break;
          uVar6 = uVar6 + 1;
          ppiVar9 = ppiVar9 + 1;
        } while (uVar6 < (uint)param_1[4]);
      }
    }
  } while( true );
  puVar7 = (undefined4 *)FUN_00406ec0((int)&local_24);
  for (puVar7 = (undefined4 *)*puVar7; puVar7 != (undefined4 *)0x0; puVar7 = (undefined4 *)*puVar7)
  {
    uVar8 = FUN_00406bb0(puVar7[2]);
    if ((char)uVar8 != '\0') {
      FUN_00406cf0(param_1);
    }
  }
  if (*(char *)((int)param_1 + 0x25) != '\0') {
    *(undefined *)(param_1 + 9) = 0;
  }
  local_c = local_c & 0xffffff00;
  if (local_24 < 2) {
    if (local_24 == 0) goto LAB_004066a5;
  }
  else {
    for (puVar7 = (undefined4 *)*local_20; puVar7 != (undefined4 *)0x0;
        puVar7 = (undefined4 *)*puVar7) {
      operator_delete((void *)puVar7[1]);
    }
  }
  operator_delete(puVar4);
LAB_004066a5:
  DVar5 = GetCurrentThreadId();
  if ((DAT_00429028 == DVar5) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
    DAT_00429028 = 0xffffffff;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    DVar5 = extraout_EAX;
  }
  ExceptionList = local_14;
  return CONCAT31((int3)(DVar5 >> 8),1);
}



void FUN_004066f0(void)

{
  return;
}



undefined4 * __thiscall FUN_00406700(void *this,byte param_1)

{
  *(undefined ***)this = aDiskFile::vftable;
  if (*(FILE **)((int)this + 4) != (FILE *)0x0) {
    fclose(*(FILE **)((int)this + 4));
  }
  *(undefined4 *)((int)this + 4) = 0;
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_00406740(undefined4 *param_1)

{
  *param_1 = aDiskFile::vftable;
  if ((FILE *)param_1[1] != (FILE *)0x0) {
    fclose((FILE *)param_1[1]);
  }
  param_1[1] = 0;
  return;
}



bool __thiscall
FUN_00406770(void *this,char *param_1,undefined4 param_2,undefined4 param_3,char *param_4)

{
  char *_Filename;
  FILE *pFVar1;
  char *_Mode;
  
  _Mode = &DAT_0042b55c;
  if (param_4 != (char *)0x0) {
    _Mode = param_4;
  }
  _Filename = &DAT_0042b55c;
  if (param_1 != (char *)0x0) {
    _Filename = param_1;
  }
  pFVar1 = fopen(_Filename,_Mode);
  *(FILE **)((int)this + 4) = pFVar1;
  if (param_1 != (char *)0x0) {
    free(param_1);
  }
  if (param_4 != (char *)0x0) {
    free(param_4);
  }
  return pFVar1 != (FILE *)0x0;
}



void __fastcall FUN_004067d0(int param_1)

{
  fclose(*(FILE **)(param_1 + 4));
  *(undefined4 *)(param_1 + 4) = 0;
  return;
}



size_t __thiscall FUN_004067f0(void *this,void *param_1,size_t param_2,size_t param_3)

{
  int iVar1;
  size_t sVar2;
  
  iVar1 = feof(*(FILE **)((int)this + 4));
  if (iVar1 != 0) {
    return 0;
  }
  sVar2 = fread(param_1,param_2,param_3,*(FILE **)((int)this + 4));
  return sVar2;
}



void __thiscall FUN_00406830(void *this,void *param_1,size_t param_2,size_t param_3)

{
  fwrite(param_1,param_2,param_3,*(FILE **)((int)this + 4));
  return;
}



void __thiscall FUN_00406850(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int unaff_retaddr;
  
  _fseeki64(*(FILE **)((int)this + 4),CONCAT44(param_3,param_2),unaff_retaddr);
  return;
}



longlong __fastcall FUN_00406870(int param_1)

{
  longlong lVar1;
  
  lVar1 = _ftelli64(*(FILE **)(param_1 + 4));
  return lVar1;
}



void __thiscall FUN_00406880(void *this,void *param_1)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  char acStack_404 [1024];
  uint local_4;
  
  local_4 = DAT_00428400 ^ (uint)acStack_404;
  iVar2 = feof(*(FILE **)((int)this + 4));
  if (iVar2 == 0) {
    acStack_404[0] = '\0';
    fgets(acStack_404,0x3ff,*(FILE **)((int)this + 4));
    pcVar3 = acStack_404;
    do {
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    for (pcVar3 = pcVar3 + (-1 - (int)(acStack_404 + 1));
        (0 < (int)pcVar3 &&
        ((acStack_404[(int)pcVar3] == '\r' || (acStack_404[(int)pcVar3] == '\n'))));
        pcVar3 = pcVar3 + -1) {
      acStack_404[(int)pcVar3] = '\0';
    }
    if (param_1 != (void *)0x0) {
      FUN_00401040(param_1,acStack_404);
    }
  }
  ___security_check_cookie_4(local_4 ^ (uint)acStack_404);
  return;
}



int __cdecl FUN_00406940(char *param_1)

{
  char *pcVar1;
  char cVar2;
  char *pcVar3;
  int iVar4;
  
  iVar4 = 0;
  pcVar3 = &DAT_0042b55c;
  if (param_1 != (char *)0x0) {
    pcVar3 = param_1;
  }
  cVar2 = *pcVar3;
  while (cVar2 != '\0') {
    iVar4 = iVar4 * 0x21 + (int)cVar2;
    pcVar1 = pcVar3 + 1;
    pcVar3 = pcVar3 + 1;
    cVar2 = *pcVar1;
  }
  if (param_1 != (char *)0x0) {
    free(param_1);
  }
  return iVar4;
}



bool __fastcall FUN_00406990(int param_1)

{
  HANDLE hThread;
  BOOL BVar1;
  int unaff_ESI;
  
  if (0x14 < unaff_ESI + 10U) {
    return false;
  }
  GetCurrentThread();
  switch(unaff_ESI) {
  case 2:
  case 3:
  case 4:
    param_1 = -1;
    break;
  case 5:
  case 6:
  case 7:
    param_1 = -2;
    break;
  case 8:
  case 9:
  case 10:
    param_1 = -0xf;
    break;
  case -10:
  case -9:
  case -8:
    param_1 = 0xf;
    break;
  case -7:
  case -6:
  case -5:
    param_1 = 2;
    break;
  case -4:
  case -3:
  case -2:
    param_1 = 1;
    break;
  case -1:
  case 0:
  case 1:
    param_1 = 0;
  }
  hThread = GetCurrentThread();
  BVar1 = SetThreadPriority(hThread,param_1);
  return BVar1 != 0;
}



void __cdecl FUN_00406a40(undefined4 *param_1,int param_2)

{
  memset(param_1,0,param_2 * 0xc);
  if (param_2 != 0) {
    do {
      param_2 = param_2 + -1;
      if (param_1 != (undefined4 *)0x0) {
        *param_1 = 0;
        param_1[2] = 0;
        param_1[1] = 0;
      }
      param_1 = param_1 + 3;
    } while (param_2 != 0);
  }
  return;
}



void FUN_00406a80(void)

{
  HANDLE *in_EAX;
  
  CloseHandle(*in_EAX);
  return;
}



undefined4 * __thiscall FUN_00406a90(void *this,byte param_1)

{
  FUN_00406ab0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_00406ab0(undefined4 *param_1)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  undefined4 *puVar4;
  int **ppiVar5;
  void *pvVar6;
  void *local_c;
  undefined *puStack_8;
  uint local_4;
  
  local_c = ExceptionList;
  puStack_8 = &LAB_0041cca6;
  ExceptionList = &local_c;
  *param_1 = aLocker::vftable;
  piVar1 = param_1 + 5;
  local_4 = 1;
  iVar2 = *piVar1;
  while (iVar2 != 0) {
    ppiVar5 = (int **)FUN_00406ec0((int)piVar1);
    piVar3 = *ppiVar5;
    if (1 < *piVar1) {
      if (piVar3 == (int *)param_1[6]) {
        iVar2 = *(int *)param_1[6];
        param_1[6] = iVar2;
        *(undefined4 *)(iVar2 + 4) = 0;
      }
      else if (piVar3 == (int *)param_1[7]) {
        puVar4 = (undefined4 *)((int *)param_1[7])[1];
        param_1[7] = puVar4;
        *puVar4 = 0;
      }
      else {
        *(int *)piVar3[1] = *piVar3;
        *(int *)(*piVar3 + 4) = piVar3[1];
      }
    }
    operator_delete(piVar3);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      param_1[7] = 0;
      param_1[6] = 0;
    }
    iVar2 = *piVar1;
  }
  local_4 = local_4 & 0xffffff00;
  if (*piVar1 < 2) {
    if (*piVar1 == 0) goto LAB_00406b8c;
    pvVar6 = (void *)param_1[7];
  }
  else {
    for (puVar4 = *(undefined4 **)param_1[6]; puVar4 != (undefined4 *)0x0;
        puVar4 = (undefined4 *)*puVar4) {
      operator_delete((void *)puVar4[1]);
    }
    pvVar6 = (void *)param_1[7];
  }
  operator_delete(pvVar6);
LAB_00406b8c:
  CloseHandle((HANDLE)param_1[2]);
  ExceptionList = local_c;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __fastcall FUN_00406bb0(int param_1)

{
  char cVar1;
  uint uVar2;
  DWORD DVar3;
  undefined4 *puVar4;
  DWORD extraout_EAX;
  uint extraout_EAX_00;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041cd38;
  local_c = ExceptionList;
  uVar2 = DAT_00428400 ^ (uint)&stack0xffffffe0;
  ExceptionList = &local_c;
  DVar3 = GetCurrentThreadId();
  if (DAT_00429028 == DVar3) {
    _DAT_0042902c = _DAT_0042902c + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    _DAT_0042902c = 1;
    DAT_00429028 = GetCurrentThreadId();
  }
  local_4 = 0;
  puVar4 = (undefined4 *)FUN_00406ec0(param_1 + 0x14);
  puVar4 = (undefined4 *)*puVar4;
  if (*(char *)(param_1 + 0x20) != '\0') {
    do {
      if (puVar4 == (undefined4 *)0x0) {
LAB_00406c54:
        DVar3 = GetCurrentThreadId();
        if ((DAT_00429028 == DVar3) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
          DAT_00429028 = 0xffffffff;
          LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
          DVar3 = extraout_EAX;
        }
        ExceptionList = local_c;
        return CONCAT31((int3)(DVar3 >> 8),1);
      }
      cVar1 = (**(code **)(*(int *)puVar4[2] + 4))();
      if (cVar1 == '\0') goto LAB_00406ca8;
      puVar4 = (undefined4 *)*puVar4;
    } while( true );
  }
  for (; puVar4 != (undefined4 *)0x0; puVar4 = (undefined4 *)*puVar4) {
    cVar1 = (**(code **)(*(int *)puVar4[2] + 4))(uVar2);
    if (cVar1 != '\0') goto LAB_00406c54;
  }
LAB_00406ca8:
  uVar2 = GetCurrentThreadId();
  if ((DAT_00429028 == uVar2) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
    DAT_00429028 = 0xffffffff;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    uVar2 = extraout_EAX_00;
  }
  ExceptionList = local_c;
  return uVar2 & 0xffffff00;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00406cf0(int *param_1)

{
  uint uVar1;
  DWORD DVar2;
  undefined4 *puVar3;
  int unaff_EDI;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041cd08;
  local_c = ExceptionList;
  uVar1 = DAT_00428400 ^ (uint)&stack0xffffffe0;
  ExceptionList = &local_c;
  DVar2 = GetCurrentThreadId();
  if (DAT_00429028 == DVar2) {
    _DAT_0042902c = _DAT_0042902c + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    _DAT_0042902c = 1;
    DAT_00429028 = GetCurrentThreadId();
  }
  local_4 = 0;
  if (*(char *)(unaff_EDI + 0x20) == '\0') {
    *(int *)(unaff_EDI + 0x10) = param_1[1];
    (**(code **)(*param_1 + 0xc))(uVar1);
  }
  else {
    *(undefined4 *)(unaff_EDI + 0x10) = 0;
    puVar3 = (undefined4 *)FUN_00406ec0(unaff_EDI + 0x14);
    for (puVar3 = (undefined4 *)*puVar3; puVar3 != (undefined4 *)0x0; puVar3 = (undefined4 *)*puVar3
        ) {
      (**(code **)(*(int *)puVar3[2] + 0xc))();
    }
  }
  puVar3 = (undefined4 *)FUN_00406ec0(unaff_EDI + 0x14);
  for (puVar3 = (undefined4 *)*puVar3; puVar3 != (undefined4 *)0x0; puVar3 = (undefined4 *)*puVar3)
  {
    (**(code **)(*(int *)puVar3[2] + 0x14))();
  }
  ReleaseSemaphore(*(HANDLE *)(unaff_EDI + 8),1,(LPLONG)0x0);
  DVar2 = GetCurrentThreadId();
  if ((DAT_00429028 == DVar2) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
    DAT_00429028 = 0xffffffff;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
  }
  ExceptionList = local_c;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00406e10(DWORD param_1)

{
  DWORD DVar1;
  undefined4 *puVar2;
  int unaff_EDI;
  HANDLE hHandle;
  
  *(undefined4 *)(unaff_EDI + 0x10) = 0xffffffff;
  DVar1 = GetCurrentThreadId();
  if ((DAT_00429028 == DVar1) && (_DAT_0042902c = _DAT_0042902c + -1, _DAT_0042902c == 0)) {
    DAT_00429028 = 0xffffffff;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
  }
  if ((int)param_1 < 0) {
    hHandle = *(HANDLE *)(unaff_EDI + 8);
    param_1 = 0xffffffff;
  }
  else {
    hHandle = *(HANDLE *)(unaff_EDI + 8);
  }
  WaitForSingleObject(hHandle,param_1);
  DVar1 = GetCurrentThreadId();
  if (DAT_00429028 == DVar1) {
    _DAT_0042902c = _DAT_0042902c + 1;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00429030);
    _DAT_0042902c = 1;
    DAT_00429028 = GetCurrentThreadId();
  }
  puVar2 = (undefined4 *)FUN_00406ec0(unaff_EDI + 0x14);
  for (puVar2 = (undefined4 *)*puVar2; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2)
  {
    (**(code **)(*(int *)puVar2[2] + 0x14))();
  }
  return *(undefined4 *)(unaff_EDI + 0x10);
}



void __fastcall FUN_00406ec0(int param_1)

{
  undefined4 *in_EAX;
  
  *in_EAX = *(undefined4 *)(param_1 + 4);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00406ed0(void)

{
  HMODULE hModule;
  
  if (DAT_0042b548 != (FARPROC)0x0) {
    return 1;
  }
  hModule = LoadLibraryA("mlang.dll");
  if (hModule == (HMODULE)0x0) {
    return 0;
  }
  DAT_0042b548 = GetProcAddress(hModule,"ConvertINetString");
  DAT_0042b558 = GetProcAddress(hModule,"ConvertINetMultiByteToUnicode");
  DAT_0042b54c = GetProcAddress(hModule,"ConvertINetUnicodeToMultiByte");
  _DAT_0042b550 = GetProcAddress(hModule,"IsConvertINetStringAvailable");
  _DAT_0042b554 = GetProcAddress(hModule,"LcidToRfc1766A");
  _DAT_0042b544 = GetProcAddress(hModule,"Rfc1766ToLcidA");
  return 1;
}



void * FUN_00406f50(void)

{
  void *_Memory;
  int *piVar1;
  int iVar2;
  
  _Memory = calloc(1,0x50);
  if (_Memory == (void *)0x0) {
    piVar1 = _errno();
    *piVar1 = 0xc;
    return (void *)0xffffffff;
  }
  iVar2 = FUN_00406fb0((int)_Memory);
  if (iVar2 != 0) {
    return _Memory;
  }
  free(_Memory);
  piVar1 = _errno();
  *piVar1 = 0x16;
  return (void *)0xffffffff;
}



undefined4 __cdecl FUN_00406fb0(int param_1)

{
  code *pcVar1;
  char *in_EAX;
  int *piVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  
  piVar2 = (int *)FUN_004073b0(in_EAX);
  piVar5 = (int *)(param_1 + 0x10);
  for (iVar3 = 8; iVar3 != 0; iVar3 = iVar3 + -1) {
    *piVar5 = *piVar2;
    piVar2 = piVar2 + 1;
    piVar5 = piVar5 + 1;
  }
  piVar2 = (int *)FUN_004073b0("UTF-8//TRANSLIT");
  iVar3 = *(int *)(param_1 + 0x10);
  piVar5 = (int *)(param_1 + 0x30);
  for (iVar4 = 8; pcVar1 = _errno_exref, iVar4 != 0; iVar4 = iVar4 + -1) {
    *piVar5 = *piVar2;
    piVar2 = piVar2 + 1;
    piVar5 = piVar5 + 1;
  }
  if ((iVar3 != -1) && (*(int *)(param_1 + 0x30) != -1)) {
    *(undefined **)(param_1 + 4) = &LAB_00407030;
    *(code **)(param_1 + 8) = FUN_00407040;
    *(code **)(param_1 + 0xc) = pcVar1;
    *(int *)param_1 = param_1;
    return 1;
  }
  return 0;
}



void __cdecl FUN_00407040(int param_1,int *param_2,int *param_3,int *param_4,int *param_5)

{
  int *piVar1;
  uint *puVar2;
  int *piVar3;
  uint *puVar4;
  int *piVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  int local_44;
  int local_40;
  int *local_3c;
  int *local_38;
  int *local_34;
  int iStack_30;
  undefined4 local_2c;
  int *local_28;
  ushort local_24;
  ushort uStack_22;
  uint local_4;
  
  local_4 = DAT_00428400 ^ (uint)&local_44;
  local_40 = param_1;
  local_38 = param_2;
  local_3c = param_3;
  local_28 = param_4;
  local_34 = param_5;
  if ((param_2 == (int *)0x0) || (*param_2 == 0)) {
    if ((param_4 != (int *)0x0) && ((*param_4 != 0 && (*(code **)(param_1 + 0x44) != (code *)0x0))))
    {
      iVar7 = (**(code **)(param_1 + 0x44))(param_1 + 0x30,*param_4,*param_5);
      if (iVar7 == -1) goto LAB_00407310;
      *param_4 = *param_4 + iVar7;
      *param_5 = *param_5 - iVar7;
    }
    uVar9 = *(uint *)(param_1 + 0x10);
    if ((((((uVar9 == 0x4b0) || (uVar9 == 0x4b1)) || (uVar9 == 12000)) ||
         ((uVar9 == 0x2ee1 || (uVar9 == 65000)))) || (uVar9 == 0xfde9)) &&
       ((*(byte *)(param_1 + 0x28) & 2) != 0)) {
      *(uint *)(param_1 + 0x10) = uVar9 ^ 1;
    }
    *(undefined4 *)(param_1 + 0x28) = 0;
    *(undefined4 *)(param_1 + 0x48) = 0;
  }
  else if (*param_3 != 0) {
    while( true ) {
      local_2c = *(undefined4 *)(param_1 + 0x28);
      local_44 = 0x10;
      iVar7 = (**(code **)(param_1 + 0x18))
                        ((int *)(param_1 + 0x10),*local_38,*local_3c,&local_24,&local_44);
      iStack_30 = iVar7;
      if (iVar7 == -1) break;
      iVar8 = *(int *)(param_1 + 0x10);
      if ((((iVar8 == 0x4b0) || (iVar8 == 0x4b1)) ||
          ((iVar8 == 12000 || (((iVar8 == 0x2ee1 || (iVar8 == 65000)) || (iVar8 == 0xfde9)))))) &&
         ((*(byte *)(param_1 + 0x28) & 1) == 0)) {
        FUN_004078a0(&local_44,(short *)&local_24,&local_44);
        *(uint *)(param_1 + 0x28) = *(uint *)(param_1 + 0x28) | 1;
      }
      piVar6 = local_28;
      piVar5 = local_34;
      if (local_44 == 0) {
        *local_38 = *local_38 + iVar7;
        *local_3c = *local_3c - iVar7;
      }
      else {
        piVar3 = *(int **)(param_1 + 0x2c);
        uVar10 = (uint)local_24;
        uVar9 = (uint)uStack_22;
        if (piVar3 != (int *)0x0) {
          uVar11 = uVar10;
          if ((ushort)(local_24 + 0x2800) < 0x400) {
            uVar11 = ((uVar10 & 0x3ff) + 0x40) * 0x400 + (uVar9 & 0x3ff);
          }
          iVar8 = 0;
          iVar7 = *piVar3;
          piVar1 = piVar3;
          while (param_1 = local_40, iVar7 != 0) {
            if (((*(byte *)(piVar1 + 2) & 1) != 0) && (piVar1[1] == uVar11)) {
              uVar11 = piVar3[iVar8 * 3];
              if (uVar11 < 0x10000) {
                uVar10 = uVar11 & 0xffff;
                local_24 = (ushort)uVar11;
                local_44 = 1;
              }
              else {
                uVar10 = uVar11 - 0x10000 >> 10 & 0x3ff | 0xd800;
                uStack_22 = (ushort)(uVar11 - 0x10000) & 0x3ff | 0xdc00;
                uVar9 = (uint)uStack_22;
                local_24 = (ushort)uVar10;
                local_44 = 2;
              }
              break;
            }
            iVar8 = iVar8 + 1;
            piVar1 = piVar3 + iVar8 * 3;
            iVar7 = piVar3[iVar8 * 3];
          }
        }
        puVar4 = *(uint **)(param_1 + 0x4c);
        if (puVar4 != (uint *)0x0) {
          if ((ushort)(local_24 + 0x2800) < 0x400) {
            uVar10 = ((uVar10 & 0x3ff) + 0x40) * 0x400 + (uVar9 & 0x3ff);
          }
          iVar7 = 0;
          uVar9 = *puVar4;
          puVar2 = puVar4;
          while (uVar9 != 0) {
            if (((*(byte *)(puVar2 + 2) & 2) != 0) && (*puVar2 == uVar10)) {
              uVar9 = puVar4[iVar7 * 3 + 1];
              if (uVar9 < 0x10000) {
                local_24 = (ushort)uVar9;
                local_44 = 1;
              }
              else {
                local_24 = (ushort)(uVar9 - 0x10000 >> 10) & 0x3ff | 0xd800;
                uStack_22 = (ushort)(uVar9 - 0x10000) & 0x3ff | 0xdc00;
                local_44 = 2;
              }
              break;
            }
            iVar7 = iVar7 + 1;
            puVar2 = puVar4 + iVar7 * 3;
            uVar9 = puVar4[iVar7 * 3];
          }
        }
        iVar7 = (**(code **)(param_1 + 0x3c))(param_1 + 0x30,&local_24,local_44,*local_28,*local_34)
        ;
        if (iVar7 == -1) {
          *(undefined4 *)(param_1 + 0x28) = local_2c;
          break;
        }
        *local_38 = *local_38 + iStack_30;
        *piVar6 = *piVar6 + iVar7;
        *local_3c = *local_3c - iStack_30;
        *piVar5 = *piVar5 - iVar7;
      }
      if (*local_3c == 0) {
        ___security_check_cookie_4(local_4 ^ (uint)&local_44);
        return;
      }
    }
LAB_00407310:
    ___security_check_cookie_4(local_4 ^ (uint)&local_44);
    return;
  }
  ___security_check_cookie_4(local_4 ^ (uint)&local_44);
  return;
}



void __cdecl FUN_004073b0(char *param_1)

{
  char *_Str1;
  char *pcVar1;
  int iVar2;
  UINT UVar3;
  BOOL BVar4;
  UINT *unaff_ESI;
  uint local_1a8;
  int local_1a4;
  _cpinfoexA _Stack_1a0;
  char local_84 [127];
  undefined uStack_5;
  uint local_4;
  
  local_4 = DAT_00428400 ^ (uint)&local_1a8;
  local_1a4 = 1;
  local_1a8 = 0;
  strncpy(local_84,param_1,0x80);
  uStack_5 = 0;
  pcVar1 = FUN_00407910();
  while (pcVar1 != (char *)0x0) {
    _Str1 = pcVar1 + 2;
    iVar2 = _stricmp(_Str1,"nocompat");
    if (iVar2 == 0) {
      local_1a4 = 0;
    }
    else {
      iVar2 = _stricmp(_Str1,"translit");
      if (iVar2 == 0) {
        local_1a8 = local_1a8 | 2;
      }
      else {
        iVar2 = _stricmp(_Str1,"ignore");
        if (iVar2 == 0) {
          local_1a8 = local_1a8 | 4;
        }
      }
    }
    *pcVar1 = '\0';
    pcVar1 = FUN_00407910();
  }
  unaff_ESI[6] = 0;
  unaff_ESI[1] = local_1a8;
  unaff_ESI[4] = 0;
  unaff_ESI[5] = 0;
  unaff_ESI[7] = 0;
  UVar3 = FUN_004076a0();
  *unaff_ESI = UVar3;
  if ((UVar3 == 0x4b0) || (UVar3 == 0x4b1)) {
    unaff_ESI[2] = (UINT)FUN_00407df0;
    unaff_ESI[3] = (UINT)FUN_00407ee0;
    iVar2 = _stricmp(local_84,"UTF-16");
    if ((iVar2 != 0) && (iVar2 = _stricmp(local_84,"UTF16"), iVar2 != 0)) {
      pcVar1 = "UCS-2";
LAB_00407612:
      iVar2 = _stricmp(local_84,pcVar1);
      if (iVar2 != 0) goto LAB_00407627;
    }
LAB_00407623:
    unaff_ESI[1] = unaff_ESI[1] | 1;
  }
  else {
    if ((UVar3 == 12000) || (UVar3 == 0x2ee1)) {
      unaff_ESI[2] = (UINT)&LAB_00407fa0;
      unaff_ESI[3] = (UINT)&LAB_00408050;
      iVar2 = _stricmp(local_84,"UTF-32");
      if (iVar2 != 0) {
        pcVar1 = "UTF32";
        goto LAB_00407612;
      }
      goto LAB_00407623;
    }
    if (UVar3 == 0xfde9) {
      unaff_ESI[2] = (UINT)&LAB_00407b80;
      unaff_ESI[3] = (UINT)&LAB_00407be0;
      unaff_ESI[4] = (UINT)&LAB_00407a60;
    }
    else if ((((UVar3 == 0xc42c) || (UVar3 == 0xc42d)) || (UVar3 == 0xc42e)) &&
            (iVar2 = FUN_00406ed0(), iVar2 != 0)) {
      unaff_ESI[2] = (UINT)FUN_00408100;
      unaff_ESI[3] = (UINT)FUN_004083a0;
      unaff_ESI[5] = (UINT)&LAB_00408600;
    }
    else if ((*unaff_ESI == 0xcadc) && (iVar2 = FUN_00406ed0(), iVar2 != 0)) {
      unaff_ESI[2] = (UINT)&LAB_00407ca0;
      unaff_ESI[3] = (UINT)FUN_00407d10;
      unaff_ESI[4] = (UINT)&LAB_00407af0;
    }
    else {
      BVar4 = IsValidCodePage(*unaff_ESI);
      if ((BVar4 == 0) || (BVar4 = GetCPInfoExA(*unaff_ESI,0,&_Stack_1a0), BVar4 == 0)) {
        *unaff_ESI = 0xffffffff;
      }
      else {
        unaff_ESI[2] = (UINT)&LAB_00407b80;
        unaff_ESI[3] = (UINT)&LAB_00407be0;
        if (_Stack_1a0.MaxCharSize == 1) {
          unaff_ESI[4] = (UINT)&LAB_00407980;
        }
        else if (_Stack_1a0.MaxCharSize == 2) {
          unaff_ESI[4] = (UINT)&LAB_00407990;
        }
        else {
          unaff_ESI[4] = (UINT)&LAB_004079d0;
        }
      }
    }
  }
LAB_00407627:
  if (local_1a4 != 0) {
    UVar3 = *unaff_ESI;
    if ((int)UVar3 < 0xc42f) {
      if (((int)UVar3 < 0xc42c) && (UVar3 != 0x3a4)) {
        if (UVar3 == 0x51c4) {
          unaff_ESI[7] = (UINT)&DAT_00428ef8;
          ___security_check_cookie_4(local_4 ^ (uint)&local_1a8);
          return;
        }
        goto LAB_0040767c;
      }
    }
    else if (UVar3 != 0xcadc) goto LAB_0040767c;
    unaff_ESI[7] = (UINT)&DAT_00428e80;
  }
LAB_0040767c:
  ___security_check_cookie_4(local_4 ^ (uint)&local_1a8);
  return;
}



int FUN_004076a0(void)

{
  char *in_EAX;
  undefined **ppuVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  char *pcVar5;
  bool bVar6;
  
  if (*in_EAX == '\0') {
LAB_0040776a:
                    // WARNING: Could not recover jumptable at 0x0040776d. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar3 = GetACP();
    return iVar3;
  }
  iVar3 = 5;
  bVar6 = true;
  pcVar4 = in_EAX;
  pcVar5 = "char";
  do {
    if (iVar3 == 0) break;
    iVar3 = iVar3 + -1;
    bVar6 = *pcVar4 == *pcVar5;
    pcVar4 = pcVar4 + 1;
    pcVar5 = pcVar5 + 1;
  } while (bVar6);
  if (bVar6) goto LAB_0040776a;
  iVar3 = 8;
  bVar6 = true;
  pcVar4 = in_EAX;
  pcVar5 = "wchar_t";
  do {
    if (iVar3 == 0) break;
    iVar3 = iVar3 + -1;
    bVar6 = *pcVar4 == *pcVar5;
    pcVar4 = pcVar4 + 1;
    pcVar5 = pcVar5 + 1;
  } while (bVar6);
  if (bVar6) {
    return 0x4b0;
  }
  iVar3 = _strnicmp(in_EAX,"cp",2);
  if (iVar3 != 0) {
    if (('/' < *in_EAX) && (*in_EAX < ':')) goto LAB_004076f9;
    iVar3 = _strnicmp(in_EAX,"xx",2);
    if (iVar3 != 0) {
      iVar3 = 0;
      if (PTR_s_CP65001_00428484 != (undefined *)0x0) {
        ppuVar1 = &PTR_s_CP65001_00428484;
        do {
          iVar2 = _stricmp(in_EAX,*ppuVar1);
          if (iVar2 == 0) {
            return (&DAT_00428480)[iVar3 * 2];
          }
          iVar3 = iVar3 + 1;
          ppuVar1 = &PTR_s_CP65001_00428484 + iVar3 * 2;
        } while ((&PTR_s_CP65001_00428484)[iVar3 * 2] != (undefined *)0x0);
      }
      return -1;
    }
  }
  in_EAX = in_EAX + 2;
LAB_004076f9:
  iVar3 = atoi(in_EAX);
  return iVar3;
}



void __fastcall FUN_00407780(ushort *param_1,undefined4 *param_2)

{
  uint in_EAX;
  
  if (in_EAX < 0x10000) {
    *param_1 = (ushort)in_EAX;
    *param_2 = 1;
    return;
  }
  *param_1 = (ushort)(in_EAX - 0x10000 >> 10) & 0x3ff | 0xd800;
  param_1[1] = (ushort)(in_EAX - 0x10000) & 0x3ff | 0xdc00;
  *param_2 = 2;
  return;
}



undefined4 FUN_004077d0(void)

{
  int in_EAX;
  
  if (((((((in_EAX != 0xc42c) && (in_EAX != 0xc42d)) && (in_EAX != 0xc42e)) &&
        ((in_EAX != 0xc431 && (in_EAX != 0xc433)))) &&
       ((in_EAX != 0xc435 && ((in_EAX != 0xcec8 && (in_EAX != 0xd698)))))) &&
      ((in_EAX < 0xdeaa || (0xdeb3 < in_EAX)))) && ((in_EAX != 65000 && (in_EAX != 0x2a)))) {
    return 8;
  }
  return 0;
}



undefined4 FUN_00407830(void)

{
  int in_EAX;
  
  if (((((in_EAX != 65000) && (in_EAX != 0xfde9)) && (in_EAX != 0xc42c)) &&
      ((((in_EAX != 0xc42d && (in_EAX != 0xc42e)) &&
        ((in_EAX != 0xc431 && ((in_EAX != 0xc433 && (in_EAX != 0xc435)))))) && (in_EAX != 0xcec8))))
     && ((in_EAX != 0xd698 && (((in_EAX < 0xdeaa || (0xdeb3 < in_EAX)) && (in_EAX != 0x2a)))))) {
    return 0;
  }
  return 1;
}



void __fastcall FUN_004078a0(undefined4 param_1,short *param_2,undefined4 *param_3)

{
  int iVar1;
  int in_EAX;
  
  if ((*param_2 == -2) && ((*(byte *)(in_EAX + 0x14) & 1) != 0)) {
    *(uint *)(in_EAX + 0x10) = *(uint *)(in_EAX + 0x10) ^ 1;
    *(uint *)(in_EAX + 0x28) = *(uint *)(in_EAX + 0x28) | 2;
    *param_2 = -0x101;
  }
  else if (*param_2 != -0x101) {
    return;
  }
  iVar1 = *(int *)(in_EAX + 0x30);
  if (((((iVar1 != 0x4b0) && (iVar1 != 0x4b1)) && (iVar1 != 12000)) &&
      (((iVar1 != 0x2ee1 && (iVar1 != 65000)) && (iVar1 != 0xfde9)))) || (iVar1 == 0xfde9)) {
    *param_3 = 0;
  }
  return;
}



char * FUN_00407910(void)

{
  char *pcVar1;
  char *pcVar2;
  char *_Str1;
  int iVar3;
  char *unaff_EDI;
  
  pcVar1 = "//";
  do {
    pcVar2 = pcVar1;
    pcVar1 = pcVar2 + 1;
  } while (*pcVar2 != '\0');
  pcVar1 = unaff_EDI;
  do {
    _Str1 = pcVar1;
    pcVar1 = _Str1 + 1;
  } while (*_Str1 != '\0');
  do {
    _Str1 = _Str1 + -1;
    if (_Str1 < unaff_EDI) {
      return (char *)0x0;
    }
  } while ((*_Str1 != '/') || (iVar3 = strncmp(_Str1,"//",(size_t)(pcVar2 + -0x424768)), iVar3 != 0)
          );
  return _Str1;
}



void __cdecl FUN_00407d10(undefined4 *param_1,undefined4 param_2,int param_3,void *param_4)

{
  int iVar1;
  void *_Dst;
  int iVar2;
  int *piVar3;
  uint unaff_EBX;
  int *piStack_30;
  undefined *puStack_2c;
  undefined4 *puStack_28;
  undefined4 local_18;
  undefined local_14 [8];
  int iStack_c;
  uint local_4;
  
  _Dst = param_4;
  iVar1 = param_3;
  local_4 = DAT_00428400 ^ (uint)&local_18;
  puStack_28 = &local_18;
  puStack_2c = local_14;
  piStack_30 = &param_3;
  local_18 = 0x10;
  iVar2 = (*DAT_0042b54c)(param_1 + 6,*param_1,param_2);
  if ((iVar2 == 0) && (iVar1 == iStack_c)) {
    if ((int)local_4 < (int)piStack_30) {
      piVar3 = _errno();
      *piVar3 = 7;
      ___security_check_cookie_4(unaff_EBX ^ (uint)&piStack_30);
      return;
    }
    piVar3 = (int *)(*(code *)param_1[4])(param_1,&puStack_2c,piStack_30);
    if (piVar3 == piStack_30) {
      memcpy(_Dst,&puStack_2c,(size_t)piStack_30);
      ___security_check_cookie_4(unaff_EBX ^ (uint)&piStack_30);
      return;
    }
  }
  piVar3 = _errno();
  *piVar3 = 0x2a;
  ___security_check_cookie_4(unaff_EBX ^ (uint)&piStack_30);
  return;
}



undefined4 __cdecl
FUN_00407df0(int *param_1,ushort *param_2,int param_3,ushort *param_4,undefined4 *param_5)

{
  ushort uVar1;
  int *piVar2;
  
  if (param_3 < 2) {
    piVar2 = _errno();
    *piVar2 = 0x16;
    return 0xffffffff;
  }
  if (*param_1 == 0x4b0) {
    uVar1 = *param_2;
LAB_00407e38:
    *param_4 = uVar1;
  }
  else if (*param_1 == 0x4b1) {
    uVar1 = CONCAT11(*(undefined *)param_2,*(undefined *)((int)param_2 + 1));
    goto LAB_00407e38;
  }
  uVar1 = *param_4;
  if ((0xdbff < uVar1) && (uVar1 < 0xe000)) goto LAB_00407eb5;
  if ((uVar1 < 0xd800) || (0xdbff < uVar1)) {
    *param_5 = 1;
    return 2;
  }
  if (param_3 < 4) {
    piVar2 = _errno();
    *piVar2 = 0x16;
    return 0xffffffff;
  }
  if (*param_1 == 0x4b0) {
    uVar1 = param_2[1];
LAB_00407e8f:
    param_4[1] = uVar1;
  }
  else if (*param_1 == 0x4b1) {
    uVar1 = CONCAT11(*(undefined *)(param_2 + 1),*(undefined *)((int)param_2 + 3));
    goto LAB_00407e8f;
  }
  if ((0xdbff < param_4[1]) && (param_4[1] < 0xe000)) {
    *param_5 = 2;
    return 4;
  }
LAB_00407eb5:
  piVar2 = _errno();
  *piVar2 = 0x2a;
  return 0xffffffff;
}



undefined4 __cdecl
FUN_00407ee0(int *param_1,ushort *param_2,undefined4 param_3,undefined *param_4,int param_5)

{
  undefined uVar1;
  int *piVar2;
  
  if (param_5 < 2) {
    piVar2 = _errno();
    *piVar2 = 7;
    return 0xffffffff;
  }
  if (*param_1 == 0x4b0) {
    *param_4 = *(undefined *)param_2;
    uVar1 = *(undefined *)((int)param_2 + 1);
  }
  else {
    if (*param_1 != 0x4b1) goto LAB_00407f2f;
    *param_4 = *(undefined *)((int)param_2 + 1);
    uVar1 = *(undefined *)param_2;
  }
  param_4[1] = uVar1;
LAB_00407f2f:
  if ((*param_2 < 0xd800) || (0xdbff < *param_2)) {
    return 2;
  }
  if (param_5 < 4) {
    piVar2 = _errno();
    *piVar2 = 7;
    return 0xffffffff;
  }
  if (*param_1 == 0x4b0) {
    param_4[2] = *(undefined *)(param_2 + 1);
    param_4[3] = *(undefined *)((int)param_2 + 3);
    return 4;
  }
  if (*param_1 == 0x4b1) {
    param_4[2] = *(undefined *)((int)param_2 + 3);
    param_4[3] = *(undefined *)(param_2 + 1);
  }
  return 4;
}



void __cdecl
FUN_00408100(int *param_1,byte *param_2,size_t param_3,ushort *param_4,undefined4 *param_5)

{
  byte bVar1;
  size_t _Size;
  size_t sVar2;
  undefined **ppuVar3;
  int iVar4;
  int *piVar5;
  uint uVar6;
  size_t _Size_00;
  int iVar7;
  uint local_30;
  int *local_2c;
  uint local_28;
  undefined4 *local_24;
  ushort *local_20;
  int local_1c;
  undefined4 local_18;
  undefined local_14 [16];
  uint local_4;
  
  local_4 = DAT_00428400 ^ (uint)&local_30;
  local_20 = param_4;
  bVar1 = *param_2;
  local_2c = param_1;
  local_24 = param_5;
  local_18 = 0;
  if (bVar1 == 0x1b) {
    iVar7 = 0;
    if (PTR_DAT_00428f78 != (undefined *)0x0) {
      ppuVar3 = &PTR_DAT_00428f78;
      do {
        if ((int)param_3 < (int)ppuVar3[1]) {
          iVar4 = strncmp((char *)param_2,*ppuVar3,param_3);
          if (iVar4 == 0) goto LAB_0040816d;
        }
        else {
          iVar4 = strncmp((char *)param_2,*ppuVar3,(size_t)ppuVar3[1]);
          if (iVar4 == 0) {
            local_2c[6] = (&DAT_00428f84)[iVar7 * 4] << 8;
            *local_24 = 0;
            ___security_check_cookie_4(local_4 ^ (uint)&local_30);
            return;
          }
        }
        iVar7 = iVar7 + 1;
        ppuVar3 = &PTR_DAT_00428f78 + iVar7 * 4;
      } while ((&PTR_DAT_00428f78)[iVar7 * 4] != (undefined *)0x0);
    }
  }
  else {
    if (bVar1 == 0xe) {
      param_1[6] = (uint)*(byte *)((int)param_1 + 0x19) << 8 | 1;
      *param_5 = 0;
      ___security_check_cookie_4(local_4 ^ (uint)&local_30);
      return;
    }
    if (bVar1 == 0xf) {
      param_1[6] = (uint)*(byte *)((int)param_1 + 0x19) << 8;
      *param_5 = 0;
      ___security_check_cookie_4(local_4 ^ (uint)&local_30);
      return;
    }
    local_28 = (uint)*(byte *)((int)param_1 + 0x19);
    local_30 = param_1[6] & 0xff;
    if (bVar1 < 0x20) {
      local_28 = 0;
      local_30 = 0;
    }
    uVar6 = local_30;
    _Size = (&DAT_00428f80)[local_28 * 4];
    if ((int)param_3 < (int)_Size) {
LAB_0040816d:
      piVar5 = _errno();
      *piVar5 = 0x16;
      goto LAB_004081ac;
    }
    iVar7 = 0;
    if (0 < (int)_Size) {
      do {
        if (0x7f < param_2[iVar7]) goto LAB_004081a0;
        iVar7 = iVar7 + 1;
      } while (iVar7 < (int)_Size);
    }
    _Size_00 = (&DAT_00428f7c)[local_28 * 4];
    memcpy(local_14,(&PTR_DAT_00428f78)[local_28 * 4],_Size_00);
    if (uVar6 == 1) {
      local_14[_Size_00] = 0xe;
      _Size_00 = _Size_00 + 1;
    }
    memcpy(local_14 + _Size_00,param_2,_Size);
    sVar2 = DAT_00428f9c;
    iVar7 = *local_2c;
    if ((((iVar7 == 0xc42c) || (iVar7 == 0xc42d)) || (iVar7 == 0xc42e)) && (local_30 == 1)) {
      memcpy(local_14,PTR_DAT_00428f98,DAT_00428f9c);
      memcpy(local_14 + sVar2,param_2,_Size);
      _Size_00 = sVar2;
    }
    local_1c = _Size_00 + _Size;
    iVar7 = (*DAT_0042b558)(&local_18,iVar7,local_14,&local_1c,local_20,local_24);
    if (((iVar7 == 0) && (local_1c == _Size_00 + _Size)) &&
       ((*local_20 != (ushort)*param_2 || (local_2c[6] == 0)))) {
      uVar6 = local_28 << 8 | local_30;
      if (local_2c[6] != uVar6) {
        local_2c[6] = uVar6;
      }
      ___security_check_cookie_4(local_4 ^ (uint)&local_30);
      return;
    }
  }
LAB_004081a0:
  piVar5 = _errno();
  *piVar5 = 0x2a;
LAB_004081ac:
  ___security_check_cookie_4(local_4 ^ (uint)&local_30);
  return;
}



void __cdecl FUN_004083a0(undefined4 *param_1,ushort *param_2,int param_3,uint param_4)

{
  char *pcVar1;
  size_t _Size;
  undefined *_Size_00;
  int iVar2;
  int *piVar3;
  undefined **ppuVar4;
  uint uVar5;
  ushort *unaff_EBP;
  char *unaff_ESI;
  char *_MaxCount;
  int iVar6;
  int *piStack_40;
  undefined *puStack_3c;
  undefined4 *puStack_38;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 *local_20;
  uint local_1c;
  ushort *local_18;
  undefined local_14 [8];
  int iStack_c;
  uint local_4;
  
  iVar6 = param_3;
  local_4 = DAT_00428400 ^ (uint)&local_28;
  puStack_38 = &local_24;
  puStack_3c = local_14;
  local_1c = param_4;
  piStack_40 = &param_3;
  local_20 = param_1;
  local_18 = param_2;
  local_24 = 0x10;
  local_28 = 0;
  iVar2 = (*DAT_0042b54c)(&local_28,*param_1,param_2);
  if ((iVar2 != 0) || (iVar6 != iStack_c)) {
    piVar3 = _errno();
    *piVar3 = 0x2a;
    ___security_check_cookie_4(local_1c ^ (uint)&piStack_40);
    return;
  }
  if ((int)local_4 < (int)puStack_3c) {
    piVar3 = _errno();
    *piVar3 = 7;
    ___security_check_cookie_4(local_1c ^ (uint)&piStack_40);
    return;
  }
  if (puStack_3c == (undefined *)0x1) {
    piVar3 = (int *)0x0;
    _MaxCount = (char *)0x0;
LAB_004084b7:
    _Size_00 = DAT_00428f7c;
    pcVar1 = &stack0xffffffd4 + (int)_MaxCount;
    if (*pcVar1 == '\x0e') {
      _MaxCount = _MaxCount + 1;
    }
    _Size = (&DAT_00428f80)[(int)piVar3 * 4];
    if (((piVar3 != (int *)0x0) || (*param_2 < 0x80)) &&
       ((int)(_MaxCount + _Size) <= (int)puStack_3c)) {
      uVar5 = (int)piVar3 << 8 | (uint)(*pcVar1 == '\x0e');
      if (param_1[6] == uVar5) {
        if (_MaxCount != (char *)0x0) {
          memmove(&stack0xffffffd4,&stack0xffffffd4 + (int)_MaxCount,_Size);
        }
        _MaxCount = (char *)0x0;
      }
      else {
        if (piVar3 == (int *)0x0) {
          memmove(&stack0xffffffd4 + (int)DAT_00428f7c,&stack0xffffffd4,_Size);
          memcpy(&stack0xffffffd4,PTR_DAT_00428f78,(size_t)_Size_00);
          _MaxCount = _Size_00;
        }
        param_1 = puStack_38;
        if (*(char *)(puStack_38 + 6) == '\x01') {
          memmove(&stack0xffffffd5,&stack0xffffffd4,(size_t)(_MaxCount + _Size));
          _MaxCount = _MaxCount + 1;
          param_1 = puStack_38;
        }
      }
      if ((int)(_MaxCount + _Size) <= (int)local_4) {
        memcpy(unaff_ESI,&stack0xffffffd4,(size_t)(_MaxCount + _Size));
        param_1[6] = uVar5;
        ___security_check_cookie_4(local_1c ^ (uint)&piStack_40);
        return;
      }
      piVar3 = _errno();
      *piVar3 = 7;
      goto LAB_004084f0;
    }
  }
  else {
    iVar6 = 1;
    piVar3 = piStack_40;
    _MaxCount = unaff_ESI;
    if (PTR_DAT_00428f88 != (undefined *)0x0) {
      ppuVar4 = &PTR_DAT_00428f88;
      iVar6 = 1;
      do {
        _MaxCount = ppuVar4[1];
        iVar2 = strncmp(&stack0xffffffd4,*ppuVar4,(size_t)_MaxCount);
        if (iVar2 == 0) {
          piVar3 = (int *)(&DAT_00428f84)[iVar6 * 4];
          break;
        }
        iVar6 = iVar6 + 1;
        ppuVar4 = &PTR_DAT_00428f78 + iVar6 * 4;
        piVar3 = piStack_40;
      } while ((&PTR_DAT_00428f78)[iVar6 * 4] != (undefined *)0x0);
    }
    param_2 = unaff_EBP;
    if ((&PTR_DAT_00428f78)[iVar6 * 4] != (undefined *)0x0) goto LAB_004084b7;
  }
  piVar3 = _errno();
  *piVar3 = 0x2a;
LAB_004084f0:
  ___security_check_cookie_4(local_1c ^ (uint)&piStack_40);
  return;
}



void FUN_00408680(void)

{
  void **this;
  uint uVar1;
  undefined4 *unaff_EDI;
  
  *unaff_EDI = aIpAddr::vftable;
  this = (void **)(unaff_EDI + 1);
  *this = (void *)0x0;
  unaff_EDI[3] = 0;
  unaff_EDI[2] = 0;
  if (DAT_0042b564 != (void *)0x0) {
    FUN_00401910(this,DAT_0042b568);
    memcpy(*this,DAT_0042b564,DAT_0042b568);
    uVar1 = DAT_0042b568;
    unaff_EDI[2] = DAT_0042b568;
    *(undefined *)(uVar1 + (int)*this) = 0;
  }
  unaff_EDI[4] = 0;
  return;
}



void __fastcall FUN_004086e0(undefined4 *param_1)

{
  *param_1 = aIpAddr::vftable;
  if ((void *)param_1[1] != (void *)0x0) {
    free((void *)param_1[1]);
  }
  return;
}



undefined4 __fastcall FUN_00408700(int param_1)

{
  void *pvVar1;
  undefined4 *in_EAX;
  void **ppvVar2;
  void **this;
  void *local_c [3];
  
  *(undefined4 *)(param_1 + 0x10) = *in_EAX;
  ppvVar2 = (void **)FUN_004018e0(local_c,"%d.%d.%d.%d");
  this = (void **)(param_1 + 4);
  if (*ppvVar2 != *this) {
    FUN_00401910(this,(uint)ppvVar2[1]);
    memcpy(*this,*ppvVar2,(size_t)ppvVar2[1]);
    pvVar1 = ppvVar2[1];
    *(void **)(param_1 + 8) = pvVar1;
    *(undefined *)((int)pvVar1 + (int)*this) = 0;
  }
  if (local_c[0] != (void *)0x0) {
    free(local_c[0]);
  }
  return CONCAT31((int3)((uint)local_c[0] >> 8),1);
}



undefined4 * __thiscall FUN_00408780(void *this,byte param_1)

{
  *(undefined ***)this = aCommChannel::vftable;
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined __fastcall FUN_004087a0(int param_1)

{
  return *(undefined *)(param_1 + 0x78);
}



void __thiscall FUN_004087b0(void *this,undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)((int)this + 0x10);
  for (iVar1 = 10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *param_1 = *puVar2;
    puVar2 = puVar2 + 1;
    param_1 = param_1 + 1;
  }
  return;
}



undefined4 __fastcall FUN_004087d0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x60);
}



int __fastcall FUN_004087e0(int param_1)

{
  return param_1 + 0x180;
}



int __fastcall FUN_004087f0(int param_1)

{
  return param_1 + 0x18c;
}



undefined4 __fastcall FUN_00408800(int param_1)

{
  return *(undefined4 *)(param_1 + 8);
}



undefined4 __fastcall FUN_00408810(int param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}



int __fastcall FUN_00408820(int param_1)

{
  return param_1 + 0x1c4;
}



void __fastcall FUN_00408830(int param_1)

{
  *(undefined *)(param_1 + 0x78) = 0;
  FUN_00402850("CarData %d, Invalidated.",(char)*(undefined4 *)(param_1 + 0x60));
  return;
}



void ** __thiscall
FUN_00408850(void *this,void **param_1,undefined4 param_2,undefined4 param_3,int param_4,
            char param_5)

{
  void *pvVar1;
  void **ppvVar2;
  char *pcVar3;
  void *local_30 [3];
  void *local_24 [3];
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041ae41;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 1;
  FUN_004010a0(local_30);
  local_4 = CONCAT31(local_4._1_3_,2);
  FUN_004010a0(param_1);
  if (param_4 == 0) {
    pcVar3 = "Vehicle";
  }
  else {
    if (param_4 != 1) goto LAB_004088cc;
    pcVar3 = "Driver";
  }
  FUN_00401040(local_30,pcVar3);
LAB_004088cc:
  FUN_004011f0((undefined4 *)&stack0x00000018);
  FUN_004011f0(local_30);
  FUN_004011f0((undefined4 *)((int)this + 0x120));
  ppvVar2 = (void **)FUN_004018e0(local_24,"%s_%d_%s_Rec%d_%d.%s");
  local_4._0_1_ = 3;
  if (*ppvVar2 != *param_1) {
    FUN_00401910(param_1,(uint)ppvVar2[1]);
    memcpy(*param_1,*ppvVar2,(size_t)ppvVar2[1]);
    pvVar1 = ppvVar2[1];
    param_1[1] = pvVar1;
    *(undefined *)((int)pvVar1 + (int)*param_1) = 0;
  }
  local_4._0_1_ = 2;
  FUN_00401170(local_24);
  if (param_5 != '\0') {
    ppvVar2 = (void **)FUN_00401300(param_1,local_18,*(int *)((int)this + 0x130) + 1,
                                    (char *)((int)param_1[1] + (-1 - *(int *)((int)this + 0x130))));
    local_4._0_1_ = 4;
    ppvVar2 = (void **)FUN_00401ab0((int *)local_24,"\\",ppvVar2);
    local_4._0_1_ = 5;
    if (*ppvVar2 != *param_1) {
      FUN_00401910(param_1,(uint)ppvVar2[1]);
      memcpy(*param_1,*ppvVar2,(size_t)ppvVar2[1]);
      pvVar1 = ppvVar2[1];
      param_1[1] = pvVar1;
      *(undefined *)((int)pvVar1 + (int)*param_1) = 0;
    }
    local_4._0_1_ = 4;
    FUN_00401170(local_24);
    local_4._0_1_ = 2;
    FUN_00401170(local_18);
  }
  local_4._0_1_ = 1;
  FUN_00401170(local_30);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170((void **)&stack0x00000018);
  ExceptionList = local_c;
  return param_1;
}



void __thiscall FUN_00408a20(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)((int)this + 0x11c) = param_1;
  FUN_00402850("CarData EventId:%d  StartTimeoutTimer timeout:%d",
               (char)*(undefined4 *)((int)this + 0x60));
  FUN_00402af0((void *)((int)this + 0x7c),param_2,0);
  return;
}



void * __thiscall FUN_00408a60(void *this,void *param_1)

{
                    // WARNING: Load size is inaccurate
  FUN_004010b0(param_1,(void **)(*this + 8));
  return param_1;
}



undefined4 __fastcall FUN_00408a90(int param_1)

{
  return *(undefined4 *)(param_1 + 0x1b8);
}



void __thiscall FUN_00408aa0(void *this,undefined4 param_1)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  uVar1 = *(undefined4 *)((int)this + 8);
  puVar2 = (undefined4 *)operator_new(0xc);
  puVar2[1] = uVar1;
  *puVar2 = 0;
  puVar2[2] = param_1;
  if (*(undefined4 **)((int)this + 8) != (undefined4 *)0x0) {
    **(undefined4 **)((int)this + 8) = puVar2;
                    // WARNING: Load size is inaccurate
    *(int *)this = *this + 1;
    *(undefined4 **)((int)this + 8) = puVar2;
    return;
  }
                    // WARNING: Load size is inaccurate
  *(int *)this = *this + 1;
  *(undefined4 **)((int)this + 4) = puVar2;
  *(undefined4 **)((int)this + 8) = puVar2;
  return;
}



void __thiscall FUN_00408af0(void *this,undefined4 *param_1)

{
  *param_1 = *(undefined4 *)((int)this + 4);
  return;
}



void FUN_00408b00(undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041ae6b;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  puVar1 = (undefined4 *)operator_new(0xc);
  local_4 = 0;
  puVar2 = (undefined4 *)0x0;
  if (puVar1 != (undefined4 *)0x0) {
    FUN_004118b0(puVar1 + 2);
    puVar2 = puVar1;
  }
  puVar2[1] = param_1;
  *puVar2 = param_2;
  ExceptionList = local_c;
  return;
}



undefined4 * __thiscall
FUN_00408b70(void *this,undefined param_1,undefined param_2,undefined param_3,uint *param_4)

{
  undefined4 *puVar1;
  uint uVar2;
  byte *pbVar3;
  int iVar4;
  char *in_stack_ffffffdc;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041ae98;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004010b0(&stack0xffffffdc,(void **)&param_1);
  uVar2 = FUN_00406940(in_stack_ffffffdc);
  uVar2 = uVar2 % *(uint *)((int)this + 4);
  *param_4 = uVar2;
                    // WARNING: Load size is inaccurate
  if (*this != 0) {
    for (puVar1 = *(undefined4 **)(*this + uVar2 * 4); puVar1 != (undefined4 *)0x0;
        puVar1 = (undefined4 *)*puVar1) {
      pbVar3 = FUN_004011f0((undefined4 *)&param_1);
      iVar4 = FUN_00401290(puVar1 + 2,pbVar3);
      if (iVar4 == 0) {
        local_4 = 0xffffffff;
        FUN_00401170((void **)&param_1);
        ExceptionList = local_c;
        return puVar1;
      }
    }
  }
  local_4 = 0xffffffff;
  FUN_00401170((void **)&param_1);
  ExceptionList = local_c;
  return (undefined4 *)0x0;
}



void __thiscall FUN_00408c40(void *this,undefined4 *param_1,int param_2)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)((int)this + 4);
  while( true ) {
    if (puVar1 == (undefined4 *)0x0) {
      *param_1 = 0;
      return;
    }
    if (puVar1[2] == param_2) break;
    puVar1 = (undefined4 *)*puVar1;
  }
  *param_1 = puVar1;
  return;
}



undefined4 __fastcall FUN_00408c80(int param_1)

{
  if ((*(int *)(param_1 + 0x1b0) <= *(int *)(param_1 + 0x1b8)) && (*(int *)(param_1 + 0x170) == 0))
  {
    return 1;
  }
  return 0;
}



void __thiscall FUN_00408ca0(void *this,int param_1)

{
  int iVar1;
  void *this_00;
  
  iVar1 = FUN_0040aaf0(param_1);
  if (iVar1 == 0) {
    this_00 = (void *)((int)this + 0x180);
  }
  else {
    if (iVar1 != 1) {
      FUN_0040aaf0(param_1);
      FUN_00402890("CarData AddImage (ev:%d), unexpected image type %d",
                   (char)*(undefined4 *)((int)this + 0x60));
      goto LAB_00408ce8;
    }
    this_00 = (void *)((int)this + 0x18c);
  }
  FUN_00408aa0(this_00,param_1);
LAB_00408ce8:
  FUN_00402870("CarData AddImage (ev:%d) Vehicles:%d Drivers:%d",
               (char)*(undefined4 *)((int)this + 0x60));
  return;
}



void __fastcall FUN_00408d10(int param_1)

{
  int local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041aec8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_10 = param_1;
  FUN_00402f40(&local_10,param_1 + 0x13c);
  local_4 = 0;
  FUN_00402870("CarData EventId:%d  Timeout (IsComplete:%d)",(char)*(undefined4 *)(param_1 + 0x60));
  *(undefined *)(param_1 + 0x138) = 1;
  if ((*(int *)(param_1 + 0x1b8) < *(int *)(param_1 + 0x1b0)) || (*(int *)(param_1 + 0x170) != 0)) {
    FUN_0040cee0(*(void **)(param_1 + 0x11c),*(undefined4 *)(param_1 + 0x60),
                 *(undefined4 *)(param_1 + 0x160));
  }
  local_4 = 0xffffffff;
  FUN_00402f90(&local_10);
  ExceptionList = local_c;
  return;
}



undefined4 __fastcall FUN_00408de0(int param_1)

{
  int *piVar1;
  undefined4 uVar2;
  int local_14;
  undefined4 local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041aef8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_004118b0(&local_14);
  local_4 = 0;
  piVar1 = (int *)FUN_00408af0((void *)(param_1 + 0x1b8),&local_10);
  if (*piVar1 != 0) {
    FUN_00411750(&local_14,(int *)(*piVar1 + 8));
    uVar2 = FUN_00411790(&local_14);
    local_4 = 0xffffffff;
    FUN_00411740(&local_14);
    ExceptionList = local_c;
    return uVar2;
  }
  local_4 = 0xffffffff;
  FUN_00411740(&local_14);
  ExceptionList = local_c;
  return 0xffffffff;
}



uint __fastcall FUN_00408e90(int param_1,undefined param_2,undefined param_3)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  int local_1c;
  undefined4 local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041af30;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004118b0(&local_1c);
  local_4 = CONCAT31(local_4._1_3_,1);
  puVar1 = (undefined4 *)FUN_00408af0((void *)(param_1 + 0x1b8),local_18);
  puVar1 = (undefined4 *)*puVar1;
  while( true ) {
    if (puVar1 == (undefined4 *)0x0) {
      local_4 = local_4 & 0xffffff00;
      FUN_00411740(&local_1c);
      local_4 = 0xffffffff;
      uVar5 = FUN_00411740((int *)&param_3);
      ExceptionList = local_c;
      return uVar5 & 0xffffff00;
    }
    FUN_00411750(&local_1c,puVar1 + 2);
    puVar2 = FUN_004117d0(&local_1c);
    iVar3 = FUN_004116d0(puVar2);
    puVar2 = FUN_004117d0((undefined4 *)&param_3);
    iVar4 = FUN_004116d0(puVar2);
    if (iVar3 == iVar4) break;
    puVar1 = (undefined4 *)*puVar1;
  }
  local_4 = local_4 & 0xffffff00;
  FUN_00411740(&local_1c);
  local_4 = 0xffffffff;
  uVar6 = FUN_00411740((int *)&param_3);
  ExceptionList = local_c;
  return CONCAT31((int3)((uint)uVar6 >> 8),1);
}



void __thiscall FUN_00408f90(void *this,int *param_1)

{
  bool bVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  void *this_00;
  undefined4 *puVar5;
  undefined4 uVar6;
  float10 fVar7;
  undefined *puVar8;
  undefined auStack_134 [44];
  int local_108;
  float local_104;
  undefined local_100 [4];
  undefined4 local_fc;
  undefined4 local_f8 [2];
  int *local_f0;
  double local_e8;
  void *local_dc [3];
  undefined4 local_d0;
  undefined local_cc;
  undefined local_c8 [68];
  uint local_84;
  void *local_4c;
  undefined *puStack_48;
  undefined4 local_44;
  
  puStack_48 = &LAB_0041af88;
  local_4c = ExceptionList;
  local_84 = DAT_00428400 ^ (uint)auStack_134;
  ExceptionList = &local_4c;
  local_44 = 0;
  local_f0 = param_1;
  local_fc = 0;
  FUN_004118b0(&local_108);
  local_44 = 1;
  FUN_004118b0(param_1);
  local_fc = 1;
  FUN_004010a0(local_dc);
  local_44 = CONCAT31(local_44._1_3_,2);
  *(undefined4 *)((int)this + 4) = 0xffffffff;
  FUN_00402870("CarData EventId:%d  EvaluateRecognitions  (Recognitions:%d)",
               (char)*(undefined4 *)((int)this + 0x60));
  puVar2 = (undefined4 *)FUN_00408af0((void *)((int)this + 0x1b8),&local_104);
  for (puVar2 = (undefined4 *)*puVar2; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2)
  {
    FUN_00411750(&local_108,puVar2 + 2);
    memset(local_c8,0,0x40);
    FUN_004117f0(&local_108,local_c8,0x40);
    bVar1 = FUN_00412880(param_1);
    if (bVar1) {
      fVar7 = (float10)FUN_004117c0(&local_108);
      local_e8 = (double)fVar7;
      fVar7 = (float10)FUN_004117c0(param_1);
      if (fVar7 < (float10)local_e8 == (NAN(fVar7) || NAN((float10)local_e8))) {
        FUN_004117c0(&local_108);
        puVar3 = FUN_004117d0(&local_108);
        FUN_004116d0(puVar3);
        FUN_00402870("CarData EventId:%d  EvaluateRecognitions \'%s\' %d %f is not good enought.",
                     (char)*(undefined4 *)((int)this + 0x60));
      }
      else {
        FUN_004117c0(param_1);
        puVar3 = FUN_004117d0(param_1);
        FUN_004116d0(puVar3);
        FUN_004117c0(&local_108);
        puVar3 = FUN_004117d0(&local_108);
        FUN_004116d0(puVar3);
        FUN_00402890("CarData EventId:%d  EvaluateRecognitions \'%s\' %d %f is better than %d %f",
                     (char)*(undefined4 *)((int)this + 0x60));
        FUN_00411750(param_1,&local_108);
      }
    }
    else {
      FUN_00411750(param_1,&local_108);
      FUN_004117c0(&local_108);
      puVar3 = FUN_004117d0(&local_108);
      FUN_004116d0(puVar3);
      FUN_00402870("CarData EventId:%d  EvaluateRecognitions \'%s\' %d %f is first recognition",
                   (char)*(undefined4 *)((int)this + 0x60));
    }
  }
  bVar1 = FUN_00412880(param_1);
  if (bVar1) {
    FUN_00401040((void *)((int)this + 100),"");
    puVar3 = (undefined4 *)0x0;
    puVar2 = (undefined4 *)FUN_00411bb0(param_1,&local_104);
    iVar4 = FUN_00411850(puVar2);
    if (0 < iVar4) {
      do {
        local_d0 = 0;
        local_cc = 0;
        puVar2 = &local_d0;
        uVar6 = 5;
        puVar8 = local_100;
        puVar5 = puVar3;
        this_00 = (void *)FUN_00411bb0(param_1,local_f8);
        puVar5 = FUN_00411bc0(this_00,puVar8,puVar5);
        FUN_00411860(puVar5,puVar2,uVar6);
        FUN_00401240((void *)((int)this + 100),(char *)&local_d0);
        puVar3 = (undefined4 *)((int)puVar3 + 1);
        puVar2 = (undefined4 *)FUN_00411bb0(param_1,&local_104);
        iVar4 = FUN_00411850(puVar2);
      } while ((int)puVar3 < iVar4);
    }
    fVar7 = (float10)FUN_004117c0(param_1);
    local_104 = (float)fVar7;
    *(float *)((int)this + 0x70) = local_104 * 100.0;
    uVar6 = FUN_00411830(param_1);
    FUN_004030d0((tm *)((int)this + 0x38),(char)((int)uVar6 >> 0x1f),(char)uVar6);
    puVar2 = FUN_004117d0(param_1);
    uVar6 = FUN_004116d0(puVar2);
    *(undefined4 *)((int)this + 4) = uVar6;
  }
  local_44._0_1_ = 1;
  FUN_00401170(local_dc);
  local_44 = (uint)local_44._1_3_ << 8;
  FUN_00411740(&local_108);
  ExceptionList = local_4c;
  ___security_check_cookie_4(local_84 ^ (uint)auStack_134);
  return;
}



void __thiscall FUN_004092e0(void *this,undefined4 *param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)FUN_00408c40((void *)((int)this + 0x20),&param_2,param_2);
  uVar1 = *puVar2;
  param_1[1] = (int)this + 4;
  *param_1 = uVar1;
  return;
}



void __thiscall FUN_00409310(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  void *local_4;
  
  local_4 = this;
  puVar2 = (undefined4 *)FUN_00408af0((void *)((int)this + 0x20),&local_4);
  uVar1 = *puVar2;
  param_1[1] = (int)this + 4;
  *param_1 = uVar1;
  return;
}



undefined4 * __thiscall FUN_00409340(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined in_stack_ffffffd4;
  undefined in_stack_ffffffd8;
  undefined in_stack_ffffffdc;
  undefined **ppuVar2;
  undefined *local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c928;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  ppuVar2 = &local_10;
  local_10 = &stack0xffffffd4;
  local_4 = 0;
  FUN_004010b0(&stack0xffffffd4,(void **)&stack0x00000008);
  puVar1 = FUN_00408b70((void *)((int)this + 4),in_stack_ffffffd4,in_stack_ffffffd8,
                        in_stack_ffffffdc,ppuVar2);
  param_1[1] = (void *)((int)this + 4);
  *param_1 = puVar1;
  local_4 = 0xffffffff;
  FUN_00401170((void **)&stack0x00000008);
  ExceptionList = local_c;
  return param_1;
}



void __fastcall FUN_004093c0(int *param_1)

{
  undefined4 *puVar1;
  void *pvVar2;
  
  if (*param_1 < 2) {
    if (*param_1 == 0) {
      return;
    }
  }
  else {
    for (puVar1 = *(undefined4 **)param_1[1]; puVar1 != (undefined4 *)0x0;
        puVar1 = (undefined4 *)*puVar1) {
      pvVar2 = (void *)puVar1[1];
      if (pvVar2 != (void *)0x0) {
        FUN_00411740((int *)((int)pvVar2 + 8));
        operator_delete(pvVar2);
      }
    }
  }
  pvVar2 = (void *)param_1[2];
  if (pvVar2 != (void *)0x0) {
    FUN_00411740((int *)((int)pvVar2 + 8));
    operator_delete(pvVar2);
  }
  return;
}



void __fastcall FUN_00409420(int *param_1,undefined param_2,undefined param_3)

{
  int iVar1;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041afc8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  iVar1 = FUN_00408b00(param_1[2],0);
  FUN_00411750((void *)(iVar1 + 8),(int *)&param_3);
  if ((int *)param_1[2] == (int *)0x0) {
    param_1[1] = iVar1;
  }
  else {
    *(int *)param_1[2] = iVar1;
  }
  *param_1 = *param_1 + 1;
  param_1[2] = iVar1;
  local_4 = 0xffffffff;
  FUN_00411740((int *)&param_3);
  ExceptionList = local_c;
  return;
}



void __thiscall FUN_004094a0(void *this,int *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
                    // WARNING: Load size is inaccurate
  if (1 < *this) {
    if (param_1 == *(int **)((int)this + 4)) {
      iVar1 = **(int **)((int)this + 4);
      *(int *)((int)this + 4) = iVar1;
      *(undefined4 *)(iVar1 + 4) = 0;
    }
    else if (param_1 == *(int **)((int)this + 8)) {
      puVar2 = (undefined4 *)(*(int **)((int)this + 8))[1];
      *(undefined4 **)((int)this + 8) = puVar2;
      *puVar2 = 0;
    }
    else {
      *(int *)param_1[1] = *param_1;
      *(int *)(*param_1 + 4) = param_1[1];
    }
  }
  if (param_1 != (int *)0x0) {
    FUN_00411740(param_1 + 2);
    operator_delete(param_1);
  }
                    // WARNING: Load size is inaccurate
  *(int *)this = *this + -1;
  if (*this == 0) {
    *(undefined4 *)((int)this + 8) = 0;
    *(undefined4 *)((int)this + 4) = 0;
  }
  return;
}



undefined4 * __thiscall FUN_00409520(void *this,void *param_1,uint param_2)

{
  void **this_00;
  uint uVar1;
  undefined *puVar2;
  undefined4 *puVar3;
  void *_Dst;
  undefined in_stack_ffffffcc;
  undefined in_stack_ffffffd0;
  undefined in_stack_ffffffd4;
  undefined **ppuVar4;
  undefined *local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041bff8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  ppuVar4 = &local_10;
  local_10 = &stack0xffffffcc;
  local_4 = 0;
  FUN_004010b0(&stack0xffffffcc,&param_1);
  puVar3 = FUN_00408b70(this,in_stack_ffffffcc,in_stack_ffffffd0,in_stack_ffffffd4,ppuVar4);
  if (puVar3 == (undefined4 *)0x0) {
                    // WARNING: Load size is inaccurate
    if (*this == 0) {
      uVar1 = *(uint *)((int)this + 4);
      _Dst = operator_new(-(uint)((int)((ulonglong)uVar1 * 4 >> 0x20) != 0) |
                          (uint)((ulonglong)uVar1 * 4));
      *(void **)this = _Dst;
      memset(_Dst,0,uVar1 * 4);
      *(uint *)((int)this + 4) = uVar1;
    }
    puVar3 = FUN_00412cb0((int)this);
    puVar2 = local_10;
    puVar3[1] = local_10;
    this_00 = (void **)(puVar3 + 2);
    if (param_1 != (void *)puVar3[2]) {
      FUN_00401910(this_00,param_2);
      memcpy(*this_00,param_1,param_2);
      puVar3[3] = param_2;
      *(undefined *)(param_2 + (int)*this_00) = 0;
    }
                    // WARNING: Load size is inaccurate
    *puVar3 = *(undefined4 *)(*this + (int)puVar2 * 4);
                    // WARNING: Load size is inaccurate
    *(undefined4 **)(*this + (int)puVar2 * 4) = puVar3;
  }
  local_4 = 0xffffffff;
  FUN_00401170(&param_1);
  ExceptionList = local_c;
  return puVar3 + 5;
}



int * __thiscall FUN_00409640(void *this,int *param_1)

{
  FUN_00408f90(this,param_1);
  return param_1;
}



void __fastcall FUN_00409660(int param_1,undefined param_2,undefined param_3)

{
  int iVar1;
  undefined4 uVar2;
  void **ppvVar3;
  tm *ptVar4;
  undefined extraout_CL;
  undefined extraout_DL;
  undefined uVar5;
  tm *ptVar6;
  __time64_t _Var7;
  void *local_80;
  void *local_7c;
  void *local_74 [3];
  void *local_68 [3];
  tm local_5c;
  tm local_34;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b030;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_00402fc0(&local_5c);
  FUN_004010a0(&local_80);
  local_4._0_1_ = 1;
  if (*(int *)(param_1 + 8) == -1) {
    iVar1 = FUN_0040bc20(*(int *)(param_1 + 0x11c));
    if (iVar1 == 0) {
      uVar2 = FUN_00411830((undefined4 *)&param_3);
      *(undefined4 *)(param_1 + 8) = uVar2;
      uVar2 = FUN_00411840((undefined4 *)&param_3);
      *(undefined4 *)(param_1 + 0xc) = uVar2;
      ppvVar3 = FUN_0040b6e0(local_68,*(int *)(param_1 + 8));
      local_4._0_1_ = 2;
      ppvVar3 = (void **)FUN_00401ab0((int *)local_74,"LPR ",ppvVar3);
      local_4._0_1_ = 3;
      FUN_00401000(&local_80,ppvVar3);
      local_4 = CONCAT31(local_4._1_3_,2);
      FUN_00401170(local_74);
      ppvVar3 = local_68;
      goto LAB_0040982c;
    }
    ptVar4 = FUN_00403080(&local_34);
    ptVar6 = &local_5c;
    for (iVar1 = 10; iVar1 != 0; iVar1 = iVar1 + -1) {
      ptVar6->tm_sec = ptVar4->tm_sec;
      ptVar4 = (tm *)&ptVar4->tm_min;
      ptVar6 = (tm *)&ptVar6->tm_min;
    }
    _Var7 = FUN_00403040(&local_5c);
    *(int *)(param_1 + 8) = (int)_Var7;
    uVar2 = FUN_00403030((int)&local_5c);
    *(undefined4 *)(param_1 + 0xc) = uVar2;
    ppvVar3 = FUN_0040b6e0(local_74,*(int *)(param_1 + 8));
    uVar5 = 4;
    local_4._0_1_ = 4;
    ppvVar3 = (void **)FUN_00401ab0((int *)local_68,"SYSTEM ",ppvVar3);
    local_4._0_1_ = 5;
    FUN_00401000(&local_80,ppvVar3);
  }
  else {
    ppvVar3 = FUN_0040b6e0(local_74,*(int *)(param_1 + 8));
    uVar5 = 6;
    local_4._0_1_ = 6;
    ppvVar3 = (void **)FUN_00401ab0((int *)local_68,"already set ",ppvVar3);
    local_4._0_1_ = 7;
    if (*ppvVar3 != local_80) {
      FUN_00401910(&local_80,(uint)ppvVar3[1]);
      memcpy(local_80,*ppvVar3,(size_t)ppvVar3[1]);
      local_7c = ppvVar3[1];
      *(undefined *)((int)local_7c + (int)local_80) = 0;
    }
  }
  local_4 = CONCAT31(local_4._1_3_,uVar5);
  FUN_00401170(local_68);
  ppvVar3 = local_74;
LAB_0040982c:
  local_4._0_1_ = 1;
  FUN_00401170(ppvVar3);
  iVar1 = FUN_00411790((undefined4 *)&param_3);
  if (0 < iVar1) {
    *(undefined *)(param_1 + 0x1b4) = 1;
  }
  uVar5 = extraout_CL;
  FUN_00411720(&stack0xffffff64,(int *)&param_3);
  FUN_00409420((int *)(param_1 + 0x1b8),extraout_DL,uVar5);
  FUN_004011f0(&local_80);
  FUN_00402870("CarData EventId:%d HandleNewRecognition %s  (TimeSource:%s)",
               (char)*(undefined4 *)(param_1 + 0x60));
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170(&local_80);
  local_4 = 0xffffffff;
  FUN_00411740((int *)&param_3);
  ExceptionList = local_c;
  return;
}



undefined4 * __thiscall FUN_004098f0(void *this,byte param_1)

{
  *(undefined ***)this = aMap<int,class_CWebServerConversation*>::vftable;
  FUN_0040c080((void **)((int)this + 4));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __thiscall
FUN_00409920(void *this,undefined param_1,undefined param_2,undefined param_3,undefined4 param_4)

{
  undefined4 *puVar1;
  void *in_stack_ffffffdc;
  uint in_stack_ffffffe0;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041ae98;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004010b0(&stack0xffffffdc,(void **)&param_1);
  puVar1 = FUN_00409520(this,in_stack_ffffffdc,in_stack_ffffffe0);
  *puVar1 = param_4;
  local_4 = 0xffffffff;
  FUN_00401170((void **)&param_1);
  ExceptionList = local_c;
  return;
}



uint __fastcall FUN_00409990(void **param_1,undefined param_2,undefined param_3)

{
  void **ppvVar1;
  void **ppvVar2;
  void **ppvVar3;
  uint uVar4;
  byte *pbVar5;
  int iVar6;
  undefined4 uVar7;
  char *in_stack_ffffffd4;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041cdf8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  if (*param_1 != (void *)0x0) {
    FUN_004010b0(&stack0xffffffd4,(void **)&param_3);
    uVar4 = FUN_00406940(in_stack_ffffffd4);
    ppvVar3 = *(void ***)((int)*param_1 + (uVar4 % (uint)param_1[1]) * 4);
    ppvVar2 = (void **)((int)*param_1 + (uVar4 % (uint)param_1[1]) * 4);
    while (ppvVar1 = ppvVar3, ppvVar1 != (void **)0x0) {
      pbVar5 = FUN_004011f0((undefined4 *)&param_3);
      iVar6 = FUN_00401290(ppvVar1 + 2,pbVar5);
      if (iVar6 == 0) {
        *ppvVar2 = *ppvVar1;
        FUN_00401170(ppvVar1 + 2);
        *ppvVar1 = param_1[3];
        param_1[3] = ppvVar1;
        ppvVar2 = param_1 + 2;
        *ppvVar2 = (void *)((int)*ppvVar2 + -1);
        if (*ppvVar2 == (void *)0x0) {
          FUN_00412d60(param_1);
        }
        local_4 = 0xffffffff;
        uVar7 = FUN_00401170((void **)&param_3);
        ExceptionList = local_c;
        return CONCAT31((int3)((uint)uVar7 >> 8),1);
      }
      ppvVar2 = ppvVar1;
      ppvVar3 = (void **)*ppvVar1;
    }
  }
  local_4 = 0xffffffff;
  uVar4 = FUN_00401170((void **)&param_3);
  ExceptionList = local_c;
  return uVar4 & 0xffffff00;
}



undefined4 __fastcall FUN_00409a80(int *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = *(int *)(param_1[1] + 4);
  if (iVar1 != 0) {
    for (puVar2 = *(undefined4 **)
                   (iVar1 + ((*(uint *)(*param_1 + 8) >> 4) % *(uint *)(param_1[1] + 8)) * 4);
        puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
      if (puVar2[2] == *(uint *)(*param_1 + 8)) {
        return puVar2[2];
      }
    }
  }
  return uRam00000008;
}



undefined4 __fastcall FUN_00409ac0(int param_1)

{
  int *piVar1;
  undefined4 uVar2;
  undefined4 local_8 [2];
  
  if (*(int *)(param_1 + 0x1e4) == 0) {
    return 0;
  }
  piVar1 = (int *)FUN_00409310((void *)(param_1 + 0x1c4),local_8);
  uVar2 = FUN_0040d020(piVar1);
  return uVar2;
}



void __fastcall FUN_00409af0(int param_1)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  void *this;
  char cVar4;
  undefined4 *puVar5;
  undefined4 local_8 [2];
  
  puVar5 = (undefined4 *)FUN_00409310((void *)(param_1 + 0x1c4),local_8);
  puVar1 = (undefined4 *)*puVar5;
  iVar2 = puVar5[1];
  do {
    if (puVar1 == (undefined4 *)0x0) {
      return;
    }
    iVar3 = *(int *)(iVar2 + 4);
    puVar5 = (undefined4 *)0x0;
    if (iVar3 != 0) {
      for (puVar5 = *(undefined4 **)(iVar3 + (((uint)puVar1[2] >> 4) % *(uint *)(iVar2 + 8)) * 4);
          puVar5 != (undefined4 *)0x0; puVar5 = (undefined4 *)*puVar5) {
        if (puVar5[2] == puVar1[2]) goto LAB_00409b3d;
      }
      puVar5 = (undefined4 *)0x0;
    }
LAB_00409b3d:
    this = (void *)puVar5[3];
    cVar4 = FUN_00416490((int)this);
    if (cVar4 == '\0') {
      FUN_004165a0(this,param_1);
    }
    puVar1 = (undefined4 *)*puVar1;
  } while( true );
}



void __fastcall FUN_00409b70(undefined4 *param_1)

{
  *param_1 = aCollection<int,class_CWebServerConversation*>::vftable;
  FUN_00412c00(param_1 + 8);
  param_1[1] = aMap<int,class_CWebServerConversation*>::vftable;
  FUN_0040c080((void **)(param_1 + 2));
  return;
}



uint __thiscall FUN_00409ba0(void *this,int *param_1,int param_2)

{
  int *piVar1;
  uint in_EAX;
  uint uVar2;
  void *pvVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  
  piVar1 = param_1;
  puVar5 = (undefined4 *)0x0;
  if (*(int *)(param_2 + 4) != 0) {
    uVar2 = (uint)param_1[2] >> 4;
    in_EAX = uVar2 / *(uint *)(param_2 + 8);
    for (puVar5 = *(undefined4 **)(*(int *)(param_2 + 4) + (uVar2 % *(uint *)(param_2 + 8)) * 4);
        puVar5 != (undefined4 *)0x0; puVar5 = (undefined4 *)*puVar5) {
      if (puVar5[2] == param_1[2]) goto LAB_00409bdd;
    }
    puVar5 = (undefined4 *)0x0;
  }
LAB_00409bdd:
  puVar6 = (undefined4 *)0x0;
  if (*(int *)((int)this + 8) != 0) {
    uVar2 = (uint)puVar5[2] >> 4;
    in_EAX = uVar2 / *(uint *)((int)this + 0xc);
    for (puVar6 = *(undefined4 **)
                   (*(int *)((int)this + 8) + (uVar2 % *(uint *)((int)this + 0xc)) * 4);
        puVar6 != (undefined4 *)0x0; puVar6 = (undefined4 *)*puVar6) {
      if (puVar6[2] == puVar5[2]) goto LAB_00409c0d;
    }
    puVar6 = (undefined4 *)0x0;
  }
LAB_00409c0d:
  if ((this != (void *)0xfffffff8) && (puVar6 != (undefined4 *)0x0)) {
    pvVar3 = (void *)FUN_00409a80((int *)&param_1);
    FUN_00414e50((void *)((int)this + 8),pvVar3);
    uVar4 = FUN_0040ae30((void *)((int)this + 0x20),piVar1);
    return CONCAT31((int3)((uint)uVar4 >> 8),1);
  }
  return in_EAX & 0xffffff00;
}



void __fastcall FUN_00409c50(undefined4 *param_1)

{
  *param_1 = aMap<class_aString,class_CCarImage*>::vftable;
  FUN_00412d60((void **)(param_1 + 1));
  return;
}



void __thiscall
FUN_00409c60(void *this,undefined param_1,undefined param_2,undefined param_3,undefined *param_4)

{
  undefined in_stack_ffffffdc;
  undefined in_stack_ffffffe0;
  undefined in_stack_ffffffe4;
  undefined4 uVar1;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b4a8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  uVar1 = param_4;
  param_4 = &stack0xffffffdc;
  FUN_004010b0(&stack0xffffffdc,(void **)&param_1);
  FUN_00409920((void *)((int)this + 4),in_stack_ffffffdc,in_stack_ffffffe0,in_stack_ffffffe4,uVar1);
  local_4 = 0xffffffff;
  FUN_00401170((void **)&param_1);
  ExceptionList = local_c;
  return;
}



void __fastcall FUN_00409cd0(int param_1,undefined param_2,undefined param_3)

{
  undefined extraout_DL;
  undefined in_stack_ffffffdc;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041ae98;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004010b0(&stack0xffffffdc,(void **)&param_3);
  FUN_00409990((void **)(param_1 + 4),extraout_DL,in_stack_ffffffdc);
  local_4 = 0xffffffff;
  FUN_00401170((void **)&param_3);
  ExceptionList = local_c;
  return;
}



undefined4 * __thiscall FUN_00409d40(void *this,byte param_1)

{
  *(undefined ***)this = aCollection<int,class_CWebServerConversation*>::vftable;
  FUN_00412c00((int *)((int)this + 0x20));
  *(undefined ***)((int)this + 4) = aMap<int,class_CWebServerConversation*>::vftable;
  FUN_0040c080((void **)((int)this + 8));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_00409d80(void *this,byte param_1)

{
  *(undefined ***)this = aMap<class_aString,class_CCarImage*>::vftable;
  FUN_00412d60((void **)((int)this + 4));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall
FUN_00409db0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,void *param_4,
            uint param_5,undefined4 param_6,void *param_7,uint param_8,undefined4 param_9,
            undefined4 param_10)

{
  void **ppvVar1;
  tm *ptVar2;
  int iVar3;
  int *piVar4;
  tm local_34;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b112;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 1;
  *(undefined ***)this = CCarData::vftable;
  FUN_00402fc0((int *)((int)this + 0x10));
  FUN_00402fc0((int)this + 0x38);
  FUN_004010a0((undefined4 *)((int)this + 100));
  local_4._0_1_ = 2;
  FUN_00402960((undefined4 *)((int)this + 0x7c));
  local_4._0_1_ = 3;
  FUN_004010a0((undefined4 *)((int)this + 0x120));
  local_4._0_1_ = 4;
  FUN_004010a0((undefined4 *)((int)this + 300));
  local_4._0_1_ = 5;
  FUN_00402e50((undefined4 *)((int)this + 0x13c));
  *(undefined ***)((int)this + 0x164) = aMap<class_aString,class_CCarImage*>::vftable;
  *(undefined4 *)((int)this + 0x168) = 0;
  *(undefined4 *)((int)this + 0x16c) = 0x11;
  *(undefined4 *)((int)this + 0x170) = 0;
  *(undefined4 *)((int)this + 0x174) = 0;
  *(undefined4 *)((int)this + 0x178) = 0;
  *(undefined4 *)((int)this + 0x17c) = 10;
  *(undefined4 *)((int)this + 0x180) = 0;
  *(undefined4 *)((int)this + 0x184) = 0;
  *(undefined4 *)((int)this + 0x188) = 0;
  *(undefined4 *)((int)this + 0x18c) = 0;
  *(undefined4 *)((int)this + 400) = 0;
  *(undefined4 *)((int)this + 0x194) = 0;
  local_4._0_1_ = 9;
  FUN_004010a0((undefined4 *)((int)this + 0x198));
  local_4._0_1_ = 10;
  FUN_004010a0((undefined4 *)((int)this + 0x1a4));
  *(undefined4 *)((int)this + 0x1b8) = 0;
  *(undefined4 *)((int)this + 0x1bc) = 0;
  *(undefined4 *)((int)this + 0x1c0) = 0;
  *(undefined ***)((int)this + 0x1c4) = aCollection<int,class_CWebServerConversation*>::vftable;
  *(undefined ***)((int)this + 0x1c8) = aMap<int,class_CWebServerConversation*>::vftable;
  *(undefined4 *)((int)this + 0x1cc) = 0;
  *(undefined4 *)((int)this + 0x1d0) = 0x11;
  *(undefined4 *)((int)this + 0x1d4) = 0;
  *(undefined4 *)((int)this + 0x1d8) = 0;
  *(undefined4 *)((int)this + 0x1dc) = 0;
  *(undefined4 *)((int)this + 0x1e0) = 10;
  *(undefined4 *)((int)this + 0x1e4) = 0;
  *(undefined4 *)((int)this + 0x1e8) = 0;
  *(undefined4 *)((int)this + 0x1ec) = 0;
  local_4 = CONCAT31(local_4._1_3_,0xd);
  *(undefined *)((int)this + 0x78) = 1;
  *(undefined *)((int)this + 0x138) = 0;
  ptVar2 = FUN_00403080(&local_34);
  piVar4 = (int *)((int)this + 0x10);
  for (iVar3 = 10; iVar3 != 0; iVar3 = iVar3 + -1) {
    *piVar4 = ptVar2->tm_sec;
    ptVar2 = (tm *)&ptVar2->tm_min;
    piVar4 = piVar4 + 1;
  }
  FUN_00401040((void *)((int)this + 100),"");
  *(undefined4 *)((int)this + 0x70) = 0;
  ppvVar1 = (void **)((int)this + 300);
  if (param_4 != *(void **)((int)this + 300)) {
    FUN_00401910(ppvVar1,param_5);
    memcpy(*ppvVar1,param_4,param_5);
    *(uint *)((int)this + 0x130) = param_5;
    *(undefined *)(param_5 + (int)*ppvVar1) = 0;
  }
  ppvVar1 = (void **)((int)this + 0x120);
  if (param_7 != *(void **)((int)this + 0x120)) {
    FUN_00401910(ppvVar1,param_8);
    memcpy(*ppvVar1,param_7,param_8);
    *(uint *)((int)this + 0x124) = param_8;
    *(undefined *)(param_8 + (int)*ppvVar1) = 0;
  }
  *(undefined4 *)((int)this + 0x60) = param_2;
  *(undefined4 *)((int)this + 0x74) = param_3;
  FUN_00402a80((void *)((int)this + 0x7c),(DWORD)this,0,0);
  *(undefined4 *)((int)this + 0x11c) = param_1;
  *(undefined4 *)((int)this + 8) = 0xffffffff;
  *(undefined4 *)((int)this + 0xc) = 0xffffffff;
  *(undefined4 *)((int)this + 0x160) = 3;
  FUN_00401040((void *)((int)this + 0x198),"Data");
  FUN_00401040((void *)((int)this + 0x1a4),"Image");
  *(undefined *)((int)this + 0x1b4) = 0;
  *(undefined4 *)((int)this + 0x1b0) = param_10;
  local_4 = local_4 & 0xffffff00;
  FUN_00401170(&param_4);
  local_4 = 0xffffffff;
  FUN_00401170(&param_7);
  ExceptionList = local_c;
  return (undefined4 *)this;
}



void __fastcall FUN_0040a070(undefined4 *param_1)

{
  int *piVar1;
  int *piVar2;
  int *piVar3;
  undefined4 *puVar4;
  int **ppiVar5;
  undefined4 *puVar6;
  int iVar7;
  uint uVar8;
  uint *puVar9;
  undefined extraout_DL;
  int in_stack_ffffffa0;
  int local_40;
  int local_3c;
  int *local_38;
  undefined4 *local_34;
  uint local_30;
  uint **local_2c;
  void *local_28 [5];
  void *local_14;
  undefined *puStack_10;
  undefined4 local_c;
  
  puStack_10 = &LAB_0041b1ea;
  local_14 = ExceptionList;
  ExceptionList = &local_14;
  *param_1 = CCarData::vftable;
  local_c = 0xb;
  local_34 = param_1;
  FUN_004118b0(&local_40);
  local_c = CONCAT31(local_c._1_3_,0xc);
  FUN_004033d0(param_1 + 0x1f);
  if (0 < (int)param_1[0x79]) {
    do {
      ppiVar5 = (int **)FUN_00409310(param_1 + 0x71,&local_30);
      iVar7 = ppiVar5[1][1];
      if (iVar7 != 0) {
        for (puVar6 = *(undefined4 **)
                       (iVar7 + (((uint)(*ppiVar5)[2] >> 4) % (uint)ppiVar5[1][2]) * 4);
            puVar6 != (undefined4 *)0x0; puVar6 = (undefined4 *)*puVar6) {
          if (puVar6[2] == (*ppiVar5)[2]) goto LAB_0040a113;
        }
      }
      puVar6 = (undefined4 *)0x0;
LAB_0040a113:
      piVar1 = (int *)puVar6[3];
      in_stack_ffffffa0 = 0x40a124;
      FUN_00409ba0(param_1 + 0x71,*ppiVar5,(int)ppiVar5[1]);
      iVar7 = FUN_004164e0((int)piVar1);
      if ((iVar7 == 2) && (FUN_00416570(piVar1), piVar1 != (int *)0x0)) {
        (**(code **)*piVar1)();
      }
    } while (0 < (int)param_1[0x79]);
  }
  if (0 < (int)param_1[0x5c]) {
    do {
      uVar8 = 0;
      local_30 = uVar8;
      if ((param_1[0x5c] != 0) && (local_30 = 0, param_1[0x5b] != 0)) {
        puVar9 = (uint *)param_1[0x5a];
        do {
          local_30 = *puVar9;
          if (local_30 != 0) break;
          uVar8 = uVar8 + 1;
          puVar9 = puVar9 + 1;
        } while (uVar8 < (uint)param_1[0x5b]);
      }
      puVar6 = *(undefined4 **)(local_30 + 0x14);
      local_2c = (uint **)(param_1 + 0x5a);
      FUN_00408a60(&local_30,local_28);
      local_38 = (int *)&stack0xffffffa0;
      local_c._0_1_ = 0xd;
      FUN_004010b0(&stack0xffffffa0,local_28);
      FUN_00409990((void **)(param_1 + 0x5a),extraout_DL,(char)in_stack_ffffffa0);
      local_c = CONCAT31(local_c._1_3_,0xc);
      FUN_00401170(local_28);
      if (puVar6 != (undefined4 *)0x0) {
        (**(code **)*puVar6)();
      }
    } while (0 < (int)param_1[0x5c]);
  }
  piVar1 = param_1 + 0x60;
  iVar7 = param_1[0x60];
  while (0 < iVar7) {
    ppiVar5 = (int **)FUN_00408af0(piVar1,&local_38);
    piVar2 = *ppiVar5;
    puVar6 = (undefined4 *)piVar2[2];
    if (1 < *piVar1) {
      if (piVar2 == (int *)param_1[0x61]) {
        iVar7 = *(int *)param_1[0x61];
        param_1[0x61] = iVar7;
        *(undefined4 *)(iVar7 + 4) = 0;
      }
      else if (piVar2 == (int *)param_1[0x62]) {
        puVar4 = (undefined4 *)((int *)param_1[0x62])[1];
        param_1[0x62] = puVar4;
        *puVar4 = 0;
      }
      else {
        *(int *)piVar2[1] = *piVar2;
        *(int *)(*piVar2 + 4) = piVar2[1];
      }
    }
    operator_delete(piVar2);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      param_1[0x62] = 0;
      param_1[0x61] = 0;
    }
    if (puVar6 != (undefined4 *)0x0) {
      (**(code **)*puVar6)();
    }
    iVar7 = *piVar1;
  }
  piVar2 = param_1 + 99;
  iVar7 = param_1[99];
  while (0 < iVar7) {
    ppiVar5 = (int **)FUN_00408af0(piVar2,&local_38);
    piVar3 = *ppiVar5;
    puVar6 = (undefined4 *)piVar3[2];
    if (1 < *piVar2) {
      if (piVar3 == (int *)param_1[100]) {
        iVar7 = *(int *)param_1[100];
        param_1[100] = iVar7;
        *(undefined4 *)(iVar7 + 4) = 0;
      }
      else if (piVar3 == (int *)param_1[0x65]) {
        puVar4 = (undefined4 *)((int *)param_1[0x65])[1];
        param_1[0x65] = puVar4;
        *puVar4 = 0;
      }
      else {
        *(int *)piVar3[1] = *piVar3;
        *(int *)(*piVar3 + 4) = piVar3[1];
      }
    }
    operator_delete(piVar3);
    *piVar2 = *piVar2 + -1;
    if (*piVar2 == 0) {
      param_1[0x65] = 0;
      param_1[100] = 0;
    }
    if (puVar6 != (undefined4 *)0x0) {
      (**(code **)*puVar6)();
    }
    iVar7 = *piVar2;
  }
  piVar3 = param_1 + 0x6e;
  iVar7 = param_1[0x6e];
  while (0 < iVar7) {
    ppiVar5 = (int **)FUN_00408af0(piVar3,&local_30);
    local_38 = *ppiVar5;
    FUN_00411750(&local_40,local_38 + 2);
    FUN_004094a0(piVar3,local_38);
    FUN_00411700(&local_3c,0,'\0');
    local_c._0_1_ = 0xe;
    FUN_00411750(&local_40,&local_3c);
    local_c = CONCAT31(local_c._1_3_,0xc);
    FUN_00411740(&local_3c);
    iVar7 = *piVar3;
  }
  local_c._1_3_ = (uint3)((uint)local_c >> 8);
  local_c._0_1_ = 0xb;
  FUN_00411740(&local_40);
  local_c._0_1_ = 10;
  param_1[0x71] = aCollection<int,class_CWebServerConversation*>::vftable;
  FUN_00412c00(param_1 + 0x79);
  param_1[0x72] = aMap<int,class_CWebServerConversation*>::vftable;
  FUN_0040c080((void **)(param_1 + 0x73));
  local_c._0_1_ = 9;
  FUN_004093c0(piVar3);
  local_c._0_1_ = 8;
  FUN_00401170((void **)(param_1 + 0x69));
  local_c._0_1_ = 7;
  FUN_00401170((void **)(param_1 + 0x66));
  FUN_00412c00(piVar2);
  FUN_00412c00(piVar1);
  local_c._0_1_ = 4;
  param_1[0x59] = aMap<class_aString,class_CCarImage*>::vftable;
  FUN_00412d60((void **)(param_1 + 0x5a));
  local_c._0_1_ = 3;
  FUN_00402eb0(param_1 + 0x4f);
  local_c._0_1_ = 2;
  FUN_00401170((void **)(param_1 + 0x4b));
  local_c._0_1_ = 1;
  FUN_00401170((void **)(param_1 + 0x48));
  local_c = (uint)local_c._1_3_ << 8;
  FUN_00402a30(param_1 + 0x1f);
  local_c = 0xffffffff;
  FUN_00401170((void **)(param_1 + 0x19));
  ExceptionList = local_14;
  return;
}



void __thiscall
FUN_0040a470(void *this,undefined param_2,undefined param_3,undefined param_4,undefined4 param_5,
            undefined4 param_6,undefined4 param_7,undefined param_8,undefined param_9,
            undefined param_10,undefined *param_11,undefined param_12,undefined *param_13)

{
  void *this_00;
  void **ppvVar1;
  undefined4 *puVar2;
  void **ppvVar3;
  void **ppvVar4;
  undefined *puVar5;
  void *in_stack_ffffffac;
  uint in_stack_ffffffb0;
  undefined4 uVar6;
  undefined *puVar7;
  undefined uVar8;
  void *in_stack_ffffffbc;
  undefined uVar9;
  uint in_stack_ffffffc0;
  undefined uVar10;
  undefined4 uVar11;
  undefined *puVar12;
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b25c;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 2;
  uVar11 = 0x40a4ad;
  this_00 = operator_new(0x6c);
  local_4._0_1_ = 3;
  if (this_00 == (void *)0x0) {
    puVar2 = (undefined4 *)0x0;
  }
  else {
    uVar6 = 0x40a4db;
    puVar12 = param_13;
    param_13 = &stack0xffffffbc;
    FUN_004010b0(&stack0xffffffbc,(void **)&param_12);
    local_4._0_1_ = 4;
    puVar7 = param_11;
    param_11 = &stack0xffffffac;
    FUN_004010b0(&stack0xffffffac,(void **)&param_8);
    puVar5 = &DAT_00423834;
    ppvVar4 = (void **)((int)this + 300);
    ppvVar3 = local_18;
    local_4._0_1_ = 5;
    ppvVar1 = FUN_00401a20(ppvVar3,ppvVar4,"\\");
    local_4 = CONCAT31(local_4._1_3_,6);
    FUN_00401990((void **)&stack0xffffffa0,ppvVar1,(void **)&param_8);
    local_4 = 7;
    puVar2 = FUN_0040a8c0(this_00,param_5,param_6,param_7,ppvVar3,(uint)ppvVar4,puVar5,
                          in_stack_ffffffac,in_stack_ffffffb0,uVar6,puVar7,in_stack_ffffffbc,
                          in_stack_ffffffc0,uVar11,puVar12);
  }
  uVar10 = (undefined)uVar11;
  uVar9 = (undefined)in_stack_ffffffc0;
  uVar8 = SUB41(in_stack_ffffffbc,0);
  local_4 = 2;
  if (this_00 != (void *)0x0) {
    FUN_00401170(local_18);
  }
  param_13 = &stack0xffffffbc;
  FUN_004010b0(&stack0xffffffbc,(void **)&param_2);
  FUN_00409c60((void *)((int)this + 0x164),uVar8,uVar9,uVar10,puVar2);
  local_4._0_1_ = 1;
  FUN_00401170((void **)&param_2);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170((void **)&param_8);
  local_4 = 0xffffffff;
  FUN_00401170((void **)&param_12);
  ExceptionList = local_c;
  return;
}



void __fastcall FUN_0040a5e0(void *param_1,undefined param_2,undefined param_3)

{
  int *piVar1;
  undefined extraout_DL;
  undefined uVar2;
  undefined4 local_14 [2];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041bff8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004011f0((undefined4 *)&param_3);
  uVar2 = 0xa0;
  FUN_00402870("CarData EventId:%d HandleDownloadedFile \'%s\'",
               (char)*(undefined4 *)((int)param_1 + 0x60));
  FUN_004010b0(&stack0xffffffd0,(void **)&param_3);
  piVar1 = FUN_00409340((void *)((int)param_1 + 0x164),local_14);
  if ((piVar1[1] == 0) || (*piVar1 == 0)) {
    FUN_004011f0((undefined4 *)&param_3);
    FUN_00402890("CarData EventId:%d HandleDownloadedFile \'%s\' . File not found",
                 (char)*(undefined4 *)((int)param_1 + 0x60));
  }
  else {
    FUN_00408ca0(param_1,*(int *)(*piVar1 + 0x14));
    FUN_004010b0(&stack0xffffffd0,(void **)&param_3);
    FUN_00409cd0((int)(void *)((int)param_1 + 0x164),extraout_DL,uVar2);
    if ((*(int *)((int)param_1 + 0x1b8) < *(int *)((int)param_1 + 0x1b0)) ||
       (*(int *)((int)param_1 + 0x170) != 0)) {
      FUN_004011f0((undefined4 *)&param_3);
      FUN_00402870("CarData EventId:%d HandleDownloadedFile \'%s\', pending files %d %s",
                   (char)*(undefined4 *)((int)param_1 + 0x60));
    }
    else {
      FUN_00402bb0((int)param_1 + 0x7c);
      FUN_00402870("CarData EventId:%d (all files generated)",
                   (char)*(undefined4 *)((int)param_1 + 0x60));
    }
  }
  local_4 = 0xffffffff;
  FUN_00401170((void **)&param_3);
  ExceptionList = local_c;
  return;
}



uint __thiscall FUN_0040a730(void *this,uint param_1,undefined4 param_2)

{
  undefined4 uVar1;
  uint in_EAX;
  undefined4 *puVar2;
  
  if (*(int *)((int)this + 8) != 0) {
    in_EAX = (param_1 >> 4) / *(uint *)((int)this + 0xc);
    for (puVar2 = *(undefined4 **)
                   (*(int *)((int)this + 8) + ((param_1 >> 4) % *(uint *)((int)this + 0xc)) * 4);
        puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
      if (puVar2[2] == param_1) goto LAB_0040a761;
    }
  }
  puVar2 = (undefined4 *)0x0;
LAB_0040a761:
  if ((this != (void *)0xfffffff8) && (puVar2 != (undefined4 *)0x0)) {
    return in_EAX & 0xffffff00;
  }
  uVar1 = *(undefined4 *)((int)this + 0x28);
  puVar2 = (undefined4 *)operator_new(0xc);
  puVar2[1] = uVar1;
  *puVar2 = 0;
  puVar2[2] = param_1;
  if (*(undefined4 **)((int)this + 0x28) == (undefined4 *)0x0) {
    *(undefined4 **)((int)this + 0x24) = puVar2;
  }
  else {
    **(undefined4 **)((int)this + 0x28) = puVar2;
  }
  *(int *)((int)this + 0x20) = *(int *)((int)this + 0x20) + 1;
  *(undefined4 **)((int)this + 0x28) = puVar2;
  puVar2 = FUN_00414eb0((void *)((int)this + 8),param_1);
  *puVar2 = param_2;
  return CONCAT31((int3)((uint)puVar2 >> 8),1);
}



undefined4 * __thiscall FUN_0040a7c0(void *this,byte param_1)

{
  FUN_0040a070((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __thiscall FUN_0040a7e0(void *this,void *param_1)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  void *this_00;
  uint uVar4;
  void *pvVar5;
  undefined4 local_8;
  int local_4;
  
  cVar1 = FUN_00416490((int)param_1);
  if (cVar1 != '\0') {
    FUN_00416460((int)param_1);
    FUN_00402890("CarData %d AddWebServerConversation ignore webRequest:%d already completed",
                 (char)*(undefined4 *)((int)this + 0x60));
    return;
  }
  iVar2 = FUN_00416460((int)param_1);
  piVar3 = (int *)FUN_004092e0((void *)((int)this + 0x1c4),&local_8,iVar2);
  local_4 = piVar3[1];
  if (*piVar3 != 0) {
    FUN_00416460((int)param_1);
    FUN_00402890("CarData %d Already contain webRequest:%d",(char)*(undefined4 *)((int)this + 0x60))
    ;
    return;
  }
  FUN_004164f0(param_1,2);
  pvVar5 = param_1;
  this_00 = (void *)FUN_004164d0((int)param_1);
  FUN_00419f90(this_00,(int)pvVar5);
  pvVar5 = param_1;
  uVar4 = FUN_00416460((int)param_1);
  FUN_0040a730((void *)((int)this + 0x1c4),uVar4,pvVar5);
  FUN_0040c6d0(*(void **)((int)this + 0x11c),(int)param_1);
  FUN_00416460((int)param_1);
  FUN_00402850("CarData %d AddWebServerConversation webRequest:%d (Count:%d)",
               (char)*(undefined4 *)((int)this + 0x60));
  return;
}



undefined4 * __thiscall
FUN_0040a8c0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,void *param_4,
            uint param_5,undefined4 param_6,void *param_7,uint param_8,undefined4 param_9,
            undefined4 param_10,void *param_11,uint param_12,undefined4 param_13,undefined4 param_14
            )

{
  void **this_00;
  void **this_01;
  void **this_02;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b2b9;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  this_00 = (void **)((int)this + 0xc);
  local_4 = 2;
  *(undefined ***)this = CCarImage::vftable;
  FUN_004010a0(this_00);
  this_01 = (void **)((int)this + 0x18);
  local_4._0_1_ = 3;
  FUN_004010a0(this_01);
  local_4._0_1_ = 4;
  FUN_00402fc0((int)this + 0x24);
  this_02 = (void **)((int)this + 0x4c);
  FUN_004010a0(this_02);
  *(undefined4 *)((int)this + 4) = param_1;
  *(undefined *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0x5c) = param_2;
  *(undefined4 *)((int)this + 0x60) = param_3;
  local_4 = CONCAT31(local_4._1_3_,5);
  if (param_7 != *this_00) {
    FUN_00401910(this_00,param_8);
    memcpy(*this_00,param_7,param_8);
    *(uint *)((int)this + 0x10) = param_8;
    *(undefined *)(param_8 + (int)*this_00) = 0;
  }
  if (param_4 != *this_01) {
    FUN_00401910(this_01,param_5);
    memcpy(*this_01,param_4,param_5);
    *(uint *)((int)this + 0x1c) = param_5;
    *(undefined *)(param_5 + (int)*this_01) = 0;
  }
  FUN_004030d0((tm *)((int)this + 0x24),(char)((int)param_10 >> 0x1f),(char)param_10);
  if (param_11 != *this_02) {
    FUN_00401910(this_02,param_12);
    memcpy(*this_02,param_11,param_12);
    *(uint *)((int)this + 0x50) = param_12;
    *(undefined *)(param_12 + (int)*this_02) = 0;
  }
  *(undefined4 *)((int)this + 0x58) = param_14;
  *(undefined4 *)((int)this + 100) = 0;
  *(undefined4 *)((int)this + 0x68) = 0;
  local_4._0_1_ = 1;
  FUN_00401170(&param_4);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170(&param_7);
  local_4 = 0xffffffff;
  FUN_00401170(&param_11);
  ExceptionList = local_c;
  return (undefined4 *)this;
}



void __fastcall FUN_0040aa50(undefined4 *param_1)

{
  char *in_stack_ffffffd4;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b301;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = CCarImage::vftable;
  local_4 = 2;
  if ((void *)param_1[0x19] != (void *)0x0) {
    operator_delete((void *)param_1[0x19]);
  }
  FUN_004010b0(&stack0xffffffd4,(void **)(param_1 + 6));
  FUN_00403820(in_stack_ffffffd4);
  local_4._0_1_ = 1;
  FUN_00401170((void **)(param_1 + 0x13));
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170((void **)(param_1 + 6));
  local_4 = 0xffffffff;
  FUN_00401170((void **)(param_1 + 3));
  ExceptionList = local_c;
  return;
}



undefined4 __fastcall FUN_0040aaf0(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



void * __thiscall FUN_0040ab00(void *this,void *param_1)

{
  if (*(int *)((int)this + 4) == 0) {
    FUN_00401100(param_1,"vehicle",(char *)0x7fffffff);
    return param_1;
  }
  if (*(int *)((int)this + 4) != 1) {
    FUN_00401100(param_1,"",(char *)0x7fffffff);
    return param_1;
  }
  FUN_00401100(param_1,"driver",(char *)0x7fffffff);
  return param_1;
}



void __fastcall FUN_0040ab60(int param_1)

{
  uint *puVar1;
  bool bVar2;
  char *pcVar3;
  void *pvVar4;
  FILE *_File;
  char *pcVar5;
  LPCSTR in_stack_ffffffd8;
  undefined4 in_stack_ffffffdc;
  undefined4 in_stack_ffffffe0;
  uint *puVar6;
  int *piVar7;
  
  if (*(void **)(param_1 + 100) != (void *)0x0) {
    operator_delete(*(void **)(param_1 + 100));
  }
  piVar7 = (int *)0x0;
  puVar1 = (uint *)(param_1 + 0x68);
  pcVar5 = (char *)0x7fffffff;
  *(undefined4 *)(param_1 + 100) = 0;
  *puVar1 = 0;
  puVar6 = puVar1;
  pcVar3 = FUN_004011f0((undefined4 *)(param_1 + 0x18));
  FUN_00401100(&stack0xffffffd8,pcVar3,pcVar5);
  bVar2 = FUN_004036e0(in_stack_ffffffd8,in_stack_ffffffdc,in_stack_ffffffe0,puVar6,piVar7);
  if ((bVar2) && (*puVar1 != 0)) {
    pvVar4 = operator_new(*puVar1);
    pcVar5 = "rb";
    *(void **)(param_1 + 100) = pvVar4;
    pcVar3 = FUN_004011f0((undefined4 *)(param_1 + 0x18));
    _File = fopen(pcVar3,pcVar5);
    fread(*(void **)(param_1 + 100),1,*puVar1,_File);
    fclose(_File);
  }
  return;
}



undefined4 * __thiscall FUN_0040ac00(void *this,byte param_1)

{
  FUN_0040aa50((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



size_t __thiscall FUN_0040ac20(void *this,void *param_1,size_t param_2)

{
  size_t sVar1;
  
  if (*(int *)((int)this + 0x10) != 0) {
    if ((*(int *)((int)this + 100) == 0) || (*(int *)((int)this + 0x68) == 0)) {
      FUN_0040ab60((int)this);
    }
    if (((param_1 != (void *)0x0) && (*(void **)((int)this + 100) != (void *)0x0)) &&
       (sVar1 = *(size_t *)((int)this + 0x68), sVar1 != 0)) {
      if ((int)sVar1 < (int)param_2) {
        param_2 = sVar1;
      }
      memcpy(param_1,*(void **)((int)this + 100),param_2);
      return param_2;
    }
  }
  return 0;
}



undefined4 __thiscall
FUN_0040ac90(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  *(undefined4 *)((int)this + 0x40) = param_1;
  *(undefined4 *)((int)this + 0x3c) = param_3;
  *(undefined4 *)((int)this + 0x44) = param_2;
  uVar1 = FUN_00403360(this,'\x01',0,0);
  return CONCAT31((int3)((uint)uVar1 >> 8),1);
}



void __fastcall thunk_FUN_004033d0(int *param_1)

{
  code *pcVar1;
  
  FUN_004061b0(param_1 + 2);
  pcVar1 = *(code **)(*param_1 + 4);
  *(undefined *)(param_1 + 1) = 1;
  (*pcVar1)();
  if (*(char *)(param_1 + 0xd) == '\0') {
    WaitForSingleObject((HANDLE)param_1[0xe],0xffffffff);
    CloseHandle((HANDLE)param_1[0xe]);
  }
  return;
}



void __fastcall FUN_0040acd0(int param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b32b;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_00401170((void **)(param_1 + 0x18));
  local_4 = 0xffffffff;
  FUN_00401170((void **)(param_1 + 0xc));
  ExceptionList = local_c;
  return;
}



void __thiscall FUN_0040ad30(void *this,undefined4 param_1,char *param_2)

{
  FILE *_File;
  undefined4 uVar1;
  undefined4 local_108;
  undefined auStack_104 [256];
  uint local_4;
  
  local_4 = DAT_00428400 ^ (uint)&local_108;
  local_108 = param_1;
  _File = fopen(param_2,"wb");
  if (_File == (FILE *)0x0) {
    FUN_004028b0("Downloader %d: Can\'t create file \'%s\'. Review if path exists",
                 (char)*(undefined4 *)((int)this + 0x40));
  }
  else {
    uVar1 = curl_easy_init();
    curl_easy_setopt(uVar1,0x271a,auStack_104);
    curl_easy_setopt(uVar1,0xd,*(undefined4 *)((int)this + 0x44));
    curl_easy_setopt(uVar1,0x2712,local_108);
    curl_easy_setopt(uVar1,0x2a,0);
    curl_easy_setopt(uVar1,0x34,1);
    curl_easy_setopt(uVar1,0x4e2b,&DAT_0040ac80);
    curl_easy_setopt(uVar1,0x2711,_File);
    curl_easy_perform(uVar1);
    curl_easy_cleanup(uVar1);
    fclose(_File);
  }
  ___security_check_cookie_4(local_4 ^ (uint)&local_108);
  return;
}



void __thiscall FUN_0040ae30(void *this,int *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
                    // WARNING: Load size is inaccurate
  if (1 < *this) {
    if (param_1 == *(int **)((int)this + 4)) {
      iVar1 = **(int **)((int)this + 4);
      *(int *)((int)this + 4) = iVar1;
      *(undefined4 *)(iVar1 + 4) = 0;
    }
    else if (param_1 == *(int **)((int)this + 8)) {
      puVar2 = (undefined4 *)(*(int **)((int)this + 8))[1];
      *(undefined4 **)((int)this + 8) = puVar2;
      *puVar2 = 0;
    }
    else {
      *(int *)param_1[1] = *param_1;
      *(int *)(*param_1 + 4) = param_1[1];
    }
  }
  operator_delete(param_1);
                    // WARNING: Load size is inaccurate
  *(int *)this = *this + -1;
  if (*this == 0) {
    *(undefined4 *)((int)this + 8) = 0;
    *(undefined4 *)((int)this + 4) = 0;
  }
  return;
}



uint __thiscall FUN_0040aea0(void *this,int param_1,undefined4 param_2,DWORD param_3)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined4 unaff_retaddr;
  int local_24;
  int *local_20;
  undefined4 local_1c [3];
  void *pvStack_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b358;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  piVar1 = (int *)((int)this + 100);
  if (*(char *)((int)this + 0x90) == '\0') {
    FUN_004038e0(piVar1);
  }
  else {
    local_24 = (int)this + 0x38;
    local_20 = piVar1;
    FUN_00403d60(local_1c,&local_24,2,1);
    local_4 = 0;
    iVar3 = FUN_00403e00(local_1c,param_3);
    local_4 = 0xffffffff;
    if (iVar3 < 0) {
      uVar4 = FUN_00403de0(local_1c);
      ExceptionList = local_c;
      return uVar4 & 0xffffff00;
    }
    FUN_00403de0(local_1c);
  }
  cVar2 = FUN_004038c0((int *)((int)this + 0xc));
  if (cVar2 == '\0') {
    uVar4 = FUN_004038c0(piVar1);
    ExceptionList = pvStack_10;
    return uVar4 & 0xffffff00;
  }
  FUN_00408aa0((void *)(*(int *)((int)this + 8) + param_1 * 0xc),unaff_retaddr);
  uVar5 = FUN_004038c0(piVar1);
  ExceptionList = pvStack_10;
  return CONCAT31((int3)((uint)uVar5 >> 8),1);
}



uint __thiscall FUN_0040afa0(void *this,int *param_1,DWORD param_2)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int **ppiVar5;
  undefined4 uVar6;
  int *piVar7;
  int local_24;
  int *local_20;
  undefined4 local_1c [4];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b388;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_24 = (int)this + 0xc;
  piVar1 = (int *)((int)this + 100);
  local_20 = piVar1;
  FUN_00403d60(local_1c,&local_24,2,1);
  local_4 = 0;
  iVar2 = FUN_00403e00(local_1c,param_2);
  if (-1 < iVar2) {
    uVar4 = *(uint *)((int)this + 4);
    uVar3 = 0;
    if (uVar4 != 0) {
      piVar7 = *(int **)((int)this + 8);
      do {
        if (*piVar7 != 0) break;
        uVar3 = uVar3 + 1;
        piVar7 = piVar7 + 3;
      } while (uVar3 < uVar4);
    }
    if (uVar3 != uVar4) {
      ppiVar5 = (int **)FUN_00408af0((void *)(*(int *)((int)this + 8) + uVar3 * 0xc),&param_2);
      piVar7 = *ppiVar5;
      *param_1 = piVar7[2];
      FUN_0040ae30((void *)(*(int *)((int)this + 8) + uVar3 * 0xc),piVar7);
      if (*(char *)((int)this + 0x90) != '\0') {
        FUN_004038c0((int *)((int)this + 0x38));
      }
      FUN_004038c0(piVar1);
      local_4 = 0xffffffff;
      uVar6 = FUN_00403de0(local_1c);
      ExceptionList = local_c;
      return CONCAT31((int3)((uint)uVar6 >> 8),1);
    }
    FUN_004038c0(piVar1);
  }
  local_4 = 0xffffffff;
  uVar4 = FUN_00403de0(local_1c);
  ExceptionList = local_c;
  return uVar4 & 0xffffff00;
}



void __thiscall FUN_0040b0c0(void *this,int param_1)

{
  FUN_0040aea0((void *)((int)this + 0x48),param_1,0,0);
  return;
}



void __fastcall FUN_0040b0e0(int param_1)

{
  FUN_0040aea0((void *)(param_1 + 0x48),0,0,0);
  return;
}



void __fastcall FUN_0040b0f0(void *param_1)

{
  void **ppvVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  char cVar4;
  char *pcVar5;
  undefined1 *puVar6;
  int iVar7;
  char *pcVar8;
  char *pcVar9;
  uint uVar10;
  undefined4 *local_1c;
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b3c3;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_004010a0(local_18);
  local_4 = 0;
  FUN_00403420(param_1,1);
  cVar4 = FUN_00403410((int)param_1);
  while (cVar4 == '\0') {
    local_1c = (undefined4 *)0x0;
    FUN_0040afa0((void *)((int)param_1 + 0x48),(int *)&local_1c,1000);
    puVar3 = local_1c;
    if (local_1c != (undefined4 *)0x0) {
      ppvVar1 = (void **)(local_1c + 3);
      puVar2 = local_1c + 6;
      FUN_004011f0(ppvVar1);
      FUN_004011f0(puVar2);
      FUN_00402870("Downloader %d: Start download \'%s\' > \'%s\'...",
                   (char)*(undefined4 *)((int)param_1 + 0x40));
      pcVar5 = FUN_004011f0(ppvVar1);
      puVar6 = FUN_004011f0(puVar2);
      iVar7 = FUN_0040ad30(param_1,puVar6,pcVar5);
      if (iVar7 == 0) {
        FUN_004011f0(ppvVar1);
        uVar10 = *(uint *)((int)param_1 + 0x40);
        pcVar9 = "Downloader %d: Download complete. File \'%s\'.";
        FUN_00402870("Downloader %d: Download complete. File \'%s\'.",(char)uVar10);
        pcVar8 = (char *)0x7fffffff;
        local_1c = (undefined4 *)&stack0xffffffc4;
        pcVar5 = FUN_004011f0(ppvVar1);
        FUN_00401100(&stack0xffffffc4,pcVar5,pcVar8);
        FUN_0040cda0(*(void **)((int)param_1 + 0x3c),*puVar3,puVar3[0x16],pcVar9,uVar10);
      }
      else {
        curl_easy_strerror();
        FUN_004011f0(puVar3 + 6);
        FUN_00402890("Downloader %d: Download failed (%s). (curl result code:%d - %s) FtpTimeoutSeconds %d (check disk space)"
                     ,(char)*(undefined4 *)((int)param_1 + 0x40));
      }
      local_4._0_1_ = 1;
      local_1c = puVar3;
      FUN_00401170((void **)(puVar3 + 6));
      local_4 = (uint)local_4._1_3_ << 8;
      FUN_00401170(ppvVar1);
      operator_delete(puVar3);
    }
    cVar4 = FUN_00403410((int)param_1);
  }
  local_4 = 0xffffffff;
  FUN_00401170(local_18);
  ExceptionList = local_c;
  return;
}



undefined4 * __thiscall FUN_0040b280(void *this,uint param_1,undefined4 param_2,undefined param_3)

{
  uint *puVar1;
  uint uVar2;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b40c;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *(undefined ***)this = aSynchroQueue2<struct_SRequestVideoInfo*>::vftable;
  FUN_00403890((void *)((int)this + 0xc),0,param_2);
  local_4 = 0;
  FUN_00403890((void *)((int)this + 0x38),param_2,param_2);
  local_4._0_1_ = 1;
  FUN_00403890((void *)((int)this + 100),1,1);
  *(undefined *)((int)this + 0x90) = param_3;
  local_4._0_1_ = 2;
  *(uint *)((int)this + 4) = param_1;
  uVar2 = -(uint)((int)((ulonglong)param_1 * 0xc >> 0x20) != 0) | (uint)((ulonglong)param_1 * 0xc);
  puVar1 = (uint *)operator_new(-(uint)(0xfffffffb < uVar2) | uVar2 + 4);
  local_4 = CONCAT31(local_4._1_3_,3);
  if (puVar1 == (uint *)0x0) {
    *(undefined4 *)((int)this + 8) = 0;
  }
  else {
    *puVar1 = param_1;
    _eh_vector_constructor_iterator_
              (puVar1 + 1,0xc,param_1,(_func_void_void_ptr *)&LAB_0040ae20,FUN_00412c00);
    *(uint **)((int)this + 8) = puVar1 + 1;
  }
  ExceptionList = local_c;
  return (undefined4 *)this;
}



void __fastcall FUN_0040b370(undefined4 *param_1)

{
  int *this;
  int iVar1;
  int *piVar2;
  undefined4 *puVar3;
  void *pvVar4;
  int **ppiVar5;
  int iVar6;
  uint uVar7;
  undefined4 *local_14;
  void *pvStack_10;
  void *local_c;
  undefined4 uStack_8;
  undefined4 local_4;
  
  uStack_8 = &LAB_0041b451;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = aSynchroQueue2<struct_SRequestVideoInfo*>::vftable;
  local_4 = 2;
  local_14 = param_1;
  FUN_004038e0(param_1 + 0x19);
  uVar7 = 0;
  if (param_1[1] != 0) {
    iVar6 = 0;
    do {
      iVar1 = *(int *)(param_1[2] + iVar6);
      while (iVar1 != 0) {
        this = (int *)(param_1[2] + iVar6);
        ppiVar5 = (int **)FUN_00408af0(this,&local_14);
        piVar2 = *ppiVar5;
        if (1 < *this) {
          if (piVar2 == (int *)this[1]) {
            iVar1 = *(int *)this[1];
            this[1] = iVar1;
            *(undefined4 *)(iVar1 + 4) = 0;
          }
          else if (piVar2 == (int *)this[2]) {
            puVar3 = (undefined4 *)((int *)this[2])[1];
            this[2] = (int)puVar3;
            *puVar3 = 0;
          }
          else {
            *(int *)piVar2[1] = *piVar2;
            *(int *)(*piVar2 + 4) = piVar2[1];
          }
        }
        operator_delete(piVar2);
        *this = *this + -1;
        if (*this == 0) {
          this[2] = 0;
          this[1] = 0;
        }
        iVar1 = *(int *)(param_1[2] + iVar6);
      }
      uVar7 = uVar7 + 1;
      iVar6 = iVar6 + 0xc;
    } while (uVar7 < (uint)param_1[1]);
  }
  pvVar4 = (void *)param_1[2];
  if (pvVar4 != (void *)0x0) {
    _eh_vector_destructor_iterator_(pvVar4,0xc,*(int *)((int)pvVar4 + -4),FUN_00412c00);
    operator_delete__((void *)((int)pvVar4 + -4));
  }
  FUN_004038c0(param_1 + 0x19);
  param_1[0x19] = aSyncObj::vftable;
  uStack_8._0_1_ = 1;
  param_1[0x1b] = aMap<int,class_aLocker*>::vftable;
  FUN_00403d00((void **)(param_1 + 0x1c));
  param_1[0xe] = aSyncObj::vftable;
  uStack_8 = (undefined *)((uint)uStack_8._1_3_ << 8);
  param_1[0x10] = aMap<int,class_aLocker*>::vftable;
  FUN_00403d00((void **)(param_1 + 0x11));
  param_1[3] = aSyncObj::vftable;
  uStack_8 = (undefined *)0xffffffff;
  param_1[5] = aMap<int,class_aLocker*>::vftable;
  FUN_00403d00((void **)(param_1 + 6));
  ExceptionList = pvStack_10;
  return;
}



undefined4 * __thiscall FUN_0040b4e0(void *this,byte param_1)

{
  FUN_0040b370((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __fastcall FUN_0040b500(undefined4 *param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b478;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_004032d0(param_1);
  local_4 = 0;
  *param_1 = CDownloaderTask::vftable;
  FUN_0040b280(param_1 + 0x12,1,0,0);
  ExceptionList = local_c;
  return param_1;
}



void __fastcall FUN_0040b560(undefined4 *param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b478;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = CDownloaderTask::vftable;
  local_4 = 0;
  FUN_0040b370(param_1 + 0x12);
  local_4 = 0xffffffff;
  FUN_00403340(param_1);
  ExceptionList = local_c;
  return;
}



undefined4 * __thiscall FUN_0040b5c0(void *this,byte param_1)

{
  FUN_0040b560((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_0040b5e0(LPWSTR param_1,undefined param_2,undefined param_3)

{
  LPCSTR lpMultiByteStr;
  int iVar1;
  LPWSTR lpWideCharStr;
  int cchWideChar;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b4a8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  memset(param_1,0,0x2000);
  cchWideChar = 0x200;
  iVar1 = -1;
  lpWideCharStr = param_1;
  lpMultiByteStr = FUN_004011f0((undefined4 *)&param_3);
  iVar1 = MultiByteToWideChar(0xfde9,0,lpMultiByteStr,iVar1,lpWideCharStr,cchWideChar);
  *(int *)(param_1 + 0x1000) = iVar1;
  local_4 = 0xffffffff;
  FUN_00401170((void **)&param_3);
  ExceptionList = local_c;
  return;
}



undefined4 __fastcall FUN_0040b670(int param_1)

{
  return *(undefined4 *)(param_1 + 0x2000);
}



undefined2 __thiscall FUN_0040b680(void *this,int param_1)

{
  if (*(int *)((int)this + 0x2000) <= param_1) {
    return 0;
  }
  return *(undefined2 *)((int)this + param_1 * 2);
}



int __thiscall FUN_0040b6a0(void *this,int param_1,short param_2)

{
  if (*(int *)((int)this + 0x2000) <= param_1) {
    return -1;
  }
  do {
    if (*(short *)((int)this + param_1 * 2) == param_2) {
      return param_1;
    }
    param_1 = param_1 + 1;
  } while (param_1 < *(int *)((int)this + 0x2000));
  return -1;
}



void ** __cdecl FUN_0040b6e0(void **param_1,int param_2)

{
  void *pvVar1;
  tm *ptVar2;
  void **ppvVar3;
  char *pcVar4;
  int local_2c;
  int local_28;
  void *local_24 [3];
  void *apvStack_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b4f9;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004010a0(param_1);
  local_4 = 0;
  FUN_004010a0(local_24);
  local_4 = 1;
  if (param_2 < 0) {
    param_2 = 0;
  }
  local_28 = param_2 >> 0x1f;
  local_2c = param_2;
  ptVar2 = _localtime64((__time64_t *)&local_2c);
  if (ptVar2->tm_hour < 0xd) {
    pcVar4 = "AM";
  }
  else {
    pcVar4 = "PM";
  }
  FUN_00401040(local_24,pcVar4);
  FUN_004011f0(local_24);
  ppvVar3 = (void **)FUN_004018e0(apvStack_18,"%.2d/%.2d/%.4d %.2d:%.2d:%.2d %s");
  local_4._0_1_ = 2;
  if (*ppvVar3 != *param_1) {
    FUN_00401910(param_1,(uint)ppvVar3[1]);
    memcpy(*param_1,*ppvVar3,(size_t)ppvVar3[1]);
    pvVar1 = ppvVar3[1];
    param_1[1] = pvVar1;
    *(undefined *)((int)pvVar1 + (int)*param_1) = 0;
  }
  local_4._0_1_ = 1;
  FUN_00401170(apvStack_18);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170(local_24);
  ExceptionList = local_c;
  return param_1;
}



void ** __cdecl FUN_0040b820(void **param_1,int param_2)

{
  void *pvVar1;
  void **ppvVar2;
  int local_20;
  int local_1c;
  void *apvStack_18 [3];
  void *local_c;
  undefined *puStack_8;
  uint local_4;
  
  puStack_8 = &LAB_0041b541;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004010a0(param_1);
  local_4 = 0;
  if (param_2 < 0) {
    param_2 = 0;
  }
  local_1c = param_2 >> 0x1f;
  local_20 = param_2;
  _localtime64((__time64_t *)&local_20);
  ppvVar2 = (void **)FUN_004018e0(apvStack_18,"%.2d:%.2d:%.2d");
  local_4 = 1;
  if (*ppvVar2 != *param_1) {
    FUN_00401910(param_1,(uint)ppvVar2[1]);
    memcpy(*param_1,*ppvVar2,(size_t)ppvVar2[1]);
    pvVar1 = ppvVar2[1];
    param_1[1] = pvVar1;
    *(undefined *)((int)pvVar1 + (int)*param_1) = 0;
  }
  local_4 = local_4 & 0xffffff00;
  FUN_00401170(apvStack_18);
  ExceptionList = local_c;
  return param_1;
}



int __thiscall FUN_0040b900(void *this,short param_1)

{
  int iVar1;
  
  if (*(int *)((int)this + 0x2000) < 1) {
    return -1;
  }
  iVar1 = 0;
  do {
    if (*(short *)((int)this + iVar1 * 2) == param_1) {
      return iVar1;
    }
    iVar1 = iVar1 + 1;
  } while (iVar1 < *(int *)((int)this + 0x2000));
  return -1;
}



void __cdecl FUN_0040b930(void **param_1,void *param_2,uint param_3)

{
  void *pvVar1;
  LPCSTR lpMultiByteStr;
  int iVar2;
  void **ppvVar3;
  undefined1 *puVar4;
  int cchWideChar;
  int iVar5;
  WCHAR *lpWideCharStr;
  int iVar6;
  void *local_270;
  uint local_26c;
  undefined4 local_264;
  void **local_260;
  void *apvStack_25c [3];
  WCHAR local_250 [32];
  CHAR aCStack_210 [512];
  uint local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b5a0;
  local_c = ExceptionList;
  local_10 = DAT_00428400 ^ (uint)&local_270;
  ExceptionList = &local_c;
  cchWideChar = 0;
  local_260 = param_1;
  local_264 = 0;
  local_4 = 1;
  FUN_004010a0(param_1);
  local_264 = 1;
  FUN_004010a0(&local_270);
  local_4 = CONCAT31(local_4._1_3_,2);
  if (param_2 != local_270) {
    FUN_00401910(&local_270,param_3);
    memcpy(local_270,param_2,param_3);
    local_26c = param_3;
    *(undefined *)(param_3 + (int)local_270) = 0;
  }
  memset(local_250,0,0x40);
  iVar6 = 0x20;
  lpWideCharStr = local_250;
  iVar5 = -1;
  lpMultiByteStr = FUN_004011f0(&param_2);
  MultiByteToWideChar(0xfde9,0,lpMultiByteStr,iVar5,lpWideCharStr,iVar6);
  iVar5 = 0;
  while ((local_250[0] != L'\0' && (iVar5 < 0x200))) {
    iVar5 = iVar5 + 1;
    local_250[0] = local_250[iVar5];
  }
  if (0 < iVar5) {
    iVar6 = 0;
    do {
      if (0 < DAT_0042b190) {
        iVar2 = 0;
        do {
          if ((&DAT_00429190)[iVar2] == local_250[iVar6]) {
            if (-1 < iVar2) goto LAB_0040ba7f;
            break;
          }
          iVar2 = iVar2 + 1;
        } while (iVar2 < DAT_0042b190);
      }
      local_250[cchWideChar] = local_250[iVar6];
      cchWideChar = cchWideChar + 1;
LAB_0040ba7f:
      iVar6 = iVar6 + 1;
    } while (iVar6 < iVar5);
  }
  memset(aCStack_210,0,0x200);
  WideCharToMultiByte(0xfde9,0,local_250,cchWideChar,aCStack_210,0x20,(LPCSTR)0x0,(LPBOOL)0x0);
  ppvVar3 = FUN_00401100(apvStack_25c,aCStack_210,(char *)0x7fffffff);
  local_4._0_1_ = 3;
  if (*ppvVar3 != *param_1) {
    FUN_00401910(param_1,(uint)ppvVar3[1]);
    memcpy(*param_1,*ppvVar3,(size_t)ppvVar3[1]);
    pvVar1 = ppvVar3[1];
    param_1[1] = pvVar1;
    *(undefined *)((int)pvVar1 + (int)*param_1) = 0;
  }
  local_4._0_1_ = 2;
  FUN_00401170(apvStack_25c);
  FUN_004011f0(param_1);
  puVar4 = FUN_004011f0(&param_2);
  FUN_00402850("ClearLicenseUTF \'%s\' > \'%s\' ",(char)puVar4);
  local_4._0_1_ = 1;
  FUN_00401170(&local_270);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170(&param_2);
  ExceptionList = local_c;
  ___security_check_cookie_4(local_10 ^ (uint)&local_270);
  return;
}



undefined4 __fastcall FUN_0040bb90(int param_1)

{
  return *(undefined4 *)(param_1 + 0x3c);
}



int __fastcall FUN_0040bba0(int param_1)

{
  return param_1 + 0x5c;
}



int __fastcall FUN_0040bbb0(int param_1)

{
  return param_1 + 0x94;
}



undefined4 __fastcall FUN_0040bbc0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x4c);
}



undefined4 __fastcall FUN_0040bbd0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x44);
}



undefined4 __fastcall FUN_0040bbe0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x48);
}



undefined4 __fastcall FUN_0040bbf0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x194);
}



undefined4 __fastcall FUN_0040bc00(int param_1)

{
  return *(undefined4 *)(param_1 + 0x198);
}



undefined __fastcall FUN_0040bc10(int param_1)

{
  return *(undefined *)(param_1 + 0x1a8);
}



undefined4 __fastcall FUN_0040bc20(int param_1)

{
  return *(undefined4 *)(param_1 + 0x1a0);
}



void __fastcall FUN_0040bc30(void **param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b5d8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_00401170(param_1 + 3);
  local_4 = 0xffffffff;
  FUN_00401170(param_1);
  ExceptionList = local_c;
  return;
}



int __fastcall FUN_0040bc90(int param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b616;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_004010a0((undefined4 *)(param_1 + 8));
  local_4 = 0;
  FUN_004010a0((undefined4 *)(param_1 + 0x14));
  local_4 = CONCAT31(local_4._1_3_,1);
  FUN_004118b0((undefined4 *)(param_1 + 0x28));
  ExceptionList = local_c;
  return param_1;
}



void __fastcall FUN_0040bcf0(int param_1)

{
  void *local_c;
  undefined *puStack_8;
  uint local_4;
  
  puStack_8 = &LAB_0041b616;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 1;
  FUN_00411740((int *)(param_1 + 0x28));
  local_4 = local_4 & 0xffffff00;
  FUN_00401170((void **)(param_1 + 0x14));
  local_4 = 0xffffffff;
  FUN_00401170((void **)(param_1 + 8));
  ExceptionList = local_c;
  return;
}



void * FUN_0040bd60(void *param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  void **ppvVar2;
  char *pcVar3;
  void *local_30 [3];
  void *local_24 [3];
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b679;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_004010a0(local_30);
  local_4 = 1;
  if (param_2 == (undefined4 *)0x0) {
    FUN_00401100(param_1,"NULL",(char *)0x7fffffff);
    goto LAB_0040bec5;
  }
  FUN_00401040(local_30,"");
  switch(*param_2) {
  case 0:
    FUN_00411780(param_2 + 10);
    puVar1 = FUN_004117d0(param_2 + 10);
    FUN_004116d0(puVar1);
    ppvVar2 = (void **)FUN_004018e0(local_24,"\'AT_RECOGNITION\' unit:%d carId:%d");
    local_4._0_1_ = 2;
    FUN_00401000(local_30,ppvVar2);
    local_4 = CONCAT31(local_4._1_3_,1);
    FUN_00401170(local_24);
    break;
  case 1:
    pcVar3 = "\'AT_RECOGNITION_RESET\'";
    goto LAB_0040be76;
  case 2:
    FUN_004011f0(param_2 + 5);
    ppvVar2 = (void **)FUN_004018e0(local_18,"\'AT_VIDEO_DOWNLOADED\' \'%s\'");
    local_4._0_1_ = 3;
    FUN_00401000(local_30,ppvVar2);
    local_4 = CONCAT31(local_4._1_3_,1);
    FUN_00401170(local_18);
    break;
  case 3:
    pcVar3 = "\'AT_IMAGE_TIMEOUT\'";
LAB_0040be76:
    FUN_00401040(local_30,pcVar3);
  }
  if (0 < (int)param_2[8]) {
    ppvVar2 = (void **)FUN_004018e0(local_18," EventId:%d");
    local_4._0_1_ = 4;
    FUN_00401200(local_30,ppvVar2);
    local_4 = CONCAT31(local_4._1_3_,1);
    FUN_00401170(local_18);
  }
  FUN_004010b0(param_1,local_30);
LAB_0040bec5:
  local_4 = local_4 & 0xffffff00;
  FUN_00401170(local_30);
  ExceptionList = local_c;
  return param_1;
}



void __thiscall FUN_0040bf00(void *this,int **param_1,int *param_2,void *param_3)

{
  int *piVar1;
  uint uVar2;
  int **ppiVar3;
  
  ppiVar3 = (int **)*param_1;
  *param_2 = (int)ppiVar3[2];
  FUN_004118c0(param_3,ppiVar3 + 3);
  if (*ppiVar3 == (int *)0x0) {
    uVar2 = (int)ppiVar3[1] + 1;
    if (uVar2 < *(uint *)((int)this + 4)) {
                    // WARNING: Load size is inaccurate
      ppiVar3 = (int **)(*this + uVar2 * 4);
      do {
        piVar1 = *ppiVar3;
        if (piVar1 != (int *)0x0) break;
        uVar2 = uVar2 + 1;
        ppiVar3 = ppiVar3 + 1;
      } while (uVar2 < *(uint *)((int)this + 4));
      *param_1 = piVar1;
      return;
    }
  }
  *param_1 = *ppiVar3;
  return;
}



void __thiscall FUN_0040bf60(void *this,int **param_1,int *param_2,int *param_3)

{
  uint uVar1;
  int **ppiVar2;
  int *piVar3;
  
  ppiVar2 = (int **)*param_1;
  *param_2 = (int)ppiVar2[2];
  *param_3 = (int)ppiVar2[3];
  piVar3 = *ppiVar2;
  if (piVar3 == (int *)0x0) {
    uVar1 = (int)ppiVar2[1] + 1;
    if (uVar1 < *(uint *)((int)this + 4)) {
                    // WARNING: Load size is inaccurate
      ppiVar2 = (int **)(*this + uVar1 * 4);
      do {
        piVar3 = *ppiVar2;
        if (piVar3 != (int *)0x0) break;
        uVar1 = uVar1 + 1;
        ppiVar2 = ppiVar2 + 1;
      } while (uVar1 < *(uint *)((int)this + 4));
    }
  }
  *param_1 = piVar3;
  return;
}



void __cdecl FUN_0040bfb0(undefined4 *param_1,int param_2)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b6b1;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  memset(param_1,0,param_2 * 4);
  if (param_2 != 0) {
    do {
      param_2 = param_2 + -1;
      local_4 = 0;
      if (param_1 != (undefined4 *)0x0) {
        FUN_004118b0(param_1);
      }
      param_1 = param_1 + 1;
    } while (param_2 != 0);
  }
  ExceptionList = local_c;
  return;
}



undefined4 __fastcall FUN_0040c030(int param_1)

{
  return *(undefined4 *)(param_1 + 0x1ac);
}



void __fastcall FUN_0040c040(int **param_1)

{
  undefined4 local_8;
  int local_4;
  
  FUN_004118b0(&local_8);
  FUN_0040bf00(param_1[1],param_1,&local_4,&local_8);
  return;
}



void __thiscall FUN_0040c070(void *this,undefined4 *param_1)

{
  *param_1 = *(undefined4 *)((int)this + 8);
  return;
}



void __fastcall FUN_0040c080(void **param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  void *pvVar4;
  
  puVar1 = (undefined4 *)*param_1;
  if ((puVar1 != (undefined4 *)0x0) && (param_1[1] != (void *)0x0)) {
    pvVar4 = param_1[1];
    puVar3 = puVar1;
    do {
      for (puVar2 = (undefined4 *)*puVar3; puVar2 != (undefined4 *)0x0;
          puVar2 = (undefined4 *)*puVar2) {
      }
      puVar3 = puVar3 + 1;
      pvVar4 = (void *)((int)pvVar4 + -1);
    } while (pvVar4 != (void *)0x0);
  }
  operator_delete__(puVar1);
  *param_1 = (void *)0x0;
  param_1[2] = (void *)0x0;
  param_1[3] = (void *)0x0;
  FUN_00402e30((int *)param_1[4]);
  param_1[4] = (void *)0x0;
  return;
}



undefined4 * __fastcall FUN_0040c0e0(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  
  if (*(int *)(param_1 + 0xc) == 0) {
    iVar3 = FUN_00402e10((undefined4 *)(param_1 + 0x10),*(int *)(param_1 + 0x14),0x10);
    iVar1 = *(int *)(param_1 + 0x14);
    puVar4 = (undefined4 *)(iVar3 + -0xc + iVar1 * 0x10);
    while (iVar1 = iVar1 + -1, -1 < iVar1) {
      *puVar4 = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 **)(param_1 + 0xc) = puVar4;
      puVar4 = puVar4 + -4;
    }
  }
  puVar4 = *(undefined4 **)(param_1 + 0xc);
  uVar2 = *puVar4;
  *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  *(undefined4 *)(param_1 + 0xc) = uVar2;
  puVar4[2] = 0;
  FUN_0040bfb0(puVar4 + 3,1);
  return puVar4;
}



undefined4 * __fastcall FUN_0040c150(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  
  if (*(int *)(param_1 + 0xc) == 0) {
    iVar3 = FUN_00402e10((undefined4 *)(param_1 + 0x10),*(int *)(param_1 + 0x14),0x18);
    iVar1 = *(int *)(param_1 + 0x14);
    puVar4 = (undefined4 *)(iVar3 + -0x14 + iVar1 * 0x18);
    while (iVar1 = iVar1 + -1, -1 < iVar1) {
      *puVar4 = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 **)(param_1 + 0xc) = puVar4;
      puVar4 = puVar4 + -6;
    }
  }
  puVar4 = *(undefined4 **)(param_1 + 0xc);
  uVar2 = *puVar4;
  *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  *(undefined4 *)(param_1 + 0xc) = uVar2;
  puVar4[2] = 0;
  FUN_00406a40(puVar4 + 3,1);
  return puVar4;
}



char __thiscall FUN_0040c1c0(void *this,void *param_1)

{
  bool bVar1;
  tm *ptVar2;
  void **ppvVar3;
  uint uVar4;
  void *pvVar5;
  undefined4 *puVar6;
  undefined4 uVar7;
  int **ppiVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  uint uVar12;
  tm *ptVar13;
  __time64_t _Var14;
  longlong lVar15;
  longlong lVar16;
  void *pvVar17;
  char local_85;
  int local_84;
  undefined4 local_80;
  int local_7c;
  undefined4 local_78;
  int local_74;
  int local_70 [2];
  int *local_68;
  int *local_64;
  tm local_5c;
  tm local_34;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b6e0;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_004118b0(&local_84);
  FUN_00402fc0(&local_5c);
  ptVar2 = FUN_00403080(&local_34);
  ptVar13 = &local_5c;
  for (iVar9 = 10; iVar9 != 0; iVar9 = iVar9 + -1) {
    ptVar13->tm_sec = ptVar2->tm_sec;
    ptVar2 = (tm *)&ptVar2->tm_min;
    ptVar13 = (tm *)&ptVar13->tm_min;
  }
  ppvVar3 = FUN_0040b820(&local_68,*(int *)((int)this + 0x1b8));
  local_4 = 0;
  FUN_004011f0(ppvVar3);
  FUN_00402870("Lane::MakeTrigger %d SbLaneIdsList.Count:%d   LastTriggerTimestamp:(%s.%.3d)",
               (char)*(undefined4 *)((int)this + 0x3c));
  local_4 = 0xffffffff;
  FUN_00401170(&local_68);
  if (1 < *(int *)((int)this + 0x1ac)) {
    _Var14 = FUN_00403040(&local_5c);
    lVar15 = __allmul((uint)_Var14,(int)(uint)_Var14 >> 0x1f,1000,0);
    local_64 = (int *)((ulonglong)lVar15 >> 0x20);
    uVar4 = FUN_00403030((int)&local_5c);
    uVar12 = uVar4 + (uint)lVar15;
    iVar9 = ((int)uVar4 >> 0x1f) + (int)local_64;
    lVar16 = __allmul(*(uint *)((int)this + 0x1b8),(int)*(uint *)((int)this + 0x1b8) >> 0x1f,1000,0)
    ;
    lVar16 = lVar16 + *(int *)((int)this + 0x1bc);
    uVar10 = (uint)lVar16;
    iVar11 = (int)*(uint *)((int)this + 0x1a4) >> 0x1f;
    iVar9 = ((iVar9 + (uint)CARRY4(uVar4,(uint)lVar15)) - (int)((ulonglong)lVar16 >> 0x20)) -
            (uint)(uVar12 < uVar10);
    if ((iVar9 <= iVar11) && ((iVar9 < iVar11 || (uVar12 - uVar10 < *(uint *)((int)this + 0x1a4)))))
    {
      FUN_00402890("Lane::MakeTrigger %d Too recent trigger, ignore request",
                   (char)*(undefined4 *)((int)this + 0x3c));
      FUN_004164a0(param_1,*(int *)((int)this + 0x3c) * 10000 + *(int *)((int)this + 0x58));
      FUN_004164f0(param_1,1);
      pvVar17 = param_1;
      pvVar5 = (void *)FUN_004164d0((int)param_1);
      FUN_00419f90(pvVar5,(int)pvVar17);
      FUN_00402f40(&local_74,(int)this + 0x14c);
      uVar7 = *(undefined4 *)((int)this + 0x148);
      local_4 = 1;
      puVar6 = (undefined4 *)operator_new(0xc);
      puVar6[1] = uVar7;
      *puVar6 = 0;
      puVar6[2] = param_1;
      if (*(undefined4 **)((int)this + 0x148) == (undefined4 *)0x0) {
        *(undefined4 **)((int)this + 0x144) = puVar6;
      }
      else {
        **(undefined4 **)((int)this + 0x148) = puVar6;
      }
      *(int *)((int)this + 0x140) = *(int *)((int)this + 0x140) + 1;
      *(undefined4 **)((int)this + 0x148) = puVar6;
      FUN_00402870("Lane %d , MakeTrigger \'%d\' reuse trigger.",
                   (char)*(undefined4 *)((int)this + 0x3c));
      local_4 = 0xffffffff;
      FUN_00402f90(&local_74);
      ExceptionList = local_c;
      return '\0';
    }
    FUN_00402870("Lane::MakeTrigger %d allowed new trigger request. (ReuseSoftwareTriggerMs:%d)",
                 (char)*(undefined4 *)((int)this + 0x3c));
  }
  local_85 = '\0';
  *(int *)((int)this + 0x58) = *(int *)((int)this + 0x58) + 1;
  if (9999 < *(int *)((int)this + 0x58)) {
    *(undefined4 *)((int)this + 0x58) = 1;
  }
  iVar9 = *(int *)((int)this + 0x3c) * 10000 + *(int *)((int)this + 0x58);
  local_7c = iVar9;
  FUN_004164a0(param_1,iVar9);
  FUN_00402870("Lane %d , MakeTrigger TriggerId:%d ...",(char)*(undefined4 *)((int)this + 0x3c));
  _Var14 = FUN_00403040(&local_5c);
  *(int *)((int)this + 0x1b8) = (int)_Var14;
  uVar7 = FUN_00403030((int)&local_5c);
  *(undefined4 *)((int)this + 0x1bc) = uVar7;
  ppiVar8 = (int **)FUN_00414e00((void *)((int)this + 0x5c),local_70);
  local_68 = *ppiVar8;
  local_64 = ppiVar8[1];
  while( true ) {
    if (local_64 == (int *)0x0) {
      ExceptionList = local_c;
      return local_85;
    }
    if (local_68 == (int *)0x0) {
      ExceptionList = local_c;
      return local_85;
    }
    FUN_004118c0(&local_80,local_68 + 3);
    FUN_004118c0(&local_84,&local_80);
    bVar1 = FUN_00412880(&local_84);
    if (!bVar1) {
      FUN_00402890("Lane %d , MakeTrigger Invalid unit",(char)*(undefined4 *)((int)this + 0x3c));
      ExceptionList = local_c;
      return local_85;
    }
    bVar1 = FUN_004116e0(&local_84,iVar9);
    if (!bVar1) break;
    if (local_85 == '\0') {
      pvVar17 = param_1;
      pvVar5 = (void *)FUN_004164d0((int)param_1);
      FUN_00419f90(pvVar5,(int)pvVar17);
      FUN_00402ed0((int)this + 0x14c);
      FUN_004164f0(param_1,1);
      uVar7 = *(undefined4 *)((int)this + 0x148);
      puVar6 = (undefined4 *)operator_new(0xc);
      puVar6[1] = uVar7;
      *puVar6 = 0;
      puVar6[2] = param_1;
      if (*(undefined4 **)((int)this + 0x148) == (undefined4 *)0x0) {
        *(undefined4 **)((int)this + 0x144) = puVar6;
      }
      else {
        **(undefined4 **)((int)this + 0x148) = puVar6;
      }
      *(int *)((int)this + 0x140) = *(int *)((int)this + 0x140) + 1;
      *(undefined4 **)((int)this + 0x148) = puVar6;
      FUN_00402f10((int)this + 0x14c);
      iVar9 = local_7c;
    }
    local_85 = '\x01';
    FUN_004116d0(&local_84);
    FUN_00402870("Lane %d , MakeTrigger  Unit:%d  TriggerId:%d \' done",
                 (char)*(undefined4 *)((int)this + 0x3c));
    FUN_004118b0(&local_78);
    FUN_0040bf00(local_64,&local_68,local_70,&local_78);
  }
  FUN_004116d0(&local_84);
  FUN_00402890("Lane %d , MakeTrigger  Unit:%d  TriggerId:%d  Fails",
               (char)*(undefined4 *)((int)this + 0x3c));
  ExceptionList = local_c;
  return local_85;
}



void __thiscall FUN_0040c5c0(void *this,void *param_1)

{
  undefined4 uVar1;
  void *this_00;
  void *this_01;
  undefined4 *puVar2;
  void **ppvVar3;
  void *pvVar4;
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  this_00 = param_1;
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b720;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_004164a0(param_1,0);
  FUN_004164f0(this_00,1);
  pvVar4 = this_00;
  this_01 = (void *)FUN_004164d0((int)this_00);
  FUN_00419f90(this_01,(int)pvVar4);
  FUN_00402f40(&param_1,(int)this + 0x14c);
  uVar1 = *(undefined4 *)((int)this + 0x148);
  local_4 = 0;
  puVar2 = (undefined4 *)operator_new(0xc);
  puVar2[1] = uVar1;
  *puVar2 = 0;
  puVar2[2] = this_00;
  if (*(undefined4 **)((int)this + 0x148) == (undefined4 *)0x0) {
    *(undefined4 **)((int)this + 0x144) = puVar2;
  }
  else {
    **(undefined4 **)((int)this + 0x148) = puVar2;
  }
  *(int *)((int)this + 0x140) = *(int *)((int)this + 0x140) + 1;
  *(undefined4 **)((int)this + 0x148) = puVar2;
  ppvVar3 = FUN_004165c0(this_00,local_18);
  local_4._0_1_ = 1;
  FUN_004011f0(ppvVar3);
  FUN_00402850("Lane %d AppendPendingWebServerRequest:%s  (PendingWebRequests.Count:%d)",
               (char)*(undefined4 *)((int)this + 0x3c));
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170(local_18);
  local_4 = 0xffffffff;
  FUN_00402f90((int *)&param_1);
  ExceptionList = local_c;
  return;
}



uint __thiscall FUN_0040c6d0(void *this,int param_1)

{
  int **ppiVar1;
  uint uVar2;
  undefined4 uVar3;
  int local_14;
  undefined4 local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b748;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_00402f40(&local_14,(int)this + 0x14c);
  ppiVar1 = (int **)FUN_00408af0((void *)((int)this + 0x140),&local_10);
  ppiVar1 = (int **)*ppiVar1;
  while( true ) {
    if (ppiVar1 == (int **)0x0) {
      local_4 = 0xffffffff;
      uVar2 = FUN_00402f90(&local_14);
      ExceptionList = local_c;
      return uVar2 & 0xffffff00;
    }
    if (ppiVar1[2] == (int *)param_1) break;
    ppiVar1 = (int **)*ppiVar1;
  }
  FUN_0040ae30((void *)((int)this + 0x140),(int *)ppiVar1);
  local_4 = 0xffffffff;
  uVar3 = FUN_00402f90(&local_14);
  ExceptionList = local_c;
  return CONCAT31((int3)((uint)uVar3 >> 8),1);
}



void * __thiscall FUN_0040c790(void *this,void *param_1,int param_2)

{
  undefined4 *puVar1;
  int iVar2;
  
  iVar2 = param_2;
  if (*(int *)((int)this + 0x1ac) <= param_2) {
    FUN_00402890("Lane %d GetSbLaneId invalid position list %d (List.Count:%d)",
                 (char)*(undefined4 *)((int)this + 0x3c));
    FUN_00401100(param_1,"",(char *)0x7fffffff);
    return param_1;
  }
  puVar1 = (undefined4 *)FUN_00405b60((void *)((int)this + 0x1ac),&param_2);
  puVar1 = (undefined4 *)*puVar1;
  if (0 < iVar2) {
    do {
      puVar1 = (undefined4 *)*puVar1;
      iVar2 = iVar2 + -1;
    } while (0 < iVar2);
  }
  FUN_004010b0(param_1,(void **)(puVar1 + 2));
  return param_1;
}



void __thiscall FUN_0040c810(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  void *local_4;
  
  local_4 = this;
  puVar2 = (undefined4 *)FUN_0040c070((void *)((int)this + 0x20),&local_4);
  uVar1 = *puVar2;
  param_1[1] = (int)this + 4;
  *param_1 = uVar1;
  return;
}



uint __thiscall FUN_0040c840(void *this,int param_1)

{
  int *piVar1;
  int *piVar2;
  char cVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  undefined4 unaff_retaddr;
  
  piVar1 = (int *)((int)this + 0x38);
  FUN_004038e0(piVar1);
  cVar3 = FUN_004038c0((int *)((int)this + 0xc));
  if (cVar3 == '\0') {
    uVar4 = FUN_004038c0(piVar1);
    return uVar4 & 0xffffff00;
  }
  uVar6 = *(undefined4 *)(*(int *)((int)this + 8) + 8 + param_1 * 0xc);
  piVar2 = (int *)(*(int *)((int)this + 8) + param_1 * 0xc);
  puVar5 = (undefined4 *)operator_new(0xc);
  puVar5[1] = uVar6;
  *puVar5 = 0;
  puVar5[2] = unaff_retaddr;
  if ((undefined4 *)piVar2[2] != (undefined4 *)0x0) {
    *(undefined4 *)piVar2[2] = puVar5;
    *piVar2 = *piVar2 + 1;
    piVar2[2] = (int)puVar5;
    uVar6 = FUN_004038c0(piVar1);
    return CONCAT31((int3)((uint)uVar6 >> 8),1);
  }
  *piVar2 = *piVar2 + 1;
  piVar2[1] = (int)puVar5;
  piVar2[2] = (int)puVar5;
  uVar6 = FUN_004038c0(piVar1);
  return CONCAT31((int3)((uint)uVar6 >> 8),1);
}



uint __thiscall FUN_0040c8d0(void *this,int *param_1,DWORD param_2)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int **ppiVar5;
  undefined4 uVar6;
  int *piVar7;
  int local_24;
  int *local_20;
  undefined4 local_1c [4];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b388;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_24 = (int)this + 0xc;
  piVar1 = (int *)((int)this + 0x38);
  local_20 = piVar1;
  FUN_00403d60(local_1c,&local_24,2,1);
  local_4 = 0;
  iVar2 = FUN_00403e00(local_1c,param_2);
  if (-1 < iVar2) {
    uVar4 = *(uint *)((int)this + 4);
    uVar3 = 0;
    if (uVar4 != 0) {
      piVar7 = *(int **)((int)this + 8);
      do {
        if (*piVar7 != 0) break;
        uVar3 = uVar3 + 1;
        piVar7 = piVar7 + 3;
      } while (uVar3 < uVar4);
    }
    if (uVar3 != uVar4) {
      ppiVar5 = (int **)FUN_00408af0((void *)(*(int *)((int)this + 8) + uVar3 * 0xc),&param_2);
      piVar7 = *ppiVar5;
      *param_1 = piVar7[2];
      FUN_0040ae30((void *)(*(int *)((int)this + 8) + uVar3 * 0xc),piVar7);
      FUN_004038c0(piVar1);
      local_4 = 0xffffffff;
      uVar6 = FUN_00403de0(local_1c);
      ExceptionList = local_c;
      return CONCAT31((int3)((uint)uVar6 >> 8),1);
    }
    FUN_004038c0(piVar1);
  }
  local_4 = 0xffffffff;
  uVar4 = FUN_00403de0(local_1c);
  ExceptionList = local_c;
  return uVar4 & 0xffffff00;
}



undefined4 * __thiscall FUN_0040c9e0(void *this,uint param_1)

{
  uint uVar1;
  void *_Dst;
  undefined4 *puVar2;
  uint uVar3;
  
  uVar1 = *(uint *)((int)this + 4);
  uVar3 = (param_1 >> 4) % uVar1;
                    // WARNING: Load size is inaccurate
  if (*this == 0) {
    _Dst = operator_new(-(uint)((int)((ulonglong)uVar1 * 4 >> 0x20) != 0) |
                        (uint)((ulonglong)uVar1 * 4));
    *(void **)this = _Dst;
    memset(_Dst,0,uVar1 * 4);
    *(uint *)((int)this + 4) = uVar1;
  }
  else {
    for (puVar2 = *(undefined4 **)(*this + uVar3 * 4); puVar2 != (undefined4 *)0x0;
        puVar2 = (undefined4 *)*puVar2) {
      if (puVar2[2] == param_1) goto LAB_0040ca5b;
    }
  }
  puVar2 = FUN_0040c0e0((int)this);
  puVar2[1] = uVar3;
  puVar2[2] = param_1;
                    // WARNING: Load size is inaccurate
  *puVar2 = *(undefined4 *)(*this + uVar3 * 4);
                    // WARNING: Load size is inaccurate
  *(undefined4 **)(*this + uVar3 * 4) = puVar2;
LAB_0040ca5b:
  return puVar2 + 3;
}



undefined4 * __thiscall FUN_0040ca70(void *this,uint param_1)

{
  uint uVar1;
  void *_Dst;
  undefined4 *puVar2;
  uint uVar3;
  
  uVar1 = *(uint *)((int)this + 4);
  uVar3 = (param_1 >> 4) % uVar1;
                    // WARNING: Load size is inaccurate
  if (*this == 0) {
    _Dst = operator_new(-(uint)((int)((ulonglong)uVar1 * 4 >> 0x20) != 0) |
                        (uint)((ulonglong)uVar1 * 4));
    *(void **)this = _Dst;
    memset(_Dst,0,uVar1 * 4);
    *(uint *)((int)this + 4) = uVar1;
  }
  else {
    for (puVar2 = *(undefined4 **)(*this + uVar3 * 4); puVar2 != (undefined4 *)0x0;
        puVar2 = (undefined4 *)*puVar2) {
      if (puVar2[2] == param_1) goto LAB_0040caeb;
    }
  }
  puVar2 = FUN_0040c150((int)this);
  puVar2[1] = uVar3;
  puVar2[2] = param_1;
                    // WARNING: Load size is inaccurate
  *puVar2 = *(undefined4 *)(*this + uVar3 * 4);
                    // WARNING: Load size is inaccurate
  *(undefined4 **)(*this + uVar3 * 4) = puVar2;
LAB_0040caeb:
  return puVar2 + 3;
}



void __fastcall FUN_0040cb00(void **param_1)

{
  undefined4 *puVar1;
  void *pvVar2;
  
  if ((*param_1 != (void *)0x0) && (pvVar2 = (void *)0x0, param_1[1] != (void *)0x0)) {
    do {
      for (puVar1 = *(undefined4 **)((int)*param_1 + (int)pvVar2 * 4); puVar1 != (undefined4 *)0x0;
          puVar1 = (undefined4 *)*puVar1) {
        FUN_00401170((void **)(puVar1 + 3));
      }
      pvVar2 = (void *)((int)pvVar2 + 1);
    } while (pvVar2 < param_1[1]);
  }
  operator_delete__(*param_1);
  *param_1 = (void *)0x0;
  param_1[2] = (void *)0x0;
  param_1[3] = (void *)0x0;
  FUN_00402e30((int *)param_1[4]);
  param_1[4] = (void *)0x0;
  return;
}



void __fastcall FUN_0040cb70(int param_1,undefined param_2,undefined param_3)

{
  undefined4 *_Dst;
  undefined4 *puVar1;
  void *local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined2 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined2 local_14;
  uint local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b783;
  local_c = ExceptionList;
  local_10 = DAT_00428400 ^ (uint)&local_5c;
  ExceptionList = &local_c;
  local_4 = 0;
  local_5c = operator_new(0x2c);
  local_4._0_1_ = 1;
  if (local_5c == (void *)0x0) {
    _Dst = (undefined4 *)0x0;
  }
  else {
    _Dst = (undefined4 *)FUN_0040bc90((int)local_5c);
  }
  local_4 = (uint)local_4._1_3_ << 8;
  memset(_Dst,0,0x2c);
  *_Dst = 0;
  FUN_00411750(_Dst + 10,(int *)&param_3);
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  local_28 = 0;
  local_24 = 0;
  local_20 = 0;
  local_1c = 0;
  local_18 = 0;
  local_14 = 0;
  local_58 = 0;
  local_54 = 0;
  local_50 = 0;
  local_4c = 0;
  local_48 = 0;
  local_44 = 0;
  local_40 = 0;
  local_3c = 0;
  local_38 = 0;
  FUN_004117f0(&param_3,&local_34,0x22);
  FUN_004117a0(&param_3,&local_58,0x22);
  FUN_00411780((undefined4 *)&param_3);
  puVar1 = FUN_004117d0((undefined4 *)&param_3);
  FUN_004116d0(puVar1);
  FUN_00402870("Lane %d OnCarHandled unit:%d car:%d \'%s\' country:%s",
               (char)*(undefined4 *)(param_1 + 0x3c));
  FUN_0040c840((void *)(param_1 + 0xdc),(int)_Dst);
  local_4 = 0xffffffff;
  FUN_00411740((int *)&param_3);
  ExceptionList = local_c;
  ___security_check_cookie_4(local_10 ^ (uint)&local_5c);
  return;
}



void __fastcall FUN_0040cce0(int param_1,undefined param_2,undefined param_3)

{
  void *pvVar1;
  undefined4 *_Dst;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b7c3;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  if (*(char *)(param_1 + 0x1a9) != '\0') {
    FUN_00411780((undefined4 *)&param_3);
    FUN_00402870("Lane %d OnCarDeparture car:%d. Raise event.",(char)*(undefined4 *)(param_1 + 0x3c)
                );
    pvVar1 = operator_new(0x2c);
    local_4._0_1_ = 1;
    if (pvVar1 == (void *)0x0) {
      _Dst = (undefined4 *)0x0;
    }
    else {
      _Dst = (undefined4 *)FUN_0040bc90((int)pvVar1);
    }
    local_4 = (uint)local_4._1_3_ << 8;
    memset(_Dst,0,0x2c);
    *_Dst = 1;
    FUN_0040c840((void *)(param_1 + 0xdc),(int)_Dst);
  }
  local_4 = 0xffffffff;
  FUN_00411740((int *)&param_3);
  ExceptionList = local_c;
  return;
}



void __thiscall
FUN_0040cda0(void *this,undefined4 param_1,undefined4 param_2,void *param_3,uint param_4)

{
  void **this_00;
  char cVar1;
  void *pvVar2;
  undefined4 *_Dst;
  undefined4 *puVar3;
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b7fb;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  cVar1 = FUN_00403410((int)this);
  if (cVar1 == '\0') {
    pvVar2 = operator_new(0x2c);
    local_4._0_1_ = 1;
    if (pvVar2 == (void *)0x0) {
      _Dst = (undefined4 *)0x0;
    }
    else {
      _Dst = (undefined4 *)FUN_0040bc90((int)pvVar2);
    }
    local_4 = (uint)local_4._1_3_ << 8;
    memset(_Dst,0,0x2c);
    *_Dst = 2;
    this_00 = (void **)(_Dst + 5);
    if (param_3 != *this_00) {
      FUN_00401910(this_00,param_4);
      memcpy(*this_00,param_3,param_4);
      _Dst[6] = param_4;
      *(undefined *)(param_4 + (int)*this_00) = 0;
    }
    _Dst[8] = param_1;
    _Dst[9] = param_2;
    puVar3 = (undefined4 *)FUN_0040bd60(local_18,_Dst);
    local_4._0_1_ = 2;
    FUN_004011f0(puVar3);
    FUN_004011f0(&param_3);
    FUN_00402870("Lane %d EnqueueVideoDownload ev:%d \'%s\' (%s)",
                 (char)*(undefined4 *)((int)this + 0x3c));
    local_4 = (uint)local_4._1_3_ << 8;
    FUN_00401170(local_18);
    FUN_0040c840((void *)((int)this + 0xdc),(int)_Dst);
  }
  local_4 = 0xffffffff;
  FUN_00401170(&param_3);
  ExceptionList = local_c;
  return;
}



void __thiscall FUN_0040cee0(void *this,undefined4 param_1,undefined4 param_2)

{
  char cVar1;
  void *pvVar2;
  undefined4 *_Dst;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b82b;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  cVar1 = FUN_00403410((int)this);
  if (cVar1 == '\0') {
    pvVar2 = operator_new(0x2c);
    local_4 = 0;
    if (pvVar2 == (void *)0x0) {
      _Dst = (undefined4 *)0x0;
    }
    else {
      _Dst = (undefined4 *)FUN_0040bc90((int)pvVar2);
    }
    local_4 = 0xffffffff;
    memset(_Dst,0,0x2c);
    *_Dst = param_2;
    _Dst[8] = param_1;
    FUN_00402870("Lane %d EnqueueTimeout ev:%d",(char)*(undefined4 *)((int)this + 0x3c));
    FUN_0040c840((void *)((int)this + 0xdc),(int)_Dst);
  }
  ExceptionList = local_c;
  return;
}



undefined4 __thiscall FUN_0040cf90(void *this,uint param_1)

{
  char cVar1;
  undefined4 *puVar2;
  
  cVar1 = FUN_00403410((int)this);
  if (cVar1 == '\0') {
    puVar2 = (undefined4 *)0x0;
    if (*(int *)((int)this + 0x98) != 0) {
      for (puVar2 = *(undefined4 **)
                     (*(int *)((int)this + 0x98) +
                     ((param_1 >> 4) % *(uint *)((int)this + 0x9c)) * 4);
          puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
        if (puVar2[2] == param_1) goto LAB_0040cfd6;
      }
      puVar2 = (undefined4 *)0x0;
    }
LAB_0040cfd6:
    if ((this != (void *)0xffffff68) && (puVar2 != (undefined4 *)0x0)) {
      return puVar2[3];
    }
  }
  return 0;
}



void __fastcall FUN_0040cff0(int param_1)

{
  FUN_0040c840((void *)(param_1 + 0xdc),0);
  return;
}



void __fastcall FUN_0040d000(undefined4 *param_1)

{
  *param_1 = aMap<int,class_SmartLprAIO::Unit>::vftable;
  FUN_0040c080((void **)(param_1 + 1));
  return;
}



void __fastcall FUN_0040d010(undefined4 *param_1)

{
  *param_1 = aMap<int,class_CUnitREC*>::vftable;
  FUN_0040c080((void **)(param_1 + 1));
  return;
}



undefined4 __fastcall FUN_0040d020(int *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = *(int *)(param_1[1] + 4);
  if (iVar1 != 0) {
    for (puVar2 = *(undefined4 **)
                   (iVar1 + ((*(uint *)(*param_1 + 8) >> 4) % *(uint *)(param_1[1] + 8)) * 4);
        puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
      if (puVar2[2] == *(uint *)(*param_1 + 8)) {
        return puVar2[3];
      }
    }
  }
  return uRam0000000c;
}



undefined4 * __thiscall FUN_0040d060(void *this,byte param_1)

{
  *(undefined ***)this = aMap<int,class_SmartLprAIO::Unit>::vftable;
  FUN_0040c080((void **)((int)this + 4));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_0040d090(void *this,byte param_1)

{
  *(undefined ***)this = aMap<int,class_CUnitREC*>::vftable;
  FUN_0040c080((void **)((int)this + 4));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_0040d0c0(void *this,byte param_1)

{
  *(undefined ***)this = aMap<int,class_CCarData*>::vftable;
  FUN_0040c080((void **)((int)this + 4));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __thiscall FUN_0040d0f0(void *this,uint param_1,void *param_2,void *param_3)

{
  void **this_00;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c208;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  this_00 = (void **)FUN_0040ca70(this,param_1);
  if (param_2 != *this_00) {
    FUN_00401910(this_00,(uint)param_3);
    memcpy(*this_00,param_2,(size_t)param_3);
    this_00[1] = param_3;
    *(undefined *)((int)param_3 + (int)*this_00) = 0;
  }
  local_4 = 0xffffffff;
  FUN_00401170(&param_2);
  ExceptionList = local_c;
  return;
}



int __thiscall FUN_0040d190(void *this,int param_1)

{
  int iVar1;
  char cVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  char *pcVar9;
  undefined uVar10;
  int local_20;
  undefined4 local_1c;
  int local_18;
  undefined4 local_14 [2];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b858;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_00402f40(&local_20,(int)this + 0x170);
  local_4 = 0;
  if (param_1 < 1) {
    if (*(char *)((int)this + 0x19c) == '\0') {
      piVar6 = (int *)FUN_0040c810((void *)((int)this + 0xb0),local_14);
      iVar1 = piVar6[1];
      for (iVar5 = *piVar6; iVar5 != 0; iVar5 = *(int *)(iVar5 + 4)) {
        iVar7 = *(int *)(iVar1 + 4);
        if (iVar7 != 0) {
          for (puVar3 = *(undefined4 **)
                         (iVar7 + ((*(uint *)(iVar5 + 8) >> 4) % *(uint *)(iVar1 + 8)) * 4);
              puVar3 != (undefined4 *)0x0; puVar3 = (undefined4 *)*puVar3) {
            if (puVar3[2] == *(uint *)(iVar5 + 8)) goto LAB_0040d37d;
          }
        }
        puVar3 = (undefined4 *)0x0;
LAB_0040d37d:
        iVar7 = puVar3[3];
        cVar2 = FUN_004087a0(iVar7);
        if (cVar2 == '\0') {
          FUN_004087a0(iVar7);
          FUN_004087d0(iVar7);
          FUN_00402890("Lane %d GetCarData(triggerId:%d) found carData evId %d. Avoid because is invalidated (isValid:%d). ReuseRecognition:%d."
                       ,(char)*(undefined4 *)((int)this + 0x3c));
        }
        else {
          iVar8 = FUN_00408820(iVar7);
          if ((*(int *)(iVar8 + 0x20) < 1) || (*(char *)((int)this + 0x19c) != '\0'))
          goto LAB_0040d2ab;
          FUN_004087d0(iVar7);
          FUN_00402890("Lane %d GetCarData found carData evId %d. Avoid because already associated with S&B Request (ReuseRecognition:%s)"
                       ,(char)*(undefined4 *)((int)this + 0x3c));
        }
      }
    }
    else if (0 < *(int *)((int)this + 0xd0)) {
      piVar6 = (int *)FUN_0040c810((void *)((int)this + 0xb0),&local_1c);
      iVar7 = FUN_0040d020(piVar6);
      cVar2 = FUN_004087a0(iVar7);
      if (cVar2 != '\0') {
LAB_0040d2ab:
        local_4 = 0xffffffff;
        FUN_00402f90(&local_20);
        ExceptionList = local_c;
        return iVar7;
      }
      FUN_004087a0(iVar7);
      FUN_004087d0(iVar7);
      FUN_00402890("Lane %d GetCarData(triggerId:%d) found last carData evId %d. Avoid because is invalidated (isValid:%d). ReuseRecognition:%d."
                   ,(char)*(undefined4 *)((int)this + 0x3c));
    }
  }
  else {
    puVar3 = (undefined4 *)FUN_00409310((void *)((int)this + 0xb0),&local_1c);
    local_18 = puVar3[1];
    for (puVar3 = (undefined4 *)*puVar3; puVar3 != (undefined4 *)0x0; puVar3 = (undefined4 *)*puVar3
        ) {
      if (*(int *)(local_18 + 4) != 0) {
        for (puVar4 = *(undefined4 **)
                       (*(int *)(local_18 + 4) +
                       (((uint)puVar3[2] >> 4) % *(uint *)(local_18 + 8)) * 4);
            puVar4 != (undefined4 *)0x0; puVar4 = (undefined4 *)*puVar4) {
          if (puVar4[2] == puVar3[2]) goto LAB_0040d22d;
        }
      }
      puVar4 = (undefined4 *)0x0;
LAB_0040d22d:
      iVar7 = puVar4[3];
      iVar5 = FUN_00408de0(iVar7);
      if (iVar5 == param_1) {
        cVar2 = FUN_004087a0(iVar7);
        if (cVar2 == '\0') {
          FUN_004087a0(iVar7);
          FUN_004087d0(iVar7);
          uVar10 = (undefined)*(undefined4 *)((int)this + 0x3c);
          pcVar9 = 
          "Lane %d GetCarData(triggerId:%d) found carData evId %d. Avoid because is invalidated (isValid:%d)"
          ;
        }
        else {
          iVar5 = FUN_00408820(iVar7);
          if ((*(int *)(iVar5 + 0x20) < 1) || (*(char *)((int)this + 0x19c) != '\0'))
          goto LAB_0040d2ab;
          FUN_004087d0(iVar7);
          uVar10 = (undefined)*(undefined4 *)((int)this + 0x3c);
          pcVar9 = 
          "Lane %d GetCarData(triggerId:%d) found carData evId %d. Avoid because already associated with S&B Request (ReuseRecognition:%s)"
          ;
        }
        FUN_00402890(pcVar9,uVar10);
      }
    }
  }
  local_4 = 0xffffffff;
  FUN_00402f90(&local_20);
  ExceptionList = local_c;
  return 0;
}



void __thiscall FUN_0040d430(void *this,uint param_1)

{
  undefined4 *this_00;
  void **ppvVar1;
  void *local_4;
  
  local_4 = this;
  FUN_004118c0(&local_4,(undefined4 *)&stack0x00000008);
  ppvVar1 = &local_4;
  this_00 = FUN_0040c9e0((void *)((int)this + 4),param_1);
  FUN_004118c0(this_00,ppvVar1);
  return;
}



void __fastcall FUN_0040d460(undefined4 *param_1)

{
  *param_1 = aMap<int,class_aString>::vftable;
  FUN_0040cb00((void **)(param_1 + 1));
  return;
}



void __thiscall FUN_0040d470(void *this,uint param_1)

{
  void *in_stack_ffffffdc;
  void *in_stack_ffffffe0;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c8f8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004010b0(&stack0xffffffdc,(void **)&stack0x00000008);
  FUN_0040d0f0((void *)((int)this + 4),param_1,in_stack_ffffffdc,in_stack_ffffffe0);
  local_4 = 0xffffffff;
  FUN_00401170((void **)&stack0x00000008);
  ExceptionList = local_c;
  return;
}



void __fastcall FUN_0040d4e0(undefined4 *param_1)

{
  *param_1 = aCollection<int,class_CCarData*>::vftable;
  FUN_00412c00(param_1 + 8);
  param_1[1] = aMap<int,class_CCarData*>::vftable;
  FUN_0040c080((void **)(param_1 + 2));
  return;
}



uint __thiscall FUN_0040d510(void *this,int *param_1)

{
  int *piVar1;
  uint in_EAX;
  undefined4 *puVar2;
  
  piVar1 = param_1;
  if (*(int *)((int)this + 8) != 0) {
    in_EAX = ((uint)param_1 >> 4) / *(uint *)((int)this + 0xc);
    for (puVar2 = *(undefined4 **)
                   (*(int *)((int)this + 8) +
                   (((uint)param_1 >> 4) % *(uint *)((int)this + 0xc)) * 4);
        puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
      if ((int *)puVar2[2] == param_1) goto LAB_0040d541;
    }
  }
  puVar2 = (undefined4 *)0x0;
LAB_0040d541:
  if ((this != (void *)0xfffffff8) && (puVar2 != (undefined4 *)0x0)) {
    FUN_00414e50((void *)((int)this + 8),param_1);
    FUN_00408c40((void *)((int)this + 0x20),&param_1,(int)piVar1);
    if (param_1 != (int *)0x0) {
      param_1 = (int *)FUN_0040ae30((void *)((int)this + 0x20),param_1);
    }
    return CONCAT31((int3)((uint)param_1 >> 8),1);
  }
  return in_EAX & 0xffffff00;
}



undefined4 * __thiscall FUN_0040d590(void *this,uint param_1,undefined4 param_2)

{
  uint *puVar1;
  uint uVar2;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b8a1;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *(undefined ***)this = aSynchroQueue<struct_SLaneAction*>::vftable;
  FUN_00403890((void *)((int)this + 0xc),0,param_2);
  local_4 = 0;
  FUN_00403890((void *)((int)this + 0x38),1,1);
  local_4._0_1_ = 1;
  *(uint *)((int)this + 4) = param_1;
  uVar2 = -(uint)((int)((ulonglong)param_1 * 0xc >> 0x20) != 0) | (uint)((ulonglong)param_1 * 0xc);
  puVar1 = (uint *)operator_new(-(uint)(0xfffffffb < uVar2) | uVar2 + 4);
  local_4 = CONCAT31(local_4._1_3_,2);
  if (puVar1 == (uint *)0x0) {
    *(undefined4 *)((int)this + 8) = 0;
  }
  else {
    *puVar1 = param_1;
    _eh_vector_constructor_iterator_
              (puVar1 + 1,0xc,param_1,(_func_void_void_ptr *)&LAB_0040ae20,FUN_00412c00);
    *(uint **)((int)this + 8) = puVar1 + 1;
  }
  ExceptionList = local_c;
  return (undefined4 *)this;
}



void __fastcall FUN_0040d660(undefined4 *param_1)

{
  int *this;
  int iVar1;
  int *piVar2;
  undefined4 *puVar3;
  void *pvVar4;
  int **ppiVar5;
  int iVar6;
  uint uVar7;
  undefined4 *local_14 [2];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b8d6;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = aSynchroQueue<struct_SLaneAction*>::vftable;
  local_4 = 1;
  local_14[0] = param_1;
  FUN_004038e0(param_1 + 0xe);
  uVar7 = 0;
  if (param_1[1] != 0) {
    iVar6 = 0;
    do {
      iVar1 = *(int *)(param_1[2] + iVar6);
      while (iVar1 != 0) {
        this = (int *)(param_1[2] + iVar6);
        ppiVar5 = (int **)FUN_00408af0(this,local_14);
        piVar2 = *ppiVar5;
        if (1 < *this) {
          if (piVar2 == (int *)this[1]) {
            iVar1 = *(int *)this[1];
            this[1] = iVar1;
            *(undefined4 *)(iVar1 + 4) = 0;
          }
          else if (piVar2 == (int *)this[2]) {
            puVar3 = (undefined4 *)((int *)this[2])[1];
            this[2] = (int)puVar3;
            *puVar3 = 0;
          }
          else {
            *(int *)piVar2[1] = *piVar2;
            *(int *)(*piVar2 + 4) = piVar2[1];
          }
        }
        operator_delete(piVar2);
        *this = *this + -1;
        if (*this == 0) {
          this[2] = 0;
          this[1] = 0;
        }
        iVar1 = *(int *)(param_1[2] + iVar6);
      }
      uVar7 = uVar7 + 1;
      iVar6 = iVar6 + 0xc;
    } while (uVar7 < (uint)param_1[1]);
  }
  pvVar4 = (void *)param_1[2];
  if (pvVar4 != (void *)0x0) {
    _eh_vector_destructor_iterator_(pvVar4,0xc,*(int *)((int)pvVar4 + -4),FUN_00412c00);
    operator_delete__((void *)((int)pvVar4 + -4));
  }
  FUN_004038d0(param_1 + 0xe);
  param_1[0xe] = aSyncObj::vftable;
  local_c = (void *)((uint)local_c & 0xffffff00);
  param_1[0x10] = aMap<int,class_aLocker*>::vftable;
  FUN_00403d00((void **)(param_1 + 0x11));
  param_1[3] = aSyncObj::vftable;
  local_c = (void *)0xffffffff;
  param_1[5] = aMap<int,class_aLocker*>::vftable;
  FUN_00403d00((void **)(param_1 + 6));
  ExceptionList = local_14[0];
  return;
}



undefined4 * __thiscall FUN_0040d7c0(void *this,byte param_1)

{
  *(undefined ***)this = aMap<int,class_aString>::vftable;
  FUN_0040cb00((void **)((int)this + 4));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_0040d7f0(void *this,byte param_1)

{
  *(undefined ***)this = aCollection<int,class_CCarData*>::vftable;
  FUN_00412c00((int *)((int)this + 0x20));
  *(undefined ***)((int)this + 4) = aMap<int,class_CCarData*>::vftable;
  FUN_0040c080((void **)((int)this + 8));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_0040d830(void *this,byte param_1)

{
  FUN_0040d660((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __fastcall FUN_0040d850(undefined4 *param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b964;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_004032d0(param_1);
  *param_1 = CLane::vftable;
  param_1[0x17] = aMap<int,class_SmartLprAIO::Unit>::vftable;
  param_1[0x18] = 0;
  param_1[0x19] = 0x11;
  param_1[0x1a] = 0;
  param_1[0x1b] = 0;
  param_1[0x1c] = 0;
  param_1[0x1d] = 10;
  param_1[0x1e] = aMap<int,class_aString>::vftable;
  param_1[0x1f] = 0;
  param_1[0x20] = 0x11;
  param_1[0x21] = 0;
  param_1[0x22] = 0;
  param_1[0x23] = 0;
  param_1[0x24] = 10;
  param_1[0x25] = aMap<int,class_CUnitREC*>::vftable;
  param_1[0x26] = 0;
  param_1[0x27] = 0x11;
  param_1[0x28] = 0;
  param_1[0x29] = 0;
  param_1[0x2a] = 0;
  param_1[0x2b] = 10;
  param_1[0x2c] = aCollection<int,class_CCarData*>::vftable;
  param_1[0x2d] = aMap<int,class_CCarData*>::vftable;
  param_1[0x2e] = 0;
  param_1[0x2f] = 0x11;
  param_1[0x30] = 0;
  param_1[0x31] = 0;
  param_1[0x32] = 0;
  param_1[0x33] = 10;
  param_1[0x34] = 0;
  param_1[0x35] = 0;
  param_1[0x36] = 0;
  local_4._0_1_ = 4;
  local_4._1_3_ = 0;
  FUN_0040d590(param_1 + 0x37,1,100);
  param_1[0x50] = 0;
  param_1[0x51] = 0;
  param_1[0x52] = 0;
  local_4._0_1_ = 6;
  FUN_00402e50(param_1 + 0x53);
  local_4 = CONCAT31(local_4._1_3_,7);
  FUN_00402e50(param_1 + 0x5c);
  param_1[0x6b] = 0;
  param_1[0x6c] = 0;
  param_1[0x6d] = 0;
  param_1[0x11] = 0xffffffff;
  param_1[0x12] = 0xffffffff;
  param_1[0x15] = 0xffffffff;
  param_1[0x10] = 0xffffffff;
  param_1[0x16] = 0;
  param_1[0x65] = 0;
  param_1[0x66] = 0;
  *(undefined *)(param_1 + 0x67) = 0;
  param_1[0x68] = 1;
  param_1[0x69] = 0;
  param_1[0x6e] = 0;
  param_1[0x6f] = 0;
  *(undefined *)((int)param_1 + 0x1a9) = 0;
  ExceptionList = local_c;
  return param_1;
}



void __fastcall FUN_0040da00(undefined4 *param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b9f2;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = CLane::vftable;
  local_4 = 8;
  FUN_004028d0(param_1 + 0x6b);
  local_4._0_1_ = 7;
  FUN_00402eb0(param_1 + 0x5c);
  local_4._0_1_ = 6;
  FUN_00402eb0(param_1 + 0x53);
  FUN_00412c00(param_1 + 0x50);
  local_4._0_1_ = 4;
  FUN_0040d660(param_1 + 0x37);
  local_4._0_1_ = 3;
  param_1[0x2c] = aCollection<int,class_CCarData*>::vftable;
  FUN_00412c00(param_1 + 0x34);
  param_1[0x2d] = aMap<int,class_CCarData*>::vftable;
  FUN_0040c080((void **)(param_1 + 0x2e));
  local_4._0_1_ = 2;
  param_1[0x25] = aMap<int,class_CUnitREC*>::vftable;
  FUN_0040c080((void **)(param_1 + 0x26));
  local_4._0_1_ = 1;
  param_1[0x1e] = aMap<int,class_aString>::vftable;
  FUN_0040cb00((void **)(param_1 + 0x1f));
  local_4 = (uint)local_4._1_3_ << 8;
  param_1[0x17] = aMap<int,class_SmartLprAIO::Unit>::vftable;
  FUN_0040c080((void **)(param_1 + 0x18));
  local_4 = 0xffffffff;
  FUN_00403340(param_1);
  ExceptionList = local_c;
  return;
}



void __thiscall FUN_0040db10(void *this,void *param_1,undefined4 param_2)

{
  bool bVar1;
  char cVar2;
  void **ppvVar3;
  undefined4 uVar4;
  byte **this_00;
  int iVar5;
  char **ppcVar6;
  undefined4 *puVar7;
  uint uVar8;
  undefined4 *puVar9;
  char **ppcVar10;
  tm *ptVar11;
  __time64_t _Var12;
  undefined uVar13;
  char *pcVar14;
  undefined *puVar15;
  void *local_200;
  void *local_1fc;
  char *local_1f4;
  int iStack_1f0;
  int local_1e8;
  undefined4 local_1e4;
  void *local_1e0 [3];
  char *local_1d4 [3];
  void *local_1c8;
  int iStack_1c4;
  void *local_1bc;
  int iStack_1b8;
  void *local_1b0;
  int local_1ac;
  undefined4 *puStack_1a4;
  void *local_1a0 [3];
  void *local_194 [3];
  int local_188;
  int local_184;
  undefined local_180 [32];
  char *local_160 [3];
  undefined4 local_154;
  char *apcStack_150 [3];
  void *local_144 [3];
  char *local_138 [8];
  char *apcStack_118 [10];
  undefined4 uStack_f0;
  undefined auStack_ec [8];
  void *local_e4 [3];
  char *apcStack_d8 [8];
  tm tStack_b8;
  char acStack_90 [128];
  uint local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041bba7;
  local_c = ExceptionList;
  local_10 = DAT_00428400 ^ (uint)&local_200;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_00405070((int)local_180,(void **)&stack0x0000000c);
  local_4._0_1_ = 1;
  FUN_004118b0(&local_1e4);
  FUN_004118b0(&local_184);
  FUN_004010a0(&local_200);
  local_4._0_1_ = 2;
  FUN_004010a0(local_1e0);
  local_4._0_1_ = 3;
  FUN_004010a0(&local_1f4);
  local_4._0_1_ = 4;
  FUN_004010a0(local_1a0);
  local_4._0_1_ = 5;
  FUN_004010a0(local_194);
  local_4._0_1_ = 6;
  FUN_004010a0(&local_1b0);
  local_4._0_1_ = 7;
  FUN_004010a0(&local_1bc);
  local_4._0_1_ = 8;
  FUN_004010a0(&local_1c8);
  local_4._0_1_ = 9;
  *(undefined4 *)((int)this + 0x3c) = param_2;
  *(void **)((int)this + 0x4c) = param_1;
  FUN_00402870("Lane %d , initializing ...",(char)param_2);
  ppvVar3 = (void **)FUN_004018e0(local_1d4,"Lane%d/CaptureTimeoutMs");
  local_4._0_1_ = 10;
  if (*ppvVar3 != local_200) {
    FUN_00401910(&local_200,(uint)ppvVar3[1]);
    memcpy(local_200,*ppvVar3,(size_t)ppvVar3[1]);
    local_1fc = ppvVar3[1];
    *(undefined *)((int)local_1fc + (int)local_200) = 0;
  }
  local_4._0_1_ = 9;
  FUN_00401170(local_1d4);
  uVar4 = FUN_004057e0(local_180,(int *)&local_200,(long *)((int)this + 0x194));
  if ((char)uVar4 == '\0') {
LAB_0040dcb8:
    FUN_004011f0(&local_200);
    uVar13 = (undefined)*(undefined4 *)((int)this + 0x3c);
    pcVar14 = "Lane%d: Missing configuration parameter (%s)";
LAB_0040ead7:
    FUN_004028b0(pcVar14,uVar13);
  }
  else {
    ppvVar3 = (void **)FUN_004018e0(local_1d4,"Lane%d/ResetRecognitionOnCarDeparture");
    local_4._0_1_ = 0xb;
    if (*ppvVar3 != local_200) {
      FUN_00401910(&local_200,(uint)ppvVar3[1]);
      memcpy(local_200,*ppvVar3,(size_t)ppvVar3[1]);
      local_1fc = ppvVar3[1];
      *(undefined *)((int)local_1fc + (int)local_200) = 0;
    }
    local_4 = CONCAT31(local_4._1_3_,9);
    FUN_00401170(local_1d4);
    uVar4 = FUN_004057e0(local_180,(int *)&local_200,&local_1e8);
    if ((char)uVar4 == '\0') {
      *(undefined *)((int)this + 0x1a9) = 0;
      FUN_004011f0(&local_200);
      FUN_00402890("Lane%d: Missing configuration parameter (%s). Set as disabled.",
                   (char)*(undefined4 *)((int)this + 0x3c));
    }
    else {
      *(bool *)((int)this + 0x1a9) = local_1e8 == 1;
    }
    ppvVar3 = (void **)FUN_004018e0(local_1d4,"Lane%d/KeepLicensePlateSeconds");
    local_4._0_1_ = 0xc;
    if (*ppvVar3 != local_200) {
      FUN_00401910(&local_200,(uint)ppvVar3[1]);
      memcpy(local_200,*ppvVar3,(size_t)ppvVar3[1]);
      local_1fc = ppvVar3[1];
      *(undefined *)((int)local_1fc + (int)local_200) = 0;
    }
    local_4._0_1_ = 9;
    FUN_00401170(local_1d4);
    uVar4 = FUN_004057e0(local_180,(int *)&local_200,(long *)((int)this + 0x198));
    if ((char)uVar4 == '\0') {
LAB_0040de12:
      FUN_004011f0(&local_200);
      uVar13 = (undefined)*(undefined4 *)((int)this + 0x3c);
      pcVar14 = "Lane%d: Missing configuration parameter (%s)";
      goto LAB_0040ead7;
    }
    ppvVar3 = (void **)FUN_004018e0(local_1d4,"Lane%d/ReuseRecognition");
    local_4._0_1_ = 0xd;
    FUN_00401000(&local_200,ppvVar3);
    local_4._0_1_ = 9;
    FUN_00401170(local_1d4);
    uVar4 = FUN_004057e0(local_180,(int *)&local_200,&local_1e8);
    if ((char)uVar4 == '\0') {
      FUN_004011f0(&local_200);
      uVar13 = (undefined)*(undefined4 *)((int)this + 0x3c);
      pcVar14 = "Lane%d: Missing configuration parameter (%s)";
      goto LAB_0040ead7;
    }
    *(bool *)((int)this + 0x19c) = local_1e8 == 1;
    ppvVar3 = (void **)FUN_004018e0(local_1d4,"Lane%d/ReuseSoftwareRecognitionMs");
    local_4._0_1_ = 0xe;
    FUN_00401000(&local_200,ppvVar3);
    local_4._0_1_ = 9;
    FUN_00401170(local_1d4);
    uVar4 = FUN_004057e0(local_180,(int *)&local_200,(long *)((int)this + 0x1a4));
    if ((char)uVar4 == '\0') goto LAB_0040dcb8;
    ppvVar3 = (void **)FUN_004018e0(local_1d4,"Lane%d/AllowTriggerOnHardwareMode");
    local_4._0_1_ = 0xf;
    FUN_00401000(&local_200,ppvVar3);
    local_4._0_1_ = 9;
    FUN_00401170(local_1d4);
    uVar4 = FUN_004057e0(local_180,(int *)&local_200,&local_1e8);
    if ((char)uVar4 == '\0') goto LAB_0040de12;
    *(bool *)((int)this + 0x1a8) = local_1e8 == 1;
    ppvVar3 = (void **)FUN_004018e0(local_1d4,"Lane%d/RecognitionTimeSource");
    local_4._0_1_ = 0x10;
    FUN_00401000(&local_200,ppvVar3);
    local_4._0_1_ = 9;
    FUN_00401170(local_1d4);
    uVar4 = FUN_00405440(local_180,(int *)&local_200,local_194);
    if ((char)uVar4 == '\0') {
      FUN_004011f0(&local_200);
      uVar13 = (undefined)*(undefined4 *)((int)this + 0x3c);
LAB_0040ead2:
      pcVar14 = "Lane%d: Missing configuration parameter (%s). Available values : LPR,System .";
      goto LAB_0040ead7;
    }
    ppcVar6 = local_1d4;
    this_00 = FUN_004014f0(local_194,'\x01');
    ppvVar3 = FUN_00401390(this_00,ppcVar6);
    local_4._0_1_ = 0x11;
    FUN_00401000(local_1e0,ppvVar3);
    local_4._0_1_ = 9;
    FUN_00401170(local_1d4);
    iVar5 = FUN_00401290(local_1e0,&DAT_0041f298);
    if (iVar5 == 0) {
      *(undefined4 *)((int)this + 0x1a0) = 0;
    }
    else {
      iVar5 = FUN_00401290(local_1e0,(byte *)"SYSTEM");
      if (iVar5 != 0) {
        FUN_004011f0(&local_200);
        uVar13 = (undefined)*(undefined4 *)((int)this + 0x3c);
        goto LAB_0040ead2;
      }
      *(undefined4 *)((int)this + 0x1a0) = 1;
    }
    ppvVar3 = (void **)FUN_004018e0(local_1d4,"Lane%d/LprUnits");
    local_4._0_1_ = 0x12;
    FUN_00401000(&local_200,ppvVar3);
    local_4._0_1_ = 9;
    FUN_00401170(local_1d4);
    uVar4 = FUN_00405440(local_180,(int *)&local_200,local_1e0);
    if ((char)uVar4 == '\0') goto LAB_0040de12;
    ppcVar6 = FUN_00401040(&local_1c8,"");
    ppvVar3 = FUN_00401000(&local_1bc,ppcVar6);
    FUN_00401000(&local_1b0,ppvVar3);
    FUN_00401100(local_e4,",",(char *)0x7fffffff);
    local_4._0_1_ = 0x13;
    FUN_00404340(local_138,local_1e0);
    local_4._0_1_ = 0x15;
    FUN_00401170(local_e4);
    uVar4 = FUN_004043f0(local_138);
    cVar2 = (char)uVar4;
    while (cVar2 != '\0') {
      ppcVar6 = FUN_00404520(local_138,local_1d4);
      local_4._0_1_ = 0x16;
      FUN_00401000(&local_1f4,ppcVar6);
      local_4._0_1_ = 0x15;
      FUN_00401170(local_1d4);
      uVar4 = FUN_004017b0(&local_1f4,&local_188,(char *)0xa);
      if ((char)uVar4 == '\0') {
        FUN_004011f0(&local_1f4);
        uVar13 = (undefined)*(undefined4 *)((int)this + 0x3c);
        pcVar14 = "Lane%d: Invalid LprUnit value \'%s\'";
        goto LAB_0040e49d;
      }
      if (local_1ac == 0) {
        FUN_00401200(&local_1b0,&local_1f4);
      }
      else {
        ppvVar3 = (void **)FUN_00401ab0((int *)local_144,",",&local_1f4);
        local_4._0_1_ = 0x17;
        FUN_00401200(&local_1b0,ppvVar3);
        local_4._0_1_ = 0x15;
        FUN_00401170(local_144);
      }
      bVar1 = false;
      local_1e8 = 0;
      FUN_00411b20(&local_154);
      iVar5 = FUN_004116c0();
      if (iVar5 <= local_1e8) {
LAB_0040e4be:
        uVar13 = (undefined)*(undefined4 *)((int)this + 0x3c);
        pcVar14 = "Lane%d: Can\'t found lpr unit with id %d";
        goto LAB_0040e49d;
      }
      do {
        if (bVar1) goto LAB_0040e3f8;
        puVar15 = auStack_ec;
        iVar5 = local_1e8;
        FUN_00411b20(&uStack_f0);
        puVar7 = FUN_00411b70(puVar15,iVar5);
        FUN_004118c0(&local_1e4,puVar7);
        iVar5 = FUN_004116d0(&local_1e4);
        if (iVar5 == local_188) {
          pcVar14 = "quercus2";
          puVar7 = FUN_00411b90(&local_1e4);
          bVar1 = FUN_00411890(puVar7,pcVar14);
          if (bVar1) {
            puVar7 = FUN_00411b90(&local_1e4);
            puVar7 = FUN_00411be0(puVar7);
            FUN_004118c0(&local_184,puVar7);
            bVar1 = FUN_00412880(&local_184);
            if (!bVar1) goto LAB_0040e2b1;
            FUN_004118d0(&local_184,acStack_90,0x80);
          }
          else {
LAB_0040e2b1:
            FUN_004116d0(&local_1e4);
            sprintf(acStack_90,"%d");
            FUN_004116d0(&local_1e4);
            FUN_00402890("Lane %d, Can\'t obtein LprUnit serial number, set lane id \'%d\'",
                         (char)*(undefined4 *)((int)this + 0x3c));
          }
          ppvVar3 = FUN_00401100(local_160,acStack_90,(char *)0x7fffffff);
          local_4._0_1_ = 0x18;
          FUN_00401000(local_1a0,ppvVar3);
          local_4._0_1_ = 0x15;
          FUN_00401170(local_160);
          puStack_1a4 = (undefined4 *)&stack0xfffffde0;
          FUN_004010b0(&stack0xfffffde0,local_1a0);
          local_4._0_1_ = 0x19;
          uVar8 = FUN_004116d0(&local_1e4);
          local_4._0_1_ = 0x15;
          FUN_0040d470((void *)((int)this + 0x78),uVar8);
          puStack_1a4 = (undefined4 *)&stack0xfffffde8;
          FUN_004118c0(&stack0xfffffde8,&local_1e4);
          uVar8 = FUN_004116d0(&local_1e4);
          uVar13 = 0x82;
          FUN_0040d430((void *)((int)this + 0x5c),uVar8);
          puStack_1a4 = (undefined4 *)&stack0xfffffde0;
          FUN_004010b0(&stack0xfffffde0,&local_1f4);
          FUN_00414ae0(param_1,this,uVar13);
          bVar1 = true;
          FUN_004011f0(local_1a0);
          FUN_004116d0(&local_1e4);
          FUN_00402870("Lane %d , Initialized LprUnit id:%d  \'%s\' (LaneUnits:%d)",
                       (char)*(undefined4 *)((int)this + 0x3c));
        }
        local_1e8 = local_1e8 + 1;
        FUN_00411b20(&local_154);
        iVar5 = FUN_004116c0();
      } while (local_1e8 < iVar5);
      if (!bVar1) goto LAB_0040e4be;
LAB_0040e3f8:
      if (*(int *)((int)this + 0x54) == -1) {
        *(int *)((int)this + 0x54) = local_188;
      }
      uVar4 = FUN_004043f0(local_138);
      cVar2 = (char)uVar4;
    }
    ppvVar3 = (void **)FUN_004018e0(local_160,"Lane%d/RecUnits");
    local_4._0_1_ = 0x1a;
    FUN_00401000(&local_200,ppvVar3);
    local_4._0_1_ = 0x15;
    FUN_00401170(local_160);
    uVar4 = FUN_00405440(local_180,(int *)&local_200,local_1e0);
    if ((char)uVar4 == '\0') {
      FUN_004011f0(&local_200);
      uVar13 = (undefined)*(undefined4 *)((int)this + 0x3c);
      pcVar14 = "Lane%d: Missing configuration parameter (%s)";
LAB_0040e49d:
      FUN_004028b0(pcVar14,uVar13);
      local_4._0_1_ = 9;
      FUN_0040bc30(local_138);
    }
    else {
      FUN_00401100(local_144,",",(char *)0x7fffffff);
      local_4._0_1_ = 0x1b;
      FUN_00404340(apcStack_118,local_1e0);
      local_4 = CONCAT31(local_4._1_3_,0x1d);
      FUN_00401170(local_144);
      uVar4 = FUN_004043f0(apcStack_118);
      cVar2 = (char)uVar4;
      while (cVar2 != '\0') {
        ppcVar6 = FUN_00404520(apcStack_118,local_160);
        local_4._0_1_ = 0x1e;
        FUN_00401000(&local_1f4,ppcVar6);
        local_4._0_1_ = 0x1d;
        FUN_00401170(local_160);
        uVar13 = 0x8d;
        uVar4 = FUN_004017b0(&local_1f4,&local_188,(char *)0xa);
        if ((char)uVar4 == '\0') {
          FUN_004011f0(&local_1f4);
          uVar13 = (undefined)*(undefined4 *)((int)this + 0x3c);
          pcVar14 = "Lane%d: Invalid RecUnit value \'%s\'";
          goto LAB_0040e733;
        }
        if (iStack_1b8 == 0) {
          FUN_00401200(&local_1bc,&local_1f4);
        }
        else {
          ppcVar6 = local_1d4;
          ppvVar3 = (void **)FUN_00401ab0((int *)ppcVar6,",",&local_1f4);
          uVar13 = SUB41(ppcVar6,0);
          local_4._0_1_ = 0x1f;
          FUN_00401200(&local_1bc,ppvVar3);
          local_4._0_1_ = 0x1d;
          FUN_00401170(local_1d4);
        }
        puStack_1a4 = (undefined4 *)operator_new(0x17c);
        local_4._0_1_ = 0x20;
        if (puStack_1a4 == (undefined4 *)0x0) {
          puVar7 = (undefined4 *)0x0;
        }
        else {
          puVar7 = FUN_00415860(puStack_1a4);
        }
        puStack_1a4 = (undefined4 *)&stack0xfffffde0;
        local_4._0_1_ = 0x1d;
        FUN_004010b0(&stack0xfffffde0,(void **)&stack0x0000000c);
        cVar2 = FUN_00415a50(puVar7,this,local_188,uVar13);
        if (cVar2 == '\0') {
          FUN_004011f0(&local_1f4);
          uVar13 = (undefined)*(undefined4 *)((int)this + 0x3c);
          pcVar14 = "Lane%d: RecUnit not found \'%s\'";
          goto LAB_0040e733;
        }
        uVar8 = FUN_004164d0((int)puVar7);
        puVar9 = FUN_00414eb0((void *)((int)this + 0x98),uVar8);
        *puVar9 = puVar7;
        puVar7 = FUN_00414c20(puVar7,apcStack_150);
        local_4._0_1_ = 0x21;
        FUN_004011f0(puVar7);
        FUN_00402870("Lane %d , initialized RecUnit %s",(char)*(undefined4 *)((int)this + 0x3c));
        local_4 = CONCAT31(local_4._1_3_,0x1d);
        FUN_00401170(apcStack_150);
        uVar4 = FUN_004043f0(apcStack_118);
        cVar2 = (char)uVar4;
      }
      ppvVar3 = (void **)FUN_004018e0(apcStack_150,"Lane%d/ScheidtBachmannLaneIds");
      local_4._0_1_ = 0x22;
      FUN_00401000(&local_200,ppvVar3);
      local_4._0_1_ = 0x1d;
      FUN_00401170(apcStack_150);
      uVar4 = FUN_00405440(local_180,(int *)&local_200,local_1e0);
      if ((char)uVar4 != '\0') {
        FUN_00401100(local_1d4,",",(char *)0x7fffffff);
        local_4._0_1_ = 0x23;
        ppcVar6 = (char **)0x40e7ae;
        FUN_00404340(apcStack_d8,local_1e0);
        local_4._0_1_ = 0x25;
        FUN_00401170(local_1d4);
        uVar4 = FUN_004043f0(apcStack_d8);
        cVar2 = (char)uVar4;
        while (cVar2 != '\0') {
          ppcVar10 = FUN_00404520(apcStack_d8,apcStack_150);
          local_4._0_1_ = 0x26;
          FUN_00401000(&local_1f4,ppcVar10);
          local_4._0_1_ = 0x25;
          FUN_00401170(apcStack_150);
          if ((iStack_1f0 == 0) || (iVar5 = FUN_00401180(&local_1f4), (char)iVar5 == '\0')) {
            FUN_004011f0(&local_1f4);
            FUN_004028b0("Lane%d: Invalid ScheidtBachmannLaneIds value \'%s\'",
                         (char)*(undefined4 *)((int)this + 0x3c));
            local_4._0_1_ = 0x1d;
            FUN_0040bc30(apcStack_d8);
            goto LAB_0040e73b;
          }
          if (iStack_1c4 == 0) {
            uVar8 = 0x40e88b;
            FUN_00401200(&local_1c8,&local_1f4);
          }
          else {
            ppcVar6 = local_160;
            ppvVar3 = (void **)FUN_00401ab0((int *)ppcVar6,",",&local_1f4);
            local_4._0_1_ = 0x27;
            uVar8 = 0x40e868;
            FUN_00401200(&local_1c8,ppvVar3);
            local_4._0_1_ = 0x25;
            FUN_00401170(local_160);
          }
          puStack_1a4 = (undefined4 *)&stack0xfffffde0;
          FUN_004010b0(&stack0xfffffde0,&local_1f4);
          FUN_00414a60(param_1,this,(char)ppcVar6);
          puStack_1a4 = (undefined4 *)&stack0xfffffde0;
          FUN_004010b0(&stack0xfffffde0,&local_1f4);
          FUN_00405a90((void *)((int)this + 0x1ac),ppcVar6,uVar8);
          uVar4 = FUN_004043f0(apcStack_d8);
          cVar2 = (char)uVar4;
        }
        ptVar11 = FUN_00403080(&tStack_b8);
        _Var12 = FUN_00403040(ptVar11);
        *(int *)((int)this + 0x50) = (int)_Var12;
        FUN_00403360(this,'\x01',0,0);
        FUN_004011f0(&local_1c8);
        FUN_004011f0(&local_1bc);
        FUN_004011f0(&local_1b0);
        FUN_00402870("Lane %d , initialize Units  (Lprs:%d %s Recs:%d %s SBLaneIds:%d %s)",
                     (char)*(undefined4 *)((int)this + 0x3c));
        FUN_004011f0(local_194);
        FUN_00402870("Lane %d , initialize Config (CaptureTimeoutMs:%d KeepLicenseSec:%d ReuseRecog:%s RecogTimeSource:%s ReuseSoftTriggerMs:%d AllowTriggerSWonHW:%d ResetRecognitionOnCarDeparture:%d)"
                     ,(char)*(undefined4 *)((int)this + 0x3c));
        local_4._0_1_ = 0x1d;
        FUN_0040bc30(apcStack_d8);
        local_4._0_1_ = 0x15;
        FUN_0040bc30(apcStack_118);
        local_4._0_1_ = 9;
        FUN_0040bc30(local_138);
        local_4._0_1_ = 8;
        FUN_00401170(&local_1c8);
        local_4._0_1_ = 7;
        FUN_00401170(&local_1bc);
        local_4._0_1_ = 6;
        FUN_00401170(&local_1b0);
        local_4._0_1_ = 5;
        FUN_00401170(local_194);
        local_4._0_1_ = 4;
        FUN_00401170(local_1a0);
        local_4._0_1_ = 3;
        FUN_00401170(&local_1f4);
        local_4._0_1_ = 2;
        FUN_00401170(local_1e0);
        local_4._0_1_ = 1;
        FUN_00401170(&local_200);
        local_4 = (uint)local_4._1_3_ << 8;
        FUN_00401f60((int)local_180);
        local_4 = 0xffffffff;
        FUN_00401170((void **)&stack0x0000000c);
        goto LAB_0040eb97;
      }
      FUN_004011f0(&local_200);
      uVar13 = (undefined)*(undefined4 *)((int)this + 0x3c);
      pcVar14 = "Lane:%d: Missing configuration parameter (%s)";
LAB_0040e733:
      FUN_004028b0(pcVar14,uVar13);
LAB_0040e73b:
      local_4._0_1_ = 0x15;
      FUN_0040bc30(apcStack_118);
      local_4._0_1_ = 9;
      FUN_0040bc30(local_138);
    }
  }
  local_4._0_1_ = 8;
  FUN_00401170(&local_1c8);
  local_4._0_1_ = 7;
  FUN_00401170(&local_1bc);
  local_4._0_1_ = 6;
  FUN_00401170(&local_1b0);
  local_4._0_1_ = 5;
  FUN_00401170(local_194);
  local_4._0_1_ = 4;
  FUN_00401170(local_1a0);
  local_4._0_1_ = 3;
  FUN_00401170(&local_1f4);
  local_4._0_1_ = 2;
  FUN_00401170(local_1e0);
  local_4._0_1_ = 1;
  FUN_00401170(&local_200);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401f60((int)local_180);
  local_4 = 0xffffffff;
  FUN_00401170((void **)&stack0x0000000c);
LAB_0040eb97:
  ExceptionList = local_c;
  ___security_check_cookie_4(local_10 ^ (uint)&local_200);
  return;
}



void __fastcall FUN_0040ebd0(int *param_1)

{
  int *piVar1;
  void *pvVar2;
  int iVar3;
  int iVar4;
  void **ppvVar5;
  void **ppvVar6;
  void **ppvVar7;
  uint uVar8;
  uint uVar9;
  int *piVar10;
  uint *puVar11;
  undefined4 *puVar12;
  undefined4 local_8 [2];
  
  FUN_00402870("Lane %d , ternimate ...",(char)param_1[0xf]);
  FUN_004033d0(param_1);
  if (0 < param_1[0x28]) {
    do {
      uVar8 = 0;
      uVar9 = uVar8;
      if ((param_1[0x28] != 0) && (uVar9 = 0, param_1[0x27] != 0)) {
        puVar11 = (uint *)param_1[0x26];
        do {
          uVar9 = *puVar11;
          if (uVar9 != 0) break;
          uVar8 = uVar8 + 1;
          puVar11 = puVar11 + 1;
        } while (uVar8 < (uint)param_1[0x27]);
      }
      pvVar2 = (void *)param_1[0x26];
      piVar10 = *(int **)(uVar9 + 0xc);
      if (pvVar2 != (void *)0x0) {
        uVar8 = ((uint)*(void **)(uVar9 + 8) >> 4) % (uint)param_1[0x27];
        ppvVar7 = *(void ***)((int)pvVar2 + uVar8 * 4);
        ppvVar6 = (void **)((int)pvVar2 + uVar8 * 4);
        while (ppvVar5 = ppvVar7, ppvVar5 != (void **)0x0) {
          if (ppvVar5[2] == *(void **)(uVar9 + 8)) {
            *ppvVar6 = *ppvVar5;
            *ppvVar5 = (void *)param_1[0x29];
            piVar1 = param_1 + 0x28;
            *piVar1 = *piVar1 + -1;
            param_1[0x29] = (int)ppvVar5;
            if (*piVar1 == 0) {
              FUN_0040c080((void **)(param_1 + 0x26));
            }
            break;
          }
          ppvVar6 = ppvVar5;
          ppvVar7 = (void **)*ppvVar5;
        }
      }
      FUN_004153f0(piVar10);
      if (piVar10 != (int *)0x0) {
        (**(code **)*piVar10)(1);
      }
    } while (0 < param_1[0x28]);
  }
  if (0 < param_1[0x34]) {
    do {
      piVar10 = (int *)FUN_00409310(param_1 + 0x2c,local_8);
      iVar3 = piVar10[1];
      uVar9 = *(uint *)(*piVar10 + 8);
      iVar4 = *(int *)(iVar3 + 4);
      puVar12 = (undefined4 *)0x0;
      if (iVar4 != 0) {
        for (puVar12 = *(undefined4 **)(iVar4 + ((uVar9 >> 4) % *(uint *)(iVar3 + 8)) * 4);
            puVar12 != (undefined4 *)0x0; puVar12 = (undefined4 *)*puVar12) {
          if (puVar12[2] == uVar9) goto LAB_0040ecfd;
        }
        puVar12 = (undefined4 *)0x0;
      }
LAB_0040ecfd:
      piVar10 = (int *)puVar12[3];
      puVar12 = (undefined4 *)0x0;
      if (iVar4 != 0) {
        for (puVar12 = *(undefined4 **)(iVar4 + ((uVar9 >> 4) % *(uint *)(iVar3 + 8)) * 4);
            puVar12 != (undefined4 *)0x0; puVar12 = (undefined4 *)*puVar12) {
          if (puVar12[2] == uVar9) goto LAB_0040ed22;
        }
        puVar12 = (undefined4 *)0x0;
      }
LAB_0040ed22:
      FUN_0040d510(param_1 + 0x2c,(int *)puVar12[2]);
      if (piVar10 != (int *)0x0) {
        (**(code **)(*piVar10 + 4))(1);
      }
    } while (0 < param_1[0x34]);
  }
  FUN_00402870("Lane %d , ternimate complete",(char)param_1[0xf]);
  return;
}



undefined4 * __thiscall FUN_0040ed70(void *this,byte param_1)

{
  FUN_0040da00((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_0040ed90(int param_1,undefined param_2,undefined param_3)

{
  bool bVar1;
  char cVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  void **ppvVar6;
  undefined4 *puVar7;
  undefined **ppuVar8;
  undefined *this;
  int iVar9;
  int iVar10;
  undefined extraout_CL;
  undefined extraout_CL_00;
  undefined extraout_CL_01;
  undefined extraout_DL;
  undefined extraout_DL_00;
  void *pvVar11;
  undefined ***pppuVar12;
  char *pcVar13;
  void *in_stack_fffffef0;
  uint uVar14;
  undefined uVar15;
  undefined4 uVar16;
  undefined auStack_f0 [3];
  char local_ed;
  void **local_ec;
  undefined **local_e8;
  void *local_e4;
  undefined4 *local_dc;
  undefined *local_d8 [3];
  void *local_cc;
  void *local_c8;
  void *local_c0 [3];
  undefined *local_b4;
  int local_b0;
  tm local_ac;
  void *local_84 [3];
  void *local_78 [3];
  void *local_6c [3];
  undefined4 local_60;
  undefined local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined2 local_38;
  undefined local_34 [36];
  uint local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041bc95;
  local_c = ExceptionList;
  local_10 = DAT_00428400 ^ (uint)auStack_f0;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004010a0(local_78);
  local_4._0_1_ = 1;
  FUN_004010a0(&local_cc);
  local_4._0_1_ = 2;
  FUN_004010a0(&local_e8);
  local_4._0_1_ = 3;
  FUN_004010a0(local_84);
  local_4._0_1_ = 4;
  FUN_004010a0(local_6c);
  local_4 = CONCAT31(local_4._1_3_,5);
  FUN_00402fc0(&local_ac);
  local_ed = '\x01';
  local_dc = (undefined4 *)0x0;
  if (0 < *(int *)(param_1 + 0xd0)) {
    puVar3 = (undefined4 *)FUN_00409310((void *)(param_1 + 0xb0),local_d8);
    puVar7 = (undefined4 *)*puVar3;
    iVar9 = puVar3[1];
    while ((puVar7 != (undefined4 *)0x0 && (local_ed != '\0'))) {
      uVar14 = puVar7[2];
      iVar10 = *(int *)(iVar9 + 4);
      if (iVar10 != 0) {
        for (puVar3 = *(undefined4 **)(iVar10 + ((uVar14 >> 4) % *(uint *)(iVar9 + 8)) * 4);
            puVar3 != (undefined4 *)0x0; puVar3 = (undefined4 *)*puVar3) {
          if (puVar3[2] == uVar14) goto LAB_0040ee9d;
        }
      }
      puVar3 = (undefined4 *)0x0;
LAB_0040ee9d:
      puVar3 = (undefined4 *)puVar3[3];
      local_ec = (void **)&stack0xfffffef8;
      in_stack_fffffef0 = (void *)0x40eeb8;
      local_dc = puVar3;
      FUN_00411720(&stack0xfffffef8,(int *)&param_3);
      uVar4 = FUN_00408e90((int)puVar3,extraout_DL,(char)uVar14);
      if ((char)uVar4 == '\0') {
        local_ed = '\0';
      }
      puVar7 = (undefined4 *)*puVar7;
    }
  }
  FUN_00401040(&local_cc,"");
  if (DAT_0042b194 == '\0') {
    puVar3 = (undefined4 *)0x0;
    uVar14 = 0x40ef5f;
    puVar7 = (undefined4 *)FUN_00411bb0(&param_3,&local_ec);
    iVar9 = FUN_00411850(puVar7);
    if (0 < iVar9) {
      do {
        uVar4 = 5;
        local_60 = 0;
        local_5c = 0;
        puVar7 = &local_60;
        ppuVar8 = &local_b4;
        puVar5 = puVar3;
        pvVar11 = (void *)FUN_00411bb0(&param_3,local_d8);
        puVar5 = FUN_00411bc0(pvVar11,ppuVar8,puVar5);
        in_stack_fffffef0 = (void *)0x40efaf;
        FUN_00411860(puVar5,puVar7,uVar4);
        FUN_00401240(&local_cc,(char *)&local_60);
        puVar3 = (undefined4 *)((int)puVar3 + 1);
        uVar14 = 0x40efd4;
        puVar7 = (undefined4 *)FUN_00411bb0(&param_3,&local_ec);
        iVar9 = FUN_00411850(puVar7);
      } while ((int)puVar3 < iVar9);
    }
  }
  else {
    local_58 = 0;
    local_54 = 0;
    local_50 = 0;
    local_4c = 0;
    local_48 = 0;
    local_44 = 0;
    local_40 = 0;
    local_3c = 0;
    local_38 = 0;
    in_stack_fffffef0 = (void *)0x40ef3d;
    FUN_004117f0(&param_3,&local_58,0x22);
    uVar14 = 0x40ef4e;
    FUN_00401040(&local_cc,(char *)&local_58);
  }
  local_d8[0] = &stack0xfffffef0;
  FUN_004010b0(&stack0xfffffef0,&local_cc);
  ppvVar6 = (void **)FUN_0040b930(local_d8,in_stack_fffffef0,uVar14);
  local_4._0_1_ = 6;
  if (*ppvVar6 != local_cc) {
    FUN_00401910(&local_cc,(uint)ppvVar6[1]);
    memcpy(local_cc,*ppvVar6,(size_t)ppvVar6[1]);
    local_c8 = ppvVar6[1];
    *(undefined *)((int)local_c8 + (int)local_cc) = 0;
  }
  local_4._0_1_ = 5;
  FUN_00401170(local_d8);
  FUN_004117a0(&param_3,local_34,0x22);
  FUN_004011f0(&local_cc);
  FUN_00411790((undefined4 *)&param_3);
  FUN_00411780((undefined4 *)&param_3);
  puVar7 = FUN_004117d0((undefined4 *)&param_3);
  FUN_004116d0(puVar7);
  FUN_00402870("Lane %d, HandleRecognition unit:%d car:%d triggerId:%d \'%s\' country:%s (PendingWebRequests:%d)"
               ,(char)*(undefined4 *)(param_1 + 0x3c));
  uVar4 = FUN_00411830((undefined4 *)&param_3);
  FUN_004030d0(&local_ac,(char)((int)uVar4 >> 0x1f),(char)uVar4);
  puVar7 = (undefined4 *)FUN_00412ad0(*(void **)(param_1 + 0x4c),local_c0);
  local_4._0_1_ = 7;
  FUN_004011f0(puVar7);
  ppuVar8 = local_d8;
  ppvVar6 = (void **)FUN_004018e0(ppuVar8,"%s\\RecUnits");
  local_4._0_1_ = 8;
  if ((undefined **)*ppvVar6 != local_e8) {
    FUN_00401910(&local_e8,(uint)ppvVar6[1]);
    ppuVar8 = local_e8;
    memcpy(local_e8,*ppvVar6,(size_t)ppvVar6[1]);
    local_e4 = ppvVar6[1];
    *(undefined *)((int)local_e4 + (int)local_e8) = 0;
  }
  local_4._0_1_ = 7;
  FUN_00401170(local_d8);
  local_4 = CONCAT31(local_4._1_3_,5);
  FUN_00401170(local_c0);
  local_d8[0] = &stack0xfffffef0;
  FUN_004010b0(&stack0xfffffef0,&local_e8);
  bVar1 = FUN_00403760((LPCSTR)ppuVar8);
  if (!bVar1) {
    local_d8[0] = &stack0xfffffef0;
    FUN_004010b0(&stack0xfffffef0,&local_e8);
    FUN_004037a0((LPCSTR)ppuVar8);
  }
  FUN_00402ff0((int)&local_ac);
  FUN_00402fe0((int)&local_ac);
  FUN_00402fd0((int)&local_ac);
  FUN_004011f0(&local_e8);
  pvVar11 = (void *)0x40f1e7;
  ppvVar6 = (void **)FUN_004018e0(local_c0,"%s\\%.4d%.2d%.2d");
  local_4._0_1_ = 9;
  if ((undefined **)*ppvVar6 != local_e8) {
    FUN_00401910(&local_e8,(uint)ppvVar6[1]);
    memcpy(local_e8,*ppvVar6,(size_t)ppvVar6[1]);
    local_e4 = ppvVar6[1];
    *(undefined *)((int)local_e4 + (int)local_e8) = 0;
  }
  local_4._0_1_ = 5;
  FUN_00401170(local_c0);
  FUN_00403000((int)&local_ac);
  FUN_004011f0(&local_e8);
  ppvVar6 = (void **)FUN_004018e0(local_c0,"%s_%.2d");
  local_4._0_1_ = 10;
  if ((undefined **)*ppvVar6 != local_e8) {
    FUN_00401910(&local_e8,(uint)ppvVar6[1]);
    memcpy(local_e8,*ppvVar6,(size_t)ppvVar6[1]);
    local_e4 = ppvVar6[1];
    *(undefined *)((int)local_e4 + (int)local_e8) = 0;
  }
  local_4._0_1_ = 5;
  FUN_00401170(local_c0);
  FUN_00403020(&local_ac.tm_sec);
  FUN_00403010((int)&local_ac);
  ppuVar8 = (undefined **)FUN_004011f0(&local_e8);
  pcVar13 = "%s_%.2d%.2d";
  ppvVar6 = (void **)FUN_004018e0(local_c0,"%s_%.2d%.2d");
  local_4._0_1_ = 0xb;
  if ((undefined **)*ppvVar6 != local_e8) {
    FUN_00401910(&local_e8,(uint)ppvVar6[1]);
    pcVar13 = (char *)0x40f316;
    ppuVar8 = local_e8;
    memcpy(local_e8,*ppvVar6,(size_t)ppvVar6[1]);
    local_e4 = ppvVar6[1];
    *(undefined *)((int)local_e4 + (int)local_e8) = 0;
  }
  local_4._0_1_ = 5;
  FUN_00401170(local_c0);
  uVar15 = extraout_CL;
  if (local_ed != '\0') {
    if (*(int *)(param_1 + 0x40) < 0) {
      *(int *)(param_1 + 0x40) = *(int *)(param_1 + 0x3c) * 1000000;
    }
    *(int *)(param_1 + 0x40) = *(int *)(param_1 + 0x40) + 1;
    uVar4 = 0x40f364;
    this = (undefined *)operator_new(0x1f0);
    local_4._0_1_ = 0xc;
    if (this == (undefined *)0x0) {
      local_dc = (undefined4 *)0x0;
      uVar15 = extraout_CL_00;
    }
    else {
      uVar16 = *(undefined4 *)(param_1 + 0x68);
      local_b4 = &stack0xfffffeec;
      pppuVar12 = &local_e8;
      uVar14 = 0x40f391;
      local_d8[0] = this;
      FUN_004010b0(&stack0xfffffeec,pppuVar12);
      local_ec = (void **)&stack0xfffffee0;
      local_4._0_1_ = 0xd;
      FUN_00412ad0(*(void **)(param_1 + 0x4c),&stack0xfffffee0);
      local_4._0_1_ = 0xc;
      local_dc = FUN_00409db0(this,param_1,*(undefined4 *)(param_1 + 0x40),
                              *(undefined4 *)(param_1 + 0x3c),pvVar11,uVar14,pppuVar12,pcVar13,
                              (uint)ppuVar8,uVar4,uVar16);
      uVar15 = extraout_CL_01;
    }
    local_4._0_1_ = 5;
  }
  local_d8[0] = &stack0xfffffef8;
  FUN_00411720(&stack0xfffffef8,(int *)&param_3);
  puVar7 = local_dc;
  FUN_00409660((int)local_dc,extraout_DL_00,uVar15);
  FUN_00402f40(&local_b0,param_1 + 0x14c);
  local_4 = CONCAT31(local_4._1_3_,0xe);
  puVar3 = (undefined4 *)FUN_00408af0((void *)(param_1 + 0x140),local_d8);
  ppvVar6 = (void **)*puVar3;
  local_ec = ppvVar6;
  while (ppvVar6 != (void **)0x0) {
    pvVar11 = ppvVar6[2];
    bVar1 = false;
    iVar9 = FUN_00408de0((int)local_dc);
    if (iVar9 < 1) {
      cVar2 = FUN_00416490((int)pvVar11);
      if (cVar2 == '\0') {
        bVar1 = true;
      }
    }
    else {
      iVar9 = FUN_004164b0((int)pvVar11);
      iVar10 = FUN_00408de0((int)local_dc);
      ppvVar6 = local_ec;
      if ((iVar10 == iVar9) &&
         (cVar2 = FUN_00416490((int)pvVar11), ppvVar6 = local_ec, cVar2 == '\0')) {
        bVar1 = true;
      }
    }
    local_ec = FUN_004165c0(pvVar11,local_c0);
    local_4._0_1_ = 0xf;
    FUN_00416490((int)pvVar11);
    FUN_004011f0(local_ec);
    FUN_00402870("Lane %d, HandleRecognition webRequest(%s Completed:%d addToCarData:%d)",
                 (char)*(undefined4 *)(param_1 + 0x3c));
    local_4 = CONCAT31(local_4._1_3_,0xe);
    FUN_00401170(local_c0);
    puVar7 = local_dc;
    if (bVar1) {
      FUN_0040a7e0(local_dc,pvVar11);
      puVar3 = (undefined4 *)FUN_00408af0((void *)(param_1 + 0x140),&local_b4);
      ppvVar6 = (void **)*puVar3;
    }
    else {
      ppvVar6 = (void **)*ppvVar6;
    }
    local_ec = ppvVar6;
    FUN_00408820((int)puVar7);
    FUN_00408de0((int)puVar7);
    FUN_00402850("Lane %d , HandleRecognition recover web request by trigger id (%d) WebServerRequests:%d"
                 ,(char)*(undefined4 *)(param_1 + 0x3c));
    puVar7 = local_dc;
  }
  if (((0 < *(int *)(param_1 + 0xa0)) || (0 < *(int *)(param_1 + 0x68))) && (local_ed != '\0')) {
    FUN_00402f40(&local_ec,param_1 + 0x170);
    local_4._0_1_ = 0x10;
    uVar14 = FUN_004087d0((int)puVar7);
    FUN_0040a730((void *)(param_1 + 0xb0),uVar14,puVar7);
    local_4 = CONCAT31(local_4._1_3_,0xe);
    FUN_00402f90((int *)&local_ec);
  }
  local_4._0_1_ = 5;
  FUN_00402f90(&local_b0);
  local_4._0_1_ = 4;
  FUN_00401170(local_6c);
  local_4._0_1_ = 3;
  FUN_00401170(local_84);
  local_4._0_1_ = 2;
  FUN_00401170(&local_e8);
  local_4._0_1_ = 1;
  FUN_00401170(&local_cc);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170(local_78);
  local_4 = 0xffffffff;
  FUN_00411740((int *)&param_3);
  ExceptionList = local_c;
  ___security_check_cookie_4(local_10 ^ (uint)auStack_f0);
  return;
}



// WARNING (jumptable): Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x0040fa83)

void __fastcall FUN_0040f630(void *param_1)

{
  int *piVar1;
  uint uVar2;
  char cVar3;
  undefined4 *puVar4;
  tm *ptVar5;
  int *piVar6;
  undefined4 *puVar7;
  int **ppiVar8;
  int iVar9;
  void *this;
  int iVar10;
  void *this_00;
  undefined4 uVar11;
  undefined extraout_CL;
  undefined extraout_DL;
  undefined extraout_DL_00;
  int *piVar12;
  __time64_t _Var13;
  __time64_t _Var14;
  longlong lVar15;
  longlong lVar16;
  undefined uVar17;
  int *local_184;
  int *local_180;
  undefined4 *local_17c;
  undefined *local_178;
  int *local_174;
  int *local_170;
  undefined *local_16c [2];
  int local_164;
  undefined4 local_15c;
  undefined4 local_158;
  void *local_154 [3];
  void *local_148 [3];
  void *local_13c [3];
  void *local_130 [3];
  void *local_124 [3];
  void *local_118 [3];
  void *local_10c [3];
  void *local_100 [3];
  void *local_f4 [3];
  undefined4 local_e8 [2];
  undefined4 local_e0 [2];
  undefined4 local_d8 [2];
  undefined4 local_d0 [2];
  int local_c8 [2];
  undefined4 local_c0 [2];
  tm local_b8;
  tm local_90;
  undefined4 local_68 [10];
  tm local_40;
  void *local_14;
  undefined *puStack_10;
  undefined4 local_c;
  
  local_c = 0xffffffff;
  puStack_10 = &LAB_0041bd33;
  local_14 = ExceptionList;
  ExceptionList = &local_14;
  FUN_00403420(param_1,1);
  cVar3 = FUN_00403410((int)param_1);
  do {
    if (cVar3 != '\0') {
      ExceptionList = local_14;
      return;
    }
    local_17c = (undefined4 *)0x0;
    FUN_0040c8d0((void *)((int)param_1 + 0xdc),(int *)&local_17c,15000);
    puVar4 = (undefined4 *)FUN_00409310((void *)((int)param_1 + 0xb0),local_d8);
    puVar7 = (undefined4 *)*puVar4;
    local_180 = (int *)puVar4[1];
    while (puVar7 != (undefined4 *)0x0) {
      if (local_180[1] != 0) {
        for (puVar4 = *(undefined4 **)
                       (local_180[1] + (((uint)puVar7[2] >> 4) % (uint)local_180[2]) * 4);
            puVar4 != (undefined4 *)0x0; puVar4 = (undefined4 *)*puVar4) {
          if (puVar4[2] == puVar7[2]) goto LAB_0040f6ed;
        }
      }
      puVar4 = (undefined4 *)0x0;
LAB_0040f6ed:
      piVar12 = (int *)puVar4[3];
      ptVar5 = (tm *)FUN_004087b0(piVar12,&local_b8.tm_sec);
      _Var13 = FUN_00403040(ptVar5);
      ptVar5 = FUN_00403080(&local_90);
      _Var14 = FUN_00403040(ptVar5);
      if ((int)_Var14 - (int)_Var13 < 0x79) {
        puVar7 = (undefined4 *)*puVar7;
      }
      else {
        FUN_004087d0((int)piVar12);
        FUN_00402870("Lane %d. Delete obsolete car data ev:%d",
                     (char)*(undefined4 *)((int)param_1 + 0x3c));
        FUN_00402ed0((int)param_1 + 0x170);
        piVar6 = (int *)FUN_004087d0((int)piVar12);
        FUN_0040d510((void *)((int)param_1 + 0xb0),piVar6);
        if (piVar12 != (int *)0x0) {
          (**(code **)(*piVar12 + 4))();
        }
        FUN_00402f10((int)param_1 + 0x170);
        puVar7 = (undefined4 *)FUN_00409310((void *)((int)param_1 + 0xb0),local_c0);
        local_180 = (int *)puVar7[1];
        puVar7 = (undefined4 *)*puVar7;
      }
    }
    FUN_00402ed0((int)param_1 + 0x14c);
    ppiVar8 = (int **)FUN_00408af0((void *)((int)param_1 + 0x140),&local_15c);
    ppiVar8 = (int **)*ppiVar8;
    while (ppiVar8 != (int **)0x0) {
      piVar12 = ppiVar8[2];
      ptVar5 = (tm *)FUN_00416470(piVar12,&local_90.tm_sec);
      _Var13 = FUN_00403040(ptVar5);
      ptVar5 = FUN_00403080(&local_b8);
      _Var14 = FUN_00403040(ptVar5);
      if ((int)_Var14 - (int)_Var13 < 0x79) {
        ppiVar8 = (int **)*ppiVar8;
      }
      else {
        FUN_00416460((int)piVar12);
        FUN_00402850("Lane %d DeleteOlderWebRequests (seconds:%d) delete old webRequest:%d",
                     (char)*(undefined4 *)((int)param_1 + 0x3c));
        piVar6 = (int *)((int)param_1 + 0x140);
        if (1 < *piVar6) {
          if (ppiVar8 == *(int ***)((int)param_1 + 0x144)) {
            piVar1 = **(int ***)((int)param_1 + 0x144);
            *(int **)((int)param_1 + 0x144) = piVar1;
            piVar1[1] = 0;
          }
          else if (ppiVar8 == *(int ***)((int)param_1 + 0x148)) {
            piVar1 = (*(int ***)((int)param_1 + 0x148))[1];
            *(int **)((int)param_1 + 0x148) = piVar1;
            *piVar1 = 0;
          }
          else {
            *ppiVar8[1] = (int)*ppiVar8;
            (*ppiVar8)[1] = (int)ppiVar8[1];
          }
        }
        operator_delete(ppiVar8);
        *piVar6 = *piVar6 + -1;
        if (*piVar6 == 0) {
          *(undefined4 *)((int)param_1 + 0x148) = 0;
          *(undefined4 *)((int)param_1 + 0x144) = 0;
        }
        iVar9 = FUN_004164e0((int)piVar12);
        if ((iVar9 == 1) && (FUN_00416570(piVar12), piVar12 != (int *)0x0)) {
          (**(code **)*piVar12)();
        }
        ppiVar8 = (int **)FUN_00408af0(piVar6,&local_158);
        ppiVar8 = (int **)*ppiVar8;
      }
    }
    FUN_00402f10((int)param_1 + 0x14c);
    puVar7 = local_17c;
    if (local_17c != (undefined4 *)0x0) {
      cVar3 = FUN_00403410((int)param_1);
      if (cVar3 == '\0') {
        puVar4 = (undefined4 *)FUN_0040bd60(local_154,puVar7);
        local_c = 0;
        FUN_004011f0(puVar4);
        FUN_00402870("Lane %d. Handle action: %s  (PendingActions.Count:%d)",
                     (char)*(undefined4 *)((int)param_1 + 0x3c));
        local_c = 0xffffffff;
        FUN_00401170(local_154);
        switch(*puVar7) {
        case 0:
          local_178 = &stack0xfffffe60;
          uVar17 = extraout_CL;
          FUN_00411720(&stack0xfffffe60,puVar7 + 10);
          this_00 = (void *)FUN_0040ed90((int)param_1,extraout_DL,uVar17);
          iVar9 = FUN_00408a90((int)this_00);
          if (iVar9 == 1) {
            ppiVar8 = (int **)FUN_00414e00((void *)((int)param_1 + 0x94),local_c8);
            local_174 = *ppiVar8;
            local_170 = ppiVar8[1];
            while ((piVar12 = local_170, local_170 != (int *)0x0 && (local_174 != (int *)0x0))) {
              FUN_00414f40((void *)local_174[3],this_00);
              FUN_0040bf60(piVar12,&local_174,(int *)local_16c,(int *)&local_178);
            }
          }
          uVar11 = FUN_00408c80((int)this_00);
          if ((char)uVar11 == '\0') {
            iVar9 = FUN_00409ac0((int)this_00);
            if (iVar9 == 0) {
              puVar4 = (undefined4 *)FUN_0040bd60(local_148,puVar7);
              local_c = 3;
              FUN_004011f0(puVar4);
              FUN_00402870("Lane %d. Handle action: %s  StartTimer DEFAULT timeout:%d (no webRequest)"
                           ,(char)*(undefined4 *)((int)param_1 + 0x3c));
              local_c = 0xffffffff;
              FUN_00401170(local_148);
              iVar9 = *(int *)((int)param_1 + 0x194);
            }
            else {
              puVar7 = local_68;
              this = (void *)FUN_00409ac0((int)this_00);
              ptVar5 = (tm *)FUN_00416470(this,puVar7);
              lVar15 = FUN_00403050(ptVar5);
              local_178 = (undefined *)((ulonglong)lVar15 >> 0x20);
              ptVar5 = FUN_00403080(&local_40);
              lVar16 = FUN_00403050(ptVar5);
              puVar7 = local_17c;
              lVar16 = lVar16 - CONCAT44(local_178,(int)lVar15);
              uVar2 = *(uint *)((int)param_1 + 0x194);
              if (lVar16 < (int)uVar2) {
                iVar9 = uVar2 - (uint)lVar16;
                local_164 = (((int)uVar2 >> 0x1f) - (int)((ulonglong)lVar16 >> 0x20)) -
                            (uint)(uVar2 < (uint)lVar16);
              }
              else {
                iVar9 = (int)uVar2 / 10;
                local_164 = iVar9 >> 0x1f;
              }
              local_17c = (undefined4 *)FUN_0040bd60(local_100,local_17c);
              local_178 = *(undefined **)((int)param_1 + 0xd0);
              local_c = 2;
              iVar10 = FUN_00409ac0((int)this_00);
              FUN_00416460(iVar10);
              FUN_004011f0(local_17c);
              FUN_00402870("Lane %d. Handle action: %s  StartTimer timeout:%d (webRequest:%d)",
                           (char)*(undefined4 *)((int)param_1 + 0x3c));
              local_c = 0xffffffff;
              FUN_00401170(local_100);
            }
            FUN_00408a20(this_00,param_1,iVar9);
            puVar4 = (undefined4 *)FUN_0040bd60(local_13c,puVar7);
            local_c = 4;
            FUN_00408c80((int)this_00);
            FUN_004087d0((int)this_00);
            FUN_004011f0(puVar4);
            FUN_00402890("Lane %d. Handle action: %s  . evId:%d  IsCompleteToSend():%d",
                         (char)*(undefined4 *)((int)param_1 + 0x3c));
            local_c = 0xffffffff;
            FUN_00401170(local_13c);
          }
          else {
            puVar4 = (undefined4 *)FUN_0040bd60(local_130,puVar7);
            local_c = 1;
            FUN_004087d0((int)this_00);
            FUN_004011f0(puVar4);
            FUN_00402870("Lane %d. Handle action: %s . evId:%d Completed",
                         (char)*(undefined4 *)((int)param_1 + 0x3c));
            local_c = 0xffffffff;
            FUN_00401170(local_130);
            uVar11 = FUN_004087d0((int)this_00);
            *(undefined4 *)((int)param_1 + 0x44) = uVar11;
LAB_0040fe3a:
            FUN_00409af0((int)this_00);
          }
          break;
        case 1:
          ppiVar8 = (int **)FUN_00409310((void *)((int)param_1 + 0xb0),local_d0);
          piVar12 = *ppiVar8;
          local_180 = ppiVar8[1];
          local_184 = piVar12;
          if (piVar12 != (int *)0x0) {
            do {
              puVar4 = (undefined4 *)0x0;
              if (local_180[1] != 0) {
                for (puVar4 = *(undefined4 **)
                               (local_180[1] + (((uint)piVar12[2] >> 4) % (uint)local_180[2]) * 4);
                    puVar4 != (undefined4 *)0x0; puVar4 = (undefined4 *)*puVar4) {
                  if (puVar4[2] == piVar12[2]) goto LAB_0040fc41;
                }
                puVar4 = (undefined4 *)0x0;
              }
LAB_0040fc41:
              iVar9 = puVar4[3];
              local_184 = piVar12;
              cVar3 = FUN_004087a0(iVar9);
              if (cVar3 != '\0') {
                FUN_00408830(iVar9);
              }
              piVar12 = (int *)*piVar12;
            } while (piVar12 != (int *)0x0);
            local_184 = (int *)0x0;
          }
          break;
        case 2:
          uVar17 = 0x7d;
          ppiVar8 = (int **)FUN_004092e0((void *)((int)param_1 + 0xb0),local_e0,puVar7[8]);
          local_184 = *ppiVar8;
          local_180 = ppiVar8[1];
          if (local_184 == (int *)0x0) {
            puVar4 = (undefined4 *)FUN_0040bd60(local_124,puVar7);
            local_c = 5;
            FUN_004011f0(puVar4);
            FUN_00402890("Lane %d. Handle action: %s . Not found CarData EventId:%d",
                         (char)*(undefined4 *)((int)param_1 + 0x3c));
            local_c = 0xffffffff;
            FUN_00401170(local_124);
          }
          else {
            this_00 = (void *)FUN_0040d020((int *)&local_184);
            local_16c[0] = &stack0xfffffe58;
            FUN_004010b0(&stack0xfffffe58,(void **)(puVar7 + 5));
            FUN_0040a5e0(this_00,extraout_DL_00,uVar17);
            uVar11 = FUN_00408c80((int)this_00);
            if ((char)uVar11 != '\0') {
              puVar4 = (undefined4 *)FUN_0040bd60(local_10c,puVar7);
              local_c = 6;
              FUN_004011f0(puVar4);
              FUN_00402870("Lane %d. Handle action: %s . EventId:%d Completed",
                           (char)*(undefined4 *)((int)param_1 + 0x3c));
              local_c = 0xffffffff;
              FUN_00401170(local_10c);
              uVar11 = FUN_004087d0((int)this_00);
              *(undefined4 *)((int)param_1 + 0x44) = uVar11;
              goto LAB_0040fe3a;
            }
          }
          break;
        case 3:
          ppiVar8 = (int **)FUN_004092e0((void *)((int)param_1 + 0xb0),local_e8,puVar7[8]);
          local_184 = *ppiVar8;
          local_180 = ppiVar8[1];
          if (local_184 != (int *)0x0) {
            this_00 = (void *)FUN_0040d020((int *)&local_184);
            uVar11 = FUN_004087d0((int)this_00);
            *(undefined4 *)((int)param_1 + 0x44) = uVar11;
            puVar4 = (undefined4 *)FUN_0040bd60(local_118,puVar7);
            local_c = 8;
            FUN_004011f0(puVar4);
            FUN_00402890("Lane %d. Handle action: %s . EventId:%d Completed by timeout",
                         (char)*(undefined4 *)((int)param_1 + 0x3c));
            local_c = 0xffffffff;
            FUN_00401170(local_118);
            goto LAB_0040fe3a;
          }
          puVar4 = (undefined4 *)FUN_0040bd60(local_f4,puVar7);
          local_c = 7;
          FUN_004011f0(puVar4);
          FUN_00402890("Lane %d. Handle action: %s . Not found CarData EventId:%d",
                       (char)*(undefined4 *)((int)param_1 + 0x3c));
          local_c = 0xffffffff;
          FUN_00401170(local_f4);
        }
      }
      FUN_0040bcf0((int)puVar7);
      operator_delete(puVar7);
    }
    cVar3 = FUN_00403410((int)param_1);
  } while( true );
}



undefined4 __cdecl FUN_0040fe90(HINSTANCE param_1)

{
  LPCSTR lpWindowName;
  LPCSTR lpClassName;
  DWORD dwStyle;
  int X;
  int Y;
  int nWidth;
  int nHeight;
  HWND pHVar1;
  HMENU hMenu;
  HINSTANCE hInstance;
  LPVOID lpParam;
  
  lpParam = (LPVOID)0x0;
  hMenu = (HMENU)0x0;
  pHVar1 = (HWND)0x0;
  nHeight = 0;
  nWidth = -0x80000000;
  Y = 0;
  X = -0x80000000;
  dwStyle = 0xcf0000;
  hInstance = param_1;
  lpWindowName = FUN_004011f0((undefined4 *)&DAT_0042b1a4);
  lpClassName = FUN_004011f0((undefined4 *)&DAT_0042b1b0);
  pHVar1 = CreateWindowExA(0,lpClassName,lpWindowName,dwStyle,X,Y,nWidth,nHeight,pHVar1,hMenu,
                           hInstance,lpParam);
  if (pHVar1 == (HWND)0x0) {
    return 0;
  }
  ShowWindow(pHVar1,0);
  UpdateWindow(pHVar1);
  DAT_0042b198 = param_1;
  DAT_0042b19c = pHVar1;
  DAT_0042b1a0 = GetMenu(pHVar1);
  DAT_0042b1a0 = GetSubMenu(DAT_0042b1a0,0);
  return CONCAT31((int3)((uint)DAT_0042b1a0 >> 8),1);
}



void FUN_0040ff20(HWND param_1,uint param_2,uint param_3,int param_4)

{
  tagPOINT local_4c;
  tagPAINTSTRUCT local_44;
  uint local_4;
  
  local_4 = DAT_00428400 ^ (uint)&local_4c;
  if (param_2 < 0x112) {
    if (param_2 == 0x111) goto LAB_0040ffd5;
    if (param_2 != 2) {
      if (param_2 != 0xf) goto LAB_0040ff80;
      BeginPaint(param_1,&local_44);
      EndPaint(param_1,&local_44);
      goto LAB_0041000d;
    }
  }
  else {
    if (param_2 != 0x400) {
LAB_0040ff80:
      DefWindowProcA(param_1,param_2,param_3,param_4);
      ___security_check_cookie_4(local_4 ^ (uint)&local_4c);
      return;
    }
    if (param_4 == 0x204) {
      GetCursorPos(&local_4c);
      TrackPopupMenu(DAT_0042b1a0,0x28,local_4c.x,local_4c.y,0,param_1,(RECT *)0x0);
    }
LAB_0040ffd5:
    if ((param_3 & 0xffff) == 0) goto LAB_0041000d;
    if ((param_3 & 0xffff) != 0x9c4c) {
      DefWindowProcA(param_1,param_2,param_3,param_4);
      ___security_check_cookie_4(local_4 ^ (uint)&local_4c);
      return;
    }
  }
  PostQuitMessage(0);
LAB_0041000d:
  ___security_check_cookie_4(local_4 ^ (uint)&local_4c);
  return;
}



void FUN_00410030(void)

{
  WNDCLASSEXA local_30;
  
  local_30.cbSize = 0x30;
  local_30.style = 3;
  local_30.lpfnWndProc = FUN_0040ff20;
  local_30.cbClsExtra = 0;
  local_30.cbWndExtra = 0;
  local_30.hInstance = DAT_0042b198;
  local_30.hIcon = LoadIconA(DAT_0042b198,(LPCSTR)0x65);
  local_30.hCursor = LoadCursorA((HINSTANCE)0x0,(LPCSTR)0x7f00);
  local_30.hbrBackground = (HBRUSH)0x6;
  local_30.lpszMenuName = (LPCSTR)0x68;
  local_30.lpszClassName = FUN_004011f0((undefined4 *)&DAT_0042b1b0);
  local_30.hIconSm = LoadIconA(local_30.hInstance,(LPCSTR)0x65);
  RegisterClassExA(&local_30);
  return;
}



void FUN_004100c0(HINSTANCE param_1,undefined4 param_2,char *param_3)

{
  char cVar1;
  void **ppvVar2;
  int iVar3;
  char **ppcVar4;
  undefined4 uVar5;
  undefined extraout_DL;
  undefined4 *puVar6;
  CHAR *pCVar7;
  undefined in_stack_fffffc2c;
  undefined uVar8;
  undefined uVar9;
  undefined in_stack_fffffc38;
  undefined uVar10;
  undefined uVar11;
  undefined in_stack_fffffc44;
  undefined uVar12;
  undefined in_stack_fffffc50;
  undefined in_stack_fffffc5c;
  undefined uVar13;
  undefined *puStack_37c;
  char *local_378 [3];
  char *local_36c;
  char *local_368;
  char *local_360;
  char *local_35c;
  char *local_354;
  char *local_350;
  char *local_348;
  char *local_344;
  char *local_33c;
  char *local_338;
  char *local_330;
  char *local_32c;
  char *local_324 [8];
  void *local_304 [3];
  tagMSG tStack_2f8;
  undefined4 local_2dc [160];
  _NOTIFYICONDATAA _Stack_5c;
  uint local_4;
  
  local_4 = DAT_00428400 ^ (uint)&puStack_37c;
  FUN_00401100(local_304," ",(char *)0x7fffffff);
  ppvVar2 = FUN_00401100(local_378,param_3,(char *)0x7fffffff);
  FUN_00404340(local_324,ppvVar2);
  FUN_00401170(local_378);
  FUN_00401170(local_304);
  FUN_004010a0(&local_36c);
  FUN_004010a0(&local_360);
  FUN_004010a0(&local_348);
  FUN_004010a0(&local_33c);
  FUN_004010a0(&local_330);
  FUN_004010a0(&local_354);
  FUN_004146d0(local_2dc);
  iVar3 = FUN_00404430(local_324);
  if (iVar3 == 6) {
    ppcVar4 = FUN_00404520(local_324,local_378);
    if (*ppcVar4 != local_36c) {
      FUN_00401910(&local_36c,(uint)ppcVar4[1]);
      memcpy(local_36c,*ppcVar4,(size_t)ppcVar4[1]);
      local_368 = ppcVar4[1];
      local_368[(int)local_36c] = '\0';
    }
    FUN_00401170(local_378);
    ppcVar4 = FUN_00404520(local_324,local_378);
    if (*ppcVar4 != local_360) {
      FUN_00401910(&local_360,(uint)ppcVar4[1]);
      memcpy(local_360,*ppcVar4,(size_t)ppcVar4[1]);
      local_35c = ppcVar4[1];
      local_35c[(int)local_360] = '\0';
    }
    FUN_00401170(local_378);
    ppcVar4 = FUN_00404520(local_324,local_378);
    if (*ppcVar4 != local_348) {
      FUN_00401910(&local_348,(uint)ppcVar4[1]);
      memcpy(local_348,*ppcVar4,(size_t)ppcVar4[1]);
      local_344 = ppcVar4[1];
      local_344[(int)local_348] = '\0';
    }
    FUN_00401170(local_378);
    ppcVar4 = FUN_00404520(local_324,local_378);
    if (*ppcVar4 != local_33c) {
      FUN_00401910(&local_33c,(uint)ppcVar4[1]);
      memcpy(local_33c,*ppcVar4,(size_t)ppcVar4[1]);
      local_338 = ppcVar4[1];
      local_338[(int)local_33c] = '\0';
    }
    FUN_00401170(local_378);
    ppcVar4 = FUN_00404520(local_324,local_378);
    if (*ppcVar4 != local_330) {
      FUN_00401910(&local_330,(uint)ppcVar4[1]);
      memcpy(local_330,*ppcVar4,(size_t)ppcVar4[1]);
      local_32c = ppcVar4[1];
      local_32c[(int)local_330] = '\0';
    }
    FUN_00401170(local_378);
    ppcVar4 = FUN_00404520(local_324,local_378);
    if (*ppcVar4 != local_354) {
      FUN_00401910(&local_354,(uint)ppcVar4[1]);
      memcpy(local_354,*ppcVar4,(size_t)ppcVar4[1]);
      local_350 = ppcVar4[1];
      local_350[(int)local_354] = '\0';
    }
    FUN_00401170(local_378);
    uVar13 = 0x91;
    printf("\n  Quercus Technologies - LPRScheidtBachmannV3 (v%s)\n");
    FUN_00401040(&DAT_0042b1b0,"WND");
    FUN_00401040(&DAT_0042b1a4,"SmartLPRAccessBridge.exe");
    FUN_00410030();
    uVar5 = FUN_0040fe90(param_1);
    if ((char)uVar5 == '\0') {
      FUN_00414900(local_2dc);
      FUN_00401170(&local_354);
      FUN_00401170(&local_330);
      FUN_00401170(&local_33c);
      FUN_00401170(&local_348);
      FUN_00401170(&local_360);
      FUN_00401170(&local_36c);
      FUN_0040bc30(local_324);
      goto LAB_00410636;
    }
    puStack_37c = &stack0xfffffc68;
    _Stack_5c.hWnd = DAT_0042b19c;
    _Stack_5c.cbSize = 0x58;
    _Stack_5c.uCallbackMessage = 0x400;
    _Stack_5c.uFlags = 7;
    _Stack_5c.uID = 0;
    FUN_004010b0(&stack0xfffffc68,&local_354);
    puStack_37c = &stack0xfffffc5c;
    FUN_004010b0(&stack0xfffffc5c,&local_330);
    puStack_37c = &stack0xfffffc50;
    uVar12 = 0x89;
    FUN_004010b0(&stack0xfffffc50,&local_33c);
    puStack_37c = &stack0xfffffc44;
    ppcVar4 = &local_348;
    uVar10 = 0x9c;
    FUN_004010b0(&stack0xfffffc44,ppcVar4);
    uVar11 = SUB41(ppcVar4,0);
    puStack_37c = &stack0xfffffc38;
    ppcVar4 = &local_360;
    uVar8 = 0xaf;
    FUN_004010b0(&stack0xfffffc38,ppcVar4);
    uVar9 = SUB41(ppcVar4,0);
    puStack_37c = &stack0xfffffc2c;
    FUN_004010b0(&stack0xfffffc2c,&local_36c);
    cVar1 = FUN_00413ad0(local_2dc,extraout_DL,in_stack_fffffc2c,uVar8,uVar9,in_stack_fffffc38,
                         uVar10,uVar11,in_stack_fffffc44,uVar12,in_stack_fffffc50,in_stack_fffffc5c,
                         uVar13);
    if (cVar1 == '\0') {
      MessageBoxA((HWND)0x0,
                  "Can\'t initialize SmartLPRAccessBridge\n\nTurn-off SmartLPRAccessBridge and review Log\\ScheidtBachmannV3.log file"
                  ,"Notification",0x30);
      _Stack_5c.hIcon = LoadIconA(param_1,(LPCSTR)0x69);
      puVar6 = (undefined4 *)"SmartLPRAccessBridge\nConfiguration error";
      pCVar7 = _Stack_5c.szTip;
      for (iVar3 = 10; iVar3 != 0; iVar3 = iVar3 + -1) {
        *(undefined4 *)pCVar7 = *puVar6;
        puVar6 = puVar6 + 1;
        pCVar7 = pCVar7 + 4;
      }
      *pCVar7 = *(CHAR *)puVar6;
    }
    else {
      _Stack_5c.hIcon = LoadIconA(param_1,(LPCSTR)0x65);
      _Stack_5c.szTip[0] = 'S';
      _Stack_5c.szTip[1] = 'm';
      _Stack_5c.szTip[2] = 'a';
      _Stack_5c.szTip[3] = 'r';
      _Stack_5c.szTip[4] = 't';
      _Stack_5c.szTip[5] = 'L';
      _Stack_5c.szTip[6] = 'P';
      _Stack_5c.szTip[7] = 'R';
      _Stack_5c.szTip[8] = 'A';
      _Stack_5c.szTip[9] = 'c';
      _Stack_5c.szTip[10] = 'c';
      _Stack_5c.szTip[0xb] = 'e';
      _Stack_5c.szTip[0xc] = 's';
      _Stack_5c.szTip[0xd] = 's';
      _Stack_5c.szTip[0xe] = 'B';
      _Stack_5c.szTip[0xf] = 'r';
      _Stack_5c.szTip[0x10] = 'i';
      _Stack_5c.szTip[0x11] = 'd';
      _Stack_5c.szTip[0x12] = 'g';
      _Stack_5c.szTip[0x13] = 'e';
      _Stack_5c.szTip[0x14] = '\0';
    }
    Shell_NotifyIconA(0,&_Stack_5c);
    iVar3 = GetMessageA(&tStack_2f8,DAT_0042b19c,0,0);
    while (iVar3 != 0) {
      TranslateMessage(&tStack_2f8);
      DispatchMessageA(&tStack_2f8);
      iVar3 = GetMessageA(&tStack_2f8,DAT_0042b19c,0,0);
    }
    FUN_00413280((int)local_2dc);
    Shell_NotifyIconA(2,&_Stack_5c);
  }
  else {
    MessageBoxA((HWND)0x0,
                "Can\'t initialize SmartLPRAccessBridge, invalid number of parameters\n\nsage: SmartLPRAccessBridge.exe scheidtbachmannIniFile scheidtbachmannLogFile accessIniFile accessLogFile recIniFile recLogFile"
                ,"Warning",0x30);
  }
  FUN_00414900(local_2dc);
  FUN_00401170(&local_354);
  FUN_00401170(&local_330);
  FUN_00401170(&local_33c);
  FUN_00401170(&local_348);
  FUN_00401170(&local_360);
  FUN_00401170(&local_36c);
  FUN_0040bc30(local_324);
LAB_00410636:
  ___security_check_cookie_4(local_4 ^ (uint)&puStack_37c);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00410660(void)

{
  char *pcVar1;
  
  DAT_0042b1bc = LoadLibraryA("SA.dll");
  if (DAT_0042b1bc == (HMODULE)0x0) {
    return 0xffffffff;
  }
  _DAT_0042b72c = GetProcAddress(DAT_0042b1bc,"System_get_Status");
  if (_DAT_0042b72c == (FARPROC)0x0) {
    pcVar1 = "System_get_Status";
  }
  else {
    DAT_0042b8d8 = GetProcAddress(DAT_0042b1bc,"System_get_Units_Item");
    if (DAT_0042b8d8 == (FARPROC)0x0) {
      pcVar1 = "System_get_Units_Item";
    }
    else {
      _DAT_0042b728 = GetProcAddress(DAT_0042b1bc,"System_get_Units_Count");
      if (_DAT_0042b728 == (FARPROC)0x0) {
        pcVar1 = "System_get_Units_Count";
      }
      else {
        DAT_0042b8d4 = GetProcAddress(DAT_0042b1bc,"System_Initialize");
        if (DAT_0042b8d4 == (FARPROC)0x0) {
          pcVar1 = "System_Initialize";
        }
        else {
          _DAT_0042b738 = GetProcAddress(DAT_0042b1bc,"System_Terminate");
          if (_DAT_0042b738 == (FARPROC)0x0) {
            pcVar1 = "System_Terminate";
          }
          else {
            DAT_0042b834 = GetProcAddress(DAT_0042b1bc,"Unit_get_Id");
            if (DAT_0042b834 == (FARPROC)0x0) {
              pcVar1 = "Unit_get_Id";
            }
            else {
              DAT_0042b89c = GetProcAddress(DAT_0042b1bc,"Unit_get_Configuration");
              if (DAT_0042b89c == (FARPROC)0x0) {
                pcVar1 = "Unit_get_Configuration";
              }
              else {
                _DAT_0042b858 = GetProcAddress(DAT_0042b1bc,"Unit_get_Active");
                if (_DAT_0042b858 == (FARPROC)0x0) {
                  pcVar1 = "Unit_get_Active";
                }
                else {
                  _DAT_0042b848 = GetProcAddress(DAT_0042b1bc,"Unit_get_OfflineCar");
                  if (_DAT_0042b848 == (FARPROC)0x0) {
                    pcVar1 = "Unit_get_OfflineCar";
                  }
                  else {
                    _DAT_0042b814 = GetProcAddress(DAT_0042b1bc,"Unit_get_Status");
                    if (_DAT_0042b814 == (FARPROC)0x0) {
                      pcVar1 = "Unit_get_Status";
                    }
                    else {
                      _DAT_0042b90c = GetProcAddress(DAT_0042b1bc,"Unit_Activate");
                      if (_DAT_0042b90c == (FARPROC)0x0) {
                        pcVar1 = "Unit_Activate";
                      }
                      else {
                        _DAT_0042b80c = GetProcAddress(DAT_0042b1bc,"Unit_MoveFirst");
                        if (_DAT_0042b80c == (FARPROC)0x0) {
                          pcVar1 = "Unit_MoveFirst";
                        }
                        else {
                          _DAT_0042b79c = GetProcAddress(DAT_0042b1bc,"Unit_MoveNext");
                          if (_DAT_0042b79c == (FARPROC)0x0) {
                            pcVar1 = "Unit_MoveNext";
                          }
                          else {
                            _DAT_0042b810 = GetProcAddress(DAT_0042b1bc,"Unit_MovePrevious");
                            if (_DAT_0042b810 == (FARPROC)0x0) {
                              pcVar1 = "Unit_MovePrevious";
                            }
                            else {
                              _DAT_0042b8e8 = GetProcAddress(DAT_0042b1bc,"Unit_MoveLast");
                              if (_DAT_0042b8e8 == (FARPROC)0x0) {
                                pcVar1 = "Unit_MoveLast";
                              }
                              else {
                                _DAT_0042b818 = GetProcAddress(DAT_0042b1bc,"Unit_Reboot");
                                if (_DAT_0042b818 == (FARPROC)0x0) {
                                  pcVar1 = "Unit_Reboot";
                                }
                                else {
                                  _DAT_0042b8e0 = GetProcAddress(DAT_0042b1bc,"Unit_ActivateOutput")
                                  ;
                                  if (_DAT_0042b8e0 == (FARPROC)0x0) {
                                    pcVar1 = "Unit_ActivateOutput";
                                  }
                                  else {
                                    DAT_0042b874 = GetProcAddress(DAT_0042b1bc,"Unit_Trigger");
                                    if (DAT_0042b874 == (FARPROC)0x0) {
                                      pcVar1 = "Unit_Trigger";
                                    }
                                    else {
                                      _DAT_0042b740 =
                                           GetProcAddress(DAT_0042b1bc,
                                                          "Unit_GetRecognitionStatistics");
                                      if (_DAT_0042b740 == (FARPROC)0x0) {
                                        pcVar1 = "Unit_GetRecognitionStatistics";
                                      }
                                      else {
                                        _DAT_0042b784 =
                                             GetProcAddress(DAT_0042b1bc,"Unit_GetInputValues");
                                        if (_DAT_0042b784 == (FARPROC)0x0) {
                                          pcVar1 = "Unit_GetInputValues";
                                        }
                                        else {
                                          _DAT_0042b720 =
                                               GetProcAddress(DAT_0042b1bc,"Unit_GetVersion");
                                          if (_DAT_0042b720 == (FARPROC)0x0) {
                                            pcVar1 = "Unit_GetVersion";
                                          }
                                          else {
                                            _DAT_0042b774 =
                                                 GetProcAddress(DAT_0042b1bc,"Unit_GetCurrentFrame")
                                            ;
                                            if (_DAT_0042b774 == (FARPROC)0x0) {
                                              pcVar1 = "Unit_GetCurrentFrame";
                                            }
                                            else {
                                              _DAT_0042b8f8 =
                                                   GetProcAddress(DAT_0042b1bc,"Unit_LoadWhiteList")
                                              ;
                                              if (_DAT_0042b8f8 == (FARPROC)0x0) {
                                                pcVar1 = "Unit_LoadWhiteList";
                                              }
                                              else {
                                                DAT_0042b860 = GetProcAddress(DAT_0042b1bc,
                                                                              "Car_get_Id");
                                                if (DAT_0042b860 == (FARPROC)0x0) {
                                                  pcVar1 = "Car_get_Id";
                                                }
                                                else {
                                                  DAT_0042b800 = GetProcAddress(DAT_0042b1bc,
                                                                                "Car_get_TriggerId")
                                                  ;
                                                  if (DAT_0042b800 == (FARPROC)0x0) {
                                                    pcVar1 = "Car_get_TriggerId";
                                                  }
                                                  else {
                                                    _DAT_0042b748 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "Car_get_GrammarOk");
                                                    if (_DAT_0042b748 == (FARPROC)0x0) {
                                                      pcVar1 = "Car_get_GrammarOk";
                                                    }
                                                    else {
                                                      DAT_0042b7ec = GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                        
                                                  "Car_get_Country");
                                                  if (DAT_0042b7ec == (FARPROC)0x0) {
                                                    pcVar1 = "Car_get_Country";
                                                  }
                                                  else {
                                                    DAT_0042b898 = GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                    
                                                  "Car_get_AvgQuality");
                                                  if (DAT_0042b898 == (FARPROC)0x0) {
                                                    pcVar1 = "Car_get_AvgQuality";
                                                  }
                                                  else {
                                                    _DAT_0042b888 =
                                                         GetProcAddress(DAT_0042b1bc,"Car_get_State"
                                                                       );
                                                    if (_DAT_0042b888 == (FARPROC)0x0) {
                                                      pcVar1 = "Car_get_State";
                                                    }
                                                    else {
                                                      DAT_0042b8f4 = GetProcAddress(DAT_0042b1bc,
                                                                                    "Car_get_Unit");
                                                      if (DAT_0042b8f4 == (FARPROC)0x0) {
                                                        pcVar1 = "Car_get_Unit";
                                                      }
                                                      else {
                                                        DAT_0042b844 = GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                            
                                                  "Car_get_License");
                                                  if (DAT_0042b844 == (FARPROC)0x0) {
                                                    pcVar1 = "Car_get_License";
                                                  }
                                                  else {
                                                    _DAT_0042b74c =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "Car_get_MinQuality");
                                                    if (_DAT_0042b74c == (FARPROC)0x0) {
                                                      pcVar1 = "Car_get_MinQuality";
                                                    }
                                                    else {
                                                      _DAT_0042b77c =
                                                           GetProcAddress(DAT_0042b1bc,"Car_get_ROI"
                                                                         );
                                                      if (_DAT_0042b77c == (FARPROC)0x0) {
                                                        pcVar1 = "Car_get_ROI";
                                                      }
                                                      else {
                                                        DAT_0042b7b0 = GetProcAddress(DAT_0042b1bc,
                                                                                      "Car_GetImage"
                                                                                     );
                                                        if (DAT_0042b7b0 == (FARPROC)0x0) {
                                                          pcVar1 = "Car_GetImage";
                                                        }
                                                        else {
                                                          DAT_0042b868 = GetProcAddress(DAT_0042b1bc
                                                                                        ,
                                                  "Car_get_TimeStamp");
                                                  if (DAT_0042b868 == (FARPROC)0x0) {
                                                    pcVar1 = "Car_get_TimeStamp";
                                                  }
                                                  else {
                                                    DAT_0042b8e4 = GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                    
                                                  "Car_get_TimeStampUSec");
                                                  if (DAT_0042b8e4 == (FARPROC)0x0) {
                                                    pcVar1 = "Car_get_TimeStampUSec";
                                                  }
                                                  else {
                                                    DAT_0042b8ac = GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                    
                                                  "Car_get_Chars_Item");
                                                  if (DAT_0042b8ac == (FARPROC)0x0) {
                                                    pcVar1 = "Car_get_Chars_Item";
                                                  }
                                                  else {
                                                    DAT_0042b828 = GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                    
                                                  "Car_get_Chars_Count");
                                                  if (DAT_0042b828 == (FARPROC)0x0) {
                                                    pcVar1 = "Car_get_Chars_Count";
                                                  }
                                                  else {
                                                    _DAT_0042b824 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "Car_get_NumberOfUnknownChars");
                                                  if (_DAT_0042b824 == (FARPROC)0x0) {
                                                    pcVar1 = "Car_get_NumberOfUnknownChars";
                                                  }
                                                  else {
                                                    DAT_0042b780 = GetProcAddress(DAT_0042b1bc,
                                                                                  "Car_AddRef");
                                                    if (DAT_0042b780 == (FARPROC)0x0) {
                                                      pcVar1 = "Car_AddRef";
                                                    }
                                                    else {
                                                      DAT_0042b8c4 = GetProcAddress(DAT_0042b1bc,
                                                                                    "Car_Release");
                                                      if (DAT_0042b8c4 == (FARPROC)0x0) {
                                                        pcVar1 = "Car_Release";
                                                      }
                                                      else {
                                                        _DAT_0042b808 =
                                                             GetProcAddress(DAT_0042b1bc,
                                                                            "Char_get_Character");
                                                        if (_DAT_0042b808 == (FARPROC)0x0) {
                                                          pcVar1 = "Char_get_Character";
                                                        }
                                                        else {
                                                          DAT_0042b8d0 = GetProcAddress(DAT_0042b1bc
                                                                                        ,
                                                  "Char_get_CharacterUTF8");
                                                  if (DAT_0042b8d0 == (FARPROC)0x0) {
                                                    pcVar1 = "Char_get_CharacterUTF8";
                                                  }
                                                  else {
                                                    DAT_0042b840 = GetProcAddress(DAT_0042b1bc,
                                                                                  "Char_get_Quality"
                                                                                 );
                                                    if (DAT_0042b840 == (FARPROC)0x0) {
                                                      pcVar1 = "Char_get_Quality";
                                                    }
                                                    else {
                                                      DAT_0042b770 = GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                        
                                                  "Notification_get_Code");
                                                  if (DAT_0042b770 == (FARPROC)0x0) {
                                                    pcVar1 = "Notification_get_Code";
                                                  }
                                                  else {
                                                    DAT_0042b890 = GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                    
                                                  "Notification_get_Unit");
                                                  if (DAT_0042b890 == (FARPROC)0x0) {
                                                    pcVar1 = "Notification_get_Unit";
                                                  }
                                                  else {
                                                    _DAT_0042b794 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "UnitStatus_get_Global");
                                                    if (_DAT_0042b794 == (FARPROC)0x0) {
                                                      pcVar1 = "UnitStatus_get_Global";
                                                    }
                                                    else {
                                                      _DAT_0042b830 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                          "UnitStatus_get_IOCard");
                                                      if (_DAT_0042b830 == (FARPROC)0x0) {
                                                        pcVar1 = "UnitStatus_get_IOCard";
                                                      }
                                                      else {
                                                        _DAT_0042b8b0 =
                                                             GetProcAddress(DAT_0042b1bc,
                                                                            "UnitStatus_get_Camera")
                                                        ;
                                                        if (_DAT_0042b8b0 == (FARPROC)0x0) {
                                                          pcVar1 = "UnitStatus_get_Camera";
                                                        }
                                                        else {
                                                          _DAT_0042b754 =
                                                               GetProcAddress(DAT_0042b1bc,
                                                                              "UnitStatus_get_Focus"
                                                                             );
                                                          if (_DAT_0042b754 == (FARPROC)0x0) {
                                                            pcVar1 = "UnitStatus_get_Focus";
                                                          }
                                                          else {
                                                            _DAT_0042b7dc =
                                                                 GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                
                                                  "UnitStatus_get_Temperature");
                                                  if (_DAT_0042b7dc == (FARPROC)0x0) {
                                                    pcVar1 = "UnitStatus_get_Temperature";
                                                  }
                                                  else {
                                                    _DAT_0042b850 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "UnitStatus_get_Communication");
                                                  if (_DAT_0042b850 == (FARPROC)0x0) {
                                                    pcVar1 = "UnitStatus_get_Communication";
                                                  }
                                                  else {
                                                    _DAT_0042b7ac =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "VersionInfo_get_Name");
                                                    if (_DAT_0042b7ac == (FARPROC)0x0) {
                                                      pcVar1 = "VersionInfo_get_Name";
                                                    }
                                                    else {
                                                      _DAT_0042b8c0 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                          "VersionInfo_get_Major");
                                                      if (_DAT_0042b8c0 == (FARPROC)0x0) {
                                                        pcVar1 = "VersionInfo_get_Major";
                                                      }
                                                      else {
                                                        _DAT_0042b8a4 =
                                                             GetProcAddress(DAT_0042b1bc,
                                                                            "VersionInfo_get_Minor")
                                                        ;
                                                        if (_DAT_0042b8a4 == (FARPROC)0x0) {
                                                          pcVar1 = "VersionInfo_get_Minor";
                                                        }
                                                        else {
                                                          _DAT_0042b838 =
                                                               GetProcAddress(DAT_0042b1bc,
                                                                                                                                                            
                                                  "VersionInfo_get_Revision");
                                                  if (_DAT_0042b838 == (FARPROC)0x0) {
                                                    pcVar1 = "VersionInfo_get_Revision";
                                                  }
                                                  else {
                                                    DAT_0042b82c = GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                    
                                                  "Configuration_Login");
                                                  if (DAT_0042b82c == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_Login";
                                                  }
                                                  else {
                                                    _DAT_0042b734 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "Configuration_Logout");
                                                    if (_DAT_0042b734 == (FARPROC)0x0) {
                                                      pcVar1 = "Configuration_Logout";
                                                    }
                                                    else {
                                                      _DAT_0042b75c =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                                                                                                    
                                                  "Configuration_ChangePassword");
                                                  if (_DAT_0042b75c == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_ChangePassword";
                                                  }
                                                  else {
                                                    _DAT_0042b87c =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "Configuration_SyncTime");
                                                    if (_DAT_0042b87c == (FARPROC)0x0) {
                                                      pcVar1 = "Configuration_SyncTime";
                                                    }
                                                    else {
                                                      _DAT_0042b8b8 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                          "Configuration_SetTime");
                                                      if (_DAT_0042b8b8 == (FARPROC)0x0) {
                                                        pcVar1 = "Configuration_SetTime";
                                                      }
                                                      else {
                                                        _DAT_0042b7a4 =
                                                             GetProcAddress(DAT_0042b1bc,
                                                                                                                                                        
                                                  "Configuration_GetLanguage");
                                                  if (_DAT_0042b7a4 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_GetLanguage";
                                                  }
                                                  else {
                                                    _DAT_0042b798 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "Configuration_SetLanguage")
                                                    ;
                                                    if (_DAT_0042b798 == (FARPROC)0x0) {
                                                      pcVar1 = "Configuration_SetLanguage";
                                                    }
                                                    else {
                                                      _DAT_0042b7e8 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                                                                                                    
                                                  "Configuration_UpdateFirmware");
                                                  if (_DAT_0042b7e8 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_UpdateFirmware";
                                                  }
                                                  else {
                                                    _DAT_0042b750 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "Configuration_RestoreFirmware");
                                                  if (_DAT_0042b750 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_RestoreFirmware";
                                                  }
                                                  else {
                                                    _DAT_0042b778 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "Configuration_ExportLog");
                                                    if (_DAT_0042b778 == (FARPROC)0x0) {
                                                      pcVar1 = "Configuration_ExportLog";
                                                    }
                                                    else {
                                                      DAT_0042b76c = GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                        
                                                  "Configuration_GetSystemInfo");
                                                  if (DAT_0042b76c == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_GetSystemInfo";
                                                  }
                                                  else {
                                                    _DAT_0042b8fc =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "Configuration_ExportStatus"
                                                                       );
                                                    if (_DAT_0042b8fc == (FARPROC)0x0) {
                                                      pcVar1 = "Configuration_ExportStatus";
                                                    }
                                                    else {
                                                      _DAT_0042b878 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                                                                                                    
                                                  "Configuration_GetEntriesCount");
                                                  if (_DAT_0042b878 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_GetEntriesCount";
                                                  }
                                                  else {
                                                    _DAT_0042b8c8 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "Configuration_GetEntryByIndex");
                                                  if (_DAT_0042b8c8 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_GetEntryByIndex";
                                                  }
                                                  else {
                                                    _DAT_0042b788 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "Configuration_GetEntryByName");
                                                  if (_DAT_0042b788 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_GetEntryByName";
                                                  }
                                                  else {
                                                    _DAT_0042b7f0 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "Configuration_SetEntry");
                                                    if (_DAT_0042b7f0 == (FARPROC)0x0) {
                                                      pcVar1 = "Configuration_SetEntry";
                                                    }
                                                    else {
                                                      _DAT_0042b758 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                                                                                                    
                                                  "Configuration_RestoreEntry");
                                                  if (_DAT_0042b758 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_RestoreEntry";
                                                  }
                                                  else {
                                                    _DAT_0042b8dc =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "Configuration_ApplyChanges"
                                                                       );
                                                    if (_DAT_0042b8dc == (FARPROC)0x0) {
                                                      pcVar1 = "Configuration_ApplyChanges";
                                                    }
                                                    else {
                                                      _DAT_0042b760 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                                                                                                    
                                                  "Configuration_DiscardChanges");
                                                  if (_DAT_0042b760 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_DiscardChanges";
                                                  }
                                                  else {
                                                    _DAT_0042b864 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "Configuration_ImportConfiguration");
                                                  if (_DAT_0042b864 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_ImportConfiguration";
                                                  }
                                                  else {
                                                    _DAT_0042b820 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "Configuration_ExportConfiguration");
                                                  if (_DAT_0042b820 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_ExportConfiguration";
                                                  }
                                                  else {
                                                    _DAT_0042b8cc =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "Configuration_IsLoggedIn");
                                                    if (_DAT_0042b8cc == (FARPROC)0x0) {
                                                      pcVar1 = "Configuration_IsLoggedIn";
                                                    }
                                                    else {
                                                      _DAT_0042b804 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                                                                                                    
                                                  "SystemInformation_get_Name");
                                                  if (_DAT_0042b804 == (FARPROC)0x0) {
                                                    pcVar1 = "SystemInformation_get_Name";
                                                  }
                                                  else {
                                                    _DAT_0042b7fc =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "SystemInformation_get_ProductionDate");
                                                  if (_DAT_0042b7fc == (FARPROC)0x0) {
                                                    pcVar1 = "SystemInformation_get_ProductionDate";
                                                  }
                                                  else {
                                                    DAT_0042b894 = GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                    
                                                  "SystemInformation_get_SerialNumber");
                                                  if (DAT_0042b894 == (FARPROC)0x0) {
                                                    pcVar1 = "SystemInformation_get_SerialNumber";
                                                  }
                                                  else {
                                                    _DAT_0042b870 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "SystemInformation_get_MacAddress");
                                                  if (_DAT_0042b870 == (FARPROC)0x0) {
                                                    pcVar1 = "SystemInformation_get_MacAddress";
                                                  }
                                                  else {
                                                    _DAT_0042b7a8 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "SystemInformation_get_BootTime");
                                                  if (_DAT_0042b7a8 == (FARPROC)0x0) {
                                                    pcVar1 = "SystemInformation_get_BootTime";
                                                  }
                                                  else {
                                                    _DAT_0042b7b8 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "SystemInformation_get_HardwareVersion");
                                                  if (_DAT_0042b7b8 == (FARPROC)0x0) {
                                                    pcVar1 = "SystemInformation_get_HardwareVersion"
                                                    ;
                                                  }
                                                  else {
                                                    _DAT_0042b8ec =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "SystemInformation_get_FirmwareVersion");
                                                  if (_DAT_0042b8ec == (FARPROC)0x0) {
                                                    pcVar1 = "SystemInformation_get_FirmwareVersion"
                                                    ;
                                                  }
                                                  else {
                                                    _DAT_0042b83c =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "SettingsEntry_AddRef");
                                                    if (_DAT_0042b83c == (FARPROC)0x0) {
                                                      pcVar1 = "SettingsEntry_AddRef";
                                                    }
                                                    else {
                                                      _DAT_0042b7d8 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                          "SettingsEntry_Release");
                                                      if (_DAT_0042b7d8 == (FARPROC)0x0) {
                                                        pcVar1 = "SettingsEntry_Release";
                                                      }
                                                      else {
                                                        _DAT_0042b8bc =
                                                             GetProcAddress(DAT_0042b1bc,
                                                                            "SettingsEntry_get_Name"
                                                                           );
                                                        if (_DAT_0042b8bc == (FARPROC)0x0) {
                                                          pcVar1 = "SettingsEntry_get_Name";
                                                        }
                                                        else {
                                                          _DAT_0042b88c =
                                                               GetProcAddress(DAT_0042b1bc,
                                                                                                                                                            
                                                  "SettingsEntry_get_Value");
                                                  if (_DAT_0042b88c == (FARPROC)0x0) {
                                                    pcVar1 = "SettingsEntry_get_Value";
                                                  }
                                                  else {
                                                    _DAT_0042b854 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "SettingsEntry_get_Description");
                                                  if (_DAT_0042b854 == (FARPROC)0x0) {
                                                    pcVar1 = "SettingsEntry_get_Description";
                                                  }
                                                  else {
                                                    _DAT_0042b71c =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "System_get_RemoteSystems_Item");
                                                  if (_DAT_0042b71c == (FARPROC)0x0) {
                                                    pcVar1 = "System_get_RemoteSystems_Item";
                                                  }
                                                  else {
                                                    _DAT_0042b86c =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "System_get_RemoteSystems_Count");
                                                  if (_DAT_0042b86c == (FARPROC)0x0) {
                                                    pcVar1 = "System_get_RemoteSystems_Count";
                                                  }
                                                  else {
                                                    _DAT_0042b85c =
                                                         GetProcAddress(DAT_0042b1bc,"Lane_get_Id");
                                                    if (_DAT_0042b85c == (FARPROC)0x0) {
                                                      pcVar1 = "Lane_get_Id";
                                                    }
                                                    else {
                                                      _DAT_0042b8a0 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                          "Lane_get_Parent");
                                                      if (_DAT_0042b8a0 == (FARPROC)0x0) {
                                                        pcVar1 = "Lane_get_Parent";
                                                      }
                                                      else {
                                                        _DAT_0042b7b4 =
                                                             GetProcAddress(DAT_0042b1bc,
                                                                            "Lane_get_Configuration"
                                                                           );
                                                        if (_DAT_0042b7b4 == (FARPROC)0x0) {
                                                          pcVar1 = "Lane_get_Configuration";
                                                        }
                                                        else {
                                                          _DAT_0042b8a8 =
                                                               GetProcAddress(DAT_0042b1bc,
                                                                              "Lane_get_Active");
                                                          if (_DAT_0042b8a8 == (FARPROC)0x0) {
                                                            pcVar1 = "Lane_get_Active";
                                                          }
                                                          else {
                                                            _DAT_0042b790 =
                                                                 GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                
                                                  "Lane_get_OfflineCar");
                                                  if (_DAT_0042b790 == (FARPROC)0x0) {
                                                    pcVar1 = "Lane_get_OfflineCar";
                                                  }
                                                  else {
                                                    _DAT_0042b7e4 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "Lane_get_Status");
                                                    if (_DAT_0042b7e4 == (FARPROC)0x0) {
                                                      pcVar1 = "Lane_get_Status";
                                                    }
                                                    else {
                                                      _DAT_0042b7d0 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                          "Lane_Activate");
                                                      if (_DAT_0042b7d0 == (FARPROC)0x0) {
                                                        pcVar1 = "Lane_Activate";
                                                      }
                                                      else {
                                                        _DAT_0042b880 =
                                                             GetProcAddress(DAT_0042b1bc,
                                                                            "Lane_MoveFirst");
                                                        if (_DAT_0042b880 == (FARPROC)0x0) {
                                                          pcVar1 = "Lane_MoveFirst";
                                                        }
                                                        else {
                                                          _DAT_0042b904 =
                                                               GetProcAddress(DAT_0042b1bc,
                                                                              "Lane_MoveNext");
                                                          if (_DAT_0042b904 == (FARPROC)0x0) {
                                                            pcVar1 = "Lane_MoveNext";
                                                          }
                                                          else {
                                                            _DAT_0042b7f8 =
                                                                 GetProcAddress(DAT_0042b1bc,
                                                                                "Lane_MovePrevious")
                                                            ;
                                                            if (_DAT_0042b7f8 == (FARPROC)0x0) {
                                                              pcVar1 = "Lane_MovePrevious";
                                                            }
                                                            else {
                                                              _DAT_0042b730 =
                                                                   GetProcAddress(DAT_0042b1bc,
                                                                                  "Lane_MoveLast");
                                                              if (_DAT_0042b730 == (FARPROC)0x0) {
                                                                pcVar1 = "Lane_MoveLast";
                                                              }
                                                              else {
                                                                _DAT_0042b73c =
                                                                     GetProcAddress(DAT_0042b1bc,
                                                                                    "Lane_Reboot");
                                                                if (_DAT_0042b73c == (FARPROC)0x0) {
                                                                  pcVar1 = "Lane_Reboot";
                                                                }
                                                                else {
                                                                  _DAT_0042b7cc =
                                                                       GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                            
                                                  "Lane_ActivateOutput");
                                                  if (_DAT_0042b7cc == (FARPROC)0x0) {
                                                    pcVar1 = "Lane_ActivateOutput";
                                                  }
                                                  else {
                                                    _DAT_0042b7c0 =
                                                         GetProcAddress(DAT_0042b1bc,"Lane_Trigger")
                                                    ;
                                                    if (_DAT_0042b7c0 == (FARPROC)0x0) {
                                                      pcVar1 = "Lane_Trigger";
                                                    }
                                                    else {
                                                      _DAT_0042b7f4 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                                                                                                    
                                                  "Lane_GetRecognitionStatistics");
                                                  if (_DAT_0042b7f4 == (FARPROC)0x0) {
                                                    pcVar1 = "Lane_GetRecognitionStatistics";
                                                  }
                                                  else {
                                                    _DAT_0042b7c4 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "Lane_GetInputValues");
                                                    if (_DAT_0042b7c4 == (FARPROC)0x0) {
                                                      pcVar1 = "Lane_GetInputValues";
                                                    }
                                                    else {
                                                      _DAT_0042b764 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                          "Lane_GetVersion");
                                                      if (_DAT_0042b764 == (FARPROC)0x0) {
                                                        pcVar1 = "Lane_GetVersion";
                                                      }
                                                      else {
                                                        _DAT_0042b900 =
                                                             GetProcAddress(DAT_0042b1bc,
                                                                            "Lane_GetCurrentFrame");
                                                        if (_DAT_0042b900 == (FARPROC)0x0) {
                                                          pcVar1 = "Lane_GetCurrentFrame";
                                                        }
                                                        else {
                                                          _DAT_0042b744 =
                                                               GetProcAddress(DAT_0042b1bc,
                                                                              "Lane_ActivateFocus");
                                                          if (_DAT_0042b744 == (FARPROC)0x0) {
                                                            pcVar1 = "Lane_ActivateFocus";
                                                          }
                                                          else {
                                                            _DAT_0042b884 =
                                                                 GetProcAddress(DAT_0042b1bc,
                                                                                "Lane_LoadWhiteList"
                                                                               );
                                                            if (_DAT_0042b884 == (FARPROC)0x0) {
                                                              pcVar1 = "Lane_LoadWhiteList";
                                                            }
                                                            else {
                                                              _DAT_0042b768 =
                                                                   GetProcAddress(DAT_0042b1bc,
                                                                                  "Car_get_Lane");
                                                              if (_DAT_0042b768 == (FARPROC)0x0) {
                                                                pcVar1 = "Car_get_Lane";
                                                              }
                                                              else {
                                                                _DAT_0042b7a0 =
                                                                     GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                        
                                                  "Notification_get_Lane");
                                                  if (_DAT_0042b7a0 == (FARPROC)0x0) {
                                                    pcVar1 = "Notification_get_Lane";
                                                  }
                                                  else {
                                                    _DAT_0042b81c =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "LaneStatus_get_Global");
                                                    if (_DAT_0042b81c == (FARPROC)0x0) {
                                                      pcVar1 = "LaneStatus_get_Global";
                                                    }
                                                    else {
                                                      _DAT_0042b7d4 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                          "LaneStatus_get_IOCard");
                                                      if (_DAT_0042b7d4 == (FARPROC)0x0) {
                                                        pcVar1 = "LaneStatus_get_IOCard";
                                                      }
                                                      else {
                                                        _DAT_0042b78c =
                                                             GetProcAddress(DAT_0042b1bc,
                                                                            "LaneStatus_get_Camera")
                                                        ;
                                                        if (_DAT_0042b78c == (FARPROC)0x0) {
                                                          pcVar1 = "LaneStatus_get_Camera";
                                                        }
                                                        else {
                                                          _DAT_0042b718 =
                                                               GetProcAddress(DAT_0042b1bc,
                                                                              "LaneStatus_get_Focus"
                                                                             );
                                                          if (_DAT_0042b718 == (FARPROC)0x0) {
                                                            pcVar1 = "LaneStatus_get_Focus";
                                                          }
                                                          else {
                                                            _DAT_0042b7bc =
                                                                 GetProcAddress(DAT_0042b1bc,
                                                                                                                                                                
                                                  "LaneStatus_get_Temperature");
                                                  if (_DAT_0042b7bc == (FARPROC)0x0) {
                                                    pcVar1 = "LaneStatus_get_Temperature";
                                                  }
                                                  else {
                                                    _DAT_0042b8b4 =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                                                                                                
                                                  "LaneStatus_get_Communication");
                                                  if (_DAT_0042b8b4 == (FARPROC)0x0) {
                                                    pcVar1 = "LaneStatus_get_Communication";
                                                  }
                                                  else {
                                                    _DAT_0042b908 =
                                                         GetProcAddress(DAT_0042b1bc,"Remote_get_Id"
                                                                       );
                                                    if (_DAT_0042b908 == (FARPROC)0x0) {
                                                      pcVar1 = "Remote_get_Id";
                                                    }
                                                    else {
                                                      _DAT_0042b7c8 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                          "Remote_get_Status");
                                                      if (_DAT_0042b7c8 == (FARPROC)0x0) {
                                                        pcVar1 = "Remote_get_Status";
                                                      }
                                                      else {
                                                        _DAT_0042b724 =
                                                             GetProcAddress(DAT_0042b1bc,
                                                                                                                                                        
                                                  "Remote_get_CommunicationStatus");
                                                  if (_DAT_0042b724 == (FARPROC)0x0) {
                                                    pcVar1 = "Remote_get_CommunicationStatus";
                                                  }
                                                  else {
                                                    _DAT_0042b84c =
                                                         GetProcAddress(DAT_0042b1bc,
                                                                        "Remote_get_Lanes_Item");
                                                    if (_DAT_0042b84c == (FARPROC)0x0) {
                                                      pcVar1 = "Remote_get_Lanes_Item";
                                                    }
                                                    else {
                                                      _DAT_0042b8f0 =
                                                           GetProcAddress(DAT_0042b1bc,
                                                                          "Remote_get_Lanes_Count");
                                                      if (_DAT_0042b8f0 == (FARPROC)0x0) {
                                                        pcVar1 = "Remote_get_Lanes_Count";
                                                      }
                                                      else {
                                                        _DAT_0042b7e0 =
                                                             GetProcAddress(DAT_0042b1bc,
                                                                            "Remote_Reboot");
                                                        if (_DAT_0042b7e0 != (FARPROC)0x0) {
                                                          return 0;
                                                        }
                                                        pcVar1 = "Remote_Reboot";
                                                        _DAT_0042b7e0 = (FARPROC)0x0;
                                                      }
                                                    }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  printf("ERROR loading function %s\n",pcVar1);
  return 0xffffffff;
}



void FUN_004116a0(void)

{
  FreeLibrary(DAT_0042b1bc);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004116b0(void)

{
                    // WARNING: Could not recover jumptable at 0x004116b0. Too many branches
                    // WARNING: Treating indirect jump as call
  (*_DAT_0042b738)();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004116c0(void)

{
                    // WARNING: Could not recover jumptable at 0x004116c0. Too many branches
                    // WARNING: Treating indirect jump as call
  (*_DAT_0042b728)();
  return;
}



void __fastcall FUN_004116d0(undefined4 *param_1)

{
  (*DAT_0042b834)(*param_1);
  return;
}



bool __thiscall FUN_004116e0(void *this,undefined4 param_1)

{
  int iVar1;
  
                    // WARNING: Load size is inaccurate
  iVar1 = (*DAT_0042b874)(*this,param_1);
  return iVar1 != 0;
}



undefined4 * __thiscall FUN_00411700(void *this,undefined4 param_1,char param_2)

{
  *(undefined4 *)this = param_1;
  if (param_2 != '\0') {
    (*DAT_0042b780)(param_1);
  }
  return (undefined4 *)this;
}



int * __thiscall FUN_00411720(void *this,int *param_1)

{
  int iVar1;
  
  iVar1 = *param_1;
  *(int *)this = iVar1;
  if (iVar1 != 0) {
    (*DAT_0042b780)(iVar1);
  }
  return (int *)this;
}



void __fastcall FUN_00411740(int *param_1)

{
  if (*param_1 != 0) {
    (*DAT_0042b8c4)(*param_1);
  }
  return;
}



int * __thiscall FUN_00411750(void *this,int *param_1)

{
  if (*param_1 != 0) {
    (*DAT_0042b780)(*param_1);
  }
                    // WARNING: Load size is inaccurate
  if (*this != 0) {
    (*DAT_0042b8c4)(*this);
  }
  *(int *)this = *param_1;
  return (int *)this;
}



void __fastcall FUN_00411780(undefined4 *param_1)

{
  (*DAT_0042b860)(*param_1);
  return;
}



void __fastcall FUN_00411790(undefined4 *param_1)

{
  (*DAT_0042b800)(*param_1);
  return;
}



void __thiscall FUN_004117a0(void *this,undefined4 param_1,undefined4 param_2)

{
                    // WARNING: Load size is inaccurate
  (*DAT_0042b7ec)(*this,param_1,param_2);
  return;
}



void __fastcall FUN_004117c0(undefined4 *param_1)

{
  (*DAT_0042b898)(*param_1);
  return;
}



undefined4 * __fastcall FUN_004117d0(undefined4 *param_1)

{
  undefined4 uVar1;
  undefined4 *unaff_retaddr;
  
  uVar1 = (*DAT_0042b8f4)(*param_1);
  *unaff_retaddr = uVar1;
  return unaff_retaddr;
}



void __thiscall FUN_004117f0(void *this,undefined4 param_1,undefined4 param_2)

{
                    // WARNING: Load size is inaccurate
  (*DAT_0042b844)(*this,param_1,param_2);
  return;
}



void __thiscall FUN_00411810(void *this,undefined4 param_1,undefined4 param_2)

{
                    // WARNING: Load size is inaccurate
  (*DAT_0042b7b0)(*this,param_1,param_2);
  return;
}



void __fastcall FUN_00411830(undefined4 *param_1)

{
  (*DAT_0042b868)(*param_1);
  return;
}



void __fastcall FUN_00411840(undefined4 *param_1)

{
  (*DAT_0042b8e4)(*param_1);
  return;
}



void __fastcall FUN_00411850(undefined4 *param_1)

{
  (*DAT_0042b828)(*param_1);
  return;
}



void __thiscall FUN_00411860(void *this,undefined4 param_1,undefined4 param_2)

{
                    // WARNING: Load size is inaccurate
  (*DAT_0042b8d0)(*this,param_1,param_2);
  return;
}



void __fastcall FUN_00411880(undefined4 *param_1)

{
  (*DAT_0042b840)(*param_1);
  return;
}



bool __thiscall FUN_00411890(void *this,undefined4 param_1)

{
  int iVar1;
  
                    // WARNING: Load size is inaccurate
  iVar1 = (*DAT_0042b82c)(*this,param_1);
  return iVar1 != 0;
}



void __fastcall FUN_004118b0(undefined4 *param_1)

{
  *param_1 = 0;
  return;
}



void __thiscall FUN_004118c0(void *this,undefined4 *param_1)

{
  *(undefined4 *)this = *param_1;
  return;
}



void __thiscall FUN_004118d0(void *this,undefined4 param_1,undefined4 param_2)

{
                    // WARNING: Load size is inaccurate
  (*DAT_0042b894)(*this,param_1,param_2);
  return;
}



void __thiscall FUN_004118f0(void *this,int param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 uStack_4;
  
  uStack_4 = 0xffffffff;
  puStack_8 = &LAB_0041afc8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  (*DAT_0042b780)();
  puStack_8 = (undefined *)0x0;
  if (DAT_0042b1c0 != (undefined4 *)0x0) {
    if (param_1 != 0) {
      (*DAT_0042b780)(param_1);
    }
    (**(code **)*DAT_0042b1c0)();
  }
  puStack_8 = (undefined *)0xffffffff;
  if (param_1 != 0) {
    (*DAT_0042b8c4)();
  }
  ExceptionList = this;
  return;
}



void __thiscall FUN_00411980(void *this,int param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 uStack_4;
  
  uStack_4 = 0xffffffff;
  puStack_8 = &LAB_0041afc8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  (*DAT_0042b780)();
  puStack_8 = (undefined *)0x0;
  if (DAT_0042b1c0 != (int *)0x0) {
    if (param_1 != 0) {
      (*DAT_0042b780)(param_1);
    }
    (**(code **)(*DAT_0042b1c0 + 4))();
  }
  puStack_8 = (undefined *)0xffffffff;
  if (param_1 != 0) {
    (*DAT_0042b8c4)();
  }
  ExceptionList = this;
  return;
}



void __thiscall FUN_00411a10(void *this,int param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 uStack_4;
  
  uStack_4 = 0xffffffff;
  puStack_8 = &LAB_0041afc8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  (*DAT_0042b780)();
  puStack_8 = (undefined *)0x0;
  if (DAT_0042b1c0 != (int *)0x0) {
    if (param_1 != 0) {
      (*DAT_0042b780)(param_1);
    }
    (**(code **)(*DAT_0042b1c0 + 8))();
  }
  puStack_8 = (undefined *)0xffffffff;
  if (param_1 != 0) {
    (*DAT_0042b8c4)();
  }
  ExceptionList = this;
  return;
}



void __cdecl FUN_00411b20(undefined4 *param_1)

{
  *param_1 = 0;
  return;
}



bool __cdecl FUN_00411b30(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  
  DAT_0042b1c0 = param_3;
  iVar1 = (*DAT_0042b8d4)(param_1,param_2,FUN_004118f0,FUN_00411980,FUN_00411a10,&LAB_00411aa0,
                          &LAB_00411af0);
  return iVar1 != 0;
}



undefined4 * FUN_00411b70(undefined4 param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 *unaff_retaddr;
  
  uVar1 = (*DAT_0042b8d8)(param_2);
  *unaff_retaddr = uVar1;
  return unaff_retaddr;
}



undefined4 * __fastcall FUN_00411b90(undefined4 *param_1)

{
  undefined4 uVar1;
  undefined4 *unaff_retaddr;
  
  uVar1 = (*DAT_0042b89c)(*param_1);
  *unaff_retaddr = uVar1;
  return unaff_retaddr;
}



void __thiscall FUN_00411bb0(void *this,undefined4 *param_1)

{
                    // WARNING: Load size is inaccurate
  *param_1 = *this;
  return;
}



undefined4 * __thiscall FUN_00411bc0(void *this,undefined4 param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  
                    // WARNING: Load size is inaccurate
  uVar1 = (*DAT_0042b8ac)(*this);
  *param_2 = uVar1;
  return param_2;
}



undefined4 * __fastcall FUN_00411be0(undefined4 *param_1)

{
  undefined4 uVar1;
  undefined4 *unaff_retaddr;
  
  uVar1 = (*DAT_0042b76c)(*param_1);
  *unaff_retaddr = uVar1;
  return unaff_retaddr;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00411c00(void)

{
  char *pcVar1;
  
  DAT_0042b1c4 = LoadLibraryA("SmartREC.dll");
  if (DAT_0042b1c4 == (HMODULE)0x0) {
    return 0xffffffff;
  }
  _DAT_0042b6a8 = GetProcAddress(DAT_0042b1c4,"System_get_Status");
  if (_DAT_0042b6a8 == (FARPROC)0x0) {
    pcVar1 = "System_get_Status";
  }
  else {
    _DAT_0042b618 = GetProcAddress(DAT_0042b1c4,"System_get_Units_Item");
    if (_DAT_0042b618 == (FARPROC)0x0) {
      pcVar1 = "System_get_Units_Item";
    }
    else {
      _DAT_0042b668 = GetProcAddress(DAT_0042b1c4,"System_get_Units_Count");
      if (_DAT_0042b668 == (FARPROC)0x0) {
        pcVar1 = "System_get_Units_Count";
      }
      else {
        DAT_0042b6dc = GetProcAddress(DAT_0042b1c4,"System_Initialize");
        if (DAT_0042b6dc == (FARPROC)0x0) {
          pcVar1 = "System_Initialize";
        }
        else {
          _DAT_0042b714 = GetProcAddress(DAT_0042b1c4,"System_Terminate");
          if (_DAT_0042b714 == (FARPROC)0x0) {
            pcVar1 = "System_Terminate";
          }
          else {
            DAT_0042b5d8 = GetProcAddress(DAT_0042b1c4,"System_GetUnit");
            if (DAT_0042b5d8 == (FARPROC)0x0) {
              pcVar1 = "System_GetUnit";
            }
            else {
              DAT_0042b6a4 = GetProcAddress(DAT_0042b1c4,"Unit_get_Id");
              if (DAT_0042b6a4 == (FARPROC)0x0) {
                pcVar1 = "Unit_get_Id";
              }
              else {
                DAT_0042b6a0 = GetProcAddress(DAT_0042b1c4,"Unit_get_IpAddress");
                if (DAT_0042b6a0 == (FARPROC)0x0) {
                  pcVar1 = "Unit_get_IpAddress";
                }
                else {
                  _DAT_0042b610 = GetProcAddress(DAT_0042b1c4,"Unit_get_Status");
                  if (_DAT_0042b610 == (FARPROC)0x0) {
                    pcVar1 = "Unit_get_Status";
                  }
                  else {
                    DAT_0042b69c = GetProcAddress(DAT_0042b1c4,"Unit_get_Configuration");
                    if (DAT_0042b69c == (FARPROC)0x0) {
                      pcVar1 = "Unit_get_Configuration";
                    }
                    else {
                      _DAT_0042b670 = GetProcAddress(DAT_0042b1c4,"Unit_get_Historic");
                      if (_DAT_0042b670 == (FARPROC)0x0) {
                        pcVar1 = "Unit_get_Historic";
                      }
                      else {
                        _DAT_0042b6b0 = GetProcAddress(DAT_0042b1c4,"Unit_Reboot");
                        if (_DAT_0042b6b0 == (FARPROC)0x0) {
                          pcVar1 = "Unit_Reboot";
                        }
                        else {
                          DAT_0042b5e4 = GetProcAddress(DAT_0042b1c4,"Unit_GetInformation");
                          if (DAT_0042b5e4 == (FARPROC)0x0) {
                            pcVar1 = "Unit_GetInformation";
                          }
                          else {
                            _DAT_0042b62c = GetProcAddress(DAT_0042b1c4,"Unit_ActivateOutput");
                            if (_DAT_0042b62c == (FARPROC)0x0) {
                              pcVar1 = "Unit_ActivateOutput";
                            }
                            else {
                              _DAT_0042b61c = GetProcAddress(DAT_0042b1c4,"Unit_GetIOValues");
                              if (_DAT_0042b61c == (FARPROC)0x0) {
                                pcVar1 = "Unit_GetIOValues";
                              }
                              else {
                                DAT_0042b638 = GetProcAddress(DAT_0042b1c4,"Unit_StartCapture");
                                if (DAT_0042b638 == (FARPROC)0x0) {
                                  pcVar1 = "Unit_StartCapture";
                                }
                                else {
                                  DAT_0042b6b8 = GetProcAddress(DAT_0042b1c4,"Unit_StopCapture");
                                  if (DAT_0042b6b8 == (FARPROC)0x0) {
                                    pcVar1 = "Unit_StopCapture";
                                  }
                                  else {
                                    _DAT_0042b5c8 =
                                         GetProcAddress(DAT_0042b1c4,"Unit_GetVideoInformation");
                                    if (_DAT_0042b5c8 == (FARPROC)0x0) {
                                      pcVar1 = "Unit_GetVideoInformation";
                                    }
                                    else {
                                      _DAT_0042b5dc =
                                           GetProcAddress(DAT_0042b1c4,"Unit_RequestLiveImage");
                                      if (_DAT_0042b5dc == (FARPROC)0x0) {
                                        pcVar1 = "Unit_RequestLiveImage";
                                      }
                                      else {
                                        _DAT_0042b68c =
                                             GetProcAddress(DAT_0042b1c4,"Historic_SetFilter");
                                        if (_DAT_0042b68c == (FARPROC)0x0) {
                                          pcVar1 = "Historic_SetFilter";
                                        }
                                        else {
                                          _DAT_0042b6ac =
                                               GetProcAddress(DAT_0042b1c4,"Historic_GetFilter");
                                          if (_DAT_0042b6ac == (FARPROC)0x0) {
                                            pcVar1 = "Historic_GetFilter";
                                          }
                                          else {
                                            _DAT_0042b688 =
                                                 GetProcAddress(DAT_0042b1c4,"Historic_GetFirst");
                                            if (_DAT_0042b688 == (FARPROC)0x0) {
                                              pcVar1 = "Historic_GetFirst";
                                            }
                                            else {
                                              _DAT_0042b680 =
                                                   GetProcAddress(DAT_0042b1c4,
                                                                  "Historic_GetPrevious");
                                              if (_DAT_0042b680 == (FARPROC)0x0) {
                                                pcVar1 = "Historic_GetPrevious";
                                              }
                                              else {
                                                _DAT_0042b694 =
                                                     GetProcAddress(DAT_0042b1c4,"Historic_GetNext")
                                                ;
                                                if (_DAT_0042b694 == (FARPROC)0x0) {
                                                  pcVar1 = "Historic_GetNext";
                                                }
                                                else {
                                                  _DAT_0042b5d4 =
                                                       GetProcAddress(DAT_0042b1c4,
                                                                      "Historic_GetLast");
                                                  if (_DAT_0042b5d4 == (FARPROC)0x0) {
                                                    pcVar1 = "Historic_GetLast";
                                                  }
                                                  else {
                                                    DAT_0042b65c = GetProcAddress(DAT_0042b1c4,
                                                                                                                                                                    
                                                  "VideoInformation_get_Id");
                                                  if (DAT_0042b65c == (FARPROC)0x0) {
                                                    pcVar1 = "VideoInformation_get_Id";
                                                  }
                                                  else {
                                                    DAT_0042b67c = GetProcAddress(DAT_0042b1c4,
                                                                                                                                                                    
                                                  "VideoInformation_get_Unit");
                                                  if (DAT_0042b67c == (FARPROC)0x0) {
                                                    pcVar1 = "VideoInformation_get_Unit";
                                                  }
                                                  else {
                                                    _DAT_0042b6e4 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "VideoInformation_get_TriggerId");
                                                  if (_DAT_0042b6e4 == (FARPROC)0x0) {
                                                    pcVar1 = "VideoInformation_get_TriggerId";
                                                  }
                                                  else {
                                                    _DAT_0042b684 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "VideoInformation_get_SequenceIndex");
                                                  if (_DAT_0042b684 == (FARPROC)0x0) {
                                                    pcVar1 = "VideoInformation_get_SequenceIndex";
                                                  }
                                                  else {
                                                    _DAT_0042b5cc =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "VideoInformation_get_Duration");
                                                  if (_DAT_0042b5cc == (FARPROC)0x0) {
                                                    pcVar1 = "VideoInformation_get_Duration";
                                                  }
                                                  else {
                                                    DAT_0042b5c4 = GetProcAddress(DAT_0042b1c4,
                                                                                                                                                                    
                                                  "VideoInformation_get_IniTimestamp");
                                                  if (DAT_0042b5c4 == (FARPROC)0x0) {
                                                    pcVar1 = "VideoInformation_get_IniTimestamp";
                                                  }
                                                  else {
                                                    DAT_0042b5d0 = GetProcAddress(DAT_0042b1c4,
                                                                                                                                                                    
                                                  "VideoInformation_get_IniTimestampUSec");
                                                  if (DAT_0042b5d0 == (FARPROC)0x0) {
                                                    pcVar1 = "VideoInformation_get_IniTimestampUSec"
                                                    ;
                                                  }
                                                  else {
                                                    _DAT_0042b60c =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "VideoInformation_get_EndTimestamp");
                                                  if (_DAT_0042b60c == (FARPROC)0x0) {
                                                    pcVar1 = "VideoInformation_get_EndTimestamp";
                                                  }
                                                  else {
                                                    _DAT_0042b654 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "VideoInformation_get_EndTimestampUSec");
                                                  if (_DAT_0042b654 == (FARPROC)0x0) {
                                                    pcVar1 = "VideoInformation_get_EndTimestampUSec"
                                                    ;
                                                  }
                                                  else {
                                                    DAT_0042b6f0 = GetProcAddress(DAT_0042b1c4,
                                                                                                                                                                    
                                                  "VideoInformation_get_Location");
                                                  if (DAT_0042b6f0 == (FARPROC)0x0) {
                                                    pcVar1 = "VideoInformation_get_Location";
                                                  }
                                                  else {
                                                    DAT_0042b6e8 = GetProcAddress(DAT_0042b1c4,
                                                                                                                                                                    
                                                  "VideoInformation_AddRef");
                                                  if (DAT_0042b6e8 == (FARPROC)0x0) {
                                                    pcVar1 = "VideoInformation_AddRef";
                                                  }
                                                  else {
                                                    DAT_0042b648 = GetProcAddress(DAT_0042b1c4,
                                                                                                                                                                    
                                                  "VideoInformation_Release");
                                                  if (DAT_0042b648 == (FARPROC)0x0) {
                                                    pcVar1 = "VideoInformation_Release";
                                                  }
                                                  else {
                                                    DAT_0042b634 = GetProcAddress(DAT_0042b1c4,
                                                                                                                                                                    
                                                  "Notification_get_Code");
                                                  if (DAT_0042b634 == (FARPROC)0x0) {
                                                    pcVar1 = "Notification_get_Code";
                                                  }
                                                  else {
                                                    DAT_0042b5e8 = GetProcAddress(DAT_0042b1c4,
                                                                                                                                                                    
                                                  "Notification_get_Unit");
                                                  if (DAT_0042b5e8 == (FARPROC)0x0) {
                                                    pcVar1 = "Notification_get_Unit";
                                                  }
                                                  else {
                                                    _DAT_0042b6c4 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                        "UnitStatus_get_Status");
                                                    if (_DAT_0042b6c4 == (FARPROC)0x0) {
                                                      pcVar1 = "UnitStatus_get_Status";
                                                    }
                                                    else {
                                                      _DAT_0042b6c0 =
                                                           GetProcAddress(DAT_0042b1c4,
                                                                                                                                                    
                                                  "UnitStatus_get_StartupTime");
                                                  if (_DAT_0042b6c0 == (FARPROC)0x0) {
                                                    pcVar1 = "UnitStatus_get_StartupTime";
                                                  }
                                                  else {
                                                    _DAT_0042b6cc =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "UnitStatus_get_Communication");
                                                  if (_DAT_0042b6cc == (FARPROC)0x0) {
                                                    pcVar1 = "UnitStatus_get_Communication";
                                                  }
                                                  else {
                                                    _DAT_0042b650 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "UnitInformation_get_Description");
                                                  if (_DAT_0042b650 == (FARPROC)0x0) {
                                                    pcVar1 = "UnitInformation_get_Description";
                                                  }
                                                  else {
                                                    _DAT_0042b710 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "UnitInformation_get_ImageWidth");
                                                  if (_DAT_0042b710 == (FARPROC)0x0) {
                                                    pcVar1 = "UnitInformation_get_ImageWidth";
                                                  }
                                                  else {
                                                    _DAT_0042b63c =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "UnitInformation_get_ImageHeight");
                                                  if (_DAT_0042b63c == (FARPROC)0x0) {
                                                    pcVar1 = "UnitInformation_get_ImageHeight";
                                                  }
                                                  else {
                                                    _DAT_0042b690 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "UnitInformation_get_FrameRate");
                                                  if (_DAT_0042b690 == (FARPROC)0x0) {
                                                    pcVar1 = "UnitInformation_get_FrameRate";
                                                  }
                                                  else {
                                                    _DAT_0042b6fc =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "UnitInformation_get_ProductName");
                                                  if (_DAT_0042b6fc == (FARPROC)0x0) {
                                                    pcVar1 = "UnitInformation_get_ProductName";
                                                  }
                                                  else {
                                                    _DAT_0042b600 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "UnitInformation_get_VersionMajor");
                                                  if (_DAT_0042b600 == (FARPROC)0x0) {
                                                    pcVar1 = "UnitInformation_get_VersionMajor";
                                                  }
                                                  else {
                                                    _DAT_0042b5ec =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "UnitInformation_get_VersionMinor");
                                                  if (_DAT_0042b5ec == (FARPROC)0x0) {
                                                    pcVar1 = "UnitInformation_get_VersionMinor";
                                                  }
                                                  else {
                                                    _DAT_0042b6e0 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "UnitInformation_get_VersionRevision");
                                                  if (_DAT_0042b6e0 == (FARPROC)0x0) {
                                                    pcVar1 = "UnitInformation_get_VersionRevision";
                                                  }
                                                  else {
                                                    DAT_0042b708 = GetProcAddress(DAT_0042b1c4,
                                                                                                                                                                    
                                                  "UnitInformation_get_Protocols");
                                                  if (DAT_0042b708 == (FARPROC)0x0) {
                                                    pcVar1 = "UnitInformation_get_Protocols";
                                                  }
                                                  else {
                                                    _DAT_0042b674 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "VersionInformation_get_Name");
                                                  if (_DAT_0042b674 == (FARPROC)0x0) {
                                                    pcVar1 = "VersionInformation_get_Name";
                                                  }
                                                  else {
                                                    _DAT_0042b6d0 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "VersionInformation_get_Major");
                                                  if (_DAT_0042b6d0 == (FARPROC)0x0) {
                                                    pcVar1 = "VersionInformation_get_Major";
                                                  }
                                                  else {
                                                    _DAT_0042b5f8 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "VersionInformation_get_Minor");
                                                  if (_DAT_0042b5f8 == (FARPROC)0x0) {
                                                    pcVar1 = "VersionInformation_get_Minor";
                                                  }
                                                  else {
                                                    _DAT_0042b6f8 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "VersionInformation_get_Revision");
                                                  if (_DAT_0042b6f8 == (FARPROC)0x0) {
                                                    pcVar1 = "VersionInformation_get_Revision";
                                                  }
                                                  else {
                                                    DAT_0042b5f4 = GetProcAddress(DAT_0042b1c4,
                                                                                                                                                                    
                                                  "Configuration_Login");
                                                  if (DAT_0042b5f4 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_Login";
                                                  }
                                                  else {
                                                    _DAT_0042b700 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                        "Configuration_Logout");
                                                    if (_DAT_0042b700 == (FARPROC)0x0) {
                                                      pcVar1 = "Configuration_Logout";
                                                    }
                                                    else {
                                                      _DAT_0042b64c =
                                                           GetProcAddress(DAT_0042b1c4,
                                                                                                                                                    
                                                  "Configuration_ChangePassword");
                                                  if (_DAT_0042b64c == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_ChangePassword";
                                                  }
                                                  else {
                                                    _DAT_0042b658 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                        "Configuration_SyncTime");
                                                    if (_DAT_0042b658 == (FARPROC)0x0) {
                                                      pcVar1 = "Configuration_SyncTime";
                                                    }
                                                    else {
                                                      _DAT_0042b640 =
                                                           GetProcAddress(DAT_0042b1c4,
                                                                          "Configuration_SetTime");
                                                      if (_DAT_0042b640 == (FARPROC)0x0) {
                                                        pcVar1 = "Configuration_SetTime";
                                                      }
                                                      else {
                                                        _DAT_0042b660 =
                                                             GetProcAddress(DAT_0042b1c4,
                                                                                                                                                        
                                                  "Configuration_UpdateFirmware");
                                                  if (_DAT_0042b660 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_UpdateFirmware";
                                                  }
                                                  else {
                                                    _DAT_0042b5e0 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "Configuration_RestoreFirmware");
                                                  if (_DAT_0042b5e0 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_RestoreFirmware";
                                                  }
                                                  else {
                                                    _DAT_0042b604 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                        "Configuration_ExportLog");
                                                    if (_DAT_0042b604 == (FARPROC)0x0) {
                                                      pcVar1 = "Configuration_ExportLog";
                                                    }
                                                    else {
                                                      DAT_0042b66c = GetProcAddress(DAT_0042b1c4,
                                                                                                                                                                        
                                                  "Configuration_GetSystemInformation");
                                                  if (DAT_0042b66c == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_GetSystemInformation";
                                                  }
                                                  else {
                                                    _DAT_0042b630 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                        "Configuration_ExportStatus"
                                                                       );
                                                    if (_DAT_0042b630 == (FARPROC)0x0) {
                                                      pcVar1 = "Configuration_ExportStatus";
                                                    }
                                                    else {
                                                      _DAT_0042b5c0 =
                                                           GetProcAddress(DAT_0042b1c4,
                                                                                                                                                    
                                                  "Configuration_GetEntriesCount");
                                                  if (_DAT_0042b5c0 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_GetEntriesCount";
                                                  }
                                                  else {
                                                    _DAT_0042b644 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "Configuration_GetEntryByIndex");
                                                  if (_DAT_0042b644 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_GetEntryByIndex";
                                                  }
                                                  else {
                                                    _DAT_0042b5fc =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "Configuration_GetEntryByName");
                                                  if (_DAT_0042b5fc == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_GetEntryByName";
                                                  }
                                                  else {
                                                    _DAT_0042b614 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                        "Configuration_SetEntry");
                                                    if (_DAT_0042b614 == (FARPROC)0x0) {
                                                      pcVar1 = "Configuration_SetEntry";
                                                    }
                                                    else {
                                                      _DAT_0042b6d8 =
                                                           GetProcAddress(DAT_0042b1c4,
                                                                                                                                                    
                                                  "Configuration_RestoreEntry");
                                                  if (_DAT_0042b6d8 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_RestoreEntry";
                                                  }
                                                  else {
                                                    _DAT_0042b620 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                        "Configuration_ApplyChanges"
                                                                       );
                                                    if (_DAT_0042b620 == (FARPROC)0x0) {
                                                      pcVar1 = "Configuration_ApplyChanges";
                                                    }
                                                    else {
                                                      _DAT_0042b6bc =
                                                           GetProcAddress(DAT_0042b1c4,
                                                                                                                                                    
                                                  "Configuration_DiscardChanges");
                                                  if (_DAT_0042b6bc == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_DiscardChanges";
                                                  }
                                                  else {
                                                    _DAT_0042b678 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "Configuration_ImportConfiguration");
                                                  if (_DAT_0042b678 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_ImportConfiguration";
                                                  }
                                                  else {
                                                    _DAT_0042b6b4 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "Configuration_ExportConfiguration");
                                                  if (_DAT_0042b6b4 == (FARPROC)0x0) {
                                                    pcVar1 = "Configuration_ExportConfiguration";
                                                  }
                                                  else {
                                                    _DAT_0042b6ec =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                        "Configuration_IsLoggedIn");
                                                    if (_DAT_0042b6ec == (FARPROC)0x0) {
                                                      pcVar1 = "Configuration_IsLoggedIn";
                                                    }
                                                    else {
                                                      _DAT_0042b5f0 =
                                                           GetProcAddress(DAT_0042b1c4,
                                                                                                                                                    
                                                  "SystemInformation_get_Name");
                                                  if (_DAT_0042b5f0 == (FARPROC)0x0) {
                                                    pcVar1 = "SystemInformation_get_Name";
                                                  }
                                                  else {
                                                    _DAT_0042b70c =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "SystemInformation_get_ProductionDate");
                                                  if (_DAT_0042b70c == (FARPROC)0x0) {
                                                    pcVar1 = "SystemInformation_get_ProductionDate";
                                                  }
                                                  else {
                                                    DAT_0042b6f4 = GetProcAddress(DAT_0042b1c4,
                                                                                                                                                                    
                                                  "SystemInformation_get_SerialNumber");
                                                  if (DAT_0042b6f4 == (FARPROC)0x0) {
                                                    pcVar1 = "SystemInformation_get_SerialNumber";
                                                  }
                                                  else {
                                                    _DAT_0042b624 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "SystemInformation_get_MacAddress");
                                                  if (_DAT_0042b624 == (FARPROC)0x0) {
                                                    pcVar1 = "SystemInformation_get_MacAddress";
                                                  }
                                                  else {
                                                    _DAT_0042b628 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "SystemInformation_get_BootTime");
                                                  if (_DAT_0042b628 == (FARPROC)0x0) {
                                                    pcVar1 = "SystemInformation_get_BootTime";
                                                  }
                                                  else {
                                                    _DAT_0042b704 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "SystemInformation_get_HardwareVersion");
                                                  if (_DAT_0042b704 == (FARPROC)0x0) {
                                                    pcVar1 = "SystemInformation_get_HardwareVersion"
                                                    ;
                                                  }
                                                  else {
                                                    _DAT_0042b608 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                        "SettingsEntry_AddRef");
                                                    if (_DAT_0042b608 == (FARPROC)0x0) {
                                                      pcVar1 = "SettingsEntry_AddRef";
                                                    }
                                                    else {
                                                      _DAT_0042b6c8 =
                                                           GetProcAddress(DAT_0042b1c4,
                                                                          "SettingsEntry_Release");
                                                      if (_DAT_0042b6c8 == (FARPROC)0x0) {
                                                        pcVar1 = "SettingsEntry_Release";
                                                      }
                                                      else {
                                                        _DAT_0042b698 =
                                                             GetProcAddress(DAT_0042b1c4,
                                                                            "SettingsEntry_get_Name"
                                                                           );
                                                        if (_DAT_0042b698 == (FARPROC)0x0) {
                                                          pcVar1 = "SettingsEntry_get_Name";
                                                        }
                                                        else {
                                                          _DAT_0042b664 =
                                                               GetProcAddress(DAT_0042b1c4,
                                                                                                                                                            
                                                  "SettingsEntry_get_Value");
                                                  if (_DAT_0042b664 == (FARPROC)0x0) {
                                                    pcVar1 = "SettingsEntry_get_Value";
                                                  }
                                                  else {
                                                    _DAT_0042b6d4 =
                                                         GetProcAddress(DAT_0042b1c4,
                                                                                                                                                
                                                  "SettingsEntry_get_Description");
                                                  if (_DAT_0042b6d4 != (FARPROC)0x0) {
                                                    return 0;
                                                  }
                                                  pcVar1 = "SettingsEntry_get_Description";
                                                  _DAT_0042b6d4 = (FARPROC)0x0;
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  printf("ERROR loading function %s\n",pcVar1);
  return 0xffffffff;
}



void FUN_00412720(void)

{
  FreeLibrary(DAT_0042b1c4);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00412730(void)

{
                    // WARNING: Could not recover jumptable at 0x00412730. Too many branches
                    // WARNING: Treating indirect jump as call
  (*_DAT_0042b714)();
  return;
}



void __fastcall FUN_00412740(undefined4 *param_1)

{
  (*DAT_0042b6a4)(*param_1);
  return;
}



void __thiscall FUN_00412750(void *this,undefined4 param_1,undefined4 param_2)

{
                    // WARNING: Load size is inaccurate
  (*DAT_0042b6a0)(*this,param_1,param_2);
  return;
}



void __thiscall
FUN_00412770(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5)

{
                    // WARNING: Load size is inaccurate
  (*DAT_0042b638)(*this,param_1,param_2,param_3,param_4,param_5);
  return;
}



bool __fastcall FUN_004127a0(undefined4 *param_1)

{
  int iVar1;
  
  iVar1 = (*DAT_0042b6b8)(*param_1);
  return iVar1 != 0;
}



int * __thiscall FUN_004127b0(void *this,int *param_1)

{
  int iVar1;
  
  iVar1 = *param_1;
  *(int *)this = iVar1;
  if (iVar1 != 0) {
    (*DAT_0042b6e8)(iVar1);
  }
  return (int *)this;
}



void __fastcall FUN_004127d0(int *param_1)

{
  if (*param_1 != 0) {
    (*DAT_0042b648)(*param_1);
  }
  return;
}



void __fastcall FUN_004127e0(undefined4 *param_1)

{
  (*DAT_0042b65c)(*param_1);
  return;
}



undefined4 * __fastcall FUN_004127f0(undefined4 *param_1)

{
  undefined4 uVar1;
  undefined4 *unaff_retaddr;
  
  uVar1 = (*DAT_0042b67c)(*param_1);
  *unaff_retaddr = uVar1;
  return unaff_retaddr;
}



void __fastcall FUN_00412810(undefined4 *param_1)

{
  (*DAT_0042b5c4)(*param_1);
  return;
}



void __fastcall FUN_00412820(undefined4 *param_1)

{
  (*DAT_0042b5d0)(*param_1);
  return;
}



void __thiscall FUN_00412830(void *this,undefined4 param_1,undefined4 param_2)

{
                    // WARNING: Load size is inaccurate
  (*DAT_0042b6f0)(*this,param_1,param_2);
  return;
}



void __fastcall FUN_00412850(undefined4 *param_1)

{
  (*DAT_0042b708)(*param_1);
  return;
}



bool __thiscall FUN_00412860(void *this,undefined4 param_1)

{
  int iVar1;
  
                    // WARNING: Load size is inaccurate
  iVar1 = (*DAT_0042b5f4)(*this,param_1);
  return iVar1 != 0;
}



bool __fastcall FUN_00412880(int *param_1)

{
  return *param_1 != 0;
}



void __thiscall FUN_00412890(void *this,undefined4 param_1,undefined4 param_2)

{
                    // WARNING: Load size is inaccurate
  (*DAT_0042b6f4)(*this,param_1,param_2);
  return;
}



undefined4 * __cdecl FUN_00412980(undefined4 param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 *unaff_retaddr;
  
  uVar1 = (*DAT_0042b5d8)(param_2);
  *unaff_retaddr = uVar1;
  return unaff_retaddr;
}



bool __cdecl FUN_004129a0(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  
  DAT_0042b1c8 = param_3;
  iVar1 = (*DAT_0042b6dc)(param_1,param_2,&LAB_004128b0,&LAB_004128e0,&LAB_00412910,&LAB_00412950);
  return iVar1 != 0;
}



undefined4 * __fastcall FUN_004129e0(undefined4 *param_1)

{
  undefined4 uVar1;
  undefined4 *unaff_retaddr;
  
  uVar1 = (*DAT_0042b69c)(*param_1);
  *unaff_retaddr = uVar1;
  return unaff_retaddr;
}



undefined4 * __fastcall FUN_00412a00(undefined4 *param_1)

{
  undefined4 uVar1;
  undefined4 *unaff_retaddr;
  
  uVar1 = (*DAT_0042b5e4)(*param_1);
  *unaff_retaddr = uVar1;
  return unaff_retaddr;
}



undefined4 * __fastcall FUN_00412a20(undefined4 *param_1)

{
  undefined4 uVar1;
  undefined4 *unaff_retaddr;
  
  uVar1 = (*DAT_0042b66c)(*param_1);
  *unaff_retaddr = uVar1;
  return unaff_retaddr;
}



void FUN_00412a40(undefined param_1)

{
  FUN_00411740((int *)&param_1);
  return;
}



void FUN_00412a50(void)

{
  return;
}



void FUN_00412a60(void)

{
  return;
}



void FUN_00412a70(undefined param_1)

{
  FUN_004127d0((int *)&param_1);
  return;
}



void FUN_00412a80(void)

{
  return;
}



undefined4 __fastcall FUN_00412a90(int param_1)

{
  return *(undefined4 *)(param_1 + 0x254);
}



void * __thiscall FUN_00412aa0(void *this,void *param_1)

{
  FUN_004010b0(param_1,(void **)((int)this + 600));
  return param_1;
}



void * __thiscall FUN_00412ad0(void *this,void *param_1)

{
  FUN_004010b0(param_1,(void **)((int)this + 0x208));
  return param_1;
}



void __fastcall FUN_00412b00(int param_1)

{
  FUN_004060c0(param_1 + 0x228);
  return;
}



void __fastcall FUN_00412b10(int param_1)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  void *local_24 [3];
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041bd70;
  local_c = ExceptionList;
  uVar2 = DAT_00428400 ^ (uint)&stack0xffffffd0;
  ExceptionList = &local_c;
  FUN_004010a0(local_18);
  local_4 = 0;
  FUN_004010a0(local_24);
  local_4 = CONCAT31(local_4._1_3_,1);
  FUN_00401040(local_24,"");
  cVar1 = FUN_00403410(param_1);
  if (cVar1 == '\0') {
    do {
      FUN_00402850("System.Receiver  waiting new connection...",(char)uVar2);
      iVar3 = FUN_00405d90((void *)(param_1 + 0x228),-1);
      if (iVar3 != 0) {
        cVar1 = FUN_00403410(param_1);
        if (cVar1 == '\0') {
          FUN_00402850("System.Receiver , new connection",(char)uVar2);
          FUN_00419b80((void *)(param_1 + 0x118),iVar3);
        }
      }
      cVar1 = FUN_00403410(param_1);
    } while (cVar1 == '\0');
  }
  local_4 = local_4 & 0xffffff00;
  FUN_00401170(local_24);
  local_4 = 0xffffffff;
  FUN_00401170(local_18);
  ExceptionList = local_c;
  return;
}



void __fastcall FUN_00412c00(int *param_1)

{
  undefined4 *puVar1;
  
  if (*param_1 < 2) {
    if (*param_1 != 0) {
      operator_delete((void *)param_1[2]);
    }
    return;
  }
  for (puVar1 = *(undefined4 **)param_1[1]; puVar1 != (undefined4 *)0x0;
      puVar1 = (undefined4 *)*puVar1) {
    operator_delete((void *)puVar1[1]);
  }
  operator_delete((void *)param_1[2]);
  return;
}



void __fastcall FUN_00412c50(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  
  if (*(int *)(param_1 + 0xc) == 0) {
    iVar3 = FUN_00402e10((undefined4 *)(param_1 + 0x10),*(int *)(param_1 + 0x14),0x10);
    iVar1 = *(int *)(param_1 + 0x14);
    puVar4 = (undefined4 *)(iVar3 + -0xc + iVar1 * 0x10);
    while (iVar1 = iVar1 + -1, -1 < iVar1) {
      *puVar4 = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 **)(param_1 + 0xc) = puVar4;
      puVar4 = puVar4 + -4;
    }
  }
  puVar4 = *(undefined4 **)(param_1 + 0xc);
  uVar2 = *puVar4;
  *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  *(undefined4 *)(param_1 + 0xc) = uVar2;
  puVar4[2] = 0;
  puVar4[3] = 0;
  return;
}



undefined4 * __fastcall FUN_00412cb0(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  
  if (*(int *)(param_1 + 0xc) == 0) {
    iVar3 = FUN_00402e10((undefined4 *)(param_1 + 0x10),*(int *)(param_1 + 0x14),0x18);
    iVar1 = *(int *)(param_1 + 0x14);
    puVar4 = (undefined4 *)(iVar3 + -0x14 + iVar1 * 0x18);
    while (iVar1 = iVar1 + -1, -1 < iVar1) {
      *puVar4 = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 **)(param_1 + 0xc) = puVar4;
      puVar4 = puVar4 + -6;
    }
  }
  puVar4 = *(undefined4 **)(param_1 + 0xc);
  uVar2 = *puVar4;
  *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  *(undefined4 *)(param_1 + 0xc) = uVar2;
  FUN_00406a40(puVar4 + 2,1);
  puVar4[5] = 0;
  return puVar4;
}



void __thiscall FUN_00412d20(void *this,undefined4 *param_1,uint param_2)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = *(int *)((int)this + 4);
  puVar2 = (undefined4 *)0x0;
  if (iVar1 != 0) {
    for (puVar2 = *(undefined4 **)(iVar1 + ((param_2 >> 4) % *(uint *)((int)this + 8)) * 4);
        puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
      if (puVar2[2] == param_2) goto LAB_00412d4e;
    }
    puVar2 = (undefined4 *)0x0;
  }
LAB_00412d4e:
  param_1[1] = (int *)((int)this + 4);
  *param_1 = puVar2;
  return;
}



void __fastcall FUN_00412d60(void **param_1)

{
  undefined4 *puVar1;
  void *pvVar2;
  
  if ((*param_1 != (void *)0x0) && (pvVar2 = (void *)0x0, param_1[1] != (void *)0x0)) {
    do {
      for (puVar1 = *(undefined4 **)((int)*param_1 + (int)pvVar2 * 4); puVar1 != (undefined4 *)0x0;
          puVar1 = (undefined4 *)*puVar1) {
        FUN_00401170((void **)(puVar1 + 2));
      }
      pvVar2 = (void *)((int)pvVar2 + 1);
    } while (pvVar2 < param_1[1]);
  }
  operator_delete__(*param_1);
  *param_1 = (void *)0x0;
  param_1[2] = (void *)0x0;
  param_1[3] = (void *)0x0;
  FUN_00402e30((int *)param_1[4]);
  param_1[4] = (void *)0x0;
  return;
}



void __fastcall FUN_00412dd0(int param_1,undefined param_2,undefined param_3)

{
  int iVar1;
  undefined uVar2;
  undefined4 *puVar3;
  uint uVar4;
  int *piVar5;
  undefined extraout_DL;
  int iVar6;
  undefined local_64 [4];
  undefined *local_60 [2];
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined2 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined2 local_14;
  uint local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041bd98;
  local_c = ExceptionList;
  local_10 = DAT_00428400 ^ (uint)local_64;
  ExceptionList = &local_c;
  local_4 = 0;
  if ((*(char *)(param_1 + 0x250) != '\0') && (*(char *)(param_1 + 0x251) == '\0')) {
    local_34 = 0;
    local_30 = 0;
    local_2c = 0;
    local_28 = 0;
    local_24 = 0;
    local_20 = 0;
    local_1c = 0;
    local_18 = 0;
    local_14 = 0;
    local_58 = 0;
    local_54 = 0;
    local_50 = 0;
    local_4c = 0;
    local_48 = 0;
    local_44 = 0;
    local_40 = 0;
    local_3c = 0;
    local_38 = 0;
    FUN_004117f0(&param_3,&local_34,0x22);
    FUN_004117a0(&param_3,&local_58,0x22);
    FUN_00411780((undefined4 *)&param_3);
    puVar3 = FUN_004117d0((undefined4 *)&param_3);
    uVar2 = FUN_004116d0(puVar3);
    FUN_00402870("OnCarHandled unit:%d car:%d \'%s\' country:%s",uVar2);
    puVar3 = FUN_004117d0((undefined4 *)&param_3);
    uVar4 = FUN_004116d0(puVar3);
    piVar5 = (int *)FUN_00412d20((void *)(param_1 + 0x68),local_60,uVar4);
    iVar6 = *piVar5;
    if ((piVar5[1] == 0) || (iVar6 == 0)) {
      puVar3 = FUN_004117d0((undefined4 *)&param_3);
      uVar2 = FUN_004116d0(puVar3);
      FUN_004028b0("OnCarHandled, not found Lane by unit Id \'%d\'",uVar2);
    }
    else {
      iVar1 = *(int *)(iVar6 + 0xc);
      local_60[0] = &stack0xffffff90;
      FUN_00411720(&stack0xffffff90,(int *)&param_3);
      FUN_0040cb70(iVar1,extraout_DL,(char)iVar6);
    }
  }
  local_4 = 0xffffffff;
  FUN_00411740((int *)&param_3);
  ExceptionList = local_c;
  ___security_check_cookie_4(local_10 ^ (uint)local_64);
  return;
}



void __fastcall FUN_00412f70(int param_1,undefined param_2,undefined param_3)

{
  int iVar1;
  undefined uVar2;
  undefined4 *puVar3;
  uint uVar4;
  int *piVar5;
  undefined extraout_DL;
  int iVar6;
  undefined *local_14 [2];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041bdc8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  if ((*(char *)(param_1 + 0x250) != '\0') && (*(char *)(param_1 + 0x251) == '\0')) {
    FUN_00411780((undefined4 *)&param_3);
    puVar3 = FUN_004117d0((undefined4 *)&param_3);
    uVar2 = FUN_004116d0(puVar3);
    FUN_00402870("OnCarDeparture unit:%d car:%d",uVar2);
    puVar3 = FUN_004117d0((undefined4 *)&param_3);
    uVar4 = FUN_004116d0(puVar3);
    piVar5 = (int *)FUN_00412d20((void *)(param_1 + 0x68),local_14,uVar4);
    iVar6 = *piVar5;
    if ((piVar5[1] == 0) || (iVar6 == 0)) {
      puVar3 = FUN_004117d0((undefined4 *)&param_3);
      uVar2 = FUN_004116d0(puVar3);
      FUN_004028b0("OnCarDepartur, not found Lane by unit Id \'%d\'",uVar2);
    }
    else {
      iVar1 = *(int *)(iVar6 + 0xc);
      local_14[0] = &stack0xffffffdc;
      FUN_00411720(&stack0xffffffdc,(int *)&param_3);
      FUN_0040cce0(iVar1,extraout_DL,(char)iVar6);
    }
  }
  local_4 = 0xffffffff;
  FUN_00411740((int *)&param_3);
  ExceptionList = local_c;
  return;
}



void __thiscall FUN_00413080(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined uVar1;
  uint uVar2;
  int *piVar3;
  undefined4 local_8 [2];
  
  if ((*(char *)((int)this + 0x250) != '\0') && (*(char *)((int)this + 0x251) == '\0')) {
    uVar1 = FUN_004116d0(&param_1);
    FUN_00402870("OnInputChange unit:%d input:%d value:%d",uVar1);
    uVar2 = FUN_004116d0(&param_1);
    piVar3 = (int *)FUN_00412d20((void *)((int)this + 0x68),local_8,uVar2);
    if ((piVar3[1] == 0) || (*piVar3 == 0)) {
      uVar1 = FUN_004116d0(&param_1);
      FUN_004028b0("OnInputChange, not found Lane by unit Id \'%d\'",uVar1);
      return;
    }
    FUN_00412a50();
  }
  return;
}



void __fastcall FUN_00413120(int param_1,undefined param_2,undefined param_3)

{
  undefined uVar1;
  undefined uVar2;
  undefined4 *puVar3;
  uint uVar4;
  int *piVar5;
  int iVar6;
  undefined4 uVar7;
  undefined extraout_DL;
  undefined4 local_14 [2];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041bdf8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  if ((*(char *)(param_1 + 0x24c) != '\0') && (*(char *)(param_1 + 0x24d) == '\0')) {
    puVar3 = FUN_004127f0((undefined4 *)&param_3);
    uVar4 = FUN_00412740(puVar3);
    piVar5 = (int *)FUN_00412d20((void *)(param_1 + 0x80),local_14,uVar4);
    if ((piVar5[1] == 0) || (*piVar5 == 0)) {
      uVar1 = FUN_004127e0((undefined4 *)&param_3);
      FUN_00402890("OnVideoAvailable video \'%d\' from unit \'%d\'. Unit %d not found lane",uVar1);
    }
    else {
      iVar6 = FUN_0040cf90(*(void **)(*piVar5 + 0xc),uVar4);
      if (iVar6 == 0) {
        uVar1 = FUN_004127e0((undefined4 *)&param_3);
        FUN_00402890("OnVideoAvailable video \'%d\' from unit \'%d\'. UnitREC %d not found",uVar1);
      }
      else {
        uVar7 = FUN_004164d0(iVar6);
        uVar1 = (undefined)uVar7;
        uVar2 = FUN_004127e0((undefined4 *)&param_3);
        FUN_00402870("OnVideoAvailable video \'%d\' from unit \'%d\'. Forward to UnitREC %d ...",
                     uVar2);
        FUN_004127b0(&stack0xffffffd8,(int *)&param_3);
        FUN_00415540(iVar6,extraout_DL,uVar1);
      }
    }
  }
  local_4 = 0xffffffff;
  FUN_004127d0((int *)&param_3);
  ExceptionList = local_c;
  return;
}



void __fastcall FUN_00413240(undefined4 *param_1)

{
  *param_1 = aMap<int,class_CLane*>::vftable;
  FUN_0040c080((void **)(param_1 + 1));
  return;
}



undefined4 * __thiscall FUN_00413250(void *this,byte param_1)

{
  *(undefined ***)this = aMap<int,class_CLane*>::vftable;
  FUN_0040c080((void **)((int)this + 4));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_00413280(int param_1)

{
  void *pvVar1;
  int *piVar2;
  int *piVar3;
  undefined4 *puVar4;
  void **ppvVar5;
  void **ppvVar6;
  void **ppvVar7;
  uint uVar8;
  int **ppiVar9;
  int *piVar10;
  undefined4 unaff_EBP;
  int iVar11;
  undefined uVar12;
  int local_4;
  
  if (*(char *)(param_1 + 0x250) != '\0') {
    *(undefined *)(param_1 + 0x251) = 1;
    local_4 = param_1;
    FUN_00419af0(param_1 + 0x120);
    FUN_004033d0((int *)(param_1 + 8));
    FUN_004060c0(param_1 + 0x230);
    if (0 < *(int *)(param_1 + 0x74)) {
      do {
        iVar11 = 0;
        if (*(int *)(param_1 + 0x74) != 0) {
          uVar8 = 0;
          if (*(uint *)(param_1 + 0x70) != 0) {
            piVar10 = *(int **)(param_1 + 0x6c);
            do {
              iVar11 = *piVar10;
              if (iVar11 != 0) break;
              uVar8 = uVar8 + 1;
              piVar10 = piVar10 + 1;
            } while (uVar8 < *(uint *)(param_1 + 0x70));
          }
        }
        pvVar1 = *(void **)(param_1 + 0x6c);
        if (pvVar1 != (void *)0x0) {
          uVar8 = ((uint)*(void **)(iVar11 + 8) >> 4) % *(uint *)(param_1 + 0x70);
          ppvVar7 = *(void ***)((int)pvVar1 + uVar8 * 4);
          ppvVar6 = (void **)((int)pvVar1 + uVar8 * 4);
          while (ppvVar5 = ppvVar7, ppvVar5 != (void **)0x0) {
            if (ppvVar5[2] == *(void **)(iVar11 + 8)) {
              *ppvVar6 = *ppvVar5;
              *ppvVar5 = *(void **)(param_1 + 0x78);
              piVar10 = (int *)(param_1 + 0x74);
              *piVar10 = *piVar10 + -1;
              *(void ***)(param_1 + 0x78) = ppvVar5;
              if (*piVar10 == 0) {
                FUN_0040c080((void **)(param_1 + 0x6c));
              }
              break;
            }
            ppvVar6 = ppvVar5;
            ppvVar7 = (void **)*ppvVar5;
          }
        }
      } while (0 < *(int *)(param_1 + 0x74));
    }
    if (0 < *(int *)(param_1 + 0x90)) {
      do {
        iVar11 = 0;
        if (*(int *)(param_1 + 0x90) != 0) {
          uVar8 = 0;
          if (*(uint *)(param_1 + 0x8c) != 0) {
            piVar10 = *(int **)(param_1 + 0x88);
            do {
              iVar11 = *piVar10;
              if (iVar11 != 0) break;
              uVar8 = uVar8 + 1;
              piVar10 = piVar10 + 1;
            } while (uVar8 < *(uint *)(param_1 + 0x8c));
          }
        }
        pvVar1 = *(void **)(param_1 + 0x88);
        if (pvVar1 != (void *)0x0) {
          uVar8 = ((uint)*(void **)(iVar11 + 8) >> 4) % *(uint *)(param_1 + 0x8c);
          ppvVar7 = *(void ***)((int)pvVar1 + uVar8 * 4);
          ppvVar6 = (void **)((int)pvVar1 + uVar8 * 4);
          while (ppvVar5 = ppvVar7, ppvVar5 != (void **)0x0) {
            if (ppvVar5[2] == *(void **)(iVar11 + 8)) {
              *ppvVar6 = *ppvVar5;
              *ppvVar5 = *(void **)(param_1 + 0x94);
              piVar10 = (int *)(param_1 + 0x90);
              *piVar10 = *piVar10 + -1;
              *(void ***)(param_1 + 0x94) = ppvVar5;
              if (*piVar10 == 0) {
                FUN_0040c080((void **)(param_1 + 0x88));
              }
              break;
            }
            ppvVar6 = ppvVar5;
            ppvVar7 = (void **)*ppvVar5;
          }
        }
      } while (0 < *(int *)(param_1 + 0x90));
    }
    uVar12 = (undefined)unaff_EBP;
    piVar10 = (int *)(param_1 + 0xbc);
    iVar11 = *(int *)(param_1 + 0xbc);
    while (0 < iVar11) {
      ppiVar9 = (int **)FUN_00408af0(piVar10,&local_4);
      piVar2 = *ppiVar9;
      piVar3 = (int *)piVar2[2];
      if (1 < *piVar10) {
        if (piVar2 == *(int **)(param_1 + 0xc0)) {
          iVar11 = **(int **)(param_1 + 0xc0);
          *(int *)(param_1 + 0xc0) = iVar11;
          *(undefined4 *)(iVar11 + 4) = 0;
        }
        else if (piVar2 == *(int **)(param_1 + 0xc4)) {
          puVar4 = (undefined4 *)(*(int **)(param_1 + 0xc4))[1];
          *(undefined4 **)(param_1 + 0xc4) = puVar4;
          *puVar4 = 0;
        }
        else {
          *(int *)piVar2[1] = *piVar2;
          *(int *)(*piVar2 + 4) = piVar2[1];
        }
      }
      operator_delete(piVar2);
      *piVar10 = *piVar10 + -1;
      if (*piVar10 == 0) {
        *(undefined4 *)(param_1 + 0xc4) = 0;
        *(undefined4 *)(param_1 + 0xc0) = 0;
      }
      FUN_0040ebd0(piVar3);
      if (piVar3 != (int *)0x0) {
        (**(code **)*piVar3)(1);
      }
      uVar12 = (undefined)unaff_EBP;
      iVar11 = *piVar10;
    }
    if (0 < *(int *)(param_1 + 0x268)) {
      FUN_004116b0();
      FUN_004116a0();
    }
    if (1 < *(int *)(param_1 + 0x268)) {
      FUN_00412730();
      FUN_00412720();
    }
    FUN_00402870("Terminate complete.",uVar12);
    if (*(undefined4 **)(param_1 + 0x24c) != (undefined4 *)0x0) {
      (**(code **)**(undefined4 **)(param_1 + 0x24c))(1);
    }
  }
  return;
}



uint __fastcall FUN_00413490(int param_1,undefined param_2,undefined param_3)

{
  byte bVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined1 *puVar4;
  void **ppvVar5;
  int iVar6;
  undefined extraout_DL;
  undefined uVar7;
  char *pcVar8;
  int local_4c;
  undefined *local_48;
  void *local_44 [3];
  void *local_38 [3];
  undefined local_2c [32];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041be98;
  local_c = ExceptionList;
  bVar1 = (byte)DAT_00428400 ^ (byte)&stack0xffffffa4;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_00405070((int)local_2c,(void **)&param_3);
  local_4._0_1_ = 1;
  FUN_004010a0(local_44);
  local_4._0_1_ = 2;
  uVar2 = FUN_00402830(&param_3);
  if ((char)uVar2 == '\0') {
    pcVar8 = "System: Error reading log configuration";
  }
  else {
    FUN_00401100(local_38,"Global/FtpTimeoutSeconds",(char *)0x7fffffff);
    local_4._0_1_ = 3;
    uVar3 = FUN_004057e0(local_2c,(int *)local_38,(long *)(param_1 + 0x254));
    local_4._0_1_ = 2;
    FUN_00401170(local_38);
    if ((char)uVar3 == '\0') {
      pcVar8 = "System: Missing configuration parameter (Global/FtpTimeoutSeconds)";
    }
    else {
      FUN_00401100(local_38,"Global/FtpPassword",(char *)0x7fffffff);
      local_4._0_1_ = 4;
      uVar3 = FUN_00405440(local_2c,(int *)local_38,(void **)(param_1 + 600));
      local_4._0_1_ = 2;
      FUN_00401170(local_38);
      if ((char)uVar3 == '\0') {
        pcVar8 = "System: Missing configuration parameter (Global/FtpPassword)";
      }
      else {
        FUN_00401100(local_38,"Global/Lanes",(char *)0x7fffffff);
        local_4._0_1_ = 5;
        uVar3 = FUN_00405440(local_2c,(int *)local_38,(void **)(param_1 + 0x220));
        local_4._0_1_ = 2;
        FUN_00401170(local_38);
        if ((char)uVar3 == '\0') {
          pcVar8 = "System: Missing configuration parameter (Global/Lanes)";
        }
        else {
          FUN_00401100(local_38,"Global/Host",(char *)0x7fffffff);
          local_4._0_1_ = 6;
          uVar3 = FUN_00405440(local_2c,(int *)local_38,(void **)&DAT_0042b1cc);
          local_4._0_1_ = 2;
          FUN_00401170(local_38);
          if ((char)uVar3 == '\0') {
            pcVar8 = "ScheidtBachmann: Missing configuration parameter (Global/Host)";
          }
          else {
            puVar4 = FUN_004011f0((undefined4 *)&DAT_0042b1cc);
            FUN_00402870("Host                       : %s",(char)puVar4);
            FUN_00401100(local_38,"Global/HttpPort",(char *)0x7fffffff);
            local_4._0_1_ = 7;
            uVar3 = FUN_004057e0(local_2c,(int *)local_38,(long *)(param_1 + 0x22c));
            local_4._0_1_ = 2;
            FUN_00401170(local_38);
            if ((char)uVar3 == '\0') {
              pcVar8 = "ScheidtBachmann: Missing configuration parameter (Global/HttpPort)";
            }
            else {
              FUN_00402870("Port                       : %d",(char)*(long *)(param_1 + 0x22c));
              FUN_00401100(local_38,"Global/Version",(char *)0x7fffffff);
              local_4._0_1_ = 8;
              uVar3 = FUN_00405440(local_2c,(int *)local_38,(void **)&DAT_0042b1d8);
              local_4._0_1_ = 2;
              FUN_00401170(local_38);
              if ((char)uVar3 == '\0') {
                pcVar8 = "ScheidtBachmann: Missing configuration parameter (Global/Version)";
              }
              else {
                puVar4 = FUN_004011f0((undefined4 *)&DAT_0042b1d8);
                FUN_00402870("Version                    : %s",(char)puVar4);
                FUN_00401100(local_38,"Global/LPRInvalidChars",(char *)0x7fffffff);
                local_4._0_1_ = 9;
                uVar3 = FUN_00405440(local_2c,(int *)local_38,local_44);
                local_4._0_1_ = 2;
                FUN_00401170(local_38);
                if ((char)uVar3 == '\0') {
                  pcVar8 = 
                  "ScheidtBachmann: Missing configuration parameter (Global/LPRInvalidChars)";
                }
                else {
                  uVar7 = local_44[0]._0_1_;
                  FUN_00402870("LPRInvalidChars            : %s",local_44[0]._0_1_);
                  local_48 = &stack0xffffff94;
                  FUN_004010b0(&stack0xffffff94,local_44);
                  FUN_0040b5e0(&DAT_00429190,extraout_DL,uVar7);
                  FUN_00401100(local_38,"Global/SendDecoratedLicense",(char *)0x7fffffff);
                  local_4._0_1_ = 10;
                  uVar3 = FUN_004057e0(local_2c,(int *)local_38,&local_4c);
                  local_4._0_1_ = 2;
                  FUN_00401170(local_38);
                  if ((char)uVar3 == '\0') {
                    pcVar8 = 
                    "ScheidtBachmann: Missing configuration parameter (Global/SendDecoratedLicense)"
                    ;
                  }
                  else {
                    DAT_0042b194 = local_4c == 1;
                    FUN_00402870("SendDecoratedLicense       : %d",DAT_0042b194);
                    FUN_00401100(local_38,"Global/DecoratedCharQuality",(char *)0x7fffffff);
                    local_4._0_1_ = 0xb;
                    uVar3 = FUN_004057e0(local_2c,(int *)local_38,&DAT_00428148);
                    local_4._0_1_ = 2;
                    FUN_00401170(local_38);
                    if ((char)uVar3 == '\0') {
                      pcVar8 = 
                      "ScheidtBachmann: Missing configuration parameter (Global/DecoratedCharQuality)"
                      ;
                    }
                    else {
                      FUN_00402870("DecoratedCharQuality       : %d",(char)DAT_00428148);
                      FUN_00401100(local_38,"Global/WorkingMode",(char *)0x7fffffff);
                      local_4._0_1_ = 0xc;
                      uVar3 = FUN_00405440(local_2c,(int *)local_38,local_44);
                      local_4._0_1_ = 2;
                      FUN_00401170(local_38);
                      if ((char)uVar3 == '\0') {
                        pcVar8 = 
                        "ScheidtBachmann: Missing configuration parameter (Global/WorkingMode)";
                      }
                      else {
                        puVar4 = FUN_004011f0(local_44);
                        FUN_00402870("WorkingMode                : %s",(char)puVar4);
                        FUN_004014f0(local_44,'\x01');
                        FUN_004014f0(local_44,'\0');
                        ppvVar5 = FUN_00401390(local_44,local_38);
                        local_4._0_1_ = 0xd;
                        FUN_00401000(local_44,ppvVar5);
                        local_4._0_1_ = 2;
                        FUN_00401170(local_38);
                        iVar6 = FUN_00401290(local_44,(byte *)"SOFTWARE");
                        if (iVar6 == 0) {
                          *(undefined4 *)(param_1 + 0x27c) = 0;
                        }
                        else {
                          iVar6 = FUN_00401290(local_44,(byte *)"HARDWARE");
                          if (iVar6 != 0) {
                            pcVar8 = 
                            "ScheidtBachmann: Invalid configuration parameter (Global/WorkingMode). Available values Software,Hardware."
                            ;
                            goto LAB_00413a21;
                          }
                          *(undefined4 *)(param_1 + 0x27c) = 1;
                        }
                        FUN_00401100(local_38,"Global/JsonVersion",(char *)0x7fffffff);
                        local_4._0_1_ = 0xe;
                        uVar3 = FUN_004057e0(local_2c,(int *)local_38,&local_4c);
                        local_4._0_1_ = 2;
                        FUN_00401170(local_38);
                        if ((char)uVar3 != '\0') {
                          if (local_4c == 1) {
                            *(undefined4 *)(param_1 + 0x278) = 1;
                          }
                          else {
                            if (local_4c != 2) {
                              pcVar8 = 
                              "ScheidtBachmann: Invalid configuration parameter (Global/JsonVersion). Available values (1,2)"
                              ;
                              goto LAB_00413a21;
                            }
                            *(undefined4 *)(param_1 + 0x278) = 2;
                          }
                          local_4._0_1_ = 1;
                          FUN_00401170(local_44);
                          local_4 = (uint)local_4._1_3_ << 8;
                          FUN_00401f60((int)local_2c);
                          local_4 = 0xffffffff;
                          uVar3 = FUN_00401170((void **)&param_3);
                          ExceptionList = local_c;
                          return CONCAT31((int3)((uint)uVar3 >> 8),1);
                        }
                        pcVar8 = 
                        "ScheidtBachmann: Missing configuration parameter (Global/JsonVersion)";
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
LAB_00413a21:
  FUN_004028b0(pcVar8,bVar1);
  local_4._0_1_ = 1;
  FUN_00401170(local_44);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401f60((int)local_2c);
  local_4 = 0xffffffff;
  uVar2 = FUN_00401170((void **)&param_3);
  ExceptionList = local_c;
  return uVar2 & 0xffffff00;
}



void __thiscall FUN_00413a70(void *this,uint param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_00414eb0((void *)((int)this + 4),param_1);
  *puVar1 = param_2;
  return;
}



void __fastcall FUN_00413a90(undefined4 *param_1)

{
  *param_1 = aMap<class_aString,class_CLane*>::vftable;
  FUN_00412d60((void **)(param_1 + 1));
  return;
}



undefined4 * __thiscall FUN_00413aa0(void *this,byte param_1)

{
  *(undefined ***)this = aMap<class_aString,class_CLane*>::vftable;
  FUN_00412d60((void **)((int)this + 4));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall
FUN_00413ad0(void *param_1,undefined param_2,undefined param_3,undefined param_4,undefined param_5,
            undefined param_6,undefined param_7,undefined param_8,undefined param_9,
            undefined param_10,undefined param_11,undefined param_12,undefined param_13)

{
  bool bVar1;
  char cVar2;
  uint uVar3;
  int iVar4;
  void *pvVar5;
  undefined4 *puVar6;
  void **ppvVar7;
  uint uVar8;
  undefined1 *puVar9;
  undefined1 *puVar10;
  int **ppiVar11;
  char **ppcVar12;
  int **ppiVar13;
  undefined4 *puVar14;
  void *this;
  undefined extraout_DL;
  LPCSTR pCVar15;
  void *in_stack_fffffd28;
  void *pvVar16;
  undefined uVar17;
  undefined4 uVar18;
  undefined4 uVar19;
  char *pcVar20;
  undefined4 uVar21;
  int *piVar22;
  char *local_2b4 [3];
  void *local_2a8 [3];
  undefined *local_29c;
  undefined4 *local_298;
  void *local_294;
  void *local_290 [3];
  void *local_284 [3];
  undefined4 local_278;
  int *local_274 [3];
  long local_268;
  int *local_264;
  int *local_260;
  int *local_25c;
  int *local_258;
  char *local_254 [8];
  char *local_234 [3];
  int local_228 [2];
  WSADATA local_220;
  char local_90 [128];
  uint local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041bf85;
  local_c = ExceptionList;
  local_10 = DAT_00428400 ^ (uint)local_2b4;
  uVar3 = DAT_00428400 ^ (uint)&stack0xfffffd3c;
  ExceptionList = &local_c;
  local_4 = 5;
  FUN_004118b0(&local_278);
  FUN_004010a0(local_2b4);
  local_4._0_1_ = 6;
  FUN_004010a0(local_2a8);
  local_4._0_1_ = 7;
  FUN_004010a0(local_290);
  local_4._0_1_ = 8;
  pvVar16 = (void *)0x413b66;
  iVar4 = WSAStartup(0x101,&local_220);
  if (iVar4 == 0) {
    uVar18 = 0x413c39;
    pvVar5 = operator_new(0x50);
    local_4._0_1_ = 9;
    local_294 = pvVar5;
    if (pvVar5 == (void *)0x0) {
      puVar6 = (undefined4 *)0x0;
    }
    else {
      uVar19 = 0xa00000;
      local_29c = &stack0xfffffd28;
      FUN_004010b0(&stack0xfffffd28,(void **)&param_6);
      puVar6 = FUN_00401b10(pvVar5,1,0,in_stack_fffffd28,(uint)pvVar16,uVar18,uVar19);
    }
    uVar17 = 0xb8;
    local_4._0_1_ = 8;
    *(undefined4 **)((int)param_1 + 0x24c) = puVar6;
    FUN_00402870("Start LPRScheidtBachmannV3 (v: %s)",0xf0);
    FUN_00402870("System::Initialize ...",uVar17);
    memset(local_90,0,0x80);
    iVar4 = gethostname(local_90,0x80);
    if (iVar4 == 0) {
      ppiVar13 = local_274;
      ppvVar7 = (void **)FUN_004018e0(ppiVar13,"%s");
      local_4._0_1_ = 10;
      FUN_00401000((void *)((int)param_1 + 0x214),ppvVar7);
      local_4._0_1_ = 8;
      FUN_00401170(local_274);
      uVar8 = FUN_00402830(&param_9);
      if ((char)uVar8 == '\0') {
        puVar9 = FUN_004011f0((undefined4 *)&param_9);
        FUN_004028b0("System::Initialize not found Global/LogLevel on file \'%s\'",(char)puVar9);
      }
      else {
        local_29c = &stack0xfffffd2c;
        FUN_004010b0(&stack0xfffffd2c,(void **)&param_3);
        bVar1 = FUN_00403760((LPCSTR)ppiVar13);
        if (bVar1) {
          local_29c = &stack0xfffffd2c;
          FUN_004010b0(&stack0xfffffd2c,(void **)&param_3);
          uVar18 = FUN_00413490((int)param_1,extraout_DL,(char)ppiVar13);
          if ((char)uVar18 == '\0') {
            puVar9 = FUN_004011f0((undefined4 *)&param_3);
            FUN_004028b0("System::Initialize, can\'t initialize ini file \'%s\'\n",(char)puVar9);
          }
          else {
            local_29c = &stack0xfffffd2c;
            FUN_004010b0(&stack0xfffffd2c,(void **)&param_9);
            bVar1 = FUN_00403760((LPCSTR)ppiVar13);
            if (bVar1) {
              iVar4 = FUN_00410660();
              uVar17 = (undefined)uVar3;
              if (iVar4 == -1) {
                pcVar20 = "System::Initialize, can\'t load SmartLprAIO library\n";
LAB_00413e1e:
                FUN_004028b0(pcVar20,uVar17);
              }
              else {
                pvVar16 = param_1;
                puVar9 = FUN_004011f0((undefined4 *)&param_11);
                puVar10 = FUN_004011f0((undefined4 *)&param_9);
                bVar1 = FUN_00411b30(puVar10,puVar9,pvVar16);
                uVar17 = (undefined)uVar3;
                if (!bVar1) {
                  pcVar20 = "System::Initialize, can\'t initialize SmartLprAIO System";
                  goto LAB_00413e1e;
                }
                *(int *)((int)param_1 + 0x268) = *(int *)((int)param_1 + 0x268) + 1;
                iVar4 = FUN_00411c00();
                uVar17 = (undefined)uVar3;
                if (iVar4 == -1) {
                  pcVar20 = "System::Initialize, can\'t load SmartREC library\n";
                  goto LAB_00413e1e;
                }
                iVar4 = (int)param_1 + 4;
                puVar9 = FUN_004011f0((undefined4 *)&param_13);
                puVar10 = FUN_004011f0((undefined4 *)&param_12);
                bVar1 = FUN_004129a0(puVar10,puVar9,iVar4);
                uVar17 = (undefined)uVar3;
                if (!bVar1) {
                  pcVar20 = "System::Initialize, can\'t initialize SmartREC System";
                  goto LAB_00413e1e;
                }
                *(int *)((int)param_1 + 0x268) = *(int *)((int)param_1 + 0x268) + 1;
                FUN_00401040((undefined4 *)((int)param_1 + 0x208),"../Log");
                FUN_004011f0((undefined4 *)((int)param_1 + 0x208));
                ppiVar13 = local_274;
                ppvVar7 = (void **)FUN_004018e0(ppiVar13,"%s/RecUnits");
                local_4._0_1_ = 0xb;
                uVar18 = 0x413f9e;
                FUN_00401000(local_2a8,ppvVar7);
                local_4._0_1_ = 8;
                FUN_00401170(local_274);
                local_29c = &stack0xfffffd2c;
                FUN_004010b0(&stack0xfffffd2c,local_2a8);
                pvVar16 = (void *)0x413fc7;
                bVar1 = FUN_00403760((LPCSTR)ppiVar13);
                if (bVar1) {
                  FUN_004010a0(local_284);
                  uVar21 = 0;
                  local_29c = &stack0xfffffd28;
                  uVar19 = 0x7fffffff;
                  pCVar15 = "*";
                  local_4._0_1_ = 0xc;
                  pvVar5 = (void *)0x413ffe;
                  FUN_00401100(&stack0xfffffd28,"*",(char *)0x7fffffff);
                  local_298 = (undefined4 *)&stack0xfffffd1c;
                  local_4._0_1_ = 0xd;
                  FUN_004010b0(&stack0xfffffd1c,local_2a8);
                  local_4 = CONCAT31(local_4._1_3_,0xc);
                  ppiVar11 = (int **)FUN_00403440(this,pvVar5,pCVar15,uVar19,pvVar16,ppiVar13,uVar18
                                                  ,uVar21);
                  uVar8 = FUN_00403650(ppiVar11,local_284,(uint *)&local_294);
                  cVar2 = (char)uVar8;
                  while (cVar2 != '\0') {
                    iVar4 = FUN_00401290(local_284,&DAT_00421390);
                    if ((iVar4 != 0) && (iVar4 = FUN_00401290(local_284,&DAT_0042138c), iVar4 != 0))
                    {
                      if (local_294 == (void *)0x0) {
                        ppiVar13 = local_274;
                        ppvVar7 = FUN_00401a20(ppiVar13,local_2a8,"/");
                        local_4._0_1_ = 0xe;
                        local_298 = (undefined4 *)&stack0xfffffd2c;
                        FUN_00401990((void **)&stack0xfffffd2c,ppvVar7,local_284);
                        FUN_00403820((char *)ppiVar13);
                        local_4 = CONCAT31(local_4._1_3_,0xc);
                        FUN_00401170(local_274);
                      }
                      else {
                        local_298 = (undefined4 *)&stack0xfffffd2c;
                        FUN_00401990((void **)&stack0xfffffd2c,local_2a8,local_284);
                        FUN_004037e0((LPCSTR)ppiVar13);
                      }
                    }
                    ppiVar13 = ppiVar11;
                    uVar8 = FUN_00403650(ppiVar11,local_284,(uint *)&local_294);
                    cVar2 = (char)uVar8;
                  }
                  local_4._1_3_ = (uint3)((uint)local_4 >> 8);
                  local_4._0_1_ = 8;
                  FUN_00401170(local_284);
                }
                FUN_00401100(local_274,",",(char *)0x7fffffff);
                local_4._0_1_ = 0xf;
                FUN_00404340(local_254,(void **)((int)param_1 + 0x220));
                local_4._0_1_ = 0x11;
                FUN_00401170(local_274);
                uVar18 = FUN_004043f0(local_254);
                cVar2 = (char)uVar18;
                while (uVar17 = (undefined)uVar3, cVar2 != '\0') {
                  ppcVar12 = FUN_00404520(local_254,local_234);
                  local_4._0_1_ = 0x12;
                  FUN_00401000(local_2b4,ppcVar12);
                  local_4._0_1_ = 0x11;
                  FUN_00401170(local_234);
                  iVar4 = FUN_00401180(local_2b4);
                  if ((char)iVar4 == '\0') {
                    FUN_004011f0(local_2b4);
                    puVar9 = FUN_004011f0(local_2b4);
                    local_268._0_1_ = SUB41(puVar9,0);
                    pcVar20 = "System::Initialize lane %s Invalid value \'%s\'";
LAB_004143a9:
                    FUN_004028b0(pcVar20,(undefined)local_268);
                    local_4._0_1_ = 8;
                    FUN_0040bc30(local_254);
                    goto LAB_00413e26;
                  }
                  uVar18 = FUN_004017b0(local_2b4,&local_268,(char *)0xa);
                  if ((char)uVar18 == '\0') {
                    FUN_004011f0(local_2b4);
                    pcVar20 = "System::Initialize lane %ld Invalid value \'%s\'";
                    goto LAB_004143a9;
                  }
                  local_298 = (undefined4 *)operator_new(0x1c4);
                  local_4._0_1_ = 0x13;
                  if (local_298 == (undefined4 *)0x0) {
                    puVar6 = (undefined4 *)0x0;
                  }
                  else {
                    puVar6 = FUN_0040d850(local_298);
                  }
                  local_298 = (undefined4 *)&stack0xfffffd2c;
                  local_4._0_1_ = 0x11;
                  FUN_004010b0(&stack0xfffffd2c,(void **)&param_3);
                  cVar2 = FUN_0040db10(puVar6,param_1,local_268);
                  if (cVar2 == '\0') {
                    puVar9 = FUN_004011f0(local_2b4);
                    FUN_004028b0("System::Initialize can\'t initialize lane %s",(char)puVar9);
                    local_4._0_1_ = 8;
                    FUN_0040bc30(local_254);
                    goto LAB_00413e26;
                  }
                  puVar14 = puVar6;
                  uVar8 = FUN_0040bb90((int)puVar6);
                  FUN_00413a70((void *)((int)param_1 + 0xa0),uVar8,puVar14);
                  piVar22 = local_228;
                  pvVar16 = (void *)FUN_0040bba0((int)puVar6);
                  ppiVar13 = (int **)FUN_00414e00(pvVar16,piVar22);
                  local_25c = *ppiVar13;
                  local_258 = ppiVar13[1];
                  while ((local_258 != (int *)0x0 && (local_25c != (int *)0x0))) {
                    FUN_004118c0(&local_294,local_25c + 3);
                    FUN_004118c0(&local_278,&local_294);
                    uVar8 = FUN_004116d0(&local_278);
                    puVar14 = FUN_00414eb0((void *)((int)param_1 + 0x6c),uVar8);
                    *puVar14 = puVar6;
                    FUN_0040c040(&local_25c);
                  }
                  ppvVar7 = local_284;
                  pvVar16 = (void *)FUN_0040bbb0((int)puVar6);
                  ppiVar13 = (int **)FUN_00414e00(pvVar16,(int *)ppvVar7);
                  local_264 = *ppiVar13;
                  local_260 = ppiVar13[1];
                  while ((piVar22 = local_260, local_260 != (int *)0x0 && (local_264 != (int *)0x0))
                        ) {
                    uVar8 = FUN_004164d0(local_264[3]);
                    puVar14 = FUN_00414eb0((void *)((int)param_1 + 0x88),uVar8);
                    *puVar14 = puVar6;
                    FUN_0040bf60(piVar22,&local_264,(int *)&local_29c,(int *)&local_298);
                  }
                  FUN_00408aa0((void *)((int)param_1 + 0xbc),puVar6);
                  uVar18 = FUN_004043f0(local_254);
                  cVar2 = (char)uVar18;
                }
                FUN_004199b0((void *)((int)param_1 + 0x120),(int)param_1 + 200,(int)param_1 + 0xf4,
                             *(undefined4 *)((int)param_1 + 0x278),
                             *(undefined4 *)((int)param_1 + 0x27c));
                cVar2 = FUN_00405c50((void *)((int)param_1 + 0x230),
                                     (u_short)*(undefined4 *)((int)param_1 + 0x22c),0x400,'\0');
                if (cVar2 == '\0') {
                  FUN_004028b0("System::Initialize Error trying to open main port %d",
                               (char)*(undefined4 *)((int)param_1 + 0x22c));
                  local_4._0_1_ = 8;
                  FUN_0040bc30(local_254);
                }
                else {
                  cVar2 = FUN_00403360((void *)((int)param_1 + 8),'\0',0,0);
                  if (cVar2 != '\0') {
                    *(undefined *)((int)param_1 + 0x250) = 1;
                    FUN_00402870("System::Initialize (Lanes:%d) complete",
                                 (char)*(undefined4 *)((int)param_1 + 0xbc));
                    local_4._0_1_ = 8;
                    FUN_0040bc30(local_254);
                    local_4._0_1_ = 7;
                    FUN_00401170(local_290);
                    local_4._0_1_ = 6;
                    FUN_00401170(local_2a8);
                    local_4._0_1_ = 5;
                    FUN_00401170(local_2b4);
                    local_4._0_1_ = 4;
                    FUN_00401170((void **)&param_3);
                    local_4._0_1_ = 3;
                    FUN_00401170((void **)&param_6);
                    local_4._0_1_ = 2;
                    FUN_00401170((void **)&param_9);
                    local_4._0_1_ = 1;
                    FUN_00401170((void **)&param_11);
                    local_4 = (uint)local_4._1_3_ << 8;
                    FUN_00401170((void **)&param_12);
                    local_4 = 0xffffffff;
                    FUN_00401170((void **)&param_13);
                    goto LAB_00414517;
                  }
                  FUN_004028b0("System::Initialize Can\'t start thread",uVar17);
                  local_4._0_1_ = 8;
                  FUN_0040bc30(local_254);
                }
              }
LAB_00413e26:
              local_4._0_1_ = 7;
              FUN_00401170(local_290);
              local_4._0_1_ = 6;
              FUN_00401170(local_2a8);
              local_4._0_1_ = 5;
              FUN_00401170(local_2b4);
              local_4._0_1_ = 4;
              FUN_00401170((void **)&param_3);
              local_4._0_1_ = 3;
              FUN_00401170((void **)&param_6);
              local_4._0_1_ = 2;
              FUN_00401170((void **)&param_9);
              local_4._0_1_ = 1;
              FUN_00401170((void **)&param_11);
              local_4 = (uint)local_4._1_3_ << 8;
              FUN_00401170((void **)&param_12);
              local_4 = 0xffffffff;
              FUN_00401170((void **)&param_13);
              goto LAB_00414517;
            }
            puVar9 = FUN_004011f0((undefined4 *)&param_9);
            FUN_004028b0("System::Initialize, can\'t find SmartLprAIO ini file \'%s\'\n",
                         (char)puVar9);
          }
        }
        else {
          puVar9 = FUN_004011f0((undefined4 *)&param_3);
          FUN_004028b0("System::Initialize, can\'t find scheidtBachmann ini file \'%s\'\n",
                       (char)puVar9);
        }
      }
    }
    else {
      iVar4 = WSAGetLastError();
      FUN_004028b0("Network failed gethostname WSAGetLastError:%d",(char)iVar4);
    }
  }
  else {
    printf("Network failed to start: %d\n");
  }
  local_4._0_1_ = 7;
  FUN_00401170(local_290);
  local_4._0_1_ = 6;
  FUN_00401170(local_2a8);
  local_4._0_1_ = 5;
  FUN_00401170(local_2b4);
  local_4._0_1_ = 4;
  FUN_00401170((void **)&param_3);
  local_4._0_1_ = 3;
  FUN_00401170((void **)&param_6);
  local_4._0_1_ = 2;
  FUN_00401170((void **)&param_9);
  local_4._0_1_ = 1;
  FUN_00401170((void **)&param_11);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170((void **)&param_12);
  local_4 = 0xffffffff;
  FUN_00401170((void **)&param_13);
LAB_00414517:
  ExceptionList = local_c;
  ___security_check_cookie_4(local_10 ^ (uint)local_2b4);
  return;
}



void __fastcall FUN_00414550(undefined4 *param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041bfcb;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = aCollection<class_aString,class_CLane*>::vftable;
  local_4 = 0;
  FUN_004028d0(param_1 + 8);
  local_4 = 0xffffffff;
  param_1[1] = aMap<class_aString,class_CLane*>::vftable;
  FUN_00412d60((void **)(param_1 + 2));
  ExceptionList = local_c;
  return;
}



uint __thiscall
FUN_004145c0(void *this,undefined param_1,undefined param_2,undefined param_3,undefined *param_4)

{
  int *piVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined uVar4;
  undefined uVar5;
  void *in_stack_ffffffd0;
  undefined uVar6;
  uint in_stack_ffffffd4;
  undefined4 local_14 [2];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041bff8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004010b0(&stack0xffffffd0,(void **)&param_1);
  piVar1 = FUN_00409340((void *)((int)this + 4),local_14);
  if ((piVar1[1] != 0) && (*piVar1 != 0)) {
    local_4 = 0xffffffff;
    uVar2 = FUN_00401170((void **)&param_1);
    ExceptionList = local_c;
    return uVar2 & 0xffffff00;
  }
  FUN_004010b0(&stack0xffffffd0,(void **)&param_1);
  uVar4 = 0x5e;
  FUN_00405a90((void *)((int)this + 0x20),in_stack_ffffffd0,in_stack_ffffffd4);
  uVar6 = (undefined)in_stack_ffffffd4;
  uVar5 = SUB41(in_stack_ffffffd0,0);
  uVar3 = param_4;
  param_4 = &stack0xffffffcc;
  FUN_004010b0(&stack0xffffffcc,(void **)&param_1);
  FUN_00409c60((void *)((int)this + 4),uVar4,uVar5,uVar6,uVar3);
  local_4 = 0xffffffff;
  uVar3 = FUN_00401170((void **)&param_1);
  ExceptionList = local_c;
  return CONCAT31((int3)((uint)uVar3 >> 8),1);
}



undefined4 * __thiscall FUN_004146b0(void *this,byte param_1)

{
  FUN_00414550((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __fastcall FUN_004146d0(undefined4 *param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041c0db;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = SmartLprAIO::ISystemEH::vftable;
  param_1[1] = SmartREC::ISystemEH::vftable;
  FUN_004032d0(param_1 + 2);
  local_4 = 0;
  *param_1 = CSystem::vftable;
  param_1[1] = CSystem::vftable;
  param_1[2] = CSystem::vftable;
  FUN_00402e50(param_1 + 0x11);
  param_1[0x1a] = aMap<int,class_CLane*>::vftable;
  param_1[0x1b] = 0;
  param_1[0x1c] = 0x11;
  param_1[0x1d] = 0;
  param_1[0x1e] = 0;
  param_1[0x1f] = 0;
  param_1[0x20] = 10;
  param_1[0x21] = aMap<int,class_CLane*>::vftable;
  param_1[0x22] = 0;
  param_1[0x23] = 0x11;
  param_1[0x24] = 0;
  param_1[0x25] = 0;
  param_1[0x26] = 0;
  param_1[0x27] = 10;
  param_1[0x28] = aMap<int,class_CLane*>::vftable;
  param_1[0x29] = 0;
  param_1[0x2a] = 0x11;
  param_1[0x2b] = 0;
  param_1[0x2c] = 0;
  param_1[0x2d] = 0;
  param_1[0x2e] = 10;
  param_1[0x2f] = 0;
  param_1[0x30] = 0;
  param_1[0x31] = 0;
  param_1[0x32] = aCollection<class_aString,class_CLane*>::vftable;
  param_1[0x33] = aMap<class_aString,class_CLane*>::vftable;
  param_1[0x34] = 0;
  param_1[0x35] = 0x11;
  param_1[0x36] = 0;
  param_1[0x37] = 0;
  param_1[0x38] = 0;
  param_1[0x39] = 10;
  param_1[0x3a] = 0;
  param_1[0x3b] = 0;
  param_1[0x3c] = 0;
  param_1[0x3d] = aCollection<class_aString,class_CLane*>::vftable;
  param_1[0x3e] = aMap<class_aString,class_CLane*>::vftable;
  param_1[0x3f] = 0;
  param_1[0x40] = 0x11;
  param_1[0x41] = 0;
  param_1[0x42] = 0;
  param_1[0x43] = 0;
  param_1[0x44] = 10;
  param_1[0x45] = 0;
  param_1[0x46] = 0;
  param_1[0x47] = 0;
  local_4._0_1_ = 7;
  FUN_004199f0(param_1 + 0x48);
  local_4._0_1_ = 8;
  FUN_004010a0(param_1 + 0x82);
  local_4._0_1_ = 9;
  FUN_004010a0(param_1 + 0x85);
  local_4._0_1_ = 10;
  FUN_004010a0(param_1 + 0x88);
  local_4._0_1_ = 0xb;
  FUN_00405b70(param_1 + 0x8c);
  local_4._0_1_ = 0xc;
  FUN_004010a0(param_1 + 0x96);
  local_4 = CONCAT31(local_4._1_3_,0xd);
  FUN_004010a0(param_1 + 0x9b);
  param_1[0x93] = 0;
  *(undefined *)(param_1 + 0x94) = 0;
  *(undefined *)((int)param_1 + 0x251) = 0;
  param_1[0x9a] = 0;
  ExceptionList = local_c;
  return param_1;
}



void __thiscall FUN_004148f0(void *this,byte param_1)

{
  FUN_00414b60((void *)((int)this + -8),param_1);
  return;
}



void __fastcall FUN_00414900(undefined4 *param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c1d7;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = CSystem::vftable;
  param_1[1] = CSystem::vftable;
  param_1[2] = CSystem::vftable;
  local_4 = 0xd;
  FUN_00401170((void **)(param_1 + 0x9b));
  local_4._0_1_ = 0xc;
  FUN_00401170((void **)(param_1 + 0x96));
  local_4._0_1_ = 0xb;
  FUN_00405bf0(param_1 + 0x8c);
  local_4._0_1_ = 10;
  FUN_00401170((void **)(param_1 + 0x88));
  local_4._0_1_ = 9;
  FUN_00401170((void **)(param_1 + 0x85));
  local_4._0_1_ = 8;
  FUN_00401170((void **)(param_1 + 0x82));
  local_4._0_1_ = 7;
  FUN_00419a60(param_1 + 0x48);
  local_4._0_1_ = 6;
  FUN_00414550(param_1 + 0x3d);
  local_4._0_1_ = 5;
  FUN_00414550(param_1 + 0x32);
  FUN_00412c00(param_1 + 0x2f);
  local_4._0_1_ = 3;
  param_1[0x28] = aMap<int,class_CLane*>::vftable;
  FUN_0040c080((void **)(param_1 + 0x29));
  local_4._0_1_ = 2;
  param_1[0x21] = aMap<int,class_CLane*>::vftable;
  FUN_0040c080((void **)(param_1 + 0x22));
  local_4._0_1_ = 1;
  param_1[0x1a] = aMap<int,class_CLane*>::vftable;
  FUN_0040c080((void **)(param_1 + 0x1b));
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00402eb0(param_1 + 0x11);
  local_4 = 0xffffffff;
  FUN_00403340(param_1 + 2);
  ExceptionList = local_c;
  return;
}



void __thiscall FUN_00414a60(void *this,undefined4 param_1,undefined param_2)

{
  undefined in_stack_ffffffdc;
  undefined in_stack_ffffffe0;
  undefined in_stack_ffffffe4;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c208;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004010b0(&stack0xffffffdc,(void **)&param_2);
  FUN_004145c0((void *)((int)this + 200),in_stack_ffffffdc,in_stack_ffffffe0,in_stack_ffffffe4,
               param_1);
  local_4 = 0xffffffff;
  FUN_00401170((void **)&param_2);
  ExceptionList = local_c;
  return;
}



void __thiscall FUN_00414ae0(void *this,undefined4 param_1,undefined param_2)

{
  undefined in_stack_ffffffdc;
  undefined in_stack_ffffffe0;
  undefined in_stack_ffffffe4;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c208;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004010b0(&stack0xffffffdc,(void **)&param_2);
  FUN_004145c0((void *)((int)this + 0xf4),in_stack_ffffffdc,in_stack_ffffffe0,in_stack_ffffffe4,
               param_1);
  local_4 = 0xffffffff;
  FUN_00401170((void **)&param_2);
  ExceptionList = local_c;
  return;
}



undefined4 * __thiscall FUN_00414b60(void *this,byte param_1)

{
  FUN_00414900((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



int __fastcall FUN_00414b80(int param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041c246;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_004010a0((undefined4 *)(param_1 + 0xc));
  local_4 = 0;
  FUN_004010a0((undefined4 *)(param_1 + 0x18));
  local_4 = CONCAT31(local_4._1_3_,1);
  FUN_00402fc0(param_1 + 0x24);
  ExceptionList = local_c;
  return param_1;
}



void __fastcall FUN_00414be0(undefined4 *param_1)

{
  undefined4 *puVar1;
  int iVar2;
  
  iVar2 = param_1[1];
  while (iVar2 != 0) {
    puVar1 = (undefined4 *)param_1[1];
    param_1[1] = *puVar1;
    operator_delete(puVar1);
    iVar2 = param_1[1];
  }
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  return;
}



undefined4 * __thiscall FUN_00414c20(void *this,undefined4 *param_1)

{
  char *pcVar1;
  void *local_3c [3];
  void *local_30 [3];
  void *local_24 [3];
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041c2a9;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_004010a0(local_30);
  local_4 = 1;
  FUN_004010a0(local_18);
  local_4._0_1_ = 2;
  FUN_004010a0(local_3c);
  local_4._0_1_ = 3;
  FUN_004010a0(local_24);
  local_4 = CONCAT31(local_4._1_3_,4);
  if (*(int *)((int)this + 0x4c) == 0) {
    pcVar1 = "VEHICLE";
  }
  else {
    if (*(int *)((int)this + 0x4c) != 1) goto LAB_00414cac;
    pcVar1 = "DRIVER";
  }
  FUN_00401040(local_30,pcVar1);
LAB_00414cac:
  if ((*(byte *)((int)this + 0x44) & 1) != 0) {
    FUN_00401040(local_3c,"http");
  }
  if ((*(byte *)((int)this + 0x44) & 2) != 0) {
    FUN_00401240(local_3c," ftp");
  }
  if ((*(byte *)((int)this + 0x44) & 4) != 0) {
    FUN_00401240(local_3c," sftp");
  }
  FUN_004011f0(local_3c);
  FUN_004011f0(local_30);
  FUN_004011f0((undefined4 *)((int)this + 0x148));
  FUN_004018e0(param_1,"id:%d %s \'%s\' (%s ):");
  local_4._0_1_ = 3;
  FUN_00401170(local_24);
  local_4._0_1_ = 2;
  FUN_00401170(local_3c);
  local_4._0_1_ = 1;
  FUN_00401170(local_18);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170(local_30);
  ExceptionList = local_c;
  return param_1;
}



void __thiscall FUN_00414d70(void *this,int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  int *piVar4;
  
                    // WARNING: Load size is inaccurate
  if (*this != 0) {
    iVar2 = *(int *)(param_1 + 4);
    piVar4 = (int *)operator_new(0xc);
    piVar4[1] = iVar2;
    *piVar4 = param_1;
    piVar4[2] = param_2;
    if (*(int ***)(param_1 + 4) != (int **)0x0) {
      **(int ***)(param_1 + 4) = piVar4;
      *(int **)(param_1 + 4) = piVar4;
                    // WARNING: Load size is inaccurate
      *(int *)this = *this + 1;
      return;
    }
    *(int **)((int)this + 4) = piVar4;
    *(int **)(param_1 + 4) = piVar4;
                    // WARNING: Load size is inaccurate
    *(int *)this = *this + 1;
    return;
  }
  uVar1 = *(undefined4 *)((int)this + 4);
  puVar3 = (undefined4 *)operator_new(0xc);
  puVar3[1] = 0;
  *puVar3 = uVar1;
  puVar3[2] = param_2;
  if (*(int *)((int)this + 4) != 0) {
    *(undefined4 **)(*(int *)((int)this + 4) + 4) = puVar3;
                    // WARNING: Load size is inaccurate
    *(int *)this = *this + 1;
    *(undefined4 **)((int)this + 4) = puVar3;
    return;
  }
                    // WARNING: Load size is inaccurate
  *(int *)this = *this + 1;
  *(undefined4 **)((int)this + 8) = puVar3;
  *(undefined4 **)((int)this + 4) = puVar3;
  return;
}



void __thiscall FUN_00414e00(void *this,int *param_1)

{
  int **ppiVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  
  ppiVar1 = (int **)((int)this + 4);
  iVar4 = 0;
  if (*(int *)((int)this + 0xc) == 0) {
    param_1[1] = (int)ppiVar1;
    *param_1 = 0;
    return;
  }
  uVar2 = 0;
  if (*(uint *)((int)this + 8) != 0) {
    piVar3 = *ppiVar1;
    do {
      iVar4 = *piVar3;
      if (iVar4 != 0) break;
      uVar2 = uVar2 + 1;
      piVar3 = piVar3 + 1;
    } while (uVar2 < *(uint *)((int)this + 8));
  }
  param_1[1] = (int)ppiVar1;
  *param_1 = iVar4;
  return;
}



uint __thiscall FUN_00414e50(void *this,void *param_1)

{
  int *piVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  uint in_EAX;
  undefined4 *puVar5;
  uint uVar6;
  
                    // WARNING: Load size is inaccurate
  iVar2 = *this;
  if (iVar2 == 0) {
    return in_EAX & 0xffffff00;
  }
  uVar6 = ((uint)param_1 >> 4) % *(uint *)((int)this + 4);
  puVar4 = *(undefined4 **)(iVar2 + uVar6 * 4);
  puVar3 = (undefined4 *)(iVar2 + uVar6 * 4);
  while( true ) {
    puVar5 = puVar4;
    if (puVar5 == (undefined4 *)0x0) {
      return 0;
    }
    if ((void *)puVar5[2] == param_1) break;
    puVar4 = (undefined4 *)*puVar5;
    puVar3 = puVar5;
  }
  *puVar3 = *puVar5;
  *puVar5 = *(undefined4 *)((int)this + 0xc);
  piVar1 = (int *)((int)this + 8);
  *piVar1 = *piVar1 + -1;
  *(undefined4 **)((int)this + 0xc) = puVar5;
  if (*piVar1 == 0) {
    puVar5 = (undefined4 *)FUN_0040c080((void **)this);
  }
  return CONCAT31((int3)((uint)puVar5 >> 8),1);
}



undefined4 * __thiscall FUN_00414eb0(void *this,uint param_1)

{
  uint uVar1;
  void *_Dst;
  undefined4 *puVar2;
  uint uVar3;
  
  uVar1 = *(uint *)((int)this + 4);
  uVar3 = (param_1 >> 4) % uVar1;
                    // WARNING: Load size is inaccurate
  if (*this == 0) {
    _Dst = operator_new(-(uint)((int)((ulonglong)uVar1 * 4 >> 0x20) != 0) |
                        (uint)((ulonglong)uVar1 * 4));
    *(void **)this = _Dst;
    memset(_Dst,0,uVar1 * 4);
    *(uint *)((int)this + 4) = uVar1;
  }
  else {
    for (puVar2 = *(undefined4 **)(*this + uVar3 * 4); puVar2 != (undefined4 *)0x0;
        puVar2 = (undefined4 *)*puVar2) {
      if (puVar2[2] == param_1) goto LAB_00414f2b;
    }
  }
  puVar2 = (undefined4 *)FUN_00412c50((int)this);
  puVar2[1] = uVar3;
  puVar2[2] = param_1;
                    // WARNING: Load size is inaccurate
  *puVar2 = *(undefined4 *)(*this + uVar3 * 4);
                    // WARNING: Load size is inaccurate
  *(undefined4 **)(*this + uVar3 * 4) = puVar2;
LAB_00414f2b:
  return puVar2 + 3;
}



void __thiscall FUN_00414f40(void *this,void *param_1)

{
  char cVar1;
  undefined4 *puVar2;
  char *pcVar3;
  void **ppvVar4;
  void *pvVar5;
  undefined4 *_Dst;
  undefined4 uVar6;
  int iVar7;
  uint uVar8;
  tm *ptVar9;
  void **ppvVar10;
  undefined4 extraout_ECX;
  undefined4 *puVar11;
  int *piVar12;
  longlong lVar13;
  undefined8 uVar14;
  undefined in_stack_ffffff3c;
  undefined in_stack_ffffff40;
  undefined in_stack_ffffff44;
  undefined4 uVar15;
  undefined4 uVar16;
  undefined uVar17;
  undefined uVar18;
  undefined uVar19;
  undefined uVar20;
  int iVar21;
  int local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined *local_60;
  undefined4 local_5c;
  void *local_58;
  void *local_54;
  void *local_4c [3];
  void *local_40 [3];
  tm local_34;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041c303;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_004010a0(&local_58);
  local_4 = 0;
  cVar1 = FUN_00403410((int)this);
  if (cVar1 == '\0') {
    local_6c = 0;
    puVar2 = (undefined4 *)FUN_00408af0((void *)((int)this + 0x5c),&local_64);
    for (puVar2 = (undefined4 *)*puVar2; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2
        ) {
      iVar21 = puVar2[2];
      local_6c = local_6c + 1;
      pcVar3 = "avi";
      if (*(int *)((int)this + 0x48) < 1) {
        pcVar3 = "jpg";
      }
      FUN_00401100(&stack0xffffff68,pcVar3,(char *)0x7fffffff);
      ppvVar4 = FUN_00408850(param_1,local_4c,*(undefined4 *)((int)this + 0x40),iVar21,
                             *(int *)((int)this + 0x4c),'\0');
      local_4._0_1_ = 1;
      if (*ppvVar4 != local_58) {
        FUN_00401910(&local_58,(uint)ppvVar4[1]);
        memcpy(local_58,*ppvVar4,(size_t)ppvVar4[1]);
        local_54 = ppvVar4[1];
        *(undefined *)((int)local_54 + (int)local_58) = 0;
      }
      local_4._0_1_ = 0;
      FUN_00401170(local_4c);
      pvVar5 = operator_new(0x5c);
      local_4._0_1_ = 2;
      if (pvVar5 == (void *)0x0) {
        _Dst = (undefined4 *)0x0;
      }
      else {
        _Dst = (undefined4 *)FUN_00414b80((int)pvVar5);
      }
      local_4 = (uint)local_4._1_3_ << 8;
      memset(_Dst,0,0x5c);
      uVar6 = FUN_004087d0((int)param_1);
      *_Dst = uVar6;
      ppvVar4 = (void **)(_Dst + 3);
      if (local_58 != (void *)_Dst[3]) {
        FUN_00401910(ppvVar4,(uint)local_54);
        memcpy(*ppvVar4,local_58,(size_t)local_54);
        _Dst[4] = local_54;
        *(undefined *)((int)local_54 + (int)*ppvVar4) = 0;
      }
      iVar7 = FUN_00408810((int)param_1);
      uVar8 = FUN_00408800((int)param_1);
      lVar13 = __allmul(uVar8,(int)uVar8 >> 0x1f,1000000,0);
      lVar13 = lVar13 + iVar21 * 1000 + (longlong)iVar7;
      uVar14 = __alldvrm((uint)lVar13,(uint)((ulonglong)lVar13 >> 0x20),1000000,0);
      local_5c = (undefined4)((ulonglong)uVar14 >> 0x20);
      FUN_00408810((int)param_1);
      FUN_00408800((int)param_1);
      FUN_004011f0(&local_58);
      FUN_00402870("UnitREC %d TakePicture IMAGE \'%s\' carId:%d offset:%d time lpr:%d.%d > img:%d.%d"
                   ,(char)*(undefined4 *)((int)this + 0x40));
      _Dst[1] = (int)uVar14;
      _Dst[2] = extraout_ECX;
      _Dst[0x13] = iVar21;
      _Dst[0x16] = *(undefined4 *)((int)this + 0x48);
      ptVar9 = FUN_00403080(&local_34);
      piVar12 = _Dst + 9;
      for (iVar7 = 10; iVar7 != 0; iVar7 = iVar7 + -1) {
        *piVar12 = ptVar9->tm_sec;
        ptVar9 = (tm *)&ptVar9->tm_min;
        piVar12 = piVar12 + 1;
      }
      _Dst[0x14] = 0;
      if (*(int *)((int)this + 0x6c) != 0) {
        for (puVar11 = *(undefined4 **)
                        (*(int *)((int)this + 0x6c) +
                        (((uint)puVar2[2] >> 4) % *(uint *)((int)this + 0x70)) * 4);
            puVar11 != (undefined4 *)0x0; puVar11 = (undefined4 *)*puVar11) {
          if (puVar11[2] == puVar2[2]) goto LAB_004151d1;
        }
      }
      puVar11 = (undefined4 *)0x0;
LAB_004151d1:
      if ((this == (void *)0xffffff94) || (puVar11 == (undefined4 *)0x0)) {
        local_68 = 1000;
      }
      else {
        local_68 = puVar11[3];
      }
      pcVar3 = "avi";
      if (*(int *)((int)this + 0x48) < 1) {
        pcVar3 = "jpg";
      }
      local_60 = &stack0xffffff68;
      FUN_00401100(&stack0xffffff68,pcVar3,(char *)0x7fffffff);
      uVar6 = *(undefined4 *)((int)this + 0x40);
      uVar20 = 1;
      ppvVar4 = local_40;
      ppvVar10 = FUN_00408850(param_1,ppvVar4,uVar6,iVar21,*(int *)((int)this + 0x4c),'\x01');
      uVar18 = (undefined)uVar6;
      uVar17 = SUB41(ppvVar4,0);
      local_4._0_1_ = 3;
      if (*ppvVar10 != local_58) {
        FUN_00401910(&local_58,(uint)ppvVar10[1]);
        uVar20 = 0x69;
        memcpy(local_58,*ppvVar10,(size_t)ppvVar10[1]);
        local_54 = ppvVar10[1];
        *(undefined *)((int)local_54 + (int)local_58) = 0;
      }
      local_4._0_1_ = 0;
      FUN_00401170(local_40);
      local_60 = &stack0xffffff64;
      uVar19 = 0xa3;
      iVar21 = local_6c;
      FUN_004010b0(&stack0xffffff64,(void **)((int)this + 0x50));
      uVar6 = _Dst[1];
      local_4._0_1_ = 4;
      FUN_004010b0(&stack0xffffff54,&local_58);
      uVar16 = *(undefined4 *)((int)this + 0x134);
      uVar15 = *(undefined4 *)((int)this + 0x4c);
      local_4._0_1_ = 5;
      FUN_004010b0(&stack0xffffff3c,(void **)(_Dst + 3));
      local_4 = (uint)local_4._1_3_ << 8;
      FUN_0040a470(param_1,in_stack_ffffff3c,in_stack_ffffff40,in_stack_ffffff44,uVar15,uVar16,
                   local_68,uVar17,uVar18,uVar19,uVar6,uVar20,iVar21);
      FUN_0040aea0((void *)((int)this + 0x84),(int)_Dst,0,0);
    }
  }
  local_4 = 0xffffffff;
  FUN_00401170(&local_58);
  ExceptionList = local_c;
  return;
}



void __fastcall FUN_00415350(int param_1)

{
  FUN_0040aea0((void *)(param_1 + 0x84),0,0,0);
  return;
}



void __fastcall FUN_00415370(undefined4 *param_1)

{
  *param_1 = aMap<int,int>::vftable;
  FUN_0040c080((void **)(param_1 + 1));
  return;
}



void __fastcall FUN_00415380(undefined4 *param_1)

{
  *param_1 = aMap<int,struct_SRequestVideoInfo*>::vftable;
  FUN_0040c080((void **)(param_1 + 1));
  return;
}



undefined4 * __thiscall FUN_00415390(void *this,byte param_1)

{
  *(undefined ***)this = aMap<int,int>::vftable;
  FUN_0040c080((void **)((int)this + 4));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_004153c0(void *this,byte param_1)

{
  *(undefined ***)this = aMap<int,struct_SRequestVideoInfo*>::vftable;
  FUN_0040c080((void **)((int)this + 4));
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_004153f0(int *param_1)

{
  int *piVar1;
  void *pvVar2;
  void *pvVar3;
  void **ppvVar4;
  void **ppvVar5;
  void **ppvVar6;
  uint uVar7;
  uint uVar8;
  uint *puVar9;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041c32b;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_004033d0(param_1);
  FUN_00414be0(param_1 + 0x17);
  FUN_00402ed0((int)(param_1 + 0x56));
  if (0 < param_1[0x49]) {
    do {
      uVar7 = 0;
      uVar8 = uVar7;
      if ((param_1[0x49] != 0) && (uVar8 = 0, param_1[0x48] != 0)) {
        puVar9 = (uint *)param_1[0x47];
        do {
          uVar8 = *puVar9;
          if (uVar8 != 0) break;
          uVar7 = uVar7 + 1;
          puVar9 = puVar9 + 1;
        } while (uVar7 < (uint)param_1[0x48]);
      }
      pvVar2 = (void *)param_1[0x47];
      pvVar3 = *(void **)(uVar8 + 0xc);
      if (pvVar2 != (void *)0x0) {
        uVar7 = ((uint)*(void **)(uVar8 + 8) >> 4) % (uint)param_1[0x48];
        ppvVar6 = *(void ***)((int)pvVar2 + uVar7 * 4);
        ppvVar5 = (void **)((int)pvVar2 + uVar7 * 4);
        while (ppvVar4 = ppvVar6, ppvVar4 != (void **)0x0) {
          if (ppvVar4[2] == *(void **)(uVar8 + 8)) {
            *ppvVar5 = *ppvVar4;
            *ppvVar4 = (void *)param_1[0x4a];
            piVar1 = param_1 + 0x49;
            *piVar1 = *piVar1 + -1;
            param_1[0x4a] = (int)ppvVar4;
            if (*piVar1 == 0) {
              FUN_0040c080((void **)(param_1 + 0x47));
            }
            break;
          }
          ppvVar5 = ppvVar4;
          ppvVar6 = (void **)*ppvVar4;
        }
      }
      if (pvVar3 != (void *)0x0) {
        local_4 = 0;
        FUN_00401170((void **)((int)pvVar3 + 0x18));
        local_4 = 0xffffffff;
        FUN_00401170((void **)((int)pvVar3 + 0xc));
        operator_delete(pvVar3);
      }
    } while (0 < param_1[0x49]);
  }
  FUN_00402f10((int)(param_1 + 0x56));
  thunk_FUN_004033d0((int *)param_1[0x4e]);
  if ((undefined4 *)param_1[0x4e] != (undefined4 *)0x0) {
    (***(code ***)(undefined4 *)param_1[0x4e])(1);
  }
  ExceptionList = local_c;
  return;
}



void __fastcall FUN_00415540(int param_1,undefined param_2,undefined param_3)

{
  int iVar1;
  char cVar2;
  uint uVar3;
  undefined4 *puVar4;
  int iVar5;
  void **ppvVar6;
  bool bVar7;
  char *pcVar8;
  undefined uVar9;
  int *piVar10;
  void *local_21c [3];
  undefined local_210 [512];
  uint local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c379;
  local_c = ExceptionList;
  local_10 = DAT_00428400 ^ (uint)local_21c;
  ExceptionList = &local_c;
  local_4 = 0;
  cVar2 = FUN_00403410(param_1);
  if (cVar2 == '\0') {
    iVar1 = param_1 + 0x158;
    FUN_00402ed0(iVar1);
    uVar3 = FUN_004127e0((undefined4 *)&param_3);
    iVar5 = *(int *)(param_1 + 0x11c);
    if (iVar5 != 0) {
      for (puVar4 = *(undefined4 **)(iVar5 + ((uVar3 >> 4) % *(uint *)(param_1 + 0x120)) * 4);
          puVar4 != (undefined4 *)0x0; puVar4 = (undefined4 *)*puVar4) {
        if (puVar4[2] == uVar3) goto LAB_004155f5;
      }
    }
    puVar4 = (undefined4 *)0x0;
LAB_004155f5:
    if (((int *)(param_1 + 0x11c) == (int *)0x0) || (puVar4 == (undefined4 *)0x0)) {
      FUN_00402f10(iVar1);
      FUN_004127e0((undefined4 *)&param_3);
      FUN_00402890("UnitREC %d. HandleVideoAvailable not found videoId:%d",
                   (char)*(undefined4 *)(param_1 + 0x40));
    }
    else {
      piVar10 = (int *)puVar4[3];
      FUN_00414e50((void *)(param_1 + 0x11c),(void *)puVar4[2]);
      FUN_00402f10(iVar1);
      iVar1 = piVar10[0x16];
      bVar7 = iVar1 == 0;
      if (bVar7) {
        iVar1 = *piVar10;
        iVar5 = FUN_0040bbd0(*(int *)(param_1 + 0x3c));
        if (iVar5 < iVar1) {
          iVar1 = piVar10[0x16];
          bVar7 = iVar1 == 0;
          goto LAB_00415681;
        }
        uVar9 = (undefined)*(undefined4 *)(param_1 + 0x40);
        pcVar8 = 
        "UnitREC %d. HandleVideoAvailable. Obsolete IMAGE eventId:%d (duration:%d) (already closed)"
        ;
      }
      else {
LAB_00415681:
        if ((bVar7 || iVar1 < 0) ||
           (iVar1 = *piVar10, iVar5 = FUN_0040bbe0(*(int *)(param_1 + 0x3c)), iVar5 < iVar1)) {
          FUN_00412830(&param_3,local_210,0x200);
          uVar3 = *(uint *)(param_1 + 0x44);
          if ((uVar3 & 1) == 0) {
            if ((uVar3 & 2) == 0) {
              if ((uVar3 & 4) == 0) {
                FUN_0040acd0((int)piVar10);
                operator_delete(piVar10);
                FUN_00402890("OnVideoAvailable. Can\'t download file, unavailable unit protocols (ftp,sftp)"
                             ,(char)piVar10);
                goto LAB_0041580f;
              }
              FUN_004011f0((undefined4 *)(param_1 + 0x148));
              FUN_004011f0((undefined4 *)(param_1 + 0x13c));
              ppvVar6 = (void **)FUN_004018e0(local_21c,"sftp://admin:%s@%s%s");
              local_4._0_1_ = 3;
            }
            else {
              FUN_004011f0((undefined4 *)(param_1 + 0x148));
              FUN_004011f0((undefined4 *)(param_1 + 0x13c));
              ppvVar6 = (void **)FUN_004018e0(local_21c,"ftp://admin:%s@%s%s");
              local_4._0_1_ = 2;
            }
          }
          else {
            FUN_004011f0((undefined4 *)(param_1 + 0x148));
            FUN_004011f0((undefined4 *)(param_1 + 0x13c));
            ppvVar6 = (void **)FUN_004018e0(local_21c,"ftp://admin:%s@%s%s");
            local_4._0_1_ = 1;
          }
          FUN_00401000(piVar10 + 6,ppvVar6);
          local_4 = (uint)local_4._1_3_ << 8;
          FUN_00401170(local_21c);
          FUN_004011f0(piVar10 + 6);
          FUN_00412820((undefined4 *)&param_3);
          FUN_00412810((undefined4 *)&param_3);
          FUN_004127e0((undefined4 *)&param_3);
          FUN_00402870("UnitREC %d. HandleVideoAvailable videoId:%d  (%d.%d), forward to download \'%s\'"
                       ,(char)*(undefined4 *)(param_1 + 0x40));
          FUN_0040b0c0(*(void **)(param_1 + 0x138),(int)piVar10);
          local_4 = 0xffffffff;
          FUN_004127d0((int *)&param_3);
          goto LAB_00415828;
        }
        uVar9 = (undefined)*(undefined4 *)(param_1 + 0x40);
        pcVar8 = 
        "UnitREC %d. HandleVideoAvailable. Obsolete VIDEO eventId:%d (duration:%d) (already closed)"
        ;
      }
      FUN_00402890(pcVar8,uVar9);
      FUN_0040acd0((int)piVar10);
      operator_delete(piVar10);
    }
  }
  else {
    FUN_004127e0((undefined4 *)&param_3);
    FUN_00402890("UnitREC %d. HandleVideoAvailable, closing application, ignore videoId:%d",
                 (char)*(undefined4 *)(param_1 + 0x40));
  }
LAB_0041580f:
  local_4 = 0xffffffff;
  FUN_004127d0((int *)&param_3);
LAB_00415828:
  ExceptionList = local_c;
  ___security_check_cookie_4(local_10 ^ (uint)local_21c);
  return;
}



undefined4 * __fastcall FUN_00415860(undefined4 *param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041c411;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_004032d0(param_1);
  local_4 = 0;
  *param_1 = CUnitREC::vftable;
  FUN_004010a0(param_1 + 0x14);
  param_1[0x17] = 0;
  param_1[0x18] = 0;
  param_1[0x19] = 0;
  param_1[0x1a] = aMap<int,int>::vftable;
  param_1[0x1b] = 0;
  param_1[0x1c] = 0x11;
  param_1[0x1d] = 0;
  param_1[0x1e] = 0;
  param_1[0x1f] = 0;
  param_1[0x20] = 10;
  local_4._0_1_ = 3;
  FUN_0040b280(param_1 + 0x21,1,100,1);
  param_1[0x46] = aMap<int,struct_SRequestVideoInfo*>::vftable;
  param_1[0x47] = 0;
  param_1[0x48] = 0x11;
  param_1[0x49] = 0;
  param_1[0x4a] = 0;
  param_1[0x4b] = 0;
  param_1[0x4c] = 10;
  local_4._0_1_ = 5;
  FUN_004010a0(param_1 + 0x4f);
  local_4._0_1_ = 6;
  FUN_004010a0(param_1 + 0x52);
  local_4 = CONCAT31(local_4._1_3_,7);
  FUN_004118b0(param_1 + 0x55);
  FUN_00402e50(param_1 + 0x56);
  ExceptionList = local_c;
  return param_1;
}



void __fastcall FUN_00415970(undefined4 *param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c491;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = CUnitREC::vftable;
  local_4 = 7;
  FUN_00402eb0(param_1 + 0x56);
  local_4._0_1_ = 6;
  FUN_00401170((void **)(param_1 + 0x52));
  local_4._0_1_ = 5;
  FUN_00401170((void **)(param_1 + 0x4f));
  local_4._0_1_ = 4;
  param_1[0x46] = aMap<int,struct_SRequestVideoInfo*>::vftable;
  FUN_0040c080((void **)(param_1 + 0x47));
  local_4._0_1_ = 3;
  FUN_0040b370(param_1 + 0x21);
  local_4._0_1_ = 2;
  param_1[0x1a] = aMap<int,int>::vftable;
  FUN_0040c080((void **)(param_1 + 0x1b));
  FUN_00412c00(param_1 + 0x17);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170((void **)(param_1 + 0x14));
  local_4 = 0xffffffff;
  FUN_00403340(param_1);
  ExceptionList = local_c;
  return;
}



void __thiscall FUN_00415a50(void *this,undefined4 param_1,undefined4 param_2,undefined param_3)

{
  int *this_00;
  bool bVar1;
  undefined uVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  int iVar5;
  void **ppvVar6;
  void **ppvVar7;
  int **ppiVar8;
  int *piVar9;
  uint uVar10;
  void *pvVar11;
  int iVar12;
  int *piVar13;
  int *piVar14;
  char *pcVar15;
  void *local_f4;
  void *pvStack_f0;
  int *local_e8;
  int *piStack_e4;
  undefined4 *local_e0;
  char local_d9;
  int local_d8;
  void *local_d4 [3];
  void *apvStack_c8 [3];
  void *local_bc [3];
  undefined local_b0 [32];
  char local_90 [128];
  uint local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c51e;
  local_c = ExceptionList;
  local_10 = DAT_00428400 ^ (uint)&local_f4;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_00405070((int)local_b0,(void **)&param_3);
  local_4._0_1_ = 1;
  FUN_004118b0(&local_d8);
  FUN_004010a0(&local_f4);
  local_4._0_1_ = 2;
  FUN_004010a0(local_d4);
  local_4._0_1_ = 3;
  FUN_004010a0(local_bc);
  local_4._0_1_ = 4;
  *(undefined4 *)((int)this + 0x3c) = param_1;
  *(undefined4 *)((int)this + 0x40) = param_2;
  piVar13 = (int *)((int)this + 0x154);
  puVar3 = FUN_00412980(&local_e8,param_2);
  FUN_004118c0(piVar13,puVar3);
  FUN_00402870("UnitREC, initialize id:%d ...",(char)*(undefined4 *)((int)this + 0x40));
  bVar1 = FUN_00412880(piVar13);
  if (bVar1) {
    FUN_00402870("UnitREC, initialize id:%d Configuration login ...",
                 (char)*(undefined4 *)((int)this + 0x40));
    pcVar15 = "quercus2";
    puVar3 = FUN_004129e0(piVar13);
    bVar1 = FUN_00412860(puVar3,pcVar15);
    if (bVar1) {
      puVar3 = FUN_004129e0(piVar13);
      puVar3 = FUN_00412a20(puVar3);
      FUN_004118c0(&local_d8,puVar3);
      bVar1 = FUN_00412880(&local_d8);
      if (bVar1) {
        FUN_00412890(&local_d8,local_90,0x80);
      }
      else {
        local_d9 = '\0';
      }
    }
    else {
      local_d9 = '\0';
    }
    FUN_00402870("UnitREC, initialize id:%d Configuration login %s",
                 (char)*(undefined4 *)((int)this + 0x40));
    if (local_d9 == '\0') {
      uVar4 = FUN_00412740(piVar13);
      sprintf(local_90,"%d",uVar4);
      uVar2 = FUN_00412740(piVar13);
      FUN_00402890("Can\'t obtein lane serial number, set lane id \'%d\'",uVar2);
    }
    puVar3 = FUN_00412a00(piVar13);
    iVar5 = FUN_00412850(puVar3);
    *(int *)((int)this + 0x44) = iVar5;
    if (iVar5 < 0) {
      *(undefined4 *)((int)this + 0x44) = 2;
    }
    ppvVar6 = FUN_00401100(apvStack_c8,local_90,(char *)0x7fffffff);
    ppvVar7 = (void **)((int)this + 0x50);
    local_4._0_1_ = 5;
    if (*ppvVar6 != *(void **)((int)this + 0x50)) {
      FUN_00401910(ppvVar7,(uint)ppvVar6[1]);
      memcpy(*ppvVar7,*ppvVar6,(size_t)ppvVar6[1]);
      pvVar11 = ppvVar6[1];
      *(void **)((int)this + 0x54) = pvVar11;
      *(undefined *)((int)pvVar11 + (int)*ppvVar7) = 0;
    }
    local_4._0_1_ = 4;
    FUN_00401170(apvStack_c8);
    FUN_00412750(piVar13,local_90,0x80);
    FUN_00401040((void *)((int)this + 0x148),local_90);
    ppvVar7 = (void **)FUN_004018e0(apvStack_c8,"Rec%d/ImageType");
    local_4._0_1_ = 6;
    if (*ppvVar7 != local_f4) {
      FUN_00401910(&local_f4,(uint)ppvVar7[1]);
      memcpy(local_f4,*ppvVar7,(size_t)ppvVar7[1]);
      pvStack_f0 = ppvVar7[1];
      *(undefined *)((int)pvStack_f0 + (int)local_f4) = 0;
    }
    local_4._0_1_ = 4;
    FUN_00401170(apvStack_c8);
    uVar4 = FUN_00405440(local_b0,(int *)&local_f4,local_d4);
    if ((char)uVar4 == '\0') {
      FUN_004011f0(&local_f4);
      uVar2 = (undefined)*(undefined4 *)((int)this + 0x40);
      pcVar15 = "UnitREC %d: Missing configuration parameter (%s)";
    }
    else {
      ppvVar7 = FUN_00401390(local_d4,apvStack_c8);
      local_4._0_1_ = 7;
      FUN_00401000(local_d4,ppvVar7);
      local_4._0_1_ = 4;
      FUN_00401170(apvStack_c8);
      iVar5 = FUN_00401290(local_d4,(byte *)"VEHICLE");
      if (iVar5 == 0) {
        *(undefined4 *)((int)this + 0x4c) = 0;
LAB_00415dc0:
        *(undefined4 *)((int)this + 0x134) = 1;
        *(undefined4 *)((int)this + 0x48) = 0;
        puVar3 = FUN_00414eb0((void *)((int)this + 0x6c),0);
        *puVar3 = 1;
        ppiVar8 = (int **)FUN_00414e00((void *)((int)this + 0x68),(int *)apvStack_c8);
        piVar13 = *ppiVar8;
        piVar14 = ppiVar8[1];
        piStack_e4 = piVar14;
        do {
          local_e8 = piVar13;
          if ((piVar14 == (int *)0x0) || (piVar13 == (int *)0x0)) goto LAB_00415ecb;
          this_00 = (int *)((int)this + 0x5c);
          if (*(int *)((int)this + 0x5c) == 0) {
            iVar5 = piVar13[2];
            uVar4 = *(undefined4 *)((int)this + 100);
            puVar3 = (undefined4 *)operator_new(0xc);
            puVar3[1] = uVar4;
            *puVar3 = 0;
            puVar3[2] = iVar5;
            piVar14 = piStack_e4;
            if (*(undefined4 **)((int)this + 100) == (undefined4 *)0x0) {
              *this_00 = *this_00 + 1;
              *(undefined4 **)((int)this + 0x60) = puVar3;
              *(undefined4 **)((int)this + 100) = puVar3;
            }
            else {
              **(undefined4 **)((int)this + 100) = puVar3;
              *this_00 = *this_00 + 1;
              *(undefined4 **)((int)this + 100) = puVar3;
            }
          }
          else {
            ppiVar8 = (int **)FUN_00408af0(this_00,&local_e0);
            piVar9 = *ppiVar8;
            if (piVar9 != (int *)0x0) {
              do {
                if (piVar13[2] < piVar9[2]) {
                  FUN_00414d70(this_00,(int)piVar9,piVar13[2]);
                  local_e8 = piVar13;
                  goto LAB_00415e8c;
                }
                piVar9 = (int *)*piVar9;
              } while (piVar9 != (int *)0x0);
            }
            FUN_00408aa0(this_00,piVar13[2]);
            local_e8 = piVar13;
          }
LAB_00415e8c:
          piVar13 = (int *)*local_e8;
          if (piVar13 == (int *)0x0) {
            uVar10 = local_e8[1] + 1;
            if (uVar10 < (uint)piVar14[1]) {
              ppiVar8 = (int **)(*piVar14 + uVar10 * 4);
              do {
                piVar13 = *ppiVar8;
                if (piVar13 != (int *)0x0) break;
                uVar10 = uVar10 + 1;
                ppiVar8 = ppiVar8 + 1;
              } while (uVar10 < (uint)piVar14[1]);
            }
          }
        } while( true );
      }
      iVar5 = FUN_00401290(local_d4,(byte *)"DRIVER");
      if (iVar5 == 0) {
        *(undefined4 *)((int)this + 0x4c) = 1;
        goto LAB_00415dc0;
      }
      FUN_004011f0(&local_f4);
      uVar2 = (undefined)*(undefined4 *)((int)this + 0x40);
      pcVar15 = "UnitREC %d: Unknown type \'%s\' available Plate,Vehicle,Driver,Other";
    }
    FUN_004028b0(pcVar15,uVar2);
  }
  else {
    FUN_004028b0("UnitREC, not found unit with id %d",(char)*(undefined4 *)((int)this + 0x40));
  }
  goto LAB_0041600c;
LAB_00415ecb:
  ppvVar7 = apvStack_c8;
  pvVar11 = (void *)FUN_0040bbc0(*(int *)((int)this + 0x3c));
  ppvVar7 = (void **)FUN_00412aa0(pvVar11,ppvVar7);
  local_4._0_1_ = 8;
  FUN_00401000((void *)((int)this + 0x13c),ppvVar7);
  local_4._0_1_ = 4;
  FUN_00401170(apvStack_c8);
  local_e0 = (undefined4 *)operator_new(0xdc);
  local_4._0_1_ = 9;
  if (local_e0 == (undefined4 *)0x0) {
    puVar3 = (undefined4 *)0x0;
  }
  else {
    puVar3 = FUN_0040b500(local_e0);
  }
  iVar5 = *(int *)((int)this + 0x3c);
  local_4._0_1_ = 4;
  *(undefined4 **)((int)this + 0x138) = puVar3;
  iVar12 = FUN_0040bbc0(iVar5);
  uVar4 = FUN_00412a90(iVar12);
  uVar4 = FUN_0040ac90(*(void **)((int)this + 0x138),*(undefined4 *)((int)this + 0x40),uVar4,iVar5);
  if ((char)uVar4 != '\0') {
    FUN_00403360(this,'\x01',0xfffffffc,0);
    FUN_00402870("UnitREC, initialize id:%d complete",(char)*(undefined4 *)((int)this + 0x40));
    local_4._0_1_ = 3;
    FUN_00401170(local_bc);
    local_4._0_1_ = 2;
    FUN_00401170(local_d4);
    local_4._0_1_ = 1;
    FUN_00401170(&local_f4);
    local_4 = (uint)local_4._1_3_ << 8;
    FUN_00401f60((int)local_b0);
    local_4 = 0xffffffff;
    FUN_00401170((void **)&param_3);
    goto LAB_00416069;
  }
  FUN_004028b0("UnitREC %d: Can\'t initialize Downloader",(char)*(undefined4 *)((int)this + 0x40));
LAB_0041600c:
  local_4._0_1_ = 3;
  FUN_00401170(local_bc);
  local_4._0_1_ = 2;
  FUN_00401170(local_d4);
  local_4._0_1_ = 1;
  FUN_00401170(&local_f4);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401f60((int)local_b0);
  local_4 = 0xffffffff;
  FUN_00401170((void **)&param_3);
LAB_00416069:
  ExceptionList = local_c;
  ___security_check_cookie_4(local_10 ^ (uint)&local_f4);
  return;
}



// WARNING: Removing unreachable block (ram,0x00416288)
// WARNING: Removing unreachable block (ram,0x00416223)

void __fastcall FUN_004160a0(void *param_1)

{
  undefined4 *this;
  int *piVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  tm *ptVar5;
  int **ppiVar6;
  bool bVar7;
  longlong lVar8;
  longlong lVar9;
  int local_3c;
  int *local_38;
  undefined4 local_34;
  undefined4 local_30;
  tm local_28;
  
  FUN_004118b0(&local_34);
  FUN_00403420(param_1,1);
  cVar2 = FUN_00403410((int)param_1);
  do {
    if (cVar2 != '\0') {
      return;
    }
    FUN_0040afa0((void *)((int)param_1 + 0x84),(int *)&local_38,0xffffffff);
    piVar1 = local_38;
    if (local_38 != (int *)0x0) {
      iVar4 = local_38[0x16];
      bVar7 = iVar4 == 0;
      if (bVar7) {
        iVar4 = *local_38;
        iVar3 = FUN_0040bbd0(*(int *)((int)param_1 + 0x3c));
        if (iVar3 < iVar4) {
          iVar4 = piVar1[0x16];
          bVar7 = iVar4 == 0;
          goto LAB_00416127;
        }
        FUN_0040bbd0(*(int *)((int)param_1 + 0x3c));
        FUN_00402890("UnitREC %d  StartCapture request for vehicle (lastEvent:%d  currentEvent:%d offset:%d) IMAGE obsolete, delete request."
                     ,(char)*(undefined4 *)((int)param_1 + 0x40));
      }
      else {
LAB_00416127:
        if ((bVar7 || iVar4 < 0) ||
           (iVar4 = *piVar1, iVar3 = FUN_0040bbe0(*(int *)((int)param_1 + 0x3c)), iVar3 < iVar4)) {
          this = (undefined4 *)((int)param_1 + 0x154);
          iVar4 = FUN_00412770(this,*piVar1,piVar1[0x16],piVar1[1],piVar1[2],&local_3c);
          if (iVar4 == 1) {
            FUN_00402890("UnitREC %d StartCapture already recording. Stop previous video and start new"
                         ,(char)*(undefined4 *)((int)param_1 + 0x40));
            FUN_004127a0(this);
            iVar4 = FUN_00412770(this,*piVar1,piVar1[0x16],piVar1[1],piVar1[2],&local_3c);
          }
          if (iVar4 != 2) {
            FUN_00402870("UnitREC %d StartCapture carId:%d (offset:%d duration:%d) done (%s). Waiting receive videoId:%d"
                         ,(char)*(undefined4 *)((int)param_1 + 0x40));
            piVar1[0x15] = local_3c;
            FUN_00402ed0((int)param_1 + 0x158);
            ppiVar6 = (int **)FUN_00414eb0((void *)((int)param_1 + 0x11c),piVar1[0x15]);
            *ppiVar6 = piVar1;
            FUN_00402f10((int)param_1 + 0x158);
            goto LAB_004162fe;
          }
          FUN_00402890("UnitREC %d StartCapture carId:%d (offset:%d duration:%d) fails, retry in a moment"
                       ,(char)*(undefined4 *)((int)param_1 + 0x40));
          FUN_00406160(300);
          if (piVar1[0x13] < 1) {
            ptVar5 = FUN_00403080(&local_28);
            lVar8 = FUN_00403050(ptVar5);
            lVar9 = FUN_00403050((tm *)(piVar1 + 9));
            if (lVar9 + 5000 <= lVar8) goto LAB_0041628c;
          }
          else {
            ptVar5 = FUN_00403080(&local_28);
            lVar8 = FUN_00403050(ptVar5);
            local_30 = (undefined4)lVar8;
            lVar9 = FUN_00403050((tm *)(piVar1 + 9));
            if (CONCAT44((int)((ulonglong)lVar8 >> 0x20),local_30) <= lVar9 + piVar1[0x13] + 5000) {
LAB_0041628c:
              piVar1[0x14] = piVar1[0x14] + 1;
              FUN_0040aea0((void *)((int)param_1 + 0x84),(int)piVar1,0,0);
              goto LAB_004162fe;
            }
          }
          FUN_00402870("UnitREC %d StartCapture can\'t reach trigger for video event:%d offset:%d retry:%d. Request deleted."
                       ,(char)*(undefined4 *)((int)param_1 + 0x40));
        }
        else {
          FUN_0040bbe0(*(int *)((int)param_1 + 0x3c));
          FUN_00402890("UnitREC %d  StartCapture request for vehicle (lastEvent:%d  currentEvent:%d offset:%d) VIDEO obsolete, delete request."
                       ,(char)*(undefined4 *)((int)param_1 + 0x40));
        }
      }
      FUN_0040acd0((int)piVar1);
      operator_delete(piVar1);
    }
LAB_004162fe:
    cVar2 = FUN_00403410((int)param_1);
  } while( true );
}



undefined4 * __thiscall FUN_00416320(void *this,byte param_1)

{
  FUN_00415970((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __fastcall FUN_00416340(undefined4 *param_1)

{
  tm *ptVar1;
  int iVar2;
  int *piVar3;
  tm local_34;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041c563;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_004032d0(param_1);
  local_4 = 0;
  *param_1 = CWebServerConversation::vftable;
  FUN_00406170(param_1 + 0x12);
  local_4 = CONCAT31(local_4._1_3_,1);
  FUN_00402fc0(param_1 + 0x21);
  param_1[0x11] = 0;
  FUN_00406270((int)(param_1 + 0x12));
  param_1[0x1c] = 0xffffffff;
  param_1[0x1d] = 0xffffffff;
  param_1[0x1f] = 0;
  param_1[0xf] = 0;
  *(undefined *)(param_1 + 0x20) = 0;
  ptVar1 = FUN_00403080(&local_34);
  piVar3 = param_1 + 0x21;
  for (iVar2 = 10; iVar2 != 0; iVar2 = iVar2 + -1) {
    *piVar3 = ptVar1->tm_sec;
    ptVar1 = (tm *)&ptVar1->tm_min;
    piVar3 = piVar3 + 1;
  }
  param_1[0x1e] = 0xffffffff;
  param_1[0x2b] = 0;
  ExceptionList = local_c;
  return param_1;
}



void __fastcall FUN_00416400(undefined4 *param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041b478;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = CWebServerConversation::vftable;
  local_4 = 0;
  FUN_00406190(param_1 + 0x12);
  local_4 = 0xffffffff;
  FUN_00403340(param_1);
  ExceptionList = local_c;
  return;
}



undefined4 __fastcall FUN_00416460(int param_1)

{
  return *(undefined4 *)(param_1 + 0x78);
}



void __thiscall FUN_00416470(void *this,undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)((int)this + 0x84);
  for (iVar1 = 10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *param_1 = *puVar2;
    puVar2 = puVar2 + 1;
    param_1 = param_1 + 1;
  }
  return;
}



undefined __fastcall FUN_00416490(int param_1)

{
  return *(undefined *)(param_1 + 0x80);
}



void __thiscall FUN_004164a0(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 0x70) = param_1;
  return;
}



undefined4 __fastcall FUN_004164b0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x70);
}



undefined4 __fastcall FUN_004164c0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x74);
}



undefined4 __fastcall FUN_004164d0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x40);
}



undefined4 __fastcall FUN_004164e0(int param_1)

{
  return *(undefined4 *)(param_1 + 0xac);
}



void __thiscall FUN_004164f0(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 0xac) = param_1;
  return;
}



uint __thiscall
FUN_00416500(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  char cVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined unaff_SI;
  
  *(undefined4 *)((int)this + 0x40) = param_1;
  *(undefined4 *)((int)this + 0x44) = param_2;
  *(undefined4 *)((int)this + 0x3c) = param_3;
  *(undefined4 *)((int)this + 0x78) = param_4;
  *(undefined4 *)((int)this + 0xac) = 0;
  cVar1 = FUN_00403360(this,'\0',1,0);
  if (cVar1 == '\0') {
    uVar2 = FUN_004028b0("WebServerRequest can\'t start thread",unaff_SI);
    return uVar2 & 0xffffff00;
  }
  uVar3 = FUN_00402870("WebServerRequest %d initialized",(char)*(undefined4 *)((int)this + 0x78));
  return CONCAT31((int3)((uint)uVar3 >> 8),1);
}



void __fastcall FUN_00416570(int *param_1)

{
  FUN_004033d0(param_1);
  if (param_1[0x11] != 0) {
    FUN_004060c0(param_1[0x11]);
    if ((undefined4 *)param_1[0x11] != (undefined4 *)0x0) {
      (***(code ***)(undefined4 *)param_1[0x11])(1);
    }
    param_1[0x11] = 0;
  }
  return;
}



void __thiscall FUN_004165a0(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 0x7c) = param_1;
  FUN_004061b0((int *)((int)this + 0x48));
  return;
}



void ** __thiscall FUN_004165c0(void *this,void **param_1)

{
  void *pvVar1;
  int iVar2;
  void **ppvVar3;
  void *local_30 [3];
  void *local_24 [3];
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  uint local_4;
  
  puStack_8 = &LAB_0041c5b9;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004010a0(param_1);
  local_4 = 0;
  ppvVar3 = (void **)FUN_004018e0(local_30,"WSConv %d ");
  local_4 = 1;
  if (*ppvVar3 != *param_1) {
    FUN_00401910(param_1,(uint)ppvVar3[1]);
    memcpy(*param_1,*ppvVar3,(size_t)ppvVar3[1]);
    pvVar1 = ppvVar3[1];
    param_1[1] = pvVar1;
    *(undefined *)((int)pvVar1 + (int)*param_1) = 0;
  }
  local_4 = local_4 & 0xffffff00;
  FUN_00401170(local_30);
  iVar2 = *(int *)((int)this + 0xac);
  if (iVar2 == 0) {
    ppvVar3 = FUN_00401a20(local_18,param_1," WC_WEB_MANAGER");
    local_4 = 2;
    FUN_00401000(param_1,ppvVar3);
    ppvVar3 = local_18;
  }
  else if (iVar2 == 1) {
    ppvVar3 = FUN_00401a20(local_24,param_1," WC_LANE");
    local_4 = 3;
    FUN_00401000(param_1,ppvVar3);
    ppvVar3 = local_24;
  }
  else {
    if (iVar2 != 2) {
      ExceptionList = local_c;
      return param_1;
    }
    ppvVar3 = FUN_00401a20(local_30,param_1," WC_CAR_DATA");
    local_4 = 4;
    FUN_00401000(param_1,ppvVar3);
    ppvVar3 = local_30;
  }
  local_4 = local_4 & 0xffffff00;
  FUN_00401170(ppvVar3);
  ExceptionList = local_c;
  return param_1;
}



int __fastcall FUN_00416720(int param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041c617;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_004010a0((undefined4 *)(param_1 + 4));
  local_4 = 0;
  FUN_004010a0((undefined4 *)(param_1 + 0x10));
  local_4._0_1_ = 1;
  FUN_004010a0((undefined4 *)(param_1 + 0x1c));
  local_4._0_1_ = 2;
  FUN_004010a0((undefined4 *)(param_1 + 0x28));
  local_4._0_1_ = 3;
  FUN_004010a0((undefined4 *)(param_1 + 0x38));
  local_4 = CONCAT31(local_4._1_3_,4);
  FUN_004010a0((undefined4 *)(param_1 + 0x44));
  ExceptionList = local_c;
  return param_1;
}



void __fastcall FUN_004167b0(int param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c617;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 4;
  FUN_00401170((void **)(param_1 + 0x44));
  local_4._0_1_ = 3;
  FUN_00401170((void **)(param_1 + 0x38));
  local_4._0_1_ = 2;
  FUN_00401170((void **)(param_1 + 0x28));
  local_4._0_1_ = 1;
  FUN_00401170((void **)(param_1 + 0x1c));
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170((void **)(param_1 + 0x10));
  local_4 = 0xffffffff;
  FUN_00401170((void **)(param_1 + 4));
  ExceptionList = local_c;
  return;
}



undefined4 * __thiscall FUN_00416840(void *this,undefined4 *param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041c677;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *(undefined4 *)this = *param_1;
  FUN_004010b0((void *)((int)this + 4),(void **)(param_1 + 1));
  local_4 = 0;
  FUN_004010b0((void *)((int)this + 0x10),(void **)(param_1 + 4));
  local_4._0_1_ = 1;
  FUN_004010b0((void *)((int)this + 0x1c),(void **)(param_1 + 7));
  local_4._0_1_ = 2;
  FUN_004010b0((void *)((int)this + 0x28),(void **)(param_1 + 10));
  local_4._0_1_ = 3;
  *(undefined4 *)((int)this + 0x34) = param_1[0xd];
  FUN_004010b0((void *)((int)this + 0x38),(void **)(param_1 + 0xe));
  local_4 = CONCAT31(local_4._1_3_,4);
  FUN_004010b0((void *)((int)this + 0x44),(void **)(param_1 + 0x11));
  *(undefined *)((int)this + 0x50) = *(undefined *)(param_1 + 0x14);
  *(undefined *)((int)this + 0x51) = *(undefined *)((int)param_1 + 0x51);
  *(undefined *)((int)this + 0x52) = *(undefined *)((int)param_1 + 0x52);
  ExceptionList = local_c;
  return (undefined4 *)this;
}



void __thiscall FUN_00416910(void *this,char *param_1,char param_2)

{
  char cVar1;
  tm *ptVar2;
  undefined4 *puVar3;
  void **ppvVar4;
  int iVar5;
  int *piVar6;
  void *pvVar7;
  char *pcVar8;
  void *local_8c;
  void *local_88;
  void *local_80;
  void *local_7c;
  void *local_74 [3];
  void *local_68 [3];
  int local_5c [10];
  tm local_34;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c6eb;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_00402fc0(local_5c);
  FUN_004010a0(&local_8c);
  local_4._0_1_ = 1;
  FUN_004010a0(&local_80);
  local_4 = CONCAT31(local_4._1_3_,2);
  ptVar2 = FUN_00403080(&local_34);
  piVar6 = local_5c;
  for (iVar5 = 10; iVar5 != 0; iVar5 = iVar5 + -1) {
    *piVar6 = ptVar2->tm_sec;
    ptVar2 = (tm *)&ptVar2->tm_min;
    piVar6 = piVar6 + 1;
  }
  if (param_2 == '\0') {
    pcVar8 = "HTTP/1.0 500 Error\r\n";
  }
  else {
    pcVar8 = "HTTP/1.0 200 OK\r\n";
  }
  FUN_00401040(&local_8c,pcVar8);
  if (local_8c != local_80) {
    FUN_00401910(&local_80,(uint)local_88);
    memcpy(local_80,local_8c,(size_t)local_88);
    local_7c = local_88;
    *(undefined *)((int)local_88 + (int)local_80) = 0;
  }
  iVar5 = 500;
  pvVar7 = local_88;
  pcVar8 = FUN_004011f0(&local_8c);
  FUN_00406020(*(void **)((int)this + 0x44),pcVar8,(int)pvVar7,iVar5);
  FUN_00401040(&local_8c,"Cache-Control: no-cache\r\n");
  FUN_00401200(&local_80,&local_8c);
  iVar5 = 500;
  pvVar7 = local_88;
  pcVar8 = FUN_004011f0(&local_8c);
  FUN_00406020(*(void **)((int)this + 0x44),pcVar8,(int)pvVar7,iVar5);
  FUN_00401040(&local_8c,"Connection: close\r\n");
  FUN_00401200(&local_80,&local_8c);
  iVar5 = 500;
  pvVar7 = local_88;
  pcVar8 = FUN_004011f0(&local_8c);
  FUN_00406020(*(void **)((int)this + 0x44),pcVar8,(int)pvVar7,iVar5);
  puVar3 = (undefined4 *)FUN_00403140(local_68);
  local_4._0_1_ = 3;
  FUN_004011f0(puVar3);
  ppvVar4 = (void **)FUN_004018e0(local_74,"Date: %s\r\n");
  local_4._0_1_ = 4;
  if (*ppvVar4 != local_8c) {
    FUN_00401910(&local_8c,(uint)ppvVar4[1]);
    memcpy(local_8c,*ppvVar4,(size_t)ppvVar4[1]);
    local_88 = ppvVar4[1];
    *(undefined *)((int)local_88 + (int)local_8c) = 0;
  }
  local_4._0_1_ = 3;
  FUN_00401170(local_74);
  local_4._0_1_ = 2;
  FUN_00401170(local_68);
  FUN_00401200(&local_80,&local_8c);
  iVar5 = 500;
  pvVar7 = local_88;
  pcVar8 = FUN_004011f0(&local_8c);
  FUN_00406020(*(void **)((int)this + 0x44),pcVar8,(int)pvVar7,iVar5);
  puVar3 = (undefined4 *)FUN_00403140(local_74);
  local_4._0_1_ = 5;
  FUN_004011f0(puVar3);
  ppvVar4 = (void **)FUN_004018e0(local_68,"Last-Modified: %s\r\n");
  local_4._0_1_ = 6;
  if (*ppvVar4 != local_8c) {
    FUN_00401910(&local_8c,(uint)ppvVar4[1]);
    memcpy(local_8c,*ppvVar4,(size_t)ppvVar4[1]);
    local_88 = ppvVar4[1];
    *(undefined *)((int)local_88 + (int)local_8c) = 0;
  }
  local_4._0_1_ = 5;
  FUN_00401170(local_68);
  local_4._0_1_ = 2;
  FUN_00401170(local_74);
  FUN_00401200(&local_80,&local_8c);
  iVar5 = 500;
  pvVar7 = local_88;
  pcVar8 = FUN_004011f0(&local_8c);
  FUN_00406020(*(void **)((int)this + 0x44),pcVar8,(int)pvVar7,iVar5);
  FUN_00401040(&local_8c,"Server: Quercus Technologies WebServer\r\n");
  FUN_00401200(&local_80,&local_8c);
  iVar5 = 500;
  pvVar7 = local_88;
  pcVar8 = FUN_004011f0(&local_8c);
  FUN_00406020(*(void **)((int)this + 0x44),pcVar8,(int)pvVar7,iVar5);
  ppvVar4 = (void **)FUN_004018e0(local_68,"Content-Type: application/json\r\n");
  local_4._0_1_ = 7;
  if (*ppvVar4 != local_8c) {
    FUN_00401910(&local_8c,(uint)ppvVar4[1]);
    memcpy(local_8c,*ppvVar4,(size_t)ppvVar4[1]);
    local_88 = ppvVar4[1];
    *(undefined *)((int)local_88 + (int)local_8c) = 0;
  }
  local_4._0_1_ = 2;
  FUN_00401170(local_68);
  FUN_00401200(&local_80,&local_8c);
  iVar5 = 500;
  pvVar7 = local_88;
  pcVar8 = FUN_004011f0(&local_8c);
  FUN_00406020(*(void **)((int)this + 0x44),pcVar8,(int)pvVar7,iVar5);
  pcVar8 = param_1;
  do {
    cVar1 = *pcVar8;
    pcVar8 = pcVar8 + 1;
  } while (cVar1 != '\0');
  ppvVar4 = (void **)FUN_004018e0(local_68,"Content-Length: %d\r\n\r\n");
  local_4._0_1_ = 8;
  if (*ppvVar4 != local_8c) {
    FUN_00401910(&local_8c,(uint)ppvVar4[1]);
    memcpy(local_8c,*ppvVar4,(size_t)ppvVar4[1]);
    local_88 = ppvVar4[1];
    *(undefined *)((int)local_88 + (int)local_8c) = 0;
  }
  local_4._0_1_ = 2;
  FUN_00401170(local_68);
  FUN_00401200(&local_80,&local_8c);
  iVar5 = 500;
  pvVar7 = local_88;
  pcVar8 = FUN_004011f0(&local_8c);
  FUN_00406020(*(void **)((int)this + 0x44),pcVar8,(int)pvVar7,iVar5);
  FUN_00401200(&local_80,(void **)&stack0x0000000c);
  FUN_004011f0(&local_80);
  FUN_00402870("WebServerRequest %d SendMessage\n%s",(char)*(undefined4 *)((int)this + 0x78));
  pcVar8 = param_1;
  do {
    cVar1 = *pcVar8;
    pcVar8 = pcVar8 + 1;
  } while (cVar1 != '\0');
  FUN_00406020(*(void **)((int)this + 0x44),param_1,(int)pcVar8 - (int)(param_1 + 1),-1);
  local_4._0_1_ = 1;
  FUN_00401170(&local_80);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170(&local_8c);
  local_4 = 0xffffffff;
  FUN_00401170((void **)&stack0x0000000c);
  ExceptionList = local_c;
  return;
}



void ** FUN_00416e00(void **param_1,int param_2)

{
  void *pvVar1;
  bool bVar2;
  bool bVar3;
  void **ppvVar4;
  undefined4 in_stack_0000003c;
  char *pcVar5;
  void *local_3c [3];
  void *local_30 [3];
  void *local_24 [3];
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c761;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 1;
  FUN_004010a0(local_30);
  local_4._0_1_ = 2;
  FUN_004010a0(param_1);
  FUN_004010a0(local_3c);
  local_4._0_1_ = 3;
  FUN_004010a0(local_18);
  local_4._0_1_ = 4;
  FUN_00401040(param_1,"");
  if (param_2 == 1) {
    pcVar5 = "GET";
  }
  else if (param_2 == 2) {
    pcVar5 = "POST";
  }
  else {
    pcVar5 = "Unknown";
  }
  FUN_00401040(local_30,pcVar5);
  bVar2 = false;
  bVar3 = false;
  switch(in_stack_0000003c) {
  case 1:
    pcVar5 = "RST_VERSIONS";
    break;
  case 2:
    bVar2 = true;
    pcVar5 = "RST_RESOURCES";
    break;
  case 3:
    bVar2 = true;
    pcVar5 = "RST_LANES";
    break;
  case 4:
    bVar3 = true;
    bVar2 = true;
    pcVar5 = "RST_RECOGNITION";
    break;
  case 5:
    bVar3 = true;
    bVar2 = true;
    pcVar5 = "RST_CAMERAS";
    break;
  default:
    pcVar5 = "Unknown";
  }
  FUN_00401040(local_3c,pcVar5);
  FUN_004011f0(local_3c);
  FUN_004011f0((undefined4 *)&stack0x0000000c);
  FUN_004011f0((undefined4 *)&stack0x00000018);
  FUN_004011f0(local_30);
  ppvVar4 = (void **)FUN_004018e0(local_24,"%s %s %s - %s");
  local_4._0_1_ = 5;
  if (*ppvVar4 != *param_1) {
    FUN_00401910(param_1,(uint)ppvVar4[1]);
    memcpy(*param_1,*ppvVar4,(size_t)ppvVar4[1]);
    pvVar1 = ppvVar4[1];
    param_1[1] = pvVar1;
    *(undefined *)((int)pvVar1 + (int)*param_1) = 0;
  }
  local_4._0_1_ = 4;
  FUN_00401170(local_24);
  if (bVar2) {
    FUN_004011f0((undefined4 *)&stack0x00000040);
    FUN_004011f0(param_1);
    ppvVar4 = (void **)FUN_004018e0(local_24,"%s vId:%s");
    local_4._0_1_ = 6;
    if (*ppvVar4 != *param_1) {
      FUN_00401910(param_1,(uint)ppvVar4[1]);
      memcpy(*param_1,*ppvVar4,(size_t)ppvVar4[1]);
      pvVar1 = ppvVar4[1];
      param_1[1] = pvVar1;
      *(undefined *)((int)pvVar1 + (int)*param_1) = 0;
    }
    local_4._0_1_ = 4;
    FUN_00401170(local_24);
  }
  if (bVar3) {
    FUN_004011f0((undefined4 *)&stack0x0000004c);
    FUN_004011f0(param_1);
    ppvVar4 = (void **)FUN_004018e0(local_24,"%s lane:%s");
    local_4._0_1_ = 7;
    if (*ppvVar4 != *param_1) {
      FUN_00401910(param_1,(uint)ppvVar4[1]);
      memcpy(*param_1,*ppvVar4,(size_t)ppvVar4[1]);
      pvVar1 = ppvVar4[1];
      param_1[1] = pvVar1;
      *(undefined *)((int)pvVar1 + (int)*param_1) = 0;
    }
    local_4._0_1_ = 4;
    FUN_00401170(local_24);
  }
  local_4._0_1_ = 3;
  FUN_00401170(local_18);
  local_4._0_1_ = 2;
  FUN_00401170(local_3c);
  local_4._0_1_ = 1;
  FUN_00401170(local_30);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_004167b0((int)&param_2);
  ExceptionList = local_c;
  return param_1;
}



undefined4 * __thiscall FUN_004170d0(void *this,byte param_1)

{
  FUN_00416400((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



uint FUN_004170f0(undefined4 param_1,int param_2,undefined4 param_3,int *param_4)

{
  int *piVar1;
  undefined4 uVar2;
  char **ppcVar3;
  int iVar4;
  void **ppvVar5;
  uint uVar6;
  int in_ECX;
  int in_stack_fffffea8;
  char *pcVar7;
  undefined uVar8;
  char *local_f0;
  int local_ec;
  void *local_e4 [3];
  void *local_d8 [3];
  char *local_cc [3];
  int *local_c0;
  char *local_bc [8];
  char *local_9c [8];
  char *local_7c [8];
  char *local_5c [3];
  char *local_50 [8];
  void *local_30 [3];
  void *local_24 [3];
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c872;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004010a0(local_e4);
  local_4._0_1_ = 1;
  FUN_004010a0(&local_f0);
  local_4._0_1_ = 2;
  FUN_004010a0(local_d8);
  local_4._0_1_ = 3;
  if (param_2 != 0) {
    FUN_00401100(local_18,"\t\r\n",(char *)0x7fffffff);
    local_4._0_1_ = 4;
    FUN_00404340(local_7c,(void **)&param_1);
    local_4._0_1_ = 6;
    FUN_00401170(local_18);
    uVar2 = FUN_004043f0(local_7c);
    if ((char)uVar2 != '\0') {
      ppcVar3 = FUN_00404520(local_7c,local_cc);
      local_4._0_1_ = 7;
      FUN_00401000(local_e4,ppcVar3);
      local_4 = CONCAT31(local_4._1_3_,6);
      FUN_00401170(local_cc);
      iVar4 = FUN_004015f0(local_e4,"GET");
      if (iVar4 < 0) {
        iVar4 = FUN_004015f0(local_e4,"POST");
        if (-1 < iVar4) {
          *param_4 = 2;
          goto LAB_004172be;
        }
        *param_4 = 0;
        FUN_004011f0(local_e4);
        FUN_004028b0("WebServerRequest %d Can\'t identify message, unknonw/unsupported (1) Http request \'%s\'"
                     ,(char)*(undefined4 *)(in_ECX + 0x78));
      }
      else {
        *param_4 = 1;
LAB_004172be:
        piVar1 = param_4;
        FUN_00401100(local_24," ",(char *)0x7fffffff);
        local_4._0_1_ = 8;
        FUN_00404340(local_9c,local_e4);
        local_4._0_1_ = 10;
        FUN_00401170(local_24);
        uVar2 = FUN_004043f0(local_9c);
        if ((char)uVar2 == '\0') {
          *piVar1 = 0;
          FUN_004011f0(local_e4);
          uVar8 = (undefined)*(undefined4 *)(in_ECX + 0x78);
          pcVar7 = 
          "WebServerRequest %d Can\'t identify message, unknonw/unsupported (2) Http request \'%s\'"
          ;
        }
        else {
          FUN_00404520(local_9c,local_cc);
          FUN_00401170(local_cc);
          uVar2 = FUN_004043f0(local_9c);
          if ((char)uVar2 == '\0') {
            *piVar1 = 0;
            FUN_004011f0(local_e4);
            uVar8 = (undefined)*(undefined4 *)(in_ECX + 0x78);
            pcVar7 = 
            "WebServerRequest %d Can\'t identify message, unknonw/unsupported (3) Http request \'%s\'"
            ;
          }
          else {
            ppcVar3 = FUN_00404520(local_9c,local_cc);
            local_4._0_1_ = 0xb;
            FUN_00401000(piVar1 + 4,ppcVar3);
            local_4._0_1_ = 10;
            FUN_00401170(local_cc);
            if (piVar1[5] == 0) {
              FUN_004011f0(local_e4);
              uVar8 = (undefined)*(undefined4 *)(in_ECX + 0x78);
              pcVar7 = 
              "WebServerRequest %d Can\'t identify message, not found http path value on \'%s\'";
            }
            else {
              uVar2 = FUN_004043f0(local_9c);
              if ((char)uVar2 == '\0') {
                *piVar1 = 0;
                FUN_004011f0(local_e4);
                uVar8 = (undefined)*(undefined4 *)(in_ECX + 0x78);
                pcVar7 = 
                "WebServerRequest %d Can\'t identify message, unknonw/unsupported (4) Http request \'%s\'"
                ;
              }
              else {
                ppcVar3 = FUN_00404520(local_9c,local_cc);
                local_4._0_1_ = 0xc;
                FUN_00401000(piVar1 + 1,ppcVar3);
                local_4._0_1_ = 10;
                FUN_00401170(local_cc);
                if (piVar1[2] != 0) {
                  FUN_00401100(local_30,"/",(char *)0x7fffffff);
                  local_4._0_1_ = 0xd;
                  FUN_00404340(local_bc,(void **)(piVar1 + 4));
                  local_4._0_1_ = 0xf;
                  FUN_00401170(local_30);
                  uVar2 = FUN_004043f0(local_bc);
                  if ((char)uVar2 == '\0') {
                    *piVar1 = 0;
                    FUN_004011f0(local_e4);
                    uVar8 = (undefined)*(undefined4 *)(in_ECX + 0x78);
                    pcVar7 = 
                    "WebServerRequest %d Can\'t identify message, unknonw/unsupported (5) Http request \'%s\'"
                    ;
                    goto LAB_004174ab;
                  }
                  ppcVar3 = FUN_00404520(local_bc,local_cc);
                  local_4._0_1_ = 0x10;
                  FUN_00401000(&local_f0,ppcVar3);
                  local_4._0_1_ = 0xf;
                  FUN_00401170(local_cc);
                  iVar4 = FUN_004015f0(&local_f0,"lpr");
                  if (iVar4 == -1) {
                    local_c0 = (int *)&stack0xfffffea8;
                    FUN_00416840(&stack0xfffffea8,piVar1);
                    ppvVar5 = FUN_00416e00(local_cc,in_stack_fffffea8);
                    local_4._0_1_ = 0x11;
                    FUN_004011f0(ppvVar5);
                    FUN_004011f0(local_e4);
                    FUN_004028b0("WebServerRequest %d Can\'t identify message, not found field \'lpr\' on request resource (%s) \'%s\'"
                                 ,(char)*(undefined4 *)(in_ECX + 0x78));
                    local_4._0_1_ = 0xf;
                    FUN_00401170(local_cc);
                    local_4._0_1_ = 10;
                    FUN_0040bc30(local_bc);
                    local_4 = CONCAT31(local_4._1_3_,6);
                    FUN_0040bc30(local_9c);
                    goto LAB_00417b44;
                  }
                  uVar2 = FUN_004043f0(local_bc);
                  if ((char)uVar2 == '\0') {
                    piVar1[0xd] = 1;
LAB_004175c1:
                    local_4._0_1_ = 10;
                    FUN_0040bc30(local_bc);
                    local_4._0_1_ = 6;
                    FUN_0040bc30(local_9c);
                    local_4._0_1_ = 3;
                    FUN_0040bc30(local_7c);
                    local_4._0_1_ = 2;
                    FUN_00401170(local_d8);
                    local_4._0_1_ = 1;
                    FUN_00401170(&local_f0);
                    local_4 = (uint)local_4._1_3_ << 8;
                    FUN_00401170(local_e4);
                    local_4 = 0xffffffff;
                    uVar2 = FUN_00401170((void **)&param_1);
                    ExceptionList = local_c;
                    return CONCAT31((int3)((uint)uVar2 >> 8),1);
                  }
                  ppcVar3 = FUN_00404520(local_bc,local_cc);
                  local_c0 = piVar1 + 0xe;
                  local_4._0_1_ = 0x12;
                  FUN_00401000(local_c0,ppcVar3);
                  local_4._0_1_ = 0xf;
                  FUN_00401170(local_cc);
                  iVar4 = FUN_004015f0(local_c0,"v");
                  if (iVar4 == -1) {
                    FUN_004011f0(local_e4);
                    FUN_004011f0(local_c0);
                    uVar8 = (undefined)*(undefined4 *)(in_ECX + 0x78);
                    pcVar7 = 
                    "WebServerRequest %d Can\'t identify message, invalid field version \'%s\' on request resource \'%s\'"
                    ;
LAB_0041769e:
                    FUN_004028b0(pcVar7,uVar8);
                    local_4._0_1_ = 10;
                    FUN_0040bc30(local_bc);
                    local_4 = CONCAT31(local_4._1_3_,6);
                    FUN_0040bc30(local_9c);
                    goto LAB_00417b44;
                  }
                  uVar2 = FUN_004043f0(local_bc);
                  if ((char)uVar2 == '\0') {
                    piVar1[0xd] = 2;
                    goto LAB_004175c1;
                  }
                  ppcVar3 = FUN_00404520(local_bc,local_cc);
                  local_4._0_1_ = 0x13;
                  FUN_00401000(&local_f0,ppcVar3);
                  local_4._0_1_ = 0xf;
                  FUN_00401170(local_cc);
                  iVar4 = FUN_004015f0(&local_f0,"lanes");
                  if (iVar4 == -1) {
                    if (local_ec != 0) {
                      FUN_004011f0(local_e4);
                      FUN_004011f0(&local_f0);
                      uVar8 = (undefined)*(undefined4 *)(in_ECX + 0x78);
                      pcVar7 = 
                      "WebServerRequest %d Can\'t identidy message, unsupported command \'%s\', on request resource \'%s\'"
                      ;
                      goto LAB_0041769e;
                    }
                    FUN_004011f0(local_e4);
                    uVar8 = (undefined)*(undefined4 *)(in_ECX + 0x78);
                    pcVar7 = 
                    "WebServerRequest %d Can\'t identify message, not found field \'lanes\' on request resource \'%s\'"
                    ;
LAB_004174ab:
                    FUN_004028b0(pcVar7,uVar8);
                  }
                  else {
                    uVar2 = FUN_004043f0(local_bc);
                    if ((char)uVar2 == '\0') {
                      piVar1[0xd] = 3;
                      goto LAB_004175c1;
                    }
                    if (*piVar1 == 2) {
                      ppcVar3 = FUN_00404520(local_bc,local_cc);
                      local_4._0_1_ = 0x14;
                      FUN_00401000(&local_f0,ppcVar3);
                      local_4._0_1_ = 0xf;
                      FUN_00401170(local_cc);
                      FUN_00401100(local_cc,"?",(char *)0x7fffffff);
                      local_4._0_1_ = 0x15;
                      FUN_00404340(local_50,&local_f0);
                      local_4._0_1_ = 0x17;
                      FUN_00401170(local_cc);
                      uVar2 = FUN_004043f0(local_50);
                      if ((char)uVar2 == '\0') {
                        *piVar1 = 0;
                        FUN_004011f0(local_e4);
                        uVar8 = (undefined)*(undefined4 *)(in_ECX + 0x78);
                        pcVar7 = 
                        "WebServerRequest %d Can\'t identify message, unknonw/unsupported (6) Http request \'%s\'"
                        ;
                      }
                      else {
                        ppcVar3 = FUN_00404520(local_50,local_5c);
                        local_4._0_1_ = 0x18;
                        FUN_00401000(&local_f0,ppcVar3);
                        local_4._0_1_ = 0x17;
                        FUN_00401170(local_5c);
                        iVar4 = FUN_00401180(&local_f0);
                        if ((char)iVar4 == '\0') {
                          FUN_004011f0(local_e4);
                          FUN_004011f0(&local_f0);
                          FUN_004028b0("WebServerRequest %d Can\'t identidy message, lane id \'%s\' isn\'t numeric value, on request resource \'%s\'"
                                       ,(char)*(undefined4 *)(in_ECX + 0x78));
                          local_4._0_1_ = 0xf;
                          FUN_0040bc30(local_50);
                          goto LAB_004174b3;
                        }
                        FUN_00401000(piVar1 + 0x11,&local_f0);
                        *(undefined *)((int)piVar1 + 0x52) = 1;
                        *(undefined *)(piVar1 + 0x14) = 1;
                        *(undefined *)((int)piVar1 + 0x51) = 1;
                        uVar2 = FUN_004043f0(local_50);
                        if ((char)uVar2 != '\0') {
                          ppcVar3 = FUN_00404520(local_50,local_5c);
                          local_4._0_1_ = 0x19;
                          FUN_00401000(&local_f0,ppcVar3);
                          local_4._0_1_ = 0x17;
                          FUN_00401170(local_5c);
                          if (local_ec != 0) {
                            ppvVar5 = FUN_00401440(&local_f0,local_5c);
                            local_4._0_1_ = 0x1a;
                            FUN_00401000(&local_f0,ppvVar5);
                            local_4._0_1_ = 0x17;
                            FUN_00401170(local_5c);
                            iVar4 = FUN_004015f0(&local_f0,"lp=no");
                            if (-1 < iVar4) {
                              *(undefined *)(piVar1 + 0x14) = 0;
                            }
                            iVar4 = FUN_004015f0(&local_f0,"vehicle=no");
                            if (-1 < iVar4) {
                              *(undefined *)((int)piVar1 + 0x51) = 0;
                            }
                            iVar4 = FUN_004015f0(&local_f0,"driver=no");
                            if (-1 < iVar4) {
                              *(undefined *)((int)piVar1 + 0x52) = 0;
                            }
                          }
                          piVar1[0xd] = 4;
                          local_4._0_1_ = 0xf;
                          FUN_0040bc30(local_50);
                          goto LAB_004175c1;
                        }
                        *piVar1 = 0;
                        FUN_004011f0(local_e4);
                        uVar8 = (undefined)*(undefined4 *)(in_ECX + 0x78);
                        pcVar7 = 
                        "WebServerRequest %d Can\'t identify message, unknonw/unsupported (7) Http request \'%s\'"
                        ;
                      }
                      FUN_004028b0(pcVar7,uVar8);
                      local_4._0_1_ = 0xf;
                      FUN_0040bc30(local_50);
                    }
                    else {
                      ppcVar3 = FUN_00404520(local_bc,local_5c);
                      local_4._0_1_ = 0x1b;
                      FUN_00401000(&local_f0,ppcVar3);
                      local_4._0_1_ = 0xf;
                      FUN_00401170(local_5c);
                      iVar4 = FUN_00401180(&local_f0);
                      if ((char)iVar4 != '\0') {
                        FUN_00401000(piVar1 + 0x11,&local_f0);
                        uVar2 = FUN_004043f0(local_bc);
                        if ((char)uVar2 == '\0') {
                          FUN_004011f0(local_e4);
                          uVar8 = (undefined)*(undefined4 *)(in_ECX + 0x78);
                          pcVar7 = 
                          "WebServerRequest %d Can\'t identify message, unknonw/unsupported (8) Http request \'%s\'"
                          ;
                        }
                        else {
                          ppcVar3 = FUN_00404520(local_bc,local_5c);
                          local_4._0_1_ = 0x1c;
                          FUN_00401000(&local_f0,ppcVar3);
                          local_4._0_1_ = 0xf;
                          FUN_00401170(local_5c);
                          iVar4 = FUN_004015f0(&local_f0,"cameras");
                          if (iVar4 == -1) {
                            FUN_004011f0(local_e4);
                            uVar8 = (undefined)*(undefined4 *)(in_ECX + 0x78);
                            pcVar7 = 
                            "WebServerRequest %d Can\'t identify message, not found field \'cameras\' on request resource \'%s\'"
                            ;
                          }
                          else {
                            uVar2 = FUN_004043f0(local_bc);
                            if ((char)uVar2 == '\0') {
                              piVar1[0xd] = 5;
                              goto LAB_004175c1;
                            }
                            FUN_004011f0(local_e4);
                            uVar8 = (undefined)*(undefined4 *)(in_ECX + 0x78);
                            pcVar7 = "WebConv %d Can\'t identify message \'%s\'";
                          }
                        }
                        goto LAB_004174ab;
                      }
                      FUN_004011f0(local_e4);
                      FUN_004011f0(&local_f0);
                      FUN_004028b0("WebServerRequest %d Can\'t identidy message, lane id \'%s\' isn\'t numeric value, on request resource \'%s\'"
                                   ,(char)*(undefined4 *)(in_ECX + 0x78));
                    }
                  }
LAB_004174b3:
                  local_4._0_1_ = 10;
                  FUN_0040bc30(local_bc);
                  local_4 = CONCAT31(local_4._1_3_,6);
                  FUN_0040bc30(local_9c);
                  goto LAB_00417b44;
                }
                FUN_004011f0(local_e4);
                uVar8 = (undefined)*(undefined4 *)(in_ECX + 0x78);
                pcVar7 = 
                "WebServerRequest %d Can\'t identify message, not found http version value on \'%s\'"
                ;
              }
            }
          }
        }
        FUN_004028b0(pcVar7,uVar8);
        local_4 = CONCAT31(local_4._1_3_,6);
        FUN_0040bc30(local_9c);
      }
LAB_00417b44:
      local_4._0_1_ = 3;
      FUN_0040bc30(local_7c);
      local_4._0_1_ = 2;
      FUN_00401170(local_d8);
      local_4._0_1_ = 1;
      FUN_00401170(&local_f0);
      local_4 = (uint)local_4._1_3_ << 8;
      FUN_00401170(local_e4);
      goto LAB_00417b91;
    }
    *param_4 = 0;
    FUN_004011f0(&param_1);
    FUN_004028b0("WebServerRequest %d Can\'t identify message, unknonw/unsupported (0) Http request \'%s\'"
                 ,(char)*(undefined4 *)(in_ECX + 0x78));
    local_4._0_1_ = 3;
    FUN_0040bc30(local_7c);
  }
  local_4._0_1_ = 2;
  FUN_00401170(local_d8);
  local_4._0_1_ = 1;
  FUN_00401170(&local_f0);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170(local_e4);
LAB_00417b91:
  local_4 = 0xffffffff;
  uVar6 = FUN_00401170((void **)&param_1);
  ExceptionList = local_c;
  return uVar6 & 0xffffff00;
}



void __fastcall FUN_00417bc0(void *param_1,undefined param_2,undefined param_3)

{
  byte bVar1;
  void **ppvVar2;
  char *pcVar3;
  char cVar4;
  void *local_30;
  void *local_2c;
  void *local_24 [3];
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c8c8;
  local_c = ExceptionList;
  bVar1 = (byte)DAT_00428400 ^ (byte)&stack0xffffffc4;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004010a0(&local_30);
  local_4._0_1_ = 1;
  if (*(int *)((int)param_1 + 0x3c) == 1) {
    FUN_004011f0((undefined4 *)&DAT_0042b1d8);
    ppvVar2 = (void **)FUN_004018e0(local_18,"{\"version\":[\"%s\"]}");
    local_4 = CONCAT31(local_4._1_3_,2);
    if (*ppvVar2 != local_30) {
      FUN_00401910(&local_30,(uint)ppvVar2[1]);
      memcpy(local_30,*ppvVar2,(size_t)ppvVar2[1]);
      local_2c = ppvVar2[1];
      *(undefined *)((int)local_2c + (int)local_30) = 0;
    }
    ppvVar2 = local_18;
  }
  else {
    if (*(int *)((int)param_1 + 0x3c) != 2) {
      FUN_004028b0("WebServerRequest HandleVersionMsg UNDEFINED INI FILE \'JSON_VERSION\'",bVar1);
      goto LAB_00417d2d;
    }
    FUN_004011f0((undefined4 *)&DAT_0042b1d8);
    ppvVar2 = (void **)FUN_004018e0(local_24,
                                    "{\"lpr:versions\":{\"-xmlns:lpr\":\"http://3rdparty.com/lpr\",\"version\":[\"%s\"]}}"
                                   );
    local_4 = CONCAT31(local_4._1_3_,3);
    if (*ppvVar2 != local_30) {
      FUN_00401910(&local_30,(uint)ppvVar2[1]);
      memcpy(local_30,*ppvVar2,(size_t)ppvVar2[1]);
      local_2c = ppvVar2[1];
      *(undefined *)((int)local_2c + (int)local_30) = 0;
    }
    ppvVar2 = local_24;
  }
  local_4._0_1_ = 1;
  FUN_00401170(ppvVar2);
  FUN_004011f0(&local_30);
  FUN_00402870("WebServerRequest %d HandleVersionMsg send \'%s\'",
               (char)*(undefined4 *)((int)param_1 + 0x78));
  FUN_004010b0(&stack0xffffffb4,&local_30);
  cVar4 = '\x01';
  local_4._0_1_ = 4;
  pcVar3 = FUN_004011f0(&local_30);
  local_4._0_1_ = 1;
  FUN_00416910(param_1,pcVar3,cVar4);
LAB_00417d2d:
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170(&local_30);
  local_4 = 0xffffffff;
  FUN_004167b0((int)&param_3);
  ExceptionList = local_c;
  return;
}



void __fastcall FUN_00417d60(void *param_1,undefined param_2,undefined param_3)

{
  void **ppvVar1;
  char *pcVar2;
  char cVar3;
  void *local_30;
  void *local_2c;
  void *local_24 [3];
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c8c8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004010a0(&local_30);
  local_4._0_1_ = 1;
  if (*(int *)((int)param_1 + 0x3c) == 1) {
    ppvVar1 = (void **)FUN_004018e0(local_18,"{\"resource\":[\"lanes\"]}");
    local_4 = CONCAT31(local_4._1_3_,2);
    if (*ppvVar1 != local_30) {
      FUN_00401910(&local_30,(uint)ppvVar1[1]);
      memcpy(local_30,*ppvVar1,(size_t)ppvVar1[1]);
      local_2c = ppvVar1[1];
      *(undefined *)((int)local_2c + (int)local_30) = 0;
    }
    ppvVar1 = local_18;
  }
  else {
    if (*(int *)((int)param_1 + 0x3c) != 2) {
      FUN_004028b0("WebServerRequest %d HandleResourcesMsg UNDEFINED INI FILE \'JSON_VERSION\'",
                   (char)*(undefined4 *)((int)param_1 + 0x78));
      goto LAB_00417ebb;
    }
    ppvVar1 = (void **)FUN_004018e0(local_24,
                                    "{\"lpr:resources\":{\"-xmlns:lpr\":\"http://3rdparty.com/lpr\",\"resource\":[\"lanes\"]}}"
                                   );
    local_4 = CONCAT31(local_4._1_3_,3);
    if (*ppvVar1 != local_30) {
      FUN_00401910(&local_30,(uint)ppvVar1[1]);
      memcpy(local_30,*ppvVar1,(size_t)ppvVar1[1]);
      local_2c = ppvVar1[1];
      *(undefined *)((int)local_2c + (int)local_30) = 0;
    }
    ppvVar1 = local_24;
  }
  local_4._0_1_ = 1;
  FUN_00401170(ppvVar1);
  FUN_004011f0(&local_30);
  FUN_00402870("WebServerRequest %d HandleResourcesMsg send \'%s\'",
               (char)*(undefined4 *)((int)param_1 + 0x78));
  FUN_004010b0(&stack0xffffffb4,&local_30);
  cVar3 = '\x01';
  local_4._0_1_ = 4;
  pcVar2 = FUN_004011f0(&local_30);
  local_4._0_1_ = 1;
  FUN_00416910(param_1,pcVar2,cVar3);
LAB_00417ebb:
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170(&local_30);
  local_4 = 0xffffffff;
  FUN_004167b0((int)&param_3);
  ExceptionList = local_c;
  return;
}



undefined4 * __thiscall FUN_00417ef0(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  void **ppvVar2;
  byte *pbVar3;
  int iVar4;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c8f8;
  puVar1 = *(undefined4 **)((int)this + 4);
  local_4 = 0;
  ppvVar2 = &local_c;
  local_c = ExceptionList;
  while( true ) {
    ExceptionList = ppvVar2;
    if (puVar1 == (undefined4 *)0x0) {
      *param_1 = 0;
      local_4 = 0xffffffff;
      FUN_00401170((void **)&stack0x00000008);
      ExceptionList = local_c;
      return param_1;
    }
    pbVar3 = FUN_004011f0((undefined4 *)&stack0x00000008);
    iVar4 = FUN_00401290(puVar1 + 2,pbVar3);
    if (iVar4 == 0) break;
    puVar1 = (undefined4 *)*puVar1;
    ppvVar2 = (void **)ExceptionList;
  }
  *param_1 = puVar1;
  local_4 = 0xffffffff;
  FUN_00401170((void **)&stack0x00000008);
  ExceptionList = local_c;
  return param_1;
}



undefined4 * __thiscall FUN_00417fa0(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined auStack_28 [8];
  undefined4 uStack_20;
  uint uStack_1c;
  undefined *local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c928;
  local_c = ExceptionList;
  uStack_1c = DAT_00428400 ^ (uint)&stack0xffffffe8;
  ExceptionList = &local_c;
  local_10 = auStack_28;
  local_4 = 0;
  FUN_004010b0(auStack_28,(void **)&stack0x00000008);
  puVar1 = FUN_00417ef0((void *)((int)this + 0x20),&local_10);
  *param_1 = *puVar1;
  param_1[1] = (int)this + 4;
  local_4 = 0xffffffff;
  uStack_20 = 0x41800c;
  FUN_00401170((void **)&stack0x00000008);
  ExceptionList = local_c;
  return param_1;
}



void __thiscall FUN_00418030(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  void *local_4;
  
  local_4 = this;
  puVar2 = (undefined4 *)FUN_00405b60((void *)((int)this + 0x20),&local_4);
  uVar1 = *puVar2;
  param_1[1] = (int)this + 4;
  *param_1 = uVar1;
  return;
}



void __fastcall FUN_00418060(void *param_1,undefined param_2,undefined param_3)

{
  void **ppvVar1;
  void *pvVar2;
  int **ppiVar3;
  int *piVar4;
  int iVar5;
  undefined4 *puVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  char cVar10;
  undefined **ppuVar11;
  char *pcVar12;
  undefined *local_5c [2];
  int *local_54;
  int *local_50;
  int *local_48 [3];
  void *local_3c;
  void *local_38;
  void *local_30 [3];
  void *local_24 [3];
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c990;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  iVar8 = 0;
  local_4 = 0;
  FUN_004010a0(&local_3c);
  local_4._0_1_ = 1;
  if (*(int *)((int)param_1 + 0x3c) == 1) {
    ppvVar1 = (void **)FUN_004018e0(&local_54,"{\"lane\":");
    local_4 = CONCAT31(local_4._1_3_,2);
    if (*ppvVar1 != local_3c) {
      FUN_00401910(&local_3c,(uint)ppvVar1[1]);
      memcpy(local_3c,*ppvVar1,(size_t)ppvVar1[1]);
      local_38 = ppvVar1[1];
      *(undefined *)((int)local_38 + (int)local_3c) = 0;
    }
    ppiVar3 = &local_54;
  }
  else {
    if (*(int *)((int)param_1 + 0x3c) != 2) {
      FUN_004028b0("WebServerRequest %d HandleLanesMsg UNDEFINED INI FILE \'JSON_VERSION\'",
                   (char)*(undefined4 *)((int)param_1 + 0x78));
      goto LAB_0041837d;
    }
    ppvVar1 = (void **)FUN_004018e0(local_48,
                                    "{\"lpr:lanes\":{\"-xmlns:lpr\":\"http://3rdparty.com/lpr\",\"lpr:lane\":"
                                   );
    local_4 = CONCAT31(local_4._1_3_,3);
    if (*ppvVar1 != local_3c) {
      FUN_00401910(&local_3c,(uint)ppvVar1[1]);
      memcpy(local_3c,*ppvVar1,(size_t)ppvVar1[1]);
      local_38 = ppvVar1[1];
      *(undefined *)((int)local_38 + (int)local_3c) = 0;
    }
    ppiVar3 = local_48;
  }
  local_4._0_1_ = 1;
  FUN_00401170(ppiVar3);
  FUN_00401240(&local_3c,"[");
  ppuVar11 = local_5c;
  pvVar2 = (void *)FUN_004199a0(*(int *)((int)param_1 + 0x40));
  ppiVar3 = (int **)FUN_00418030(pvVar2,ppuVar11);
  piVar7 = *ppiVar3;
  local_50 = ppiVar3[1];
  local_54 = piVar7;
  if (piVar7 != (int *)0x0) {
    do {
      local_5c[0] = &stack0xffffff7c;
      iVar8 = iVar8 + 1;
      local_54 = piVar7;
      FUN_004010b0(&stack0xffffff7c,(void **)(piVar7 + 2));
      piVar4 = FUN_00409340(local_50,local_48);
      pvVar2 = *(void **)(*piVar4 + 0x14);
      if (1 < iVar8) {
        FUN_00401240(&local_3c,",");
      }
      iVar9 = 0;
      iVar5 = FUN_0040c030((int)pvVar2);
      if (0 < iVar5) {
        do {
          puVar6 = (undefined4 *)FUN_0040c790(pvVar2,local_18,iVar9);
          local_4._0_1_ = 4;
          FUN_004011f0(puVar6);
          ppvVar1 = (void **)FUN_004018e0(local_24,"%s{\"id\":%s}");
          local_4._0_1_ = 5;
          ppvVar1 = FUN_00401990(local_30,&local_3c,ppvVar1);
          local_4._0_1_ = 6;
          if (*ppvVar1 != local_3c) {
            FUN_00401910(&local_3c,(uint)ppvVar1[1]);
            memcpy(local_3c,*ppvVar1,(size_t)ppvVar1[1]);
            local_38 = ppvVar1[1];
            *(undefined *)((int)local_38 + (int)local_3c) = 0;
          }
          local_4._0_1_ = 5;
          FUN_00401170(local_30);
          local_4._0_1_ = 4;
          FUN_00401170(local_24);
          local_4._0_1_ = 1;
          FUN_00401170(local_18);
          iVar9 = iVar9 + 1;
          iVar5 = FUN_0040c030((int)pvVar2);
          piVar7 = local_54;
        } while (iVar9 < iVar5);
      }
      piVar7 = (int *)*piVar7;
    } while (piVar7 != (int *)0x0);
    local_54 = (int *)0x0;
  }
  FUN_00401240(&local_3c,"]");
  if (*(int *)((int)param_1 + 0x3c) == 1) {
    pcVar12 = "}";
  }
  else {
    if (*(int *)((int)param_1 + 0x3c) != 2) {
      FUN_004028b0("WebServerRequest %d HandleLanesMsg UNDEFINED INI FILE \'JSON_VERSION\'",
                   (char)*(undefined4 *)((int)param_1 + 0x78));
      goto LAB_0041837d;
    }
    pcVar12 = "}}";
  }
  FUN_00401240(&local_3c,pcVar12);
  FUN_004011f0(&local_3c);
  FUN_00402870("WebServerRequest %d HandleLanesMsg send \'%s\'",
               (char)*(undefined4 *)((int)param_1 + 0x78));
  local_5c[0] = &stack0xffffff7c;
  FUN_004010b0(&stack0xffffff7c,&local_3c);
  cVar10 = '\x01';
  local_4._0_1_ = 7;
  pcVar12 = FUN_004011f0(&local_3c);
  local_4._0_1_ = 1;
  FUN_00416910(param_1,pcVar12,cVar10);
LAB_0041837d:
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170(&local_3c);
  local_4 = 0xffffffff;
  FUN_004167b0((int)&param_3);
  ExceptionList = local_c;
  return;
}



void __fastcall
FUN_004183c0(void *param_1,undefined param_2,undefined param_3,undefined param_4,undefined param_5,
            undefined param_6,undefined param_7,undefined param_8,undefined param_9,
            undefined param_10,undefined param_11)

{
  int iVar1;
  void *pvVar2;
  int *piVar3;
  void **ppvVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  char cVar8;
  void *local_3c [3];
  void *local_30 [3];
  void *local_24 [3];
  void *local_18 [3];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041c9e8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_4 = 0;
  FUN_004010a0(local_30);
  local_4._0_1_ = 1;
  FUN_004010b0(&stack0xffffffa0,(void **)&param_11);
  ppvVar4 = local_3c;
  local_4._0_1_ = 2;
  pvVar2 = (void *)FUN_00419990(*(int *)((int)param_1 + 0x40));
  local_4._0_1_ = 1;
  piVar3 = FUN_00417fa0(pvVar2,ppvVar4);
  iVar1 = *piVar3;
  pvVar2 = (void *)piVar3[1];
  if (iVar1 == 0) {
    FUN_004011f0((undefined4 *)&param_11);
    FUN_004028b0("WebServerRequest %d Can\'t handle cameras message. Not found laneId \'%s\'",
                 (char)*(undefined4 *)((int)param_1 + 0x78));
    FUN_00401100(&stack0xffffffa0,"",(char *)0x7fffffff);
    pcVar7 = "";
    cVar8 = '\0';
  }
  else {
    if (*(int *)((int)param_1 + 0x3c) == 1) {
      ppvVar4 = (void **)FUN_004018e0(local_24,"{\"camera\":[{\"id\":\"1\"}");
      local_4 = CONCAT31(local_4._1_3_,3);
      FUN_00401000(local_30,ppvVar4);
      ppvVar4 = local_24;
    }
    else {
      if (*(int *)((int)param_1 + 0x3c) != 2) {
        FUN_004028b0("WebServerRequest %d HandleCamerasMsg UNDEFINED INI FILE \'JSON_VERSION\'",
                     (char)*(undefined4 *)((int)param_1 + 0x78));
        goto LAB_004185e5;
      }
      ppvVar4 = (void **)FUN_004018e0(local_3c,
                                      "{\"lpr:cameras\":{\"-xmlns:lpr\":\"http://3rdparty.com/lpr\",\"lpr:camera\":[{\"id\":1}"
                                     );
      local_4 = CONCAT31(local_4._1_3_,4);
      FUN_00401000(local_30,ppvVar4);
      ppvVar4 = local_3c;
    }
    local_4._0_1_ = 1;
    FUN_00401170(ppvVar4);
    FUN_004010b0(&stack0xffffffa0,(void **)(iVar1 + 8));
    piVar3 = FUN_00409340(pvVar2,local_3c);
    iVar1 = *(int *)(*piVar3 + 0x14);
    iVar6 = 0;
    iVar5 = FUN_0040bbb0(iVar1);
    if (0 < *(int *)(iVar5 + 0xc)) {
      do {
        ppvVar4 = (void **)FUN_004018e0(local_18,",{\"id\":\"%d\"}");
        local_4._0_1_ = 5;
        FUN_00401200(local_30,ppvVar4);
        local_4._0_1_ = 1;
        FUN_00401170(local_18);
        iVar6 = iVar6 + 1;
        iVar5 = FUN_0040bbb0(iVar1);
      } while (iVar6 < *(int *)(iVar5 + 0xc));
    }
    FUN_00401240(local_30,"]");
    if (*(int *)((int)param_1 + 0x3c) == 1) {
      pcVar7 = "}";
    }
    else {
      if (*(int *)((int)param_1 + 0x3c) != 2) {
        FUN_004028b0("WebServerRequest %d HandleCamerasMsg UNDEFINED INI FILE \'JSON_VERSION\'",
                     (char)*(undefined4 *)((int)param_1 + 0x78));
        goto LAB_004185e5;
      }
      pcVar7 = "}}";
    }
    FUN_00401240(local_30,pcVar7);
    FUN_004011f0(local_30);
    FUN_00402870("WebServerRequest %d HandleCamerasMsg send \'%s\'",
                 (char)*(undefined4 *)((int)param_1 + 0x78));
    FUN_004010b0(&stack0xffffffa0,local_30);
    cVar8 = '\x01';
    local_4._0_1_ = 6;
    pcVar7 = FUN_004011f0(local_30);
    local_4._0_1_ = 1;
  }
  FUN_00416910(param_1,pcVar7,cVar8);
LAB_004185e5:
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170(local_30);
  local_4 = 0xffffffff;
  FUN_004167b0((int)&param_3);
  ExceptionList = local_c;
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void __thiscall
FUN_00418620(void *this,undefined param_2,undefined param_3,undefined param_4,undefined param_5,
            undefined param_6,undefined param_7,undefined param_8,undefined param_9,
            undefined param_10,undefined param_11,char param_12)

{
  undefined *puVar1;
  bool bVar2;
  ushort uVar3;
  short sVar4;
  char *_Dest;
  int *piVar5;
  void *pvVar6;
  int iVar7;
  void **ppvVar8;
  char *pcVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  int **ppiVar12;
  size_t sVar13;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined **ppuVar14;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 extraout_EDX_02;
  code *pcVar15;
  int iVar16;
  undefined4 *puVar17;
  char in_stack_00000055;
  char in_stack_00000056;
  char cVar18;
  undefined uVar19;
  char *pcVar20;
  uint uVar21;
  char **ppcVar22;
  undefined4 uVar23;
  int local_4128;
  char *local_4124;
  undefined *local_4120;
  int local_411c;
  void *local_4118;
  void *local_4114;
  void *pvStack_4110;
  void *local_4108;
  int iStack_4104;
  char *pcStack_40fc;
  int iStack_40f8;
  int *piStack_40f4;
  void *local_40f0;
  void *local_40ec [3];
  void *local_40e0 [3];
  undefined **local_40d4;
  void *local_40d0;
  uint local_40cc;
  undefined4 local_40c8;
  undefined4 local_40c4;
  undefined4 local_40c0;
  undefined4 local_40bc;
  void *local_40b8 [3];
  undefined *local_40ac [3];
  undefined *local_40a0 [3];
  undefined *local_4094 [3];
  undefined4 uStack_4088;
  undefined *local_4084 [3];
  undefined *puStack_4078;
  undefined *apuStack_4074 [3];
  WCHAR aWStack_4068 [4098];
  WCHAR aWStack_2064 [4098];
  undefined4 uStack_60;
  undefined uStack_5c;
  undefined4 uStack_58;
  undefined4 uStack_54;
  undefined4 uStack_50;
  undefined4 uStack_4c;
  undefined4 uStack_48;
  undefined4 uStack_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  undefined2 uStack_38;
  undefined4 uStack_34;
  undefined4 uStack_30;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined2 uStack_14;
  uint local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041caff;
  local_c = ExceptionList;
  local_10 = DAT_00428400 ^ (uint)&local_4128;
  ExceptionList = &local_c;
  local_4 = 0;
  local_40f0 = this;
  FUN_004010a0(local_40ec);
  local_4._0_1_ = 1;
  FUN_004010a0(local_40b8);
  local_4._0_1_ = 2;
  FUN_004010a0(&local_4108);
  local_4._0_1_ = 3;
  FUN_004010a0(&local_4114);
  local_4._0_1_ = 4;
  FUN_004010a0(local_40e0);
  local_40d4 = aMap<int,int>::vftable;
  local_40d0 = (void *)0x0;
  local_40cc = 0x11;
  local_40c8 = 0;
  local_40c4 = 0;
  local_40c0 = 0;
  local_40bc = 10;
  local_4._0_1_ = 6;
  FUN_004118b0(&local_4128);
  local_4._0_1_ = 7;
  _Dest = (char *)operator_new(0x80000);
  memset(_Dest,0,0x80000);
  FUN_00401040(local_40ec,"");
  if (*(void **)((int)this + 0x7c) == (void *)0x0) {
    FUN_00402890("WebServerRequest %d HandleRecognitionMsg send error, hasn\'t LPR recognition data"
                 ,(char)*(undefined4 *)((int)this + 0x78));
  }
  else {
    piVar5 = FUN_00409640(*(void **)((int)this + 0x7c),&local_411c);
    local_4._0_1_ = 8;
    FUN_00411750(&local_4128,piVar5);
    local_4._0_1_ = 7;
    FUN_00411740(&local_411c);
  }
  if (*(int *)((int)this + 0x7c) != 0) {
    FUN_004087f0(*(int *)((int)this + 0x7c));
    FUN_004087e0(*(int *)((int)this + 0x7c));
    FUN_004087d0(*(int *)((int)this + 0x7c));
    FUN_00402850("WebServerRequest %d HandleRecognitionMsg ev:%d completed:%d (imgs: v:%d d:%d)",
                 (char)*(undefined4 *)((int)this + 0x78));
  }
  local_4120 = &stack0xffffbeb8;
  FUN_004010b0(&stack0xffffbeb8,(void **)&param_11);
  ppuVar14 = local_40a0;
  local_4._0_1_ = 9;
  pvVar6 = (void *)FUN_00419990(*(int *)((int)this + 0x40));
  local_4 = CONCAT31(local_4._1_3_,7);
  piVar5 = FUN_00417fa0(pvVar6,ppuVar14);
  pvVar6 = (void *)piVar5[1];
  if (*piVar5 == 0) {
    FUN_004011f0((undefined4 *)&param_11);
    FUN_004028b0("WebServerRequest %d Can\'t handle recognition message. Not found laneId \'%s\'",
                 (char)*(undefined4 *)((int)this + 0x78));
    local_4120 = &stack0xffffbeb8;
    FUN_00401100(&stack0xffffbeb8,"",(char *)0x7fffffff);
    cVar18 = '\0';
    pcVar20 = "";
  }
  else {
    local_4120 = &stack0xffffbeb8;
    FUN_004010b0(&stack0xffffbeb8,(void **)(*piVar5 + 8));
    FUN_00409340(pvVar6,local_40a0);
    if (*(int *)((int)this + 0x3c) == 1) {
      FUN_004011f0((undefined4 *)&param_11);
      pcVar20 = "{\"lane\":{\"id\":%s},\"cameraDetail\":[";
    }
    else {
      if (*(int *)((int)this + 0x3c) != 2) {
        operator_delete__(_Dest);
        FUN_004028b0("WebServerRequest %d HandleRecognitionMsg UNDEFINED INI FILE \'JSON_VERSION\'",
                     (char)*(undefined4 *)((int)this + 0x78));
        goto LAB_00419554;
      }
      FUN_004011f0((undefined4 *)&param_11);
      pcVar20 = 
      "{\"lpr:laneDetail\":{\"-xmlns:lpr\":\"http://3rdparty.com/lpr\",\"lpr:lane\":{\"id\":%s},\"lpr:cameraDetail\":["
      ;
    }
    sprintf(_Dest,pcVar20);
    if (param_12 == '\0') {
      ppvVar8 = (void **)FUN_004018e0(local_4084,"%s");
      local_4._0_1_ = 0x13;
      ppvVar8 = FUN_00401a20(local_40ac,ppvVar8,"...");
      local_4._0_1_ = 0x14;
      FUN_00401000(local_40ec,ppvVar8);
      local_4._0_1_ = 0x13;
      FUN_00401170(local_40ac);
      local_4 = CONCAT31(local_4._1_3_,7);
      FUN_00401170(local_4084);
      this = local_40f0;
      pcVar15 = sprintf_exref;
    }
    else {
      if (*(int *)((int)this + 0x3c) == 1) {
        pcVar20 = 
        "%s{\"camera\":{\"id\":1},\"preferredImage\":1,\"image\":[{\"id\":1,\"spectrum\":\"IR\",";
      }
      else {
        if (*(int *)((int)this + 0x3c) != 2) {
          operator_delete__(_Dest);
          FUN_004028b0("WebServerRequest %d HandleRecognitionMsg UNDEFINED INI FILE \'JSON_VERSION\'"
                       ,(char)*(undefined4 *)((int)this + 0x78));
          goto LAB_00419554;
        }
        pcVar20 = 
        "%s{\"lpr:camera\":{\"id\":1},\"preferredImage\":1,\"lpr:image\":[{\"id\":1,\"spectrum\":\"IR\","
        ;
      }
      sprintf(_Dest,pcVar20);
      pvVar6 = operator_new(0x10000);
      local_4118 = pvVar6;
      memset(pvVar6,0,0x10000);
      bVar2 = FUN_00412880(&local_4128);
      if (bVar2) {
        iVar7 = FUN_00411810(&local_4128,pvVar6,0x10000);
      }
      else {
        iVar7 = 0;
      }
      ppvVar8 = (void **)FUN_004018e0(local_4094,"%s");
      local_4._0_1_ = 10;
      ppvVar8 = FUN_00401a20(local_40a0,ppvVar8,"...imageData ...");
      local_4._0_1_ = 0xb;
      FUN_00401000(local_40ec,ppvVar8);
      local_4._0_1_ = 10;
      FUN_00401170(local_40a0);
      local_4 = CONCAT31(local_4._1_3_,7);
      FUN_00401170(local_4094);
      pcVar20 = _Dest;
      if (iVar7 == 0) {
        sprintf(_Dest,"%s\"imageData\":\"\",");
        pcVar15 = sprintf_exref;
      }
      else {
        pcVar9 = (char *)operator_new(iVar7 * 2 + 1);
        iVar16 = 0;
        local_4124 = pcVar9;
        if (0 < iVar7) {
          do {
            sprintf(pcVar9,"%.2x");
            iVar16 = iVar16 + 1;
            pcVar9 = pcVar9 + 2;
          } while (iVar16 < iVar7);
        }
        pcVar15 = sprintf_exref;
        sprintf(_Dest,"%s\"imageData\":\"");
        pcVar9 = local_4124;
        sprintf(_Dest,"%s%s",_Dest,local_4124);
        sprintf(_Dest,"%s\",",_Dest);
        operator_delete__(pcVar9);
      }
      operator_delete__(local_4118);
      uVar21 = 0x418a40;
      FUN_00401040(&local_4114,"");
      bVar2 = FUN_00412880(&local_4128);
      if (bVar2) {
        if (DAT_0042b194 == '\0') {
          puVar17 = (undefined4 *)0x0;
          uVar21 = 0x418ad5;
          puVar10 = (undefined4 *)FUN_00411bb0(&local_4128,&local_411c);
          iVar7 = FUN_00411850(puVar10);
          if (0 < iVar7) {
            do {
              uVar23 = 5;
              puVar10 = &uStack_60;
              uStack_60 = 0;
              uStack_5c = 0;
              ppuVar14 = &local_4120;
              puVar11 = puVar17;
              pvVar6 = (void *)FUN_00411bb0(&local_4128,&local_4118);
              puVar11 = FUN_00411bc0(pvVar6,ppuVar14,puVar11);
              pcVar20 = (char *)0x418b1c;
              FUN_00411860(puVar11,puVar10,uVar23);
              FUN_00401240(&local_4114,(char *)&uStack_60);
              puVar17 = (undefined4 *)((int)puVar17 + 1);
              uVar21 = 0x418b3e;
              puVar10 = (undefined4 *)FUN_00411bb0(&local_4128,&local_411c);
              iVar7 = FUN_00411850(puVar10);
            } while ((int)puVar17 < iVar7);
          }
        }
        else {
          uStack_34 = 0;
          uStack_30 = 0;
          uStack_2c = 0;
          uStack_28 = 0;
          uStack_24 = 0;
          uStack_20 = 0;
          uStack_1c = 0;
          uStack_18 = 0;
          uStack_14 = 0;
          pcVar20 = (char *)0x418aaf;
          FUN_004117f0(&local_4128,&uStack_34,0x22);
          uVar21 = 0x418ac0;
          FUN_00401040(&local_4114,(char *)&uStack_34);
        }
      }
      local_4120 = &stack0xffffbeb8;
      FUN_004010b0(&stack0xffffbeb8,&local_4114);
      ppvVar8 = (void **)FUN_0040b930(local_4094,pcVar20,uVar21);
      local_4._0_1_ = 0xc;
      if (*ppvVar8 != local_4114) {
        FUN_00401910(&local_4114,(uint)ppvVar8[1]);
        memcpy(local_4114,*ppvVar8,(size_t)ppvVar8[1]);
        pvStack_4110 = ppvVar8[1];
        *(undefined *)((int)pvStack_4110 + (int)local_4114) = 0;
      }
      local_4 = CONCAT31(local_4._1_3_,7);
      FUN_00401170(local_4094);
      this = local_40f0;
      if (*(int *)((int)local_40f0 + 0x3c) == 1) {
        FUN_004011f0(&local_4114);
      }
      else {
        if (*(int *)((int)local_40f0 + 0x3c) != 2) {
          operator_delete__(_Dest);
          FUN_004028b0("WebServerRequest %d HandleRecognitionMsg(2) UNDEFINED INI FILE \'JSON_VERSION\'"
                       ,(char)*(undefined4 *)((int)this + 0x78));
          goto LAB_00419554;
        }
        FUN_004011f0(&local_4114);
      }
      (*pcVar15)(_Dest);
      uStack_58 = 0;
      uStack_54 = 0;
      uStack_50 = 0;
      uStack_4c = 0;
      uStack_48 = 0;
      uStack_44 = 0;
      uStack_40 = 0;
      uStack_3c = 0;
      uStack_38 = 0;
      FUN_00401040(&local_4108,"");
      bVar2 = FUN_00412880(&local_4128);
      if (bVar2) {
        FUN_004011f0(&local_4114);
        uVar19 = (undefined)*(undefined4 *)((int)this + 0x78);
        FUN_00402850("WebServerRequest %d HandleRecognitionMsg License \'%s\' %s",uVar19);
        if (DAT_0042b194 == '\0') {
          puVar17 = (undefined4 *)0x0;
          puVar10 = (undefined4 *)FUN_00411bb0(&local_4128,&local_411c);
          iVar7 = FUN_00411850(puVar10);
          if (0 < iVar7) {
            do {
              uVar23 = 5;
              puVar10 = &uStack_60;
              ppuVar14 = &local_4120;
              uStack_60 = 0;
              uStack_5c = 0;
              puVar11 = puVar17;
              pvVar6 = (void *)FUN_00411bb0(&local_4128,&local_4118);
              puVar11 = FUN_00411bc0(pvVar6,ppuVar14,puVar11);
              FUN_00411860(puVar11,puVar10,uVar23);
              MultiByteToWideChar(0xfde9,0,(LPCSTR)&uStack_60,-1,(LPWSTR)&uStack_4088,0x20);
              iVar7 = FUN_0040b900(&DAT_00429190,(short)uStack_4088);
              if (iVar7 < 0) {
                if (iStack_4104 != 0) {
                  FUN_00401240(&local_4108,",");
                }
                piVar5 = &iStack_40f8;
                puVar10 = puVar17;
                pvVar6 = (void *)FUN_00411bb0(&local_4128,&pcStack_40fc);
                puVar10 = FUN_00411bc0(pvVar6,piVar5,puVar10);
                FUN_00411880(puVar10);
                FUN_0041a580(extraout_ECX_01,extraout_EDX_01);
                ppvVar8 = (void **)FUN_004018e0(local_40ac,"%d");
                local_4._0_1_ = 0x12;
                FUN_00401200(&local_4108,ppvVar8);
                local_4 = CONCAT31(local_4._1_3_,7);
                FUN_00401170(local_40ac);
              }
              puVar17 = (undefined4 *)((int)puVar17 + 1);
              puVar10 = (undefined4 *)FUN_00411bb0(&local_4128,&local_411c);
              iVar7 = FUN_00411850(puVar10);
              pcVar15 = sprintf_exref;
            } while ((int)puVar17 < iVar7);
          }
        }
        else {
          FUN_00401040(local_40e0,"");
          puVar17 = (undefined4 *)0x0;
          puVar10 = (undefined4 *)FUN_00411bb0(&local_4128,&local_411c);
          iVar7 = FUN_00411850(puVar10);
          if (0 < iVar7) {
            do {
              uVar23 = 5;
              puVar10 = &uStack_60;
              ppuVar14 = &local_4120;
              uStack_60 = 0;
              uStack_5c = 0;
              puVar11 = puVar17;
              pvVar6 = (void *)FUN_00411bb0(&local_4128,&local_4118);
              puVar11 = FUN_00411bc0(pvVar6,ppuVar14,puVar11);
              uVar19 = 0xd;
              FUN_00411860(puVar11,puVar10,uVar23);
              FUN_00401240(local_40e0,(char *)&uStack_60);
              puVar17 = (undefined4 *)((int)puVar17 + 1);
              puVar10 = (undefined4 *)FUN_00411bb0(&local_4128,&local_411c);
              iVar7 = FUN_00411850(puVar10);
            } while ((int)puVar17 < iVar7);
          }
          local_4120 = &stack0xffffbeb8;
          FUN_004010b0(&stack0xffffbeb8,local_40e0);
          FUN_0040b5e0(aWStack_4068,extraout_DL,uVar19);
          local_4120 = &stack0xffffbeb8;
          FUN_004010b0(&stack0xffffbeb8,&local_4114);
          FUN_0040b5e0(aWStack_2064,extraout_DL_00,uVar19);
          local_4124 = (char *)0x0;
          iVar7 = FUN_0040b670((int)aWStack_2064);
          if (0 < iVar7) {
            do {
              puVar10 = (undefined4 *)0xffffffff;
              uVar3 = FUN_0040b680(aWStack_2064,(int)local_4124);
              if ((local_40d0 == (void *)0x0) ||
                 (piVar5 = *(int **)((int)local_40d0 + ((uint)(uVar3 >> 4) % local_40cc) * 4),
                 piVar5 == (int *)0x0)) {
                piVar5 = (int *)0x0;
              }
              else {
                do {
                  if (piVar5[2] == (uint)uVar3) {
                    if (piVar5 != (int *)0x0) {
                      puVar10 = (undefined4 *)piVar5[3];
                    }
                    goto LAB_00418de8;
                  }
                  piVar5 = (int *)*piVar5;
                } while (piVar5 != (int *)0x0);
                piVar5 = (int *)0x0;
              }
LAB_00418de8:
              sVar4 = FUN_0040b680(aWStack_2064,(int)local_4124);
              puVar17 = (undefined4 *)FUN_0040b6a0(aWStack_4068,(int)puVar10 + 1,sVar4);
              if (iStack_4104 != 0) {
                FUN_00401240(&local_4108,",");
              }
              if ((int)puVar17 < 0) {
                if ((int)puVar10 < 0) {
                  ppvVar8 = (void **)FUN_004018e0(local_40ac,"%d");
                  local_4 = CONCAT31(local_4._1_3_,0x11);
                  FUN_00401200(&local_4108,ppvVar8);
                  ppuVar14 = local_40ac;
                }
                else {
                  puVar17 = (undefined4 *)FUN_00411bb0(&local_4128,&iStack_40f8);
                  iVar7 = FUN_00411850(puVar17);
                  if ((int)puVar10 < iVar7) {
                    ppcVar22 = &pcStack_40fc;
                    pvVar6 = (void *)FUN_00411bb0(&local_4128,&piStack_40f4);
                    puVar10 = FUN_00411bc0(pvVar6,ppcVar22,puVar10);
                    FUN_00411880(puVar10);
                    FUN_0041a580(extraout_ECX_00,extraout_EDX_00);
                    ppvVar8 = (void **)FUN_004018e0(local_4084,"%d");
                    local_4 = CONCAT31(local_4._1_3_,0x10);
                    FUN_00401200(&local_4108,ppvVar8);
                    ppuVar14 = local_4084;
                  }
                  else {
                    ppvVar8 = (void **)FUN_004018e0(apuStack_4074,"%d");
                    local_4 = CONCAT31(local_4._1_3_,0xf);
                    FUN_00401200(&local_4108,ppvVar8);
                    ppuVar14 = apuStack_4074;
                  }
                }
              }
              else {
                if ((int)puVar10 < 0) {
                  uVar3 = FUN_0040b680(aWStack_2064,(int)local_4124);
                  piVar5 = FUN_00414eb0(&local_40d0,(uint)uVar3);
                  *piVar5 = (int)puVar17;
                }
                else {
                  piVar5[3] = (int)puVar17;
                }
                puVar10 = (undefined4 *)FUN_00411bb0(&local_4128,&local_4120);
                iVar7 = FUN_00411850(puVar10);
                if ((int)puVar17 < iVar7) {
                  piVar5 = &local_411c;
                  pvVar6 = (void *)FUN_00411bb0(&local_4128,&local_4118);
                  puVar10 = FUN_00411bc0(pvVar6,piVar5,puVar17);
                  FUN_00411880(puVar10);
                  FUN_0041a580(extraout_ECX,extraout_EDX);
                  ppvVar8 = (void **)FUN_004018e0(local_40a0,"%d");
                  local_4 = CONCAT31(local_4._1_3_,0xe);
                  FUN_00401200(&local_4108,ppvVar8);
                  ppuVar14 = local_40a0;
                }
                else {
                  ppvVar8 = (void **)FUN_004018e0(local_4094,"%d");
                  local_4 = CONCAT31(local_4._1_3_,0xd);
                  FUN_00401200(&local_4108,ppvVar8);
                  ppuVar14 = local_4094;
                }
              }
              local_4 = CONCAT31(local_4._1_3_,7);
              FUN_00401170(ppuVar14);
              pcVar20 = local_4124 + 1;
              local_4124 = pcVar20;
              iVar7 = FUN_0040b670((int)aWStack_2064);
              this = local_40f0;
              pcVar15 = sprintf_exref;
            } while ((int)pcVar20 < iVar7);
          }
        }
        FUN_004011f0(&local_4108);
        FUN_004117c0(&local_4128);
        FUN_0041a580(extraout_ECX_02,extraout_EDX_02);
        (*pcVar15)(_Dest,"%s,\"lpnQF\":%d,\"lpnQFchar\":[%s],");
        FUN_004117a0(&local_4128,&uStack_58,0x22);
        (*pcVar15)(_Dest);
        (*pcVar15)();
      }
      else {
        FUN_00402850("WebServerRequest %d HandleRecognitionMsg without car license recognition",
                     (char)*(undefined4 *)((int)this + 0x78));
        (*pcVar15)(_Dest,"%s,\"lpnQF\":0,\"lpnQFchar\":[],\"lpState\":\"undefined\"");
        (*pcVar15)();
      }
    }
    if (*(int *)((int)this + 0x7c) != 0) {
      local_4118 = (void *)0x2;
      local_411c = 0;
      do {
        iVar7 = local_411c;
        FUN_004087e0(*(int *)((int)this + 0x7c));
        if (iVar7 == 0) {
          ppuVar14 = &puStack_4078;
          pvVar6 = (void *)FUN_004087e0(*(int *)((int)this + 0x7c));
        }
        else {
          ppuVar14 = local_40a0;
          pvVar6 = (void *)FUN_004087f0(*(int *)((int)this + 0x7c));
        }
        ppiVar12 = (int **)FUN_00408af0(pvVar6,ppuVar14);
        piStack_40f4 = *ppiVar12;
        if ((piStack_40f4 != (int *)0x0) &&
           (((in_stack_00000055 != '\0' && (iVar7 == 0)) ||
            ((in_stack_00000056 != '\0' && (iVar7 == 1)))))) {
          if (*(int *)((int)this + 0x3c) == 1) {
            pcVar20 = "%s,{\"camera\":{\"id\":%d},\"preferredImage\":1,\"image\":[";
          }
          else {
            if (*(int *)((int)this + 0x3c) != 2) {
              operator_delete__(_Dest);
              FUN_004028b0("WebServerRequest %d HandleRecognitionMsg UNDEFINED INI FILE \'JSON_VERSION\'"
                           ,(char)*(undefined4 *)((int)this + 0x78));
              goto LAB_00419554;
            }
            pcVar20 = "%s,{\"lpr:camera\":{\"id\":%d},\"preferredImage\":1,\"lpr:image\":[";
          }
          sprintf(_Dest,pcVar20);
          iStack_40f8 = 1;
          do {
            puVar1 = (undefined *)piStack_40f4[2];
            local_4120 = puVar1;
            if (1 < iStack_40f8) {
              sprintf(_Dest,"%s,");
            }
            sprintf(_Dest,"%s{\"id\":%d,\"spectrum\":\"DAYLIGHT\",");
            pvVar6 = operator_new(0x10000);
            memset(pvVar6,0,0x10000);
            sVar13 = FUN_0040ac20(puVar1,pvVar6,0x10000);
            if (sVar13 == 0) {
              sprintf(_Dest,"%s\"imageData\":\"\"");
              pcVar15 = sprintf_exref;
            }
            else {
              local_4124 = (char *)operator_new(sVar13 * 2 + 1);
              iVar7 = 0;
              pcVar20 = local_4124;
              if (0 < (int)sVar13) {
                do {
                  pcStack_40fc = pcVar20;
                  sprintf(pcStack_40fc,"%.2x");
                  pcStack_40fc = pcStack_40fc + 2;
                  iVar7 = iVar7 + 1;
                  pcVar20 = pcStack_40fc;
                } while (iVar7 < (int)sVar13);
              }
              pcVar15 = sprintf_exref;
              sprintf(_Dest,"%s\"imageData\":\"");
              pcVar20 = local_4124;
              sprintf(_Dest,"%s%s",_Dest,local_4124);
              sprintf(_Dest,"%s\"",_Dest);
              operator_delete__(pcVar20);
            }
            operator_delete__(pvVar6);
            puVar1 = local_4120;
            puVar10 = (undefined4 *)FUN_0040ab00(local_4120,local_40ac);
            local_4._0_1_ = 0x15;
            FUN_004011f0(puVar10);
            (*pcVar15)(_Dest);
            local_4 = CONCAT31(local_4._1_3_,7);
            FUN_00401170(local_40ac);
            iVar7 = FUN_0040aaf0((int)puVar1);
            if ((iVar7 == 0) || (iVar7 = FUN_0040aaf0((int)puVar1), iVar7 == 1)) {
              (*pcVar15)();
            }
            (*pcVar15)();
            piStack_40f4 = (int *)*piStack_40f4;
            iStack_40f8 = iStack_40f8 + 1;
          } while (piStack_40f4 != (int *)0x0);
          local_4118 = (void *)((int)local_4118 + 1);
          sprintf(_Dest,"%s]}");
          this = local_40f0;
          iVar7 = local_411c;
        }
        local_411c = iVar7 + 1;
        pcVar15 = sprintf_exref;
      } while (local_411c < 2);
    }
    if ((*(int *)((int)this + 0x3c) != 1) && (*(int *)((int)this + 0x3c) != 2)) {
      FUN_004028b0("WebServerRequest %d HandleRecognitionMsg(3) UNDEFINED INI FILE \'JSON_VERSION\'"
                   ,(char)*(undefined4 *)((int)this + 0x78));
      operator_delete__(_Dest);
      goto LAB_00419554;
    }
    (*pcVar15)();
    local_40a0[0] = &stack0xffffbeb8;
    FUN_004010b0(&stack0xffffbeb8,local_40ec);
    cVar18 = '\x01';
    pcVar20 = _Dest;
  }
  FUN_00416910(this,pcVar20,cVar18);
  operator_delete__(_Dest);
LAB_00419554:
  local_4._0_1_ = 6;
  FUN_00411740(&local_4128);
  local_4._0_1_ = 5;
  local_40d4 = aMap<int,int>::vftable;
  FUN_0040c080(&local_40d0);
  local_4._0_1_ = 4;
  FUN_00401170(local_40e0);
  local_4._0_1_ = 3;
  FUN_00401170(&local_4114);
  local_4._0_1_ = 2;
  FUN_00401170(&local_4108);
  local_4._0_1_ = 1;
  FUN_00401170(local_40b8);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00401170(local_40ec);
  local_4 = 0xffffffff;
  FUN_004167b0((int)&param_2);
  ExceptionList = local_c;
  ___security_check_cookie_4(local_10 ^ (uint)&local_4128);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void __fastcall FUN_00419620(void *param_1)

{
  char cVar1;
  void *pvVar2;
  int iVar3;
  undefined4 uVar4;
  void **ppvVar5;
  void *pvVar6;
  void **ppvVar7;
  undefined extraout_CL;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined uVar8;
  int in_stack_fff7ff2c;
  undefined in_stack_fff7ff30;
  undefined in_stack_fff7ff34;
  undefined in_stack_fff7ff38;
  undefined in_stack_fff7ff3c;
  undefined in_stack_fff7ff40;
  undefined in_stack_fff7ff44;
  undefined in_stack_fff7ff48;
  undefined uVar9;
  char *pcVar10;
  int iVar11;
  undefined uVar12;
  int iVar13;
  int *piVar14;
  undefined *puStack_80074;
  void *apvStack_80070 [2];
  undefined4 uStack_80068;
  int aiStack_80064 [13];
  undefined4 uStack_80030;
  void *apvStack_80020 [4];
  char acStack_80010 [524284];
  uint uStack_14;
  void *local_c;
  undefined4 uStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  uStack_8 = &LAB_0041cb51;
  local_c = ExceptionList;
  pvVar2 = (void *)(DAT_00428400 ^ (uint)&puStack_80074);
  ExceptionList = &local_c;
  FUN_00416720((int)aiStack_80064);
  local_4 = 0;
  memset(acStack_80010,0,0x80000);
  iVar3 = FUN_00405f80(*(void **)((int)param_1 + 0x44),acStack_80010,0x80000,15000);
  iVar11 = *(int *)((int)param_1 + 0x78);
  pcVar10 = "WebServerRequest %d Read len:%d\n%s";
  iVar13 = iVar3;
  FUN_00402870("WebServerRequest %d Read len:%d\n%s",(char)iVar11);
  if (iVar3 != 0) {
    piVar14 = aiStack_80064;
    puStack_80074 = &stack0xfff7ff70;
    FUN_004018e0((undefined4 *)&stack0xfff7ff70,"%s");
    uVar4 = FUN_004170f0(pcVar10,iVar11,iVar13,piVar14);
    if ((char)uVar4 != '\0') {
      puStack_80074 = &stack0xfff7ff2c;
      FUN_00416840(&stack0xfff7ff2c,aiStack_80064);
      ppvVar7 = apvStack_80070;
      ppvVar5 = FUN_00416e00(ppvVar7,in_stack_fff7ff2c);
      uVar8 = (undefined)in_stack_fff7ff2c;
      local_4._0_1_ = 1;
      FUN_004011f0(ppvVar5);
      uVar12 = 0x2f;
      FUN_00402870("WebServerRequest %d identified message \'%s\'",
                   (char)*(undefined4 *)((int)param_1 + 0x78));
      local_4 = (uint)local_4._1_3_ << 8;
      FUN_00401170(apvStack_80070);
      switch(uStack_80030) {
      case 1:
        puStack_80074 = &stack0xfff7ff2c;
        FUN_00416840(&stack0xfff7ff2c,aiStack_80064);
        ppvVar7 = (void **)0x419793;
        FUN_00417bc0(param_1,extraout_DL_00,uVar8);
        break;
      case 2:
        puStack_80074 = &stack0xfff7ff2c;
        FUN_00416840(&stack0xfff7ff2c,aiStack_80064);
        ppvVar7 = (void **)0x419774;
        FUN_00417d60(param_1,extraout_DL,uVar8);
        break;
      case 3:
        puStack_80074 = &stack0xfff7ff2c;
        FUN_00416840(&stack0xfff7ff2c,aiStack_80064);
        ppvVar7 = (void **)0x4197b2;
        FUN_00418060(param_1,extraout_DL_01,uVar8);
        break;
      case 4:
        FUN_00402870("WebServerRequest %d make trigger...",
                     (char)*(undefined4 *)((int)param_1 + 0x78));
        puStack_80074 = &stack0xfff7ff74;
        uVar9 = 0xf5;
        uVar12 = extraout_CL;
        FUN_004010b0(&stack0xfff7ff74,apvStack_80020);
        pvVar6 = (void *)FUN_0041a0e0(*(int *)((int)param_1 + 0x40),extraout_DL_03,uVar12);
        if (pvVar6 == (void *)0x0) {
          FUN_00402890("WebServerRequest %d not found lane associed to SBId \'%d\', can\'t make trigger."
                       ,(char)*(undefined4 *)((int)param_1 + 0x78));
        }
        else {
          uVar4 = FUN_00419cb0(*(void **)((int)param_1 + 0x40),pvVar6,param_1);
          if ((char)uVar4 != '\0') {
            FUN_0040bbf0((int)pvVar6);
            FUN_00402870("WebServerRequest %d make trigger waiting recognition. CaptureTimeout %d ..."
                         ,(char)*(undefined4 *)((int)param_1 + 0x78));
            FUN_0040bbf0((int)pvVar6);
            cVar1 = FUN_004038e0((int *)((int)param_1 + 0x48));
            if (cVar1 == '\0') {
              uVar12 = (undefined)*(undefined4 *)((int)param_1 + 0x78);
              FUN_00402890("WebServerRequest %d awake by TIMEOUT",uVar12);
            }
            else {
              uVar12 = (undefined)*(undefined4 *)((int)param_1 + 0x78);
              FUN_00402870("WebServerRequest %d awake, Recognition data complete.",uVar12);
            }
            FUN_00416840(&stack0xfff7ff28,&uStack_80068);
            FUN_00418620(param_1,(char)ppvVar7,uVar8,in_stack_fff7ff30,in_stack_fff7ff34,
                         in_stack_fff7ff38,in_stack_fff7ff3c,in_stack_fff7ff40,in_stack_fff7ff44,
                         in_stack_fff7ff48,uVar9,uVar12);
          }
        }
        break;
      case 5:
        puStack_80074 = &stack0xfff7ff2c;
        FUN_00416840(&stack0xfff7ff2c,aiStack_80064);
        ppvVar7 = (void **)0x4197d1;
        FUN_004183c0(param_1,extraout_DL_02,uVar8,in_stack_fff7ff30,in_stack_fff7ff34,
                     in_stack_fff7ff38,in_stack_fff7ff3c,in_stack_fff7ff40,in_stack_fff7ff44,
                     in_stack_fff7ff48,uVar12);
        break;
      default:
        FUN_004028b0("WebServerRequest %d \'%s\' can\'t identify request",
                     (char)*(undefined4 *)((int)param_1 + 0x78));
      }
      FUN_00416840(&stack0xfff7ff28,&uStack_80068);
      ppvVar7 = FUN_00416e00(&puStack_80074,(int)ppvVar7);
      uStack_8._0_1_ = 2;
      FUN_004011f0(ppvVar7);
      FUN_00402870("WebServerRequest %d identified \'%s\' terminate...",
                   (char)*(undefined4 *)((int)param_1 + 0x78));
      uStack_8 = (undefined *)((uint)uStack_8._1_3_ << 8);
      FUN_00401170(&puStack_80074);
      goto LAB_00419934;
    }
  }
  puStack_80074 = &stack0xfff7ff74;
  FUN_00401100(&stack0xfff7ff74,"",(char *)0x7fffffff);
  FUN_00416910(param_1,"",'\0');
LAB_00419934:
  uStack_8 = (undefined *)0xffffffff;
  *(undefined *)((int)param_1 + 0x80) = 1;
  FUN_004167b0((int)&uStack_80068);
  ExceptionList = pvVar2;
  ___security_check_cookie_4(uStack_14 ^ (uint)&stack0xfff7ff88);
  return;
}



undefined4 __fastcall FUN_00419990(int param_1)

{
  return *(undefined4 *)(param_1 + 0x34);
}



undefined4 __fastcall FUN_004199a0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x38);
}



undefined4 __thiscall
FUN_004199b0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  
  *(undefined4 *)((int)this + 0x3c) = param_3;
  *(undefined4 *)((int)this + 0x34) = param_1;
  *(undefined4 *)((int)this + 0x38) = param_2;
  *(undefined4 *)((int)this + 0x40) = param_4;
  FUN_00402a80((void *)((int)this + 0x44),(DWORD)this,0,0);
  uVar1 = FUN_00402af0((void *)((int)this + 0x44),1000,1);
  return CONCAT31((int3)((uint)uVar1 >> 8),1);
}



undefined4 * __fastcall FUN_004199f0(undefined4 *param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041cb96;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = CWebServersManager::vftable;
  FUN_00402e50(param_1 + 1);
  param_1[10] = 0;
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  local_4 = 1;
  FUN_00402960(param_1 + 0x11);
  param_1[0x39] = 0;
  ExceptionList = local_c;
  return param_1;
}



void __fastcall FUN_00419a60(undefined4 *param_1)

{
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041cbd6;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = CWebServersManager::vftable;
  local_4 = 1;
  FUN_00402a30(param_1 + 0x11);
  FUN_00412c00(param_1 + 10);
  local_4 = 0xffffffff;
  FUN_00402eb0(param_1 + 1);
  ExceptionList = local_c;
  return;
}



undefined4 * __thiscall FUN_00419ad0(void *this,byte param_1)

{
  FUN_00419a60((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_00419af0(int param_1)

{
  int iVar1;
  int *piVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  int **ppiVar5;
  int *this;
  int local_4;
  
  local_4 = param_1;
  FUN_004033d0((int *)(param_1 + 0x44));
  this = (int *)(param_1 + 0x28);
  iVar1 = *this;
  while (0 < iVar1) {
    ppiVar5 = (int **)FUN_00408af0(this,&local_4);
    piVar2 = *ppiVar5;
    puVar3 = (undefined4 *)piVar2[2];
    if (1 < *this) {
      if (piVar2 == *(int **)(param_1 + 0x2c)) {
        iVar1 = **(int **)(param_1 + 0x2c);
        *(int *)(param_1 + 0x2c) = iVar1;
        *(undefined4 *)(iVar1 + 4) = 0;
      }
      else if (piVar2 == *(int **)(param_1 + 0x30)) {
        puVar4 = (undefined4 *)(*(int **)(param_1 + 0x30))[1];
        *(undefined4 **)(param_1 + 0x30) = puVar4;
        *puVar4 = 0;
      }
      else {
        *(int *)piVar2[1] = *piVar2;
        *(int *)(*piVar2 + 4) = piVar2[1];
      }
    }
    operator_delete(piVar2);
    *this = *this + -1;
    if (*this == 0) {
      *(undefined4 *)(param_1 + 0x30) = 0;
      *(undefined4 *)(param_1 + 0x2c) = 0;
    }
    if (puVar3 != (undefined4 *)0x0) {
      (**(code **)*puVar3)(1);
    }
    iVar1 = *this;
  }
  return;
}



void __thiscall FUN_00419b80(void *this,undefined4 param_1)

{
  byte bVar1;
  undefined4 *this_00;
  undefined4 uVar2;
  undefined4 *puVar3;
  int local_14;
  undefined4 *local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041cc13;
  local_c = ExceptionList;
  bVar1 = (byte)DAT_00428400 ^ (byte)&stack0xffffffe0;
  ExceptionList = &local_c;
  local_10 = (undefined4 *)operator_new(0xb0);
  local_4 = 0;
  if (local_10 == (undefined4 *)0x0) {
    this_00 = (undefined4 *)0x0;
  }
  else {
    this_00 = FUN_00416340(local_10);
  }
  *(int *)((int)this + 0xe4) = *(int *)((int)this + 0xe4) + 1;
  local_4 = 0xffffffff;
  uVar2 = FUN_00416500(this_00,this,param_1,*(undefined4 *)((int)this + 0x3c),
                       *(undefined4 *)((int)this + 0xe4));
  if ((char)uVar2 == '\0') {
    FUN_004028b0("Can\'t create web server",bVar1);
    ExceptionList = local_c;
    return;
  }
  FUN_00402f40(&local_14,(int)this + 4);
  local_4 = 1;
  FUN_004164f0(this_00,0);
  uVar2 = *(undefined4 *)((int)this + 0x30);
  puVar3 = (undefined4 *)operator_new(0xc);
  puVar3[1] = uVar2;
  *puVar3 = 0;
  puVar3[2] = this_00;
  if (*(undefined4 **)((int)this + 0x30) == (undefined4 *)0x0) {
    *(undefined4 **)((int)this + 0x2c) = puVar3;
  }
  else {
    **(undefined4 **)((int)this + 0x30) = puVar3;
  }
  *(int *)((int)this + 0x28) = *(int *)((int)this + 0x28) + 1;
  *(undefined4 **)((int)this + 0x30) = puVar3;
  uVar2 = FUN_00416460((int)this_00);
  FUN_00402850("Create web request id:%d (count:%d)",(char)uVar2);
  local_4 = 0xffffffff;
  FUN_00402f90(&local_14);
  ExceptionList = local_c;
  return;
}



uint __thiscall FUN_00419cb0(void *this,void *param_1,void *param_2)

{
  undefined uVar1;
  char cVar2;
  uint uVar3;
  int iVar4;
  void *pvVar5;
  undefined4 uVar6;
  tm *ptVar7;
  int iVar8;
  undefined3 extraout_var;
  undefined unaff_BL;
  __time64_t _Var9;
  undefined4 local_2c;
  tm local_28;
  
  FUN_004118b0(&local_2c);
  if (param_1 == (void *)0x0) {
    uVar1 = 0x78;
    if (*(int *)((int)this + 0x40) != 0) {
      uVar1 = 0x6c;
    }
    uVar3 = FUN_00402890("WebServerManager MakeTrigger (WorkingMode:%s) lane is null",uVar1);
    return uVar3 & 0xffffff00;
  }
  uVar1 = 0x78;
  if (*(int *)((int)this + 0x40) != 0) {
    uVar1 = 0x6c;
  }
  FUN_0040bb90((int)param_1);
  FUN_00402890("WebServerManager MakeTrigger (WorkingMode:%s) lane \'(%d)\'",uVar1);
  if (*(int *)((int)this + 0x40) == 0) {
    FUN_0040c1c0(param_1,param_2);
    iVar4 = FUN_004164b0((int)param_2);
    pvVar5 = (void *)FUN_0040d190(param_1,iVar4);
    if (pvVar5 == (void *)0x0) {
      FUN_00402890("WebServerManager MakeTrigger any CarData available",unaff_BL);
    }
    else {
      FUN_004164b0((int)param_2);
      FUN_00416460((int)param_2);
      uVar6 = FUN_004087d0((int)pvVar5);
      FUN_00402890("WebServerManager MakeTrigger carData:%d webRequest:%d trigger:%d",(char)uVar6);
      FUN_0040a7e0(pvVar5,param_2);
      uVar6 = FUN_00408c80((int)pvVar5);
      if ((char)uVar6 != '\0') {
        FUN_004165a0(param_2,pvVar5);
      }
    }
    FUN_004164b0((int)param_2);
    uVar6 = FUN_0040bb90((int)param_1);
    uVar6 = FUN_00402870("WebServerManager MakeTrigger, lane \'%d\' trigger %d done",(char)uVar6);
    return CONCAT31((int3)((uint)uVar6 >> 8),1);
  }
  pvVar5 = (void *)FUN_0040d190(param_1,0);
  if (pvVar5 == (void *)0x0) {
    FUN_00402870("WebServerManager: MakeTrigger HW CarData not found.",unaff_BL);
    cVar2 = FUN_0040bc10((int)param_1);
    if (cVar2 == '\0') {
      FUN_00402870("WebServerManager: MakeTrigger > Waiting Unit recognition (AllowTriggerOnHWMode disabled)."
                   ,unaff_BL);
      uVar6 = FUN_0040c5c0(param_1,param_2);
      return CONCAT31((int3)((uint)uVar6 >> 8),1);
    }
  }
  else {
    ptVar7 = FUN_00403080(&local_28);
    _Var9 = FUN_00403040(ptVar7);
    iVar4 = FUN_00408800((int)pvVar5);
    FUN_0040bc00((int)param_1);
    ptVar7 = FUN_00403080(&local_28);
    FUN_00403040(ptVar7);
    FUN_00408800((int)pvVar5);
    uVar6 = FUN_004087d0((int)pvVar5);
    FUN_00402870("WebServerManager MakeTrigger recover carData:%d  (CarData Ticks:%d  System:%d = diff.Seconds:%d  (KeepLicenseSeconds:%d)"
                 ,(char)uVar6);
    iVar8 = FUN_0040bc00((int)param_1);
    if ((int)_Var9 - iVar4 < iVar8) {
      FUN_0040bc20((int)param_1);
      FUN_0040bc00((int)param_1);
      FUN_0040bb90((int)param_1);
      uVar6 = FUN_004087d0((int)pvVar5);
      FUN_00402870("WebServerManager MakeTrigger valid CarData:%d (secs:%d/Lane %d KeepLicenseSeconds:%d  RecognitionTimeSource:%s)"
                   ,(char)uVar6);
      FUN_0040a7e0(pvVar5,param_2);
      uVar6 = FUN_00408c80((int)pvVar5);
      if ((char)uVar6 != '\0') {
        uVar6 = FUN_004165a0(param_2,pvVar5);
        return CONCAT31((int3)((uint)uVar6 >> 8),1);
      }
      goto LAB_00419f7e;
    }
    FUN_0040bc20((int)param_1);
    FUN_0040bc00((int)param_1);
    FUN_0040bb90((int)param_1);
    uVar6 = FUN_004087d0((int)pvVar5);
    FUN_00402870("WebServerManager MakeTrigger invalid CarData:%d , too older (secs:%d/Lane %d KeepLicenseSeconds:%d  RecognitionTimeSource:%s)"
                 ,(char)uVar6);
    cVar2 = FUN_0040bc10((int)param_1);
    if (cVar2 == '\0') {
      uVar6 = FUN_0040c5c0(param_1,param_2);
      return CONCAT31((int3)((uint)uVar6 >> 8),1);
    }
  }
  cVar2 = FUN_0040bc10((int)param_1);
  if (cVar2 != '\0') {
    FUN_00402870("WebServerManager: MakeTrigger AllowTriggerOnHardwareMode ...",unaff_BL);
    FUN_0040c1c0(param_1,param_2);
    return CONCAT31(extraout_var,1);
  }
  FUN_004164c0((int)param_2);
  uVar6 = FUN_0040bb90((int)param_1);
  uVar6 = FUN_00402870("WebServerManager: MakeTrigger, lane \'%s\' Waiting license plate hardware recognition..."
                       ,(char)uVar6);
LAB_00419f7e:
  return CONCAT31((int3)((uint)uVar6 >> 8),1);
}



void __thiscall FUN_00419f90(void *this,int param_1)

{
  int **ppiVar1;
  undefined4 uVar2;
  int local_14;
  undefined4 local_10;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041cc38;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  FUN_00402f40(&local_14,(int)this + 4);
  local_4 = 0;
  ppiVar1 = (int **)FUN_00408af0((void *)((int)this + 0x28),&local_10);
  ppiVar1 = (int **)*ppiVar1;
  do {
    if (ppiVar1 == (int **)0x0) {
      uVar2 = FUN_00416460(param_1);
      FUN_00402870("WebServerManager: ReleaseWebRequest webRequest:%d (not found)",(char)uVar2);
LAB_0041a003:
      local_4 = 0xffffffff;
      FUN_00402f90(&local_14);
      ExceptionList = local_c;
      return;
    }
    if (ppiVar1[2] == (int *)param_1) {
      uVar2 = FUN_00416460(param_1);
      FUN_00402870("WebServerManager ReleaseWebRequest webRequest:%d (found)",(char)uVar2);
      FUN_0040ae30((void *)((int)this + 0x28),(int *)ppiVar1);
      goto LAB_0041a003;
    }
    ppiVar1 = (int **)*ppiVar1;
  } while( true );
}



void __fastcall FUN_0041a050(int param_1)

{
  void *this;
  int *piVar1;
  char cVar2;
  int **ppiVar3;
  int iVar4;
  undefined4 local_8;
  undefined4 local_4;
  
  this = (void *)(param_1 + 0x28);
  if (*(int *)(param_1 + 0x28) != 0) {
    FUN_00402ed0(param_1 + 4);
    ppiVar3 = (int **)FUN_00408af0(this,&local_8);
    ppiVar3 = (int **)*ppiVar3;
    while (ppiVar3 != (int **)0x0) {
      piVar1 = ppiVar3[2];
      cVar2 = FUN_00416490((int)piVar1);
      if (cVar2 == '\0') {
        ppiVar3 = (int **)*ppiVar3;
      }
      else {
        FUN_0040ae30(this,(int *)ppiVar3);
        iVar4 = FUN_004164e0((int)piVar1);
        if ((iVar4 == 0) && (FUN_00416570(piVar1), piVar1 != (int *)0x0)) {
          (**(code **)*piVar1)(1);
        }
        ppiVar3 = (int **)FUN_00408af0(this,&local_4);
        ppiVar3 = (int **)*ppiVar3;
      }
    }
    FUN_00402f10(param_1 + 4);
  }
  return;
}



undefined4 __fastcall FUN_0041a0e0(int param_1,undefined param_2,undefined param_3)

{
  void *this;
  undefined4 uVar1;
  int *piVar2;
  undefined1 *puVar3;
  undefined4 uStack_28;
  undefined4 *local_14 [2];
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_0041cc68;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  local_14[0] = &uStack_28;
  local_4 = 0;
  FUN_004010b0(&uStack_28,(void **)&param_3);
  piVar2 = FUN_00417fa0(*(void **)(param_1 + 0x34),local_14);
  this = (void *)piVar2[1];
  if (*piVar2 == 0) {
    puVar3 = FUN_004011f0((undefined4 *)&param_3);
    uStack_28 = 0x41a14b;
    FUN_00402890("WebServerManager GetLane not found \'%s\'",(char)puVar3);
    local_4 = 0xffffffff;
    FUN_00401170((void **)&param_3);
    ExceptionList = local_c;
    return 0;
  }
  local_14[0] = &uStack_28;
  FUN_004010b0(&uStack_28,(void **)(*piVar2 + 8));
  piVar2 = FUN_00409340(this,local_14);
  uVar1 = *(undefined4 *)(*piVar2 + 0x14);
  local_4 = 0xffffffff;
  FUN_00401170((void **)&param_3);
  ExceptionList = local_c;
  return uVar1;
}



undefined4 __thiscall
FUN_0041a174(void *this,undefined param_1,undefined *param_2,undefined param_3,void *param_4,
            undefined param_5,undefined4 param_6,undefined param_7,undefined param_8)

{
  undefined4 uVar1;
  int *piVar2;
  void *unaff_ESI;
  undefined auStack_c [8];
  undefined4 uStack_4;
  
  param_2 = auStack_c;
  FUN_004010b0(auStack_c,(void **)((int)this + 8));
  piVar2 = FUN_00409340(unaff_ESI,&param_2);
  uVar1 = *(undefined4 *)(*piVar2 + 0x14);
  param_6 = 0xffffffff;
  uStack_4 = 0x41a1a8;
  FUN_00401170((void **)&param_8);
  ExceptionList = param_4;
  return uVar1;
}



int WSAGetLastError(void)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041a1be. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = WSAGetLastError();
  return iVar1;
}



int gethostname(char *name,int namelen)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041a1c4. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = gethostname(name,namelen);
  return iVar1;
}



int WSAStartup(WORD wVersionRequired,LPWSADATA lpWSAData)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041a1ca. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = WSAStartup(wVersionRequired,lpWSAData);
  return iVar1;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041a246. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041a1d6. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



// Library Function - Single Match
//  @__security_check_cookie@4
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __fastcall ___security_check_cookie_4(int param_1)

{
  if (param_1 == DAT_00428400) {
    return;
  }
                    // WARNING: Subroutine does not return
  ___report_gsfailure();
}



// Library Function - Multiple Matches With Different Base Names
//  public: virtual void * __thiscall exception::`vector deleting destructor'(unsigned int)
//  public: virtual void * __thiscall std::exception::`vector deleting destructor'(unsigned int)
//  public: virtual void * __thiscall logic_error::`vector deleting destructor'(unsigned int)
//  public: virtual void * __thiscall type_info::`vector deleting destructor'(unsigned int)
// 
// Library: Visual Studio 2005 Release

int * __thiscall FID_conflict__vector_deleting_destructor_(void *this,byte param_1)

{
  int *piVar1;
  
  if ((param_1 & 2) == 0) {
    type_info::_type_info_dtor_internal_method((type_info *)this);
    piVar1 = (int *)this;
    if ((param_1 & 1) != 0) {
      operator_delete(this);
    }
  }
  else {
    piVar1 = (int *)((int)this + -4);
    _eh_vector_destructor_iterator_(this,0xc,*piVar1,type_info::_type_info_dtor_internal_method);
    if ((param_1 & 1) != 0) {
      operator_delete(piVar1);
    }
  }
  return piVar1;
}



void _purecall(void)

{
                    // WARNING: Could not recover jumptable at 0x0041a23a. Too many branches
                    // WARNING: Treating indirect jump as call
  _purecall();
  return;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x0041a240. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041a246. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __cdecl operator_delete__(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x0041a24c. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete__(param_1);
  return;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041a252. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  void __stdcall __ArrayUnwind(void *,unsigned int,int,void (__thiscall*)(void *))
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __ArrayUnwind(void *param_1,uint param_2,int param_3,_func_void_void_ptr *param_4)

{
  void *in_stack_ffffffc8;
  
  while( true ) {
    param_3 = param_3 + -1;
    if (param_3 < 0) break;
    (*param_4)(in_stack_ffffffc8);
  }
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  void __stdcall `eh vector destructor iterator'(void *,unsigned int,int,void (__thiscall*)(void
// *))
// 
// Library: Visual Studio 2005 Release

void _eh_vector_destructor_iterator_
               (void *param_1,uint param_2,int param_3,_func_void_void_ptr *param_4)

{
  void *in_stack_ffffffd0;
  
  while( true ) {
    param_3 = param_3 + -1;
    if (param_3 < 0) break;
    (*param_4)(in_stack_ffffffd0);
  }
  FUN_0041a301();
  return;
}



void FUN_0041a301(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) == 0) {
    __ArrayUnwind(*(void **)(unaff_EBP + 8),*(uint *)(unaff_EBP + 0xc),*(int *)(unaff_EBP + 0x10),
                  *(_func_void_void_ptr **)(unaff_EBP + 0x14));
  }
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  void __stdcall `eh vector constructor iterator'(void *,unsigned int,int,void (__thiscall*)(void
// *),void (__thiscall*)(void *))
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void _eh_vector_constructor_iterator_
               (void *param_1,uint param_2,int param_3,_func_void_void_ptr *param_4,
               _func_void_void_ptr *param_5)

{
  void *in_stack_ffffffcc;
  int local_20;
  
  for (local_20 = 0; local_20 < param_3; local_20 = local_20 + 1) {
    (*param_4)(in_stack_ffffffcc);
  }
  FUN_0041a366();
  return;
}



void FUN_0041a366(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x20) == 0) {
    __ArrayUnwind(*(void **)(unaff_EBP + 8),*(uint *)(unaff_EBP + 0xc),*(int *)(unaff_EBP + -0x1c),
                  *(_func_void_void_ptr **)(unaff_EBP + 0x18));
  }
  return;
}



// Library Function - Single Match
//  __allmul
// 
// Library: Visual Studio

longlong __allmul(uint param_1,uint param_2,uint param_3,uint param_4)

{
  if ((param_4 | param_2) == 0) {
    return (ulonglong)param_1 * (ulonglong)param_3;
  }
  return CONCAT44((int)((ulonglong)param_1 * (ulonglong)param_3 >> 0x20) +
                  param_2 * param_3 + param_1 * param_4,
                  (int)((ulonglong)param_1 * (ulonglong)param_3));
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

_onexit_t __cdecl FUN_0041a3b4(_onexit_t param_1)

{
  _onexit_t p_Var1;
  undefined4 local_24;
  int local_20 [5];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00426ff0;
  uStack_c = 0x41a3c0;
  local_20[0] = _decode_pointer(DAT_0042b928);
  if (local_20[0] == -1) {
    p_Var1 = _onexit(param_1);
  }
  else {
    _lock(8);
    local_8 = (undefined *)0x0;
    local_20[0] = _decode_pointer(DAT_0042b928);
    local_24 = _decode_pointer(DAT_0042b924);
    p_Var1 = (_onexit_t)__dllonexit(param_1,local_20,&local_24);
    DAT_0042b928 = _encode_pointer(local_20[0]);
    DAT_0042b924 = _encode_pointer(local_24);
    local_8 = (undefined *)0xfffffffe;
    FUN_0041a44a();
  }
  return p_Var1;
}



void FUN_0041a44a(void)

{
  _unlock(8);
  return;
}



int __cdecl FUN_0041a453(_onexit_t param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = FUN_0041a3b4(param_1);
  return (p_Var1 != (_onexit_t)0x0) - 1;
}



// Library Function - Single Match
//  __alldvrm
// 
// Library: Visual Studio

undefined8 __alldvrm(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  bool bVar10;
  char cVar11;
  uint uVar9;
  
  cVar11 = (int)param_2 < 0;
  if ((bool)cVar11) {
    bVar10 = param_1 != 0;
    param_1 = -param_1;
    param_2 = -(uint)bVar10 - param_2;
  }
  if ((int)param_4 < 0) {
    cVar11 = cVar11 + '\x01';
    bVar10 = param_3 != 0;
    param_3 = -param_3;
    param_4 = -(uint)bVar10 - param_4;
  }
  uVar3 = param_1;
  uVar5 = param_3;
  uVar6 = param_2;
  uVar9 = param_4;
  if (param_4 == 0) {
    uVar3 = param_2 / param_3;
    iVar4 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) /
                 (ulonglong)param_3);
  }
  else {
    do {
      uVar8 = uVar9 >> 1;
      uVar5 = uVar5 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar7 = uVar6 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar6 & 1) != 0) << 0x1f;
      uVar6 = uVar7;
      uVar9 = uVar8;
    } while (uVar8 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar5;
    iVar4 = (int)uVar1;
    lVar2 = (ulonglong)param_3 * (uVar1 & 0xffffffff);
    uVar3 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar5 = uVar3 + iVar4 * param_4;
    if (((CARRY4(uVar3,iVar4 * param_4)) || (param_2 < uVar5)) ||
       ((param_2 <= uVar5 && (param_1 < (uint)lVar2)))) {
      iVar4 = iVar4 + -1;
    }
    uVar3 = 0;
  }
  if (cVar11 == '\x01') {
    bVar10 = iVar4 != 0;
    iVar4 = -iVar4;
    uVar3 = -(uint)bVar10 - uVar3;
  }
  return CONCAT44(uVar3,iVar4);
}



// WARNING: This is an inlined function

void __alloca_probe(void)

{
  undefined *in_EAX;
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 unaff_retaddr;
  undefined auStack_4 [4];
  
  puVar2 = (undefined4 *)((int)&stack0x00000000 - (int)in_EAX & ~-(uint)(&stack0x00000000 < in_EAX))
  ;
  for (puVar1 = (undefined4 *)((uint)auStack_4 & 0xfffff000); puVar2 < puVar1;
      puVar1 = puVar1 + -0x400) {
  }
  *puVar2 = unaff_retaddr;
  return;
}



ulonglong __fastcall FUN_0041a580(undefined4 param_1,undefined4 param_2)

{
  ulonglong uVar1;
  uint uVar2;
  float fVar3;
  float10 in_ST0;
  uint local_20;
  float fStack_1c;
  
  if (DAT_0042b91c == 0) {
    uVar1 = (ulonglong)ROUND(in_ST0);
    local_20 = (uint)uVar1;
    fStack_1c = (float)(uVar1 >> 0x20);
    fVar3 = (float)in_ST0;
    if ((local_20 != 0) || (fVar3 = fStack_1c, (uVar1 & 0x7fffffff00000000) != 0)) {
      if ((int)fVar3 < 0) {
        uVar1 = uVar1 + (0x80000000 < ((uint)(float)(in_ST0 - (float10)uVar1) ^ 0x80000000));
      }
      else {
        uVar2 = (uint)(0x80000000 < (uint)(float)(in_ST0 - (float10)uVar1));
        uVar1 = CONCAT44((int)fStack_1c - (uint)(local_20 < uVar2),local_20 - uVar2);
      }
    }
    return uVar1;
  }
  return CONCAT44(param_2,(int)in_ST0);
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___tmainCRTStartup
// 
// Library: Visual Studio 2005 Release

int ___tmainCRTStartup(void)

{
  byte bVar1;
  void *Exchange;
  void *pvVar2;
  BOOL BVar3;
  int iVar4;
  bool bVar5;
  byte *pbVar6;
  _STARTUPINFOA local_6c;
  byte *local_24;
  uint local_20;
  undefined4 uStack_c;
  undefined4 local_8;
  
  uStack_c = 0x41a682;
  bVar5 = false;
  local_20 = 0;
  local_8 = 0;
  GetStartupInfoA(&local_6c);
  Exchange = StackBase;
  local_8 = 1;
  do {
    pvVar2 = (void *)InterlockedCompareExchange((LONG *)&DAT_0042b918,(LONG)Exchange,0);
    if (pvVar2 == (void *)0x0) {
LAB_0041a6d9:
      if (DAT_0042b914 == 1) {
        _amsg_exit(0x1f);
      }
      else if (DAT_0042b914 == 0) {
        DAT_0042b914 = 1;
        iVar4 = _initterm_e(&DAT_0041e2a8,&DAT_0041e2b4);
        if (iVar4 != 0) {
          return 0xff;
        }
      }
      else {
        DAT_0042b200 = 1;
      }
      if (DAT_0042b914 == 1) {
        _initterm(&DAT_0041e280,&DAT_0041e2a4);
        DAT_0042b914 = 2;
      }
      if (!bVar5) {
        InterlockedExchange((LONG *)&DAT_0042b918,0);
      }
      if ((DAT_0042b920 != (code *)0x0) &&
         (BVar3 = __IsNonwritableInCurrentImage((PBYTE)&DAT_0042b920), BVar3 != 0)) {
        (*DAT_0042b920)(0,2,0);
      }
      pbVar6 = *(byte **)_acmdln_exref;
      while ((bVar1 = *pbVar6, local_24 = pbVar6, 0x20 < bVar1 || ((bVar1 != 0 && (local_20 != 0))))
            ) {
        if (bVar1 == 0x22) {
          local_20 = (uint)(local_20 == 0);
        }
        iVar4 = _ismbblead((uint)bVar1);
        if (iVar4 != 0) {
          pbVar6 = pbVar6 + 1;
        }
        pbVar6 = pbVar6 + 1;
      }
      for (; (*local_24 != 0 && (*local_24 < 0x21)); local_24 = local_24 + 1) {
      }
      DAT_0042b1fc = FUN_004100c0((HINSTANCE)&IMAGE_DOS_HEADER_00400000,0,(char *)local_24);
      if (DAT_0042b1f0 != 0) {
        if (DAT_0042b200 == 0) {
          _cexit();
        }
        return DAT_0042b1fc;
      }
                    // WARNING: Subroutine does not return
      exit(DAT_0042b1fc);
    }
    if (pvVar2 == Exchange) {
      bVar5 = true;
      goto LAB_0041a6d9;
    }
    Sleep(1000);
  } while( true );
}



void entry(void)

{
  ___security_init_cookie();
  ___tmainCRTStartup();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___report_gsfailure
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl ___report_gsfailure(void)

{
  undefined4 in_EAX;
  HANDLE hProcess;
  undefined4 in_ECX;
  undefined4 in_EDX;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined2 in_CS;
  undefined2 in_SS;
  undefined2 in_DS;
  undefined2 in_FS;
  undefined2 in_GS;
  byte in_AF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined4 unaff_retaddr;
  UINT uExitCode;
  undefined4 local_32c;
  undefined4 local_328;
  
  _DAT_0042b320 =
       (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4((int)&stack0xfffffffc,0x328) * 0x800 |
       (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)&local_32c < 0) * 0x80 |
       (uint)(&stack0x00000000 == (undefined *)0x32c) * 0x40 | (uint)(in_AF & 1) * 0x10 |
       (uint)((POPCOUNT((uint)&local_32c & 0xff) & 1U) == 0) * 4 |
       (uint)(&stack0xfffffffc < (undefined *)0x328) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  _DAT_0042b324 = &stack0x00000004;
  _DAT_0042b260 = 0x10001;
  _DAT_0042b208 = 0xc0000409;
  _DAT_0042b20c = 1;
  local_32c = DAT_00428400;
  local_328 = DAT_00428404;
  _DAT_0042b214 = unaff_retaddr;
  _DAT_0042b2ec = in_GS;
  _DAT_0042b2f0 = in_FS;
  _DAT_0042b2f4 = in_ES;
  _DAT_0042b2f8 = in_DS;
  _DAT_0042b2fc = unaff_EDI;
  _DAT_0042b300 = unaff_ESI;
  _DAT_0042b304 = unaff_EBX;
  _DAT_0042b308 = in_EDX;
  _DAT_0042b30c = in_ECX;
  _DAT_0042b310 = in_EAX;
  _DAT_0042b314 = unaff_EBP;
  DAT_0042b318 = unaff_retaddr;
  _DAT_0042b31c = in_CS;
  _DAT_0042b328 = in_SS;
  DAT_0042b258 = IsDebuggerPresent();
  _crt_debugger_hook(1);
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&PTR_DAT_00423630);
  if (DAT_0042b258 == 0) {
    _crt_debugger_hook(1);
  }
  uExitCode = 0xc0000409;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



// WARNING: This is an inlined function
// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_2
// Library Function - Single Match
//  __SEH_prolog4
// 
// Library: Visual Studio

void __cdecl __SEH_prolog4(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 unaff_EBX;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined local_8 [8];
  
  iVar1 = -param_2;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00428400 ^ (uint)&param_2;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  ExceptionList = local_8;
  return;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __SEH_epilog4
// 
// Library: Visual Studio

void __SEH_epilog4(void)

{
  undefined4 *unaff_EBP;
  undefined4 unaff_retaddr;
  
  ExceptionList = (void *)unaff_EBP[-4];
  *unaff_EBP = unaff_retaddr;
  return;
}



void __cdecl _unlock(int _File)

{
                    // WARNING: Could not recover jumptable at 0x0041aac8. Too many branches
                    // WARNING: Treating indirect jump as call
  _unlock(_File);
  return;
}



void __dllonexit(void)

{
                    // WARNING: Could not recover jumptable at 0x0041aace. Too many branches
                    // WARNING: Treating indirect jump as call
  __dllonexit();
  return;
}



void __cdecl _lock(int _File)

{
                    // WARNING: Could not recover jumptable at 0x0041aad4. Too many branches
                    // WARNING: Treating indirect jump as call
  _lock(_File);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0041aada(void)

{
  return 1;
}



// WARNING: Removing unreachable block (ram,0x0041ab65)
// WARNING: Removing unreachable block (ram,0x0041ab52)
// Library Function - Single Match
//  __get_sse2_info
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

undefined4 __get_sse2_info(void)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  byte in_AF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  uint uVar4;
  uint local_8;
  
  local_8 = 0;
  uVar4 = (uint)(in_NT & 1) * 0x4000 | (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | 0x40
          | (uint)(in_AF & 1) * 0x10 | 4 | (uint)(in_ID & 1) * 0x200000 |
          (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000
  ;
  uVar1 = uVar4 ^ 0x200000;
  if (((uint)((uVar1 & 0x4000) != 0) * 0x4000 | (uint)((uVar1 & 0x400) != 0) * 0x400 |
       (uint)((uVar1 & 0x200) != 0) * 0x200 | (uint)((uVar1 & 0x100) != 0) * 0x100 |
       (uint)((uVar1 & 0x40) != 0) * 0x40 | (uint)((uVar1 & 0x10) != 0) * 0x10 |
       (uint)((uVar1 & 4) != 0) * 4 | (uint)((uVar1 & 0x200000) != 0) * 0x200000 |
      (uint)((uVar1 & 0x40000) != 0) * 0x40000) != uVar4) {
    cpuid_basic_info(0);
    iVar2 = cpuid_Version_info(1);
    local_8 = *(uint *)(iVar2 + 8);
  }
  if (((local_8 & 0x4000000) == 0) || (iVar2 = FUN_0041aada(), iVar2 == 0)) {
    uVar3 = 0;
  }
  else {
    uVar3 = 1;
  }
  return uVar3;
}



void __cdecl _amsg_exit(int param_1)

{
                    // WARNING: Could not recover jumptable at 0x0041ab98. Too many branches
                    // WARNING: Treating indirect jump as call
  _amsg_exit(param_1);
  return;
}



// Library Function - Single Match
//  __ValidateImageBase
// 
// Library: Visual Studio 2005 Release

BOOL __cdecl __ValidateImageBase(PBYTE pImageBase)

{
  if ((*(short *)pImageBase == 0x5a4d) &&
     (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550)) {
    return (uint)(*(short *)((int)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) == 0x10b);
  }
  return 0;
}



// Library Function - Single Match
//  __FindPESection
// 
// Library: Visual Studio 2005 Release

PIMAGE_SECTION_HEADER __cdecl __FindPESection(PBYTE pImageBase,DWORD_PTR rva)

{
  int iVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  uint uVar3;
  
  iVar1 = *(int *)(pImageBase + 0x3c);
  uVar3 = 0;
  p_Var2 = (PIMAGE_SECTION_HEADER)
           (pImageBase + *(ushort *)(pImageBase + iVar1 + 0x14) + 0x18 + iVar1);
  if (*(ushort *)(pImageBase + iVar1 + 6) != 0) {
    do {
      if ((p_Var2->VirtualAddress <= rva) &&
         (rva < (p_Var2->Misc).PhysicalAddress + p_Var2->VirtualAddress)) {
        return p_Var2;
      }
      uVar3 = uVar3 + 1;
      p_Var2 = p_Var2 + 1;
    } while (uVar3 < *(ushort *)(pImageBase + iVar1 + 6));
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __IsNonwritableInCurrentImage
// 
// Library: Visual Studio 2005 Release

BOOL __cdecl __IsNonwritableInCurrentImage(PBYTE pTarget)

{
  BOOL BVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  PBYTE pImageBase;
  
  BVar1 = __ValidateImageBase((PBYTE)&IMAGE_DOS_HEADER_00400000);
  if ((BVar1 != 0) &&
     (p_Var2 = __FindPESection(pImageBase,(int)pTarget - (int)pImageBase),
     p_Var2 != (PIMAGE_SECTION_HEADER)0x0)) {
    return ~(p_Var2->Characteristics >> 0x1f) & 1;
  }
  return 0;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x0041acce. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void _initterm_e(void)

{
                    // WARNING: Could not recover jumptable at 0x0041acd4. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm_e();
  return;
}



// Library Function - Single Match
//  ___security_init_cookie
// 
// Library: Visual Studio 2005 Release

void __cdecl ___security_init_cookie(void)

{
  DWORD DVar1;
  DWORD DVar2;
  DWORD DVar3;
  uint uVar4;
  LARGE_INTEGER local_14;
  _FILETIME local_c;
  
  local_c.dwLowDateTime = 0;
  local_c.dwHighDateTime = 0;
  if ((DAT_00428400 == 0xbb40e64e) || ((DAT_00428400 & 0xffff0000) == 0)) {
    GetSystemTimeAsFileTime(&local_c);
    uVar4 = local_c.dwHighDateTime ^ local_c.dwLowDateTime;
    DVar1 = GetCurrentProcessId();
    DVar2 = GetCurrentThreadId();
    DVar3 = GetTickCount();
    QueryPerformanceCounter(&local_14);
    DAT_00428400 = uVar4 ^ DVar1 ^ DVar2 ^ DVar3 ^ local_14.s.HighPart ^ local_14.s.LowPart;
    if (DAT_00428400 == 0xbb40e64e) {
      DAT_00428400 = 0xbb40e64f;
    }
    else if ((DAT_00428400 & 0xffff0000) == 0) {
      DAT_00428400 = DAT_00428400 | DAT_00428400 << 0x10;
    }
    DAT_00428404 = ~DAT_00428400;
  }
  else {
    DAT_00428404 = ~DAT_00428400;
  }
  return;
}



void __cdecl _crt_debugger_hook(int param_1)

{
                    // WARNING: Could not recover jumptable at 0x0041ad9a. Too many branches
                    // WARNING: Treating indirect jump as call
  _crt_debugger_hook(param_1);
  return;
}



void __thiscall type_info::_type_info_dtor_internal_method(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x0041ada0. Too many branches
                    // WARNING: Treating indirect jump as call
  _type_info_dtor_internal_method(this);
  return;
}



void _except_handler4_common(void)

{
                    // WARNING: Could not recover jumptable at 0x0041ada6. Too many branches
                    // WARNING: Treating indirect jump as call
  _except_handler4_common();
  return;
}



SOCKET accept(SOCKET s,sockaddr *addr,int *addrlen)

{
  SOCKET SVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041adb8. Too many branches
                    // WARNING: Treating indirect jump as call
  SVar1 = accept(s,addr,addrlen);
  return SVar1;
}



int listen(SOCKET s,int backlog)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041adbe. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = listen(s,backlog);
  return iVar1;
}



int send(SOCKET s,char *buf,int len,int flags)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041adc4. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = send(s,buf,len,flags);
  return iVar1;
}



int closesocket(SOCKET s)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041adca. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = closesocket(s);
  return iVar1;
}



SOCKET socket(int af,int type,int protocol)

{
  SOCKET SVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041add0. Too many branches
                    // WARNING: Treating indirect jump as call
  SVar1 = socket(af,type,protocol);
  return SVar1;
}



int bind(SOCKET s,sockaddr *addr,int namelen)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041add6. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = bind(s,addr,namelen);
  return iVar1;
}



int recv(SOCKET s,char *buf,int len,int flags)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041addc. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = recv(s,buf,len,flags);
  return iVar1;
}



int setsockopt(SOCKET s,int level,int optname,char *optval,int optlen)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041ade2. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = setsockopt(s,level,optname,optval,optlen);
  return iVar1;
}



u_short htons(u_short hostshort)

{
  u_short uVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041ade8. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = htons(hostshort);
  return uVar1;
}



int select(int nfds,fd_set *readfds,fd_set *writefds,fd_set *exceptfds,timeval *timeout)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041adee. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = select(nfds,readfds,writefds,exceptfds,timeout);
  return iVar1;
}



void Unwind_0041ae00(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0x18));
  return;
}



void Unwind_0041ae08(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x30));
  return;
}



void Unwind_0041ae10(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x34) & 1) != 0) {
    *(uint *)(unaff_EBP + -0x34) = *(uint *)(unaff_EBP + -0x34) & 0xfffffffe;
    FUN_00401170(*(void ***)(unaff_EBP + 4));
    return;
  }
  return;
}



void Unwind_0041ae29(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0041ae31(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041ae39(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0041ae60(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0041ae90(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 4));
  return;
}



void Unwind_0041aec0(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0041aef0(void)

{
  int unaff_EBP;
  
  FUN_00411740((int *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0041af20(void)

{
  int unaff_EBP;
  
  FUN_00411740((int *)(unaff_EBP + 4));
  return;
}



void Unwind_0041af28(void)

{
  int unaff_EBP;
  
  FUN_00411740((int *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_0041af50(void)

{
  int unaff_EBP;
  
  FUN_00411740((int *)(unaff_EBP + -200));
  return;
}



void Unwind_0041af5b(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0xbc) & 1) != 0) {
    *(uint *)(unaff_EBP + -0xbc) = *(uint *)(unaff_EBP + -0xbc) & 0xfffffffe;
    FUN_00411740(*(int **)(unaff_EBP + -0xb0));
    return;
  }
  return;
}



void Unwind_0041af7d(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x9c));
  return;
}



void Unwind_0041afc0(void)

{
  int unaff_EBP;
  
  FUN_00411740((int *)(unaff_EBP + 4));
  return;
}



void Unwind_0041aff0(void)

{
  int unaff_EBP;
  
  FUN_00411740((int *)(unaff_EBP + 4));
  return;
}



void Unwind_0041aff8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x80));
  return;
}



void Unwind_0041b000(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x68));
  return;
}



void Unwind_0041b008(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x74));
  return;
}



void Unwind_0041b010(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x74));
  return;
}



void Unwind_0041b018(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x68));
  return;
}



void Unwind_0041b020(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x74));
  return;
}



void Unwind_0041b028(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x68));
  return;
}



void Unwind_0041b060(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0x1c));
  return;
}



void Unwind_0041b068(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0x10));
  return;
}



void Unwind_0041b070(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x38) + 100));
  return;
}



void Unwind_0041b07b(void)

{
  int unaff_EBP;
  
  FUN_00402a30((undefined4 *)(*(int *)(unaff_EBP + -0x38) + 0x7c));
  return;
}



void Unwind_0041b086(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x38) + 0x120));
  return;
}



void Unwind_0041b094(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x38) + 300));
  return;
}



void Unwind_0041b0a2(void)

{
  int unaff_EBP;
  
  FUN_00402eb0((undefined4 *)(*(int *)(unaff_EBP + -0x38) + 0x13c));
  return;
}



void Unwind_0041b0b0(void)

{
  int unaff_EBP;
  
  FUN_00409c50((undefined4 *)(*(int *)(unaff_EBP + -0x38) + 0x164));
  return;
}



void Unwind_0041b0be(void)

{
  int unaff_EBP;
  
  FUN_00412c00((int *)(*(int *)(unaff_EBP + -0x38) + 0x180));
  return;
}



void Unwind_0041b0cc(void)

{
  int unaff_EBP;
  
  FUN_00412c00((int *)(*(int *)(unaff_EBP + -0x38) + 0x18c));
  return;
}



void Unwind_0041b0da(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x38) + 0x198));
  return;
}



void Unwind_0041b0e8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x38) + 0x1a4));
  return;
}



void Unwind_0041b0f6(void)

{
  int unaff_EBP;
  
  FUN_004093c0((int *)(*(int *)(unaff_EBP + -0x38) + 0x1b8));
  return;
}



void Unwind_0041b104(void)

{
  int unaff_EBP;
  
  FUN_00409b70((undefined4 *)(*(int *)(unaff_EBP + -0x38) + 0x1c4));
  return;
}



void Unwind_0041b130(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x2c) + 100));
  return;
}



void Unwind_0041b13b(void)

{
  int unaff_EBP;
  
  FUN_00402a30((undefined4 *)(*(int *)(unaff_EBP + -0x2c) + 0x7c));
  return;
}



void Unwind_0041b146(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x2c) + 0x120));
  return;
}



void Unwind_0041b154(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x2c) + 300));
  return;
}



void Unwind_0041b162(void)

{
  int unaff_EBP;
  
  FUN_00402eb0((undefined4 *)(*(int *)(unaff_EBP + -0x2c) + 0x13c));
  return;
}



void Unwind_0041b170(void)

{
  int unaff_EBP;
  
  FUN_00409c50((undefined4 *)(*(int *)(unaff_EBP + -0x2c) + 0x164));
  return;
}



void Unwind_0041b17e(void)

{
  int unaff_EBP;
  
  FUN_00412c00((int *)(*(int *)(unaff_EBP + -0x2c) + 0x180));
  return;
}



void Unwind_0041b18c(void)

{
  int unaff_EBP;
  
  FUN_00412c00((int *)(*(int *)(unaff_EBP + -0x2c) + 0x18c));
  return;
}



void Unwind_0041b19a(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x2c) + 0x198));
  return;
}



void Unwind_0041b1a8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x2c) + 0x1a4));
  return;
}



void Unwind_0041b1b6(void)

{
  int unaff_EBP;
  
  FUN_004093c0((int *)(*(int *)(unaff_EBP + -0x2c) + 0x1b8));
  return;
}



void Unwind_0041b1c4(void)

{
  int unaff_EBP;
  
  FUN_00409b70((undefined4 *)(*(int *)(unaff_EBP + -0x2c) + 0x1c4));
  return;
}



void Unwind_0041b1d2(void)

{
  int unaff_EBP;
  
  FUN_00411740((int *)(unaff_EBP + -0x38));
  return;
}



void Unwind_0041b1da(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x20));
  return;
}



void Unwind_0041b1e2(void)

{
  int unaff_EBP;
  
  FUN_00411740((int *)(unaff_EBP + -0x34));
  return;
}



void Unwind_0041b210(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0x2c));
  return;
}



void Unwind_0041b218(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0x1c));
  return;
}



void Unwind_0041b220(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 4));
  return;
}



void Unwind_0041b228(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x20));
  return;
}



void Unwind_0041b233(void)

{
  int unaff_EBP;
  
  FUN_00401170(*(void ***)(unaff_EBP + 0x38));
  return;
}



void Unwind_0041b23b(void)

{
  int unaff_EBP;
  
  FUN_00401170(*(void ***)(unaff_EBP + 0x28));
  return;
}



void Unwind_0041b243(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x24) & 1) != 0) {
    *(uint *)(unaff_EBP + -0x24) = *(uint *)(unaff_EBP + -0x24) & 0xfffffffe;
    FUN_00401170((void **)(unaff_EBP + -0x18));
    return;
  }
  return;
}



void Unwind_0041b280(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0x2c));
  return;
}



void Unwind_0041b288(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0x1c));
  return;
}



void Unwind_0041b290(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0x10));
  return;
}



void Unwind_0041b298(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_0041b2a3(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x18));
  return;
}



void Unwind_0041b2ae(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x4c));
  return;
}



void Unwind_0041b2e0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x14) + 0xc));
  return;
}



void Unwind_0041b2eb(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x14) + 0x18));
  return;
}



void Unwind_0041b2f6(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x14) + 0x4c));
  return;
}



void Unwind_0041b320(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_0041b350(void)

{
  int unaff_EBP;
  
  FUN_00403de0((undefined4 *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_0041b380(void)

{
  int unaff_EBP;
  
  FUN_00403de0((undefined4 *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_0041b3b0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041b3b8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x1c) + 0xc));
  return;
}



void Unwind_0041b3e0(void)

{
  int unaff_EBP;
  
  FUN_00406190((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_0041b3eb(void)

{
  int unaff_EBP;
  
  FUN_00406190((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x38));
  return;
}



void Unwind_0041b3f6(void)

{
  int unaff_EBP;
  
  FUN_00406190((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 100));
  return;
}



void Unwind_0041b401(void)

{
  int unaff_EBP;
  
  operator_delete__(*(void **)(unaff_EBP + 0xc));
  return;
}



void Unwind_0041b430(void)

{
  int unaff_EBP;
  
  FUN_00406190((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0xc));
  return;
}



void Unwind_0041b43b(void)

{
  int unaff_EBP;
  
  FUN_00406190((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x38));
  return;
}



void Unwind_0041b446(void)

{
  int unaff_EBP;
  
  FUN_00406190((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 100));
  return;
}



void Unwind_0041b470(void)

{
  int unaff_EBP;
  
  FUN_00403340(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0041b4a0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 4));
  return;
}



void Unwind_0041b4d0(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x30) & 1) != 0) {
    *(uint *)(unaff_EBP + -0x30) = *(uint *)(unaff_EBP + -0x30) & 0xfffffffe;
    FUN_00401170(*(void ***)(unaff_EBP + 4));
    return;
  }
  return;
}



void Unwind_0041b4e9(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0041b4f1(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041b520(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x24) & 1) != 0) {
    *(uint *)(unaff_EBP + -0x24) = *(uint *)(unaff_EBP + -0x24) & 0xfffffffe;
    FUN_00401170(*(void ***)(unaff_EBP + 4));
    return;
  }
  return;
}



void Unwind_0041b539(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041b560(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 8));
  return;
}



void Unwind_0041b568(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x264) & 1) != 0) {
    *(uint *)(unaff_EBP + -0x264) = *(uint *)(unaff_EBP + -0x264) & 0xfffffffe;
    FUN_00401170(*(void ***)(unaff_EBP + -0x260));
    return;
  }
  return;
}



void Unwind_0041b58a(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x270));
  return;
}



void Unwind_0041b595(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x25c));
  return;
}



void Unwind_0041b5d0(void)

{
  int unaff_EBP;
  
  FUN_00401170(*(void ***)(unaff_EBP + -0x10));
  return;
}



void Unwind_0041b600(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 8));
  return;
}



void Unwind_0041b60b(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x14));
  return;
}



void Unwind_0041b640(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x30));
  return;
}



void Unwind_0041b648(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x34) & 1) != 0) {
    *(uint *)(unaff_EBP + -0x34) = *(uint *)(unaff_EBP + -0x34) & 0xfffffffe;
    FUN_00401170(*(void ***)(unaff_EBP + 4));
    return;
  }
  return;
}



void Unwind_0041b661(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0041b669(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041b671(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041b6a0(void)

{
  FUN_004066f0();
  return;
}



void Unwind_0041b6d0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x68));
  return;
}



void Unwind_0041b6d8(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + -0x74));
  return;
}



void Unwind_0041b710(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + 4));
  return;
}



void Unwind_0041b718(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041b740(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0041b770(void)

{
  int unaff_EBP;
  
  FUN_00411740((int *)(unaff_EBP + 4));
  return;
}



void Unwind_0041b778(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x5c));
  return;
}



void Unwind_0041b7b0(void)

{
  int unaff_EBP;
  
  FUN_00411740((int *)(unaff_EBP + 4));
  return;
}



void Unwind_0041b7b8(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0041b7e0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0xc));
  return;
}



void Unwind_0041b7e8(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x1c));
  return;
}



void Unwind_0041b7f3(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041b820(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0041b850(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + -0x20));
  return;
}



void Unwind_0041b880(void)

{
  int unaff_EBP;
  
  FUN_00406190((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_0041b88b(void)

{
  int unaff_EBP;
  
  FUN_00406190((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x38));
  return;
}



void Unwind_0041b896(void)

{
  int unaff_EBP;
  
  operator_delete__(*(void **)(unaff_EBP + 8));
  return;
}



void Unwind_0041b8c0(void)

{
  int unaff_EBP;
  
  FUN_00406190((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0xc));
  return;
}



void Unwind_0041b8cb(void)

{
  int unaff_EBP;
  
  FUN_00406190((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x38));
  return;
}



void Unwind_0041b900(void)

{
  int unaff_EBP;
  
  FUN_00403340(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0041b908(void)

{
  int unaff_EBP;
  
  FUN_0040d000((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x5c));
  return;
}



void Unwind_0041b913(void)

{
  int unaff_EBP;
  
  FUN_0040d460((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x78));
  return;
}



void Unwind_0041b91e(void)

{
  int unaff_EBP;
  
  FUN_0040d010((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x94));
  return;
}



void Unwind_0041b92c(void)

{
  int unaff_EBP;
  
  FUN_0040d4e0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xb0));
  return;
}



void Unwind_0041b93a(void)

{
  int unaff_EBP;
  
  FUN_0040d660((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xdc));
  return;
}



void Unwind_0041b948(void)

{
  int unaff_EBP;
  
  FUN_00412c00((int *)(*(int *)(unaff_EBP + -0x10) + 0x140));
  return;
}



void Unwind_0041b956(void)

{
  int unaff_EBP;
  
  FUN_00402eb0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x14c));
  return;
}



void Unwind_0041b980(void)

{
  int unaff_EBP;
  
  FUN_00403340(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0041b988(void)

{
  int unaff_EBP;
  
  FUN_0040d000((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x5c));
  return;
}



void Unwind_0041b993(void)

{
  int unaff_EBP;
  
  FUN_0040d460((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x78));
  return;
}



void Unwind_0041b99e(void)

{
  int unaff_EBP;
  
  FUN_0040d010((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x94));
  return;
}



void Unwind_0041b9ac(void)

{
  int unaff_EBP;
  
  FUN_0040d4e0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xb0));
  return;
}



void Unwind_0041b9ba(void)

{
  int unaff_EBP;
  
  FUN_0040d660((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xdc));
  return;
}



void Unwind_0041b9c8(void)

{
  int unaff_EBP;
  
  FUN_00412c00((int *)(*(int *)(unaff_EBP + -0x10) + 0x140));
  return;
}



void Unwind_0041b9d6(void)

{
  int unaff_EBP;
  
  FUN_00402eb0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x14c));
  return;
}



void Unwind_0041b9e4(void)

{
  int unaff_EBP;
  
  FUN_00402eb0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x170));
  return;
}



void Unwind_0041ba10(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0xc));
  return;
}



void Unwind_0041ba18(void)

{
  int unaff_EBP;
  
  FUN_00401f60(unaff_EBP + -0x180);
  return;
}



void Unwind_0041ba23(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x200));
  return;
}



void Unwind_0041ba2e(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1e0));
  return;
}



void Unwind_0041ba39(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -500));
  return;
}



void Unwind_0041ba44(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1a0));
  return;
}



void Unwind_0041ba4f(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x194));
  return;
}



void Unwind_0041ba5a(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1b0));
  return;
}



void Unwind_0041ba65(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1bc));
  return;
}



void Unwind_0041ba70(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1c8));
  return;
}



void Unwind_0041ba7b(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1d4));
  return;
}



void Unwind_0041ba86(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1d4));
  return;
}



void Unwind_0041ba91(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1d4));
  return;
}



void Unwind_0041ba9c(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1d4));
  return;
}



void Unwind_0041baa7(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1d4));
  return;
}



void Unwind_0041bab2(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1d4));
  return;
}



void Unwind_0041babd(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1d4));
  return;
}



void Unwind_0041bac8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1d4));
  return;
}



void Unwind_0041bad3(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1d4));
  return;
}



void Unwind_0041bade(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xe4));
  return;
}



void Unwind_0041bae9(void)

{
  int unaff_EBP;
  
  FUN_0040bc30((void **)(unaff_EBP + -0x138));
  return;
}



void Unwind_0041baf4(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1d4));
  return;
}



void Unwind_0041baff(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x144));
  return;
}



void Unwind_0041bb0a(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x160));
  return;
}



void Unwind_0041bb15(void)

{
  int unaff_EBP;
  
  FUN_00401170(*(void ***)(unaff_EBP + -0x1a4));
  return;
}



void Unwind_0041bb20(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x160));
  return;
}



void Unwind_0041bb2b(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x144));
  return;
}



void Unwind_0041bb36(void)

{
  int unaff_EBP;
  
  FUN_0040bc30((void **)(unaff_EBP + -0x118));
  return;
}



void Unwind_0041bb41(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x160));
  return;
}



void Unwind_0041bb4c(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1d4));
  return;
}



void Unwind_0041bb57(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x1a4));
  return;
}



void Unwind_0041bb65(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x150));
  return;
}



void Unwind_0041bb70(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x150));
  return;
}



void Unwind_0041bb7b(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x1d4));
  return;
}



void Unwind_0041bb86(void)

{
  int unaff_EBP;
  
  FUN_0040bc30((void **)(unaff_EBP + -0xd8));
  return;
}



void Unwind_0041bb91(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x150));
  return;
}



void Unwind_0041bb9c(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x160));
  return;
}



void Unwind_0041bbe0(void)

{
  int unaff_EBP;
  
  FUN_00411740((int *)(unaff_EBP + 4));
  return;
}



void Unwind_0041bbe8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x78));
  return;
}



void Unwind_0041bbf0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xcc));
  return;
}



void Unwind_0041bbfb(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xe8));
  return;
}



void Unwind_0041bc06(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x84));
  return;
}



void Unwind_0041bc11(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x6c));
  return;
}



void Unwind_0041bc19(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xd8));
  return;
}



void Unwind_0041bc24(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xc0));
  return;
}



void Unwind_0041bc2f(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xd8));
  return;
}



void Unwind_0041bc3a(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xc0));
  return;
}



void Unwind_0041bc45(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xc0));
  return;
}



void Unwind_0041bc50(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xc0));
  return;
}



void Unwind_0041bc5b(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0xd8));
  return;
}



void Unwind_0041bc69(void)

{
  int unaff_EBP;
  
  FUN_00401170(*(void ***)(unaff_EBP + -0xb4));
  return;
}



void Unwind_0041bc74(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + -0xb0));
  return;
}



void Unwind_0041bc7f(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xc0));
  return;
}



void Unwind_0041bc8a(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + -0xec));
  return;
}



void Unwind_0041bcd0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x14c));
  return;
}



void Unwind_0041bcdb(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x128));
  return;
}



void Unwind_0041bce6(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xf8));
  return;
}



void Unwind_0041bcf1(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x140));
  return;
}



void Unwind_0041bcfc(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x134));
  return;
}



void Unwind_0041bd07(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x11c));
  return;
}



void Unwind_0041bd12(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x104));
  return;
}



void Unwind_0041bd1d(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xec));
  return;
}



void Unwind_0041bd28(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x110));
  return;
}



void Unwind_0041bd60(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041bd68(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0041bd90(void)

{
  int unaff_EBP;
  
  FUN_00411740((int *)(unaff_EBP + 4));
  return;
}



void Unwind_0041bdc0(void)

{
  int unaff_EBP;
  
  FUN_00411740((int *)(unaff_EBP + 4));
  return;
}



void Unwind_0041bdf0(void)

{
  int unaff_EBP;
  
  FUN_004127d0((int *)(unaff_EBP + 4));
  return;
}



void Unwind_0041be20(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 4));
  return;
}



void Unwind_0041be28(void)

{
  int unaff_EBP;
  
  FUN_00401f60(unaff_EBP + -0x2c);
  return;
}



void Unwind_0041be30(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x44));
  return;
}



void Unwind_0041be38(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x38));
  return;
}



void Unwind_0041be40(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x38));
  return;
}



void Unwind_0041be48(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x38));
  return;
}



void Unwind_0041be50(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x38));
  return;
}



void Unwind_0041be58(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x38));
  return;
}



void Unwind_0041be60(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x38));
  return;
}



void Unwind_0041be68(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x38));
  return;
}



void Unwind_0041be70(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x38));
  return;
}



void Unwind_0041be78(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x38));
  return;
}



void Unwind_0041be80(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x38));
  return;
}



void Unwind_0041be88(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x38));
  return;
}



void Unwind_0041be90(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x38));
  return;
}



void Unwind_0041bec0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0x40));
  return;
}



void Unwind_0041bec8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0x34));
  return;
}



void Unwind_0041bed0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0x28));
  return;
}



void Unwind_0041bed8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0x1c));
  return;
}



void Unwind_0041bee0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0x10));
  return;
}



void Unwind_0041bee8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 4));
  return;
}



void Unwind_0041bef0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x2b4));
  return;
}



void Unwind_0041befb(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x2a8));
  return;
}



void Unwind_0041bf06(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x290));
  return;
}



void Unwind_0041bf11(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x294));
  return;
}



void Unwind_0041bf1f(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x274));
  return;
}



void Unwind_0041bf2a(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x274));
  return;
}



void Unwind_0041bf35(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x284));
  return;
}



void Unwind_0041bf40(void)

{
  int unaff_EBP;
  
  FUN_00401170(*(void ***)(unaff_EBP + -0x29c));
  return;
}



void Unwind_0041bf4b(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x274));
  return;
}



void Unwind_0041bf56(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x274));
  return;
}



void Unwind_0041bf61(void)

{
  int unaff_EBP;
  
  FUN_0040bc30((void **)(unaff_EBP + -0x254));
  return;
}



void Unwind_0041bf6c(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x234));
  return;
}



void Unwind_0041bf77(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x298));
  return;
}



void Unwind_0041bfc0(void)

{
  int unaff_EBP;
  
  FUN_00413a90((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_0041bff0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 4));
  return;
}



void Unwind_0041c020(void)

{
  int unaff_EBP;
  
  FUN_00403340((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 8));
  return;
}



void Unwind_0041c02b(void)

{
  int unaff_EBP;
  
  FUN_00402eb0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x44));
  return;
}



void Unwind_0041c036(void)

{
  int unaff_EBP;
  
  FUN_00413240((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x68));
  return;
}



void Unwind_0041c041(void)

{
  int unaff_EBP;
  
  FUN_00413240((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x84));
  return;
}



void Unwind_0041c04f(void)

{
  int unaff_EBP;
  
  FUN_00413240((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xa0));
  return;
}



void Unwind_0041c05d(void)

{
  int unaff_EBP;
  
  FUN_00412c00((int *)(*(int *)(unaff_EBP + -0x10) + 0xbc));
  return;
}



void Unwind_0041c06b(void)

{
  int unaff_EBP;
  
  FUN_00414550((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 200));
  return;
}



void Unwind_0041c079(void)

{
  int unaff_EBP;
  
  FUN_00414550((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xf4));
  return;
}



void Unwind_0041c087(void)

{
  int unaff_EBP;
  
  FUN_00419a60((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x120));
  return;
}



void Unwind_0041c095(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x208));
  return;
}



void Unwind_0041c0a3(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x214));
  return;
}



void Unwind_0041c0b1(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x220));
  return;
}



void Unwind_0041c0bf(void)

{
  int unaff_EBP;
  
  FUN_00405bf0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x230));
  return;
}



void Unwind_0041c0cd(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 600));
  return;
}



void Unwind_0041c100(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x10) == 0) {
    *(undefined4 *)(unaff_EBP + -0x14) = 0;
  }
  else {
    *(int *)(unaff_EBP + -0x14) = *(int *)(unaff_EBP + -0x10) + 8;
  }
  FUN_00403340(*(undefined4 **)(unaff_EBP + -0x14));
  return;
}



void Unwind_0041c127(void)

{
  int unaff_EBP;
  
  FUN_00402eb0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x44));
  return;
}



void Unwind_0041c132(void)

{
  int unaff_EBP;
  
  FUN_00413240((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x68));
  return;
}



void Unwind_0041c13d(void)

{
  int unaff_EBP;
  
  FUN_00413240((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x84));
  return;
}



void Unwind_0041c14b(void)

{
  int unaff_EBP;
  
  FUN_00413240((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xa0));
  return;
}



void Unwind_0041c159(void)

{
  int unaff_EBP;
  
  FUN_00412c00((int *)(*(int *)(unaff_EBP + -0x10) + 0xbc));
  return;
}



void Unwind_0041c167(void)

{
  int unaff_EBP;
  
  FUN_00414550((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 200));
  return;
}



void Unwind_0041c175(void)

{
  int unaff_EBP;
  
  FUN_00414550((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xf4));
  return;
}



void Unwind_0041c183(void)

{
  int unaff_EBP;
  
  FUN_00419a60((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x120));
  return;
}



void Unwind_0041c191(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x208));
  return;
}



void Unwind_0041c19f(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x214));
  return;
}



void Unwind_0041c1ad(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x220));
  return;
}



void Unwind_0041c1bb(void)

{
  int unaff_EBP;
  
  FUN_00405bf0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x230));
  return;
}



void Unwind_0041c1c9(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 600));
  return;
}



void Unwind_0041c200(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 8));
  return;
}



void Unwind_0041c230(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_0041c23b(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x18));
  return;
}



void Unwind_0041c270(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x30));
  return;
}



void Unwind_0041c278(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041c280(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x3c));
  return;
}



void Unwind_0041c288(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0041c290(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x40) & 1) != 0) {
    *(uint *)(unaff_EBP + -0x40) = *(uint *)(unaff_EBP + -0x40) & 0xfffffffe;
    FUN_00401170(*(void ***)(unaff_EBP + 4));
    return;
  }
  return;
}



void Unwind_0041c2d0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x58));
  return;
}



void Unwind_0041c2d8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x4c));
  return;
}



void Unwind_0041c2e0(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x68));
  return;
}



void Unwind_0041c2eb(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x40));
  return;
}



void Unwind_0041c2f3(void)

{
  int unaff_EBP;
  
  FUN_00401170(*(void ***)(unaff_EBP + -0x60));
  return;
}



void Unwind_0041c2fb(void)

{
  int unaff_EBP;
  
  FUN_00401170(*(void ***)(unaff_EBP + -0x70));
  return;
}



void Unwind_0041c320(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_0041c350(void)

{
  int unaff_EBP;
  
  FUN_004127d0((int *)(unaff_EBP + 4));
  return;
}



void Unwind_0041c358(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x21c));
  return;
}



void Unwind_0041c363(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x21c));
  return;
}



void Unwind_0041c36e(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x21c));
  return;
}



void Unwind_0041c3b0(void)

{
  int unaff_EBP;
  
  FUN_00403340(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0041c3b8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x50));
  return;
}



void Unwind_0041c3c3(void)

{
  int unaff_EBP;
  
  FUN_00412c00((int *)(*(int *)(unaff_EBP + -0x10) + 0x5c));
  return;
}



void Unwind_0041c3ce(void)

{
  int unaff_EBP;
  
  FUN_00415370((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x68));
  return;
}



void Unwind_0041c3d9(void)

{
  int unaff_EBP;
  
  FUN_0040b370((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x84));
  return;
}



void Unwind_0041c3e7(void)

{
  int unaff_EBP;
  
  FUN_00415380((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x118));
  return;
}



void Unwind_0041c3f5(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x13c));
  return;
}



void Unwind_0041c403(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x148));
  return;
}



void Unwind_0041c430(void)

{
  int unaff_EBP;
  
  FUN_00403340(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0041c438(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x50));
  return;
}



void Unwind_0041c443(void)

{
  int unaff_EBP;
  
  FUN_00412c00((int *)(*(int *)(unaff_EBP + -0x10) + 0x5c));
  return;
}



void Unwind_0041c44e(void)

{
  int unaff_EBP;
  
  FUN_00415370((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x68));
  return;
}



void Unwind_0041c459(void)

{
  int unaff_EBP;
  
  FUN_0040b370((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x84));
  return;
}



void Unwind_0041c467(void)

{
  int unaff_EBP;
  
  FUN_00415380((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x118));
  return;
}



void Unwind_0041c475(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x13c));
  return;
}



void Unwind_0041c483(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x148));
  return;
}



void Unwind_0041c4b0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0xc));
  return;
}



void Unwind_0041c4b8(void)

{
  int unaff_EBP;
  
  FUN_00401f60(unaff_EBP + -0xb0);
  return;
}



void Unwind_0041c4c3(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xf4));
  return;
}



void Unwind_0041c4ce(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xd4));
  return;
}



void Unwind_0041c4d9(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xbc));
  return;
}



void Unwind_0041c4e4(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -200));
  return;
}



void Unwind_0041c4ef(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -200));
  return;
}



void Unwind_0041c4fa(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -200));
  return;
}



void Unwind_0041c505(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -200));
  return;
}



void Unwind_0041c510(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0xe0));
  return;
}



void Unwind_0041c550(void)

{
  int unaff_EBP;
  
  FUN_00403340(*(undefined4 **)(unaff_EBP + -0x38));
  return;
}



void Unwind_0041c558(void)

{
  int unaff_EBP;
  
  FUN_00406190((undefined4 *)(*(int *)(unaff_EBP + -0x38) + 0x48));
  return;
}



void Unwind_0041c580(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x34) & 1) != 0) {
    *(uint *)(unaff_EBP + -0x34) = *(uint *)(unaff_EBP + -0x34) & 0xfffffffe;
    FUN_00401170(*(void ***)(unaff_EBP + 4));
    return;
  }
  return;
}



void Unwind_0041c599(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x30));
  return;
}



void Unwind_0041c5a1(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x30));
  return;
}



void Unwind_0041c5a9(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0041c5b1(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041c5e0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_0041c5eb(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x10));
  return;
}



void Unwind_0041c5f6(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x1c));
  return;
}



void Unwind_0041c601(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x28));
  return;
}



void Unwind_0041c60c(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x38));
  return;
}



void Unwind_0041c640(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_0041c64b(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x10));
  return;
}



void Unwind_0041c656(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x1c));
  return;
}



void Unwind_0041c661(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x28));
  return;
}



void Unwind_0041c66c(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 0x38));
  return;
}



void Unwind_0041c6a0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0xc));
  return;
}



void Unwind_0041c6a8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x8c));
  return;
}



void Unwind_0041c6b3(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x80));
  return;
}



void Unwind_0041c6bb(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x68));
  return;
}



void Unwind_0041c6c3(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x74));
  return;
}



void Unwind_0041c6cb(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x74));
  return;
}



void Unwind_0041c6d3(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x68));
  return;
}



void Unwind_0041c6db(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x68));
  return;
}



void Unwind_0041c6e3(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x68));
  return;
}



void Unwind_0041c710(void)

{
  int unaff_EBP;
  
  FUN_004167b0(unaff_EBP + 8);
  return;
}



void Unwind_0041c718(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x30));
  return;
}



void Unwind_0041c720(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x40) & 1) != 0) {
    *(uint *)(unaff_EBP + -0x40) = *(uint *)(unaff_EBP + -0x40) & 0xfffffffe;
    FUN_00401170(*(void ***)(unaff_EBP + 4));
    return;
  }
  return;
}



void Unwind_0041c739(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x3c));
  return;
}



void Unwind_0041c741(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041c749(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0041c751(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0041c759(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0041c780(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 4));
  return;
}



void Unwind_0041c788(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xe4));
  return;
}



void Unwind_0041c793(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xf0));
  return;
}



void Unwind_0041c79e(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xd8));
  return;
}



void Unwind_0041c7a9(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041c7b1(void)

{
  int unaff_EBP;
  
  FUN_0040bc30((void **)(unaff_EBP + -0x7c));
  return;
}



void Unwind_0041c7b9(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xcc));
  return;
}



void Unwind_0041c7c4(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0041c7cc(void)

{
  int unaff_EBP;
  
  FUN_0040bc30((void **)(unaff_EBP + -0x9c));
  return;
}



void Unwind_0041c7d7(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xcc));
  return;
}



void Unwind_0041c7e2(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xcc));
  return;
}



void Unwind_0041c7ed(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x30));
  return;
}



void Unwind_0041c7f5(void)

{
  int unaff_EBP;
  
  FUN_0040bc30((void **)(unaff_EBP + -0xbc));
  return;
}



void Unwind_0041c800(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xcc));
  return;
}



void Unwind_0041c80b(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xcc));
  return;
}



void Unwind_0041c816(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xcc));
  return;
}



void Unwind_0041c821(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xcc));
  return;
}



void Unwind_0041c82c(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xcc));
  return;
}



void Unwind_0041c837(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0xcc));
  return;
}



void Unwind_0041c842(void)

{
  int unaff_EBP;
  
  FUN_0040bc30((void **)(unaff_EBP + -0x50));
  return;
}



void Unwind_0041c84a(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x5c));
  return;
}



void Unwind_0041c852(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x5c));
  return;
}



void Unwind_0041c85a(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x5c));
  return;
}



void Unwind_0041c862(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x5c));
  return;
}



void Unwind_0041c86a(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x5c));
  return;
}



void Unwind_0041c8a0(void)

{
  int unaff_EBP;
  
  FUN_004167b0(unaff_EBP + 4);
  return;
}



void Unwind_0041c8a8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x30));
  return;
}



void Unwind_0041c8b0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0041c8b8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041c8c0(void)

{
  int unaff_EBP;
  
  FUN_00401170(*(void ***)(unaff_EBP + -0x34));
  return;
}



void Unwind_0041c8f0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 8));
  return;
}



void Unwind_0041c920(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 8));
  return;
}



void Unwind_0041c950(void)

{
  int unaff_EBP;
  
  FUN_004167b0(unaff_EBP + 4);
  return;
}



void Unwind_0041c958(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x3c));
  return;
}



void Unwind_0041c960(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x48));
  return;
}



void Unwind_0041c968(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x54));
  return;
}



void Unwind_0041c970(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041c978(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0041c980(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x30));
  return;
}



void Unwind_0041c988(void)

{
  int unaff_EBP;
  
  FUN_00401170(*(void ***)(unaff_EBP + -0x5c));
  return;
}



void Unwind_0041c9b0(void)

{
  int unaff_EBP;
  
  FUN_004167b0(unaff_EBP + 4);
  return;
}



void Unwind_0041c9b8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x30));
  return;
}



void Unwind_0041c9c0(void)

{
  int unaff_EBP;
  
  FUN_00401170(*(void ***)(unaff_EBP + -0x40));
  return;
}



void Unwind_0041c9c8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x3c));
  return;
}



void Unwind_0041c9d0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_0041c9d8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041c9e0(void)

{
  int unaff_EBP;
  
  FUN_00401170(*(void ***)(unaff_EBP + -0x40));
  return;
}



void Unwind_0041ca10(void)

{
  int unaff_EBP;
  
  FUN_004167b0(unaff_EBP + 4);
  return;
}



void Unwind_0041ca18(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x40ec));
  return;
}



void Unwind_0041ca23(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x40b8));
  return;
}



void Unwind_0041ca2e(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x4108));
  return;
}



void Unwind_0041ca39(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x4114));
  return;
}



void Unwind_0041ca44(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x40e0));
  return;
}



void Unwind_0041ca4f(void)

{
  int unaff_EBP;
  
  FUN_00415370((undefined4 *)(unaff_EBP + -0x40d4));
  return;
}



void Unwind_0041ca5a(void)

{
  int unaff_EBP;
  
  FUN_00411740((int *)(unaff_EBP + -0x4128));
  return;
}



void Unwind_0041ca65(void)

{
  int unaff_EBP;
  
  FUN_00411740((int *)(unaff_EBP + -0x411c));
  return;
}



void Unwind_0041ca70(void)

{
  int unaff_EBP;
  
  FUN_00401170(*(void ***)(unaff_EBP + -0x4120));
  return;
}



void Unwind_0041ca7b(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x4094));
  return;
}



void Unwind_0041ca86(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x40a0));
  return;
}



void Unwind_0041ca91(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x4094));
  return;
}



void Unwind_0041ca9c(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x4094));
  return;
}



void Unwind_0041caa7(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x40a0));
  return;
}



void Unwind_0041cab2(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x4074));
  return;
}



void Unwind_0041cabd(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x4084));
  return;
}



void Unwind_0041cac8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x40ac));
  return;
}



void Unwind_0041cad3(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x40ac));
  return;
}



void Unwind_0041cade(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x4084));
  return;
}



void Unwind_0041cae9(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x40ac));
  return;
}



void Unwind_0041caf4(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x40ac));
  return;
}



void Unwind_0041cb30(void)

{
  int unaff_EBP;
  
  FUN_004167b0(unaff_EBP + -0x80064);
  return;
}



void Unwind_0041cb3b(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x80070));
  return;
}



void Unwind_0041cb46(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x80070));
  return;
}



void Unwind_0041cb80(void)

{
  int unaff_EBP;
  
  FUN_00402eb0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_0041cb8b(void)

{
  int unaff_EBP;
  
  FUN_00412c00((int *)(*(int *)(unaff_EBP + -0x10) + 0x28));
  return;
}



void Unwind_0041cbc0(void)

{
  int unaff_EBP;
  
  FUN_00402eb0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_0041cbcb(void)

{
  int unaff_EBP;
  
  FUN_00412c00((int *)(*(int *)(unaff_EBP + -0x10) + 0x28));
  return;
}



void Unwind_0041cc00(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0041cc0b(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0041cc30(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0041cc60(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 4));
  return;
}



void Unwind_0041cc90(void)

{
  FUN_00406a80();
  return;
}



void Unwind_0041cc9b(void)

{
  FUN_00403c90();
  return;
}



void Unwind_0041ccd0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x10) + 8));
  return;
}



void Unwind_0041cd00(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041cd30(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0041cd60(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + -0x24));
  return;
}



void Unwind_0041cd68(void)

{
  FUN_00403c90();
  return;
}



void Unwind_0041cd90(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0041cdc0(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0041cdf0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 4));
  return;
}



void Unwind_0041ce20(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0041ce50(void)

{
  int unaff_EBP;
  
  FUN_00402f90((int *)(unaff_EBP + -0x20));
  return;
}



void Unwind_0041ce58(void)

{
  FUN_00403c90();
  return;
}



void Unwind_0041ce80(void)

{
  int unaff_EBP;
  
  FUN_004086e0((undefined4 *)(unaff_EBP + -0x148));
  return;
}



void Unwind_0041cec0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x54) + 8));
  return;
}



void Unwind_0041cecb(void)

{
  int unaff_EBP;
  
  FUN_004028d0((int *)(*(int *)(unaff_EBP + -0x54) + 0x14));
  return;
}



void Unwind_0041ced6(void)

{
  int unaff_EBP;
  
  FUN_00406740((undefined4 *)(unaff_EBP + -0x50));
  return;
}



void Unwind_0041cede(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x48));
  return;
}



void Unwind_0041cee6(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x3c));
  return;
}



void Unwind_0041cf10(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(*(int *)(unaff_EBP + -0x4008c) + 8));
  return;
}



void Unwind_0041cf1e(void)

{
  int unaff_EBP;
  
  FUN_004028d0((int *)(*(int *)(unaff_EBP + -0x4008c) + 0x14));
  return;
}



void Unwind_0041cf2c(void)

{
  int unaff_EBP;
  
  FUN_00406740((undefined4 *)(unaff_EBP + -0x4006c));
  return;
}



void Unwind_0041cf37(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x4009c));
  return;
}



void Unwind_0041cf42(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x40044));
  return;
}



void Unwind_0041cf4d(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x40064));
  return;
}



void Unwind_0041cf58(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x40078));
  return;
}



void Unwind_0041cf63(void)

{
  int unaff_EBP;
  
  FUN_004028d0((int *)(unaff_EBP + -0x40088));
  return;
}



void Unwind_0041cfa0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 0x10));
  return;
}



void Unwind_0041cfa8(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + 4));
  return;
}



void Unwind_0041cfb0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x30));
  return;
}



void Unwind_0041cfe0(void)

{
  int unaff_EBP;
  
  FUN_00401170((void **)(unaff_EBP + -0x48));
  return;
}



void Unwind_0041cfe8(void)

{
  int unaff_EBP;
  
  FUN_00401f60(unaff_EBP + -0x30);
  return;
}


