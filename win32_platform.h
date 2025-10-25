#ifndef WIN32_PLATFORM_H
#define WIN32_PLATFORM_H
#pragma warning(disable : 4996)
#include <Windows.h>
#include <Shlwapi.h>
#include <aclapi.h>

struct slay_mutex {
    CRITICAL_SECTION cs;
};

// Helper function to convert UTF-8 to UTF-16
static wchar_t* win32_utf8_to_utf16(const char* utf8_str) {
    if (!utf8_str) return NULL;
    
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, NULL, 0);
    if (len == 0) return NULL;
    
    wchar_t* utf16_str = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (!utf16_str) return NULL;
    
    if (MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, utf16_str, len) == 0) {
        free(utf16_str);
        return NULL;
    }
    
    return utf16_str;
}

SLAYAPI slay_bool slay_does_file_exist(const char* file_path) {
    wchar_t* wide_path = win32_utf8_to_utf16(file_path);
    if (!wide_path) return 0;
    
    DWORD attrs = GetFileAttributesW(wide_path);
    free(wide_path);
    return (attrs != INVALID_FILE_ATTRIBUTES) && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

SLAYAPI size_t slay_get_file_size(const char* file_path) {
    wchar_t* wide_path = win32_utf8_to_utf16(file_path);
    if (!wide_path) return 0;
    
    HANDLE file = CreateFileW(
        wide_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    
    free(wide_path);

    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }

    LARGE_INTEGER file_size;
    if (GetFileSizeEx(file, &file_size)) {
        CloseHandle(file);
        return file_size.QuadPart;
    }
    CloseHandle(file);
    return 0;
}

SLAYAPI size_t slay_get_last_write_time(const char* file) {
    wchar_t* wide_path = win32_utf8_to_utf16(file);
    if (!wide_path) return 0;
    
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (!GetFileAttributesExW(wide_path, GetFileExInfoStandard, &fileInfo)) {
        free(wide_path);
        return 0;
    }
    free(wide_path);
    return ((uint64_t)fileInfo.ftLastWriteTime.dwHighDateTime << 32) |
           fileInfo.ftLastWriteTime.dwLowDateTime;
}

SLAYAPI size_t slay_get_last_read_time(const char* file) {
    wchar_t* wide_path = win32_utf8_to_utf16(file);
    if (!wide_path) return 0;
    
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (!GetFileAttributesExW(wide_path, GetFileExInfoStandard, &fileInfo)) {
        free(wide_path);
        return 0;
    }
    free(wide_path);
    return ((uint64_t)fileInfo.ftLastAccessTime.dwHighDateTime << 32) |
           fileInfo.ftLastAccessTime.dwLowDateTime;
}

SLAYAPI uint32_t slay_get_file_permissions(const char* file_path) {
    if (!file_path) {
        return 0;
    }

    wchar_t* wide_path = win32_utf8_to_utf16(file_path);
    if (!wide_path) return 0;

    uint32_t permissions = 0;

    PACL pDacl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD dwRes = GetNamedSecurityInfoW(
        wide_path,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        &pDacl,
        NULL,
        &pSD);

    free(wide_path);

    if (dwRes != ERROR_SUCCESS) {
        if (pSD)
            LocalFree(pSD);
        return 0;
    }

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        LocalFree(pSD);
        return 0;
    }

    GENERIC_MAPPING mapping = {0};
    mapping.GenericRead = FILE_GENERIC_READ;
    mapping.GenericWrite = FILE_GENERIC_WRITE;
    mapping.GenericExecute = FILE_GENERIC_EXECUTE;
    mapping.GenericAll = FILE_ALL_ACCESS;

    PRIVILEGE_SET privileges = {0};
    DWORD privSize = sizeof(privileges);
    BOOL accessStatus = FALSE;

    ACCESS_MASK accessRights = 0;
    dwRes = GetEffectiveRightsFromAclA(pDacl, NULL, &accessRights);

    if (dwRes == ERROR_SUCCESS) {
        if (accessRights & FILE_GENERIC_READ)
            permissions |= SLAY_READ;
        if (accessRights & FILE_GENERIC_WRITE)
            permissions |= SLAY_WRITE;
        if (accessRights & FILE_GENERIC_EXECUTE)
            permissions |= SLAY_EXECUTE;
    }

    CloseHandle(hToken);
    LocalFree(pSD);

    return permissions;
}

SLAYAPI slay_bool slay_change_file_permissions(const char* file_path, uint32_t permission_flags) {
    if (!file_path) {
        return 0;
    }

    wchar_t* wide_path = win32_utf8_to_utf16(file_path);
    if (!wide_path) return 0;

    DWORD dwAccessRights = 0;
    if (permission_flags & SLAY_READ)
        dwAccessRights |= GENERIC_READ;
    if (permission_flags & SLAY_WRITE)
        dwAccessRights |= GENERIC_WRITE;
    if (permission_flags & SLAY_EXECUTE)
        dwAccessRights |= GENERIC_EXECUTE;

    if (dwAccessRights == 0) {
        free(wide_path);
        return 0;
    }

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        free(wide_path);
        return 0;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (dwSize == 0) {
        CloseHandle(hToken);
        free(wide_path);
        return 0;
    }

    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
    if (!pTokenUser) {
        CloseHandle(hToken);
        free(wide_path);
        return 0;
    }

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        free(pTokenUser);
        CloseHandle(hToken);
        free(wide_path);
        return 0;
    }

    CloseHandle(hToken);

    EXPLICIT_ACCESS_W ea = {0};
    ea.grfAccessPermissions = dwAccessRights;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = (LPWSTR)pTokenUser->User.Sid;

    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    DWORD dwRes = GetNamedSecurityInfoW(
        wide_path,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        &pOldDACL,
        NULL,
        &pSD);

    if (dwRes != ERROR_SUCCESS) {
        free(pTokenUser);
        free(wide_path);
        return 0;
    }

    dwRes = SetEntriesInAclW(1, &ea, pOldDACL, &pNewDACL);
    if (dwRes != ERROR_SUCCESS) {
        LocalFree(pSD);
        free(pTokenUser);
        free(wide_path);
        return 0;
    }

    dwRes = SetNamedSecurityInfoW(
        wide_path,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        pNewDACL,
        NULL);

    LocalFree(pNewDACL);
    LocalFree(pSD);
    free(pTokenUser);
    free(wide_path);

    return (dwRes == ERROR_SUCCESS) ? 1 : 0;
}

SLAYAPI unsigned char *slay_read_entire_file(const char *file_path, size_t *bytes_read) {
    wchar_t* wide_path = win32_utf8_to_utf16(file_path);
    if (!wide_path) return NULL;
    
    HANDLE file = CreateFileW(
        wide_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    free(wide_path);

    if (file == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(file, &file_size)) {
        CloseHandle(file);
        return NULL;
    }

    if (file_size.QuadPart > SIZE_MAX) {
        CloseHandle(file);
        return NULL;
    }

    size_t total_size = (size_t)file_size.QuadPart;
    char *buffer = (char *)malloc(total_size + 1);
    if (!buffer) {
        CloseHandle(file);
        return NULL;
    }

    size_t total_read = 0;
    while (total_read < total_size) {
        DWORD chunk = (DWORD)((total_size - total_read > MAXDWORD) ? MAXDWORD : (total_size - total_read));
        DWORD read_now = 0;

        if (!ReadFile(file, buffer + total_read, chunk, &read_now, NULL)) {
            free(buffer);
            CloseHandle(file);
            return NULL;
        }

        if (read_now == 0) break;

        total_read += read_now;
    }
    buffer[total_size] = '\0';
    CloseHandle(file);

    if (bytes_read)
        *bytes_read = total_read;

    return (unsigned char*)buffer;
}

SLAYAPI slay_bool slay_write_file(const char* file_path, size_t file_size, char* buffer) {
    wchar_t* wide_path = win32_utf8_to_utf16(file_path);
    if (!wide_path) return 1;
    
    HANDLE file = CreateFileW(
        wide_path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    free(wide_path);

    if (file == INVALID_HANDLE_VALUE) {
        return 1;
    }

    size_t remaining = file_size;
    const char* current_pos = buffer;

    while (remaining > 0) {
        DWORD chunk = (remaining > MAXDWORD) ? MAXDWORD : (DWORD)remaining;
        DWORD bytes_written = 0;

        if (!WriteFile(file, current_pos, chunk, &bytes_written, NULL) ||
            bytes_written != chunk) {
            CloseHandle(file);
            return 1;
        }

        remaining -= chunk;
        current_pos += chunk;
    }

    CloseHandle(file);
    return 0;
}

SLAYAPI slay_bool slay_copy_file(const char* original_path, const char* copy_path) {
    wchar_t* wide_original = win32_utf8_to_utf16(original_path);
    wchar_t* wide_copy = win32_utf8_to_utf16(copy_path);
    
    if (!wide_original || !wide_copy) {
        if (wide_original) free(wide_original);
        if (wide_copy) free(wide_copy);
        return 1;
    }
    
    BOOL result = CopyFileW(wide_original, wide_copy, FALSE);
    
    free(wide_original);
    free(wide_copy);
    
    return result ? 0 : 1;
}

SLAYAPI slay_file* slay_open_file(const char* file_path) {
    wchar_t* wide_path = win32_utf8_to_utf16(file_path);
    if (!wide_path) return NULL;
    
    slay_file* file = NULL;

    if (!file) {
        free(wide_path);
        return NULL;
    }
    
    file = CreateFileW(
        wide_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    free(wide_path);

    if (file == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    return file;
}

SLAYAPI slay_bool slay_read_from_open_file(slay_file* file, size_t offset, size_t bytes_to_read, char* buffer) {
    if (!file || file == INVALID_HANDLE_VALUE || !buffer) {
        return 0;
    }

    LARGE_INTEGER file_offset = {0};
    file_offset.QuadPart = (LONGLONG)offset;

    if (!SetFilePointerEx(file, file_offset, NULL, FILE_BEGIN)) {
        return 0;
    }

    size_t total_read = 0;
    DWORD to_read;
    while (total_read < bytes_to_read) {
        if ((DWORD)((bytes_to_read - total_read) > MAXDWORD)) {
            to_read = MAXDWORD;
        } else {
            to_read = (DWORD)(bytes_to_read - total_read);
        }
        DWORD bytesRead = 0;
        BOOL success = ReadFile(file, buffer + total_read, to_read, &bytesRead, NULL);
        if (!success || bytesRead != to_read) {
            return 0;
        }
        total_read += bytesRead;
    }

    return 1;
}

SLAYAPI slay_bool slay_close_file(slay_file* file) {
    if (!file) return 0;
    
    if (!CloseHandle(file)) {
        return 0;
    }
    free(file);
    return 1;
}

//----------------------------------------------------------------------------------
// Directory Listing.
//----------------------------------------------------------------------------------
SLAYAPI slay_bool slay_path_is_dir(const char* path) {
    wchar_t* wide_path = win32_utf8_to_utf16(path);
    if (!wide_path) return 1;

    slay_bool is_dir = PathIsDirectoryW(wide_path) ? slay_true : slay_false;

    free(wide_path);

    return is_dir;
}

//----------------------------------------------------------------------------------
// Random Number Generator.
//----------------------------------------------------------------------------------
SLAYAPI void slay_srand(uint64_t* state, uint64_t seed) {
    if (seed == 0) {
        seed = 1; // Avoid zero state which would produce all zeros
    }
    *state = seed;
}

SLAYAPI uint32_t slay_rand(uint64_t* state) {
    // SDL's well-tested LCG constants:
    // - Multiplier: 0xff1cd035 (32-bit for better performance on 32-bit archs)
    // - Increment: 0x05 (small odd number, generates smaller ARM code)
    // - These constants passed extensive testing with PractRand and TestU01
    *state = *state * 0xff1cd035ul + 0x05;

    // Return upper 32 bits - they have better statistical properties
    // and longer period than lower bits in an LCG
    return (uint32_t)(*state >> 32);
}

SLAYAPI char* slay_clipboard_get(void) {
    if (!OpenClipboard(NULL))
        return NULL;

    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (!hData) {
        CloseClipboard();
        return NULL;
    }

    wchar_t* wtext = GlobalLock(hData);
    if (!wtext) {
        CloseClipboard();
        return NULL;
    }

    // Convert wide char text to UTF-8
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wtext, -1, NULL, 0, NULL, NULL);
    char* text = (char*)malloc(size_needed);
    if (text)
        WideCharToMultiByte(CP_UTF8, 0, wtext, -1, text, size_needed, NULL, NULL);

    GlobalUnlock(hData);
    CloseClipboard();

    return text; // caller must free()
}

SLAYAPI void slay_clipboard_set(const char* text) {
    if (text == NULL || *text == '\0')
        return;

    // Calculate the size of the text, including the null terminator
    size_t len = strlen(text) + 1;
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
    if (!hMem)
        return;

    // Copy the text into the allocated memory
    memcpy(GlobalLock(hMem), text, len);
    GlobalUnlock(hMem);

    // Open the clipboard and set the data
    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        SetClipboardData(CF_TEXT, hMem);
        CloseClipboard();
    } else {
        GlobalFree(hMem);
    }
}

//----------------------------------------------------------------------------------
// Url Launch Function.
//----------------------------------------------------------------------------------
SLAYAPI void slay_url_launch(char* url) {
    if (!url || !*url)
        return;

    // ShellExecuteA automatically opens the URL with the default app (e.g., browser)
    HINSTANCE result = ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);

    // Optional: check if it failed
    if ((INT_PTR)result <= 32) {
        MessageBoxA(NULL, "Failed to open URL.", "Error", MB_ICONERROR);
    }
}
//----------------------------------------------------------------------------------
// File Requester Functions.
//----------------------------------------------------------------------------------
#include <commdlg.h>

typedef struct PalRequester {
    char path[MAX_PATH];
} PalRequester;

static PalRequester g_requesters[16]; // simple static pool, indexed by `id`

static PalRequester* win32_get_requester(void* id) {
    uintptr_t index = (uintptr_t)id;
    if (index >= 16)
        return NULL;
    return &g_requesters[index];
}

static void win32_build_filter_string(char** types, uint32_t type_count, char* out, size_t out_size) {
    // Builds Windows filter string like: "Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0"
    out[0] = '\0';
    size_t pos = 0;
    for (uint32_t i = 0; i < type_count; i++) {
        const char* ext = types[i];
        int written = snprintf(out + pos, out_size - pos, "%s files (*.%s)%c*.%s%c", ext, ext, '\0', ext, '\0');
        pos += written;
        if (pos >= out_size)
            break;
    }
    // Add final double null terminator
    out[pos++] = '\0';
}

void slay_create_save_dialog(char** types, uint32_t type_count, void* id) {
    PalRequester* req = win32_get_requester(id);
    if (!req)
        return;

    OPENFILENAMEA ofn = {0};
    char filter[512];
    win32_build_filter_string(types, type_count, filter, sizeof(filter));
    char path[MAX_PATH] = {0};

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFilter = filter[0] ? filter : "All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    ofn.lpstrDefExt = type_count > 0 ? types[0] : "";

    if (GetSaveFileNameA(&ofn)) {
        strcpy_s(req->path, MAX_PATH, path);
    } else {
        req->path[0] = '\0';
    }
}

void slay_create_load_dialog(char** types, uint32_t type_count, void* id) {
    PalRequester* req = win32_get_requester(id);
    if (!req)
        return;

    OPENFILENAMEA ofn = {0};
    char filter[512];
    win32_build_filter_string(types, type_count, filter, sizeof(filter));
    char path[MAX_PATH] = {0};

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFilter = filter[0] ? filter : "All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    ofn.lpstrDefExt = type_count > 0 ? types[0] : "";

    if (GetOpenFileNameA(&ofn)) {
        strcpy_s(req->path, MAX_PATH, path);
    } else {
        req->path[0] = '\0';
    }
}

char* slay_show_save_dialog(void* id) {
    PalRequester* req = win32_get_requester(id);
    return (req && req->path[0]) ? req->path : NULL;
}

char* slay_show_load_dialog(void* id) {
    PalRequester* req = win32_get_requester(id);
    return (req && req->path[0]) ? req->path : NULL;
}

enum {
    PAL_UPPER_BIT = (1 << 0),     // A-Z
    PAL_LOWER_BIT = (1 << 1),     // a-z
    PAL_DIGIT_BIT = (1 << 2),     // 0-9
    PAL_UNDER_BIT = (1 << 3),     // _
    PAL_HYPHEN_BIT = (1 << 4),    // -
    PAL_DOT_BIT = (1 << 5),       // .
    PAL_EOL_BIT = (1 << 6),       // \r, \n (included in whitespace)
    PAL_WHITESPACE_BIT = (1 << 7) // All whitespace chars
};

static const uint8_t slay_char_masks[128] = {
    // Control characters (0-31)
    [0] = 0, [1] = 0, [2] = 0, [3] = 0, [4] = 0,
    [5] = 0, [6] = 0, [7] = 0, [8] = 0,

    ['\t'] = PAL_WHITESPACE_BIT, // tab
    ['\n'] = PAL_WHITESPACE_BIT | PAL_EOL_BIT, // new line
    ['\v'] = PAL_WHITESPACE_BIT, // vertical tab (not used anymore)
    ['\f'] = PAL_WHITESPACE_BIT, // form feed (not used anymore)
    ['\r'] = PAL_WHITESPACE_BIT | PAL_EOL_BIT, // carriage return

    [14] = 0, [15] = 0, [16] = 0, [17] = 0, [18] = 0,
    [19] = 0, [20] = 0, [21] = 0, [22] = 0, [23] = 0,
    [24] = 0, [25] = 0, [26] = 0, [27] = 0, [28] = 0,
    [29] = 0, [30] = 0, [31] = 0,

    // Printable characters (32-127)
    [' '] = PAL_WHITESPACE_BIT, // Space
    ['!'] = 0, ['"'] = 0, ['#'] = 0, ['$'] = 0,
    ['%'] = 0, ['&'] = 0, ['\''] = 0, ['('] = 0,
    [')'] = 0, ['*'] = 0, ['+'] = 0, [','] = 0,
    ['-'] = PAL_HYPHEN_BIT, ['.'] = PAL_DOT_BIT,
    ['/'] = 0,

    // Numbers (0-9)
    ['0'] = PAL_DIGIT_BIT, ['1'] = PAL_DIGIT_BIT,
    ['2'] = PAL_DIGIT_BIT, ['3'] = PAL_DIGIT_BIT,
    ['4'] = PAL_DIGIT_BIT, ['5'] = PAL_DIGIT_BIT,
    ['6'] = PAL_DIGIT_BIT, ['7'] = PAL_DIGIT_BIT,
    ['8'] = PAL_DIGIT_BIT, ['9'] = PAL_DIGIT_BIT,

    [':'] = 0, [';'] = 0, ['<'] = 0, ['='] = 0,
    ['>'] = 0, ['?'] = 0, ['@'] = 0,

    // Uppercase (A-Z)
    ['A'] = PAL_UPPER_BIT, ['B'] = PAL_UPPER_BIT,
    ['C'] = PAL_UPPER_BIT, ['D'] = PAL_UPPER_BIT,
    ['E'] = PAL_UPPER_BIT, ['F'] = PAL_UPPER_BIT,
    ['G'] = PAL_UPPER_BIT, ['H'] = PAL_UPPER_BIT,
    ['I'] = PAL_UPPER_BIT, ['J'] = PAL_UPPER_BIT,
    ['K'] = PAL_UPPER_BIT, ['L'] = PAL_UPPER_BIT,
    ['M'] = PAL_UPPER_BIT, ['N'] = PAL_UPPER_BIT,
    ['O'] = PAL_UPPER_BIT, ['P'] = PAL_UPPER_BIT,
    ['Q'] = PAL_UPPER_BIT, ['R'] = PAL_UPPER_BIT,
    ['S'] = PAL_UPPER_BIT, ['T'] = PAL_UPPER_BIT,
    ['U'] = PAL_UPPER_BIT, ['V'] = PAL_UPPER_BIT,
    ['W'] = PAL_UPPER_BIT, ['X'] = PAL_UPPER_BIT,
    ['Y'] = PAL_UPPER_BIT, ['Z'] = PAL_UPPER_BIT,

    ['['] = 0, ['\\'] = 0, [']'] = 0, ['^'] = 0,
    ['_'] = PAL_UNDER_BIT, ['`'] = 0,

    // Lowercase (a-z)
    ['a'] = PAL_LOWER_BIT, ['b'] = PAL_LOWER_BIT,
    ['c'] = PAL_LOWER_BIT, ['d'] = PAL_LOWER_BIT,
    ['e'] = PAL_LOWER_BIT, ['f'] = PAL_LOWER_BIT,
    ['g'] = PAL_LOWER_BIT, ['h'] = PAL_LOWER_BIT,
    ['i'] = PAL_LOWER_BIT, ['j'] = PAL_LOWER_BIT,
    ['k'] = PAL_LOWER_BIT, ['l'] = PAL_LOWER_BIT,
    ['m'] = PAL_LOWER_BIT, ['n'] = PAL_LOWER_BIT,
    ['o'] = PAL_LOWER_BIT, ['p'] = PAL_LOWER_BIT,
    ['q'] = PAL_LOWER_BIT, ['r'] = PAL_LOWER_BIT,
    ['s'] = PAL_LOWER_BIT, ['t'] = PAL_LOWER_BIT,
    ['u'] = PAL_LOWER_BIT, ['v'] = PAL_LOWER_BIT,
    ['w'] = PAL_LOWER_BIT, ['x'] = PAL_LOWER_BIT,
    ['y'] = PAL_LOWER_BIT, ['z'] = PAL_LOWER_BIT,

    ['{'] = 0, ['|'] = 0, ['}'] = 0, ['~'] = 0,
    [127] = 0 // DEL
};

// clang-format on
// String Parsing functions
SLAYAPI slay_bool slay_is_uppercase(char ch) {
    return slay_char_masks[(slay_bool)ch] & PAL_UPPER_BIT;
}

SLAYAPI slay_bool slay_is_lowercase(char ch) {
    return slay_char_masks[(slay_bool)ch] & PAL_LOWER_BIT;
}

SLAYAPI slay_bool slay_is_letter(char ch) {
    return slay_char_masks[(slay_bool)ch] & (PAL_UPPER_BIT | PAL_LOWER_BIT);
}

SLAYAPI slay_bool slay_is_number(char ch) {
    return slay_char_masks[(slay_bool)ch] & PAL_DIGIT_BIT;
}

SLAYAPI slay_bool slay_is_alphanumeric(char ch) {
    return slay_is_number(ch) || slay_is_letter(ch);
}

SLAYAPI slay_bool slay_is_end_of_line(char ch) {
    return slay_char_masks[(slay_bool)ch] & PAL_EOL_BIT;
}

SLAYAPI slay_bool slay_is_underscore(char ch) {
    return slay_char_masks[(slay_bool)ch] & PAL_UNDER_BIT;
}

SLAYAPI slay_bool slay_is_hyphen(char ch) {
    return slay_char_masks[(slay_bool)ch] & PAL_HYPHEN_BIT;
}

SLAYAPI slay_bool slay_is_dot(char ch) {
    return slay_char_masks[(slay_bool)ch] & PAL_DOT_BIT;
}
SLAYAPI slay_bool slay_is_whitespace(char ch) {
    return slay_char_masks[(slay_bool)ch] & PAL_WHITESPACE_BIT;
}

SLAYAPI slay_bool slay_are_chars_equal(char ch1, char ch2) {
    return (slay_bool)ch1 == (slay_bool)ch2;
}

SLAYAPI slay_bool slay_are_strings_equal(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *s1 == *s2;
}

SLAYAPI int slay_strcmp(const char* s1, const char* s2) {
	while (*s1 && (*s1 == *s2)) {
		s1++;
		s2++;
	}
	return (unsigned char)*s1 - (unsigned char)*s2;
}

SLAYAPI int slay_strncmp(const char* s1, const char* s2, size_t n) {
    while (n > 0 && *s1 && (*s1 == *s2)) {
        s1++;
        s2++;
        n--;
    }

    if (n == 0)
        return 0;

    return (unsigned char)*s1 - (unsigned char)*s2;
}

//----------------------------------------------------------------------------------
// Time Functions.
//----------------------------------------------------------------------------------
typedef struct _KSYSTEM_TIME {
    ULONG LowPart;  // Low 32 bits of the 64-bit time value
    LONG High1Time; // High 32 bits (first copy)
    LONG High2Time; // High 32 bits (second copy)
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef struct _KUSER_SHARED_DATA {
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;
    KSYSTEM_TIME InterruptTime;
    KSYSTEM_TIME SystemTime;
    KSYSTEM_TIME TimeZoneBias;
    // padding to get to right offsets.
    UCHAR Padding0[0x300 - 0x20];
    LONGLONG QpcFrequency; // Performance Counter Frequency at offset 0x300
    // padding to get to TickCount
    UCHAR Padding1[0x320 - 0x308];
    union {
        KSYSTEM_TIME TickCount;
        UINT64 TickCountQuad;
    };
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;
#define KUSER_SHARED_DATA_ADDRESS 0x7FFE0000
static uint64_t g_app_start_time = 0;

SLAYAPI slay_time slay_get_date_and_time_utc(void) {
    PKUSER_SHARED_DATA kuser = (PKUSER_SHARED_DATA)KUSER_SHARED_DATA_ADDRESS;
    LARGE_INTEGER time = {0};
    do {
        time.HighPart = kuser->SystemTime.High1Time;
        time.LowPart = kuser->SystemTime.LowPart;
    } while (time.HighPart != kuser->SystemTime.High2Time);

    uint64_t total_100ns = time.QuadPart;
    uint64_t total_days = total_100ns / (10000000ULL * 60 * 60 * 24); // 100ns to days
    uint64_t remaining_100ns = total_100ns % (10000000ULL * 60 * 60 * 24);

    uint32_t year = 1601 + (uint32_t)(total_days / 365.25);

    uint64_t days_since_1601 = total_days;
    year = 1601;
    while (1) {
        uint32_t days_in_year = 365;
        if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) {
            days_in_year = 366;
        }

        if (days_since_1601 < days_in_year)
            break;
        days_since_1601 -= days_in_year;
        year++;
    }

    uint32_t days_in_months[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) {
        days_in_months[1] = 29;
    }

    uint32_t month = 1;
    while (month <= 12 && days_since_1601 >= days_in_months[month - 1]) {
        days_since_1601 -= days_in_months[month - 1];
        month++;
    }

    uint32_t day = (uint32_t)days_since_1601 + 1;

    uint64_t total_seconds = remaining_100ns / 10000000ULL;
    uint32_t hours = (uint32_t)(total_seconds / 3600);
    total_seconds %= 3600;
    uint32_t minutes = (uint32_t)(total_seconds / 60);
    uint32_t seconds = (uint32_t)(total_seconds % 60);

    slay_time result = {0};
    result.year = year;
    result.month = month;
    result.day = day;
    result.weeks = 0; // Unused for system time
    result.hours = hours;
    result.minutes = minutes;
    result.seconds = seconds;

    return result;
}

SLAYAPI slay_time slay_get_date_and_time_local(void) {
    PKUSER_SHARED_DATA kuser = (PKUSER_SHARED_DATA)KUSER_SHARED_DATA_ADDRESS;

    LARGE_INTEGER system_time = {0};
    do {
        system_time.HighPart = kuser->SystemTime.High1Time;
        system_time.LowPart = kuser->SystemTime.LowPart;
    } while (system_time.HighPart != kuser->SystemTime.High2Time);

    LARGE_INTEGER timezone_bias = {0};
    do {
        timezone_bias.HighPart = kuser->TimeZoneBias.High1Time;
        timezone_bias.LowPart = kuser->TimeZoneBias.LowPart;
    } while (timezone_bias.HighPart != kuser->TimeZoneBias.High2Time);

    uint64_t local_time_100ns = system_time.QuadPart - timezone_bias.QuadPart;

    uint64_t total_days = local_time_100ns / (10000000ULL * 60 * 60 * 24); // 100ns to days
    uint64_t remaining_100ns = local_time_100ns % (10000000ULL * 60 * 60 * 24);

    uint32_t year = 1601 + (uint32_t)(total_days / 365.25);

    uint64_t days_since_1601 = total_days;
    year = 1601;
    while (1) {
        uint32_t days_in_year = 365;

        if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) {
            days_in_year = 366;
        }

        if (days_since_1601 < days_in_year)
            break;
        days_since_1601 -= days_in_year;
        year++;
    }

    uint32_t days_in_months[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) {
        days_in_months[1] = 29;
    }

    uint32_t month = 1;
    while (month <= 12 && days_since_1601 >= days_in_months[month - 1]) {
        days_since_1601 -= days_in_months[month - 1];
        month++;
    }

    uint32_t day = (uint32_t)days_since_1601 + 1;

    uint64_t total_seconds = remaining_100ns / 10000000ULL;
    uint32_t hours = (uint32_t)(total_seconds / 3600);
    total_seconds %= 3600;
    uint32_t minutes = (uint32_t)(total_seconds / 60);
    uint32_t seconds = (uint32_t)(total_seconds % 60);

    slay_time result = {0};
    result.year = year;
    result.month = month;
    result.day = day;
    result.weeks = 0; // Unused for system time
    result.hours = hours;
    result.minutes = minutes;
    result.seconds = seconds;

    return result;
}

SLAYAPI slay_time slay_get_time_since_boot(void) {
    PKUSER_SHARED_DATA kuser = (PKUSER_SHARED_DATA)KUSER_SHARED_DATA_ADDRESS;
    LARGE_INTEGER time = {0};

    do {
        time.HighPart = kuser->TickCount.High1Time;
        time.LowPart = kuser->TickCount.LowPart;
    } while (time.HighPart != kuser->TickCount.High2Time);

    uint64_t tick_ms = ((uint64_t)time.QuadPart * kuser->TickCountMultiplier) >> 24;
    uint64_t total_seconds = tick_ms / 1000;
    uint32_t total_days = (uint32_t)(total_seconds / (24 * 60 * 60));
    uint32_t remaining_seconds = (uint32_t)(total_seconds % (24 * 60 * 60));

    uint32_t years = total_days / 365;
    uint32_t remaining_days = total_days % 365;

    uint32_t leap_days = years / 4 - years / 100 + years / 400;
    if (remaining_days >= leap_days && years > 0) {
        remaining_days -= leap_days;
    }

    uint32_t months = remaining_days / 30;
    remaining_days %= 30;

    uint32_t weeks = remaining_days / 7;
    remaining_days %= 7;

    uint32_t hours = remaining_seconds / 3600;
    remaining_seconds %= 3600;
    uint32_t minutes = remaining_seconds / 60;
    uint32_t seconds = remaining_seconds % 60;

    slay_time result = {0};
    result.year = years;
    result.month = months;
    result.weeks = weeks;
    result.day = remaining_days;
    result.hours = hours;
    result.minutes = minutes;
    result.seconds = seconds;

    return result;
}

void win32_init_timer(void) {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    g_app_start_time = counter.QuadPart;
}

SLAYAPI void slay_init() {
    win32_init_timer();
}

SLAYAPI double slay_get_time_since_slay_started(void) {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);

    uint64_t elapsed_ticks = counter.QuadPart - g_app_start_time;

    // Get frequency from KUSER_SHARED_DATA (Windows 8+) or fall back to API
    PKUSER_SHARED_DATA kuser = (PKUSER_SHARED_DATA)KUSER_SHARED_DATA_ADDRESS;
    uint64_t frequency = kuser->QpcFrequency;

    // Fallback to API if frequency is 0 (older Windows versions)
    if (frequency == 0) {
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);
        frequency = freq.QuadPart;
    }

    return (double)elapsed_ticks / (double)frequency;
}

SLAYAPI uint64_t slay_get_timer(void) {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return counter.QuadPart;
}

// Gets the frequency of the raw timer that is used by slay, not including any time the computer
// is sleeping while slay is running.
SLAYAPI uint64_t slay_get_timer_frequency(void) {
    PKUSER_SHARED_DATA kuser = (PKUSER_SHARED_DATA)KUSER_SHARED_DATA_ADDRESS;
    uint64_t frequency = kuser->QpcFrequency;
    // Fallback to API if frequency is 0 (older Windows versions)
    if (frequency == 0) {
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);
        frequency = freq.QuadPart;
    }

    return frequency;
}
//----------------------------------------------------------------------------------
// Multi-threadding functions.
//----------------------------------------------------------------------------------
SLAYAPI slay_mutex *slay_create_mutex() {
    slay_mutex *mutex = malloc(sizeof(*mutex));
    if (!mutex) return NULL;
    InitializeCriticalSection(&mutex->cs);
    return mutex;
}

SLAYAPI void slay_lock_mutex(slay_mutex *mutex) {
    EnterCriticalSection(&mutex->cs);
}

SLAYAPI slay_bool slay_lock_mutex_try(slay_mutex *mutex) {
    return TryEnterCriticalSection(&mutex->cs) ? 1 : 0;
}

SLAYAPI void slay_unlock_mutex(slay_mutex *mutex) {
    LeaveCriticalSection(&mutex->cs);
}

SLAYAPI void slay_destroy_mutex(slay_mutex *mutex) {
    DeleteCriticalSection(&mutex->cs);
    free(mutex);
}

SLAYAPI slay_signal *slay_create_signal(void) {
    // Manual-reset event, initially non-signaled
    return (slay_signal *)CreateEventW(NULL, TRUE, FALSE, NULL);
}

SLAYAPI slay_bool slay_wait_for_signal(slay_signal *signal, slay_mutex *mutex) {
    if (!signal)
        return slay_false;

    // Release the mutex so other threads can activate the signal
    if (mutex)
        slay_unlock_mutex(mutex);

    // Wait for the signal to be activated
    DWORD result = WaitForSingleObject((HANDLE)signal, INFINITE);

    // Reacquire the mutex before returning
    if (mutex)
        slay_lock_mutex(mutex);

    return (result == WAIT_OBJECT_0);
}

SLAYAPI slay_bool slay_activate_signal(slay_signal *signal) {
    if (!signal)
        return slay_false;

    return SetEvent((HANDLE)signal) ? slay_true : slay_false;
}

SLAYAPI slay_bool slay_deactivate_signal(slay_signal *signal) {
    if (!signal)
        return slay_false;

    return ResetEvent((HANDLE)signal) ? slay_true : slay_false;
}

SLAYAPI void slay_destroy_signal(slay_signal *signal) {
    if (signal)
        CloseHandle((HANDLE)signal);
}

typedef struct {
    slay_thread_func func;
    void *arg;
} thread_wrapper_arg;

// Wrapper to adapt slay_thread_func to Windows signature
DWORD WINAPI thread_wrapper(LPVOID param) {
    thread_wrapper_arg *wrapper = (thread_wrapper_arg *)param;
    wrapper->func(wrapper->arg);
    HeapFree(GetProcessHeap(), 0, wrapper);
    return 0;
}

SLAYAPI slay_thread *slay_create_thread(slay_thread_func func, void *arg) {
    thread_wrapper_arg *wrapper = (thread_wrapper_arg *)HeapAlloc(GetProcessHeap(), 0, sizeof(thread_wrapper_arg));
    if (!wrapper) return NULL;
    wrapper->func = func;
    wrapper->arg = arg;

    HANDLE thread = CreateThread(NULL, 0, thread_wrapper, wrapper, CREATE_SUSPENDED, NULL);
    return (slay_thread *)thread;
}

SLAYAPI slay_bool slay_start_thread(slay_thread *thread) {
    if (!thread) return slay_false;
    return ResumeThread((HANDLE)thread) != (DWORD)-1;
}

SLAYAPI slay_bool slay_join_thread(slay_thread *thread) {
    if (!thread) return slay_false;
    return WaitForSingleObject((HANDLE)thread, INFINITE) == WAIT_OBJECT_0;
}

SLAYAPI void slay_destroy_thread(slay_thread *thread) {
    if (thread) CloseHandle((HANDLE)thread);
}

//----------------------------------------------------------------------------------
// Dynamic Library Functions.
//----------------------------------------------------------------------------------
SLAYAPI void* slay_load_dynamic_library(const char* dll) {
    HMODULE result = LoadLibraryA(dll);
    return (void*)result;
}

SLAYAPI void* slay_load_dynamic_function(void* dll, char* func_name) {
    FARPROC proc = GetProcAddress(dll, func_name);
    return (void*)proc;
}

SLAYAPI slay_bool slay_free_dynamic_library(void* dll) {
    slay_bool free_result = FreeLibrary(dll);
    return (slay_bool)free_result;
}

//----------------------------------------------------------------------------------
// Execute other programs.
//----------------------------------------------------------------------------------
SLAYAPI slay_bool slay_execute(const char *command, slay_bool wait_for_command_to_finish) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // CreateProcessA modifies the command line buffer, so copy it
    char cmdline[MAX_PATH * 4];
    strncpy(cmdline, command, sizeof(cmdline) - 1);
    cmdline[sizeof(cmdline) - 1] = '\0';

    if (!CreateProcessA(
            NULL,           // application name
            cmdline,        // command line
            NULL,           // process attributes
            NULL,           // thread attributes
            FALSE,          // inherit handles
            0,              // creation flags
            NULL,           // environment
            NULL,           // current directory
            &si,
            &pi)) {
        return slay_false;
    }

    // Optionally wait for process to finish
    if (wait_for_command_to_finish) {
		WaitForSingleObject(pi.hProcess, INFINITE);
    }

    // Clean up handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return slay_true;
}
#endif // WIN32_PLATFORM_H