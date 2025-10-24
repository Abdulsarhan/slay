#ifndef SLAY_H
#define SLAY_H

#include <stdint.h>   // For Clearly Defined Types.
#include <sys/stat.h> // For time_t and stat.
typedef uint8_t slay_bool;

typedef struct {
	void* handle;
} slay_file;

typedef struct {
    uint32_t year;
    uint32_t month;
    uint32_t weeks;
    uint32_t day;
    uint32_t hours;
    uint32_t minutes;
    uint32_t seconds;
} slay_time;

#if defined(_WIN32)
#if defined(__TINYC__)
#define __declspec(x) __attribute__((x))
#endif

#if defined(PAL_BUILD_SHARED)
#define SLAYAPI __declspec(dllexport) // We are building the library as a Win32 shared library (.dll)
#elif defined(PAL_USE_SHARED)
#define SLAYAPI __declspec(dllimport) // We are using the library as a Win32 shared library (.dll)
#endif

#else
#if defined(PAL_BUILD_SHARED)
#define SLAYAPI __attribute__((visibility("default"))) // We are building as a Unix shared library (.so/.dylib)
#endif
#endif

#ifndef SLAYAPI
#define SLAYAPI extern // extern is default, but it doesn't hurt to be explicit.
#endif

#define SLAY_READ 0x01
#define SLAY_WRITE 0x02
#define SLAY_EXECUTE 0x04

#if defined(__cplusplus)
#define CLITERAL(type) type
#else
#define CLITERAL(type) (type)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// File I/O
SLAYAPI slay_bool slay_does_file_exist(const char* file_path);
SLAYAPI size_t slay_get_last_write_time(const char* file);
SLAYAPI size_t slay_get_last_read_time(const char* file);
SLAYAPI size_t slay_get_file_size(const char* file_path);
SLAYAPI uint32_t slay_get_file_permissions(const char* file_path);
SLAYAPI slay_bool slay_change_file_permissions(const char* file_path, uint32_t permission_flags);
SLAYAPI unsigned char* slay_read_entire_file(const char* file_path, size_t* bytes_read);
SLAYAPI slay_bool slay_write_file(const char* file_path, size_t file_size, char* buffer);
SLAYAPI slay_bool slay_copy_file(const char* original_path, const char* copy_path);

// Open File I/O
SLAYAPI slay_file* slay_open_file(const char* file_path);
SLAYAPI slay_bool slay_read_from_open_file(slay_file* file, size_t offset, size_t bytes_to_read, char* buffer);
SLAYAPI slay_bool slay_close_file(slay_file* file);

// Random Number Generation
SLAYAPI void slay_srand(uint64_t* state, uint64_t seed);
SLAYAPI uint32_t slay_rand(uint64_t* state);

// Clip board
SLAYAPI void slay_clipboard_set(const char* text);
SLAYAPI char* slay_clipboard_get(void);

// URL launch
SLAYAPI void slay_url_launch(char* url);

// File dialog / requester
SLAYAPI void slay_create_save_dialog(char** types, uint32_t type_count, void* id);
SLAYAPI void slay_create_load_dialog(char** types, uint32_t type_count, void* id);
SLAYAPI char* slay_show_save_dialog(void* id);
SLAYAPI char* slay_show_load_dialog(void* id);

// String parsing functions.
SLAYAPI slay_bool slay_is_uppercase(char ch);
SLAYAPI slay_bool slay_is_lowercase(char ch);
SLAYAPI slay_bool slay_is_letter(char ch);
SLAYAPI slay_bool slay_is_end_of_line(char ch);
SLAYAPI slay_bool slay_is_whitespace(char ch);
SLAYAPI slay_bool slay_is_number(char ch);
SLAYAPI slay_bool slay_is_alphanumeric(char ch);
SLAYAPI slay_bool slay_is_underscore(char ch);
SLAYAPI slay_bool slay_is_hyphen(char ch);
SLAYAPI slay_bool slay_is_dot(char ch);
SLAYAPI slay_bool slay_are_chars_equal(char ch1, char ch2);
SLAYAPI slay_bool slay_are_strings_equal(const char *s1, const char *s2);
SLAYAPI int slay_strcmp(const char *s1, const char *s2);
SLAYAPI int slay_strncmp(const char *s1, const char *s2, size_t n);

// Time functions
SLAYAPI slay_time slay_get_date_and_time_utc(void);
SLAYAPI slay_time slay_get_date_and_time_local(void);
SLAYAPI slay_time slay_get_time_since_boot(void);
SLAYAPI double slay_get_time_since_slay_started(void);
SLAYAPI uint64_t slay_get_timer(void);
SLAYAPI uint64_t slay_get_timer_frequency(void);

// .dll/.so/.dylib loading
SLAYAPI void *slay_load_dynamic_library(const char *dll);
SLAYAPI void *slay_load_dynamic_function(void *dll, char *func_name);
SLAYAPI slay_bool slay_free_dynamic_library(void *dll);

#ifdef __cplusplus
}
#endif

#endif // SLAY_H
