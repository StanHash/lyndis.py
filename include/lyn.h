/* Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */

/*
 * This header defines a few helper macros for defining lyndis directives from
 * within C source files. Directives within assembly files need to be written
 * manually.
 *
 * The macros defined are:
 * - lyn_replace(name): put this before a function definition. Marks that
 *   function as being a replacement for the existing function with that name.
 * - lyn_at(addr): put this before a function or object definition. Lyndis will
 *   place that function or object at the given address.
 * - lyn_free(addr, size): standalone directive (end it with ';'!). Marks free
 *   space (that is, space lyndis is allowed to put new stuff in).
 * - lyn_purge(name): standalone directive (end it with ';'!). Marks the given
 *   symbol as being purged (that is, it cannot be referenced, and the space it
 *   occupied is now considered free space).
 *
 * - lyn_word_at(addr): helper that defines a word at given addr.
 *   use as such: "lyn_word_at(0xDEADBEEF) = 0xCAFEBABE;"
 * - lyn_addr_at(addr), lyn_half_at(addr), lyn_byte_at(addr): same as above for
 *   other data types
 * - lyn_words_at(addr), ...: same as above, but for arrays.
 */

#ifndef LYN_HELPERS_H
#define LYN_HELPERS_H

#define LYN__KEEP __attribute__((used))
#define LYN__SECTION(name) __attribute__((section(name)))

// directives applied to functions and/or objects
#define lyn_replace(name) LYN__SECTION("__lyn.replace_" #name)
#define lyn_at(addr) LYN__SECTION("__lyn.at_" #addr)

// standalone directives
#define lyn_free(addr, size) LYN__SECTION("__lyn.meta") LYN__KEEP static char const __lyn$_meta_free_##addr[] = "free " #addr " " #size
#define lyn_purge(name) LYN__SECTION("__lyn.meta") LYN__KEEP static char const __lyn$_meta_purge_##name[] = "purge " #name

// helpers
#define lyn_word_at(addr) lyn_at(addr) LYN__KEEP static unsigned int const __lyn$_word_at_##addr
#define lyn_addr_at(addr) lyn_at(addr) LYN__KEEP static void const * const __lyn$_addr_at_##addr
#define lyn_half_at(addr) lyn_at(addr) LYN__KEEP static unsigned short const __lyn$_half_at_##addr
#define lyn_byte_at(addr) lyn_at(addr) LYN__KEEP static unsigned char const __lyn$__at_##addr

#define lyn_words_at(addr) lyn_word_at(addr)[]
#define lyn_addrs_at(addr) lyn_addr_at(addr)[]
#define lyn_halfs_at(addr) lyn_half_at(addr)[]
#define lyn_bytes_at(addr) lyn_byte_at(addr)[]

#endif // LYN_HELPERS_H
