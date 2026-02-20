# lyndis.py

A prototypal "patching linker", which links object files directly to an existing binary. It was designed as a binary ROM hacking tool, targeting GBA ROMs in particular. For that reason, it only handles 32bit ARM objects.

This is very experimental, not very stable, full of hacks (and probably full of bugs as well), has very bad error handling/reporting, lacks documentation, and has barely been used in any kind of significant work. (Have fun!)

## Usage

Let's assume you have a few source files and a way to compile them.

You invoke lyndis as such

    {python 3} lyndis.py base.gba target.gba a.o b.o...

However, this won't just work with just a bunch of regular objects. At least some of them need to embed "lyn directives". The simplest way to do so it to use the included helper header [lyn.h](include/lyn.h). Following is a example C snippet demonstrating use of some of these directives:

```c
#include <lyn.h>

/* We assume the base ROM is only 16MiB in size.
 * mark the rest of the available address range as free */
lyn_free(0x09000000, 0x01000000);

/* Replace a string pointer at a specific location */
lyn_at(0x0800ABDC) char const * const my_new_string_pointer = "Hello World!";

/* Replace a string pointer at a specific location using shorter helper */
lyn_addr_at(0x0800ACDC) = "Hello World!";

/* Replace a function at a specific location */
lyn_at(0x0800048C) void NewFunction(void)
{
    /* ... */
}

/* Replace a few instructions. We could also have used a 32bit object with
 * value 0x46C046C0 to achieve the same result */
lyn_at(0x08000C84) [[gnu::naked]] void hook_08000C84(void)
{
    /* dummy out a few instructions, as an example */
    asm("nop\n"
        "nop\n");
}
```

### Reference files

lyndis can take a reference file. To do so, use the `-r {path to reference file}` command line argument.

A reference file is a text file that describes the base binary. It contains information about existing symbols, ranges of "free space" available by default, and allows changing the corresponding address range.

An example reference, describing fe6, is available here: [goodies/fe6_reference.txt](goodies/fe6_reference.txt). Most of it was generated using [goodies/elf2ref.py](goodies/elf2ref.py).

Using a reference file that defines base symbols allows the use of the "replace" and "purge" directives, like in the following hypothetical C patch:

```c
#include <lyn.h>

/* the function GetItemSpeedBonus is now unused, we can purge it to make
 * more room for other things */
lyn_purge(GetItemSpeedBonus);

/* replace the base function GetUnitSpeed with our own new implementation */
lyn_replace(GetUnitSpeed)
int GetUnitSpeed(struct Unit * unit)
{
    /* ... */
}
```

### map files

lyndis can produce a map file, that describes where things went in the target binary. To do so, use the `-m {path to desired output file}` command line argument. This can help debugging.

## How does it work?

lyndis takes a set of object files, compiled using conventional toolchains (GCC...),
and inserts it into a binary (in our case, a GBA ROM).

These objects may or may not contain special "directives" embedded into section
names, which gets lyndis behave in special ways. These directives must be
prefixed by `__lyn.`.

For example, a section whose name ends with `__lyn.replace_GetUnit` will replace
the function GetUnit.

List of supported directives:

* `at_{address}`: specifies that this section should be placed at the given
  address.

* `replace_{name}`: specifies that this section replaces the symbol named {name}
  that section may declare a symbol with the same name at the start of the
  section.
  If {name} is a function, lyndis is allowed to insert trampolines if the new
  section doesn't fit the function (if that function has a size parameter).

* `meta`: a `__lyn.meta` section contains strings that are commands to lyndis.
  This is where you can purge reference symbols (`purge {name}`) or define free
  space (`free {address} {length}`). Command strings are separated by the null
  character.

## Relation to "lyn"

The name of this tool is "lyndis", which implies a connection with another related but different tool I have written named "[lyn](https://github.com/StanHash/lyn)".

Both of these tools take the same kind of input (object files), but have different targets:

- lyn produces event files to be fed to Event Assembler, which allowed the use of conventional toolchains (GCC...) within exisiting ROM hacking environments. (EA-based GBAFE hacking was especially popular at the time lyn was originally written).
- lyndis is a standalone tool, that forgoes EA entirely and simply patches the ROM itself directly.

A planned rewrite of the original lyn ("lyn 3") was meant to be able to understand the same kind of directives as lyndis, which would in turn allow interoperability between the two tools.

This python implementation of lyndis was meant as a prototype implementation of a better, cleaner version probably written in C++ like the original lyn. This is why this is "lyndis.py" and not just "lyndis".

As with lyn, the name "lyndis" is meant to be stylized with a lowercase 'L'. This is to distinguish the name of the tools from the name of everybody's favorite tutorial lord.

## License

lyndis.py and lyn.h are marked with CC0 1.0. To view a copy of this license, visit https://creativecommons.org/publicdomain/zero/1.0/
