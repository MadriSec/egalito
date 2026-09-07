Test levels:
- fast
- normal
- full

Unit test overview

The runner executes both synthetic tests and ELF-based tests. The ELF fixtures
are stored in `test/binary/build/` and are selected through `TESTDIR` in the
unit test Makefile.

Synthetic tests (no ELF file required)
- `analysis/_flow.cpp`: checks forward and backward data-flow propagation.
- `analysis/_jumptable_cycle.cpp`: checks that jump-table base-address lookup
	does not loop on cyclic state graphs.
- `analysis/_jumptable_active_lookup.cpp`: checks that active base-address
	lookups are skipped safely.
- `pass/_promotejumps.cpp`: checks displacement range helpers.
- `chunk/_mutator.cpp`: checks chunk insertion and append operations.
- `log/_temp.cpp`: checks temporary log-level scoping.
- `util/_intervaltree.cpp`: checks interval-tree add, remove, overlap, and
	bound queries.

ELF-based tests
- `disasm/_disassemble.cpp`: reads `hello`, `hello-s`, and `hi5` and checks
	ELF parsing, symbol-based disassembly, and fuzzy function recovery.
- `elf/_elfmap.cpp`: reads `hello` and checks that the ELF is dynamic.
- `elf/_symbol.cpp`: reads `hello` and `hi5` and checks symbol-list creation,
	plus ARM mapping-symbol support.
- `analysis/_walker.cpp`: reads `cfg` and checks CFG traversal orders.
- `analysis/_jumptable.cpp`: reads `jumptable` and checks jump-table detection
	in `main`, in selected libc functions, and on all libc tables for completeness.
- `chunk/_position.cpp`: reads `hi0` and checks position integrity before and
	after chunk mutation.
- `pass/_stackextend.cpp`: reads `stack` and checks stack-frame extension on
	the main binary and in libc on AArch64.
- `pass/_instrumentcalls.cpp`: reads `log` and checks call instrumentation on
	the main binary on AArch64.
- `pass/_regreplace.cpp`: reads `stack` and checks register replacement across
	libc on AArch64.

Platform-specific notes
- Some tests are compiled only on one architecture, such as x86_64, AArch64,
	or ARM.
- The exact ELF contents depend on the target libc and platform used to build
	the fixtures, so the expected counts in the configs are not universal.
