# x64dbg MCP workflows

`$1` means the value supplied by the user in natural language. Execute calls through the registered x64dbg MCP server and adapt parameters to the server's tool schemas.

## Debug session

1. Call `debug_get_state`, `module_get_main`, `module_list`, `thread_list`, and `register_list`.
2. If paused at a valid instruction, inspect the current RIP/EIP with `disassembly_at` (about 20 instructions), then call `stack_get_trace` and `breakpoint_list`.
3. Inspect main-module imports with `module_get_imports`; use `function_list` after `script_execute` with `cfanal` only when analysis is missing.
4. Report target, state, architecture, modules, current location, stack, breakpoints, and recommendations tied to the user's issue.

## Crash analysis

1. Confirm a paused exception with `debug_get_state`; capture `register_list`, `disassembly_at` at the supplied crash address or current RIP/EIP, `stack_get_trace`, and `stack_get_pointers`.
2. For pointer operands, call `memory_get_info` and, when valid, `memory_read`; inspect roughly 256 bytes around RSP/ESP.
3. Use `symbol_from_address`, `module_get`, `function_get`, and `xref_get` to establish ownership and callers.
4. Classify only with evidence: null dereference, use-after-free, buffer/stack overflow, DEP violation, integer overflow, uninitialized memory, or double free. Report the faulting instruction, exception access, evidence, root cause, and next breakpoints.

## Unpacking

1. Use `module_get_main`, `dump_analyze_module`, `module_get_imports`, and entry-point `disassembly_at` to assess sections, entropy, imports, and packer indicators.
2. Try `dump_detect_oep`; otherwise monitor likely unpacking APIs (for example `VirtualProtect` or `VirtualAlloc`) with breakpoints and inspect candidate code.
3. Verify a candidate OEP with `debug_run_to`, `debug_get_state`, `function_get`, and `disassembly_at`; bookmark it.
4. Call `dump_module` with the module, output path, and OEP, then verify with `dump_analyze_module`, imports, and dumpable regions. Clearly label uncertain or partial results.

## Function tracing

1. Resolve a symbol with `symbol_resolve`/`symbol_search`, or accept a hexadecimal address. Then use `disassembly_function`, `symbol_from_address`, `memory_get_info`, `function_get`, and `xref_get`.
2. Identify calling convention, parameters, calls, branches, loops, returns, and data references.
3. Set an entry breakpoint and logging breakpoint; log RCX/RDX/R8/R9 on x64 or stack arguments on x86. Add exit logging at relevant RET sites and key calls.
4. Capture entry/exit with `context_get_snapshot`, step carefully, compare with `context_compare_snapshots`, and report control flow, parameters, calls, return value, and breakpoints.

## Algorithm analysis

1. Inspect the complete function with `disassembly_function`; fall back to `disassembly_at` with a larger count if boundaries fail.
2. Resolve symbols, ownership, callers, data references, constants, lookup tables, and control-flow blocks.
3. If paused at entry, inspect registers and stack arguments; use `debug_step_over` and `eval_expression` for dynamic evidence.
4. Give an estimated signature and pseudocode, but separate known facts from algorithm hypotheses and include confidence. Check common constants such as MD5/SHA, CRC, ChaCha20, Base64, and TEA/XTEA only as leads.

## API monitoring

1. Call `module_get_imports` first and monitor only imported or dynamically resolved APIs.
2. Categories: file (`CreateFile`, `ReadFile`, `WriteFile`), network (`connect`, `send`, `recv`, WinINet), registry, crypto, process injection (`CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory`), and memory (`VirtualAlloc`, `VirtualProtect`, `LoadLibrary`, `GetProcAddress`).
3. Resolve each target with `symbol_resolve`, set a breakpoint, and configure `breakpoint_set_log` with architecture-appropriate parameter formatting. Use conditions to reduce noise.
4. Report resolved/unresolved APIs and logging formats; do not infer behavior until calls are observed.

## Vulnerability assessment

1. Establish target and mitigations with `module_get_main`, `module_list`, `dump_analyze_module`, `module_get_imports`, and `function_list`.
2. Search for risky APIs and symbols (copy/format functions, heap allocation, command execution, file/path APIs), then use `xref_get` and `disassembly_at` at each call site.
3. Trace input sources such as `ReadFile`, `recv`, `WSARecv`, window-text APIs, and registry reads toward sinks. Look for missing bounds checks, unchecked sizes, unsafe format strings, and lifetime mistakes.
4. Report findings with location, evidence, severity, mitigation status, exploitability confidence, and remediation. Do not call a pattern a vulnerability without data-flow or runtime evidence.

## String hunting

1. Identify the target and layout with `module_get_main`, `module_list`, and `dump_analyze_module`.
2. Search the main-module range with `memory_search` for the requested pattern and its UTF-16LE form; without a pattern, check credentials, URLs, file paths, errors, registry keys, and crypto terms.
3. For each hit, use `memory_read`, `xref_get`, `disassembly_at`, `symbol_from_address`, and `function_get` to establish usage. If direct xrefs fail, search for the address bytes in code.
4. Group results by category and prioritize strings that influence network, authentication, file, or control-flow behavior.

## State comparison

1. At paused point A, call `context_get_snapshot` with stack/memory enabled, `register_list`, `disassembly_at`, `stack_get_trace`, and `bookmark_set`.
2. Ask the user to advance execution, then capture the same data at point B.
3. Call `context_compare_snapshots`; supplement it with `eval_expression` for changed stack slots and analyze registers, flags, stack, memory, and control flow.
4. Report exact deltas and a concise explanation of what occurred between points.

## Memory dumping

1. Call `debug_get_state`, `memory_enumerate`, `module_list`, and `dump_get_dumpable_regions`.
2. For an address, call `memory_get_info`; for the main module, call `module_get_main`, `dump_analyze_module`, and imports. Use `eval_expression` for computed addresses.
3. Inspect the first 256 bytes with `memory_read`; recognize MZ/PE, archive, text, and high-entropy indicators.
4. Use `dump_module` for a PE or `dump_memory_region` with `as_raw_binary: true` for raw memory. Verify with `dump_analyze_module` and bookmark the region. Never overwrite an existing output without confirmation.

## Binary patching

1. Parse the goal/address, then inspect with `disassembly_at`, `symbol_from_address`, `function_get`, `disassembly_function`, and `xref_get`.
2. Preview instructions with `assembler_assemble` using `write_to_memory: false`; show original bytes/disassembly and proposed bytes/disassembly.
3. Obtain explicit confirmation. Back up with `memory_read`, then apply with `assembler_assemble` (`write_to_memory: true`) or `memory_write`.
4. Verify with `disassembly_at`, inspect `patch_list`, bookmark the address, and explain rollback with `patch_restore`. Persist only through an explicitly requested dump.
