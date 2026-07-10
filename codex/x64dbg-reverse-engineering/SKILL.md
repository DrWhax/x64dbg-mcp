---
name: x64dbg-reverse-engineering
description: Reverse-engineer, debug, unpack, trace, analyze, dump, or patch Windows binaries through the x64dbg/x32dbg MCP server. Use when a task requires live debugger state, registers, memory, disassembly, symbols, breakpoints, API monitoring, vulnerability research, crash analysis, algorithm identification, or binary patching.
---

# x64dbg Reverse Engineering

Use the x64dbg MCP tools to perform evidence-driven Windows binary analysis. Ask for the target path, address, symbol, or analysis goal when it is not provided. Treat live debugger state as authoritative and distinguish observed facts from hypotheses.

## Connection and safety

- Confirm the MCP server is connected before attempting debugger calls. The expected Streamable HTTP endpoint is `http://192.168.1.110:3000/mcp`.
- Begin investigations with `debug_get_state`, `module_get_main`, and an appropriate context query.
- Prefer read-only inspection first. Before `memory_write`, `register_set`, script execution, or patching, explain the effect and obtain explicit user confirmation; preserve original bytes and verify afterward.
- Use underscore tool names such as `disassembly_at`, `memory_read`, and `breakpoint_set` exactly as exposed by the server.
- Report addresses in hexadecimal, identify the architecture (x86/x64), and cite the tool observations supporting conclusions.

## Choose a workflow

Read the matching workflow in [workflows.md](references/workflows.md) and follow its phases. The slash-command arguments map to ordinary user-provided values: `debug-session issue`, `analyze-crash address`, `trace-function symbol`, and so on.

- New target or general triage: **debug session**
- Exception or access violation: **crash analysis**
- Packed/protected target: **unpacking**
- Function behavior: **function tracing** or **algorithm analysis**
- Security review: **vulnerability assessment**
- API behavior: **API monitoring**
- Interesting constants/text: **string hunting**
- Before/after execution behavior: **state comparison**
- Memory extraction: **memory dumping**
- Controlled modification: **binary patching**

## Core investigation habits

- Resolve symbols before guessing addresses; use `symbol_resolve`, `symbol_from_address`, and `function_get`.
- Correlate `module_list`, `module_get_imports`, memory regions, and section protections before interpreting code.
- Use `xref_get` to move from data or APIs to code, then inspect callers and callees with `disassembly_at` or `disassembly_function`.
- For x64 Windows fastcall, inspect RCX/RDX/R8/R9; for x86, inspect stack arguments. Return values are commonly in RAX/EAX.
- For dynamic behavior, combine breakpoints/logging, `context_get_snapshot`, stepping, and `context_compare_snapshots`.
- Do not claim exploitability, an algorithm identity, or an unpacking OEP without recording the concrete evidence and confidence.

## Tool reference

Use the workflow reference below for the calls needed for each supported task.
