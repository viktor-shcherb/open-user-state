# AGENTS.md

## Documentation
guidelines:
  - **File/Module Headers**  
    - Add or enrich a top‑of‑file comment that describes:
      - the overall purpose of this module  
      - its place in the system’s architecture  
      - key design decisions or patterns used
  - **High‑Level Sections**  
    - Before each major section or logical block, insert a brief comment summarizing:
      - the problem being solved in this block  
      - why this approach was chosen (performance, clarity, reusability, etc.)
  - **Types & Classes**  
    - For each class or type definition, explain:
      - its role in the domain model  
      - any invariants or assumptions  
      - how it interacts with others
  - **Inline Comments**  
    - For any non‑trivial algorithm, transformation, or conditional:
      - write a short inline note on **why** it’s needed  
      - describe any trade‑offs or edge cases handled
  - **Avoid “What”**  
    - Don’t restate code semantics or syntax  
    - Assume a reader can read the code; focus on rationale, context, and intent.
