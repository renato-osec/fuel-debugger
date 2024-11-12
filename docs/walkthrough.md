## example usage

Spin up a local node, with a funded account by 

```bash
fuel-core run --snapshot ${PATH_TO_CONFIG} --db-type in-memory --debug
```
Deploy a contract and serialize a json tx for it (see mira example)

If youd like to inspect the bytecode of called contracts you can run

```
forc parse-bytecode ${PATH_TO_BIN}
```

## Using the debugger

Execute the `debugger`. The cli interface presents several commands :
    - `n,start_tx <json_file_path>` : run a serialized tx
    - `b [contract_id] <pc>` : set a breakpoint at a given pc for a certain contract (default 0x0 for the main script)
    - `c` : continue
    - `reset` : remove all breakpoints
    - `s [on/off]` : enter/exit single stepping mode
    - `r,reg <reg_name/id>` : inspect a reg
    - `m, mem <offset> <len>` : read a slice of memory
    - `code [offset]` : read mem as code (default $pc)
    - `frame` : get info about current call frame, if any
    - `search [start] [end] <pattern>` : search for a pattern in memory
