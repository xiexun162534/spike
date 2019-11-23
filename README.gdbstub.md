# Usage
In a terminal,
``` shell
spike --gdb-port=<port> <program>
```
and then in another terminal, run gdb and use `target remote localhost:<port>` to connect.

# How to print CSRs?
In gdb,
```
target remote localhost:1234
set tdesc /path/to/spike/riscv/gdb-xml/riscv-target.xml
```
