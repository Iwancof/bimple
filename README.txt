# What is this.

this is tool to convert binary which needs dynamic library into statical binary.
Inspired by `statifier`

# Usage

```sh
$ make
$ ./main target_binary
$ musl-gcc ./result.c -nostdlib -lc -o result

$ ./result
```

this will be changed soon...

# Currently support
- we can call libc function.

