// TODO: replace this by C++ or Rust.

#define PACKAGE "bimple"
#define PACKAGE_VERSION "0.1"

#include <libgen.h>
#include <linux/elf.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bfd.h>

typedef struct {
  size_t start, end, size;
  int readable, writable, executable, private;
  char *path;
  char *content;
  // path is from heap.
} map_object;

map_object create_map_object(size_t start, size_t end, size_t size,
                             char perm[5], char *path) {
  map_object mo = {.start = start,
                   .end = end,
                   .size = size,
                   .readable = 0,
                   .writable = 0,
                   .executable = 0,
                   .private = 0};

  size_t len = strlen(path) + 1;
  char *new_path = (char *)malloc(len);
  strncpy(new_path, path, len);

  mo.path = new_path;

  if (perm[0] == 'r') {
    mo.readable = 1;
  }
  if (perm[1] == 'w') {
    mo.writable = 1;
  }
  if (perm[2] == 'x') {
    mo.executable = 1;
  }
  if (perm[3] == 'p') {
    mo.private = 1;
  }

  char *content = (char *)malloc(mo.size);
  mo.content = content;

  return mo;
}

void print_map_object(char *ident, map_object *mo) {
  printf("%sstart = 0x%lx\n", ident, mo->start);
  printf("%send = 0x%lx\n", ident, mo->end);
  printf("%ssize = 0x%lx\n", ident, mo->size);
  printf("%spath = %s\n", ident, mo->path);
  printf("%sperm = %c%c%c%c\n", ident, mo->readable ? 'r' : '-',
         mo->writable ? 'w' : '-', mo->executable ? 'x' : '-',
         mo->private ? 'p' : '-');
}

void free_map_object(map_object *mo) { free(mo->path); }

const char insert_code[] = {
    0xcc // int3
};

// TODO: separate functions.
int main(int argc, char *argv[], char *envp[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s path_to_dynamic_binary\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  bfd_init();

  char *convert_binary = argv[1];

  struct bfd *abfd = bfd_openr(convert_binary, NULL);
  if (!bfd_check_format(abfd, bfd_object)) {
    fprintf(stderr, "Failed to open binary\n");
    exit(EXIT_FAILURE);
  }

  FILE *binary = fopen(convert_binary, "rb");
  if (binary == NULL) {
    perror("Failed to open binary source");
    exit(EXIT_FAILURE);
  }

  fseek(binary, 0, SEEK_END);
  size_t binary_file_size = ftell(binary);
  char *buffer = (char *)malloc(binary_file_size);
  rewind(binary);

  fread(buffer, 1, binary_file_size, binary);
  fclose(binary);

  bfd_vma entry = bfd_get_start_address(abfd);
  // FIXME: get file offset instead of vm address.
  // this leads to crash on some binaries(e.g. /usr/bin/gcc)
  printf("entry = 0x%lx\n", entry);

  size_t insert_code_size =
      (((sizeof(insert_code) - 1) / sizeof(long)) + 1) * sizeof(long);

  // save old _start
  long *moved_buffer = (long *)malloc(insert_code_size);
  memcpy(moved_buffer, &buffer[entry], insert_code_size);

  // overwrite _start
  memcpy(&buffer[entry], insert_code, sizeof(insert_code));

  bfd_close(abfd);

  // make temporary file and write edited binary.
  char destination_path[] = "/tmp/working_binary_XXXXXX";
  int fd = mkstemp(destination_path);
  write(fd, buffer, binary_file_size);
  close(fd);

  // change file permission.
  chmod(destination_path, 0x777);

  // allocate new argv
  char *new_argv[2];
  new_argv[0] = destination_path;
  new_argv[1] = NULL;

  pid_t child_pid;

  if ((child_pid = fork()) == -1) {
    perror("fork() failed.");
    exit(EXIT_FAILURE);
  }

  if (child_pid == 0) {
    // child

    ptrace(PTRACE_TRACEME, NULL, NULL, NULL);

    // execute binary.
    // FIXME: resolve dynamic libraries specified by relative path.
    execve(destination_path, new_argv, envp);

    fprintf(stderr, "Unreachable");
    exit(EXIT_FAILURE);
  }

  // parent
  int status;
  waitpid(child_pid, &status, 0);

  if (!WIFSTOPPED(status)) {
    fprintf(stderr, "[!] interrupt didn't occure(ld:_start)\n");
    exit(EXIT_FAILURE);
  }
  // child process stopped at ld.so.6:_start

  ptrace(PTRACE_CONT, child_pid, NULL, 0);
  waitpid(child_pid, &status, 0);
  // child process stopped at user:_start

  if (!WIFSTOPPED(status)) {
    fprintf(stderr, "[!] interrupt didn't occure(user:_start)\n");
    exit(EXIT_FAILURE);
  }

  // save registers.
  struct user_regs_struct regs;
  struct iovec v = {.iov_base = &regs,
                    .iov_len = sizeof(struct user_regs_struct)};

  ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &v);
  regs.rip -= sizeof(insert_code); // rip indicate next of insert_code.
  printf("[+] stopped at %p\n", (void *)regs.rip);

  // read all memory data.

  // read maps file.
  char *vmmap_path = (char *)malloc(0x80);
  snprintf(vmmap_path, 0x80, "/proc/%d/maps", child_pid);

  FILE *vmmap = fopen(vmmap_path, "r");
  if (vmmap == NULL) {
    perror("Could not open vmmap");
    exit(EXIT_FAILURE);
  }
  free(vmmap_path);

  size_t vmmap_buffer_size = 0x10000;
  char *vmmap_buffer = malloc(vmmap_buffer_size);
  if (fread(vmmap_buffer, 1, vmmap_buffer_size, vmmap) == vmmap_buffer_size) {
    fprintf(stderr, "extend buffer size");
    exit(EXIT_FAILURE);
  }

  map_object *maps[0x100] = {NULL}; // TODO: use extenable vector.
  size_t map_counter = 0;

  char *token, *line;
  line = strtok_r(vmmap_buffer, "\n", &token);

  size_t user_base_addr = 0;
  do {
    // read map.

    // format: start-end perm size dev inode path
    size_t start, end, size, inode;
    char perm[5], *dev, *path;
    dev = malloc(10);
    path = malloc(100);
    strcpy(path, ""); // initialize.

    sscanf(line, "%lx-%lx %4s %lx %9s %ld %99s", &start, &end, perm, &size, dev,
           &inode, path); // is it safe?

    size = end - start; // TODO:
    free(dev);

    map_object mo = create_map_object(start, end, size, perm, path);
    free(path);

    // read data
    size_t remain = mo.size;
    if (remain % sizeof(long) != 0) {
      fprintf(stderr, "invalid size\n");
      exit(EXIT_FAILURE);
    }

    printf("%s\n", mo.path);

    char *bin_base = basename(strdup(mo.path));           // FIXME: free it.
    char *dest_base = basename(strdup(destination_path)); //

    if (!(strcmp(bin_base, dest_base))) { // FIXME: replace it with strict compare
      if (user_base_addr == 0) { // based on first map.
        user_base_addr = start;

        // restore original binary
        long ret =
            ptrace(PTRACE_POKETEXT, child_pid, start + entry, moved_buffer[0]);
        if (ret == -1) {
          fprintf(stderr, "Could not write original binary\n");
          exit(EXIT_FAILURE);
        }
      }
    }

    // read tracee's memory.
    long *read_dest = (long *)mo.content; // allocated in create_map_object

    size_t count = remain / sizeof(long);
    for (size_t i = 0; i < count; i++) {
      // PTRACE_PEEKDATA return long value.
      // TODO: ALSR
      read_dest[i] =
          ptrace(PTRACE_PEEKDATA, child_pid, mo.start + i * sizeof(long), NULL);
    }

    // copy to heap and add map to `maps`
    map_object *tmp = maps[map_counter] =
        (map_object *)malloc(sizeof(map_object));
    memcpy(tmp, &mo, sizeof(map_object));
    map_counter += 1;
  } while ((line = strtok_r(NULL, "\n", &token)));

  // make runtime loader.
  FILE *source_code = fopen("./result.c", "w"); // TODO: separate to template file
  FILE *template = fopen("./template.c", "r");

  char* template_buf = malloc(0x100);
  size_t read_num;

  do {
    read_num = fread(template_buf, 0x1, 0x100, template);
    fwrite(template_buf, 1, read_num, source_code);
  } while(read_num == 0x100);

  fprintf(source_code, "\n");
  fprintf(source_code, "void map_objects() {\n");
  fprintf(source_code, "  char *dest;\n");

  for (map_object **p = &maps[0]; *p != NULL; p++) {
    if ((*p)->size == 0) { // is it ok?
      continue;
    }

    int prot = PROT_NONE;
    if ((*p)->readable) {
      prot |= PROT_READ;
    }
    if ((*p)->writable) {
      prot |= PROT_WRITE;
    }
    if ((*p)->executable) {
      prot |= PROT_EXEC;
    }

    int flag = MAP_ANONYMOUS;
    if ((*p)->private) {
      flag |= MAP_PRIVATE;
    }

    // for writing data, prot must have PROT_WRITE.
    fprintf(source_code, "  dest = mmap((void*)0x%lx, 0x%lx, %d, %d, -1, 0);\n",
            (*p)->start, (*p)->size, prot | PROT_WRITE, flag);
    // TODO: embed it to elf sections.
    // TODO: debug suppoort

    // copy data.
    fprintf(source_code, "  memcpy(dest, \"");
    for (size_t i = 0; i < (*p)->size; i++) {
      fprintf(source_code, "\\x%hhx",
              (*p)->content[i]); // TODO: replace it with some smart way.
    }
    fprintf(source_code, "\", %ld);\n", (*p)->size);

    // back to original permission.
    fprintf(source_code, "  mprotect((void*)0x%lx, 0x%lx, %d);\n", (*p)->start,
            (*p)->size, prot);
  }

  fprintf(source_code, "}\n\t");
  fprintf(source_code, "asm(\n\t");
  fprintf(source_code, "\".global _start\\n\\t\"\n\t");
  fprintf(source_code, "\"_start:\\n\\t\"\n\t");
  fprintf(source_code, "\"  call map_objects\\n\\t\"\n\t");

  // write register store code. and jump to user:_start.
  // TODO: restore args, argv
  fprintf(source_code, // TODO: use setjmp
          // "  asm(\\\"movq $0x%llx, %%rsp\\\");" // at first, restore rsp.
          "\"  movq $0x%llx, %%rbp\\n\\t\"\n\t"

          "\"  movq $0x%lx, %%rax\\n\\t\"\n\t" // write _start address.
          "\"  push %%rax\\n\\t\"\n\t"         // and store is to stack.

          "\"  movq $0x%llx, %%rdi\\n\\t\"\n\t" // restore registers.
          "\"  movq $0x%llx, %%rsi\\n\\t\"\n\t"
          "\"  movq $0x%llx, %%rax\\n\\t\"\n\t"
          "\"  movq $0x%llx, %%rbx\\n\\t\"\n\t"
          "\"  movq $0x%llx, %%rcx\\n\\t\"\n\t"
          "\"  movq $0x%llx, %%rdx\\n\\t\"\n\t"
          "\"  movq $0x%llx, %%r8\\n\\t\"\n\t"
          "\"  movq $0x%llx, %%r9\\n\\t\"\n\t"
          "\"  movq $0x%llx, %%r10\\n\\t\"\n\t"
          "\"  movq $0x%llx, %%r11\\n\\t\"\n\t"
          "\"  movq $0x%llx, %%r12\\n\\t\"\n\t"
          "\"  movq $0x%llx, %%r13\\n\\t\"\n\t"
          "\"  movq $0x%llx, %%r14\\n\\t\"\n\t"
          "\"  movq $0x%llx, %%r15\\n\\t\"\n\t" // done.

          "\"  ret\\n\\t\"\n\t", // jump to $rax(user:_start)
          // regs.rsp
          regs.rbp,

          user_base_addr + entry,

          regs.rdi, regs.rsi, regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.r8,
          regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15);

  // fprintf(source_code, "  exit(EXIT_SUCCESS);\n"); // unreachable?
  // fprintf(source_code, "}\n");
  fprintf(source_code, ");\n\t");

  fclose(source_code);

  /// cleanup maps.
  for (map_object **p = &maps[0]; *p != NULL; p++) {
    free_map_object(*p);
    free(*p);
  }
}
