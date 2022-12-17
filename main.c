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

  char *new_path = (char *)malloc(strlen(path));
  strcpy(new_path, path);
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

int main(int argc, char *argv[], char *envp[]) {
  bfd_init();

  struct bfd *abfd = bfd_openr("./assets/target", NULL);
  if (!bfd_check_format(abfd, bfd_object)) {
    fprintf(stderr, "Failed to open binary\n");
    exit(EXIT_FAILURE);
  }
  FILE *binary = fopen("./assets/target", "rb");
  if (binary == NULL) {
    perror("Failed to open binary source");
    exit(EXIT_FAILURE);
  }
  fseek(binary, 0, SEEK_END);
  size_t size = ftell(binary);
  char *buffer = (char *)malloc(size);
  rewind(binary);

  fread(buffer, 1, size, binary);
  fclose(binary);
  binary = NULL;

  bfd_vma entry = bfd_get_start_address(abfd);
  printf("entry = 0x%lx\n", entry);

  asection *text_start = bfd_get_section_by_name(abfd, ".text");
  printf("%lx\n", text_start->filepos);

  size_t cut_size =
      (((sizeof(insert_code) - 1) / sizeof(long)) + 1) * sizeof(long);
  printf("cutting %lx\n", cut_size);

  long *moved_buffer = (long *)malloc(cut_size);
  memcpy(moved_buffer, &buffer[entry], cut_size);
  // printf("buf = %hhx %hhx %hhx %hhx \n", moved_buffer[0], moved_buffer[1],
  // moved_buffer[2], moved_buffer[3]);
  printf("buf = %lx\n", moved_buffer[0]);

  memcpy(&buffer[entry], insert_code, sizeof(insert_code));

  bfd_close(abfd);

  char destination_path[] = "./assets/destination_XXXXXX";
  int fd = mkstemp(destination_path);

  write(fd, buffer, size);

  close(fd);

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
    ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
    puts("start!");
    execve(destination_path, new_argv, envp);

    puts("end!");

    exit(EXIT_FAILURE);
  }

  // parent

  int status;
  waitpid(child_pid, &status, 0);

  if (!WIFSTOPPED(status)) {
    fprintf(stderr, "[!] interrupt didn't occure\n");
    exit(EXIT_FAILURE);
  }
  puts("[+] stopped");

  // child process stopped at ld.so.6:_start

  ptrace(PTRACE_CONT, child_pid, NULL, 0);
  waitpid(child_pid, &status, 0);

  // child process stopped at user:_start

  struct user_regs_struct regs;
  struct iovec v = {.iov_base = &regs,
                    .iov_len = sizeof(struct user_regs_struct)};

  ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &v);
  regs.rip -= sizeof(insert_code);
  printf("%p\n", (void *)regs.rip);

  // read all memory data.

  char *vmmap_path = (char *)malloc(0x80);
  snprintf(vmmap_path, 0x80, "/proc/%d/maps", child_pid);

  FILE *vmmap = fopen(vmmap_path, "r");
  if (vmmap == NULL) {
    perror("Could not open vmmap");
    exit(EXIT_FAILURE);
  }
  char *vmmap_buffer = malloc(0x1000);
  if (fread(vmmap_buffer, 1, 0x1000, vmmap) == 0x1000) {
    fprintf(stderr, "extend buffer size");
    exit(EXIT_FAILURE);
  }

  map_object *maps[0x100] = {NULL};
  size_t map_count = 0;

  char *token, *line;
  line = strtok_r(vmmap_buffer, "\n", &token);

  size_t user_text = 0;

  do {
    // start-end perm size dev inode path
    size_t start, end, size, inode;
    char perm[5], *dev, *path;
    dev = malloc(10);
    path = malloc(100);
    strcpy(path, "");

    sscanf(line, "%lx-%lx %4s %lx %9s %ld %99s", &start, &end, perm, &size, dev,
           &inode, path);

    size = end - start; // TODO:

    free(dev);

    map_object mo = create_map_object(start, end, size, perm, path);
    free(path);

    // puts("found map object");
    // print_map_object("  ", &mo);

    // print_map_object("  ", &mo);

    // read data
    size_t remain = mo.size;
    long *read_dest = (long *)mo.content;

    if (remain % sizeof(long) != 0) {
      fprintf(stderr, "invalid size\n");
      exit(EXIT_FAILURE);
    }

    printf("%s\n", mo.path);

    char *bin_base = basename(strdup(mo.path)); // TODO: free it
    char *dest_base = basename(strdup(destination_path));

    if (!(strcmp(bin_base, dest_base))) {
      if (user_text == 0) {
        user_text = start;
        long ret =
            ptrace(PTRACE_POKETEXT, child_pid, start + entry, moved_buffer[0]);
        printf("poke result = %ld\n", ret);
      }
    }

    printf("%s: 0x%lx\n", bin_base, start);

    size_t count = remain / sizeof(long);
    for (size_t i = 0; i < count; i++) {
      read_dest[i] =
          ptrace(PTRACE_PEEKDATA, child_pid, mo.start + i * sizeof(long), NULL);
    }

    map_object *tmp = maps[map_count] =
        (map_object *)malloc(sizeof(map_object));
    memcpy(tmp, &mo, sizeof(map_object));

    map_count += 1;
  } while ((line = strtok_r(NULL, "\n", &token)));

  FILE *source_code = fopen("./result.c", "w");
  fprintf(source_code, "#include<sys/mman.h>\n");
  fprintf(source_code, "#include<stdlib.h>\n");
  fprintf(source_code, "#include<string.h>\n");
  fprintf(source_code, "\n");
  fprintf(source_code, "void _start() {\n");
  fprintf(source_code, "  char *dest;\n");

  for (map_object **p = &maps[0]; *p != NULL; p++) {
    if ((*p)->size == 0) {
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

    fprintf(source_code, "  dest = mmap((void*)0x%lx, 0x%lx, %d, %d, -1, 0);\n",
            (*p)->start, (*p)->size, prot | PROT_WRITE, flag);
    fprintf(source_code, "  memcpy(dest, \"");
    for (size_t i = 0; i < (*p)->size; i++) {
      fprintf(source_code, "\\x%hhx", (*p)->content[i]);
    }
    fprintf(source_code, "\", %ld);\n", (*p)->size);

    fprintf(source_code, "  mprotect((void*)0x%lx, 0x%lx, %d);\n", (*p)->start,
            (*p)->size, prot);
  }

  /*
  fprintf(source_code,
          "asm(\"pushq $0x%x\");",
          (int)((user_text + entry)));
  fprintf(source_code,
          "asm(\"pushq $0x%.8x\");",
          (int)((user_text + entry) >> 32));
          */
  fprintf(source_code,
          "asm(\"movq $0x%llx, %%rsp\");"
          "asm(\"movq $0x%llx, %%rbp\");"

          "asm(\"movq $0x%lx, %%rax\");"
          "asm(\"push %%rax\");"

          "asm(\"movq $0x%llx, %%rdi\");"
          "asm(\"movq $0x%llx, %%rsi\");"
          "asm(\"movq $0x%llx, %%rax\");"
          "asm(\"movq $0x%llx, %%rbx\");"
          "asm(\"movq $0x%llx, %%rcx\");"
          "asm(\"movq $0x%llx, %%rdx\");"
          "asm(\"movq $0x%llx, %%r8\");"
          "asm(\"movq $0x%llx, %%r9\");"
          "asm(\"movq $0x%llx, %%r10\");"
          "asm(\"movq $0x%llx, %%r11\");"
          "asm(\"movq $0x%llx, %%r12\");"
          "asm(\"movq $0x%llx, %%r13\");"
          "asm(\"movq $0x%llx, %%r14\");"
          "asm(\"movq $0x%llx, %%r15\");"

          "asm(\"ret\");",
          regs.rsp, 
          regs.rbp,

          user_text + entry,

          regs.rdi, regs.rsi, regs.rax, regs.rbx, regs.rcx, regs.rdx,
          regs.r8, regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14,
          regs.r15);

  printf("break %p\n", user_text + 0x1159);

  fprintf(source_code, "exit(EXIT_SUCCESS);\n");
  fprintf(source_code, "}\n");

  fclose(source_code);

  for (map_object **p = &maps[0]; *p != NULL; p++) {
    free_map_object(*p);
    free(*p);
  }
}
