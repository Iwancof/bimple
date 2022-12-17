#include<stdio.h>
#include<math.h>
#include<stdlib.h>
#include<unistd.h>
#include<signal.h>

double global_val = 4.0;

int main() {
  puts("called target's main");
  // kill(getpid(), SIGKILL);
  // kill(getpid(), SIGTRAP);
  // kill(getpid(), SIGINT);

  puts("call function in libc.so.6");

  double ret = sqrt(global_val);
  printf("call function in libm.so.6: %f\n", ret);
}
