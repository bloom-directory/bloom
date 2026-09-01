#include <errno.h>
#include <limits.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

int main(int argc, char **argv) {
  char *end = NULL;
  long parsed = 0;
  mach_port_t task = MACH_PORT_NULL;
  kern_return_t result = KERN_FAILURE;

  if (argc != 2) {
    fprintf(stderr, "usage: task-access-probe PID\n");
    return 64;
  }
  errno = 0;
  parsed = strtol(argv[1], &end, 10);
  if (errno != 0 || end == argv[1] || *end != '\0' || parsed <= 0 ||
      parsed > INT_MAX) {
    fprintf(stderr, "task-access-probe: invalid PID\n");
    return 64;
  }

  result = task_for_pid(mach_task_self(), (pid_t)parsed, &task);
  if (result != KERN_SUCCESS) {
    return 1;
  }
  if (task != MACH_PORT_NULL) {
    mach_port_deallocate(mach_task_self(), task);
  }
  fprintf(stderr, "task-access-probe: unexpectedly obtained task access\n");
  return 0;
}
