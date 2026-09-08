#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static void fail(const char *message) {
  perror(message);
  exit(1);
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: hostile-unix-listener SOCKET CONNECTED_MARKER\n");
    return 64;
  }
  if (strlen(argv[1]) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
    fprintf(stderr, "Unix socket path is too long\n");
    return 64;
  }

  int listener = socket(AF_UNIX, SOCK_STREAM, 0);
  if (listener < 0) fail("socket");
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  strcpy(address.sun_path, argv[1]);
  unlink(argv[1]);
  if (bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0) fail("bind");
  if (chmod(argv[1], 0666) < 0) fail("chmod");
  if (listen(listener, 1) < 0) fail("listen");

  int client = accept(listener, NULL, NULL);
  if (client < 0) fail("accept");
  int marker = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (marker < 0) fail("connected marker");
  if (write(marker, "connected\n", 10) != 10) fail("write marker");
  close(marker);

  /* A hostile endpoint never produces an authenticated triad response. */
  shutdown(client, SHUT_RDWR);
  close(client);
  close(listener);
  unlink(argv[1]);
  return 0;
}
