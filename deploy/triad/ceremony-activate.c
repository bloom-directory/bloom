/*
 * bloom-ceremony-activate -- minimal systemd-style socket activation shim.
 *
 * DEVELOPMENT / SANDBOX ONLY. Not part of any release bundle.
 *
 * Why this exists
 * ---------------
 * bloom-broker acquires its ceremony origin listener through
 * `bloom_service_activation::take_tcp_listener("broker-ceremony")`, and that
 * adapter has, by design, no path-binding fallback:
 *
 *     "There is deliberately no path-binding fallback. A process outside its
 *      launch manager fails closed instead of creating a weaker endpoint."
 *
 * On Linux the adapter reads the systemd socket-activation protocol --
 * LISTEN_PID / LISTEN_FDS / LISTEN_FDNAMES with the listeners starting at fd 3.
 * scripts/triad-dev-launch.sh satisfies that with a real
 * `bloom-triad-dev-*-broker-ceremony.socket` systemd user unit. A container has
 * no systemd, so this shim performs exactly the same handoff and nothing else:
 * bind one TCP listener, place it on fd 3, publish the three variables, exec
 * the real Broker.
 *
 * It is deliberately not a supervisor: `exec` replaces this process, so the
 * Broker keeps PID 1 semantics, receives signals directly, and LISTEN_PID
 * stays correct across the handoff.
 *
 * Usage:
 *     bloom-ceremony-activate <ip:port> <fd-name> <program> [args...]
 *
 * It handles no secrets and reads no configuration.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LISTEN_FD 3

static void fail(const char *message)
{
	fprintf(stderr, "bloom-ceremony-activate: %s: %s\n", message,
		strerror(errno));
	exit(1);
}

static void reject(const char *message)
{
	fprintf(stderr, "bloom-ceremony-activate: %s\n", message);
	exit(1);
}

/* Parses a strict "dotted.quad:port" listen address. Host names are rejected
 * on purpose: this endpoint must stay pinned to a literal loopback address,
 * and a resolver would make that depend on container DNS. */
static void parse_listen_address(const char *value, struct sockaddr_in *out)
{
	char host[64];
	const char *colon = strrchr(value, ':');
	size_t host_length;
	char *end = NULL;
	long port;

	if (colon == NULL) {
		reject("listen address must be <ip>:<port>");
	}
	host_length = (size_t)(colon - value);
	if (host_length == 0 || host_length >= sizeof(host)) {
		reject("listen address host is empty or too long");
	}
	memcpy(host, value, host_length);
	host[host_length] = '\0';

	errno = 0;
	port = strtol(colon + 1, &end, 10);
	if (errno != 0 || end == colon + 1 || *end != '\0' || port <= 0 ||
	    port > 65535) {
		reject("listen address port is not in 1..65535");
	}

	memset(out, 0, sizeof(*out));
	out->sin_family = AF_INET;
	out->sin_port = htons((unsigned short)port);
	if (inet_pton(AF_INET, host, &out->sin_addr) != 1) {
		reject("listen address host is not a literal IPv4 address");
	}
}

int main(int argc, char **argv)
{
	struct sockaddr_in address;
	char pid_value[32];
	int fd;

	if (argc < 4) {
		reject("usage: bloom-ceremony-activate <ip:port> <fd-name> "
		       "<program> [args...]");
	}
	if (argv[2][0] == '\0' || strchr(argv[2], ':') != NULL) {
		reject("fd name must be non-empty and contain no ':'");
	}

	parse_listen_address(argv[1], &address);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		fail("socket");
	}
	/* The Broker owns this origin exclusively; SO_REUSEADDR only avoids the
	 * TIME_WAIT rebind stall after a restart, and SO_REUSEPORT is
	 * deliberately NOT set so a second Broker in the same network namespace
	 * still loses the AC-31 origin race loudly. */
	{
		int one = 1;

		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one,
			       sizeof(one)) < 0) {
			fail("setsockopt(SO_REUSEADDR)");
		}
	}
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		fail("bind");
	}
	if (listen(fd, SOMAXCONN) < 0) {
		fail("listen");
	}

	if (fd != LISTEN_FD) {
		if (dup2(fd, LISTEN_FD) < 0) {
			fail("dup2");
		}
		if (close(fd) < 0) {
			fail("close");
		}
	}
	/* systemd hands activated descriptors over without FD_CLOEXEC; the
	 * adapter in the Broker expects to inherit fd 3 across the exec. */
	if (fcntl(LISTEN_FD, F_SETFD, 0) < 0) {
		fail("fcntl(F_SETFD)");
	}

	if (snprintf(pid_value, sizeof(pid_value), "%ld", (long)getpid()) < 0) {
		reject("could not format LISTEN_PID");
	}
	if (setenv("LISTEN_PID", pid_value, 1) != 0 ||
	    setenv("LISTEN_FDS", "1", 1) != 0 ||
	    setenv("LISTEN_FDNAMES", argv[2], 1) != 0) {
		fail("setenv");
	}

	execv(argv[3], &argv[3]);
	fail("execv");
	return 1;
}
