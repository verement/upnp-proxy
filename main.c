
# include <unistd.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>

# include <limits.h>
# include <linux/netfilter_ipv4.h>

# include <errno.h>
# include <stdio.h>

# define PORT 7909

struct context {
  int in_sockfd;
  int out_sockfd;
};

static int initialize(struct context *, int);
static int process(struct context *);
static int finish(struct context *);

int main(int argc, char *argv[])
{
  struct context context;

# if 0
  if (daemon(0, 0) == -1)
    return 1;
# endif

  if (initialize(&context, PORT) == -1)
    return 2;

  if (process(&context) == -1)
    return 3;

  if (finish(&context) == -1)
    return 4;

  return 0;
}

static
int initialize(struct context *context, int port)
{
  int in_fd, out_fd;
  struct sockaddr_in sin;

  /* create the sockets */

  in_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (in_fd == -1) {
    perror("socket");
    return -1;
  }

  out_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (out_fd == -1) {
    perror("socket");
    return -1;
  }

  /* bind the inbound socket to a local port */

  sin.sin_family      = AF_INET;
  sin.sin_port        = htons(port);
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (bind(in_fd, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
    perror("bind");
    return -1;
  }

  /* save the sockets in the context */

  context->in_sockfd  = in_fd;
  context->out_sockfd = out_fd;

  return 0;
}

static
void log_packet(const char *data, int len, const struct sockaddr_in *src)
{
  printf("UDP packet from %s port %d\n",
	 inet_ntoa(src->sin_addr), ntohs(src->sin_port));
}

static
int find_orig_dst(int sockfd, const struct sockaddr_in *src,
		  struct sockaddr_in *orig_dst)
{
  struct sockaddr unspec;
  socklen_t addrlen;

  unspec.sa_family = AF_UNSPEC;

  if (connect(sockfd, (struct sockaddr *) src, sizeof(*src)) == -1) {
    perror("connect");
    return -1;
  }

  addrlen = sizeof(*orig_dst);
  if (getsockopt(sockfd, SOL_IP, SO_ORIGINAL_DST, orig_dst, &addrlen) == -1) {
    perror("getsockopt(SO_ORIGINAL_DST)");
    connect(sockfd, &unspec, sizeof(unspec));
    return -1;
  }

  if (connect(sockfd, &unspec, sizeof(unspec)) == -1)
    perror("connect(AF_UNSPEC)");

  return 0;
}

static
int process(struct context *context)
{
  while (1) {
    ssize_t size;
    char buffer[1500];
    struct sockaddr_in src, orig_dst;
    socklen_t addrlen;

    do {
      addrlen = sizeof(src);
      size = recvfrom(context->in_sockfd, buffer, sizeof(buffer), 0,
		      (struct sockaddr *) &src, &addrlen);
    } while (size == -1 && errno == EINTR);
    if (size == -1) {
      perror("recvfrom");
      continue;
    }

    if (size == 0)
      break;

    if (addrlen != sizeof(src))
      return -1;

    log_packet(buffer, size, &src);

    if (find_orig_dst(context->in_sockfd, &src, &orig_dst) == -1) {
      fprintf(stderr, "unable to determine original destination\n");
      continue;
    }

    printf("  original destination %s port %d\n",
	   inet_ntoa(orig_dst.sin_addr), ntohs(orig_dst.sin_port));
  }

  return 0;
}

static
int finish(struct context *context)
{
  /* close the sockets */

  if (close(context->in_sockfd) == -1 ||
      close(context->out_sockfd) == -1) {
    perror("close");
    return -1;
  }

  return 0;
}
