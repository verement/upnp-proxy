
# include <unistd.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>

# include <libnetfilter_conntrack/libnetfilter_conntrack.h>

# include <errno.h>
# include <stdio.h>
# include <string.h>

# define PORT 7909

struct context {
  int sockfd;
  struct nfct_handle *cth;
};

struct answer {
  int found;
  const struct sockaddr_in *src;
  struct sockaddr_in *dst;
};

static int initialize(struct context *, int);
static int process(struct context *);
static int finish(struct context *);

int main(int argc, char *argv[])
{
  struct context context;

  if (daemon(0, 0) == -1)
    return 1;

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
  int fd;
  struct sockaddr_in sin;
  struct nfct_handle *cth;

  /* create the inbound socket */

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    perror("socket");
    return -1;
  }

  /* bind the inbound socket to a local port */

  sin.sin_family      = AF_INET;
  sin.sin_port        = htons(port);
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
    perror("bind");
    return -1;
  }

  /* get a handle for the netfilter conntrack library */

  cth = nfct_open(CONNTRACK, 0);
  if (cth == 0) {
    perror("nfct_open");
    return -1;
  }

  /* save the socket and handle in the context */

  context->sockfd  = fd;
  context->cth = cth;

  return 0;
}

static
void log_packet(const char *data, int len, const struct sockaddr_in *src)
{
  printf("UDP packet from %s port %d\n",
	 inet_ntoa(src->sin_addr), ntohs(src->sin_port));
}

static
int callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct,
	     void *data)
{
  struct answer *answer = data;

  if (nfct_get_attr_u8(ct, ATTR_L3PROTO) == AF_INET &&
      nfct_get_attr_u8(ct, ATTR_L4PROTO) == IPPROTO_UDP) {
    const struct sockaddr_in *src = answer->src;

    if (nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST) == src->sin_addr.s_addr &&
	nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST) == src->sin_port &&
	nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC) == htonl(INADDR_LOOPBACK) &&
	nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC) == htons(PORT)) {
      struct sockaddr_in *dst = answer->dst;
# if 0
      char buffer[1024];

      nfct_snprintf(buffer, sizeof(buffer), ct,
		    NFCT_T_UNKNOWN, NFCT_O_DEFAULT, NFCT_OF_SHOW_LAYER3);
      printf(">> %s\n", buffer);
# endif

      dst->sin_family      = AF_INET;
      dst->sin_port        = nfct_get_attr_u16(ct, ATTR_PORT_DST);
      dst->sin_addr.s_addr = nfct_get_attr_u32(ct, ATTR_IPV4_DST);

      answer->found = 1;

# if 0
      /* this causes libnetfilter_conntrack to fail? */
      return NFCT_CB_STOP;
# endif
    }
  }

  return NFCT_CB_CONTINUE;
}

static
int find_orig_dst(const struct context *context,
		  const struct sockaddr_in *src, struct sockaddr_in *dst)
{
  int result = 0;
  u_int32_t family = AF_INET;
  struct answer answer;

  answer.found = 0;
  answer.src   = src;
  answer.dst   = dst;

  nfct_callback_register(context->cth, NFCT_T_ALL, callback, &answer);
  if (nfct_query(context->cth, NFCT_Q_DUMP, &family) == -1) {
    perror("nfct_query");
    result = -1;
  }
  nfct_callback_unregister(context->cth);

  if (!answer.found)
    result = -1;

  return result;
}

# define LOCATION  "LOCATION: http://"

static
int rewrite_send(const struct context *context, char buffer[], size_t size,
		 const struct sockaddr_in *dst)
{
  char *location;
  int fd;
  ssize_t sent;

  /* create the outbound socket */

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    perror("socket");
    return -1;
  }

  if (connect(fd, (const struct sockaddr *) dst, sizeof(*dst)) == -1) {
    perror("connect");
    close(fd);
    return -1;
  }

  /* find the LOCATION header */

  location = strstr(buffer, LOCATION);
  if (location == 0)
    fprintf(stderr, "unable to find LOCATION header\n");
  else {
    char *location_ip, *location_ip_end;

    location_ip = location + sizeof(LOCATION) - 1;
    location_ip_end = strchr(location_ip, ':');

    if (location_ip_end == 0)
      fprintf(stderr, "unable to find LOCATION address end\n");
    else {
      struct sockaddr_in src;
      socklen_t addrlen;
      char *src_ip;
      size_t iplen;

      /* determine the address substitute */

      addrlen = sizeof(src);
      if (getsockname(fd, (struct sockaddr *) &src, &addrlen) == -1) {
	perror("getsockname");
	close(fd);
	return -1;
      }

      src_ip = inet_ntoa(src.sin_addr);
      iplen = strlen(src_ip);

      printf("sending reply from %s port %d\n", src_ip, ntohs(src.sin_port));

      memmove(location_ip + iplen, location_ip_end,
	      size - (location_ip_end - buffer));
      size = size - (location_ip_end - location_ip) + iplen;

      memcpy(location_ip, src_ip, iplen);

# if 0
      buffer[size] = 0;
      printf(">>%s<<\n", buffer);
# endif
    }
  }

  /* send the reply */

  do
    sent = send(fd, buffer, size, 0);
  while (sent == -1 && errno == EINTR);
  if (sent == -1) {
    perror("send");
    close(fd);
    return -1;
  }

  if (sent != size)
    fprintf(stderr, "sent size doesn't match\n");

  if (close(fd) == -1)
    perror("close");

  return 0;
}

static
int process(struct context *context)
{
  printf("receiving packets...\n");

  while (1) {
    ssize_t size;
    char buffer[1509];
    struct sockaddr_in src, dst;
    socklen_t addrlen;

    do {
      addrlen = sizeof(src);
      size = recvfrom(context->sockfd, buffer, sizeof(buffer) - 9, 0,
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

    buffer[size] = 0;

    log_packet(buffer, size, &src);

    if (find_orig_dst(context, &src, &dst) == -1) {
      fprintf(stderr, "unable to determine original destination\n");
      continue;
    }

    printf("...original destination %s port %d\n",
	   inet_ntoa(dst.sin_addr), ntohs(dst.sin_port));

    if (rewrite_send(context, buffer, size, &dst) == -1)
      fprintf(stderr, "reply failed\n");
  }

  return 0;
}

static
int finish(struct context *context)
{
  int result = 0;

  /* close the inbound socket */

  if (close(context->sockfd) == -1) {
    perror("close");
    result = -1;
  }

  /* close the netfilter conntrack library */

  if (nfct_close(context->cth) == -1) {
    perror("nfct_close");
    result = -1;
  }

  return result;
}
