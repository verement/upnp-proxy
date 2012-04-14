
# include <unistd.h>

struct context {
  
};

static int initialize(struct context *);
static int process(struct context *);
static int finish(struct context *);

int main(int argc, char *argv[])
{
  struct context context;

  if (daemon(0, 0) == -1)
    return 1;

  if (initialize(&context) == -1)
    return 2;

  if (process(&context) == -1)
    return 3;

  if (finish(&context) == -1)
    return 4;

  return 0;
}

static
int initialize(struct context *context)
{
  return 0;
}

static
int process(struct context *context)
{
  return 0;
}

static
int finish(struct context *context)
{
  return 0;
}
