#include "lab.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

static void print_usage(FILE *out)
{
  (void)fprintf(out, "Usage: myapp info <address>/<prefix>\n"
                     "       myapp split <network>/<prefix> <count>\n"
                     "       myapp lookup <table-file> <address>...\n");
}

static int invalid_command_line(void)
{
  (void)fprintf(stderr, "myapp: invalid command line\n");
  print_usage(stderr);
  return 1;
}

static bool parse_count(const char *text, uint32_t *count)
{
  if (text == NULL || *text == '\0' || count == NULL) {
    return false;
  }

  uint32_t parsed = 0;
  for (const char *cursor = text; *cursor != '\0'; cursor++) {
    if (*cursor < '0' || *cursor > '9') {
      return false;
    }
    uint32_t digit = (uint32_t)(*cursor - '0');
    if (parsed > (UINT32_MAX - digit) / 10U) {
      return false;
    }
    parsed = parsed * 10U + digit;
  }

  *count = parsed;
  return true;
}

static int command_info(const char *text)
{
  cidr_t block;
  if (!cidr_parse(text, &block)) {
    (void)fprintf(stderr, "myapp: invalid address/prefix: %s\n", text);
    return 1;
  }

  char address[IP_STR_LEN];
  char netmask[IP_STR_LEN];
  char network[IP_STR_LEN];
  char broadcast[IP_STR_LEN];
  char first_host[IP_STR_LEN];
  char last_host[IP_STR_LEN];
  ip_format(block.addr, address);
  ip_format(cidr_mask(block.prefix), netmask);
  ip_format(cidr_network(block), network);
  ip_format(cidr_broadcast(block), broadcast);
  ip_format(cidr_first_host(block), first_host);
  ip_format(cidr_last_host(block), last_host);

  (void)printf("address    %s\n", address);
  (void)printf("prefix     /%u\n", (unsigned int)block.prefix);
  (void)printf("netmask    %s\n", netmask);
  (void)printf("network    %s\n", network);
  (void)printf("broadcast  %s\n", broadcast);
  (void)printf("first host %s\n", first_host);
  (void)printf("last host  %s\n", last_host);
  (void)printf("hosts      %" PRIu64 "\n", cidr_host_count(block));
  return 0;
}

static int command_split(const char *block_text, const char *count_text)
{
  cidr_t block;
  if (!cidr_parse(block_text, &block)) {
    (void)fprintf(stderr, "myapp: invalid network/prefix: %s\n", block_text);
    return 1;
  }
  if (!cidr_is_network(block)) {
    (void)fprintf(stderr,
                  "myapp: split requires a network address with no host bits set: %s\n",
                  block_text);
    return 1;
  }

  uint32_t count;
  if (!parse_count(count_text, &count) || count == 0U) {
    (void)fprintf(stderr, "myapp: invalid subnet count: %s\n", count_text);
    return 1;
  }
  if ((count & (count - 1U)) != 0U) {
    (void)fprintf(stderr, "myapp: subnet count must be a power of two: %s\n",
                  count_text);
    return 1;
  }

  cidr_t last_subnet;
  if (!cidr_subnet(block, count, count - 1U, &last_subnet)) {
    (void)fprintf(stderr,
                  "myapp: splitting this block would require a prefix longer than /32\n");
    return 1;
  }

  for (uint32_t i = 0; i < count; i++) {
    cidr_t subnet;
    (void)cidr_subnet(block, count, i, &subnet);
    char formatted[CIDR_STR_LEN];
    cidr_format(subnet, formatted);
    (void)printf("%s\n", formatted);
  }
  return 0;
}

static int command_lookup(int argc, char *argv[])
{
  const char *path = argv[2];
  FILE *in = fopen(path, "r");
  if (in == NULL) {
    (void)fprintf(stderr, "myapp: %s: %s\n", path, strerror(errno));
    return 2;
  }

  fwd_table_t *table = table_create();
  if (table == NULL) {
    (void)fclose(in);
    (void)fprintf(stderr, "myapp: could not allocate forwarding table\n");
    return 2;
  }

  size_t bad_line = 0;
  if (!table_load(table, in, &bad_line)) {
    if (bad_line != 0) {
      (void)fprintf(stderr, "myapp: %s:%zu: not a valid route\n", path,
                    bad_line);
    } else {
      (void)fprintf(stderr, "myapp: %s: could not read table\n", path);
    }
    (void)fclose(in);
    table_destroy(table);
    return 2;
  }
  (void)fclose(in);

  bool has_invalid_address = false;
  bool has_unreachable_address = false;
  for (int i = 3; i < argc; i++) {
    uint32_t address;
    if (!ip_parse(argv[i], &address)) {
      (void)fprintf(stderr, "myapp: invalid IPv4 address: %s\n", argv[i]);
      has_invalid_address = true;
      continue;
    }

    char address_text[IP_STR_LEN];
    ip_format(address, address_text);
    const route_t *route = table_lookup(table, address);
    if (route == NULL) {
      (void)printf("%s unreachable\n", address_text);
      has_unreachable_address = true;
    } else if (route->gateway == 0U) {
      (void)printf("%s dev %s\n", address_text, route->dev);
    } else {
      char gateway[IP_STR_LEN];
      ip_format(route->gateway, gateway);
      (void)printf("%s via %s dev %s\n", address_text, gateway, route->dev);
    }
  }

  table_destroy(table);
  if (has_invalid_address) {
    return 1;
  }
  return has_unreachable_address ? 3 : 0;
}

int main(int argc, char *argv[])
{
  if (argc == 1) {
    print_usage(stdout);
    return 0;
  }

  if (strcmp(argv[1], "info") == 0) {
    if (argc != 3) {
      return invalid_command_line();
    }
    return command_info(argv[2]);
  }
  if (strcmp(argv[1], "split") == 0) {
    if (argc != 4) {
      return invalid_command_line();
    }
    return command_split(argv[2], argv[3]);
  }
  if (strcmp(argv[1], "lookup") == 0) {
    if (argc < 4) {
      return invalid_command_line();
    }
    return command_lookup(argc, argv);
  }

  return invalid_command_line();
}