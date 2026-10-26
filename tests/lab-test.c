#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "harness/unity.h"
#include "../src/lab.h"

int main_exclude(int argc, char *argv[]);

void setUp(void) {
}

void tearDown(void) {
}

static bool read_captured(FILE *stream, char *buffer, size_t capacity)
{
  if (capacity == 0 || fflush(stream) != 0 || fseek(stream, 0, SEEK_SET) != 0) {
    return false;
  }

  size_t length = fread(buffer, 1, capacity - 1U, stream);
  if (ferror(stream) != 0 || length == capacity - 1U) {
    return false;
  }
  buffer[length] = '\0';
  return true;
}

static int invoke_cli(int argc, char *argv[], char *stdout_text,
                      size_t stdout_capacity, char *stderr_text,
                      size_t stderr_capacity)
{
  FILE *captured_stdout = tmpfile();
  FILE *captured_stderr = tmpfile();
  if (captured_stdout == NULL || captured_stderr == NULL) {
    if (captured_stdout != NULL) {
      (void)fclose(captured_stdout);
    }
    if (captured_stderr != NULL) {
      (void)fclose(captured_stderr);
    }
    return -1;
  }

  (void)fflush(NULL);
  int saved_stdout = dup(STDOUT_FILENO);
  int saved_stderr = dup(STDERR_FILENO);
  if (saved_stdout < 0 || saved_stderr < 0 ||
      dup2(fileno(captured_stdout), STDOUT_FILENO) < 0 ||
      dup2(fileno(captured_stderr), STDERR_FILENO) < 0) {
    if (saved_stdout >= 0) {
      (void)dup2(saved_stdout, STDOUT_FILENO);
      (void)close(saved_stdout);
    }
    if (saved_stderr >= 0) {
      (void)dup2(saved_stderr, STDERR_FILENO);
      (void)close(saved_stderr);
    }
    (void)fclose(captured_stdout);
    (void)fclose(captured_stderr);
    return -1;
  }

  int status = main_exclude(argc, argv);
  (void)fflush(NULL);
  bool stdout_restored = dup2(saved_stdout, STDOUT_FILENO) >= 0;
  bool stderr_restored = dup2(saved_stderr, STDERR_FILENO) >= 0;
  (void)close(saved_stdout);
  (void)close(saved_stderr);

  bool captured = read_captured(captured_stdout, stdout_text, stdout_capacity) &&
                  read_captured(captured_stderr, stderr_text, stderr_capacity);
  (void)fclose(captured_stdout);
  (void)fclose(captured_stderr);
  return stdout_restored && stderr_restored && captured ? status : -1;
}

static bool write_route_file(char path[64], const char *contents)
{
  (void)strcpy(path, "/tmp/cs425-p3-routes-XXXXXX");
  int fd = mkstemp(path);
  if (fd < 0) {
    return false;
  }

  size_t length = strlen(contents);
  ssize_t written = write(fd, contents, length);
  bool ok = written >= 0 && (size_t)written == length;
  if (close(fd) != 0) {
    ok = false;
  }
  if (!ok) {
    (void)unlink(path);
  }
  return ok;
}

void test_cli_usage_and_invalid_command_exit_codes(void)
{
  char out[512];
  char err[512];
  char *no_args[] = {"myapp", NULL};
  TEST_ASSERT_EQUAL_INT(0, invoke_cli(1, no_args, out, sizeof(out), err,
                                      sizeof(err)));
  TEST_ASSERT_EQUAL_STRING("Usage: myapp info <address>/<prefix>\n"
                           "       myapp split <network>/<prefix> <count>\n"
                           "       myapp lookup <table-file> <address>...\n",
                           out);
  TEST_ASSERT_EQUAL_STRING("", err);

  char *unknown[] = {"myapp", "unknown", NULL};
  TEST_ASSERT_EQUAL_INT(1, invoke_cli(2, unknown, out, sizeof(out), err,
                                      sizeof(err)));
  TEST_ASSERT_EQUAL_STRING("", out);
  TEST_ASSERT_EQUAL_STRING("myapp: invalid command line\n"
                           "Usage: myapp info <address>/<prefix>\n"
                           "       myapp split <network>/<prefix> <count>\n"
                           "       myapp lookup <table-file> <address>...\n",
                           err);

  char *short_split[] = {"myapp", "split", "192.0.2.0/24", NULL};
  TEST_ASSERT_EQUAL_INT(1, invoke_cli(3, short_split, out, sizeof(out), err,
                                      sizeof(err)));
  TEST_ASSERT_EQUAL_STRING("myapp: invalid command line\n"
                           "Usage: myapp info <address>/<prefix>\n"
                           "       myapp split <network>/<prefix> <count>\n"
                           "       myapp lookup <table-file> <address>...\n",
                           err);

  char *short_lookup[] = {"myapp", "lookup", "routes.txt", NULL};
  TEST_ASSERT_EQUAL_INT(1, invoke_cli(3, short_lookup, out, sizeof(out), err,
                                      sizeof(err)));
  TEST_ASSERT_EQUAL_STRING("myapp: invalid command line\n"
                           "Usage: myapp info <address>/<prefix>\n"
                           "       myapp split <network>/<prefix> <count>\n"
                           "       myapp lookup <table-file> <address>...\n",
                           err);

  char *wrong_arity[] = {"myapp", "info", "192.0.2.1/24", "extra", NULL};
  TEST_ASSERT_EQUAL_INT(1, invoke_cli(4, wrong_arity, out, sizeof(out), err,
                                      sizeof(err)));
  TEST_ASSERT_EQUAL_STRING("myapp: invalid command line\n"
                           "Usage: myapp info <address>/<prefix>\n"
                           "       myapp split <network>/<prefix> <count>\n"
                           "       myapp lookup <table-file> <address>...\n",
                           err);
}

void test_cli_info_output_and_error_exit_code(void)
{
  char out[512];
  char err[512];
  char *valid[] = {"myapp", "info", "192.0.2.5/32", NULL};
  TEST_ASSERT_EQUAL_INT(0, invoke_cli(3, valid, out, sizeof(out), err,
                                      sizeof(err)));
  TEST_ASSERT_EQUAL_STRING("address    192.0.2.5\n"
                           "prefix     /32\n"
                           "netmask    255.255.255.255\n"
                           "network    192.0.2.5\n"
                           "broadcast  192.0.2.5\n"
                           "first host 192.0.2.5\n"
                           "last host  192.0.2.5\n"
                           "hosts      1\n",
                           out);
  TEST_ASSERT_EQUAL_STRING("", err);

  char *zero_prefix[] = {"myapp", "info", "10.1.2.3/0", NULL};
  TEST_ASSERT_EQUAL_INT(0, invoke_cli(3, zero_prefix, out, sizeof(out), err,
                                      sizeof(err)));
  TEST_ASSERT_EQUAL_STRING("address    10.1.2.3\n"
                           "prefix     /0\n"
                           "netmask    0.0.0.0\n"
                           "network    0.0.0.0\n"
                           "broadcast  255.255.255.255\n"
                           "first host 0.0.0.1\n"
                           "last host  255.255.255.254\n"
                           "hosts      4294967294\n",
                           out);

  char *invalid[] = {"myapp", "info", "192.0.2.5/33", NULL};
  TEST_ASSERT_EQUAL_INT(1, invoke_cli(3, invalid, out, sizeof(out), err,
                                      sizeof(err)));
  TEST_ASSERT_EQUAL_STRING("", out);
  TEST_ASSERT_EQUAL_STRING("myapp: invalid address/prefix: 192.0.2.5/33\n",
                           err);
}

void test_cli_split_output_and_error_exit_codes(void)
{
  char out[512];
  char err[512];
  char *valid[] = {"myapp", "split", "192.0.2.0/24", "4", NULL};
  TEST_ASSERT_EQUAL_INT(0, invoke_cli(4, valid, out, sizeof(out), err,
                                      sizeof(err)));
  TEST_ASSERT_EQUAL_STRING("192.0.2.0/26\n"
                           "192.0.2.64/26\n"
                           "192.0.2.128/26\n"
                           "192.0.2.192/26\n",
                           out);
  TEST_ASSERT_EQUAL_STRING("", err);

  char *invalid_count[] = {"myapp", "split", "192.0.2.0/24", "3", NULL};
  TEST_ASSERT_EQUAL_INT(1, invoke_cli(4, invalid_count, out, sizeof(out), err,
                                      sizeof(err)));
  TEST_ASSERT_EQUAL_STRING("", out);
  TEST_ASSERT_EQUAL_STRING(
      "myapp: subnet count must be a power of two: 3\n", err);

  char *not_network[] = {"myapp", "split", "192.0.2.1/24", "2", NULL};
  TEST_ASSERT_EQUAL_INT(1, invoke_cli(4, not_network, out, sizeof(out), err,
                                      sizeof(err)));
  TEST_ASSERT_EQUAL_STRING(
      "myapp: split requires a network address with no host bits set: 192.0.2.1/24\n",
      err);

  char *too_many[] = {"myapp", "split", "192.0.2.5/32", "2", NULL};
  TEST_ASSERT_EQUAL_INT(1, invoke_cli(4, too_many, out, sizeof(out), err,
                                      sizeof(err)));
  TEST_ASSERT_EQUAL_STRING(
      "myapp: splitting this block would require a prefix longer than /32\n",
      err);
}

void test_cli_lookup_output_and_exit_codes(void)
{
  char path[64];
  TEST_ASSERT_TRUE(write_route_file(
      path, "default 192.0.2.1 eth0\n"
            "10.0.0.0/8 10.1.0.1 eth1\n"
            "10.1.0.0/16 direct eth2\n"));

  char out[512];
  char err[512];
  char *valid[] = {"myapp", "lookup", path, "10.1.2.3", "10.2.3.4",
                   "8.8.8.8", NULL};
  TEST_ASSERT_EQUAL_INT(0, invoke_cli(6, valid, out, sizeof(out), err,
                                      sizeof(err)));
  TEST_ASSERT_EQUAL_STRING("10.1.2.3 dev eth2\n"
                           "10.2.3.4 via 10.1.0.1 dev eth1\n"
                           "8.8.8.8 via 192.0.2.1 dev eth0\n",
                           out);
  TEST_ASSERT_EQUAL_STRING("", err);
  (void)unlink(path);

  TEST_ASSERT_TRUE(write_route_file(path, "10.0.0.0/8 direct eth0\n"));
  char *unreachable[] = {"myapp", "lookup", path, "8.8.8.8", NULL};
  TEST_ASSERT_EQUAL_INT(3, invoke_cli(4, unreachable, out, sizeof(out), err,
                                      sizeof(err)));
  TEST_ASSERT_EQUAL_STRING("8.8.8.8 unreachable\n", out);
  TEST_ASSERT_EQUAL_STRING("", err);

  char *invalid_address[] = {"myapp", "lookup", path, "8.8.8.x", NULL};
  TEST_ASSERT_EQUAL_INT(1, invoke_cli(4, invalid_address, out, sizeof(out),
                                      err, sizeof(err)));
  TEST_ASSERT_EQUAL_STRING("", out);
  TEST_ASSERT_EQUAL_STRING("myapp: invalid IPv4 address: 8.8.8.x\n", err);
  (void)unlink(path);

  TEST_ASSERT_TRUE(write_route_file(path, "broken route line\n"));
  char *bad_table[] = {"myapp", "lookup", path, "8.8.8.8", NULL};
  TEST_ASSERT_EQUAL_INT(2, invoke_cli(4, bad_table, out, sizeof(out), err,
                                      sizeof(err)));
  TEST_ASSERT_EQUAL_STRING("", out);
  char expected_error[128];
  (void)snprintf(expected_error, sizeof(expected_error),
                 "myapp: %s:1: not a valid route\n", path);
  TEST_ASSERT_EQUAL_STRING(expected_error, err);
  (void)unlink(path);
}

void test_ip_parse_valid_addresses(void) {
  uint32_t addr = 0;
  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &addr));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A8010A), addr);
  TEST_ASSERT_TRUE(ip_parse("0.0.0.0", &addr));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0), addr);
  TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &addr));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, addr);
}

void test_ip_parse_rejects_malformed_addresses(void) {
  const char *invalid[] = {
      "1.2.3", "1.2.3.4.5", "1..2.3", "256.1.1.1", "010.0.0.1",
      "1.2.3.4x", "+1.2.3.4", "1.2.3.-4", "1.2.3.4 ", "1.a.3.4", ""
  };
  uint32_t addr = UINT32_C(0x12345678);

  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    TEST_ASSERT_FALSE(ip_parse(invalid[i], &addr));
    TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x12345678), addr);
  }
  TEST_ASSERT_FALSE(ip_parse(NULL, &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4", NULL));
}

void test_ip_format(void) {
  char out[IP_STR_LEN];
  ip_format(UINT32_C(0xC0A8010A), out);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10", out);
  ip_format(UINT32_MAX, out);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", out);
}

void test_cidr_parse_valid_blocks(void) {
  cidr_t block = {0};
  TEST_ASSERT_TRUE(cidr_parse("132.178.227.11/25", &block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E30B), block.addr);
  TEST_ASSERT_EQUAL_UINT8(25, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &block));
  TEST_ASSERT_EQUAL_UINT8(0, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("192.0.2.2/31", &block));
  TEST_ASSERT_EQUAL_UINT8(31, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("255.255.255.255/32", &block));
  TEST_ASSERT_EQUAL_UINT8(32, block.prefix);
}

void test_cidr_parse_rejects_malformed_blocks(void) {
  const char *invalid[] = {
      "1.2.3", "1.2.3.4.5", "1..2.3", "256.1.1.1", "010.0.0.1",
      "1.2.3.4x", "1.2.3.4/33", "1.2.3.4/024", "1.2.3.4/",
      "1.2.3/24", "1.2.3.4/24x", "1.2.3.4/2/4", "1.2.3.4/+24",
      "/24", "1234567890123456/24", "1.2.3.4/a"
  };
  cidr_t block = {.addr = UINT32_C(0x12345678), .prefix = 17};

  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    TEST_ASSERT_FALSE(cidr_parse(invalid[i], &block));
    TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x12345678), block.addr);
    TEST_ASSERT_EQUAL_UINT8(17, block.prefix);
  }
  TEST_ASSERT_FALSE(cidr_parse(NULL, &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/24", NULL));
}

void test_cidr_format(void) {
  char out[CIDR_STR_LEN];
  cidr_t block = {.addr = UINT32_C(0xC0A8010A), .prefix = 24};
  cidr_format(block, out);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10/24", out);
  block.prefix = 255;
  cidr_format(block, out);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10/32", out);
}

void test_cidr_mask(void) {
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0), cidr_mask(0));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x80000000), cidr_mask(1));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFF00), cidr_mask(24));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFFFE), cidr_mask(31));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_mask(32));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_mask(255));
}

void test_cidr_network_broadcast_and_host_ranges(void) {
  cidr_t block = {.addr = UINT32_C(0x84B2E30B), .prefix = 25};
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E300), cidr_network(block));
  TEST_ASSERT_FALSE(cidr_is_network(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E37F), cidr_broadcast(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E301), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E37E), cidr_last_host(block));

  block = (cidr_t){.addr = UINT32_C(0xC0000202), .prefix = 31};
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0000202), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0000203), cidr_last_host(block));
  block = (cidr_t){.addr = UINT32_C(0xC0000202), .prefix = 32};
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0000202), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0000202), cidr_last_host(block));

  block = (cidr_t){.addr = 0, .prefix = 0};
  TEST_ASSERT_EQUAL_HEX32(0, cidr_network(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_broadcast(block));
  TEST_ASSERT_EQUAL_HEX32(1, cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX - 1U, cidr_last_host(block));
  TEST_ASSERT_TRUE(cidr_is_network(block));

  block = (cidr_t){.addr = UINT32_MAX, .prefix = 32};
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_network(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_broadcast(block));
}

void test_cidr_slash30_31_and_32_boundaries(void) {
  cidr_t block = {.addr = UINT32_C(0xC0000202), .prefix = 30};
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0000200), cidr_network(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0000203), cidr_broadcast(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0000201), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0000202), cidr_last_host(block));

  block = (cidr_t){.addr = UINT32_C(0xC0000202), .prefix = 31};
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0000202), cidr_network(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0000203), cidr_broadcast(block));
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0xC0000202)));
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0xC0000203)));
  TEST_ASSERT_FALSE(cidr_contains(block, UINT32_C(0xC0000204)));

  block = (cidr_t){.addr = UINT32_C(0xC0000202), .prefix = 32};
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0xC0000202)));
  TEST_ASSERT_FALSE(cidr_contains(block, UINT32_C(0xC0000203)));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(1), cidr_host_count(block));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(2147483646),
                           cidr_host_count((cidr_t){.addr = 0, .prefix = 1}));
}

void test_cidr_host_count(void) {
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(4294967294),
                           cidr_host_count((cidr_t){.addr = 0, .prefix = 0}));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(2),
                           cidr_host_count((cidr_t){.addr = 0, .prefix = 30}));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(2),
                           cidr_host_count((cidr_t){.addr = 0, .prefix = 31}));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(1),
                           cidr_host_count((cidr_t){.addr = 0, .prefix = 32}));
}

void test_cidr_contains_and_network_check(void) {
  cidr_t block = {.addr = UINT32_C(0x84B2E300), .prefix = 25};
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0x84B2E301)));
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0x84B2E37F)));
  TEST_ASSERT_FALSE(cidr_contains(block, UINT32_C(0x84B2E380)));
  TEST_ASSERT_TRUE(cidr_is_network(block));
  TEST_ASSERT_TRUE(cidr_contains((cidr_t){.addr = 0, .prefix = 0},
                                 UINT32_MAX));
}

void test_cidr_subnet(void) {
  cidr_t subnet = {0};
  cidr_t block = {.addr = UINT32_C(0xC0A80100), .prefix = 24};
  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 0, &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A80100), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(26, subnet.prefix);
  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 3, &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A801C0), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(26, subnet.prefix);

  block = (cidr_t){.addr = 0, .prefix = 0};
  TEST_ASSERT_TRUE(cidr_subnet(block, UINT32_C(0x80000000),
                               UINT32_C(0x7FFFFFFF), &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFFFE), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(31, subnet.prefix);
  TEST_ASSERT_TRUE(cidr_subnet(block, 1, 0, &subnet));
  TEST_ASSERT_EQUAL_UINT8(0, subnet.prefix);
}

void test_cidr_subnet_extreme_valid_requests(void) {
  cidr_t subnet = {0};
  cidr_t single_address = {.addr = UINT32_MAX, .prefix = 32};
  TEST_ASSERT_TRUE(cidr_subnet(single_address, 1, 0, &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(32, subnet.prefix);

  cidr_t half_space = {.addr = 0, .prefix = 1};
  TEST_ASSERT_TRUE(cidr_subnet(half_space, UINT32_C(0x80000000),
                               UINT32_C(0x7FFFFFFF), &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x7FFFFFFF), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(32, subnet.prefix);
}

void test_cidr_subnet_rejects_invalid_requests_without_modifying_output(void) {
  cidr_t subnet = {.addr = UINT32_C(0x12345678), .prefix = 12};
  cidr_t unaligned = {.addr = UINT32_C(0xC0A80101), .prefix = 24};
  cidr_t block = {.addr = 0, .prefix = 31};

  TEST_ASSERT_FALSE(cidr_subnet(block, 0, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 3, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 4, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 2, 2, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(unaligned, 1, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet((cidr_t){.addr = 0, .prefix = 33},
                                1, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 1, 0, NULL));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x12345678), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(12, subnet.prefix);
}

void test_route_parse(void) {
  route_t route = {0};
  TEST_ASSERT_TRUE(route_parse(" \tdefault\t132.178.227.1  eno1\n", &route));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0), route.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(0, route.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E301), route.gateway);
  TEST_ASSERT_EQUAL_STRING("eno1", route.dev);

  TEST_ASSERT_TRUE(route_parse("10.1.2.0/24 direct eth2", &route));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0A010200), route.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(24, route.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0), route.gateway);
  TEST_ASSERT_EQUAL_STRING("eth2", route.dev);

  TEST_ASSERT_TRUE(route_parse("default direct 123456789012345", &route));
  TEST_ASSERT_EQUAL_STRING("123456789012345", route.dev);
}

void test_route_parse_rejects_invalid_lines_without_modifying_output(void) {
  const char *invalid[] = {
      "default direct", "default direct eth0 extra",
      "10.1.2.1/24 direct eth0", "10.0.0.0/8 256.0.0.1 eth0",
      "default direct", "default direct ",
      "default direct 1234567890123456", "default direct eth0\nextra",
      " \t\r\n", "12345678901234567890/24 direct eth0",
      "default 1234567890123456 eth0", "defaulx direct eth0",
      "default direkt eth0", "default direct eth\v0"
  };
  route_t route = {
      .dest = {.addr = UINT32_C(0x12345600), .prefix = 24},
      .gateway = UINT32_C(0x01020304),
      .dev = "keep"
  };

  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    TEST_ASSERT_FALSE(route_parse(invalid[i], &route));
    TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x12345600), route.dest.addr);
    TEST_ASSERT_EQUAL_UINT8(24, route.dest.prefix);
    TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x01020304), route.gateway);
    TEST_ASSERT_EQUAL_STRING("keep", route.dev);
  }
  TEST_ASSERT_FALSE(route_parse(NULL, &route));
  TEST_ASSERT_FALSE(route_parse("default direct eth0", NULL));
}

void test_table_add_and_lookup_longest_prefix(void) {
  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_EQUAL_size_t(0, table_count(table));

  const char *lines[] = {
      "default 132.178.227.1 eno1",
      "10.0.0.0/8 10.1.0.1 eth1",
      "10.1.0.0/16 direct eth1",
      "10.1.2.0/24 direct eth2",
      "10.1.2.128/25 10.1.2.1 eth2"
  };
  route_t route;
  for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
    TEST_ASSERT_TRUE(route_parse(lines[i], &route));
    TEST_ASSERT_TRUE(table_add(table, &route));
  }
  TEST_ASSERT_EQUAL_size_t(5, table_count(table));
  TEST_ASSERT_FALSE(table_add(table, &route));

  const route_t *match = table_lookup(table, UINT32_C(0x0A0102C8));
  TEST_ASSERT_NOT_NULL(match);
  TEST_ASSERT_EQUAL_UINT8(25, match->dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0A010201), match->gateway);
  match = table_lookup(table, UINT32_C(0x0A010214));
  TEST_ASSERT_NOT_NULL(match);
  TEST_ASSERT_EQUAL_UINT8(24, match->dest.prefix);
  match = table_lookup(table, UINT32_C(0x0A010901));
  TEST_ASSERT_NOT_NULL(match);
  TEST_ASSERT_EQUAL_UINT8(16, match->dest.prefix);
  match = table_lookup(table, UINT32_C(0x0A090001));
  TEST_ASSERT_NOT_NULL(match);
  TEST_ASSERT_EQUAL_UINT8(8, match->dest.prefix);
  match = table_lookup(table, UINT32_C(0xC0A80001));
  TEST_ASSERT_NOT_NULL(match);
  TEST_ASSERT_EQUAL_UINT8(0, match->dest.prefix);
  match = table_lookup(table, 0);
  TEST_ASSERT_NOT_NULL(match);
  TEST_ASSERT_EQUAL_UINT8(0, match->dest.prefix);

  table_destroy(table);
  table_destroy(NULL);
  TEST_ASSERT_EQUAL_size_t(0, table_count(NULL));
  TEST_ASSERT_NULL(table_lookup(NULL, UINT32_MAX));
  table = table_create();
  TEST_ASSERT_NULL(table_lookup(table, UINT32_MAX));
  table_destroy(table);
}

void test_table_lookup_order_and_no_default(void) {
  fwd_table_t *table = table_create();
  const char *lines[] = {
      "10.1.2.128/25 10.1.2.1 eth2",
      "10.1.2.0/24 direct eth2",
      "10.1.0.0/16 direct eth1",
      "10.0.0.0/8 10.1.0.1 eth1",
      "default 132.178.227.1 eno1"
  };
  route_t route;
  for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
    TEST_ASSERT_TRUE(route_parse(lines[i], &route));
    TEST_ASSERT_TRUE(table_add(table, &route));
  }

  const route_t *match = table_lookup(table, UINT32_C(0x0A0102C8));
  TEST_ASSERT_NOT_NULL(match);
  TEST_ASSERT_EQUAL_UINT8(25, match->dest.prefix);
  match = table_lookup(table, UINT32_C(0x0A010214));
  TEST_ASSERT_NOT_NULL(match);
  TEST_ASSERT_EQUAL_UINT8(24, match->dest.prefix);
  match = table_lookup(table, UINT32_C(0x08080808));
  TEST_ASSERT_NOT_NULL(match);
  TEST_ASSERT_EQUAL_UINT8(0, match->dest.prefix);
  table_destroy(table);

  table = table_create();
  TEST_ASSERT_TRUE(route_parse("10.0.0.0/8 direct eth0", &route));
  TEST_ASSERT_TRUE(table_add(table, &route));
  TEST_ASSERT_NULL(table_lookup(table, UINT32_C(0x08080808)));
  table_destroy(table);
}

void test_table_add_grows_past_multiple_capacities(void) {
  fwd_table_t *table = table_create();
  const char *lines[] = {
      "10.0.0.0/8 direct e0", "11.0.0.0/8 direct e1",
      "12.0.0.0/8 direct e2", "13.0.0.0/8 direct e3",
      "14.0.0.0/8 direct e4", "15.0.0.0/8 direct e5",
      "16.0.0.0/8 direct e6", "17.0.0.0/8 direct e7",
      "18.0.0.0/8 direct e8"
  };
  route_t route;
  for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
    TEST_ASSERT_TRUE(route_parse(lines[i], &route));
    TEST_ASSERT_TRUE(table_add(table, &route));
  }
  TEST_ASSERT_EQUAL_size_t(9, table_count(table));
  table_destroy(table);
}

void test_table_add_allows_same_network_address_at_different_prefix(void) {
  fwd_table_t *table = table_create();
  route_t route;
  TEST_ASSERT_TRUE(route_parse("10.1.2.0/24 direct eth0", &route));
  TEST_ASSERT_TRUE(table_add(table, &route));
  TEST_ASSERT_TRUE(route_parse("10.1.2.0/25 direct eth1", &route));
  TEST_ASSERT_TRUE(table_add(table, &route));
  TEST_ASSERT_EQUAL_size_t(2, table_count(table));
  table_destroy(table);
}

void test_table_add_rejects_invalid_destinations(void) {
  fwd_table_t *table = table_create();
  route_t route = {
      .dest = {.addr = UINT32_C(0x0A000001), .prefix = 24},
      .gateway = 0,
      .dev = "eth0"
  };
  TEST_ASSERT_FALSE(table_add(table, &route));
  TEST_ASSERT_EQUAL_size_t(0, table_count(table));
  route.dest = (cidr_t){.addr = UINT32_C(0x0A000000), .prefix = 33};
  TEST_ASSERT_FALSE(table_add(table, &route));
  TEST_ASSERT_FALSE(table_add(NULL, &route));
  TEST_ASSERT_FALSE(table_add(table, NULL));
  table_destroy(table);
}

void test_table_load_comments_and_reports_first_bad_line(void) {
  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  FILE *in = tmpfile();
  TEST_ASSERT_NOT_NULL(in);
  TEST_ASSERT_TRUE(fputs("# sample routes\n\n default 132.178.227.1 eno1\n"
                         "10.0.0.0/8 direct eth1 # inline comment\n",
                         in) >= 0);
  rewind(in);

  size_t bad_line = 99;
  TEST_ASSERT_TRUE(table_load(table, in, &bad_line));
  TEST_ASSERT_EQUAL_size_t(0, bad_line);
  TEST_ASSERT_EQUAL_size_t(2, table_count(table));
  fclose(in);
  table_destroy(table);

  table = table_create();
  in = tmpfile();
  TEST_ASSERT_NOT_NULL(in);
  TEST_ASSERT_TRUE(fputs("default direct eth0\n"
                         "10.0.0.0/8 direct eth1\n"
                         "10.1.0.1/24 direct eth2\n"
                         "192.168.0.0/16 direct eth3\n",
                         in) >= 0);
  rewind(in);
  TEST_ASSERT_FALSE(table_load(table, in, &bad_line));
  TEST_ASSERT_EQUAL_size_t(3, bad_line);
  TEST_ASSERT_EQUAL_size_t(2, table_count(table));
  fclose(in);
  table_destroy(table);

  table = table_create();
  in = tmpfile();
  TEST_ASSERT_NOT_NULL(in);
  TEST_ASSERT_TRUE(fputs("10.0.0.0/8 direct eth0\n"
                         "10.1.0.0/16 direct eth1\n"
                         "10.0.0.0/8 direct eth2\n",
                         in) >= 0);
  rewind(in);
  TEST_ASSERT_FALSE(table_load(table, in, NULL));
  TEST_ASSERT_EQUAL_size_t(2, table_count(table));
  fclose(in);
  table_destroy(table);
}

void test_table_load_invalid_arguments(void) {
  size_t bad_line = 8;
  TEST_ASSERT_FALSE(table_load(NULL, NULL, &bad_line));
  TEST_ASSERT_EQUAL_size_t(0, bad_line);
  fwd_table_t *table = table_create();
  bad_line = 8;
  TEST_ASSERT_FALSE(table_load(table, NULL, &bad_line));
  TEST_ASSERT_EQUAL_size_t(0, bad_line);
  TEST_ASSERT_FALSE(table_load(table, NULL, NULL));
  table_destroy(table);
}

static ssize_t fail_file_read(void *cookie, char *buffer, size_t size)
{
  (void)cookie;
  (void)buffer;
  (void)size;
  errno = EIO;
  return -1;
}

void test_table_load_reports_read_errors(void)
{
  cookie_io_functions_t functions = {.read = fail_file_read};
  FILE *in = fopencookie(NULL, "r", functions);
  TEST_ASSERT_NOT_NULL(in);

  fwd_table_t *table = table_create();
  size_t bad_line = 17;
  TEST_ASSERT_FALSE(table_load(table, in, &bad_line));
  TEST_ASSERT_EQUAL_size_t(0, bad_line);
  TEST_ASSERT_EQUAL_size_t(0, table_count(table));
  (void)fclose(in);
  table_destroy(table);
}

typedef struct {
  const char *data;
  size_t length;
  size_t offset;
} partial_read_cookie_t;

static ssize_t partial_then_fail_read(void *cookie, char *buffer, size_t size)
{
  partial_read_cookie_t *state = cookie;
  if (state->offset < state->length) {
    size_t remaining = state->length - state->offset;
    size_t amount = remaining < size ? remaining : size;
    memcpy(buffer, state->data + state->offset, amount);
    state->offset += amount;
    return (ssize_t)amount;
  }

  errno = EIO;
  return -1;
}

void test_table_load_keeps_routes_before_late_read_error(void)
{
  const char route_line[] = "10.0.0.0/8 direct eth0\n";
  partial_read_cookie_t state = {
      .data = route_line,
      .length = sizeof(route_line) - 1U,
      .offset = 0
  };
  cookie_io_functions_t functions = {.read = partial_then_fail_read};
  FILE *in = fopencookie(&state, "r", functions);
  TEST_ASSERT_NOT_NULL(in);

  fwd_table_t *table = table_create();
  size_t bad_line = 17;
  TEST_ASSERT_FALSE(table_load(table, in, &bad_line));
  TEST_ASSERT_EQUAL_size_t(0, bad_line);
  TEST_ASSERT_EQUAL_size_t(1, table_count(table));
  (void)fclose(in);
  table_destroy(table);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_cli_usage_and_invalid_command_exit_codes);
  RUN_TEST(test_cli_info_output_and_error_exit_code);
  RUN_TEST(test_cli_split_output_and_error_exit_codes);
  RUN_TEST(test_cli_lookup_output_and_exit_codes);
  RUN_TEST(test_ip_parse_valid_addresses);
  RUN_TEST(test_ip_parse_rejects_malformed_addresses);
  RUN_TEST(test_ip_format);
  RUN_TEST(test_cidr_parse_valid_blocks);
  RUN_TEST(test_cidr_parse_rejects_malformed_blocks);
  RUN_TEST(test_cidr_format);
  RUN_TEST(test_cidr_mask);
  RUN_TEST(test_cidr_network_broadcast_and_host_ranges);
  RUN_TEST(test_cidr_slash30_31_and_32_boundaries);
  RUN_TEST(test_cidr_host_count);
  RUN_TEST(test_cidr_contains_and_network_check);
  RUN_TEST(test_cidr_subnet);
  RUN_TEST(test_cidr_subnet_extreme_valid_requests);
  RUN_TEST(test_cidr_subnet_rejects_invalid_requests_without_modifying_output);
  RUN_TEST(test_route_parse);
  RUN_TEST(test_route_parse_rejects_invalid_lines_without_modifying_output);
  RUN_TEST(test_table_add_and_lookup_longest_prefix);
  RUN_TEST(test_table_lookup_order_and_no_default);
  RUN_TEST(test_table_add_grows_past_multiple_capacities);
  RUN_TEST(test_table_add_allows_same_network_address_at_different_prefix);
  RUN_TEST(test_table_add_rejects_invalid_destinations);
  RUN_TEST(test_table_load_comments_and_reports_first_bad_line);
  RUN_TEST(test_table_load_invalid_arguments);
  RUN_TEST(test_table_load_reports_read_errors);
  RUN_TEST(test_table_load_keeps_routes_before_late_read_error);
  return UNITY_END();
}
