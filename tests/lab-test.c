#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include "harness/unity.h"
#include "../src/lab.h"

void setUp(void) {
}

void tearDown(void) {
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

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_valid_addresses);
  RUN_TEST(test_ip_parse_rejects_malformed_addresses);
  RUN_TEST(test_ip_format);
  RUN_TEST(test_cidr_parse_valid_blocks);
  RUN_TEST(test_cidr_parse_rejects_malformed_blocks);
  RUN_TEST(test_cidr_format);
  RUN_TEST(test_cidr_mask);
  RUN_TEST(test_cidr_network_broadcast_and_host_ranges);
  RUN_TEST(test_cidr_host_count);
  RUN_TEST(test_cidr_contains_and_network_check);
  RUN_TEST(test_cidr_subnet);
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
  return UNITY_END();
}
