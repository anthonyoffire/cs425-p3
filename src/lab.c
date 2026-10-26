#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "lab.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

struct fwd_table {
  route_t *routes;
  size_t count;
  size_t capacity;
};

static bool route_next_field(const char **cursor, const char *end,
                             const char **field, size_t *length)
{
  while (*cursor < end && (**cursor == ' ' || **cursor == '\t')) {
    (*cursor)++;
  }
  if (*cursor == end) {
    return false;
  }

  *field = *cursor;
  while (*cursor < end && **cursor != ' ' && **cursor != '\t') {
    (*cursor)++;
  }
  *length = (size_t)(*cursor - *field);
  return true;
}

static bool route_is_blank(const char *line)
{
  while (*line != '\0') {
    if (!isspace((unsigned char)*line)) {
      return false;
    }
    line++;
  }
  return true;
}

bool ip_parse(const char *text, uint32_t *addr)
{
  uint32_t parsed = 0;

  if (text == NULL || addr == NULL) {
    return false;
  }

  for (unsigned int octet_index = 0; octet_index < 4; octet_index++) {
    if (*text < '0' || *text > '9') {
      return false;
    }

    char first_digit = *text;
    unsigned int digit_count = 0;
    unsigned int octet = 0;
    do {
      octet = octet * 10U + (unsigned int)(*text - '0');
      if (octet > 255U) {
        return false;
      }
      digit_count++;
      text++;
    } while (*text >= '0' && *text <= '9');

    if (first_digit == '0' && digit_count > 1U) {
      return false;
    }

    parsed = (parsed << 8) | (uint32_t)octet;

    if (octet_index < 3) {
      if (*text != '.') {
        return false;
      }
      text++;
    } else if (*text != '\0') {
      return false;
    }
  }

  *addr = parsed;
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
  (void)snprintf(out, IP_STR_LEN, "%u.%u.%u.%u",
                 (unsigned int)((addr >> 24) & 0xFFU),
                 (unsigned int)((addr >> 16) & 0xFFU),
                 (unsigned int)((addr >> 8) & 0xFFU),
                 (unsigned int)(addr & 0xFFU));
}

bool cidr_parse(const char *text, cidr_t *block)
{
  if (text == NULL || block == NULL) {
    return false;
  }

  const char *slash = strchr(text, '/');
  if (slash == NULL || slash == text || strchr(slash + 1, '/') != NULL) {
    return false;
  }

  size_t address_length = (size_t)(slash - text);
  if (address_length >= IP_STR_LEN || slash[1] == '\0') {
    return false;
  }

  char address_text[IP_STR_LEN];
  memcpy(address_text, text, address_length);
  address_text[address_length] = '\0';

  uint32_t address;
  if (!ip_parse(address_text, &address)) {
    return false;
  }

  const char *prefix_text = slash + 1;
  if (*prefix_text < '0' || *prefix_text > '9') {
    return false;
  }
  if (*prefix_text == '0' && prefix_text[1] != '\0') {
    return false;
  }

  unsigned int prefix = 0;
  while (*prefix_text >= '0' && *prefix_text <= '9') {
    prefix = prefix * 10U + (unsigned int)(*prefix_text - '0');
    if (prefix > 32U) {
      return false;
    }
    prefix_text++;
  }
  if (*prefix_text != '\0') {
    return false;
  }

  cidr_t parsed = {.addr = address, .prefix = (uint8_t)prefix};
  *block = parsed;
  return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN])
{
  char address[IP_STR_LEN];
  ip_format(block.addr, address);
  unsigned int prefix = block.prefix > 32U ? 32U : (unsigned int)block.prefix;
  (void)snprintf(out, CIDR_STR_LEN, "%s/%u", address, prefix);
}

uint32_t cidr_mask(uint8_t prefix)
{
  if (prefix == 0U) {
    return 0;
  }
  if (prefix > 32U) {
    prefix = 32U;
  }
  return UINT32_MAX << (32U - prefix);
}

uint32_t cidr_network(cidr_t block)
{
  return block.addr & cidr_mask(block.prefix);
}

uint32_t cidr_broadcast(cidr_t block)
{
  return cidr_network(block) | ~cidr_mask(block.prefix);
}

uint32_t cidr_first_host(cidr_t block)
{
  uint32_t network = cidr_network(block);
  return block.prefix >= 31U ? network : network + 1U;
}

uint32_t cidr_last_host(cidr_t block)
{
  uint32_t broadcast = cidr_broadcast(block);
  return block.prefix >= 31U ? broadcast : broadcast - 1U;
}

uint64_t cidr_host_count(cidr_t block)
{
  if (block.prefix == 31U) {
    return UINT64_C(2);
  }
  if (block.prefix >= 32U) {
    return UINT64_C(1);
  }
  return (UINT64_C(1) << (32U - block.prefix)) - UINT64_C(2);
}

bool cidr_contains(cidr_t block, uint32_t addr)
{
  uint32_t mask = cidr_mask(block.prefix);
  return (addr & mask) == (block.addr & mask);
}

bool cidr_is_network(cidr_t block)
{
  return block.addr == cidr_network(block);
}

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out)
{
  if (out == NULL || block.prefix > 32U || !cidr_is_network(block) ||
      n == 0U || (n & (n - 1U)) != 0U || i >= n) {
    return false;
  }

  uint32_t borrowed_bits = 0;
  for (uint32_t remaining = n; remaining > 1U; remaining >>= 1) {
    borrowed_bits++;
  }
  uint32_t new_prefix = (uint32_t)block.prefix + borrowed_bits;
  if (new_prefix > 32U) {
    return false;
  }

  uint32_t host_bits = 32U - new_prefix;
  uint64_t subnet_size = UINT64_C(1) << host_bits;
  uint64_t subnet_addr = (uint64_t)block.addr + (uint64_t)i * subnet_size;
  cidr_t subnet = {
      .addr = (uint32_t)subnet_addr,
      .prefix = (uint8_t)new_prefix
  };
  *out = subnet;
  return true;
}

bool route_parse(const char *line, route_t *route)
{
  if (line == NULL || route == NULL) {
    return false;
  }

  const char *start = line;
  while (*start != '\0' && isspace((unsigned char)*start)) {
    start++;
  }
  const char *end = start + strlen(start);
  while (end > start && isspace((unsigned char)end[-1])) {
    end--;
  }
  if (start == end) {
    return false;
  }

  const char *fields[3];
  size_t lengths[3];
  const char *cursor = start;
  for (size_t i = 0; i < 3; i++) {
    if (!route_next_field(&cursor, end, &fields[i], &lengths[i])) {
      return false;
    }
  }
  if (cursor != end) {
    return false;
  }

  cidr_t dest;
  if (lengths[0] == 7 && memcmp(fields[0], "default", 7) == 0) {
    dest = (cidr_t){.addr = 0, .prefix = 0};
  } else {
    if (lengths[0] >= CIDR_STR_LEN) {
      return false;
    }
    char dest_text[CIDR_STR_LEN];
    memcpy(dest_text, fields[0], lengths[0]);
    dest_text[lengths[0]] = '\0';
    if (!cidr_parse(dest_text, &dest) || !cidr_is_network(dest)) {
      return false;
    }
  }

  uint32_t gateway;
  if (lengths[1] == 6 && memcmp(fields[1], "direct", 6) == 0) {
    gateway = 0;
  } else {
    if (lengths[1] >= IP_STR_LEN) {
      return false;
    }
    char gateway_text[IP_STR_LEN];
    memcpy(gateway_text, fields[1], lengths[1]);
    gateway_text[lengths[1]] = '\0';
    if (!ip_parse(gateway_text, &gateway)) {
      return false;
    }
  }

  if (lengths[2] >= DEV_NAME_LEN) {
    return false;
  }
  for (size_t i = 0; i < lengths[2]; i++) {
    if (isspace((unsigned char)fields[2][i])) {
      return false;
    }
  }

  route_t parsed = {.dest = dest, .gateway = gateway, .dev = {0}};
  memcpy(parsed.dev, fields[2], lengths[2]);
  *route = parsed;
  return true;
}

fwd_table_t *table_create(void)
{
  return calloc(1, sizeof(fwd_table_t));
}

void table_destroy(fwd_table_t *table)
{
  if (table != NULL) {
    free(table->routes);
    free(table);
  }
}

size_t table_count(const fwd_table_t *table)
{
  return table == NULL ? 0 : table->count;
}

bool table_add(fwd_table_t *table, const route_t *route)
{
  if (table == NULL || route == NULL || route->dest.prefix > 32U ||
      !cidr_is_network(route->dest)) {
    return false;
  }

  for (size_t i = 0; i < table->count; i++) {
    if (table->routes[i].dest.addr == route->dest.addr &&
        table->routes[i].dest.prefix == route->dest.prefix) {
      return false;
    }
  }

  if (table->count == table->capacity) {
    size_t new_capacity = table->capacity == 0 ? 4 : table->capacity * 2U;
    route_t *new_routes =
        reallocarray(table->routes, new_capacity, sizeof(*table->routes));
    if (new_routes == NULL) { // GCOVR_EXCL_BR_LINE
      return false; // GCOVR_EXCL_LINE
    }
    table->routes = new_routes;
    table->capacity = new_capacity;
  }

  table->routes[table->count] = *route;
  table->count++;
  return true;
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line)
{
  if (bad_line != NULL) {
    *bad_line = 0;
  }
  if (table == NULL || in == NULL) {
    return false;
  }

  char *line = NULL;
  size_t capacity = 0;
  size_t line_number = 0;
  ssize_t length;
  while ((length = getline(&line, &capacity, in)) >= 0) {
    (void)length;
    line_number++;
    char *comment = strchr(line, '#');
    if (comment != NULL) {
      *comment = '\0';
    }
    if (route_is_blank(line)) {
      continue;
    }

    route_t route;
    if (!route_parse(line, &route) || !table_add(table, &route)) {
      if (bad_line != NULL) {
        *bad_line = line_number;
      }
      free(line);
      return false;
    }
  }

  bool read_ok = (feof(in) != 0) & (ferror(in) == 0);
  free(line);
  return read_ok;
}

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest)
{
  if (table == NULL) {
    return NULL;
  }

  const route_t *best = NULL;
  for (size_t i = 0; i < table->count; i++) {
    const route_t *candidate = &table->routes[i];
    if (cidr_contains(candidate->dest, dest) &&
        (best == NULL || candidate->dest.prefix > best->dest.prefix)) {
      best = candidate;
    }
  }
  return best;
}
