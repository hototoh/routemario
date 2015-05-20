/**
 * radix_trie.h
 * This radix_trie's key must be equal or less than 32 bit.
 * suited for IPv4 route lookup
 */

#ifndef RADIX_TIRE_H
#define RADIX_TIRE_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#define PREFIX_MASK_SIZE (8-1)

struct radix_trie_node {
  uint32_t prefix;
  uint8_t len;
  struct radix_trie_node* next[2];
  void *item;
};

void
destroy_radix_trie(struct radix_trie_node *root);

struct radix_trie_node *
create_radix_trie_node(uint16_t prefix, uint8_t len);

#define create_radix_trie() create_radix_trie_node(0, 0)

int
radix_trie_insert_item(struct radix_trie_node *root, uint32_t key,
                       uint8_t len, void* item);

void *
radix_trie_lookup_item(struct radix_trie_noe *root, uint32_t key);
                       
void
radix_trie_delete_item(struct radix_trie_node *root, uint32_t key, uint8_t len);
                       

#endif
