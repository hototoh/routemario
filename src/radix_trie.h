#ifndef RADIX_TIRE_H
#define RADIX_TIRE_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#define PREFIX_MASK_SIZE (8-1)

struct radix_trie_node {
  uint8_t prefix;
  uint8_t len;
  struct radix_trie_node* next[2];
  void *item;
};

struct radix_trie {
  uint16_t len;
  struct radix_trie_node* heads[0];
};

struct radix_trie*
create_radix_trie(uint16_t len);

void
destroy_radix_trie(struct radix_trie *trie);

int
radix_trie_insert_item(struct radix_trie *trie, uint8_t* key,
                       uint8_t len, void* item);

void *
radix_trie_lookup_item(struct radix_trie *trie, uint8_t* key, uint8_t len);
                       

void
radix_trie_delete_item(struct radix_trie *trie, uint8_t key, uint8_t len);
                       

#endif
