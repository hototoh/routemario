/**
 * radix_trie.h
 * This radix_trie's key must be equal or less than 32 bit.
 * suited for IPv4 route lookup
 */

#ifndef RADIXTRIE_H
#define RADIXTRIE_H

#include <stdint.h>
#include <stdbool.h>

typedef void (*item_free_func)(void*);

struct radixtrie_node {
  struct radixtrie_node* parent;
  struct radixtrie_node* next[2];
  void *item;
};

struct radixtrie {
  item_free_func item_free;
  struct radixtrie_node root;
};

struct radixtrie *
radixtrie_create();

void
radixtrie_destroy(struct radixtrie *trie);

int
radixtrie_insert_item(struct radixtrie *trie, uint32_t key,
                       uint8_t deps, void *item);

int
radixtrie_lookup_item(struct radixtrie *trie, uint32_t key, void **item);
                       
int
radixtrie_delete_item(struct radixtrie *tire, uint32_t key, uint8_t deps);
                       
#endif
