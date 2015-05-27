/**
 * Hiroshi Tokaku <tkk@hongo.wide.ad.jp>
 **/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "radixtrie.h"
#include "bit_utils.h"

#ifdef DPDK
#include <rte_malloc.h>
#include <rte_log.h>
#define mmalloc(x) rte_malloc("fdb", (x), 0)
#define mfree(x) rte_free((x))
#define RTE_LOGTYPE_POPTRIE RTE_LOGTYPE_USER1
#define LOG(x, fmt, ...) RTE_LOG(x, POPTRIE, fmt, ## __VA_ARGS__)
#else
#define mmalloc(x) malloc((x))
#define mfree(x) free((x))
#ifndef ERR
#define ERR
#endif
#ifndef WARNING
#define WARNING
#endif
#ifndef INFO
#define INFO
#endif
#ifndef DEBUG
#define DEBUG
#endif
#define LOG(x, fmt, ...) \
  printf(#x " %s (%u):" fmt, __func__, __LINE__, ## __VA_ARGS__)
#endif

struct radixtrie *
radixtrie_create(item_free_func item_free)
{
  struct radixtrie *trie;
  size_t msize = sizeof(struct radixtrie);
  trie = (struct radixtrie *)mmalloc(msize);
  if (trie == NULL) {
    LOG(ERR, "Fail to allocate memory for radixtrie.\n");
    return NULL;
  }

  memset(trie, 0, msize);
  trie->item_free = item_free;
  return trie;
}

struct radixtrie_node *
radixtrie_node_create()
{
  struct radixtrie_node *node;
  size_t msize = sizeof(struct radixtrie_node);
  node = (struct radixtrie_node *)mmalloc(msize);
  if (node == NULL) {
    LOG(ERR, "Fail to allocate memory for radixtrie.\n");
    return NULL;
  }

  memset(node, 0, msize);
  node->parent = NULL;
  return node;
}

static void
radixtrie_delete_descendant_items(struct radixtrie *trie,
                                  struct radixtrie_node *node)
{
  if (node->next[0] != NULL)
    radixtrie_delete_descendant_items(trie, node->next[0]);
  if (node->next[1] != NULL)
    radixtrie_delete_descendant_items(trie, node->next[1]);
  if (node->item != NULL)
    trie->item_free(node->item);
  mfree(node);
}
                    
static void
radixtrie_delete_all_items(struct radixtrie* trie)
{
  struct radixtrie_node *node = &trie->root;  
  if (node->next[0] != NULL)
    radixtrie_delete_descendant_items(trie, node->next[0]);
  if (node->next[1] != NULL)
    radixtrie_delete_descendant_items(trie, node->next[1]);
  trie->item_free(node->item);
}
  
void
radixtrie_destroy(struct radixtrie *trie)
{
  radixtrie_delete_all_items(trie);
  mfree(trie);
}

void
radixtrie_node_destroy(struct radixtrie_node *node)
{
  mfree(node);
}

int
radixtrie_insert_item(struct radixtrie *trie, uint32_t key,
                       uint8_t deps, void *item)
{
  if (deps < 0) {
    LOG(ERR, "Invalid arguments..\n");
    return EINVAL;
  }
  
  uint8_t cur = 0;
  struct radixtrie_node *node = &trie->root, *parent = NULL;
  if (deps == 0) {
    LOG(DEBUG, "add default.\n");
    node->item = item;
    return 0;
  }

  while (node != NULL) {    
    uint8_t next_bit = kth_32bit_fleft(key, ++cur);
    parent = node;
    node = node->next[next_bit];
    if (node == NULL) {
      node = radixtrie_node_create();
      if (node == NULL) {
        LOG(ERR, "Fail to create radixtrie node.\n");
        return ENOMEM;
      }
      parent->next[next_bit] = node;
    }
    if (cur == deps) break;
  }

  node->item = item;
  return 0;
}

int
radixtrie_lookup_item(struct radixtrie *trie, uint32_t key, void **_item)
{
  void *item;
  uint8_t cur = 0;
  struct radixtrie_node *node = &trie->root;

  while (node != NULL) {
    if (node->item != NULL) item = node->item;
    
    uint8_t next_bit = kth_32bit_fleft(key, ++cur);
    node = node->next[next_bit];
  }
  
  *_item = item;
  if (item == NULL)
    return ENOENT;
  else
    return 0;
}
                       
int
radixtrie_delete_item(struct radixtrie *trie, uint32_t key, uint8_t deps)
{
  uint8_t cur = 0;
  struct radixtrie_node *node = &trie->root, *parent = NULL;
  if (deps == 0) {
    LOG(DEBUG, "delete default.\n");
    trie->item_free(node->item);
    return 0;
  }

  while (node != NULL && cur <= deps) {    
    uint8_t next_bit = kth_32bit_fleft(key, ++cur);
    parent = node;
    node = node->next[next_bit];
    if (node == NULL) return ENOENT;    
    if (cur == deps) {
      parent->next[next_bit] = NULL;
      trie->item_free(node);
      return 0;
    }
  }
  return ENOENT;
}
