#ifndef ROUTEMARIO_H
#define ROUTEMARIO_H

struct lcore_env {
  uint8_t n_port;
  uint8_t lcore_id;
  struct fdb_table* fdb;
  struct mbuf_table tx_mbufs[0];
};

#endif
