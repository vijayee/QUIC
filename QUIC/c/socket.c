#include "socket.h"
#include <quicly.h>
#include <quicly/defaults.h>
#include <quicly/streambuf.h>
#include <hashmap.h>


static  HASHMAP(void*, *pony_callback) dispatcher;
void quic_pony_dispatcher_init() {
  if (dispactcher == null) {
    hashmap_init(&dispatcher, hash_pointer, ptrcmp);
  }
}
void quic_subscribe_stream_open (quicly_context_t* ctx, void * actor, void * cb, void* pb) {
  struct pony_callback* pc;
  pc = malloc(sizeof(pony_callback));
  pc->receiver = actor;
  pc->sender = pb;
  hashmap_put(&dispatcher, cb, pc);
  quicly_stream_open_t* stream_open = malloc(sizeof(quicly_stream_open_t));
  stream_open->on_stream_open = cb;
  ctx->stream_open = stream_open;
}

int quic_dispatch_pony_actor_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{

    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(struct st_stream_data_t))) != 0)
        return ret;
    struct pony_callback* pc = hashmap_get(&dispatcher, self);
    if (pc == NULL) {
      return -1;
    }
    pc->sender(pc->receiver, stream);
    stream->callbacks = ctx.tls->certificates.count != 0 ? &server_stream_callbacks : &client_stream_callbacks;
    return 0;
}

quicly_context_t* quic_create_ietf_ctx() {
  quicly_context_t ctx;
  ctx = quicly_spec_context;
  return &ctx
}

quicly_context_t* quic_create_performant_ctx() {
  quicly_context_t ctx;
  ctx = quicly_performant_context;
  return &ctx
}
void quic_ctx_add_ptls_ctx(quicly_ctx_t* ctx) {
  ptls_context_t tlsctx = {.random_bytes = ptls_openssl_random_bytes,
                                .get_time = &ptls_get_time,
                                .key_exchanges = ptls_openssl_key_exchanges,
                                .cipher_suites = cipher_suites,
                                .require_dhe_on_psk = 1,
                                .save_ticket = &save_session_ticket,
                                .on_client_hello = &on_client_hello};
}

int64_t quic_get_connection_timeout(quicly_conn_t *conn) {
    return quicly_get_first_timeout(conn);
}


int  ptrcmp(const void* ptr1, const char* ptr2) {
  if (ptr1 == ptr2) {
    return 0;
  } else {
    return 1;
  }
}
size_t hash_pointer(void * input) {
    #if __ILP32__
        size_t x = (size_t) input;
        x = ( ~x) + (x << 15);
        x = x ^ (x >> 12);
        x = x + (x << 2);
        x = x ^ (x >> 4);
        x = (x + (x << 3)) + (x << 11);
        x = x ^ (x >> 16);
        return x;
    #else
        size_t x = (size_t) input;
        x = (~x) + (x << 21);
        x = x ^ (x >> 24);
        x = (x + (x << 3)) + (x << 8);
        x = x ^ (x >> 14);
        x = (x + (x << 2)) + (x << 4);
        x = x ^ (x >> 28);
        x = x + (x << 31);
        return x;
    #endif
}

uint8_t * quic_receive_message(int fd, quicly_ctx_t* ctx) {
  while (1) {
      uint8_t buf[ctx.transport_params.max_udp_payload_size];
      struct msghdr mess;
      quicly_address_t remote;
      struct iovec vec;
      memset(&mess, 0, sizeof(mess));
      mess.msg_name = &remote.sa;
      mess.msg_namelen = sizeof(remote);
      vec.iov_base = buf;
      vec.iov_len = sizeof(buf);
      mess.msg_iov = &vec;
      mess.msg_iovlen = 1;
      ssize_t rret;
      while ((rret = recvmsg(fd, &mess, 0)) == -1 && errno == EINTR)
          ;
      if (rret == -1)
          break;
      size_t off = 0;
      while (off != rret) {
          quicly_decoded_packet_t packet;
          if (quicly_decode_packet(&ctx, &packet, buf, rret, &off) == SIZE_MAX)
              break;
          if (QUICLY_PACKET_IS_LONG_HEADER(packet.octets.base[0])) {
              if (packet.version != 0 && !quicly_is_supported_version(packet.version)) {
                  uint8_t payload[ctx.transport_params.max_udp_payload_size];
                  size_t payload_len = quicly_send_version_negotiation(&ctx, packet.cid.src, packet.cid.dest.encrypted,
                                                                       quicly_supported_versions, payload);
                  assert(payload_len != SIZE_MAX);
                  send_one_packet(fd, &remote.sa, payload, payload_len);
                  break;
              }
              /* there is no way to send response to these v1 packets */
              if (packet.cid.dest.encrypted.len > QUICLY_MAX_CID_LEN_V1 || packet.cid.src.len > QUICLY_MAX_CID_LEN_V1)
                  break;
          }

          quicly_conn_t *conn = NULL;
          size_t i;
          for (i = 0; i != num_conns; ++i) {
              if (quicly_is_destination(conns[i], NULL, &remote.sa, &packet)) {
                  conn = conns[i];
                  break;
              }
          }
          if (conn != NULL) {
              /* existing connection */
              quicly_receive(conn, NULL, &remote.sa, &packet);
          } else if (QUICLY_PACKET_IS_INITIAL(packet.octets.base[0])) {
              /* long header packet; potentially a new connection */
              quicly_address_token_plaintext_t *token = NULL, token_buf;
              if (packet.token.len != 0) {
                  const char *err_desc = NULL;
                  int ret = quicly_decrypt_address_token(address_token_aead.dec, &token_buf, packet.token.base,
                                                         packet.token.len, 0, &err_desc);
                  if (ret == 0 &&
                      validate_token(&remote.sa, packet.cid.src, packet.cid.dest.encrypted, &token_buf, &err_desc)) {
                      token = &token_buf;
                  } else if (enforce_retry && (ret == QUICLY_TRANSPORT_ERROR_INVALID_TOKEN ||
                                               (ret == 0 && token_buf.type == QUICLY_ADDRESS_TOKEN_TYPE_RETRY))) {
                      /* Token that looks like retry was unusable, and we require retry. There's no chance of the
                       * handshake succeeding. Therefore, send close without aquiring state. */
                      uint8_t payload[ctx.transport_params.max_udp_payload_size];
                      size_t payload_len = quicly_send_close_invalid_token(&ctx, packet.version, packet.cid.src,
                                                                           packet.cid.dest.encrypted, err_desc, payload);
                      assert(payload_len != SIZE_MAX);
                      send_one_packet(fd, &remote.sa, payload, payload_len);
                  }
              }
              if (enforce_retry && token == NULL && packet.cid.dest.encrypted.len >= 8) {
                  /* unbound connection; send a retry token unless the client has supplied the correct one, but not too
                   * many
                   */
                  uint8_t new_server_cid[8], payload[ctx.transport_params.max_udp_payload_size];
                  memcpy(new_server_cid, packet.cid.dest.encrypted.base, sizeof(new_server_cid));
                  new_server_cid[0] ^= 0xff;
                  size_t payload_len = quicly_send_retry(
                      &ctx, address_token_aead.enc, packet.version, &remote.sa, packet.cid.src, NULL,
                      ptls_iovec_init(new_server_cid, sizeof(new_server_cid)), packet.cid.dest.encrypted,
                      ptls_iovec_init(NULL, 0), ptls_iovec_init(NULL, 0), NULL, payload);
                  assert(payload_len != SIZE_MAX);
                  send_one_packet(fd, &remote.sa, payload, payload_len);
                  break;
              } else {
                  /* new connection */
                  int ret = quicly_accept(&conn, &ctx, NULL, &remote.sa, &packet, token, &next_cid, NULL);
                  if (ret == 0) {
                      assert(conn != NULL);
                      ++next_cid.master_id;
                      conns = realloc(conns, sizeof(*conns) * (num_conns + 1));
                      assert(conns != NULL);
                      conns[num_conns++] = conn;
                  } else {
                      assert(conn == NULL);
                  }
              }
          } else if (!QUICLY_PACKET_IS_LONG_HEADER(packet.octets.base[0])) {
              /* short header packet; potentially a dead connection. No need to check the length of the incoming packet,
               * because loop is prevented by authenticating the CID (by checking node_id and thread_id). If the peer is
               * also sending a reset, then the next CID is highly likely to contain a non-authenticating CID, ... */
              if (packet.cid.dest.plaintext.node_id == 0 && packet.cid.dest.plaintext.thread_id == 0) {
                  uint8_t payload[ctx.transport_params.max_udp_payload_size];
                  size_t payload_len = quicly_send_stateless_reset(&ctx, packet.cid.dest.encrypted.base, payload);
                  assert(payload_len != SIZE_MAX);
                  send_one_packet(fd, &remote.sa, payload, payload_len);
              }
          }
      }
  }
}
/*
int main()
{
    void *ptr ;
    ptr = "timeless";
    size_t adr = (size_t) ptr;
    printf("this is a pointer %p\n", ptr);
    printf("this is a size_t %zu\n", adr);
    printf("this is a hashed size_t %zu\n", hash_size_t(adr));

    return 0;
}*/
