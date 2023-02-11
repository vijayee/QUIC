#include <pony.h>
#include <quicly.h>


struct pony_callback
{
  void(*sender)();
  void* receiver;
};
/** Set the pony actor to be returned by quic callbacks**/
void quic_pony_dispatcher_init();
void quic_subscribe_stream_open(quicly_context_t* ctx, void* actor, void* cb);
quicly_context_t* quic_create_ietf_ctx();
quicly_context_t* quic_create_performant_ctx();
quicly_context_t* quic_create_performant_ctx();
quicly_context_t* quic_free_ctx(quicly_context_t* ctx);
int quic_dispatch_pony_actor_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);
int64_t quic_get_connection_timeout(quicly_conn_t *conn);
uint8_t* quic_receive_message(int fd);
