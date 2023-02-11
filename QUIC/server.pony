use @quic_retrieve_actor[QUICServer](self)
use @quic_is_new_connection_event[U8](event:Pointer[None] tag)
use "collections"
actor QUICServer
  let _subscribers': Subscribers
  new create() =>
  be acceptNewConnection(connection: Pointer[None] tag)
  fun @serverCallback(self: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag) =>
    if @quic_is_new_connection_event(event) == 1 then
      let quicServer: QUICServer = @quic_retrieve_actor(self)
      quicServer.acceptNewConnection(event)
    end
