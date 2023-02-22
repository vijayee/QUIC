use @quic_retrieve_actor[QUICServer](self)
use @quic_is_new_connection_event[U8](event:Pointer[None] tag)
use @quic_server_listener_open[Pointer[None] tag](registration: Pointer[None] tag, serverListenerCallback: Pointer[None] tag)?
use @quic_server_listener_close[None](listener: Pointer[None] tag)
use @quic_cache_set[None](key: Pointer[None] tag, value: Pointer[None] tag)?
use @quic_cache_get[Pointer[None]](key: Pointer[None] tag)?;
use @quic_server_configuration[QUICConfiguration](key: Pointer[None] tag)?
use @quic_server_actor[QUICServer](key: Pointer[None] tag)?
use @quic_receive_connection[Pointer[None] tag](event: Pointer[None] tag)
use @quic_connection_set_configuration(connection: Pointer[None] tag, configuration: Pointer[None] tag)
use @quic_send_resumption_ticket[None](connection: Pointer[None] tag)
use @quic_close_connection[None](connection: Pointer[None] tag)
use @quic_connection_set_callback[None](connection: Pointer[None] tag, connectionCallback: Pointer[None] tag)

use "collections"

actor QUICServer
  let _subscribers': Subscribers
  let _registration: QUICRegistration
  let _configuration: QUICConfiguration
  let _listener: Pointer[None] tag
  let _connections:
  new create(registration: QUICRegistration, configuration: QUICConfiguration) =>
    _subscribers' = Subscribers
    try
      _listener = @quic_server_listener_open(registration, addressof this.@serverCallback)?
      c
      @quic_cache_set(addressof this, addressof _configuration)?
    else
      // send an error
      None
    end


  fun @serverCallback(self: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag): U32 =>
    if @quic_is_new_connection_event(event) == 1 then
      try
        let quicServer: QUICServer = @quic_server_actor(self)?
        let configuration: QUICConfiguration = @quic_server_configuration(quicServer)?
        let conn: Pointer[None] tag = @quic_receive_connection(event)
        let connection: QUICConnection = QUICConnection._serverConnection(conn)
        let connectionCb = @{(conn: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag): U32 =>
          return _QUICConnectionCallback(conn: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag)
        } val

        @quic_connection_set_callback()
        @quic_connection_set_callback(conn, addressof connectionCb)
        let status: U32 = @quic_connection_set_configuration(conn, configuration)

        if status == 0 then
          @quic_cache_set(conn, addressof connection)?
        end
        return status
      else
        return 1
      end
    else
      return 0
    end
  fun _final() =>
    try
      @quic_server_listener_close(_listener(_listener)
      @quic_free(_listener)
      @quic_cache_delete(addressof this.@serverCallback)?
      @quic_cache_delete(addressof this)?
    end
