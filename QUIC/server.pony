use @quic_retrieve_actor[QUICServer](self)
use @quic_is_new_connection_event[U8](event:Pointer[None] tag)
use @quic_server_listener_open[Pointer[None] tag](registration: Pointer[None] tag, serverListenerCallback: Pointer[None] tag)?
use @quic_server_listener_close[None](listener: Pointer[None] tag)
use @quic_cache_set[None](key: Pointer[None] tag, value: Pointer[None] tag)?
use @quic_cache_get[Pointer[None]](key: Pointer[None] tag)?;
use @quic_server_configuration[Pointer[Noner]](ctx: Pointer[None] tag)
use @quic_server_actor[QUICServer](ctx: Pointer[None] tag)
use @quic_receive_connection[Pointer[None] tag](event: Pointer[None] tag)
use @quic_connection_set_configuration(connection: Pointer[None] tag, configuration: Pointer[None] tag)
use @quic_send_resumption_ticket[None](connection: Pointer[None] tag)
use @quic_connection_actor[QUICConnection](key: Pointer[None] tag)?
use @quic_close_connection[None](connection: Pointer[None] tag)
use @quic_connection_set_callback[None](connection: Pointer[None] tag, connectionCallback: Pointer[None] tag)
use @quic_new_server_event_context[Pointer[None] tag](serverActor: Pointer[None] tag, configuration: Pointer[None] tag)
use @quic_new_connection_event_context[Pointer[None] tag]()
use @quic_free_connection_event_context[None](ctx: Pointer[None] tag)
use "collections"
use "Streams"

actor QUICServer is NotificationEmitter
  let _subscribers': Subscribers
  let _registration: QUICRegistration
  let _configuration: QUICConfiguration
  let _listener: Pointer[None] tag
  let _connections: Array[QUICConnection]
  let ctx: Pointer[None] tag
  new create(registration: QUICRegistration, configuration: QUICConfiguration) =>
    _subscribers' = Subscribers
    _connections = Array[QUICConnection](10)
    try
      ctx = @quic_new_server_event_context(addressof this, _configuration.config)
      _listener = @quic_server_listener_open(registration, addressof this.@serverCallback, ctx)?

    else
      _listener = Pointer[None]()
      // send an error
      None
    end

  be _acceptNewConnection(connection: QUICConnection)
    _connections.push(connection)

  fun @serverCallback(ctx: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag): U32 =>
    if @quic_is_new_connection_event(event) == 1 then
      try
        let quicServer: QUICServer = @quic_server_actor(ctx)?
        let configuration: Pointer[None] tag = @quic_server_configuration(ctx)?
        let conn: Pointer[None] tag = @quic_receive_connection(event)
        let connection: QUICConnection = QUICConnection._serverConnection(conn, ctx)
        let connectionCtx: Pointer[None] tag  = @quic_new_connection_event_context[Pointer[None] tag]()
        let connectionCb = @{(conn: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag): U32 =>
          return _QUICConnectionCallback(conn: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag)
        } val

        @quic_connection_set_callback(conn, addressof connectionCb, connectionCtx)
        let status: U32 = @quic_connection_set_configuration(conn, configuration)

        if status == 0 then
          quicServer._acceptNewConnection(connection)
          @quic_free_connection_event_context(connectionCtx)
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
