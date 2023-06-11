use "collections"
use "Streams"
use "Exception"

primitive NoResume
  fun apply(): U8 =>
    @quic_server_resumption_no_resume()
primitive ResumeOnly
  fun apply(): U8 =>
    @quic_server_resumption_resume_only()
primitive ResumeAndZeroRTT
  fun apply(): U8 =>
    @quic_server_resumption_resume_and_zerortt()


primitive NewQUICServer
  fun apply(registration: QUICRegistration, configuration: QUICConfiguration val): QUICServer ?  =>
    let server: QUICServer = QUICServer._create(registration, configuration)
    let ctx = @quic_new_server_event_context(server, configuration.config)
    try
      let listener = @quic_server_listener_open(registration.registration, addressof server.serverCallback, ctx)?
      server._initialize(ctx, listener)
    else
      @quic_free(ctx)
      error
    end
    server

actor QUICServer is NotificationEmitter
  let _subscribers: Subscribers
  let _registration: QUICRegistration
  let _configuration: QUICConfiguration val
  var _listener: Pointer[None] tag
  let _connections: Array[QUICConnection]
  var _ctx: Pointer[None] tag
  var _isClosed: Bool = true

  new _create(registration: QUICRegistration, configuration: QUICConfiguration val) =>
    _subscribers = Subscribers
    _connections = Array[QUICConnection](10)
    _configuration = configuration
    _registration = registration
    _listener = Pointer[None]
    _ctx = Pointer[None]

  be _initialize(ctx: Pointer[None] tag, listener: Pointer[None] tag) =>
    _isClosed = false
    _ctx = ctx
    _listener = listener

  fun ref subscribers(): Subscribers =>
    _subscribers

  be _acceptNewConnection(connection: QUICConnection) =>
    _connections.push(connection)
    let onclose: CloseNotify iso= object iso is CloseNotify
      let _server: QUICServer = this
      let _connection: QUICConnection = connection
      fun ref apply() =>
          _server._removeConnection(_connection)
    end
    connection.subscribe(consume onclose)

  be _removeConnection(connection: QUICConnection) =>
    var i: USize = 0
    var found: Bool = false
    for conn in _connections.values() do
      if conn is connection then
        found = true
      end
      i = i + 1
    end
    if found then
      _connections.remove(i, 1)
    end

  be getConnections(cb: {(Array[QUICConnection] val)} val) =>
    let size = _connections.size()
    let connections: Array[QUICConnection] iso = recover Array[QUICConnection](size) end
    for conn in _connections.values() do
      connections.push(conn)
    end
    cb(consume connections)

  be listen(port: U16 , ip: String = "0.0.0.0", family: QUICAddressFamily = Unspecified) =>
    try
      let alpn: Array[Pointer[U8] tag] = Array[Pointer[U8] tag](_configuration.alpn.size())
      for app in _configuration.alpn.values() do
        alpn.push(app.cstring())
      end
      @quic_server_listener_start(_listener, alpn.cpointer(), alpn.size().u32(), family(), ip.cstring(), port.string().cstring())?
      notify(ListenerStartedEvent)
    else
      notifyError(Exception("Failed to start server listener"))
    end

  be stopListening() =>
    @quic_server_listener_stop(_listener)
    notify(ListenerStoppedEvent)

  be close() =>
    _isClosed = true
    @quic_server_listener_close(_listener)
    @quic_free(_listener)
    @quic_free(_ctx)
    notify(CloseEvent)

  fun @serverCallback(ctx: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag): U32 =>
    if @quic_is_new_connection_event(event) == 1 then
      let quicServer: QUICServer = @quic_server_actor(ctx)
      let configuration: Pointer[None] tag = @quic_server_configuration(ctx)
      let conn: Pointer[None] tag = @quic_receive_connection(event)
      let connectionCtx: Pointer[None] tag = @quic_new_connection_event_context[Pointer[None] tag](0, Pointer[None])
      let connection: QUICConnection = QUICConnection._serverConnection(conn, connectionCtx)
      @quic_connection_event_context_set_actor(connectionCtx, connection)
      let connectionCb = @{(conn: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag): U32 =>
        _QUICConnectionCallback(conn, context, event)
      } val

      @quic_connection_set_callback(conn, connectionCb, connectionCtx)
      let status: U32 = @quic_connection_set_configuration(conn, configuration)

      if status == 0 then
        quicServer._acceptNewConnection(connection)
      end
      return status
    else
      return 0
    end

  fun _final() =>
    if not _isClosed then
      @quic_server_listener_close(_listener)
      @quic_free(_listener)
      @quic_free(_ctx)
    end
