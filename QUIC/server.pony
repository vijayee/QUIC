use "collections"
use "Streams"
use "Exception"
use "Print"
primitive NoResume
  fun apply(): U8 =>
    @quic_server_resumption_no_resume()
primitive ResumeOnly
  fun apply(): U8 =>
    @quic_server_resumption_resume_only()
primitive ResumeAndZeroRTT
  fun apply(): U8 =>
    @quic_server_resumption_resume_and_zerortt()


primitive _QUICServerCallback
  fun @apply(context: Pointer[None] tag) =>
    let quicServer: QUICServer = @quic_server_actor(context)
    quicServer._readEventQueue()

primitive NewQUICServer
  fun apply(registration: QUICRegistration, configuration: QUICConfiguration val): QUICServer ?  =>
    let server: QUICServer = QUICServer._create(registration, configuration)
    let queue: Pointer[None] tag = @quic_new_event_queue()
    let ctx: Pointer[None] tag = @quic_new_server_event_context(server, addressof _QUICServerCallback.apply, queue)
    try
      let listener = @quic_server_listener_open(registration.registration, ctx)?
      server._initialize(ctx, listener, queue)
    else
      @quic_free(ctx)
      @quic_free(queue)
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
  var _queue: Pointer[None] tag
  var _isClosed: Bool = true

  new _create(registration: QUICRegistration, configuration: QUICConfiguration val) =>
    _subscribers = Subscribers
    _connections = Array[QUICConnection](10)
    _configuration = configuration
    _registration = registration
    _listener = Pointer[None]
    _ctx = Pointer[None]
    _queue = Pointer[None]

  be _initialize(ctx: Pointer[None] tag, listener: Pointer[None] tag, queue: Pointer[None] tag) =>
    _isClosed = false
    _ctx = ctx
    _listener = listener
    _queue = queue

  fun ref subscribers(): Subscribers =>
    _subscribers

  fun ref _acceptNewConnection(connection: QUICConnection) =>
    _connections.push(connection)
    let onclose: CloseNotify iso= object iso is CloseNotify
      let _server: QUICServer = this
      let _connection: QUICConnection = connection
      fun ref apply() =>
          _server._removeConnection(_connection)
    end
    connection.subscribe(consume onclose)
    notifyPayload[QUICConnection](NewConnectionEvent, connection)


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

  be _readEventQueue() =>
    try
      let event: Pointer[None] tag = @quic_dequeue_event(_queue, 0)?
      match @quic_server_event_type_as_int(event)
        | 0  =>
          let conn: Pointer[None] tag = @quic_receive_connection(event)
          let queue = @quic_new_event_queue()
          let connectionCtx: Pointer[None] tag = @quic_new_connection_event_context(0, Pointer[None], queue)
          let connection: QUICConnection = QUICConnection._serverConnection(conn, connectionCtx, queue)
          @quic_connection_event_context_set_actor(connectionCtx, connection)

          @quic_connection_set_callback(conn, addressof _QUICConnectionCallback.apply, connectionCtx)
          let status: U32 = @quic_connection_set_configuration(conn, _configuration.config)

          if status == 0 then
            _acceptNewConnection(connection)
          end
      | 1 =>
        return
      end
      @quic_server_free_event(event)
    end

  fun _final() =>
    Println("GC Happening")
    if not _isClosed then
      @quic_server_listener_close(_listener)
      @quic_free(_listener)
      @quic_free(_ctx)
    end
