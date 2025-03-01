use "collections"
use "Streams"
use "Exception"
use "Print"
use "time"

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
    let queue: Pointer[None] tag = @quic_new_event_queue()
    let server: QUICServer = QUICServer._create(registration, configuration, queue)
    let ctx: Pointer[None] tag = @quic_new_server_event_context(server, addressof _QUICServerCallback.apply, queue, configuration.config, addressof _QUICConnectionCallback.apply)
    try
      let listener = @quic_server_listener_open(registration.registration, ctx)?
      server._initialize(ctx, listener)
    else
      @quic_free(ctx)
      @quic_free(queue)
      error
    end
    server


 class TestNotify is TimerNotify
   let _server: QUICServer


   new iso create(server: QUICServer) =>
     _server = server

   fun ref apply(timer: Timer, count: U64): Bool =>
     Println("timer fire")
     _server._fromTimer()
     true

actor QUICServer is NotificationEmitter
  let _subscribers: Subscribers
  let _registration: QUICRegistration
  let _configuration: QUICConfiguration val
  var _listener: Pointer[None] tag
  let _connections: Array[QUICConnection]
  var _ctx: Pointer[None] tag
  var _queue: Pointer[None] tag
  var _isClosed: Bool = true

  new _create(registration: QUICRegistration, configuration: QUICConfiguration val, queue: Pointer[None] tag) =>
    _subscribers = Subscribers
    _connections = Array[QUICConnection](10)
    _configuration = configuration
    _registration = registration
    _listener = Pointer[None]
    _ctx = Pointer[None]
    _queue = queue

    let timers = Timers
    let timer = Timer(TestNotify(this), 5_000_000_000, 2_000_000_000)
    timers(consume timer)

  be _fromTimer() =>
    Println("Got a timer")

  be _initialize(ctx: Pointer[None] tag, listener: Pointer[None] tag) =>
    _isClosed = false
    _ctx = ctx
    _listener = listener

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
      @quic_server_listener_start(_listener, alpn.cpointer(), alpn.size().u32(), family(), ip.cstring(), port)?
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
      let wrapper: Pointer[None] tag = @quic_dequeue_event(_queue, 0)?
      let event: Pointer[None] tag = @quic_server_event_from_wrapper(wrapper)
      match @quic_server_event_type_as_int(event)
        | 0  =>
          let conn: Pointer[None] tag = @quic_receive_connection(event)
          let connectionCtx: Pointer[None] tag = @quic_server_connection_context_from_wrapper(wrapper)
          let queue: Pointer[None] tag = @quic_server_connection_queue_from_context(connectionCtx)
          let connection: QUICConnection = QUICConnection._serverConnection(conn, connectionCtx, queue)
          @quic_connection_event_context_set_actor(connectionCtx, connection)
          let status: I32 = @quic_server_configuration_status_from_wrapper(wrapper)

          if status == -2 then
            _acceptNewConnection(connection)
            if (@quic_queue_empty(queue) == 0) then
              connection._readEventQueue()
            end
          else
            notifyError(Exception("Failed to set configuration for new connection"))
          end
      | 1 =>
        return
      end
      @quic_server_free_event(event)
    else
      notifyError(Exception("Server Queue Empty"))
      close()
    end

  fun _final() =>
    Println("GC Happening")
    if not _isClosed then
      @quic_server_listener_close(_listener)
      @quic_free(_listener)
      @quic_free(_ctx)
    end
