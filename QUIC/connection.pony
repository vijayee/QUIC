use "Streams"
use "Exception"
use "Print"
use "collections"
primitive _QUICConnectionCallback
  fun @apply (context: Pointer[None]) =>
    let connection: QUICConnection = @quic_connection_actor(context)
    connection._readEventQueue()


primitive OpenZeroRTTStream
  fun apply(): U32 =>
    0x0001

primitive OpenUnidirectionalStream
  fun apply(): U32 =>
    0x0002

type QUICStreamOpenFlags is (OpenZeroRTTStream | OpenUnidirectionalStream)

primitive Immediate
  fun apply(): U32 =>
    0x0001

primitive FailBlocked
  fun apply(): U32 =>
    0x0002

primitive ShutdownOnFail
  fun apply(): U32 =>
    0x0004

primitive IndicatePeerAccept
  fun apply(): U32 =>
    0x0008

type QUICStreamStartFlags is (None | Immediate | FailBlocked | ShutdownOnFail | IndicatePeerAccept)

primitive Unspecified
  fun apply(): I32 =>
    @quic_address_family_unspecified()
primitive INET
  fun apply(): I32 =>
    @quic_address_family_inet()
primitive INET6
  fun apply() : I32 =>
    @quic_address_family_inet6()

type QUICAddressFamily is (Unspecified| INET | INET6)

primitive NewQUICConnection
  fun apply(registration: QUICRegistration, configuration: QUICConfiguration val): QUICConnection ? =>
    let ctx = @quic_new_connection_event_context(1, addressof _QUICConnectionCallback.apply)
    try
      let connection = QUICConnection._create(configuration)
      @quic_connection_event_context_set_actor(ctx, connection)
      let conn = @quic_connection_open(registration.registration, addressof _QUICConnectionCallback.apply, ctx)?

      connection._initialize(ctx, conn)
      connection
    else
      @quic_free_connection_event_context(ctx)
      error
    end

actor QUICConnection is NotificationEmitter
  var _connection: Pointer[None] tag
  let _streams: Array[QUICStream]
  var _ctx: Pointer[None] tag
  let _subscribers: Subscribers
  var _invalid: Bool = true
  var _started: Bool = false
  var _configuration: (QUICConfiguration val | None) = None


  new _create(configuration: QUICConfiguration val) =>
    _configuration = configuration
    _streams = Array[QUICStream](3)
    _ctx = Pointer[None]
    _subscribers = Subscribers
    _connection = Pointer[None]

  new _serverConnection(conn: Pointer[None] tag, ctx: Pointer[None] tag) =>
    _streams = Array[QUICStream](3)
    _connection = conn
    _ctx = ctx
    _subscribers = Subscribers
    _invalid = false

  fun ref subscribers() : Subscribers =>
    _subscribers

  be _readEventQueue() =>
    try
      let event: Pointer[None] tag = @quic_dequeue_event(_ctx)?
      match  @quic_get_connection_event_type_as_int(event)
        //QUIC_CONNECTION_EVENT_CONNECTED
        | 0 =>
          let sessionResumed: Bool = @quic_connection_connected_event_session_resumed(event) == 1
          let alpn: Array[U8] iso = recover
            let alpnLength: USize = @quic_connection_connected_event_session_negotiated_alpn_length(event).usize()
            let ponyBuffer: Pointer[U8] = @pony_alloc(@pony_ctx(), alpnLength)
            @quic_connection_connected_event_session_negotiated_alpn_data(event, ponyBuffer)
            let alpn': Array[U8] = Array[U8].from_cpointer(ponyBuffer, alpnLength)
            alpn'
          end
          let data: ConnectedData = ConnectedData(sessionResumed, consume alpn)
          _dispatchConnected(data)

        //QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT
        | 1 =>
          let status: U32 = @quic_connection_shutdown_initiated_by_transport_data_status(event)
          let errorCode: U64 = @quic_connection_shutdown_initiated_by_transport_data_error_code(event)
          let data: ShutdownInitiatedByTransportData = ShutdownInitiatedByTransportData(status, errorCode)
          _dispatchShutdownInitiatedByTransport(data)
        //QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER
        | 2 =>
          let data: U64 = @quic_connection_shutdown_initiated_by_peer_data(event)
          _dispatchShutdownInitiatedByPeer(data)
        //QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
        | 3 =>
          var data': _ShutdownCompleteData = _ShutdownCompleteData
          @quic_connection_shutdown_complete_data(event, addressof data')
          let data: ShutdownCompleteData = ShutdownCompleteData(data'.handshakeCompleted, data'.peerAcknowledgedShutdown, data'.appCloseInProgress)
          _dispatchShutdownComplete(data)
          _dispatchClose()
          _close()
        //QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED
        | 4 =>
          let data': Pointer[None] tag = @quic_connection_event_local_address_changed_data(event)
          let data: QUICAddress val = recover val QUICAddress(data') end
          _dispatchLocalAddressChanged(data)
        // QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED
        | 5 =>
          let data': Pointer[None] tag = @quic_connection_event_peer_address_changed_data(event)
          let data: QUICAddress val = recover val QUICAddress(data') end
          _dispatchPeerAddressChanged(data)
        // QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED
        | 6 =>
          let strm: Pointer[None] tag = @quic_receive_stream(event)
          let ctx: Pointer[None] tag = @quic_stream_new_event_context(addressof _QUICStreamCallback.apply)
          let stream: QUICStream = match @quic_receive_stream_type(event)
          | 1 => QUICReadableStream._create(strm, ctx)
          else
            QUICDuplexStream._create(strm, ctx)
          end
          @quic_stream_event_context_set_actor(ctx, stream)
          @quic_stream_set_callback(strm, ctx)
          _receiveNewStream(stream)
         //QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE
        | 7 =>
          var data': _StreamsAvailableData = _StreamsAvailableData
          @quic_connection_event_streams_available_data(event, addressof data')
          let data: StreamsAvailableData = StreamsAvailableData(data'.bidirectionalCount, data'.unidirectionalCount)
          _dispatchStreamsAvailable(data)
        //QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS
        | 8 =>
          let data: Bool = @quic_connection_event_peer_needs_streams_data(event) == 1
          _dispatchPeerNeedsStreams(data)
        //QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED
        | 9 =>
          let data: U16 = @quic_connection_event_ideal_processor_changed_data(event)
          _dispatchIdealProcessorChanged(data)
        //QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED
        | 10 =>
          var data': _DatagramStateChangedData = _DatagramStateChangedData
          @quic_connection_event_datagram_state_changed_data(event, addressof data')
          let data: DatagramStateChangedData = DatagramStateChangedData(data'.sendEnabled == 1, data'.maxSendLength.usize())
          _dispatchDatagramStateChanged(data)
        //QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED
        | 11 =>
          let length: USize = @quic_connection_event_datagram_received_buffer_length(event).usize()
          let data': Array[U8] val = recover
            let buffer: Pointer[U8] = @pony_alloc(@pony_ctx(), length)
            Array[U8].from_cpointer(buffer, length)
          end
          let flags: Array[QUICReceiveFlags] val = recover
            let flags': Array[QUICReceiveFlags] = Array[QUICReceiveFlags](2)
            let flag: U32 = @quic_connection_event_datagram_received_flags(event)

            if flag == 0 then
              flags'.push(None)
            else
              if (flag and ZeroRTT()) == ZeroRTT() then
                flags'.push(ZeroRTT)
              end
              if (flag and FIN()) == FIN() then
                flags'.push(FIN)
              end
            end
            flags'
          end
          let data = DatagramReceivedData(flags, data')
          _dispatchDatagramReceived(data)
          //QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED
        | 12 =>
          let data: QUICDatagramSendState = match @quic_connection_event_datagram_send_state_changed_data(event)
            | 0 => Unknown
            | 1 => Sent
            | 2 => LostSuspect
            | 3 => LostDiscarded
            | 4 => Acknowledged
            | 5 => AcknowledgedSpurious
            | 6 => Canceled
            else
              Unknown
          end
          _dispatchDatagramSendStateChanged(data)
          //QUIC_CONNECTION_EVENT_RESUMED
        | 13 =>
          let buffer: Array[U8] val = recover
            let length: USize = @quic_connection_event_resumed_resumption_state_length(event).usize()
            let buffer': Pointer[U8] = @pony_alloc(@pony_ctx(), length)
            @quic_connection_event_resumed_resumption_state_buffer(event, buffer')
            Array[U8].from_cpointer(buffer', length)
           end
          let data: ResumedData val = ResumedData(buffer)
          _dispatchResumed(data)
          //QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED
        | 14 =>
          let ticket: Array[U8] val = recover
            let length: USize = @quic_connection_event_resumption_ticket_received_resumption_ticket_length(event).usize()
            let buffer: Pointer[U8] = @pony_alloc(@pony_ctx(), length)
            @quic_connection_event_resumption_ticket_received_resumption_ticket(event, buffer)
            Array[U8].from_cpointer(buffer, length)
          end
          let data: ResumptionTicketReceivedData =  ResumptionTicketReceivedData(ticket)
          _dispatchResumptionTicketReceived(data)
          //QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED
        | 15 =>
          _dispatchPeerCertificateReceived()
      end
      @quic_connection_free_event(event)
    else
      Println("queue is empty")
    end

  be _initialize(ctx: Pointer[None] tag, connection: Pointer[None] tag) =>
    _invalid = false
    _ctx = ctx
    _connection = connection

  be start( ip: String, port: U16, family: QUICAddressFamily = Unspecified, resumptionTicket: (Array[U8] val | None) = None) =>
    if not _started then
      try
        match resumptionTicket
          | let resumptionTicket': Array[U8] val =>
            @quic_connection_set_resumption_ticket(_connection, resumptionTicket'.cpointer(), resumptionTicket'.size().u32())?
        end
        @quic_connection_start(_connection, (_configuration as QUICConfiguration).config, family(), ip.cstring(), port)?
        _started = true
      else
        notifyError(Exception("Failed to start connection"))
      end
      _started = true
    end

  be openStream[S: (QUICDuplexStream tag | QUICWriteableStream tag) = QUICDuplexStream](cb: {((S | Exception))} val, flag: (QUICStreamOpenFlags | None) = None) =>
    if _invalid then
      cb(Exception("Connection is invalid"))
      return
    end
    let ctx: Pointer[None] tag = @quic_stream_new_event_context(addressof _QUICStreamCallback.apply)
    try
      let flag': U32 = match flag
        | None => 0
        | let flag'': QUICStreamOpenFlags => flag''()
      end
      let strm: Pointer[None] tag = @quic_stream_open_stream(_connection, flag', ctx)?

      iftype S <: QUICWriteableStream then
        let ws: QUICWriteableStream tag = QUICWriteableStream._create(strm, ctx)
        @quic_stream_event_context_set_actor(ctx, ws)
        _streams.push(ws)
        let onclose: CloseNotify iso= object iso is CloseNotify
          let _connection: QUICConnection = this
          let _stream: QUICStream = ws
          fun ref apply() =>
            _connection._removeStream(_stream)
        end
        ws.subscribe(consume onclose)
        cb(ws)
      elseif S <: QUICDuplexStream then
        let ds: QUICDuplexStream tag = QUICDuplexStream._create(strm, ctx)
        @quic_stream_event_context_set_actor(ctx, ds)
        _streams.push(ds)
        let onclose: CloseNotify iso= object iso is CloseNotify
          let _connection: QUICConnection = this
          let _stream: QUICStream = ds
          fun ref apply() =>
            _connection._removeStream(_stream)
        end
        ds.subscribe(consume onclose)
        cb(ds)
      end
      @quic_stream_start_stream(strm)?
    else
      cb(Exception("Failed to Open Stream"))
      @quic_free(ctx)
    end

  fun ref _receiveNewStream(stream: QUICStream) =>
    _streams.push(stream)
    let onclose: CloseNotify iso= object iso is CloseNotify
      let _connection: QUICConnection = this
      let _stream: QUICStream = stream
      fun ref apply() =>
        _connection._removeStream(_stream)
    end
    stream.subscribe(consume onclose)
    _dispatchPeerStreamStarted(stream)

  be _removeStream(stream: QUICStream) =>
    var i: USize = 0
    var found: Bool = false
    for strm in _streams.values() do
      if strm is stream then
        found = true
      end
      i = i + 1
    end
    if found then
      _streams.remove(i, 1)
    end

  be getStreams(cb: {(Array[QUICStream] val)} val) =>
    let size = _streams.size()
    let streams: Array[QUICStream] iso = recover Array[QUICStream tag](size) end
    for strm in _streams.values() do
      streams.push(strm)
    end
    cb(consume streams)

  fun ref subscribeInternal(notify': Notify iso, once: Bool = false) =>
    let subscribers': Subscribers = subscribers()
    let notify'': Notify = consume notify'
    try
      subscribers'(notify'')?.push((notify'', once))
    else
      let arr: Subscriptions = Subscriptions(10)
      arr.push((notify'', once))
      subscribers'(notify'') =  arr
    end
    if subscriberCount(notify'') == 0 then
      match notify''
      | let notify''': ConnectedNotify =>
        if subscriberCount(ConnectedEvent) == 0 then
          ConnectedEvent._enable(_ctx)
        end
      | let notify''': ShutdownInitiatedByTransportNotify =>
        if subscriberCount(ShutdownInitiatedByTransportEvent) == 0 then
          ShutdownInitiatedByTransportEvent._enable(_ctx)
        end
      | let notify''': ShutdownInitiatedByPeerNotify =>
        if subscriberCount(ShutdownInitiatedByPeerEvent) == 0 then
          ShutdownInitiatedByPeerEvent._enable(_ctx)
        end
      | let notify''': ShutdownCompleteNotify =>
        if subscriberCount(ShutdownCompleteEvent) == 0 then
          ShutdownCompleteEvent._enable(_ctx)
        end
      | let notify''': LocalAddressChangedNotify =>
        if subscriberCount(LocalAddressChangedEvent) == 0 then
          LocalAddressChangedEvent._enable(_ctx)
        end
      | let notify''': PeerAddressChangedNotify =>
        if subscriberCount(PeerAddressChangedEvent) == 0 then
          PeerAddressChangedEvent._enable(_ctx)
        end
      | let notify''': PeerStreamStartedNotify =>
        if subscriberCount(PeerStreamStartedEvent) == 0 then
          PeerStreamStartedEvent._enable(_ctx)
        end
      | let notify''': StreamsAvailableNotify =>
        if subscriberCount(StreamsAvailableEvent) == 0 then
          StreamsAvailableEvent._enable(_ctx)
        end
      | let notify''': PeerNeedsStreamsNotify =>
        if subscriberCount(PeerNeedsStreamsEvent) == 0 then
          PeerNeedsStreamsEvent._enable(_ctx)
        end
      | let notify''': IdealProcessorChangedNotify =>
        if subscriberCount(IdealProcessorChangedEvent) == 0 then
          IdealProcessorChangedEvent._enable(_ctx)
        end
      | let notify''':  DatagramStateChangedNotify =>
        if subscriberCount( DatagramStateChangedEvent) == 0 then
           DatagramStateChangedEvent._enable(_ctx)
        end
      | let notify''': DatagramReceivedNotify =>
        if subscriberCount(DatagramReceivedEvent) == 0 then
          DatagramReceivedEvent._enable(_ctx)
        end
      | let notify''': DatagramSendStateChangedNotify =>
        if subscriberCount(DatagramSendStateChangedEvent) == 0 then
          DatagramSendStateChangedEvent._enable(_ctx)
        end
      | let notify''': ResumedNotify =>
        if subscriberCount(ResumedEvent) == 0 then
          ResumedEvent._enable(_ctx)
        end
      | let notify''': ResumptionTicketReceivedNotify =>
        if subscriberCount(ResumptionTicketReceivedEvent) == 0 then
          ResumptionTicketReceivedEvent._enable(_ctx)
        end
      | let notify''': PeerCertificateReceivedNotify =>
        if subscriberCount(PeerCertificateReceivedEvent) == 0 then
          PeerCertificateReceivedEvent._enable(_ctx)
        end
      end
    end

    fun ref _dispatchPeerStreamStarted(data: QUICStream) =>
        notifyPayload[QUICStream](PeerStreamStartedEvent, data)

    fun ref _dispatchConnected(data: ConnectedData val) =>
      notifyPayload[ConnectedData](ConnectedEvent, data)

    fun ref _dispatchShutdownInitiatedByTransport(data: ShutdownInitiatedByTransportData val) =>
      Println("Notify called")
      notifyPayload[ShutdownInitiatedByTransportData val](ShutdownInitiatedByTransportEvent, data)

    fun ref _dispatchShutdownInitiatedByPeer(data: U64) =>
      notifyPayload[U64](ShutdownInitiatedByPeerEvent, data)

    fun ref _dispatchShutdownComplete(data: ShutdownCompleteData val) =>
      Println("Shutdown Complete notified")
      notifyPayload[ShutdownCompleteData val](ShutdownCompleteEvent, data)

    fun ref _dispatchLocalAddressChanged(data: QUICAddress val) =>
      notifyPayload[QUICAddress val](LocalAddressChangedEvent, data)

    fun ref _dispatchPeerAddressChanged(data: QUICAddress val) =>
      notifyPayload[QUICAddress val](PeerAddressChangedEvent, data)

    fun ref _dispatchStreamsAvailable(data: StreamsAvailableData val) =>
      notifyPayload[StreamsAvailableData val](StreamsAvailableEvent, data)

    fun ref _dispatchPeerNeedsStreams(data: Bool) =>
      notifyPayload[Bool](PeerNeedsStreamsEvent, data)

    fun ref _dispatchDatagramStateChanged(data: DatagramStateChangedData val) =>
      notifyPayload[DatagramStateChangedData val](DatagramStateChangedEvent, data)

    fun ref _dispatchDatagramReceived(data: DatagramReceivedData val) =>
      notifyPayload[DatagramReceivedData val](DatagramReceivedEvent, data)

    fun ref _dispatchDatagramSendStateChanged(data: QUICDatagramSendState) =>
      notifyPayload[QUICDatagramSendState](DatagramSendStateChangedEvent, data)

    fun ref _dispatchResumed(data: ResumedData val) =>
      notifyPayload[ResumedData val](ResumedEvent, data)

    fun ref _dispatchResumptionTicketReceived(data: ResumptionTicketReceivedData val) =>
       notifyPayload[ResumptionTicketReceivedData val](ResumptionTicketReceivedEvent, data)

    fun ref _dispatchPeerCertificateReceived() =>
       notify(PeerCertificateReceivedEvent)

    fun ref _dispatchIdealProcessorChanged(data: U16) =>
      notifyPayload[U16](IdealProcessorChangedEvent, data)

    fun ref _dispatchClose() =>
      notify(CloseEvent)

    fun _close() =>
      @quic_connection_shutdown(_connection)
      @quic_connection_close(_connection)

    be close() => None
      _close()
    fun _final() =>
      _close()
      @quic_free_connection_event_context(_ctx)
