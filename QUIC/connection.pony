
use @quic_connection_actor[QUICConnection](key: Pointer[None] tag)?
use @quic_get_connection_event_type_as_uint[U8](event: Pointer[None] tag)
use @quic_receive_stream[Pointer[None] tag](event: Pointer[None] tag)
use @quic_receive_stream_type[U8](event: Pointer[None] tag)
use @quic_cache_set[None](key: Pointer[None] tag, value: Pointer[None] tag)?
use @quic_stream_actor[QUICStream](key: Poiner[None] tag)?
use @quic_connection_open[Pointer[None] tag](registration: Pointer[None] tag, callback:Pointer[None] tag)?
use @quic_free_connection_event_context[None](ctx: Pointer[None] tag)

primitive _QUICConnectionCallback(cb: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag): U32 =>
  try
    let connection: QUICConnection = @quic_connection_actor(cb)?
    match  @quic_get_connection_event_type_as_uint(event)
      //QUIC_CONNECTION_EVENT_CONNECTED
      | 0 =>
        @quic_send_resumption_ticket(conn)
      //QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT
      | 1 =>
        connection._dispatchShutdown()
      //QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER
      | 2 =>
        connection._dispatchShutdown()
      //QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
      | 3 =>
        @quic_close_connection(conn)
        connection._dispatchClosed()
      //QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED
      | 4 =>
        connection._dispatchLocalAdressChanged()
      // QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED
      | 5 =>
        connection._dispatchRemoteAdressChanged()
      // QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED
      | 6 =>
        let strm: Pointer[None] tag = @quic_receive_stream(event);
        let stream: QUICStream = match quic_receive_stream_type(event)
          | 1 => QUICReadableStream._create(strm)
        else
          QUICDuplexStream._create(strm)
        end
        let streamCallback =@{(strm: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag) =>
          try
            let stream: QUICStream = @quic_stream_actor(strm)?
            return _QUICStreamCallback(strm, context, event, stream)
          else
            return 1
          end
          return
        }
        @quic_cache_set(strm, addressof stream)
        connection._dispatchNewStream(stream)
       //QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE
      | 7 =>
        connection._dispatchStreamsAvailable()
      //QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS
      | 8 =>
        connection._dispatchStreamsNeeded()
      //QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED
      | 9 =>
        connection._dispatchIdealProcessorChanged()
      //QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED
      | 10 =>
        connection._dispatchDatagramStateChanged()
      //QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED
      | 11 =>
        connection._dispatchDatagramReceived()
        //QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED
      | 12 =>
        connection._dispatchDatagramSendStateChanged()
        //QUIC_CONNECTION_EVENT_RESUMED
      | 13 =>
        connection._dispatchConnectionResumed()
        //QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED
      | 14 =>
        connection._dispatchResumptionTicketReceived()
        //QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED
      | 15 =>
        connection._dispatchRemoteCertificateReceived()
    end
    return 0
  else
    return 1
  end

actor QUICConnection is NotificationEmitter
  let _connection: Pointer[None] tag
  let _streams: Array[QUICStream]
  let _ctx: Pointer[None] tag

  new create(registration: QUICRegistration, configuration: QUICConfiguration, ctx: Pointer[None] tag, resumptionTicket: (Array[U8] val | None)) =>
    _streams = Array[QUICStream](3)
    _ctx = ctx
    try
      _connection = @quic_connection_open(registration, addressof this.connectionCallback)?
    else
      _connection = Pointer[None]()
    end

  new _serverConnection(conn: Pointer[None] tag, ctx: Pointer[None] tag) =>
    streams = Array[QUICStream](3)
    connection = conn

  be _receiveNewStream(connection: QUICConnection)
    _connections.push(connection)

  fun @connectionCallback(conn: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag): U32 =>
    return _QUICConnectionCallback(conn: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag)

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
          ConnectedEvent._enable()
        end
      | let notify''': ShutdownInitiatedByTransportNotify =>
        if subscriberCount(ShutdownInitiatedByTransportEvent) == 0 then
          ShutdownInitiatedByTransportEvent._enable()
        end
      | let notify''': ShutdownInitiatedByPeerNotify =>
        if subscriberCount(ShutdownInitiatedByPeerEvent) == 0 then
          ShutdownInitiatedByPeerEvent._enable()
        end
      | let notify''': ShutdownCompleteNotify =>
        if subscriberCount(ShutdownCompleteEvent) == 0 then
          ShutdownCompleteEvent._enable()
        end
      | let notify''': LocalAddressChangedNotify =>
        if subscriberCount(LocalAddressChangedEvent) == 0 then
          LocalAddressChangedEvent._enable()
        end
      | let notify''': PeerAddressChangedNotify =>
        if subscriberCount(PeerAddressChangedEvent) == 0 then
          PeerAddressChangedEvent._enable()
        end
      | let notify''': PeerStreamStartedNotify =>
        if subscriberCount(PeerStreamStartedEvent) == 0 then
          PeerStreamStartedEvent._enable()
        end
      | let notify''': StreamsAvailableNotify =>
        if subscriberCount(StreamsAvailableEvent) == 0 then
          StreamsAvailableEvent._enable()
        end
      | let notify''': PeerNeedsStreamsNotify =>
        if subscriberCount(PeerNeedsStreamsEvent) == 0 then
          PeerNeedsStreamsEvent._enable()
        end
      | let notify''': IdealProcessorChangedNotify =>
        if subscriberCount(IdealProcessorChangedEvent) == 0 then
          IdealProcessorChangedEvent._enable()
        end
      | let notify''':  DatagramStateChangedNotify =>
        if subscriberCount( DatagramStateChangedEvent) == 0 then
           DatagramStateChangedEvent._enable()
        end
      | let notify''': DatagramReceivedNotify =>
        if subscriberCount(DatagramReceivedEvent) == 0 then
          DatagramReceivedEvent._enable()
        end
      | let notify''': DatagramSendStateChangedNotify =>
        if subscriberCount(DatagramSendStateChangedEvent) == 0 then
          DatagramSendStateChangedEvent._enable()
        end
      | let notify''': ResumedNotify =>
        if subscriberCount(ResumedEvent) == 0 then
          ResumedEvent._enable()
        end
      | let notify''': ResumptionTicketReceivedNotify =>
        if subscriberCount(ResumptionTicketReceivedEvent) == 0 then
          ResumptionTicketReceivedEvent._enable()
        end
      | let notify''': PeerCertificateReceivedNotify =>
        if subscriberCount(PeerCertificateReceivedEvent) == 0 then
          PeerCertificateReceivedEvent._enable()
        end
      end
    end


  fun _final()=>
    @quic_free_connection_event_context(_ctx)
