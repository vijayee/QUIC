use @pony_alloc[Pointer[U8]](ctx: Pointer[None], size: USize)
use @pony_ctx[Pointer[None]]()
use @quic_connection_actor[QUICConnection](ctx: Pointer[None] tag)?
use @quic_get_connection_event_type_as_uint[U32](event: Pointer[None] tag)
use @quic_receive_stream[Pointer[None] tag](event: Pointer[None] tag)
use @quic_receive_stream_type[U8](event: Pointer[None] tag)
use @quic_cache_set[None](key: Pointer[None] tag, value: Pointer[None] tag)?
use @quic_stream_actor[QUICStream](key: Poiner[None] tag)?
use @quic_connection_open[Pointer[None] tag](registration: Pointer[None] tag, callback:Pointer[None] tag)?
use @quic_free_connection_event_context[None](ctx: Pointer[None] tag)
use @quic_connection_event_enabled[U8](ctx: Pointer[None] tag, event: Pointer[None] tag)
use @quic_connection_connected_event_session_negotiated_alpn_length[U8](event: Pointer[None] tag)
use @quic_connection_connected_event_session_resumed[U8](event: Pointer[None] tag)
use @quic_connection_connected_event_session_negotiated_alpn_data[None](event: Pointer[None] tag, buffer: Pointer[U8] tag)
use @quic_connection_shutdown_initiated_by_transport_data[ShutdownInitiatedByTransportData](event: Pointer[None] tag)
use @quic_connection_shutdown_initiated_by_peer_data[U64](event: Pointer[None] tag)
use @quic_connection_shutdown_complete_data[None](event: Pointer[None] tag, data: Pointer[ShutdownCompleteData] tag);
use @quic_connection_event_local_address_changed_data[Pointer[None] tag](event: Pointer[None] tag)
use @quic_connection_event_peer_address_changed_data[Pointer[None] tag](event: Pointer[None] tag)
use @quic_connection_event_streams_available_data[None](event: Pointer[None] tag, data: Pointer[StreamsAvailableData])
use @quic_connection_event_peer_needs_streams_data[U8](event: Pointer[None] tag)
use @quic_connection_event_ideal_processor_changed_data[U16](event: Pointer[None] tag)
use @quic_connection_event_datagram_send_state_changed_data[U32](event: Pointer[None] tag)
use @quic_connection_event_datagram_received_flags[U32](event: Pointer[None] tag)
use @quic_connection_event_datagram_received_buffer_length[U32](event: Pointer[None] tag)
use @quic_connection_event_datagram_received_buffer[None](event: Pointer[None] tag, buffer: Pointer[U8] tag)
use @quic_connection_event_datagram_state_changed_data[None](event: Pointer[None] tag, data: Pointer[DatagramStateChangedData] tag)
use @quic_connection_event_resumed_resumption_state_length[U16](event: Pointer[None] tag)
use @quic_connection_event_resumed_resumption_state_buffer[None](event: Pointer[None] tag, buffer: Pointer[U8] tag)
use @quic_connection_event_resumption_ticket_received_resumption_ticket_length[U32](event: Pointer[None] tag)
use @quic_connection_event_resumption_ticket_received_resumption_ticket[None](event: Pointer[None] tag, buffer: Pointer[U8] tag)

primitive _QUICConnectionCallback(cb: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag): U32 =>
  try
    let connection: QUICConnection = @quic_connection_actor(context)?
    match  @quic_get_connection_event_type_as_uint(event)
      //QUIC_CONNECTION_EVENT_CONNECTED
      | 0 =>
        @quic_send_resumption_ticket(conn)
        if @quic_connection_event_enabled(context, event) == 1 then
          let alpnLength: U8 = @quic_connection_connected_event_session_negotiated_alpn_length(event)
          let sessionResumed: Bool = @quic_connection_connected_event_session_resumed(event) == 1
          let ponyBuffer: Pointer[None] tag = @pony_alloc(@pony_ctx(), alpLength.usize())
          @quic_connection_connected_event_session_negotiated_alpn_data(event, ponyBuffer)
          let alpn: Array[U8] iso = recover Array[U8].from_cpointer(ponyBuffer) end
          let data: ConnectedData = ConnectedData(sesionResumed, consume alpn)
          connection._dispatchConnected(data)
        end
      //QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT
      | 1 =>
        if @quic_connection_event_enabled(context, event) == 1 then
          let data: ShutdownInitiatedByTransportData val = recover val @quic_connection_shutdown_initiated_by_transport_data(event) end
          connection._dispatchShutdownInitiatedByTransportData(data)
        end
      //QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER
      | 2 =>
        if @quic_connection_event_enabled(context, event) == 1 then
          let data: u64 = @quic_connection_shutdown_initiated_by_peer_data(event)
          connection._dispatchShutdownInitiatedByPeerData(data)
        end
      //QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
      | 3 =>
        if @quic_connection_event_enabled(context, event) == 1 then
          let data: ShutdownCompleteData val =  recover val
            let data': ShutdownCompleteData = ShutdownCompleteData
            @quic_connection_shutdown_complete_data(event, addressof data')
            data'
          end
          connection._dispatchShutdownComplete(data)
        end
        @quic_close_connection(conn)
        connection._dispatchClosed()
      //QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED
      | 4 =>
        if @quic_connection_event_enabled(context, event) == 1 then
          let data': Pointer[None] tag = @quic_connection_event_local_address_changed_data(event)
          let data: QUICAddress val = recover val QUICAddress(data') end
          connection._dispatchLocalAddressChanged(data)
        end
      // QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED
      | 5 =>
        if @quic_connection_event_enabled(context, event) == 1 then
          let data': Pointer[None] tag = @quic_connection_event_peer_address_changed_data(event)
          let data: QUICAddress val = recover val QUICAddress(data') end
          connection._dispatchPeerAddressChanged(data)
        end
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
        if @quic_connection_event_enabled(context, event) == 1 then
          let data: StreamsAvailableData val = recover val
            let data': StreamsAvailableData = StreamsAvailableData
             @quic_connection_event_streams_available_data(event, addressof data)
             data'
           end
          connection._dispatchStreamsAvailable(data)
        end
      //QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS
      | 8 =>
        if @quic_connection_event_enabled(context, event) == 1 then
          let data: Bool = @quic_connection_event_peer_needs_streams_data(event) == 1
          connection._dispatchPeerNeedsStreams(data)
        end
      //QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED
      | 9 =>
        if @quic_connection_event_enabled(context, event) == 1 then
          let data: Bool = @quic_connection_event_peer_needs_streams_data(event) == 1
          connection._dispatchIdealProcessorChanged(data)
        end
      //QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED
      | 10 =>
        if @quic_connection_event_enabled(context, event) == 1 then
          let data: DatagramStateChangedData val = recover
            let data' = DatagramStateChangedData
            quic_connection_event_datagram_state_changed_data(event, addressof data')
            data'
          end
          connection._dispatchDatagramStateChanged(data)
        end
      //QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED
      | 11 =>
        if @quic_connection_event_enabled(context, event) == 1 then
          let length: USize = @quic_connection_event_datagram_received_buffer_length(event).usize()
          let buffer: Pointer[U8] tag = @pony_alloc(@pony_ctx(), length)
          let data': Array[U8] val = recover Array[U8].from_cpointer(buffer) end
          let flags: Array[QUICReceiveFlags] val = recover
            let flags': Array[QUICReceiveFlags] = Array[QUICReceiveFlags](2)
            let flag: U32 = @quic_connection_event_datagram_received_flags(event)

            if flag == 0 then
              flags'.push(None)
            else
              if (flag and ZeroRTT()) == ZeroRTT() then
                flags'.push(ZeroRTT)
              end
              if (flag and FIN()) == FIN() the
                flags'.push(FIN)
              end
            end
            flags'
          end
          let data = DatagramReceivedData(flags, data')
          connection._dispatchDatagramReceived(data)
        end
        //QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED
      | 12 =>
        if @quic_connection_event_enabled(context, event) == 1 then
          let data: QUICDatagramSendState = match @quic_connection_event_datagram_send_state_changed_data[U32](event)
            | 0 => Unknown
            | 1 => Sent
            | 2 => LostSuspect
            | 3 => LostDiscarded
            | 4 => Acknowledged
            | 5 => AcknowledgedSpurious
            | 6 => Canceled
          end
          connection._dispatchDatagramSendStateChanged(data)
        end
        //QUIC_CONNECTION_EVENT_RESUMED
      | 13 =>
        if @quic_connection_event_enabled(context, event) == 1 then
          let length: U16 = @quic_connection_event_resumed_resumption_state_length(event)
          let buffer': Pointer[U8] tag = @pony_alloc(@pony_ctx(), length.usize())
          @quic_connection_event_resumed_resumption_state_buffer(event, buffer)
          let buffer: Array[U8] val = recover Array[U8].from_cpointer(buffer') end
          let data: ResumedData val = ResumedData(buffer)
          connection._dispatchResumed(data)
        end
        //QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED
      | 14 =>
        if @quic_connection_event_enabled(context, event) == 1 then
          let length: U32 = @quic_connection_event_resumption_ticket_received_resumption_ticket_length(event)
          let buffer: Pointer[U8] tag = @pony_alloc(@pony_ctx(), length.usize())
          @quic_connection_event_resumption_ticket_received_resumption_ticket(event, buffer)
          let ticket: Array[U8] val = recover Array[U8].from_cpointer(buffer) end
          let data: ResumptionTicketReceivedData =  ResumptionTicketReceivedData(ticket)
          connection._dispatchResumptionTicketReceived(data)
        end
        //QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED
      | 15 =>
        if @quic_connection_event_enabled(context, event) == 1 then
          connection._dispatchPeerCertificateReceived()
        end
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

    be _dispatchConnected(data: ConnectedData) =>
      notifyPayload[ConnectedData](ConnectedEvent, data)

    be _dispatchShutdownInitiatedByTransport(data: ShutdownInitiatedByTransportData val) =>
      notifyPayload[ShutdownInitiatedByTransportData val](ShutdownInitiatedByTransportEvent, data)

    be _dispatchShutdownInitiatedByPeer(data: U64) =>
      notifyPayload[U64](ShutdownInitiatedByPeerEvent, data)

    be _dispatchShutdownInitiatedComplete(data: ShutdownCompleteData val) =>
      notifyPayload[ShutdownCompleteData val](ShutdownCompleteEvent, data)

    be _dispatchLocalAddressChanged(data: QUICAddress val) =>
      notifyPayload[QUICAddress val](LocalAddressChangedEvent, data)

    be _dispatchPeerAddressChanged(data: QUICAddress val) =>
      notifyPayload[QUICAddress val](PeerAddressChangedEvent, data)

    be _dispatchStreamsAvailable(data: StreamsAvailableData val) =>
      notifyPayload[StreamsAvailableData val](StreamsAvailableEvent, data)

    be _dispatchPeerNeedsStreams(data: Bool) =>
      notifyPayload[Bool](PeerNeedsStreamsEvent, data)

    be _dispatchDatagramStateChanged(data: DatagramStateChangedData val) =>
      notifyPayload[DatagramStateChangedData val](DatagramChangedEvent, data)

    be _dispatchDatagramReceived(data: DatagramReceivedData val) =>
      notifyPayload[DatagramReceivedData val](DatagramReceivedEvent, data)

    be _dispatchDatagramSendStateChanged(data: QUICDatagramSendState) =>
      notifyPayload[QUICDatagramSendState](DatagramStateChangedEvent, data)

    be _dispatchDatagramSendStateChanged(data: ResumedData) =>
      notifyPayload[ResumedData](ResumedEvent, data)

    be _dispatchResumptionTicketReceived(data: ResumptionTicketReceivedData val) =>
       notifyPayload[ResumptionTicketReceivedData val](ResumptionTicketReceivedEvent, data)

    be _dispatchPeerCertificateReceived()
       notify(PeerCertificateReceivedEvent)
    be _dispatchClosed() =>
      notify(ClosedEvent)

  fun _final()=>
    @quic_free_connection_event_context(_ctx)
