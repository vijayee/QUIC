
use @quic_connection_actor[QUICConnection](key: Pointer[None] tag)?
use @quic_get_connection_event_type_as_uint[U8](event: Pointer[None] tag)

primitive _QUICConnectionCallback(conn: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag, connection: QUICConnection): U32 =>
  try
    let connection: QUICConnection = @quic_connection_actor(conn)?
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
        connection._dispatchPeerStreamInitiated()
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

actor QUICConnection
  let connection: Pointer[None] tag
  new _serverConnection(conn: Pointer[None] tag) =>
    connection = conn

  fun @connectionCallback (self: Pointer[None] tag, context: Pointer[None] tag, event: Pointer[None] tag) =>
