use "lib:numa"
use "lib:msquic"
use "lib:ponyquic"
use @quic_new_configuration[Pointer[None] tag](registration:Pointer[None] tag, alpn: Pointer[Pointer[U8]tag] tag, alpnSize: U32, settings: Pointer[None], buf: QUICBuffer)?
use @quic_new_settings[Pointer[None] tag](maxBytesPerKey: QUICSettingValue[U64] tag,
    handshakeIdleTimeoutMs: QUICSettingValue[U64] tag,
    idleTimeoutMs: QUICSettingValue[U64] tag,
    mtuDiscoverySearchCompleteTimeoutUs: QUICSettingValue[U64] tag,
    tlsClientMaxSendBuffer: QUICSettingValue[U32] tag,
    tlsServerMaxSendBuffer: QUICSettingValue[U32] tag,
    streamRecvWindowDefault: QUICSettingValue[U32] tag,
    streamRecvBufferDefault: QUICSettingValue[U32] tag,
    connFlowControlWindow: QUICSettingValue[U32] tag,
    maxWorkerQueueDelayUs: QUICSettingValue[U32] tag,
    maxStatelessOperations: QUICSettingValue[U32] tag,
    initialWindowPackets: QUICSettingValue[U32] tag,
    sendIdleTimeoutMs: QUICSettingValue[U32] tag,
    initialRttMs: QUICSettingValue[U32] tag,
    maxAckDelayMs: QUICSettingValue[U32] tag,
    disconnectTimeoutMs: QUICSettingValue[U32] tag,
    keepAliveIntervalMs: QUICSettingValue[U32] tag,
    congestionControlAlgorithm: QUICSettingValue[U16] tag,
    peerBidiStreamCount: QUICSettingValue[U16] tag,
    peerUnidiStreamCount: QUICSettingValue[U16] tag,
    maxBindingStatelessOperations: QUICSettingValue[U16] tag,
    statelessOperationExpirationMs: QUICSettingValue[U16] tag,
    minimumMtu: QUICSettingValue[U16] tag,
    maximumMtu: QUICSettingValue[U16] tag,
    sendBufferingEnabled: QUICSettingValue[U8] tag,
    pacingEnabled: QUICSettingValue[U8] tag,
    migrationEnabled: QUICSettingValue[U8] tag,
    datagramReceiveEnabled: QUICSettingValue[U8] tag,
    serverResumptionLevel: QUICSettingValue[U8] tag,
    greaseQuicBitEnabled: QUICSettingValue[U8] tag,
    ecnEnabled: QUICSettingValue[U8] tag,
    maxOperationsPerDrain: QUICSettingValue[U8] tag,
    mtuDiscoveryMissingProbeCount: QUICSettingValue[U8] tag,
    destCidUpdateIdleTimeoutMs: QUICSettingValue[U32] tag)
use @quic_configuration_load_credential[None](configuration: Pointer[None] tag, credentials: Pointer[None] tag)?

use @quic_certificate_file[Pointer[None] tag](privateKeyFile: Pointer[U8] tag, certificateFile: Pointer[U8] tag)
use @quic_certificate_file_protected[Pointer[None] tag](certificateFile: Pointer[U8] tag, privateKeyFile: Pointer[U8] tag, privateKeyPassword: Pointer[U8] tag)
use @quic_certificate_pkcs12[Pointer[None]](Asn1Blob: Pointer[U8] tag, Asn1BlobLength: U32, privateKeyPassword: Pointer[U8] tag)
use @quic_new_credential_config[Pointer[None] tag](credType: I32, flags: U64, cert: Pointer[None] tag, allowedCiphers: U8, caCertificateFile: Pointer[U8] tag)

use @quic_connection_actor[QUICConnection](ctx: Pointer[None] tag)
use @quic_get_connection_event_type_as_uint[U32](event: Pointer[None] tag)
use @quic_receive_stream[Pointer[None] tag](event: Pointer[None] tag)
use @quic_receive_stream_type[U32](event: Pointer[None] tag)
use @quic_stream_set_callback[None](stream: QUICStream, streamCallback: Pointer[None] tag, ctx: Pointer[None] tag)
use @quic_stream_new_event_context[Pointer[None] tag]()
use @quic_stream_event_context_set_actor[None](ctx: Pointer[None] tag, streamActor: QUICStream)
use @quic_connection_open[Pointer[None] tag](registration: Pointer[None] tag, callback:Pointer[None] tag, ctx: Pointer[None] tag)?
use @quic_free_connection_event_context[None](ctx: Pointer[None] tag)
use @quic_connection_event_enabled[U8](ctx: Pointer[None] tag, event: Pointer[None] tag)
use @quic_connection_connected_event_session_negotiated_alpn_length[U8](event: Pointer[None] tag)
use @quic_connection_connected_event_session_resumed[U8](event: Pointer[None] tag)
use @quic_connection_connected_event_session_negotiated_alpn_data[None](event: Pointer[None] tag, buffer: Pointer[U8] tag)
use @quic_connection_shutdown_initiated_by_transport_data[_ShutdownInitiatedByTransportData](event: Pointer[None] tag)
use @quic_connection_shutdown_initiated_by_peer_data[U64](event: Pointer[None] tag)
use @quic_connection_shutdown_complete_data[None](event: Pointer[None] tag, data: Pointer[_ShutdownCompleteData] tag)
use @quic_connection_event_local_address_changed_data[Pointer[None] tag](event: Pointer[None] tag)
use @quic_connection_event_peer_address_changed_data[Pointer[None] tag](event: Pointer[None] tag)
use @quic_connection_event_streams_available_data[None](event: Pointer[None] tag, data: Pointer[_StreamsAvailableData])
use @quic_connection_event_peer_needs_streams_data[U8](event: Pointer[None] tag)
use @quic_connection_event_ideal_processor_changed_data[U16](event: Pointer[None] tag)
use @quic_connection_event_datagram_send_state_changed_data[U32](event: Pointer[None] tag)
use @quic_connection_event_datagram_received_flags[U32](event: Pointer[None] tag)
use @quic_connection_event_datagram_received_buffer_length[U32](event: Pointer[None] tag)
use @quic_connection_event_datagram_received_buffer[None](event: Pointer[None] tag, buffer: Pointer[U8] tag)
use @quic_connection_event_datagram_state_changed_data[None](event: Pointer[None] tag, data: Pointer[_DatagramStateChangedData] tag)
use @quic_connection_event_resumed_resumption_state_length[U16](event: Pointer[None] tag)
use @quic_connection_event_resumed_resumption_state_buffer[None](event: Pointer[None] tag, buffer: Pointer[U8] tag)
use @quic_connection_event_resumption_ticket_received_resumption_ticket_length[U32](event: Pointer[None] tag)
use @quic_connection_event_resumption_ticket_received_resumption_ticket[None](event: Pointer[None] tag, buffer: Pointer[U8] tag)

use @quic_stream_get_total_buffer[None](event: Pointer[None] tag, buffer: Pointer[U8] tag, stream: Pointer[None] tag)
use @quic_stream_get_total_buffer_length[U64](event: Pointer[None] tag)

use @quic_stream_status_pending[U32]()
use @pony_alloc[Pointer[U8]](ctx: Pointer[None], size: USize)
use @pony_ctx[Pointer[None]]()
use @quic_stream_actor[QUICStream](ctx: Pointer[None] tag)
use @quic_get_stream_event_type_as_uint[U32](event: Pointer[None] tag)

use @quic_connection_set_connected_event[None](ctx: Pointer[None], value: U8)
use @quic_connection_set_shutdown_initiated_by_transport_event[None](ctx: Pointer[None], value: U8)
use @quic_connection_set_shutdown_initiated_by_peer_event[None](ctx: Pointer[None], value: U8)
use @quic_connection_set_shutdown_complete_event[None](ctx: Pointer[None], value: U8)
use @quic_connection_set_local_address_changed_event[None](ctx: Pointer[None], value: U8)
use @quic_connection_set_peer_address_changed_event[None](ctx: Pointer[None], value: U8)
use @quic_connection_set_peer_stream_started_event[None](ctx: Pointer[None], value: U8)
use @quic_connection_set_streams_available_event[None](ctx: Pointer[None], value: U8)
use @quic_connection_set_peer_needs_streams_event[None](ctx: Pointer[None], value: U8)
use @quic_connection_set_ideal_processor_changed_event[None](ctx: Pointer[None], value: U8)
use @quic_connection_set_datagram_state_changed_event[None](ctx: Pointer[None], value: U8)
use @quic_connection_set_datagram_received_event[None](ctx: Pointer[None], value: U8)
use @quic_connection_set_datagram_send_state_changed_event[None](ctx: Pointer[None], value: U8)
use @quic_connection_set_resumed_changed_event[None](ctx: Pointer[None], value: U8)
use @quic_connection_set_datagram_resumption_ticket_received_event[None](ctx: Pointer[None], value: U8)
use @quic_connection_set_datagram_peer_certificate_received_event[None](ctx: Pointer[None], value: U8)

use @quic_new_registration[Pointer[None] tag](config: Pointer[None] tag)?
use @quic_free_registration[None](registration: Pointer[None] tag)
use @quic_new_registration_config[Pointer[None] tag](appName: Pointer[U8 val] tag, executionProfile: I32)
use @quic_free[None](ptr: Pointer[None] tag)

use @quic_is_new_connection_event[U8](event:Pointer[None] tag)
use @quic_server_listener_open[Pointer[None] tag](registration: Pointer[None] tag, serverListenerCallback: Pointer[None] tag, ctx: Pointer[None] tag)?
use @quic_server_listener_close[None](listener: Pointer[None] tag)
use @quic_server_configuration[Pointer[None]](ctx: Pointer[None] tag)
use @quic_server_actor[QUICServer](ctx: Pointer[None] tag)
use @quic_receive_connection[Pointer[None] tag](event: Pointer[None] tag)
use @quic_connection_set_configuration[U32](connection: Pointer[None] tag, configuration: Pointer[None] tag)
use @quic_send_resumption_ticket[None](connection: Pointer[None] tag)
use @quic_close_connection[None](connection: Pointer[None] tag)
use @quic_connection_set_callback[None](connection: Pointer[None] tag, connectionCallback: Pointer[None] tag, ctx: Pointer[None] tag)
use @quic_new_server_event_context[Pointer[None] tag](serverActor: QUICServer, configuration: Pointer[None] tag)
use @quic_new_connection_event_context[Pointer[None] tag]()
use @quic_connection_event_context_set_actor[None](ctx: Pointer[None] tag, connectionActor: QUICConnection)

use @quic_stream_start_complete_data[_StreamStartCompleteData](event: Pointer[None] tag)
use @quic_stream_event_send_complete_canceled[U8](event: Pointer[None] tag)
use @quic_stream_event_peer_send_aborted_error_code[U64](event: Pointer[None] tag)
use @quic_stream_event_peer_receive_aborted_error_code[U64](event: Pointer[None] tag)
use @quic_stream_event_send_shutdown_complete_graceful[U8](event: Pointer[None] tag)
use @quic_stream_shutdown_complete_data[_StreamShutdownCompleteData](event: Pointer[None] tag)
use @quic_stream_event_ideal_send_buffer_size_byte_count[U64](event: Pointer[None] tag)
use @quic_stream_open_stream[Pointer[None] tag](connection: Pointer[None] tag, flag: U32, callback: Pointer[None] tag, ctx: Pointer[None] tag)?
use @quic_stream_close_stream[None](stream: Pointer[None] tag)
use @quic_stream_start_stream[None](stream: Pointer[None] tag)?
use @quic_stream_send[None](stream: Pointer[None] tag, buffer: Pointer[U8] tag, bufferLength: USize)?
use @quic_stream_shutdown[None](stream: Pointer[None] tag, flag: U32)?

use @quic_connection_start[None](connection:Pointer[None] tag, configurgation: Pointer[None] tag, family: U16, target: Pointer[U8] tag, port:U16)?
use @quic_connection_set_resumption_ticket[None](connection: Pointer[None] tag, ticket: Pointer[U8] tag, ticketLength: U32)?
use @quic_connection_close[None](connection: Pointer[None] tag)
use @quic_connection_shutdown[None](connection: Pointer[None] tag)
use @quic_server_resumption_no_resume[U8]()
use @quic_server_resumption_resume_only[U8]()
use @quic_server_resumption_resume_and_zerortt[U8]()
