use "Streams"
use "Exception"

use @quic_connection_set_connected_event[None](ctx: Pointer[None], uint8_t value)
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

primitive QUICHashspace
  fun apply(): USize => 20000

trait ConnectedNotify is PayloadNotify[ConnectedData val]
  fun ref apply(data: ConnectedData)
  fun box hash(): USize =>
    QUICHashspace() + 1

primitive ConnectedEvent is ConnectedNotify
  fun ref apply(data: ConnectedData) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_connected_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_connected_event(ctx, 0)

trait ShutdownInitiatedByTransportNotify is PayloadNotify[ShutdownInitiatedByTransportData val]
  fun ref apply(data: ShutdownInitiatedByTransportData)
  fun box hash(): USize =>
    QUICHashspace() + 2

primitive ShutdownInitiatedByTransportEvent is ShutdownInitiatedByTransportNotify
  fun ref apply(data: ConnectedData) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_shutdown_initiated_by_transport_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_shutdown_initiated_by_transport_event(ctx, 0)

trait ShutdownInitiatedByPeerNotify is PayloadNotify[Exception]
  fun ref apply(data: Exception)
  fun box hash(): USize =>
    QUICHashspace() + 3

primitive ShutdownInitiatedByPeerEvent is ShutdownInitiatedByPeerNotify
  fun ref apply(data: Exception) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_shutdown_initiated_by_peer_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_shutdown_initiated_by_peer_event(ctx, 0)

trait ShutdownCompleteNotify is PayloadNotify[ShutdownCompleteData val]
  fun ref apply(data: ShutdownCompleteData)
  fun box hash(): USize =>
    QUICHashspace() + 4

primitive ShutdownCompleteEvent is ShutdownCompleteNotify
  fun ref apply(data: ShutdownCompleteData) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_shutdown_complete_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_shutdown_complete_event(ctx, 0)

trait LocalAddressChangedNotify is ParyloadNotify[QUICAdressInfo val]
  fun ref apply(data: QUICAdressInfo)
  fun box hash(): USize =>
    QUICHashspace() + 5

primitive LocalAddressChangedEvent is LocalAddressChangedNotify
  fun ref apply(data: QUICAdressInfo) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_local_address_changed_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_local_address_changed_event(ctx, 0)

trait PeerAddressChangedNotify is PayloadNotify[QUICAdressInfo val]
  fun ref apply(data: QUICAdressInfo) => None
  fun box hash(): USize =>
    QUICHashspace() + 6

primitive PeerAddressChangedEvent is PeerAddressChangedNotify
  fun ref apply(data: QUICAdressInfo) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_peer_address_changed_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_peer_address_changed_event(ctx, 0)

trait PeerStreamStartedNotify is PayloadNotify[PeerStreamStartedData val]
  fun ref apply(data: PeerStreamStartedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 7

primitive PeerStreamStartedEvent is PeerStreamStartedNotify
  fun ref apply(data: PeerStreamStartedData) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_peer_stream_started_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_peer_stream_started_event(ctx, 0)

trait StreamsAvailableNotify is PayloadNotify[StreamsAvailableData val]
  fun ref apply(data: PeerStreamStartedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 8

primitive StreamsAvailableEvent is StreamsAvailableNotify
  fun ref apply(data: StreamsAvailableData) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_streams_available_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_streams_available_event(ctx, 0)

trait PeerNeedsStreamsNotify is PayloadNotify[Bool]
  fun ref apply(data: Bool) => None
  fun box hash(): USize =>
    QUICHashspace() + 9

primitive PeerNeedsStreamsEvent is PeerNeedsStreamsNotify
  fun ref apply(data: Bool) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_peer_needs_streams_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_peer_needs_streams_event(ctx, 0)


trait IdealProcessorChangedNotify is PayloadNotify[U16]
  fun ref apply(data: U16) => None
  fun box hash(): USize =>
    QUICHashspace() + 10

primitive IdealProcessorChangedEvent is PeerNeedsStreamsNotify
  fun ref apply(data: U16) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_ideal_processor_changed_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_ideal_processor_changed_event(ctx, 0)

trait DatagramStateChangedNotify is PayloadNotify[DatagramStateChangedData val]
  fun ref apply(data: DatagramStateChangedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 11

primitive DatagramStateChangedEvent is DatagramStateChangedNotify
  fun ref apply(data: DatagramStateChanged) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_state_changed_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_state_changed_event(ctx, 0)

trait DatagramReceivedNotify is PayloadNotify[DatagramReceivedData val]
  fun ref apply(data: DatagramReceivedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 12

primitive DatagramReceivedEvent is DatagramReceivedNotify
  fun ref apply(data: DatagramReceived) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_received_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_received_event(ctx, 0)

trait DatagramSendStateChangedNotify is PayloadNotify[DatagramSendStateChangedData val]
  fun ref apply(data: DatagramSendStateChangedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 13

primitive DatagramSendStateChangedEvent is DatagramSendStateChangedNotify
  fun ref apply(data: DatagramSendStateChangedDatal) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_send_state_changed_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_send_state_changed_event(ctx, 0)

trait ResumedNotify is PayloadNotify[ResumedData val]
  fun ref apply(data: ResumedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 14

primitive ResumedEvent is ResumedNotify
  fun ref apply(data: ResumedData) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_resumed_changed_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_resumed_changed_event(ctx, 0)

trait ResumptionTicketReceivedNotify is PayloadNotify[Array[U8] val]
  fun ref apply(data: Array[U8] val) => None
  fun box hash(): USize =>
    QUICHashspace() + 15

primitive ResumptionTicketReceivedEvent is ResumptionTicketReceivedNotify
  fun ref apply(data: Array[U8] val) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_resumption_ticket_received_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_resumption_ticket_received_event(ctx, 0)

trait PeerCertificateReceivedNotify is PayloadNotify[QUICCertificate]
  fun ref apply(data: QUICCertificate) => None
  fun box hash(): USize =>
    QUICHashspace() + 16

primitive PeerCertificateReceivedEvent is PeerCertificateReceivedNotify
  fun ref apply(data: Array[U8] val) => None
  fun ref _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_peer_certificate_received_event(ctx, 1)
  fun ref _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_peer_certificate_received_event(ctx, 0)

trait StartCompleteNotify is PayloadNotify[StartCompleteData]
  fun ref apply(data: StartCompleteData) => None
  fun box hash(): USize =>
    QUICHashspace() + 17

primitive StartCompleteEvent is StartCompleteNotify
  fun ref apply(data: Array[U8] val) => None

trait SendCompleteNotify is PayloadNotify[SendCompleteData]
  fun ref apply(data: SendCompleteData) => None
  fun box hash(): USize =>
    QUICHashspace() + 18

primitive SendCompleteEvent is SendCompleteNotify
  fun ref apply(data: Array[U8] val) => None

trait PeerSendAbortedNotify is PayloadNotify[Exception]
  fun ref apply(data: Exception) => None
  fun box hash(): USize =>
    QUICHashspace() + 19

primitive PeerSendAbortedEvent is PeerSendAbortedNotify
  fun ref apply(data: Array[U8] val) => None

trait SendShutdownCompleteNotify is PayloadNotify[Bool]
  fun ref apply(data: Bool) => None
  fun box hash(): USize =>
    QUICHashspace() + 20

primitive SendShutdownCompleteEvent is SendShutdownCompleteNotify
  fun ref apply(data: Array[U8] val) => None

trait ShutdownCompleteNotify is PayloadNotify[Bool]
  fun ref apply(data: Bool) => None
  fun box hash(): USize =>
    QUICHashspace() + 21

primitive ShutdownCompleteEvent is SendShutdownCompleteNotify
  fun ref apply(data: Bool) => None

trait IdealSendBufferSizeNotify is PayloadNotify[U64]
  fun ref apply(data: U64) => None
  fun box hash(): USize =>
    QUICHashspace() + 22

primitive IdealSendBufferSizeEvent is IdealSendBufferSizeNotify
  fun ref apply(data: U64) => None
