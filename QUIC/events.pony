use "Streams"
use "Exception"

primitive QUICHashspace
  fun apply(): USize => 20000
//Connection Events
trait ConnectedNotify is PayloadNotify[ConnectedData val]
  fun ref apply(data: ConnectedData val)
  fun box hash(): USize =>
    QUICHashspace() + 1

primitive ConnectedEvent is ConnectedNotify
  fun ref apply(data: ConnectedData val) => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_connected_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_connected_event(ctx, 0)

trait ShutdownInitiatedByTransportNotify is PayloadNotify[ShutdownInitiatedByTransportData val]
  fun ref apply(data: ShutdownInitiatedByTransportData)
  fun box hash(): USize =>
    QUICHashspace() + 2

primitive ShutdownInitiatedByTransportEvent is ShutdownInitiatedByTransportNotify
  fun ref apply(data: ShutdownInitiatedByTransportData) => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_shutdown_initiated_by_transport_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_shutdown_initiated_by_transport_event(ctx, 0)

trait ShutdownInitiatedByPeerNotify is PayloadNotify[U64]
  fun ref apply(data: U64)
  fun box hash(): USize =>
    QUICHashspace() + 3

primitive ShutdownInitiatedByPeerEvent is ShutdownInitiatedByPeerNotify
  fun ref apply(data: U64) => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_shutdown_initiated_by_peer_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_shutdown_initiated_by_peer_event(ctx, 0)

trait ShutdownCompleteNotify is PayloadNotify[ShutdownCompleteData val]
  fun ref apply(data: ShutdownCompleteData)
  fun box hash(): USize =>
    QUICHashspace() + 4

primitive ShutdownCompleteEvent is ShutdownCompleteNotify
  fun ref apply(data: ShutdownCompleteData) => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_shutdown_complete_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_shutdown_complete_event(ctx, 0)

trait LocalAddressChangedNotify is PayloadNotify[QUICAddress val]
  fun ref apply(data: QUICAddress val)
  fun box hash(): USize =>
    QUICHashspace() + 5

primitive LocalAddressChangedEvent is LocalAddressChangedNotify
  fun ref apply(data: QUICAddress val) => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_local_address_changed_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_local_address_changed_event(ctx, 0)

trait PeerAddressChangedNotify is PayloadNotify[QUICAddress val]
  fun ref apply(data: QUICAddress val) => None
  fun box hash(): USize =>
    QUICHashspace() + 6

primitive PeerAddressChangedEvent is PeerAddressChangedNotify
  fun ref apply(data: QUICAddress val) => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_peer_address_changed_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_peer_address_changed_event(ctx, 0)

trait PeerStreamStartedNotify is PayloadNotify[QUICStream]
  fun ref apply(data: QUICStream) => None
  fun box hash(): USize =>
    QUICHashspace() + 7

primitive PeerStreamStartedEvent is PeerStreamStartedNotify
  fun ref apply(data: QUICStream) => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_peer_stream_started_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_peer_stream_started_event(ctx, 0)

trait StreamsAvailableNotify is PayloadNotify[StreamsAvailableData val]
  fun ref apply(data: StreamsAvailableData) => None
  fun box hash(): USize =>
    QUICHashspace() + 8

primitive StreamsAvailableEvent is StreamsAvailableNotify
  fun ref apply(data: StreamsAvailableData) => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_streams_available_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_streams_available_event(ctx, 0)

trait PeerNeedsStreamsNotify is PayloadNotify[Bool]
  fun ref apply(data: Bool) => None
  fun box hash(): USize =>
    QUICHashspace() + 9

primitive PeerNeedsStreamsEvent is PeerNeedsStreamsNotify
  fun ref apply(data: Bool) => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_peer_needs_streams_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_peer_needs_streams_event(ctx, 0)


trait IdealProcessorChangedNotify is PayloadNotify[U16]
  fun ref apply(data: U16) => None
  fun box hash(): USize =>
    QUICHashspace() + 10

primitive IdealProcessorChangedEvent is IdealProcessorChangedNotify
  fun ref apply(data: U16) => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_ideal_processor_changed_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_ideal_processor_changed_event(ctx, 0)

trait DatagramStateChangedNotify is PayloadNotify[DatagramStateChangedData val]
  fun ref apply(data: DatagramStateChangedData val) => None
  fun box hash(): USize =>
    QUICHashspace() + 11

primitive DatagramStateChangedEvent is DatagramStateChangedNotify
  fun ref apply(data: DatagramStateChangedData val) => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_state_changed_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_state_changed_event(ctx, 0)

trait DatagramReceivedNotify is PayloadNotify[DatagramReceivedData val]
  fun ref apply(data: DatagramReceivedData val) => None
  fun box hash(): USize =>
    QUICHashspace() + 12

primitive DatagramReceivedEvent is DatagramReceivedNotify
  fun ref apply(data: DatagramReceivedData val) => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_received_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_received_event(ctx, 0)

trait DatagramSendStateChangedNotify is PayloadNotify[QUICDatagramSendState]
  fun ref apply(data: QUICDatagramSendState) => None
  fun box hash(): USize =>
    QUICHashspace() + 13

primitive DatagramSendStateChangedEvent is DatagramSendStateChangedNotify
  fun ref apply(data: QUICDatagramSendState) => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_send_state_changed_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_send_state_changed_event(ctx, 0)

trait ResumedNotify is PayloadNotify[ResumedData val]
  fun ref apply(data: ResumedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 14

primitive ResumedEvent is ResumedNotify
  fun ref apply(data: ResumedData) => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_resumed_changed_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_resumed_changed_event(ctx, 0)

trait ResumptionTicketReceivedNotify is PayloadNotify[ResumptionTicketReceivedData]
  fun ref apply(data: ResumptionTicketReceivedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 15

primitive ResumptionTicketReceivedEvent is ResumptionTicketReceivedNotify
  fun ref apply(data: ResumptionTicketReceivedData) => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_resumption_ticket_received_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_resumption_ticket_received_event(ctx, 0)

trait PeerCertificateReceivedNotify is VoidNotify
  fun ref apply()
  fun box hash(): USize =>
    QUICHashspace() + 16

primitive PeerCertificateReceivedEvent is PeerCertificateReceivedNotify
  fun ref apply() => None
  fun _enable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_peer_certificate_received_event(ctx, 1)
  fun _disable(ctx: Pointer[None] tag) =>
    @quic_connection_set_datagram_peer_certificate_received_event(ctx, 0)

//Stream Events
trait StreamStartCompleteNotify is PayloadNotify[StreamStartCompleteData]
  fun ref apply(data: StreamStartCompleteData) => None
  fun box hash(): USize =>
    QUICHashspace() + 17

primitive StreamStartCompleteEvent is StreamStartCompleteNotify
  fun ref apply(data: StreamStartCompleteData) => None

trait SendCompleteNotify is PayloadNotify[SendCompleteData]
  fun ref apply(data: SendCompleteData) => None
  fun box hash(): USize =>
    QUICHashspace() + 18

primitive SendCompleteEvent is SendCompleteNotify
  fun ref apply(data: SendCompleteData) => None

trait PeerSendShutdownNotify is VoidNotify
  fun ref apply() => None
  fun box hash(): USize =>
    QUICHashspace() + 19

primitive PeerSendShutdownEvent is PeerSendShutdownNotify
  fun ref apply() => None

trait PeerSendAbortedNotify is PayloadNotify[PeerSendAbortedData]
  fun ref apply(data: PeerSendAbortedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 20

primitive PeerSendAbortedEvent is PeerSendAbortedNotify
  fun ref apply(data: PeerSendAbortedData) => None

trait PeerReceiveAbortedNotify is PayloadNotify[PeerReceiveAbortedData]
  fun ref apply(data: PeerReceiveAbortedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 21

primitive PeerReceiveAbortedEvent is PeerReceiveAbortedNotify
  fun ref apply(data: PeerReceiveAbortedData) => None


trait SendShutdownCompleteNotify is PayloadNotify[SendShutdownCompleteData]
  fun ref apply(data: SendShutdownCompleteData) => None
  fun box hash(): USize =>
    QUICHashspace() + 22

primitive SendShutdownCompleteEvent is SendShutdownCompleteNotify
  fun ref apply(data: SendShutdownCompleteData) => None

trait StreamShutdownCompleteNotify is PayloadNotify[StreamShutdownCompleteData]
  fun ref apply(data: StreamShutdownCompleteData) => None
  fun box hash(): USize =>
    QUICHashspace() + 23

primitive StreamShutdownCompleteEvent is StreamShutdownCompleteNotify
  fun ref apply(data: StreamShutdownCompleteData) => None

trait IdealSendBufferSizeNotify is PayloadNotify[IdealSendBufferSizeData]
  fun ref apply(data: IdealSendBufferSizeData) => None
  fun box hash(): USize =>
    QUICHashspace() + 24

primitive IdealSendBufferSizeEvent is IdealSendBufferSizeNotify
  fun ref apply(data: IdealSendBufferSizeData) => None

trait PeerAcceptedNotify is VoidNotify
  fun ref apply() => None
  fun box hash(): USize =>
    QUICHashspace() + 25

primitive PeerAcceptedEvent is PeerAcceptedNotify
  fun ref apply() => None

trait ListenerStartedNotify is VoidNotify
  fun ref apply() => None
  fun box hash(): USize =>
    QUICHashspace() + 26

primitive ListenerStartedEvent is ListenerStartedNotify
  fun ref apply() => None

trait ListenerStoppedNotify is VoidNotify
  fun ref apply() => None
  fun box hash(): USize =>
    QUICHashspace() + 27

primitive ListenerStoppedEvent is ListenerStoppedNotify
  fun ref apply() => None
