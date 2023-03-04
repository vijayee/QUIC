use "Streams"
use "Exception"
primitive QUICHashspace
  fun apply(): USize => 20000

trait ConnectedNotify is PayloadNotify[ConnectedData val]
  fun ref apply(data: ConnectedData)
  fun box hash(): USize =>
    QUICHashspace() + 1

primitive ConnectedEvent is ConnectedNotify
  fun ref apply(data: ConnectedData) => None

trait ShutdownInitiatedByTransportNotify is PayloadNotify[ShutdownInitiatedByTransportData val]
  fun ref apply(data: ShutdownInitiatedByTransportData)
  fun box hash(): USize =>
    QUICHashspace() + 2

primitive ShutdownInitiatedByTransportEvent is ShutdownInitiatedByTransportNotify
  fun ref apply(data: ConnectedData) => None

trait ShutdownInitiatedByPeerNotify is PayloadNotify[Exception]
  fun ref apply(data: Exception)
  fun box hash(): USize =>
    QUICHashspace() + 3

primitive ShutdownInitiatedByPeerEvent is ShutdownInitiatedByPeerNotify
  fun ref apply(data: Exception) => None

trait ShutdownCompleteNotify is PayloadNotify[ShutdownCompleteData val]
  fun ref apply(data: ShutdownCompleteData)
  fun box hash(): USize =>
    QUICHashspace() + 4

primitive ShutdownCompleteEvent is ShutdownCompleteNotify
  fun ref apply(data: ShutdownCompleteData) => None

trait LocalAddressChangedNotify is ParyloadNotify[QUICAdressInfo val]
  fun ref apply(data: QUICAdressInfo)
  fun box hash(): USize =>
    QUICHashspace() + 5

primitive LocalAddressChangedEvent is LocalAddressChangedNotify
  fun ref apply(data: QUICAdressInfo) => None

trait PeerAddressChangedNotify is PayloadNotify[QUICAdressInfo val]
  fun ref apply(data: QUICAdressInfo) => None
  fun box hash(): USize =>
    QUICHashspace() + 6

primitive PeerAddressChangedEvent is PeerAddressChangedNotify
  fun ref apply(data: QUICAdressInfo) => None

trait PeerStreamStartedNotify is PayloadNotify[PeerStreamStartedData val]
  fun ref apply(data: PeerStreamStartedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 7

primitive PeerStreamStartedEvent is PeerStreamStartedNotify
  fun ref apply(data: PeerStreamStartedData) => None

trait StreamsAvailableNotify is PayloadNotify[StreamsAvailableData val]
  fun ref apply(data: PeerStreamStartedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 8

primitive StreamsAvailableEvent is StreamsAvailableNotify
  fun ref apply(data: StreamsAvailableData) => None

trait PeerNeedsStreamsNotify is PayloadNotify[Bool]
  fun ref apply(data: Bool) => None
  fun box hash(): USize =>
    QUICHashspace() + 9

primitive PeerNeedsStreamsEvent is PeerNeedsStreamsNotify
  fun ref apply(data: Bool) => None

trait IdealProcessorChangedNotify is PayloadNotify[U16]
  fun ref apply(data: PeerStreamStartedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 10

trait DatagramStateChangedNotify is PayloadNotify[DatagramStateChangedData val]
  fun ref apply(data: DatagramStateChangedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 11

primitive DatagramStateChangedEvent is DatagramStateChangedNotify
  fun ref apply(data: DatagramStateChanged) => None

trait DatagramReceivedNotify is PayloadNotify[DatagramReceivedData val]
  fun ref apply(data: DatagramReceivedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 12

primitive DatagramReceivedEvent is DatagramReceivedNotify
  fun ref apply(data: DatagramReceived) => None

trait DatagramSendStateChangedNotify is PayloadNotify[DatagramSendStateChangedData val]
  fun ref apply(data: DatagramSendStateChangedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 13

primitive DatagramSendStateChangedEvent is DatagramSendStateChangedNotify
  fun ref apply(data: DatagramSendStateChangedDatal) => None

trait ResumedNotify is PayloadNotify[ResumedData val]
  fun ref apply(data: ResumedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 14

primitive ResumedChangedEvent is ResumedNotify
  fun ref apply(data: ResumedData) => None

trait ResumptionTicketReceivedNotify is PayloadNotify[Array[U8] val]
  fun ref apply(data: ResumedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 15

primitive ResumptionTicketReceivedEvent is ResumptionTicketReceivedNotify
  fun ref apply(data: Array[U8] val) => None

trait ResumptionTicketReceivedNotify is PayloadNotify[Array[U8] val]
  fun ref apply(data: ResumedData) => None
  fun box hash(): USize =>
    QUICHashspace() + 15

primitive ResumptionTicketReceivedEvent is ResumptionTicketReceivedNotify
  fun ref apply(data: Array[U8] val) => None

trait PeerCertificateReceivedNotify is PayloadNotify[QUICCertificate]
  fun ref apply(data: QUICCertificate) => None
  fun box hash(): USize =>
    QUICHashspace() + 16

primitive PeerCertificateReceivedEvent is PeerCertificateReceivedNotify
  fun ref apply(data: Array[U8] val) => None

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
