use @quic_free[None](ptr: Pointer[None] tag)
class ConnectedData
  let sessionResumed: Bool
  let negotiatedAlpn: Array[U8]
  new val create(sessionResumed': Bool, negotiatedAlpn': Array[U8] val) =>
    sessionResumed = sessionResumed'
    negotiatedAlpn = negotiatedAlpn'

struct ShutdownInitiatedByTransportData
  var status: U32
  var errorCode: U64

struct ShutdownCompleteData
  var handshakeCompleted: Bool = false
  var peerAcknowledgedShutdown: Bool = false
  var appCloseInProgress: Bool = false

class QUICAddress
  let address: Pointer[None] tag
  new create(address': Pointer[None] tag) =>
    address = address'
  fun _final() =>
    @quic_free(address)

struct StreamsAvailableData
  var bidirectionalCount: U16 = 0
  var unidirectionalCount: U16 = 0

struct DatagramStateChangedData
  var sendEnabled: U8 = 0
  var maxSendLength: U16 = 0

primitive Unknown
primitive Sent
primitive LostSuspect
primitive LostDiscarded
primitive Acknowledged
primitive AcknowledgedSpurious
primitive Canceled

type QUICDatagramSendState is (Unknown | Sent | LostSuspect | LostDiscarded | Acknowledged | AcknowledgedSpurious | Canceled)

primitive ZeroRTT
  fun apply(): U32 =>
    0x0001

primitive FIN
  fun apply(): U32 =>
    0x0002

type QUICReceiveFlags is (None | ZeroRTT | FIN)

class DatagramReceivedData
  let flags : Array[QUICReceiveFlags] val
  let buffer: Array[U8] val
  new val create(flags': Array[QUICReceiveFlags] val, buffer': Array[U8] val) =>
    flags= flags'
    buffer= buffer'

class ResumedData
  var resumptionState: Array[U8] val
  new val create(resumptionState': Array[U8] val) =>
    resumptionState = resumptionsState'

class ResumptionTicketReceivedData
  let resumptionTicket: Array[U8] val
  new val create(resumptionTicket': Array[U8] val) =>
    resumptionTicket = resumptionTicket'

struct QUICBuffer
  var length: U32 = 0
  var buffer: Pointer[U8] tag = Pointer[U8]
  new create(length': U32, buffer': Pointer[U8] tag) =>
    length = length'
    buffer = buffer'
