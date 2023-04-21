
class val ConnectedData
  let sessionResumed: Bool
  let negotiatedAlpn: Array[U8] val
  new create(sessionResumed': Bool, negotiatedAlpn': Array[U8] val) =>
    sessionResumed = sessionResumed'
    negotiatedAlpn = negotiatedAlpn'

struct _ShutdownInitiatedByTransportData
  var status: U32 = 0
  var errorCode: U64 = 0

class val ShutdownInitiatedByTransportData
  let status: U32
  let errorCode: U64
  new create(status': U32, errorCode': U64) =>
    status = status'
    errorCode = errorCode'

struct _ShutdownCompleteData
  var handshakeCompleted: Bool = false
  var peerAcknowledgedShutdown: Bool = false
  var appCloseInProgress: Bool = false

class val ShutdownCompleteData
  let handshakeCompleted: Bool
  let peerAcknowledgedShutdown: Bool
  let appCloseInProgress: Bool
  new create(handshakeCompleted': Bool, peerAcknowledgedShutdown': Bool, appCloseInProgress': Bool) =>
    handshakeCompleted = handshakeCompleted'
    peerAcknowledgedShutdown = peerAcknowledgedShutdown'
    appCloseInProgress = appCloseInProgress'

class QUICAddress
  let address: Pointer[None] tag
  new create(address': Pointer[None] tag) =>
    address = address'
  fun _final() =>
    @quic_free(address)

struct _StreamsAvailableData
  var bidirectionalCount: U16 = 0
  var unidirectionalCount: U16 = 0

class val StreamsAvailableData
  let bidirectionalCount: U16
  let unidirectionalCount: U16
  new create(bidirectionalCount': U16, unidirectionalCount': U16) =>
    bidirectionalCount = bidirectionalCount'
    unidirectionalCount = unidirectionalCount'

struct _DatagramStateChangedData
  var sendEnabled: U8 = 0
  var maxSendLength: U16 = 0

class val DatagramStateChangedData
  let sendEnabled: Bool
  let maxSendLength: USize
  new create(sendEnabled': Bool, maxSendLength': USize) =>
    sendEnabled = sendEnabled'
    maxSendLength = maxSendLength'

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
    flags = flags'
    buffer = buffer'

class val ResumedData
  var resumptionState: Array[U8] val
  new create(resumptionState': Array[U8] val) =>
    resumptionState = resumptionState'

class val ResumptionTicketReceivedData
  let resumptionTicket: Array[U8] val
  new create(resumptionTicket': Array[U8] val) =>
    resumptionTicket = resumptionTicket'

struct QUICBuffer
  var length: U32 = 0
  var buffer: Pointer[U8] tag = Pointer[U8]
  new create(length': U32, buffer': Pointer[U8] tag) =>
    length = length'
    buffer = buffer'

struct _StreamStartCompleteData
  var status: U32 = 0
  var id: U64 = 0
  var peerAccepted: U8 = 0

class val StreamStartCompleteData
  var status: U32
  var id: U64
  var peerAccepted: Bool
  new create(status': U32, id': U64, peerAccepted': Bool) =>
    status = status'
    id = id'
    peerAccepted = peerAccepted'

struct _StreamShutdownCompleteData
  var connectionShutdown: U8 = 0
  var appCloseInProgress: U8 = 0
  var connectionShutdownByApp: U8 = 0
  var connectionClosedRemotely: U8 = 0
  var connectionErrorCode: U64 = 0
  var connectionCloseStatus: U32 = 0

class val StreamShutdownCompleteData
  let connectionShutdown: Bool
  let appCloseInProgress: Bool
  let connectionShutdownByApp: Bool
  let connectionClosedRemotely: Bool
  let connectionErrorCode: U64
  let connectionCloseStatus: U32
  new create(connectionShutdown': Bool, appCloseInProgress': Bool, connectionShutdownByApp': Bool, connectionClosedRemotely': Bool, connectionErrorCode': U64, connectionCloseStatus': U32) =>
    connectionShutdown = connectionShutdown'
    appCloseInProgress = appCloseInProgress'
    connectionShutdownByApp = connectionShutdownByApp'
    connectionClosedRemotely = connectionClosedRemotely'
    connectionErrorCode = connectionErrorCode'
    connectionCloseStatus = connectionCloseStatus'

class val SendCompleteData
  let canceled: Bool
  new create(canceled': Bool) =>
    canceled = canceled'

class val SendShutdownCompleteData
  let graceful: Bool
  new create(graceful': Bool) =>
    graceful = graceful'

class val PeerSendAbortedData
  let errorCode: U64
  new create(errorCode': U64) =>
     errorCode =  errorCode'

class val PeerReceiveAbortedData
 let errorCode: U64
 new create(errorCode': U64) =>
    errorCode =  errorCode'

class val IdealSendBufferSizeData
  let byteCount: U64
  new create(byteCount': U64) =>
    byteCount = byteCount'
