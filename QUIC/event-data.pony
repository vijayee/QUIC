use @quic_free[None](ptr: Pointer[None] tag)
class ConnectedData
  let sessionResumed: Bool
  let negotiatedAlpn: Array[U8]
  new val create(sessionResumed': Bool, negotiatedAlpn': Array[U8] val) =>
    sessionResumed = sessionResumed'
    negotiatedAlpn = negotiatedAlpn;

struct ShutdownInitiatedByTransportData
  var status: U32
  var errorCode: U64

struct ShutdowCompleteData
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
  let bidirectionalCount: U16 = 0
  let unidirectionalCount: U16 = 0
