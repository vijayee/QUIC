primitive QuicStatusSuccess
  fun string(): String => "Quic Status Succes"
primitive QuicStatusPending
  fun string(): String => "Quic Status Pending"
primitive QuicStatusContinue
  fun string(): String => "Quic Status Continue"
primitive QuicStatusOutOfMemory
  fun string(): String => "Quic Status Out Of Memory"
primitive QuicStatusInvalidParameter
  fun string(): String => "Quic Status Invalid Parameter"
primitive QuicStatusInvalidState
  fun string(): String => "Quic Status Invalid State"
primitive QuicStatusNotSupported
  fun string(): String => "Quic Status Not Supported"
primitive QuicStatusNotFound
  fun string(): String => "Quic Status Not Found"
primitive QuicStatusBufferTooSmall
  fun string(): String => "Quic Status Buffer Too Small"
primitive QuicStatusHandshakeFailure
  fun string(): String => "Quic Status Handshake Failure"
primitive QuicStatusAborted
  fun string(): String => "Quic Status Aborted"
primitive QuicStatusAddressInUse
  fun string(): String => "Quic Status Address In Use"
primitive QuicStatusInvalidAddress
  fun string(): String => "Quic Status Invalid Address"
primitive QuicStatusConnectionTimeout
  fun string(): String => "Quic Status Connection Timeout"
primitive QuicStatusConnectionIdle
  fun string(): String => "Quic Status Connection Idle"
primitive QuicStatusInternalError
  fun string(): String => "Quic Status Internal Error"
primitive QuicStatusConnectionRefused
  fun string(): String => "Quic Status Connection Refused"
primitive QuicStatusProtocolError
  fun string(): String => "Quic Status Protocol Error"
primitive QuicStatusVerNegError
  fun string(): String => "Quic Status Ver Neg Error"
primitive QuicStatusUnreachable
  fun string(): String => "Quic Status Unreachable"
primitive QuicStatusTLSError
  fun string(): String => "Quic Status TLS Error"
primitive QuicStatusUserCanceled
  fun string(): String => "Quic Status User Canceled"
primitive QuicStatusALPNNegFailure
  fun string(): String => "Quic Status ALPN Neg Failure"
primitive QuicStatusStreamLimitReached
  fun string(): String => "Quic Status Stream Limit Reached"
primitive QuicStatusALPNInUse
  fun string(): String => "Quic Status ALPN In Use"
primitive QuicStatusAddressNotAvailable
  fun string(): String => "Quic Status Address Not Available"
primitive QuicStatusTLSAlert
  fun string(): String => "Quic Status TLS Alert"
primitive QuicStatusCloseNotify
  fun string(): String => "Quic Status Close Notify"
primitive QuicStatusBadCertificate
  fun string(): String => "Quic Status Bad Certificate"
primitive QuicStatusUnsupportedCertificate
  fun string(): String => "Quic Status Unsupported Certificate"
primitive QuicStatusRevokedCertificate
  fun string(): String => "Quic Status Revoked Certificate"
primitive QuicStatusExpiredCertificate
  fun string(): String => "Quic Status Expired Certificate"
primitive QuicStatusUnknownCertificate
  fun string(): String => "Quic Status Unknown Certificate"
primitive QuicStatusRequiredCertificate
  fun string(): String => "Quic Status Required Certificate"
primitive QuicStatusCertExpired
  fun string(): String => "Quic Status Cert Expired"
primitive QuicStatusCertUntrustedRoot
  fun string(): String => "Quic Status Cert Untrusted Root"
primitive QuicStatusCertNoCert
  fun string(): String => "Quic Status Cert No Cert"

type QUICStatus is (QuicStatusSuccess | QuicStatusPending | QuicStatusContinue |
  QuicStatusOutOfMemory | QuicStatusInvalidParameter | QuicStatusInvalidState | QuicStatusNotSupported |
  QuicStatusNotFound | QuicStatusBufferTooSmall | QuicStatusStreamLimitReached | QuicStatusALPNInUse |
  QuicStatusHandshakeFailure | QuicStatusAborted | QuicStatusAddressInUse | QuicStatusInvalidAddress |
  QuicStatusConnectionTimeout | QuicStatusConnectionIdle | QuicStatusInternalError | QuicStatusConnectionRefused |
  QuicStatusProtocolError | QuicStatusVerNegError | QuicStatusUnreachable | QuicStatusTLSError | QuicStatusUserCanceled |
  QuicStatusALPNNegFailure | QuicStatusAddressNotAvailable | QuicStatusTLSAlert | QuicStatusCloseNotify |
  QuicStatusBadCertificate | QuicStatusUnsupportedCertificate | QuicStatusRevokedCertificate | QuicStatusExpiredCertificate |
  QuicStatusUnknownCertificate | QuicStatusRequiredCertificate | QuicStatusCertExpired | QuicStatusCertUntrustedRoot | QuicStatusCertNoCert)

primitive QUICStatusFromCode
  fun apply(code: U64): (QUICStatus | None) =>
    match code
      | 0 => QuicStatusSuccess
      | -2 => QuicStatusPending
      | -1 => QuicStatusContinue
      | 12 => QuicStatusOutOfMemory
      | 22 => QuicStatusInvalidParameter
      | 1 => QuicStatusInvalidState
      | 95 => QuicStatusNotSupported
      | 2 =>  QuicStatusNotFound
      | 75 =>  QuicStatusBufferTooSmall
      | 103 => QuicStatusHandshakeFailure
      | 125 => QuicStatusAborted
      | 98 => QuicStatusAddressInUse
      | 97 => QuicStatusInvalidAddress
      | 110 => QuicStatusConnectionTimeout
      | 62 => QuicStatusConnectionIdle
      | 5 => QuicStatusInternalError
      | 111 => QuicStatusConnectionRefused
      | 71 => QuicStatusProtocolError
      | 93 => QuicStatusVerNegError
      | 113 => QuicStatusUnreachable
      | 126 => QuicStatusTLSError
      | 130 => QuicStatusUserCanceled
      | 91 => QuicStatusALPNNegFailure
      | 86 => QuicStatusStreamLimitReached
      | 91 => QuicStatusALPNInUse
      | 99 => QuicStatusAddressNotAvailable
      | 0xBEBC300 => QuicStatusCloseNotify
      | 0xBEBC32A => QuicStatusBadCertificate
      | 0xBEBC32B => QuicStatusRevokedCertificate
      | 0xBEBC32C => QuicStatusExpiredCertificate
      | 0xBEBC32D => QuicStatusExpiredCertificate
      | 0xBEBC32E => QuicStatusUnknownCertificate
      | 0xBEBC374 => QuicStatusRequiredCertificate
      | 0xBEBC401 => QuicStatusCertExpired
      | 0xBEBC402 => QuicStatusCertUntrustedRoot
      | 0xBEBC403 => QuicStatusCertNoCert
    end
