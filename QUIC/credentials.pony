use @quic_certificate_file[Pointer[None] tag](privateKeyFile: Pointer[U8] tag, certificateFile: Pointer[U8] tag)
use @quic_certificate_file_protected[Pointer[None] tag](certificateFile: Pointer[U8] tag, privateKeyFile: Pointer[U8] tag, privateKeyPassword: Pointer[U8] tag)
use @quic_certificate_pkcs12[Pointer[None]](Asn1Blob: Pointer[U8] tag, Asn1BlobLength: U32, privateKeyPassword: Pointer[U8] tag)
use @quic_new_credential_config[Pointer[None] tag](credType: I32, flags: U64, cert: Pointer[None] tag, allowedCiphers: U8, caCertificateFile: Pointer[U8] tag)

primitive QUICServer
  fun apply(): U64 => 0x00000000
primitive QUICClient
  fun apply(): U64 => 0x00000001
primitive NoCertificateValidation
  fun apply(): U64 => 0x00000004
primitive EnableOCSP
  fun apply(): U64 => 0x00000008
primitive IndicateCertificateReceived
  fun apply(): U64 => 0x00000010
primitive DeferCertificateValidation
  fun apply(): U64 => 0x00000010
primitive RequireClientAuthentication
  fun apply(): U64 => 0x00000040
primitive UseTLSBuiltInCertificateValidation
  fun apply(): U64 => 0x00000080
primitive RevocationCheckChain
  fun apply(): U64 => 0x00000200
primitive RevocationCheckEndCert
  fun apply(): U64 => 0x00000100
primitive RevocationCheckChainExcludeRoot
  fun apply(): U64 => 0x00000400
primitive IgnoreNoRevocationCheck
  fun apply(): U64 => 0x00000800
primitive IgnoreRevocationOffline
  fun apply(): U64 => 0x00001000
primitive AllowedCipherSuites
  fun apply(): U64 => 0x00002000
primitive UsePortableCertificates
  fun apply(): U64 => 0x00004000
primitive SetCACertificateFile
  fun apply(): U64 => 0x00100000

type QUICCredentialFlag is  (QUICServer
| QUICClient
| NoCertificateValidation
| EnableOCSP
| IndicateCertificateReceived
| DeferCertificateValidation
| RequireClientAuthentication
| UseTLSBuiltInCertificateValidation
| RevocationCheckChain
| RevocationCheckEndCert
| RevocationCheckChainExcludeRoot
| IgnoreNoRevocationCheck
| IgnoreRevocationOffline
| AllowedCipherSuites
| UsePortableCertificates
| SetCACertificateFile)

type QUICCredentialFlags is Array[QUICCredentialFlag]

primitive CipherSuiteNone
  fun apply(): U8 => 0x0
primitive SuiteAES128GCMSHA256
  fun apply(): U8 => 0x1
primitive SuiteAES256GCMSHA384
  fun apply(): U8 => 0x2
primitive ChaCha20Poly1305SHA256
  fun apply(): U8 => 0x4

type QUICAllowedCipherSuiteFlag is (CipherSuiteNone
| SuiteAES128GCMSHA256
| SuiteAES256GCMSHA384
| ChaCha20Poly1305SHA256)

type QUICAllowedCipherSuiteFlags is Array[QUICAllowedCipherSuiteFlag]

class val QUICCredential
  let cred: Pointer[None] tag
  let certificate: QUICCertificate
  new create(certificate': QUICCertificate, flags': QUICCredentialFlags = [], allowedCipherSuiteFlags: QUICAllowedCipherSuiteFlags = [], caCertificateFile: (String | None) = None ) =>
    certificate = certificate'
    var flags: U64 = 0
    for flag in flags'.values() do
      flags = flags or flag()
    end
    var ciphers: U8 = 0
    for cipher in allowedCipherSuiteFlags.values() do
      ciphers = ciphers or cipher()
    end
    cred = @quic_new_credential_config(certificate.credType, flags, certificate.cert, ciphers,
      match caCertificateFile
        | let caCertificateFile': String =>
          caCertificateFile'.cstring()
        | None =>
          Pointer[U8].create()
      end)
  fun _final() =>
    @quic_free(cred)

class val QUICCertificate
  let cert: Pointer[None] tag
  let credType: I32
  new create(certificateFile: String, privateKeyFile: String, password: (String | None) = None) =>
    match password
    | None =>
      cert = @quic_certificate_file(certificateFile.cstring(), privateKeyFile.cstring())
      credType = 4
    | let password': String =>
      cert = @quic_certificate_file_protected(certificateFile.cstring(), privateKeyFile.cstring(), password'.cstring())
      credType = 5
    end

  new pkcs12(blob: Array[U8] val, password: (String | None) = None) =>
    cert = match password
    | None => @quic_certificate_pkcs12(blob.cpointer(), blob.size().u32(), Pointer[U8].create())
    | let password': String =>
        @quic_certificate_pkcs12(blob.cpointer(), blob.size().u32(), password'.cstring())
    end
    credType = 6

  fun _final() =>
    @quic_free(cert)
