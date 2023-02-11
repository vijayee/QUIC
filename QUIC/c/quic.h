#include <msquic.h>

static QUIC_API_TABLE* MSQuic;
static size_t registration_count;
// Create a new registration object
// also initialize the apitable if it is uninitialized
HQUIC* quic_new_registration(QUIC_REGISTRATION_CONFIG* config);
void quic_free_registration(HQUIC* registration);
QUIC_REGISTRATION_CONFIG* quic_new_registration_config(const char* appName, int32_t executionProfile);
QUIC_CERTIFICATE_FILE*  quic_certificate_file(const char* privateKeyFile, const char* certificateFile);
QUIC_CERTIFICATE_FILE_PROTECTED* quic_certificate_file_protected(const char* certificateFile, const char* privateKeyFile, const char* privateKeyPassword);
QUIC_CERTIFICATE_PKCS12* quic_certificate_pkcs12(const uint8_t *Asn1Blob, uint32_t Asn1BlobLength, const char* privateKeyPassword);
void quic_free_certificate_file(QUIC_CERTIFICATE_FILE* cert);
void quic_free(void* ptr);
QUIC_CREDENTIAL_CONFIG* quic_new_credential_config(int32_t credType, uint64_t flags, void * cert, uint8_t allowedCiphers, const char* caCertificateFile);
QUIC_SETTINGS* quic_new_settings(uint64_t* maxBytesPerKey,
    uint64_t* handshakeIdleTimeoutMs,
    uint64_t* idleTimeoutMs,
    uint64_t* mtuDiscoverySearchCompleteTimeoutUs,
    uint32_t* tlsClientMaxSendBuffer,
    uint32_t* tlsServerMaxSendBuffer,
    uint32_t* streamRecvWindowDefault,
    uint32_t* streamRecvBufferDefault,
    uint32_t* connFlowControlWindow,
    uint32_t* maxWorkerQueueDelayUs,
    uint32_t* maxStatelessOperations,
    uint32_t* initialWindowPackets,
    uint32_t* sendIdleTimeoutMs,
    uint32_t* initialRttMs,
    uint32_t* maxAckDelayMs,
    uint32_t* disconnectTimeoutMs,
    uint32_t* keepAliveIntervalMs,
    uint16_t* congestionControlAlgorithm,
    uint16_t* peerBidiStreamCount,
    uint16_t* peerUnidiStreamCount,
    uint16_t* maxBindingStatelessOperations,
    uint16_t* dtatelessOperationExpirationMs,
    uint16_t* minimumMtu,
    uint16_t* maximumMtu,
    uint8_t* sendBufferingEnabled,
    uint8_t* pacingEnabled,
    uint8_t* migrationEnabled,
    uint8_t* datagramReceiveEnabled,
    uint8_t* serverResumptionLevel,
    uint8_t* greaseQuicBitEnabled,
    uint8_t* ecnEnabled,
    uint8_t* maxOperationsPerDrain,
    uint8_t* mtuDiscoveryMissingProbeCount,
    uint32_t* destCidUpdateIdleTimeoutMs);
HQUIC* quic_new_configuration(HQUIC* registration, char** alpn, alpnSize: uint32_t, QUIC_SETTINGS* settings);
void quic_configuration_load_credential(HQUIC* configuration, QUIC_CREDENTIAL_CONFIG* credentials);

struct pony_callback
{
  void(*sender)();
  void* receiver;
};

void* quic_retrieve_actor(HQUIC* self);
void quic_pony_dispatcher_init();
