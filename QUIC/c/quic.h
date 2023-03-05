#include <msquic.h>
#if __linux__
  #include <pthread.h>
#endif
#if _WIN32
  #include <windows.h>
#endif
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
void* quic_retrieve_actor(HQUIC* self);
void quic_pony_dispatcher_init();
uint8_t quic_is_new_connection_event(QUIC_LISTENER_EVENT* event);
HQUIC* quic_server_listener_open(HQUIC* registration, void* serverListenerCallback, quic_server_event_context* ctx);
void quic_server_listener_close(HQUIC* listener);
void quic_cache_set(void* key, void* value);
void* quic_cache_get(void* key);
void quic_cache_delete(void* key);
void* quic_server_actor(quic_server_event_context* ctx);
HQUIC* quic_server_configuration(quic_server_event_context* ctx);

typedef quic_cache_get quic_connection_actor;
typedef quic_cache_get quic_stream_actor;
HQUIC* quic_receive_connection(QUIC_LISTENER_EVENT* event);
void quic_connection_set_configuration(HQUIC* connection, HQUIC* configuration);
void quic_connection_set_callback(HQUIC* connection, void* connectionCallback);
uint8_t quic_get_connection_event_type_as_uint(QUIC_LISTENER_EVENT* event);
void quic_send_resumption_ticket(HQUIC* connection);
void quic_close_connection(HQUIC* connection);
HQUIC* quic_receive_stream(QUIC_CONNECTION_EVENT* event);
uint8_t quic_receive_stream_type(QUIC_CONNECTION_EVENT* event);
void quic_stream_set_callback(HQUIC* stream, void* streamCallback);
uint8_t quic_get_stream_event_type_as_uint(QUIC_STREAM_EVENT* event);
uint32_t quic_stream_status_pending();
uint64_t quic_stream_get_total_buffer_length(QUIC_STREAM_EVENT* event);
void quic_stream_get_total_buffer(QUIC_STREAM_EVENT* event, uint8_t* buffer, HQUIC* stream);

struct {
  void*  serverActor;
  HQUIC* configuration;
} quic_server_event_context;

quic_server_event_context* quic_new_server_event_context(void* serverActor, HQUIC* configuration);

struct {
  void* connectionActor;
  uint8_t QUIC_CONNECTION_EVENT_CONNECTED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_CONNECTED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_CONNECTED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE;
  #if __linux__
    pthread_mutex_t  QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_RESUMED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_RESUMED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_RESUMED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK;
  #endif
  uint8_t QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED;
  #if __linux__
    pthread_mutex_t QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK;
  #endif
  #if _WIN32
    CRITICAL_SECTION QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK;
  #endif
} quic_connection_event_context;

quic_connection_event_context* quic_new_connection_event_context();
void quic_connection_event_context_set_actor(quic_connection_event_context* ctx, void* connectionActor);

void quic_free_connection_event_context(quic_connection_event_context* ctx);

HQUIC* quic_connection_open(HQUIC* registration, void* callback);
void quic_connection_set_connected_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_shutdown_initiated_by_transport_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_shutdown_initiated_by_peer_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_shutdown_complete_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_local_address_changed_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_peer_address_changed_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_peer_stream_started_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_streams_available_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_peer_needs_streams_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_ideal_processor_changed_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_datagram_state_changed_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_datagram_received_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_datagram_send_state_changed_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_resumed_changed_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_datagram_resumption_ticket_received_event(quic_connection_event_context* ctx, uint8_t value);
void quic_connection_set_datagram_peer_certificate_received_event(quic_connection_event_context* ctx, uint8_t value);
