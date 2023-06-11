#include "quic.h"
#include <pony.h>
#include <string.h>
#include <stdio.h>
#if _WIN32
  #include <windows.h>
#else
  #include <pthread.h>
  #include <sys/socket.h>
  #include <netdb.h>
#endif
#include <msquic.h>





#if _WIN32
  void platform_lock(CRITICAL_SECTION lock) {
    EnterCriticalSection(&lock);
  }
  void platform_unlock(CRITICAL_SECTION lock) {
    LeaveCriticalSection(&lock);
  }
  void platform_lock_init(CRITICAL_SECTION lock) {
    InitializeCriticalSection(&lock);
  }
  void platform_lock_destroy(CRITICAL_SECTION lock) {
    DeleteCriticalSection(&lock, NULL);
  }
  CRITICAL_SECTION MSQuicLock;
#else
  void platform_lock(pthread_mutex_t lock) {
    pthread_mutex_lock(&lock);
  }
  void platform_unlock(pthread_mutex_t lock) {
    pthread_mutex_unlock(&lock);
  }
  void platform_lock_init(pthread_mutex_t lock) {
    pthread_mutex_init(&lock, NULL);
  }

  void platform_lock_destroy(pthread_mutex_t lock) {
    int result = pthread_mutex_destroy(&lock);
  }
  pthread_mutex_t MSQuicLock = PTHREAD_MUTEX_INITIALIZER;
#endif


HQUIC* quic_new_registration(QUIC_REGISTRATION_CONFIG* config) {
  if (MSQuic == NULL) {
    #if _WIN32
    if (NULL == MSQuicLock.DebugInfo) {
      platform_lock_init(MSQuicLock);
    }
    #endif
    platform_lock(MSQuicLock);
    if (QUIC_FAILED(MsQuicOpen2(&MSQuic))) {
      pony_error();
      platform_unlock(MSQuicLock);
      return NULL;
    }
    platform_unlock(MSQuicLock);
  }

  platform_lock(MSQuicLock);
  HQUIC* registration = malloc(sizeof(HQUIC));

  if (QUIC_FAILED(MSQuic->RegistrationOpen(config, registration))) {
        free(registration);
        pony_error();
        platform_unlock(MSQuicLock);
        return NULL;
  } else {
    registration_count++;
  }
  platform_unlock(MSQuicLock);

  return registration;
}

QUIC_REGISTRATION_CONFIG* quic_new_registration_config(const char * appName, int32_t executionProfile) {
  QUIC_REGISTRATION_CONFIG* config = malloc(sizeof(QUIC_REGISTRATION_CONFIG));
  config->AppName= appName;
  config->ExecutionProfile= executionProfile;
  return config;
}
void quic_free(void* ptr) {
  free(ptr);
}

void quic_free_registration(HQUIC* registration) {
  MSQuic->RegistrationClose(*registration);
  registration_count--;
}

QUIC_CERTIFICATE_FILE*  quic_certificate_file(const char* privateKeyFile, const char* certificateFile) {
  QUIC_CERTIFICATE_FILE* cert = malloc(sizeof(QUIC_CERTIFICATE_FILE));
  cert->PrivateKeyFile = privateKeyFile;
  cert->CertificateFile = certificateFile;
  return cert;
}

QUIC_CERTIFICATE_FILE_PROTECTED* quic_certificate_file_protected(const char* certificateFile, const char* privateKeyFile, const char* privateKeyPassword) {
  QUIC_CERTIFICATE_FILE_PROTECTED* cert = malloc(sizeof(QUIC_CERTIFICATE_FILE_PROTECTED));
  cert->PrivateKeyFile = privateKeyFile;
  cert->CertificateFile = certificateFile;
  cert->PrivateKeyPassword = privateKeyPassword;
  return cert;
}

QUIC_CERTIFICATE_PKCS12* quic_certificate_pkcs12(const uint8_t *asn1Blob, uint32_t asn1BlobLength, const char* privateKeyPassword) {
  QUIC_CERTIFICATE_PKCS12* cert = malloc(sizeof(QUIC_CERTIFICATE_PKCS12));
  cert->Asn1Blob = asn1Blob;
  cert->Asn1BlobLength = asn1BlobLength;
  cert->PrivateKeyPassword = privateKeyPassword;
  return cert;
}

QUIC_CREDENTIAL_CONFIG* quic_new_credential_config(int32_t credType, uint64_t flags, void * cert, uint8_t allowedCiphers, const char* caCertificateFile) {
  QUIC_CREDENTIAL_CONFIG* cred = calloc(1, sizeof(QUIC_CREDENTIAL_CONFIG));
  cred->Type = credType;
  cred->Flags = flags;
  switch(credType){
    case 4:
      cred->CertificateFile = cert;
      break;
    case 5:
      cred->CertificateFileProtected = cert;
      break;
    case 6:
      cred->CertificatePkcs12 = cert;
      break;
  }
  cred->AllowedCipherSuites = allowedCiphers;
  cred->CaCertificateFile = caCertificateFile;
  return cred;
}

QUIC_SETTINGS* quic_new_settings(struct quic_setting_value_uint64_t maxBytesPerKey,
  struct quic_setting_value_uint64_t handshakeIdleTimeoutMs,
  struct quic_setting_value_uint64_t idleTimeoutMs,
  struct quic_setting_value_uint64_t mtuDiscoverySearchCompleteTimeoutUs,
  struct quic_setting_value_uint32_t tlsClientMaxSendBuffer,
  struct quic_setting_value_uint32_t tlsServerMaxSendBuffer,
  struct quic_setting_value_uint32_t streamRecvWindowDefault,
  struct quic_setting_value_uint32_t streamRecvBufferDefault,
  struct quic_setting_value_uint32_t connFlowControlWindow,
  struct quic_setting_value_uint32_t maxWorkerQueueDelayUs,
  struct quic_setting_value_uint32_t maxStatelessOperations,
  struct quic_setting_value_uint32_t initialWindowPackets,
  struct quic_setting_value_uint32_t sendIdleTimeoutMs,
  struct quic_setting_value_uint32_t initialRttMs,
  struct quic_setting_value_uint32_t maxAckDelayMs,
  struct quic_setting_value_uint32_t disconnectTimeoutMs,
  struct quic_setting_value_uint32_t keepAliveIntervalMs,
  struct quic_setting_value_uint16_t congestionControlAlgorithm,
  struct quic_setting_value_uint16_t peerBidiStreamCount,
  struct quic_setting_value_uint16_t peerUnidiStreamCount,
  struct quic_setting_value_uint16_t maxBindingStatelessOperations,
  struct quic_setting_value_uint16_t statelessOperationExpirationMs,
  struct quic_setting_value_uint16_t minimumMtu,
  struct quic_setting_value_uint16_t maximumMtu,
  struct quic_setting_value_uint8_t sendBufferingEnabled,
  struct quic_setting_value_uint8_t pacingEnabled,
  struct quic_setting_value_uint8_t migrationEnabled,
  struct quic_setting_value_uint8_t datagramReceiveEnabled,
  struct quic_setting_value_uint8_t serverResumptionLevel,
  struct quic_setting_value_uint8_t greaseQuicBitEnabled,
  struct quic_setting_value_uint8_t ecnEnabled,
  struct quic_setting_value_uint8_t maxOperationsPerDrain,
  struct quic_setting_value_uint8_t mtuDiscoveryMissingProbeCount,
  struct quic_setting_value_uint32_t destCidUpdateIdleTimeoutMs) {

  int result = false;
  QUIC_SETTINGS* settings = calloc(1, sizeof(QUIC_SETTINGS));
  settings->MaxBytesPerKey = maxBytesPerKey.value;
  settings->IsSet.MaxBytesPerKey = maxBytesPerKey.set;

  settings->HandshakeIdleTimeoutMs = handshakeIdleTimeoutMs.value;
  settings->IsSet.HandshakeIdleTimeoutMs = handshakeIdleTimeoutMs.set;

  settings->IdleTimeoutMs = idleTimeoutMs.value;
  settings->IsSet.IdleTimeoutMs = idleTimeoutMs.set;

  settings->MtuDiscoverySearchCompleteTimeoutUs = mtuDiscoverySearchCompleteTimeoutUs.value;
  settings->IsSet.IdleTimeoutMs = idleTimeoutMs.set;

  settings->TlsClientMaxSendBuffer = tlsClientMaxSendBuffer.value;
  settings->IsSet.TlsClientMaxSendBuffer = tlsClientMaxSendBuffer.set;

  settings->StreamRecvWindowDefault = streamRecvWindowDefault.value;
  settings->IsSet.StreamRecvWindowDefault = streamRecvWindowDefault.set;

  settings->StreamRecvBufferDefault = streamRecvBufferDefault.value;
  settings->IsSet.StreamRecvBufferDefault = streamRecvBufferDefault.set;

  settings->ConnFlowControlWindow = connFlowControlWindow.value;
  settings->IsSet.ConnFlowControlWindow = connFlowControlWindow.set;

  settings->MaxWorkerQueueDelayUs = maxWorkerQueueDelayUs.value;
  settings->IsSet.MaxWorkerQueueDelayUs = maxWorkerQueueDelayUs.set;

  settings->MaxStatelessOperations = maxStatelessOperations.value;
  settings->IsSet.MaxStatelessOperations = maxStatelessOperations.set;

  settings->MaxWorkerQueueDelayUs= maxWorkerQueueDelayUs.value;
  settings->IsSet.MaxWorkerQueueDelayUs = maxWorkerQueueDelayUs.set;

  settings->InitialWindowPackets = initialWindowPackets.value;
  settings->IsSet.InitialWindowPackets = initialWindowPackets.set;

  settings->SendIdleTimeoutMs = sendIdleTimeoutMs.value;
  settings->IsSet.SendIdleTimeoutMs = sendIdleTimeoutMs.set;

  settings->InitialRttMs = initialRttMs.value;
  settings->IsSet.InitialRttMs = initialRttMs.set;

  settings->MaxAckDelayMs = maxAckDelayMs.value;
  settings->IsSet.MaxAckDelayMs = maxAckDelayMs.set;

  settings->DisconnectTimeoutMs = disconnectTimeoutMs.value;
  settings->IsSet.DisconnectTimeoutMs = disconnectTimeoutMs.set;

  settings->KeepAliveIntervalMs = keepAliveIntervalMs.value;
  settings->IsSet.KeepAliveIntervalMs = keepAliveIntervalMs.set;

  settings->CongestionControlAlgorithm = congestionControlAlgorithm.value;
  settings->IsSet.CongestionControlAlgorithm = congestionControlAlgorithm.set;

  settings->PeerBidiStreamCount = peerBidiStreamCount.value;
  settings->IsSet.PeerBidiStreamCount = peerBidiStreamCount.set;

  settings->PeerUnidiStreamCount = peerUnidiStreamCount.value;
  settings->IsSet.PeerUnidiStreamCount = peerUnidiStreamCount.set;

  settings->MaxBindingStatelessOperations = maxBindingStatelessOperations.value;
  settings->IsSet.MaxBindingStatelessOperations = maxBindingStatelessOperations.set;

  settings->StatelessOperationExpirationMs = statelessOperationExpirationMs.value;
  settings->IsSet.StatelessOperationExpirationMs = statelessOperationExpirationMs.set;

  settings->MinimumMtu = minimumMtu.value;
  settings->IsSet.MinimumMtu = minimumMtu.set;

  settings->MaximumMtu = maximumMtu.value;
  settings->IsSet.MaximumMtu = maximumMtu.set;

  settings->SendBufferingEnabled = sendBufferingEnabled.value;
  settings->IsSet.SendBufferingEnabled = sendBufferingEnabled.set;

  settings->PacingEnabled = pacingEnabled.value;
  settings->IsSet.PacingEnabled = pacingEnabled.set;

  settings->MaxOperationsPerDrain = migrationEnabled.value;
  settings->IsSet.MaxOperationsPerDrain = migrationEnabled.set;

  settings->DatagramReceiveEnabled = datagramReceiveEnabled.value;
  settings->IsSet.DatagramReceiveEnabled = datagramReceiveEnabled.set;

  settings->ServerResumptionLevel = serverResumptionLevel.value;
  settings->IsSet.ServerResumptionLevel = serverResumptionLevel.set;

  settings->GreaseQuicBitEnabled = greaseQuicBitEnabled.value;
  settings->IsSet.GreaseQuicBitEnabled = greaseQuicBitEnabled.set;

  settings->EcnEnabled = ecnEnabled.value;
  settings->IsSet.EcnEnabled = ecnEnabled.set;

  settings->MaxOperationsPerDrain = maxOperationsPerDrain.value;
  settings->IsSet.MaxOperationsPerDrain = maxOperationsPerDrain.set;

  settings->MtuDiscoveryMissingProbeCount = mtuDiscoveryMissingProbeCount.value;
  settings->IsSet.MtuDiscoveryMissingProbeCount = mtuDiscoveryMissingProbeCount.set;

  settings->DestCidUpdateIdleTimeoutMs = destCidUpdateIdleTimeoutMs.value;
  settings->IsSet.DestCidUpdateIdleTimeoutMs = destCidUpdateIdleTimeoutMs.set;

  return settings;
}
HQUIC* quic_new_configuration(HQUIC* registration, char** alpn, uint32_t alpnSize, QUIC_SETTINGS* settings) {
  HQUIC* configuration = malloc(sizeof(HQUIC));
  QUIC_BUFFER alpns[alpnSize];

  for (int i = 0; i < alpnSize; i++) {
    alpns[i] = (QUIC_BUFFER) { .Length = strlen(alpn[i]), .Buffer = (uint8_t*) alpn[i] };
  }

  if (QUIC_FAILED(MSQuic->ConfigurationOpen(*registration, (const QUIC_BUFFER* const)&alpns, alpnSize, settings, sizeof(*settings), NULL, configuration))) {
    pony_error();
    return NULL;
  }
  return configuration;
}

void quic_configuration_load_credential(HQUIC* configuration, QUIC_CREDENTIAL_CONFIG* credentials) {
  QUIC_STATUS Status;
  if (QUIC_FAILED(Status = MSQuic->ConfigurationLoadCredential(*configuration, credentials))) {
    printf("%u\n", Status);
    pony_error();
  }
}


uint8_t quic_is_new_connection_event(QUIC_LISTENER_EVENT* event) {
  if(event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
     return 1;
  } else {
    return 0;
  }
}

HQUIC* quic_server_listner_open(HQUIC* registration, void* serverListenerCallback, struct quic_server_event_context* ctx) {
  HQUIC* listener = malloc(sizeof(HQUIC));

  if (QUIC_FAILED(MSQuic->ListenerOpen(*registration, serverListenerCallback, ctx, listener))) {
    quic_free(listener);
    pony_error();
    return NULL;
  }
  return listener;
}
void quic_server_listener_close(HQUIC* listener) {
  if (listener != NULL) {
    MSQuic->ListenerClose(*listener);
  }
}

HQUIC* quic_receive_connection(QUIC_LISTENER_EVENT* event) {
  return &event->NEW_CONNECTION.Connection;
}

uint32_t quic_connection_set_configuration(HQUIC* connection, HQUIC* configuration) {
  return (uint32_t) MSQuic->ConnectionSetConfiguration(*connection, *configuration);
}

HQUIC* quic_server_listener_open(HQUIC* registration, void* serverListenerCallback, struct quic_server_event_context* ctx) {
  HQUIC* listener = malloc(sizeof(HQUIC));

  if (QUIC_FAILED(MSQuic->ListenerOpen(*registration, serverListenerCallback, ctx, listener))) {
    pony_error();
    free(listener);
    return NULL;
  }
  return listener;
}

uint32_t quic_get_connection_event_type_as_uint(QUIC_LISTENER_EVENT* event) {
  return (uint32_t) event->Type;
}

void quic_send_resumption_ticket(HQUIC* connection) {
  MSQuic->ConnectionSendResumptionTicket(*connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
}

void quic_close_connection(HQUIC* connection) {
  MSQuic->ConnectionClose(*connection);
}

void quic_connection_set_callback(HQUIC* connection, void* connectionCallback, void* ctx) {
  MSQuic->SetCallbackHandler(*connection, connectionCallback, ctx);
}

HQUIC* quic_receive_stream(QUIC_CONNECTION_EVENT* event) {
  return &event->PEER_STREAM_STARTED.Stream;
}

void quic_stream_set_callback(HQUIC* stream, void* streamCallback, void* ctx) {
  return MSQuic->SetCallbackHandler(*stream, streamCallback, ctx);
}

uint32_t quic_receive_stream_type(QUIC_CONNECTION_EVENT* event) {
  return (uint32_t) event->PEER_STREAM_STARTED.Flags;
}

uint32_t quic_get_stream_event_type_as_uint(QUIC_STREAM_EVENT* event) {
  return (uint32_t) event->Type;
}

uint32_t quic_stream_get_buffer_count(QUIC_STREAM_EVENT* event) {
  return event->RECEIVE.BufferCount;
}

uint64_t quic_stream_get_total_buffer_length(QUIC_STREAM_EVENT* event) {
  return event->RECEIVE.BufferCount;
}

uint32_t quic_stream_status_pending() {
  return (uint32_t) QUIC_STATUS_PENDING;
}

uint32_t min(uint32_t a, uint32_t b) {
  if (a < b) {
    return a;
  } else {
    return b;
  }
}
void quic_stream_get_total_buffer(QUIC_STREAM_EVENT* event, uint8_t* buffer, HQUIC* stream) {
  uint64_t offset = event->RECEIVE.AbsoluteOffset;
  for (uint32_t i = 0; offset < sizeof(uint64_t) && i < event->RECEIVE.BufferCount; ++i) {
    uint32_t length = min((uint32_t)(sizeof(uint64_t) - offset), event->RECEIVE.Buffers[i].Length);
    memcpy(buffer + offset, event->RECEIVE.Buffers[i].Buffer, length);
    offset += length;
  }
  MSQuic->StreamReceiveComplete(*stream, offset);
}

struct quic_connection_event_context* quic_new_connection_event_context(uint8_t isClient, void * cb) {
  struct quic_connection_event_context* ctx= calloc(1, sizeof(struct quic_connection_event_context));
  ctx->isClient = isClient;
  ctx->cb= cb;
  printf("pointer address in context %p\n", ctx->cb);
  ctx->QUIC_CONNECTION_EVENT_CONNECTED = 1;
  ctx->QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED = 1;
  ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT =1;
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_CONNECTED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_RESUMED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK);
  platform_lock_init(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
  return ctx;
}

void quic_free_connection_event_context(struct quic_connection_event_context* ctx) {
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_CONNECTED_LOCK);
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK);
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK);
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK);
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK);
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK);
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK);
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK);
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK);
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK);
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK);
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED_LOCK);
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK);
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_RESUMED_LOCK);
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK);
  platform_lock_destroy(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
  free(ctx);
}

void quic_connection_event_context_set_actor(struct quic_connection_event_context* ctx, void* connectionActor) {
    ctx->connectionActor = connectionActor;
}
unsigned int testcb(HQUIC* Connection, void* Context, QUIC_CONNECTION_EVENT* Event) {
  printf("This is the cb happening\n");
  struct quic_connection_event_context* ctx = (struct quic_connection_event_context*) Context;
  if (ctx->cb == NULL) {
    printf("This thang is null\n");
  }
  pony_register_thread();
  printf("pointer address at testcb %p\n", ctx->cb);
  unsigned int (*cb)(HQUIC*, void*, QUIC_CONNECTION_EVENT*) = ctx->cb;

  return (*cb)(Connection, Context, Event);
}

void print_pointer(void* ptr) {
  printf("pointer address printed %p\n", ptr);
}
HQUIC* quic_connection_open(HQUIC* registration, void* callback, struct quic_connection_event_context* ctx) {
  HQUIC* connection = malloc(sizeof(HQUIC));
  unsigned int (*cb)(HQUIC*, void*, QUIC_CONNECTION_EVENT*) = callback;
  printf("pointer address at open %p\n", callback);
  //unsigned int i = (*cb)(NULL, NULL, NULL);
  if (QUIC_FAILED(MSQuic->ConnectionOpen(*registration, testcb, ctx, connection))) {
     pony_error();
     free(connection);
     return NULL;
   }
   return connection;
}

struct quic_server_event_context* quic_new_server_event_context(void* serverActor, HQUIC* configuration) {
  struct quic_server_event_context* ctx = malloc(sizeof(struct quic_server_event_context));
  ctx->serverActor = serverActor;
  ctx->configuration = configuration;
  return ctx;
}

void* quic_server_actor(struct quic_server_event_context* ctx) {
  return ctx->serverActor;
}

HQUIC* quic_server_configuration(struct quic_server_event_context* ctx) {
  return ctx->configuration;
}

void quic_connection_set_connected_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_CONNECTED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_CONNECTED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_CONNECTED_LOCK);
}

void quic_connection_set_shutdown_initiated_by_transport_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK);
  ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK);
}

void quic_connection_set_shutdown_initiated_by_peer_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK);
  ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK);
}

void quic_connection_set_shutdown_complete_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK);
  ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK);
}

void quic_connection_set_local_address_changed_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK);
}

void quic_connection_set_peer_address_changed_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK);
}

void quic_connection_set_peer_stream_started_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx-> QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK);
  ctx-> QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK);
}

void quic_connection_set_streams_available_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK);
  ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK);
}

void quic_connection_set_peer_needs_streams_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK);
  ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK);
}

void quic_connection_set_ideal_processor_changed_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK);
}

void quic_connection_set_datagram_state_changed_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK);
}

void quic_connection_set_datagram_received_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
}

void quic_connection_set_datagram_send_state_changed_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK);
}

void quic_connection_set_resumed_changed_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_RESUMED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_RESUMED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_RESUMED_LOCK);
}

void quic_connection_set_datagram_resumption_ticket_received_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK);
}

void quic_connection_set_datagram_peer_certificate_received_event(struct quic_connection_event_context* ctx, uint8_t value) {
  platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
  ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED = value;
  platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
}

uint8_t quic_connection_connected_event_session_resumed(QUIC_CONNECTION_EVENT* event) {
  return (uint8_t) event->CONNECTED.SessionResumed;
}

uint8_t quic_connection_connected_event_session_negotiated_alpn_length(QUIC_CONNECTION_EVENT* event) {
  return event->CONNECTED.NegotiatedAlpnLength;
}

void quic_connection_connected_event_session_negotiated_alpn_data(QUIC_CONNECTION_EVENT* event, uint8_t* buffer) {
  memcpy(buffer, event->CONNECTED.NegotiatedAlpn, (size_t)event->CONNECTED.NegotiatedAlpnLength);
}

uint8_t quic_connection_event_enabled(struct quic_connection_event_context* ctx, QUIC_CONNECTION_EVENT* event) {
  uint8_t value = 0;
  switch (event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED :
        platform_lock(ctx->QUIC_CONNECTION_EVENT_CONNECTED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_CONNECTED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_CONNECTED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED_LOCK);
        return value;
        break;
    case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_RESUMED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_RESUMED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_RESUMED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED_LOCK);
        break;
    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
        platform_lock(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
        value = ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED;
        platform_unlock(ctx->QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED_LOCK);
        break;
  }
  return value;
}

void* quic_connection_actor(struct quic_connection_event_context* ctx) {
  return ctx->connectionActor;
}

struct shutdown_initiated_by_transport_data quic_connection_shutdown_initiated_by_transport_data(QUIC_CONNECTION_EVENT* event) {
  struct shutdown_initiated_by_transport_data data;
  data.errorCode = (uint64_t) event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode;
  data.status = (uint32_t) event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
  return data;
}

uint64_t quic_connection_shutdown_initiated_by_peer_data(QUIC_CONNECTION_EVENT* event) {
  return event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode;
}

void quic_connection_shutdown_complete_data(QUIC_CONNECTION_EVENT* event, struct shutdown_complete_data* data) {
  data->handshakeCompleted = (uint8_t) event->SHUTDOWN_COMPLETE.HandshakeCompleted;
  data->peerAcknowledgedShutdown = (uint8_t) event->SHUTDOWN_COMPLETE.PeerAcknowledgedShutdown;
  data->appCloseInProgress = (uint8_t) event->SHUTDOWN_COMPLETE.AppCloseInProgress;
}

QUIC_ADDR* quic_connection_event_local_address_changed_data(QUIC_CONNECTION_EVENT* event) {
  QUIC_ADDR* addr = malloc(sizeof(event->LOCAL_ADDRESS_CHANGED.Address));
  memcpy(addr, &event->LOCAL_ADDRESS_CHANGED.Address, sizeof(event->LOCAL_ADDRESS_CHANGED.Address));
  return addr;
}

QUIC_ADDR* quic_connection_event_peer_address_changed_data(QUIC_CONNECTION_EVENT* event) {
  QUIC_ADDR* addr = malloc(sizeof(event->PEER_ADDRESS_CHANGED.Address));
  memcpy(addr, &event->PEER_ADDRESS_CHANGED.Address, sizeof(event->PEER_ADDRESS_CHANGED.Address));
  return addr;
}
void quic_connection_event_streams_available_data(QUIC_CONNECTION_EVENT* event, struct streams_available_data* data) {
  data->bidirectionalCount = event->STREAMS_AVAILABLE.BidirectionalCount;
  data->unidirectionalCount = event->STREAMS_AVAILABLE.UnidirectionalCount;
}

uint8_t quic_connection_event_peer_needs_streams_data(QUIC_CONNECTION_EVENT* event) {
  return (uint8_t)event->PEER_NEEDS_STREAMS.Bidirectional;
}

uint16_t quic_connection_event_ideal_processor_changed_data(QUIC_CONNECTION_EVENT* event) {
  return event->IDEAL_PROCESSOR_CHANGED.IdealProcessor;
}

uint32_t quic_connection_event_datagram_send_state_changed_data(QUIC_CONNECTION_EVENT* event) {
  return (uint32_t) event->DATAGRAM_SEND_STATE_CHANGED.State;
}

uint32_t quic_connection_event_datagram_received_flags(QUIC_CONNECTION_EVENT* event) {
  return (uint32_t) event->DATAGRAM_RECEIVED.Flags;
}

uint32_t quic_connection_event_datagram_received_buffer_length(QUIC_CONNECTION_EVENT* event) {
  return event->DATAGRAM_RECEIVED.Buffer->Length;
}

void quic_connection_event_datagram_received_buffer(QUIC_CONNECTION_EVENT* event, uint8_t* buffer) {
  memcpy(buffer, event->DATAGRAM_RECEIVED.Buffer->Buffer, (size_t) event->DATAGRAM_RECEIVED.Buffer->Length);
}
void quic_connection_event_datagram_state_changed_data(QUIC_CONNECTION_EVENT* event, struct datagram_state_changed_data* data) {
  data->sendEnabled = (uint8_t) event->DATAGRAM_STATE_CHANGED.SendEnabled;
  data->maxSendLength = event->DATAGRAM_STATE_CHANGED.MaxSendLength;
}

uint16_t quic_connection_event_resumed_resumption_state_length(QUIC_CONNECTION_EVENT* event) {
  return event->RESUMED.ResumptionStateLength;
}

void quic_connection_event_resumed_resumption_state_buffer(QUIC_CONNECTION_EVENT* event, uint8_t* buffer) {
  memcpy(buffer, event->RESUMED.ResumptionState, (size_t) event->RESUMED.ResumptionStateLength);
}

uint32_t quic_connection_event_resumption_ticket_received_resumption_ticket_length(QUIC_CONNECTION_EVENT* event) {
  return event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength;
}
void quic_connection_event_resumption_ticket_received_resumption_ticket(QUIC_CONNECTION_EVENT* event, uint8_t* buffer) {
  memcpy(buffer, event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket, (size_t) event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
}

struct quic_stream_event_context * quic_stream_new_event_context() {
  struct quic_stream_event_context * ctx = calloc(1, sizeof(struct quic_stream_event_context));
  return ctx;
}

void quic_stream_event_context_set_actor(struct quic_stream_event_context* ctx, void* streamActor) {
  ctx->streamActor = streamActor;
}

void* quic_stream_actor(struct quic_stream_event_context* ctx) {
  return ctx->streamActor;
}

struct stream_start_complete_data quic_stream_start_complete_data(QUIC_STREAM_EVENT * event) {
  struct stream_start_complete_data data;
  data.status = (uint32_t) event->START_COMPLETE.Status;
  data.id = event->START_COMPLETE.ID;
  data.peerAccepted = (uint8_t) event->START_COMPLETE.PeerAccepted;
  return data;
}

uint8_t quic_stream_event_send_complete_canceled(QUIC_STREAM_EVENT * event) {
  return (uint8_t) event->SEND_COMPLETE.Canceled;
}

uint64_t quic_stream_event_peer_send_aborted_error_code(QUIC_STREAM_EVENT * event) {
  return event->PEER_SEND_ABORTED.ErrorCode;
}

uint64_t quic_stream_event_peer_receive_aborted_error_code(QUIC_STREAM_EVENT * event) {
  return event->PEER_RECEIVE_ABORTED.ErrorCode;
}

uint8_t quic_stream_event_send_shutdown_complete_graceful(QUIC_STREAM_EVENT * event) {
  return (uint8_t) event->SEND_SHUTDOWN_COMPLETE.Graceful;
}

struct stream_shutdown_complete_data quic_stream_shutdown_complete_data(QUIC_STREAM_EVENT * event) {
  struct stream_shutdown_complete_data data;
  data.connectionShutdown = event->SHUTDOWN_COMPLETE.ConnectionShutdown;
  data.appCloseInProgress = event->SHUTDOWN_COMPLETE.AppCloseInProgress;
  data.connectionShutdownByApp = (uint8_t) event->SHUTDOWN_COMPLETE.ConnectionShutdownByApp;
  data.connectionClosedRemotely = (uint8_t) event->SHUTDOWN_COMPLETE.ConnectionClosedRemotely;
  data.connectionErrorCode = (uint8_t) event->SHUTDOWN_COMPLETE.ConnectionErrorCode;
  data.connectionCloseStatus = (uint8_t) event->SHUTDOWN_COMPLETE.ConnectionCloseStatus;
  return data;
}

uint64_t quic_stream_event_ideal_send_buffer_size_byte_count(QUIC_STREAM_EVENT * event) {
  return event->IDEAL_SEND_BUFFER_SIZE.ByteCount;
}

HQUIC* quic_stream_open_stream(HQUIC* connection, QUIC_STREAM_OPEN_FLAGS flag, void* callback, void* ctx) {
  HQUIC* stream = NULL;
  if (QUIC_FAILED(MSQuic->StreamOpen(*connection, flag, callback, ctx, stream))) {
    pony_error();
    return NULL;
  };
  return stream;
}

void quic_stream_close_stream(HQUIC* stream) {
  MSQuic->StreamClose(*stream);
}

void quic_stream_start_stream(HQUIC* stream, QUIC_STREAM_START_FLAGS flag) {
  if (QUIC_FAILED(MSQuic->StreamStart(*stream, flag))) {
    pony_error();
  };
}
void quic_stream_send(HQUIC* stream, uint8_t* buffer, size_t bufferLength) {
  QUIC_BUFFER* sendBuffer = malloc(sizeof(QUIC_BUFFER));
  if (sendBuffer == NULL) {
    pony_error();
    return;
  }

  sendBuffer->Buffer = malloc(bufferLength);
  if (sendBuffer->Buffer  == NULL) {
    free(sendBuffer);
    pony_error();
    return;
  }
  memcpy(sendBuffer->Buffer, buffer, bufferLength);
  sendBuffer->Length = (uint32_t) bufferLength;
  if (QUIC_FAILED(MSQuic->StreamSend(*stream, sendBuffer, 1, 0, sendBuffer))) {
    free(sendBuffer->Buffer);
    free(sendBuffer);
    pony_error();
  }
}

void quic_stream_shutdown(HQUIC* stream, QUIC_STREAM_SHUTDOWN_FLAGS flag) {
  if (QUIC_FAILED(MSQuic->StreamShutdown(*stream, flag, 0))) {
    pony_error();
  }
}

void quic_connection_start(HQUIC* connection, HQUIC* configuration, int family, char * target, uint16_t port) {
  if (QUIC_FAILED(MSQuic->ConnectionStart(*connection, *configuration, family, target, port))) {
    pony_error();
  }
}

void quic_connection_set_resumption_ticket(HQUIC* connection, uint8_t * ticket, uint32_t ticketLength) {
  if(QUIC_FAILED(MSQuic->SetParam(*connection, QUIC_PARAM_CONN_RESUMPTION_TICKET, ticketLength, ticket))) {
    pony_error();
  };
}

void quic_connection_shutdown(HQUIC* connection) {
  MSQuic->ConnectionShutdown(*connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
}

void quic_connection_close(HQUIC* connection) {
  MSQuic->ConnectionClose(*connection);
}

uint8_t quic_server_resumption_no_resume() {
  return (uint8_t) QUIC_SERVER_NO_RESUME;
}
uint8_t quic_server_resumption_resume_only() {
  return (uint8_t) QUIC_SERVER_RESUME_ONLY;
}
uint8_t quic_server_resumption_resume_and_zerortt() {
  return (uint8_t) QUIC_SERVER_RESUME_AND_ZERORTT;
};

void quic_server_listener_start(HQUIC* listener, char** alpn, uint32_t alpnSize, int family, char* ip, char* port) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_ADDRCONFIG;
  hints.ai_family = family;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  if((ip != NULL) && (ip[0] == '\0'))
    ip = NULL;

  struct addrinfo* result;

  if (getaddrinfo(ip, port, &hints, &result) != 0) {
    pony_error();
    return;
  }
  QUIC_ADDR address = {0};
  address.Ip = *result->ai_addr;

  QUIC_BUFFER alpns[alpnSize];

  for (int i = 0; i < alpnSize; i++) {
    alpns[i] = (QUIC_BUFFER) { .Length = strlen(alpn[i]), .Buffer = (uint8_t*) alpn[i] };
  }
  if (QUIC_FAILED(MSQuic->ListenerStart(*listener, (const QUIC_BUFFER* const)&alpns, alpnSize, &address))) {
    freeaddrinfo(result);
    pony_error();
    return;
  }
  freeaddrinfo(result);
}

int quic_address_family_unspecified() {
  return AF_UNSPEC;
}

int quic_address_family_inet() {
  return AF_INET;
}

int quic_address_family_inet6() {
  return AF_INET6;
}

void quic_server_listener_stop(HQUIC* listener) {
  MSQuic->ListenerStop(*listener);
}

void quic_configuration_close(HQUIC* configuration) {
  MSQuic->ConfigurationClose(*configuration);
}
uint8_t quic_connection_is_client(struct quic_connection_event_context* ctx) {
  return ctx->isClient;
}
