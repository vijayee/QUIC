#include "quic.h"
#include <pony.h>
#if __linux__
  #include <pthread.h>
#endif
#if _WIN32
  #include <windows.h>
#endif
#include <msquic.h>
#include <hashmap.h>


static  HASHMAP(void*, void*) callbackCache;
size_t hash_pointer(void * input);
int  ptrcmp(const void* ptr1, const char* ptr2);
#if ___linux__
  void platform_lock(pthread_mutex_t lock) {
    pthread_mutex_lock(&lock);
  }
  void platform_unlock(pthread_mutex_t lock) {
    EnterCriticalSection(&Lock);
  }
#endif
#if _WIN32
  void platform_lock(CRITICAL_SECTION lock) {
    InitializeCriticalSection(&lock);
  }
  void platform_unlock(CRITICAL_SECTION lock) {
    pthread_mutex_unlock(&Lock);
  }
#endif
#if __linux__
pthread_mutex_t CacheLock = PTHREAD_MUTEX_INITIALIZER;
#endif
#if _WIN32
  CRITICAL_SECTION CacheLock;
  InitializeCriticalSection(&CaLock);
#endif

#if __linux__
pthread_mutex_t MSQuicLock = PTHREAD_MUTEX_INITIALIZER;
#endif
#if _WIN32
  CRITICAL_SECTION MSQuicLock;
  InitializeCriticalSection(&MSQuicLock);
#endif

HQUIC* quic_new_registration(QUIC_REGISTRATION_CONFIG* config) {

  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (MSQuic == NULL) {
    platform_lock(&MSQuicLock);
    if (QUIC_FAILED(Status = MsQuicOpen2(&MSQuic))) {
      pony_error();
      platform_unlock(&MSQuicLock);
      return NULL;
    }
    platform_unlock(&MSQuicLock);
  }

  platform_lock(&MSQuicLock);
  HQUIC* registration = malloc(sizeof(HQUIC));

  if (QUIC_FAILED(Status = MSQuic->RegistrationOpen(config, registration))) {
        free(registration);
        pony_error();
        #if __linux__
              pthread_mutex_unlock(&MSQuicLock);
        #endif
        return NULL;
  } else {
    registration_count++;
  }
  platform_unlock(&MSQuicLock);

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
  uint32_t* destCidUpdateIdleTimeoutMs) {

  int result = false;
  QUIC_CREDENTIAL_CONFIG* settings = calloc(1, sizeof(QUIC_SETTINGS));
  if (maxBytesPerKey != NULL) {
    settings->MaxBytesPerKey = *maxBytesPerKey;
    settings->IsSet->MaxBytesPerKey = TRUE;
  }

  if (handshakeIdleTimeoutMs != NULL) {
    settings->HandshakeIdleTimeoutMs = *handshakeIdleTimeoutMs;
    settings->IsSet->HandshakeIdleTimeoutMs = TRUE;
  }

  if (idleTimeoutMs != NULL) {
    settings->IdleTimeoutMs = *idleTimeoutMs;
    settings->IsSet->IdleTimeoutMs = TRUE;
  }

  if (mtuDiscoverySearchCompleteTimeoutUs != NULL) {
    settings->MtuDiscoverySearchCompleteTimeoutUs = *mtuDiscoverySearchCompleteTimeoutUs;
    settings->IsSet->IdleTimeoutMs = TRUE;
  }

  if (tlsClientMaxSendBuffer != NULL) {
    settings->TlsClientMaxSendBuffer = *tlsClientMaxSendBuffer;
    settings->IsSet->TlsClientMaxSendBuffer = TRUE;
  }

  if (streamRecvWindowDefault != NULL) {
    settings->StreamRecvWindowDefault = *streamRecvWindowDefault;
    settings->IsSet->StreamRecvWindowDefault = TRUE;
  }

  if (streamRecvBufferDefault != NULL) {
    settings->StreamRecvBufferDefault = *streamRecvBufferDefault;
    settings->IsSet->StreamRecvBufferDefault = TRUE;
  }

  if (connFlowControlWindow != NULL) {*
    settings->ConnFlowControlWindow = connFlowControlWindow;
    settings->IsSet->ConnFlowControlWindow = TRUE;
  }

  if (maxWorkerQueueDelayUs != NULL) {
    settings->MaxWorkerQueueDelayUs = *maxWorkerQueueDelayUs;
    settings->IsSet->MaxWorkerQueueDelayUs = TRUE;
  }

  if (maxStatelessOperations != NULL) {
    settings->MaxStatelessOperations = *maxStatelessOperations;
    settings->IsSet->MaxStatelessOperations = TRUE;
  }

  if (maxStatelessOperations != NULL) {
    settings->MaxStatelessOperations = *maxWorkerQueueDelayUs;
    settings->IsSet->MaxStatelessOperations = TRUE;
  }

  if (initialWindowPackets != NULL) {
    settings->InitialWindowPackets = *initialWindowPackets;
    settings->IsSet->InitialWindowPackets = TRUE;
  }

  if (sendIdleTimeoutMs != NULL) {
    settings->SendIdleTimeoutMs = *sendIdleTimeoutMs;
    settings->IsSet->SendIdleTimeoutMs = TRUE;
  }

  if (initialRttMs != NULL) {
    settings->InitialRttMs = *initialRttMs;
    settings->IsSet->InitialRttMs = TRUE;
  }

  if (maxAckDelayMs != NULL) {
    settings->MaxAckDelayMs = *maxAckDelayMs;
    settings->IsSet->MaxAckDelayMs = TRUE;
  }

  if (disconnectTimeoutMs != NULL) {
    settings->DisconnectTimeoutMs = *disconnectTimeoutMs;
    settings->IsSet->DisconnectTimeoutMs = TRUE;
  }

  if (keepAliveIntervalMs != NULL) {
    settings->KeepAliveIntervalMs = *keepAliveIntervalMs;
    settings->IsSet->KeepAliveIntervalMs = TRUE;
  }

  if (congestionControlAlgorithm != NULL) {
    settings->CongestionControlAlgorithm = *congestionControlAlgorithm;
    settings->IsSet->congestionControlAlgorithm = TRUE;
  }

  if (peerBidiStreamCount != NULL) {
    settings->PeerBidiStreamCount = *peerBidiStreamCount;
    settings->IsSet->PeerBidiStreamCount = TRUE;
  }

  if (peerUnidiStreamCount != NULL) {
    settings->PeerUnidiStreamCount = *peerUnidiStreamCount;
    settings->IsSet->PeerUnidiStreamCount = TRUE;
  }

  if (maxBindingStatelessOperations != NULL) {
    settings->MaxBindingStatelessOperations = *maxBindingStatelessOperations;
    settings->IsSet->MaxBindingStatelessOperations = TRUE;
  }

  if (dtatelessOperationExpirationMs != NULL) {
    settings->DtatelessOperationExpirationMs = *DtatelessOperationExpirationMs;
    settings->IsSet->DtatelessOperationExpirationMs = TRUE;
  }

  if (minimumMtu != NULL) {
    settings->MinimumMtu = *minimumMtu;
    settings->IsSet->MinimumMtu = TRUE;
  }

  if (maximumMtu != NULL) {
    settings->MaximumMtu = *maximumMtu;
    settings->IsSet->MaximumMtu = TRUE;
  }

  if (sendBufferingEnabled != NULL) {
    settings->SendBufferingEnabled = *sendBufferingEnabled;
    settings->IsSet->SendBufferingEnabled = TRUE;
  }

  if (pacingEnabled != NULL) {
    settings->PacingEnabled = *pacingEnabled;
    settings->IsSet->PacingEnabled = TRUE;
  }

  if (migrationEnabled != NULL) {
    settings->MigrationEnabled = *migrationEnabled;
    settings->IsSet->MigrationEnabled = TRUE;
  }

  if (datagramReceiveEnabled != NULL) {
    settings->DatagramReceiveEnabled = *datagramReceiveEnabled;
    settings->IsSet->DatagramReceiveEnabled = TRUE;
  }

  if (serverResumptionLevel != NULL) {
    settings->ServerResumptionLevel = *serverResumptionLevel;
    settings->IsSet->ServerResumptionLevel = TRUE;
  }

  if (pacingEnabled != NULL) {
    settings->PacingEnabled = *pacingEnabled;
    settings->IsSet->PacingEnabled = TRUE;
  }

  if (migrationEnabled != NULL) {
    settings->MigrationEnabled = *migrationEnabled;
    settings->IsSet->MigrationEnabled = TRUE;
  }

  if (datagramReceiveEnabled != NULL) {
    settings->DatagramReceiveEnabled = *datagramReceiveEnabled;
    settings->IsSet->DatagramReceiveEnabled = TRUE;
  }

  if (serverResumptionLevel != NULL) {
    settings->ServerResumptionLevel = *serverResumptionLevel;
    settings->IsSet->ServerResumptionLevel = TRUE;
  }

  if (greaseQuicBitEnabled != NULL) {
    settings->GreaseQuicBitEnabled = *greaseQuicBitEnabled;
    settings->IsSet->GreaseQuicBitEnabled = TRUE;
  }

  if (ecnEnabled != NULL) {
    settings->EcnEnabled = *ecnEnabled;
    settings->IsSet->EcnEnabled= TRUE;
  }

  if (maxOperationsPerDrain != NULL) {
    settings->MaxOperationsPerDrain = *maxOperationsPerDrain;
    settings->IsSet->MaxOperationsPerDrain = TRUE;
  }

  if (mtuDiscoveryMissingProbeCount != NULL) {
    settings->MtuDiscoveryMissingProbeCount = *mtuDiscoveryMissingProbeCount;
    settings->IsSet->MtuDiscoveryMissingProbeCount = TRUE;
  }

  if (destCidUpdateIdleTimeoutMs != NULL) {
    settings->DestCidUpdateIdleTimeoutMs = *DestCidUpdateIdleTimeoutMs;
    settings->IsSet->DestCidUpdateIdleTimeoutMs = TRUE;
  }
  return settings;
}
HQUIC* quic_new_configuration(HQUIC* registration, char** alpn, alpnSize: uint32_t, QUIC_SETTINGS* settings) {
  HQUIC* configuration = malloc(sizeof(HQUIC));
  if (QUIC_FAILED(MsQuic->ConfigurationOpen(*Registration, alpn, alpnSize, settings, sizeof(*settings), NULL, configuration))) {
        pony_error();
        return NULL;
  }
  return configuration;
}

void quic_configuration_load_credential(HQUIC* configuration, QUIC_CREDENTIAL_CONFIG* credentials) {
  if (QUIC_FAILED(MsQuic->ConfigurationLoadCredential(*configuration, credentials))) {
    pony_error();
  }
}

void* quic_retrieve_actor(HQUIC* self) {
  if (dispactcher == null) {
    hashmap_init(&dispatcher, hash_pointer, ptrcmp);
  }
}

int  ptrcmp(const void* ptr1, const char* ptr2) {
  if (ptr1 == ptr2) {
    return 0;
  } else {
    return 1;
  }
}
size_t hash_pointer(void * input) {
    #if __ILP32__
        size_t x = (size_t) input;
        x = ( ~x) + (x << 15);
        x = x ^ (x >> 12);
        x = x + (x << 2);
        x = x ^ (x >> 4);
        x = (x + (x << 3)) + (x << 11);
        x = x ^ (x >> 16);
        return x;
    #else
        size_t x = (size_t) input;
        x = (~x) + (x << 21);
        x = x ^ (x >> 24);
        x = (x + (x << 3)) + (x << 8);
        x = x ^ (x >> 14);
        x = (x + (x << 2)) + (x << 4);
        x = x ^ (x >> 28);
        x = x + (x << 31);
        return x;
    #endif
}

void quic_pony_dispatcher_init() {
  if (dispactcher == null) {
    #if __linux__
      pthread_mutex_lock(&DispatcherLock);
    #endif
    #if _WIN32
      EnterCriticalSection(&DispatcherLock);
    #endif
    hashmap_init(&dispatcher, hash_pointer, ptrcmp);
    #if __linux__
          pthread_mutex_unlock(&DispatchLock);
    #endif
    #if _WIN32
      LeaveCriticalSection(&DispatcherLock);
    #endif
  }
}
uint8_t quic_is_new_connection_event(QUIC_CONNECTION_EVENT* event) {
  if(Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
     return 1;
  } else {
    return 0;
  }
}

HQUIC* quic_server_listner_open(HQUIC* registration, void* serverListenerCallback) {
  HQUIC* listener = malloc(sizeof(HQUIC));

  if (QUIC_FAILED(MSQuic->ListnerOpen(registration,serverListenerCallback, NULL,lisener))) {
    quic_free(listener)
    pony_error();
    return NULL;
  }
  return listener;
}
void quic_server_listener_close(HQUIC* listener) {
  if (listener != NULL) {
    MSQuic->ListenerClose(listener);
  }
}

void quic_cache_set(void* key, void* value) {
  if (hashmap_put(&callbackCache, key, value) < 0) {
    pony_error();
    return;
  }
}

void* quic_cache_get(void* key) {
   void * result = hashmap_get(&callbackCache, key)
   if (!result) {
     pony_error();
   }
   return result;
}

void quic_cache_delete(void* key) {
   void * result = hashmap_remove(&callbackCache, key)
   if (!result) {
     pony_error();
   }
   return result;
}

HQUIC* quic_receive_connection(QUIC_LISTENER_EVENT* event) {
  return &Event->NEW_CONNECTION.Connection;
}

QUIC_STATUS quic_connection_set_configuration(HQUIC* connection, HQUIC* configuration) {
  return MSQuic->ConnectionSetConfiguration(connection, configuration);
}

HQUIC* quic_server_listener_open(HQUIC* registration, void* serverListenerCallback) {
  HQUOC* listener = malloc(sizeof(HQUIC))
  if (QUIC_FAILED(Status = MsQuic->ListenerOpen(registration, serverListenerCallback, NULL, &Listener))) {
        pony_error();
        free(listener);
        return NULL;
  }
  return listener;
}

uint8_t quic_get_connection_event_type_as_uint(QUIC_LISTENER_EVENT* event) {
  return (uint8_t) event->Type;
}

void quic_send_resumption_ticket(HQUIC* connection) {
  MSQuic->ConnectionSendResumptionTicket(connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
}

void quic_close_connection(HQUIC* connection) {
  MSQUic->ConnectionClose(connection);
}

void quic_connection_set_callback(HQUIC* connection, void* connectionCallback) {
  MsQuic->SetCallbackHandler(connection, connectionCallback, NULL);
}
