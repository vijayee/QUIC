use "pony_test"
use "../../.."
use "Streams"
use "Exception"
use "Print"
use "lib:ponyquic"
use @print_pointer[None](ptr: Pointer[None])
actor Main
  new create(env: Env) =>
    PonyTest(env, RunClient)


actor RunClient is TestList
  fun tag tests(test: PonyTest) =>
    test(_TestClient)

actor QUICCustodian
   var ward: (QUICConnection | None) = None
   fun _final() =>
     Println("custodian culled")
   be apply(ward':  (QUICConnection | None)) =>
     ward = ward'
class iso _TestClient is UnitTest
  let custodian: QUICCustodian
  fun name(): String => "Testing Client Creation"
  fun _final() =>
    Println("test disposed of")
  new create() =>
    custodian = QUICCustodian
  fun apply(t: TestHelper) =>
    t.long_test(5000000000)
    t.expect_action("listener started")
    t.expect_action("listener stopped")
    try
      let registration = QUICRegistration(t.env.root, "test")?
      let settings: QUICSettings iso = recover
        let settings': QUICSettings = QUICSettings
        settings'.idleTimeoutMs= 1000
        settings'.serverResumptionLevel = ResumeAndZeroRTT()
        settings'.peerBidiStreamCount = 1
        settings'
      end

      let certificate: QUICCertificate = QUICCertificate("./server2.crt", "./server2.key")
      let credentials: QUICCredentials = QUICCredentials(certificate)
      try
        let configuration: QUICConfiguration = QUICConfiguration(registration, ["this"], consume settings, credentials)?

        let onConnected: ConnectedNotify iso = object iso is ConnectedNotify
          let _t: TestHelper = t
          fun ref apply(data: ConnectedData val) =>
              Println("client connected")
             _t.complete_action("client connected")
        end
        let onShutdown: ShutdownCompleteNotify iso = object iso is ShutdownCompleteNotify
          let _t: TestHelper = t
          fun ref apply(data: ShutdownCompleteData) =>
            Println("client disconnected")
             _t.complete_action("client disconnected")
        end
        let errorNotify: ErrorNotify iso = object iso is ErrorNotify
          let _t: TestHelper = t
          fun ref apply(ex: Exception) =>
             _t.fail(ex.string())
             _t.complete(true)
        end
        let closeNotify: CloseNotify iso = object iso is CloseNotify
          let _t: TestHelper = t
          let _configuration: QUICConfiguration = configuration
          fun ref apply() =>
            Println("closed")
            _configuration.close()
        end
        try
          let client = NewQUICConnection(registration, configuration, "127.0.0.1", 9090)?
          custodian(client)
          client.subscribe(consume errorNotify)
          client.subscribe(consume onConnected)
          client.subscribe(consume onShutdown)
          client.subscribe(consume closeNotify)
          @print_pointer(addressof client.connectionCallback)

          //client.close()
          Println("All Subscriptions")
        else
          t.fail("Client Creation Error")
          configuration.close()
        end
      else
        t.fail("Configuration Error")
      end
    else
      t.fail("Registration Error")
    end
