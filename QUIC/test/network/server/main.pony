use "pony_test"
use "../../.."
use "Streams"
use "Exception"
use "Print"

actor Main
  new create(env: Env) =>
    PonyTest(env, RunServer)

actor RunServer is TestList
  fun tag tests(test: PonyTest) =>
    test(_TestServer)

class iso _TestServer is UnitTest
    fun name(): String => "Testing Server Creation"
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

        let certificate: QUICCertificate = QUICCertificate("./server1.crt", "./server1.key")
        let credentials: QUICCredentials = QUICCredentials(certificate)
        try
          let configuration: QUICConfiguration = QUICConfiguration(registration, ["this"], consume settings, credentials)?
          let listenerStarted: ListenerStartedNotify iso = object iso is ListenerStartedNotify
            let _t: TestHelper = t
            fun ref apply() =>
                Println("listener started")
               _t.complete_action("listener started")
          end
          let listenerStopped: ListenerStoppedNotify iso = object iso is ListenerStoppedNotify
            let _t: TestHelper = t
            fun ref apply() =>
              Println("listener stopped")
               _t.complete_action("listener stopped")
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
            let server = NewQUICServer(registration, configuration)?
            server.subscribe(consume errorNotify)
            server.subscribe(consume listenerStarted)
            server.subscribe(consume listenerStopped)
            server.subscribe(consume closeNotify)
            server.listen(9090)
            //server.stopListening()
           //server.close()
          else
            t.fail("Server Creation Error")
            configuration.close()
          end
        else
          t.fail("Configuration Error")
        end
      else
        t.fail("Registration Error")
      end
      t.complete(true)
