use "pony_test"
use "../../.."
use "Streams"
use "Exception"
use "Print"

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

primitive LoremIpsum
  fun apply(): Array[U8 val] iso^ =>
    let text: String iso = recover String().>append("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Morbi et velit bibendum, suscipit ipsum eu, commodo ligula. Praesent eu facilisis nulla. Nam ipsum velit, tempus eget risus a, consectetur egestas mauris. Vestibulum ac pulvinar nulla. Nulla vestibulum nibh enim. Curabitur quis aliquam justo. Pellentesque ut volutpat quam. Maecenas tempor velit sed dui aliquam ultricies. In non odio vel quam ornare gravida.

Donec molestie sapien id massa fringilla convallis. Vestibulum blandit feugiat nulla, nec lobortis urna ultrices ut. Etiam purus augue, convallis quis maximus a, lacinia sit amet nulla. Proin lectus nisl, lacinia nec blandit ut, imperdiet in augue. Proin ac porta purus. Etiam quis dui sagittis, rhoncus metus semper, porta neque. Fusce ipsum nisl, semper sit amet luctus non, consequat id libero. Vivamus sit amet ante urna. Nunc posuere, turpis vel porta sagittis, nunc nunc imperdiet odio, sit amet volutpat tellus ipsum vel ligula. Donec neque elit, tempus molestie laoreet nec, efficitur id eros.") end
    (consume text).iso_array()

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
    t.expect_action("stream opened")
    t.expect_action("stream closed")
    t.expect_action("data received")
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
        let configuration: QUICConfiguration = QUICConfiguration(registration, ["sample"], consume settings, credentials)?
        try

          let client = NewQUICConnection(registration, configuration)?
          Println("got this far")
          custodian(client)
          let onConnected: ConnectedNotify iso = object iso is ConnectedNotify
            let _t: TestHelper = t
            let connection: QUICConnection = client
            fun ref apply(data: ConnectedData val) =>
              Println("client connected")
              _t.complete_action("client connected")
              connection.openStream({(stream: (QUICDuplexStream | Exception))=>
                match stream
                  | let stream': QUICDuplexStream =>
                    Println("stream opened")
                    _t.complete_action("stream opened")
                    let onClose: CloseNotify iso = object iso is CloseNotify
                      let _t: TestHelper = _t
                      fun ref apply() =>
                        _t.complete_action("stream closed")
                    end
                    let onError: ErrorNotify iso = object iso is ErrorNotify
                      let _t: TestHelper = _t
                      fun ref apply(ex: Exception) =>
                        _t.complete_action(ex.string())
                        _t.complete(true)
                    end
                    let onData: DataNotify[Array[U8] iso] iso = object iso is DataNotify[Array[U8] iso]
                      let _t: TestHelper = _t
                      fun ref apply(data: Array[U8] iso) =>
                        _t.complete_action("data received")
                    end

                    stream'.subscribe(consume onClose)
                    stream'.subscribe(consume onError)
                    stream'.subscribe(consume onData)
                    stream'.write(LoremIpsum())
                  | let ex: Exception =>
                    _t.fail(ex.string())
                    _t.complete(true)
                end
              } val)
          end
          let onShutdown: ShutdownCompleteNotify iso = object iso is ShutdownCompleteNotify
            let _t: TestHelper = t
            fun ref apply(data: ShutdownCompleteData) =>
              Println("client disconnected")
              _t.complete_action("client disconnected")
          end
          let onShutdownInitiatedByTransport: ShutdownInitiatedByTransportNotify iso = object iso is ShutdownInitiatedByTransportNotify
            fun ref apply(data: ShutdownInitiatedByTransportData) =>
              Println("Error Code: " + data.errorCode.string())
              Println("Status: " + data.status.string())
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
              _t.complete(true)
              _configuration.close()
          end
          client.subscribe(consume errorNotify)
          client.subscribe(consume onConnected)
          client.subscribe(consume onShutdown)
          client.subscribe(consume closeNotify)
          client.subscribe(consume onShutdownInitiatedByTransport)
          client.start ("127.0.0.1", 4567)

          //client.close()
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
