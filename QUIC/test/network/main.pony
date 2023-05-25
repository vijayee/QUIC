use "pony_test"
use "../.."
actor Main is TestList
  new create(env: Env) =>
    PonyTest(env, this)
  new make () =>
    None
  fun tag tests(test: PonyTest) =>
    test(_TestServer)


class iso _TestServer is UnitTest
    fun name(): String => "Testing Server Creation"
    fun apply(t: TestHelper) =>
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
          //configuration.close()
          let server = QUICServer(registration, configuration)
          server.listen(9090)
          //server.close()
        else
          t.fail("Configuration Error")
        end
      else
        t.fail("Registration Error")
      end
      t.complete(true)
