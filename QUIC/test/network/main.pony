use "pony_test"
use "../.."
use "Streams"
use "Exception"
use "Print"
use "cli"
actor Main
  new create(env: Env) =>
    var isClient: Bool = false
    for data in env.vars.values() do
      Println(data)
    end
    for arg in env.args.values() do
      if (arg == "client") then
        isClient = true
        break
      end
    end
    if isClient then
      PonyTest(env, RunClient)
    else
      PonyTest(env, RunServer)
    end


actor RunClient is TestList
  fun tag tests(test: PonyTest) =>
    test(_TestClient)
actor RunServer is TestList
  fun tag tests(test: PonyTest) =>
    test(_TestServer)
