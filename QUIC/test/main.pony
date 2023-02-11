use "pony_test"
use ".."
actor Main is TestList
  new create(env: Env) =>
    PonyTest(env, this)
  new make () =>
    None
  fun tag tests(test: PonyTest) =>
    test(_TestRegistrationCreation)


class iso _TestRegistrationCreation is UnitTest
    fun name(): String => "Testing Registration Creation"
    fun apply(t: TestHelper) =>
      try
        let registration = QUICRegistration(t.env.root, "test")?
      else
        t.fail("Registration Error")
      end
