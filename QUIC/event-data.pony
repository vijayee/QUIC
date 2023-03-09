class ConnectedData
  let sessionResumed: Bool
  let negotiatedAlpn: Array[U8]
  new val create(sessionResumed': Bool, negotiatedAlpn': Array[U8] val) =>
    sessionResumed = sessionResumed'
    negotiatedAlpn = negotiatedAlpn;
