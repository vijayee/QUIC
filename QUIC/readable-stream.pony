use "Streams"
use "Exception"
use @quic_free[None](ptr: Pointer[None] tag)
actor QUICReadableStream is ReadablePushStream[Array[U8] iso]
  var _readable: Bool = true
  var _isDestroyed: Bool = false
  let _subscribers': Subscribers
  var _pipeNotifiers': (Array[Notify tag] iso | None) = None
  var _isPiped: Bool = false
  let _auto: Bool = false
  let _ctx: Pointer[None] tag

  new create(ctx: Pointer[None] tag) =>
    _subscribers' = Subscribers(3)
    _ctx = ctx

  fun _final() =>
    @quic_free(_ctx)

  fun readable(): Bool =>
    _readable

  fun destroyed(): Bool =>
    _isDestroyed

  fun ref isPiped(): Bool =>
    _isPiped

  fun ref pipeNotifiers(): (Array[Notify tag] iso^ | None) =>
    _pipeNotifiers' = None

  fun ref autoPush(): Bool =>
    _auto

  fun ref subscribers() : Subscribers =>
    _subscribers'

  be _receive(event: Pointer[None] tag) =>
    let data: Array[U8] iso = recover
      let size: U64 = @quic_stream_get_total_buffer_length(event)
      let buffer: Pointer[U8] = @pony_alloc(@pony_ctx(), size.usize())
      @quic_stream_get_total_buffer(event, buffer, stream)
      let data' = Array.cpointer(buffer, size)
      data'
    end
    notifyData(consume data)

  be push() =>
    if destroyed() then
      notifyError(Exception("Stream has been destroyed"))
    else
      None
      //notifyData(consume chunk)
    end

  be read(cb: {(Array[U8] iso)} val, size: (USize | None) = None) =>
    if destroyed() then
      notifyError(Exception("Stream has been destroyed"))
    else
      var size' = match size
      | None => _buffer.size()
      | let size'': USize => size''
      end
      size' = size'.min(_buffer.size())

      let data = recover Array[U8](size') end
      let stop = _buffer.head() + size'
      try
        for i in Range(_buffer.head(), stop) do
          data.push(_buffer(i)?)
        end
        cb(consume data)
        try
          if stop < _buffer.size() then
            let buf = Array[U8](_buffer.size() - stop)
            for i' in Range(stop, _buffer.size()) do
              buf.push(_buffer(i')?)
            end
            _buffer.clear()
            for i'' in buf.values() do
              _buffer.push(i'')
            end
          end
        else
          notifyError(Exception("Failed to reset buffer"))
        end
      else
        notifyError(Exception("Failed to read buffer"))
      end
    end

  be pipe(stream: WriteablePushStream[Array[U8] iso] tag) =>
    if destroyed() then
      notifyError(Exception("Stream has been destroyed"))
    else
      let pipeNotifiers': Array[Notify tag] iso = try
         pipeNotifiers() as Array[Notify tag] iso^
      else
        let pipeNotifiers' = recover Array[Notify tag] end
        consume pipeNotifiers'
      end

      let pipedNotify: PipedNotify iso =  object iso is PipedNotify
        let _stream: ReadablePushStream[Array[U8] iso] tag = this
        fun ref apply() =>
          _stream.push()
      end
      let pipedNotify': PipedNotify tag = pipedNotify
      pipeNotifiers'.push(pipedNotify')
      stream.subscribe(consume pipedNotify)

      let errorNotify: ErrorNotify iso = object iso  is ErrorNotify
        let _stream: ReadablePushStream[Array[U8] iso] tag = this
        fun ref apply (ex: Exception) => _stream.destroy(ex)
      end
      let errorNotify': ErrorNotify tag = errorNotify
      pipeNotifiers'.push(errorNotify')
      stream.subscribe(consume errorNotify)

      let closeNotify: CloseNotify iso = object iso  is CloseNotify
        let _stream: ReadablePushStream[Array[U8] iso] tag = this
        fun ref apply () => _stream.close()
      end
      let closeNotify': CloseNotify tag = closeNotify
      pipeNotifiers'.push(closeNotify')
      stream.subscribe(consume closeNotify)

      _pipeNotifiers' = consume pipeNotifiers'
      stream.piped(this)
      _isPiped = true
      notifyPipe()
    end

  be destroy(message: (String | Exception)) =>
    match message
      | let message' : String =>
        notifyError(Exception(message'))
      | let message' : Exception =>
        notifyError(message')
    end
    _isDestroyed = true
    let subscribers': Subscribers = subscribers()
    subscribers'.clear()

  be close() =>
    if not destroyed() then
      _isDestroyed = true
      notifyClose()
      let subscribers': Subscribers = subscribers()
      subscribers'.clear()
      _pipeNotifiers' = None
      _isPiped = false
    end

  fun ref notifyData(data: Array[U8] iso) =>
    try
      let subscribers': Subscribers  = subscribers()
      var notify'': (DataNotify[Array[U8] iso] | None) =  None
      let onces = Array[USize](subscribers'.size())

      var i: USize = 0
      for notify in subscribers'(DataKey[Array[U8] iso])?.values() do
        match notify
        |  (let notify': DataNotify[Array[U8] iso], let once: Bool) =>
            notify'' = notify'
            if once then
              onces.push(i)
            end
            break
        end
        i = i + 1
      end

      match notify''
        | let notify''': DataNotify[Array[U8] iso] =>
          if _buffer.size() > 0 then
            try
              data' = recover Array[U8](_buffer.size() + data.size()) end
              for i' in Range(_buffer.head(), _buffer.head() + _buffer.size()) do
                data'.push(_buffer(i')?)
              end
              for i'' in data.values() do
                data'.push(i'')
              end
              notify'''(consume data')
              _buffer.clear()
            else
              notifyError(Exception("Error copying buffer"))
            end
          else
            notify'''(consume data)
          end
        else
          let overflow = for i' in data.values() do
            _buffer.push(i')
          end
          if overflow then
            _notifyOverflow()
          end
      end
      if onces.size() > 0 then
        discardOnces(subscribers'(DataKey[Array[U8] iso])?, onces)
      end
    end
