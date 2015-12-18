
var Buffer = require('buffer').Buffer
var crypto = require('crypto')
var typeforce = require('typeforce')
var extend = require('xtend')

var IV_SIZE = 16
var KEY_SIZE = 32
var ALGORITHM = 'aes-256-ctr'


module.exports = {
  /*
   * @return Buffer (format: iv|ciphertext)
   */
  encrypt: function (opts, cb) {
    if (opts.iv) {
      if (opts.iv.length !== IV_SIZE) {
        return cb(new Error('invalid IV size'))
      }

      return run()
    }

    opts = extend(opts)
    crypto.randomBytes(IV_SIZE, function (err, iv) {
      if (err) return cb(err)

      opts.iv = iv
      run()
    })

    function run () {
      runCipherOp('createCipheriv', opts, cb)
    }
  },
  /*
   * input data should be of the format returned
   * by the above encrypt method
   */
  decrypt: runCipherOp.bind(null, 'createDecipheriv')
}

function runCipherOp (createCipherMethod, opts, cb) {
  typeforce('String', createCipherMethod)
  typeforce({
    data: 'Buffer',
    key: 'Buffer',
    pieceSize: '?Number',
    iv: '?Buffer'
  }, opts)

  if (opts.key.length !== KEY_SIZE) {
    return cb(new Error('invalid key size'))
  }

  var input = opts.data
  var iv = opts.iv
  var bufs = []
  if (createCipherMethod === 'createDecipheriv') {
    if (iv) return cb(new Error('expected "iv" as part of "data"'))

    iv = input.slice(0, IV_SIZE)
    input = input.slice(IV_SIZE)
  } else {
    bufs.push(iv)
  }

  var cipher = crypto[createCipherMethod](ALGORITHM, opts.key, iv)
  var pieceSize = opts.pieceSize || input.length
  var offset = 0
  var isLastOne

  iterate()

  /**
   * if pieceSize is indicated, will yield (setTimeout)
   * between encryptions of pieceSize sized pieces
   *
   * @return {[type]} [description]
   */
  function iterate () {
    var bytes
    if (input.length - offset <= pieceSize) {
      bytes = input.slice(offset)
      isLastOne = true
    } else {
      bytes = input.slice(offset, offset + pieceSize)
      offset += pieceSize
    }

    bufs.push(cipher.update(bytes))
    if (!isLastOne) return setTimeout(iterate, 0)

    bufs.push(cipher.final())
    cb(null, Buffer.concat(bufs))
  }
}
