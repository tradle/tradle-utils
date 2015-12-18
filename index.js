'use strict'

var assert = require('assert')
var crypto = require('crypto')
var createTorrent = require('create-torrent')
var parseTorrent = require('parse-torrent')
var defaults = require('defaults')
var stringify = require('json-stable-stringify')
var bitcoin = require('@tradle/bitcoinjs-lib')
var ec = require('elliptic').ec('secp256k1')
var bn = require('bn.js')
var typeforce = require('typeforce')
var extend = require('xtend')

var CIPHERTEXT_ENCODING = 'base64'
var PLAINTEXT_ENCODING = 'utf8'
var SYMMETRIC_ENCRYPTION_ALGO = 'aes-256-ctr'
var DHT_MSG_REGEX = /^d1:(.?d2:id20:|eli20)/

var IV_SIZE = 16
var KEY_SIZE = 32
var utils = {
  ENCRYPTION_PIECE_SIZE: 10240, // 10KB
  /*
   * @return Buffer (format: iv|ciphertext)
   */
  encryptAsync: function (opts, cb) {
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
  decryptAsync: runCipherOp.bind(null, 'createDecipheriv'),
  createTorrent: function (data, options, callback) {
    if (typeof data === 'string') console.warn('Interpreting data as file path: ' + data)

    if (typeof options === 'function') {
      callback = options
      options = null
    }

    var name = utils.getTorrentName(data)
    options = defaults(options || {}, {
      name: name
    })

    assert(options.name === name, 'Torrent name must be ' + name)

    createTorrent(data, options, function (err, torrent) {
      if (err) return callback(err)

      callback(null, parseTorrent(torrent))
    })
  },

  getInfoHash: function (data, callback) {
    utils.createTorrent(data, function (err, torrent) {
      if (err) return callback(err)

      callback(null, torrent.infoHash)
    })
  },

  getStorageKeyFor: function (data, callback) {
    utils.getInfoHash(data, function (err, infoHash) {
      callback(err, new Buffer(infoHash, 'hex'))
    })
  },

  getTorrentName: function (val) {
    return crypto.createHash('sha256').update(val).digest('hex')
  },

  httpError: function (code, msg) {
    var err = new Error(msg)
    err.code = code
    return err
  },

  isTruthy: function (val) {
    if (typeof val === 'undefined' || val === null || val === false) return false
    if (val instanceof Number) return !!val

    return val !== '0' && val !== 'false'
  },

  requireOption: function (options, option) {
    if (!(option in options)) throw new Error('Missing required option: ' + option)

    return options[option]
  },

  requireOptions: function (options /* [, option1, option2, ...] */) {
    [].slice.call(arguments, 1).map(function (arg) {
      utils.requireOption(options, arg)
    })
  },

  proxyFunctions: function (proxy, source) {
    for (var p in source) {
      if (!proxy[p] && typeof source[p] === 'function') {
        proxy[p] = source[p].bind(source)
      }
    }
  },

  bindPrototypeFunctions: function (obj) {
    // bind all prototype functions to self
    var proto = obj.constructor.prototype
    for (var p in proto) {
      var val = proto[p]
      if (typeof val === 'function') {
        obj[p] = obj[p].bind(obj)
      }
    }
  },

  requireParam: function (paramName, paramValue) {
    if (typeof paramValue === 'undefined') throw new Error('Missing required parameter: ' + paramName)

    return paramValue
  },

  prettify: function (obj) {
    if (typeof obj === 'string') return obj

    return stringify(obj, { space: 2 })
  },

  stringify: function (obj) {
    if (typeof obj === 'string') return obj

    return stringify(obj)
  },

  getAddressFromInput: function (input, networkName) {
    var pub
    try {
      pub = bitcoin.ECPubKey.fromBuffer(input.script.chunks[1])
      return pub.getAddress(bitcoin.networks[networkName]).toString()
    } catch (err) {
    }
  },

  getAddressFromOutput: function (output, networkName) {
    if (bitcoin.scripts.classifyOutput(output.script) === 'pubkeyhash') {
      return bitcoin.Address
        .fromOutputScript(output.script, bitcoin.networks[networkName])
        .toString()
    }
  },

  getOpReturnData: function (tx) {
    if (typeof tx === 'string') tx = bitcoin.Transaction.fromHex(tx)
    else if (Buffer.isBuffer(tx)) tx = bitcoin.Transaction.fromBuffer(tx)

    for (var i = 0, l = tx.outs.length; i < l; i++) {
      var out = tx.outs[i]
      if (bitcoin.scripts.isNullDataOutput(out.script)) {
        return out.script.chunks[1]
      }
    }
  },

  sharedSecret: function (aPriv, bPub) {
    if (typeof aPriv === 'string') aPriv = bitcoin.ECKey.fromWIF(aPriv)
    if (typeof bPub !== 'string') bPub = bPub.toHex()

    var ad = typeof aPriv.toWIF === 'function' ? aPriv.d : aPriv

    // elliptic is 10x faster at ECDH
    var ecA = ec.keyPair({ priv: new bn(ad.toString(16), 16) })
    var ecB = ec.keyFromPublic(bPub, 'hex')
    var sharedSecret = ecA.derive(ecB.getPublic())
    var buf = new Buffer(sharedSecret.toString('hex', 2), 'hex')
    return buf
  },

  // sharedSecretOld: function (aPriv, bPub) {
  //   if (typeof aPriv === 'string') aPriv = bitcoin.ECKey.fromWIF(aPriv)
  //   if (typeof bPub === 'string') bPub = bitcoin.ECPubKey.fromHex(bPub)

  //   aPriv = aPriv.d || aPriv
  //   var shared = bPub.Q.multiply(aPriv).getEncoded(true)
  //   // cut off version byte 0x02/0x03
  //   // https://github.com/cryptocoinjs/ecurve/blob/master/lib/point.js#L207
  //   if (shared.length === 33) shared = shared.slice(1)

  //   return shared
  // },

  sharedEncryptionKey: function (aPriv, bPub) {
    var sharedSecret = utils.sharedSecret(aPriv, bPub)
    return crypto.createHash('sha256').update(sharedSecret).digest()
  },

  encrypt: function (text, password) {
    assert(text && password, 'text and password are both required')

    var cipher = crypto.createCipher(SYMMETRIC_ENCRYPTION_ALGO, password)
    return updateCipher(cipher, text)
  },

  decrypt: function (text, password) {
    assert(text && password, 'text and password are both required')

    var decipher = crypto.createDecipher(SYMMETRIC_ENCRYPTION_ALGO, password)
    return updateDecipher(decipher, text)
  },

  isDHTMessage: function (msg) {
    return DHT_MSG_REGEX.test(msg)
  },

  newMsgNonce: function (cb) {
    crypto.randomBytes(32, function (err, bytes) {
      cb(err, bytes && bytes.toString('base64'))
    })
  }
}

function updateCipher (cipher, data) {
  if (Buffer.isBuffer(data)) return Buffer.concat([cipher.update(data), cipher.final()])
  else return cipher.update(data, 'utf8', 'base64') + cipher.final('base64')
}

function updateDecipher (decipher, data) {
  if (Buffer.isBuffer(data)) return Buffer.concat([decipher.update(data), decipher.final()])
  else return decipher.update(data, 'base64', 'utf8') + decipher.final('utf8')
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

  var cipher = crypto[createCipherMethod](SYMMETRIC_ENCRYPTION_ALGO, opts.key, iv)
  var pieceSize = opts.pieceSize || utils.ENCRYPTION_PIECE_SIZE
  pieceSize = Math.min(pieceSize, input.length)

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

module.exports = utils
