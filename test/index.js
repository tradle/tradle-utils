var crypto = require('crypto')
var test = require('tape')
var bufferEqual = require('buffer-equal')
var ECKey = require('@tradle/bitcoinjs-lib').ECKey
var nativeECDH = require('../ecdh')
var browserECDH = require('../ecdh-browser')
var utils = require('../')
require('./ecdh-async')

test('aes encrypt/decrypt with password', function (t) {
  t.plan(2)

  var buf = crypto.randomBytes(32)
  var key = crypto.randomBytes(32)
  var encrypted = utils.encrypt(buf, key)
  var decrypted = utils.decrypt(encrypted, key)

  t.ok(!bufferEqual(buf, encrypted))
  t.ok(bufferEqual(buf, decrypted))

  buf = crypto.randomBytes(128)
// t.ok(bufferEqual(buf, utils.fileToBuf(utils.fileToString(buf))))
})

test('aes encrypt/decrypt with key', function (t) {
  t.plan(1)

  var plaintext = crypto.randomBytes(1000)
  var key = crypto.randomBytes(32)
  utils.encryptAsync({
    data: plaintext,
    key: key,
    pieceSize: 32
  }, function (err, ciphertext) {
    if (err) throw err

    utils.decryptAsync({
      data: ciphertext,
      key: key,
      pieceSize: 20
    }, function (err, decrypted) {
      if (err) throw err

      t.ok(bufferEqual(decrypted, plaintext))
    })
  })
})

test('ecdh', function (t) {
  var a = ECKey.makeRandom()
  var b = ECKey.makeRandom()

  // pass in strings
  var sharedSecret = utils.sharedEncryptionKey(a.d, b.pub.toHex())

  ;[nativeECDH, browserECDH].forEach(function (impl) {
    utils.ecdh = impl
    var ab = utils.sharedEncryptionKey(a.d, b.pub.toHex())
    var ba = utils.sharedEncryptionKey(b.d, a.pub.toHex())
    var fromWIF = utils.sharedEncryptionKey(a.toWIF(), b.pub.toHex())
    var fromECKey = utils.sharedEncryptionKey(a, b.pub.toHex())
    var fromECPubKey = utils.sharedEncryptionKey(a, b.pub)

    ;[ab, ba, fromWIF, fromECKey, fromECPubKey].forEach(function (val) {
      t.deepEqual(val, sharedSecret)
    })
  })

  t.end()
})

// test('new ecdh vs old', function (t) {
//   t.plan(1)

//   var a = ECKey.makeRandom()
//   var b = ECKey.makeRandom()

//   // var ab = a.pub.Q.multiply(b.d).getEncoded()
//   // var ba = b.pub.Q.multiply(a.d).getEncoded()

//   var ab = utils.sharedSecret(a.d, b.pub)
//   var ba = utils.sharedSecretOld(b.d, a.pub)

//   t.ok(bufferEqual(ab, ba))
// })
