var crypto = require('crypto')
var test = require('tape')
var bufferEqual = require('buffer-equal')
var ECKey = require('bitcoinjs-lib').ECKey
var utils = require('../')

test('aes encrypt/decrypt', function (t) {
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

test('ecdh', function (t) {
  var a = ECKey.makeRandom()
  var b = ECKey.makeRandom()

  // var ab = a.pub.Q.multiply(b.d).getEncoded()
  // var ba = b.pub.Q.multiply(a.d).getEncoded()

  // pass in strings
  var ab = utils.sharedEncryptionKey(a.d, b.pub.toHex())
  var ba = utils.sharedEncryptionKey(b.d, a.pub.toHex())
  var fromWIF = utils.sharedEncryptionKey(a.toWIF(), b.pub.toHex())
  var fromECKey = utils.sharedEncryptionKey(a, b.pub.toHex())
  var fromECPubKey = utils.sharedEncryptionKey(a, b.pub)

  t.ok(bufferEqual(ab, ba))
  t.ok(bufferEqual(ab, fromWIF))
  t.ok(bufferEqual(ab, fromECKey))
  t.ok(bufferEqual(ab, fromECPubKey))

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
