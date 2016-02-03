
var utils = require('../')
var test = require('tape')
var ECKey = require('@tradle/bitcoinjs-lib').ECKey

if (process.env.WORKERS_ENABLED) {
  console.log('testing with workers')
}

test('ecdh (async)', function (t) {
  var a = ECKey.makeRandom()
  var b = ECKey.makeRandom()

  // pass in strings
  var expected = utils.sharedEncryptionKey(a.d, b.pub.toHex())
  utils.sharedEncryptionKey(a.d, b.pub.toHex(), check)
  utils.sharedEncryptionKey(a.d, b.pub.toHex(), check)
  utils.sharedEncryptionKey(a.toWIF(), b.pub.toHex(), check)
  utils.sharedEncryptionKey(a, b.pub.toHex(), check)
  utils.sharedEncryptionKey(a, b.pub, check)

  var togo = 5

  function check (err, result) {
    if (err) throw err

    t.deepEqual(result, expected)
    if (--togo === 0) {
      t.end()
      utils.destroy()
    }
  }
})
