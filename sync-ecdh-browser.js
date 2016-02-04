var bitcoin = require('@tradle/bitcoinjs-lib')
var bn = require('bn.js')
var ec = require('elliptic').ec('secp256k1')
var ecdhUtils = require('./ecdh-utils')

module.exports = function (aPriv, bPub) {
  var ecA = ec.keyPair({ priv: aPriv, privEnc: 'hex' })
  var ecB = ec.keyFromPublic(bPub, 'hex')
  var sharedSecret = ecA.derive(ecB.getPublic())
  // pad to 64 bytes
  // https://github.com/indutny/bn.js/issues/22
  return new Buffer(sharedSecret.toString('hex', 64), 'hex')
}
