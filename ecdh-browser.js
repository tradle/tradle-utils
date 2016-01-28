var bitcoin = require('@tradle/bitcoinjs-lib')
var bn = require('bn.js')
var ec = require('elliptic').ec('secp256k1')
var ecdhUtils = require('./ecdh-utils')

module.exports = function (aPriv, bPub) {
  if (typeof bPub !== 'string') bPub = bPub.toHex()
  if (typeof aPriv === 'string') {
    aPriv = ecdhUtils.ecKeyStringFromWIF(aPriv)
  } else {
    aPriv = ecdhUtils.ecKeyToString(aPriv)
  }

  var ecA = ec.keyPair({ priv: new bn(aPriv, 16) })
  var ecB = ec.keyFromPublic(bPub, 'hex')
  var sharedSecret = ecA.derive(ecB.getPublic())
  // pad to an even number of bytes
  // https://github.com/indutny/bn.js/issues/22
  return new Buffer(sharedSecret.toString('hex', 2), 'hex')
}
