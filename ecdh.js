var crypto = require('crypto')
var ecdh = crypto.createECDH('secp256k1')

module.exports = function (aPriv, bPub) {
  ecdh.setPrivateKey(aPriv, 'hex')
  return ecdh.computeSecret(bPub, 'hex')
}

