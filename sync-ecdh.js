var crypto = require('crypto')
var ecdh = crypto.createECDH('secp256k1')

module.exports = function syncECDH (priv, pub) {
  ecdh.setPrivateKey(priv, 'hex')
  return ecdh.computeSecret(pub, 'hex')
}
