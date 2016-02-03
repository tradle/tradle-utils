var crypto = require('crypto')
var ecdh = crypto.createECDH('secp256k1')

module.exports = function syncECDH (priv, pub) {
  ecdh.setPrivateKey(priv, 'hex')
  var secret = ecdh.computeSecret(pub, 'hex')
  return crypto.createHash('sha256').update(secret).digest()
}
