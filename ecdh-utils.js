const crypto = require('crypto')
const ecdh = crypto.createECDH('secp256k1')
const ECKey = require('@tradle/bitcoinjs-lib').ECKey

var utils = module.exports = {
  ecKeyToString: function (key) {
    var ad = typeof key.toWIF === 'function' ? key.d : key
    return utils.padToEven(ad.toString(16))
  },

  ecKeyStringFromWIF: function (priv) {
    return utils.ecKeyToString(ECKey.fromWIF(priv))
  },

  padToEven: function (hex) {
    // pad to an even number of bytes
    return hex.length % 2 === 0 ? hex : '0' + hex
  },

  syncECDH: function (priv, pub) {
    ecdh.setPrivateKey(priv, 'hex')
    var secret = ecdh.computeSecret(pub, 'hex')
    return crypto.createHash('sha256').update(secret).digest()
  }
}
