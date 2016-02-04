const crypto = require('crypto')
const ecdh = crypto.createECDH('secp256k1')
const ECKey = require('@tradle/bitcoinjs-lib').ECKey
const syncECDH = require('./sync-ecdh')

var utils = module.exports = {
  ecKeyToString: function (key) {
    var ad = typeof key.toWIF === 'function' ? key.d : key
    return padHexToLength(ad.toString(16), 64)
  },

  ecKeyStringFromWIF: function (priv) {
    return utils.ecKeyToString(ECKey.fromWIF(priv))
  },

  syncECDH: syncECDH,

  sharedEncryptionKey: function (aPriv, bPub) {
    var secret = utils.syncECDH(aPriv, bPub)
    return crypto.createHash('sha256').update(secret).digest()
  }
}

function padHexToLength (hex, length) {
  // pad to 64 bytes
  while (hex.length % length !== 0) {
    hex = '0' + hex
  }

  return hex
}
