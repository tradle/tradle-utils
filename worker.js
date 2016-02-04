
var bitcoin = require('@tradle/bitcoinjs-lib')
var ecdhUtils = require('./ecdh-utils')

process.on('message', function (data) {
  try {
    switch (data.cmd) {
      case 'ecdh':
        process.send({
          data: ecdh(data.data)
        })

        break
      case 'decompress':
        process.send({
          data: decompress(data.data)
        })

        break
      default:
        throw new Error('unknown command: ' + data.cmd)
        break
    }
  } catch (err) {
    process.send({
      error: {
        message: err.message,
        stack: err.stack
      }
    })
  }
})

function ecdh (data) {
  if (data.wif) {
    data.priv = ecdhUtils.ecKeyStringFromWIF(data.wif)
  }

  return ecdhUtils.sharedEncryptionKey(data.priv, data.pub).toString('hex')
}

function decompress (pubHex) {
  var pub = bitcoin.ECPubKey.fromHex(pubHex)
  if (!pub.compressed) return pubHex

  pub.compressed = false
  return pub.toHex()
}
