const path = require('path')
const crypto = require('crypto')
const bitcoin = require('@tradle/bitcoinjs-lib')
const extend = require('xtend')
const ecdhUtils = require('./ecdh-utils')

var cluster
var computecluster
var cc
var WORKERS_ENABLED
try {
  cluster = require('cluster')
  computecluster = require('compute-cluster')
  cc = new computecluster({
    module: path.resolve(__dirname, './worker.js'),
    max_backlog: Infinity
  })

  // only if cluster is available
  WORKERS_ENABLED = process.env.WORKERS_ENABLED
} catch (err) {}

module.exports = performECDH

function performECDH (aPriv, bPub, cb) {
  if (typeof bPub !== 'string') bPub = bPub.toHex()
  if (!cb) {
    if (typeof aPriv === 'string') {
      aPriv = ecdhUtils.ecKeyStringFromWIF(aPriv)
    } else {
      aPriv = ecdhUtils.ecKeyToString(aPriv)
    }

    return ecdhUtils.sharedEncryptionKey(aPriv, bPub)
  }

  if (!WORKERS_ENABLED) {
    return process.nextTick(function () {
      cb(null, performECDH(aPriv, bPub))
    })
  }

  var data = {
    pub: bPub
  }

  var msg = {
    cmd: 'ecdh',
    data: data
  }

  if (typeof aPriv === 'string') data.wif = aPriv
  else data.priv = ecdhUtils.ecKeyToString(aPriv)

  cc.enqueue(msg, function (err, result) {
    if (err) return cb(err)

    if (result.error) {
      err = extend(new Error(result.error.message), result.error)
      return cb(err)
    }

    cb(null, new Buffer(result.data, 'hex'))
  })
}

if (WORKERS_ENABLED) {
  module.exports.close = cc.exit.bind(cc)
}
