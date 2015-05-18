'use strict';

var assert = require('assert');
var createTorrent = require('create-torrent');
var parseTorrent = require('parse-torrent');
var crypto = require('crypto');
var defaults = require('defaults');
var stringify = require('json-stable-stringify');

var utils = {
  createTorrent: function(data, options, callback) {
    if (typeof data === 'string') console.warn('Interpreting data as file path: ' + data);

    if (typeof options === 'function') {
      callback = options;
      options = null;
    }

    var name = utils.getTorrentName(data);
    options = defaults(options || {}, {
      name: name
    });

    assert(options.name === name, 'Torrent name must be ' + name);

    createTorrent(data, options, function(err, torrent) {
      if (err) return callback(err);

      callback(null, parseTorrent(torrent));
    });
  },

  getInfoHash: function(data, callback) {
    utils.createTorrent(data, function(err, torrent) {
      if (err) return callback(err);

      callback(null, torrent.infoHash);
    });
  },

  getTorrentName: function(val) {
    return crypto.createHash('sha256').update(val).digest('hex');
  },

  httpError: function(code, msg) {
    var err = new Error(msg);
    err.code = code;
    return err;
  },

  isTruthy: function(val) {
    if (typeof val === 'undefined' || val === null || val === false) return false;
    if (val instanceof Number) return !!val;

    return val !== '0' && val !== 'false';
  },

  proxyFunctions: function(proxy, source) {
    for (var p in source) {
      if (!proxy[p] && typeof source[p] === 'function')
        proxy[p] = source[p].bind(source);
    }
  },

  bindPrototypeFunctions: function(obj) {
    // bind all prototype functions to self
    var proto = obj.constructor.prototype;
    for (var p in proto) {
      var val = proto[p];
      if (typeof val === 'function')
        obj[p] = obj[p].bind(obj);
    }
  },

  prettify: function(obj) {
    if (typeof obj === 'string') return obj;

    return stringify(obj, { space: 2 });
  },

  stringify: function(obj) {
    if (typeof obj === 'string') return obj;

    return stringify(obj);
  }
}

module.exports = utils;
