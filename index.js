
'use strict';

var assert = require('assert');
var createTorrent = require('create-torrent');
var parseTorrent = require('parse-torrent');
var crypto = require('crypto');
var defaults = require('defaults');

var utils = {
  createTorrent: function(data, options, callback) {
    if (typeof data === 'string') console.warn('Interpreting data as file path: ' + data);
    
    if (typeof options === 'function') {
      callback = options;
      options = null;
    }

    var name = utils.getTorrentName(data);
    options = defaults(options || {}, { name: name });

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
  }
}

module.exports = utils;