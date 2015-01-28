'use strict';

var assert = require('assert');
var createTorrent = require('create-torrent');
var parseTorrent = require('parse-torrent');
var crypto = require('crypto');
var defaults = require('defaults');
var fs = require('fs');
var path = require('path');
var mkdirp = require('mkdirp');

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

  requireOption: function(options, option) {
    if (!(option in options)) throw new Error('Missing required option: ' + option);

    return options[option];
  },

  requireOptions: function(options /*, option1, option2... */ ) {
    [].slice.call(arguments, 1).map(function(arg) {
      utils.requireOption(options, arg);
    });
  },

  writeFile: function(options, callback) {
    var filePath = utils.requireOption(options, 'path');
    filePath = path.resolve(filePath);
    var data = utils.requireOption(options, 'data');
    var fileOptions = options.options || {
      encoding: 'utf8'
    };
    var tmpPath = options.safe ?
      filePath + '.' + crypto.randomBytes(8).toString('hex') + '.tmp' :
      filePath;

    mkdirp(path.dirname(filePath), function(err) {
      if (err) return callback(err);

      fs.writeFile(tmpPath, data, fileOptions, function(err) {
        if (err) return callback(err);

        if (!options.safe) return callback();

        fs.rename(tmpPath, filePath, function(err) {
          if (err) return callback(err);

          callback();
        })
      });
    });
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

  requireParam: function(paramName, paramValue) {
    if (typeof paramValue === 'undefined') throw new Error('Missing required parameter: ' + paramName);

    return paramValue;
  }
}

module.exports = utils;
