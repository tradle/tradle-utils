'use strict';

module.exports = function (grunt) {

  require('load-grunt-tasks')(grunt);

  grunt.registerTask('setup', [
    'githooks'
  ]);

  grunt.registerTask('default', [
    'jshint:default'
  ]);

  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    githooks: {
      all: {
        'pre-commit': 'jsbeautifier:verify jshint'
      }
    },

    jsbeautifier: {
      options: {
        config: '.jsbeautifyrc'
      },

      default: {
        src: ['*.js']
      },

      verify: {
        src: ['*.js'],
        options: {
          mode: 'VERIFY_ONLY'
        }
      }
    },

    jshint: {
      options: {
        jshintrc: '.jshintrc'
      },

      gruntfile: {
        src: 'Gruntfile.js'
      },

      default: {
        src: ['Gruntfile.js', '*.js']
      }
    }

  });

};
