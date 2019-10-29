'use strict';

const http = require('http');

const pqc = require('../pqc-over-tcp');
const { kem, computeKeyId } = require('../protocol');

const httpServerDebug = require('debug')('http:server');
const httpClientDebug = require('debug')('http:client');

// Generate the server key pair.
const { publicKey, privateKey } = kem.keypair();
const publicKeyId = computeKeyId(publicKey);

// Create the HTTP server.
const httpServer = http.createServer((req, res) => {
  httpServerDebug('received request');
  res.end('ok');
});

const server = pqc.createServer({
  getPublicKey(sni, callback) {
    callback(null, publicKey);
  },
  getPublicKeyId(sni, callback) {
    callback(null, publicKeyId);
  },
  getPrivateKey(sni, callback) {
    callback(null, privateKey);
  }
}, c => {
  httpServer.emit('connection', c);
  c.on('error', err => console.error(err));
});

// Prevent the server from keeping the process running.
server.unref();

// Wait for the server to be bound to a port.
server.listen(8124, () => {
  const req = http.request('http://localhost:8124/foo', {
    createConnection(options, callback) {
      const conn = pqc.connect({
        hostname: options.hostname,
        port: options.port,
        getPublicKey(id, signature, callback) {
          callback(null);
        },
        rememberPublicKey(id, key) {
          // Ignore it
        }
      }, () => {
        callback(null, conn);
      });

      conn.on('error', err => console.error(err));
      // TODO: Errors
    }
  });

  req.on('socket', () => httpClientDebug('connection established'));
  req.on('response', (res) => {
    httpClientDebug('received response');
    res.resume();
  });

  req.end();
});
