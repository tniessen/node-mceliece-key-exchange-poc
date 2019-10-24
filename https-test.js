'use strict';

const { createPublicKey, sign, verify } = require('crypto');
const fs = require('fs');
const https = require('https');

const pqc = require('./pqc-over-tcp');
const { kem, computeKeyId } = require('./protocol');

const httpsServerDebug = require('debug')('https:server');
const httpsClientDebug = require('debug')('https:client');

const httpsOptions = {
  key: fs.readFileSync('key.pem', 'ascii'),
  cert: fs.readFileSync('cert.pem', 'ascii')
};

// Generate the server key pair.
const { publicKey, privateKey } = kem.keypair();
const publicKeyId = computeKeyId(publicKey);

// Sign the public key id.
const publicKeySignature = sign('sha256', publicKeyId, httpsOptions.key);

// Create the HTTPS server.
const httpsServer = https.createServer(httpsOptions, (req, res) => {
  httpsServerDebug('received request');
  res.end('ok');
});

httpsServer.on('error', (err) => console.error(err));
httpsServer.on('clientError', (err, conn) => {
  console.error(err);
  conn.destroy(err);
});

const server = pqc.createServer({
  getPublicKey(sni, callback) {
    callback(null, publicKey);
  },
  getPublicKeyId(sni, callback) {
    callback(null, publicKeyId, publicKeySignature);
  },
  getPrivateKey(sni, callback) {
    callback(null, privateKey);
  }
}, c => {
  httpsServer.emit('connection', c);
  c.on('error', err => console.error(err));
});

// Prevent the server from keeping the process running.
server.unref();

// Wait for the server to be bound to a port.
server.listen(8124, () => {
  const conn = pqc.connect({
    hostname: 'localhost',
    port: 8124,
    getPublicKey(id, signature, callback) {
      if (signature.length === 0)
        return callback(new Error('Missing signature'));

      conn.publicKeyId = id;
      conn.publicKeySignature = signature;
      callback(null);
    },
    rememberPublicKey(id, key) {
      // Ignore it
    }
  });
  conn.on('error', err => console.error(err));

  const req = https.request('https://localhost:8124/foo', { socket: conn });
  req.on('error', (err) => console.error(err));

  req.on('socket', (socket) => {
    socket.once('secureConnect', () => {
      const certPublicKey = createPublicKey({
        key: socket.getPeerCertificate().pubkey,
        format: 'der',
        type: 'spki'
      });
      if (verify('sha256', conn.publicKeyId, certPublicKey, conn.publicKeySignature)) {
        httpsClientDebug('PQC public key was signed with TLS public key');
      } else {
        httpsClientDebug('PQC public key signature is invalid');
        // TODO: End the connection
      }
    });
  });

  req.on('response', (res) => {
    httpsClientDebug('received response');
    res.resume();
  });

  req.end();
});
