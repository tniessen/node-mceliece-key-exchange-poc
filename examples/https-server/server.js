'use strict';

const { createPublicKey, sign, verify } = require('crypto');
const fs = require('fs');
const https = require('https');
const pug = require('pug');

const pqc = require('../../pqc-over-tcp');
const { kem, computeKeyId } = require('../../protocol');

const httpsServerDebug = require('debug')('https:server');

const httpsOptions = {
  key: fs.readFileSync(`${__dirname}/../key.pem`, 'ascii'),
  cert: fs.readFileSync(`${__dirname}/../cert.pem`, 'ascii')
};

// Generate the server key pair.
httpsServerDebug('generating keypair');
const { publicKey, privateKey } = kem.keypair();
const publicKeyId = computeKeyId(publicKey);

// Sign the public key id.
const publicKeySignature = sign('sha256', publicKeyId, httpsOptions.key);

const render = pug.compileFile(`${__dirname}/view.pug`);

// Create the HTTPS server.
const httpsServer = https.createServer(httpsOptions, (req, res) => {
  httpsServerDebug('received request');

  const cert = req.socket.getCertificate();

  const reqLines = [`${req.method} ${req.url} HTTP/${req.httpVersion}`];
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    reqLines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
  }

  res.setHeader('Content-Type', 'text/html');
  res.end(render({
    http: {
      reqLines
    },
    tls: {
      cert
    },
    pqc: {
      publicKeyId: publicKeyId.toString('hex'),
      publicKeySignature: publicKeySignature.toString('hex')
    }
  }));
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

// Wait for the server to be bound to a port.
server.listen(8124, () => {
  const addr = server.address();
  httpsServerDebug(`listening on ${addr.address}:${addr.port}`);
});
