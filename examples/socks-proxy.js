'use strict';

const socks = require('socksv5'); // TODO: Use @heroku/socksv5?
const debug = require('debug')('socks:proxy');

const pqc = require('../pqc-over-tcp');

const publicKeyCache = {};

const srv = socks.createServer((info, accept, deny) => {
  if (info.cmd === 'connect' &&
      info.dstAddr === 'example.ca' &&
      info.dstPort === 443) {
    debug(`intercepting connection from ${info.srcAddr}:${info.srcPort} to ${info.dstAddr}:${info.dstPort}`);

    const conn = pqc.connect({
      hostname: 'localhost',
      port: 8124,
      getPublicKey(id, signature, callback) {
        const hexId = id.toString('hex');
        const publicKey = publicKeyCache[hexId];
        debug(publicKey ? `reusing known public key ${hexId}`
                        : `unknown public key ${hexId}`);
        callback(undefined, publicKey);
      },
      rememberPublicKey(id, key) {
        const hexId = id.toString('hex');
        debug(`remembering public key ${hexId}`);
        publicKeyCache[hexId] = key;
      }
    });

    const socket = accept(true);
    socket.pipe(conn);
    conn.pipe(socket);
  } else {
    accept();
  }
});

srv.listen(1080, '0.0.0.0', () => {
  const addr = srv.address();
  debug(`listening on ${addr.address}:${addr.port}`);
});

srv.useAuth(socks.auth.None());
