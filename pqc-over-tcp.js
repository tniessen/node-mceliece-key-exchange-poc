'use strict';

const net = require('net');
const { PQCClient, PQCServer } = require('./protocol');

const tcpServerDebug = require('debug')('tcp:server');
const tcpClientDebug = require('debug')('tcp:client');

function createServer(options, connectionListener) {
  return net.createServer((c) => {
    tcpServerDebug(`connection from ${c.address().address}:${c.address().port}`);

    const pqc = new PQCServer(c, options);

    // TODO: Handle errors

    pqc.once('encrypted', () => connectionListener(pqc));
  });
}

function connect(options, connectListener) {
  let pcq;
  const client = net.connect(options);
  const pqc = new PQCClient(client, options);

  client.once('connect', () => {
    tcpClientDebug('connected');

    pqc.beginKeyExchange();
    if (connectListener)
      pqc.once('encrypted', connectListener);
  });

  client.on('close', () => tcpClientDebug('disconnected'));

  const oldEnd = pqc.end;
  pqc.end = (data, encoding, callback) => {
    if (typeof data === 'function') {
      callback = data;
      data = undefined;
    } else if (typeof encoding === 'function') {
      callback = encoding;
      encoding = undefined;
    }

    oldEnd.call(pqc, data, encoding);
    client.end(callback);
    return pqc;
  };

  return pqc;
}

module.exports = {
  createServer,
  connect
};
