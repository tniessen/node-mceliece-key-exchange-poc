'use strict';

const debugClient = require('debug')('pqc:client');
debugClient.color = 5;
const debugServer = require('debug')('pqc:server');
debugServer.color = 2;

const { McEliece } = require('mceliece-nist');
const { Duplex } = require('stream');
const { createHash, createCipheriv, createDecipheriv, randomBytes } = require('crypto');

// Used for public key identification and key derivation.
const PROTO_HASH = 'sha256';
const PROTO_HASH_SIZE = 32;
// Used for symmetric encryption of the protected traffic.
const PROTO_CIPHER = 'aes-256-ctr';
const PROTO_KEY_SIZE = 32;
const PROTO_IV_SIZE = 16;
// Used for key exchange.
const PROTO_KEM = 'mceliece6960119f';

const kem = new McEliece(PROTO_KEM);

const errorPrefix = Buffer.from('pqc#', 'ascii');
const clientHelloPrefix = Buffer.from('pqc?', 'ascii');
const serverHelloPrefix = Buffer.from('pqc!', 'ascii');
const publicKeyRequestPrefix = Buffer.from('pqc+', 'ascii');
const publicKeyReplyPrefix = Buffer.from('pqc=', 'ascii');
const clientEncryptedKeyPrefix = Buffer.from('pqc*', 'ascii');
const connectionReadyPrefix = Buffer.from('pqc$', 'ascii');

const kPending = Symbol('kPending');
const kBuffer = Symbol('kBuffer');
const kSecure = Symbol('kSecure');
const kNextLayer = Symbol('kNextLayer');

function xor(a, b) {
  const result = Buffer.alloc(a.length);
  for (let i = 0; i < result.length; i++)
    result[i] = a[i] ^ b[i];
  return result;
}

function hash(bufs) {
  const h = createHash(PROTO_HASH);
  for (const buf of bufs)
    h.update(buf)
  return h.digest();
}

class PQCBase extends Duplex {
  constructor(nextLayer, options) {
    super(options);
    this[kNextLayer] = nextLayer;
    this[kPending] = [];
    this[kBuffer] = Buffer.alloc(0);

    nextLayer.on('data', (chunk) => {
      // TODO: Fix this, this should handle messages in a loop
      if (this[kBuffer]) {
        this[kBuffer] = Buffer.concat([this[kBuffer], chunk]);
        if (this[kBuffer].length > 4) {
          const payloadSize = this[kBuffer].readUInt32BE();
          if (this[kBuffer].length >= 4 + payloadSize) {
            const message = this[kBuffer].slice(4, 4 + payloadSize);
            this[kBuffer] = this[kBuffer].slice(4 + payloadSize);
            this.handleMessage(message);
          }
        }
      } else {
        this.push(this[kSecure].recv.update(chunk));
      }
    });
  }

  writeMessage(msg) {
    const buf = Buffer.alloc(4 + msg.length);
    buf.writeUInt32BE(msg.length);
    msg.copy(buf, 4);
    this[kNextLayer].write(buf);
  }

  setupEncryption(key, nonce, iv) {
    this.debug('deriving session keys from K xor N');
    key = xor(key, nonce);
    const key1 = hash([Buffer.from([0x00]), key]);
    const key2 = hash([Buffer.from([0xff]), key]);

    let keyIn, keyOut;
    if (this instanceof PQCClient) {
      keyIn = key1;
      keyOut = key2;
    } else {
      keyIn = key2;
      keyOut = key1;
    }

    this[kSecure] = {
      recv: createDecipheriv(PROTO_CIPHER, keyIn, iv),
      send: createCipheriv(PROTO_CIPHER, keyOut, iv)
    };

    this.push(this[kSecure].recv.update(this[kBuffer]));
    delete this[kBuffer];

    for (const [chunk, cb] of this[kPending])
      this[kNextLayer].write(this[kSecure].send.update(chunk), cb);

    this.debug('tunnel ready');
    this.emit('encrypted');
  }

  _write(chunk, encoding, callback) {
    if (!Buffer.isBuffer(chunk))
      chunk = Buffer.from(chunk, encoding);

    if (this[kSecure])
      return this[kNextLayer].write(this[kSecure].send.update(chunk), callback);

    this[kPending].push([chunk, callback]);
  }

  _read(size) {
    if (this[kSecure]) {
      const data = this[kNextLayer].read(size);
      if (data != null) {
        this.push(this[kSecure].recv.update(data));
      }
    }
  }
}

class PQCClient extends PQCBase {
  constructor(nextLayer, options) {
    super(nextLayer, options);

    this.debug = debugClient;

    this.getPublicKey = options && options.getPublicKey;
    if (typeof this.getPublicKey !== 'function')
      throw new TypeError(`options.getPublicKey must be a function`);
    this.rememberPublicKey = options && options.rememberPublicKey;
    if (typeof this.rememberPublicKey !== 'function')
      throw new TypeError(`options.rememberPublicKey must be a function`);
    this.sni = options.sni;
    if (this.sni !== undefined && typeof this.sni !== 'string')
      throw new TypeError(`options.sni must be a string`);

    this.handleMessage = this.handleServerHello;
  }

  beginKeyExchange() {
    let sni;
    if (this.sni) {
      this.debug(`initiating key exchange with SNI '${options.sni}'`);
      sni = Buffer.from(this.sni, 'utf8');
    } else {
      this.debug(`initiating key exchange without SNI`);
      sni = Buffer.alloc(0);
    }

    const clientHello = Buffer.concat([clientHelloPrefix, sni]);
    this.writeMessage(clientHello);
  }

  handleServerHello(message) {
    if (message.length !== 4 + PROTO_HASH_SIZE + PROTO_KEY_SIZE ||
        !serverHelloPrefix.equals(message.slice(0, 4)))
      return this.emit('error', 'Invalid server hello');

    this.publicKeyId = message.slice(4, 4 + PROTO_HASH_SIZE);
    this.nonce = message.slice(4 + PROTO_HASH_SIZE);
    this.debug(`got valid public key id and nonce`);

    // TODO: Pause processing of messages while waiting for async function
    this.getPublicKey(this.publicKeyId, (err, key) => {
      // TODO: Handle error

      if (key === undefined) {
        this.debug(`unknown public key id`);
        this.handleMessage = this.handlePublicKeyReply;
        this.writeMessage(publicKeyRequestPrefix);
      } else {
        this.actualKeyExchange(key);
      }
    });
  }

  handlePublicKeyReply(message) {
    if (message.length !== 4 + kem.publicKeySize) // TODO: Also check prefix
      return this.emit('error', 'Invalid public key reply');

    const publicKey = message.slice(4);
    if (!hash([publicKey]).equals(this.publicKeyId))
      return this.emit('error', 'Wrong public key');

    this.rememberPublicKey(this.publicKeyId, publicKey);
    this.actualKeyExchange(message.slice(4));
  }

  actualKeyExchange(publicKey) {
    const { key, encryptedKey } = kem.generateKey(publicKey);
    const iv = randomBytes(PROTO_IV_SIZE);

    this.key = key;
    this.iv = iv;

    this.debug('sending k\' and iv');

    this.handleMessage = this.handleConnectionReady;
    this.writeMessage(Buffer.concat([clientEncryptedKeyPrefix, encryptedKey, iv]));
  }

  handleConnectionReady() {
    // TODO: Rewrite this function as a factory in order to pass key and IV as parameters?
    this.setupEncryption(this.key, this.nonce, this.iv);
    delete this.key;
    delete this.nonce;
    delete this.iv;
  }
}

class PQCServer extends PQCBase {
  constructor(nextLayer, options) {
    super(nextLayer, options);

    this.debug = debugServer;

    this.getPublicKeyId = options && options.getPublicKeyId;
    if (typeof this.getPublicKeyId !== 'function')
      throw new TypeError(`options.getPublicKey must be a function`);
    this.getPublicKey = options && options.getPublicKey;
    if (typeof this.getPublicKey !== 'function')
      throw new TypeError(`options.getPublicKey must be a function`);
    this.getPrivateKey = options && options.getPrivateKey;
    if (typeof this.getPrivateKey !== 'function')
      throw new TypeError(`options.getPrivateKey must be a function`);

    this.handleMessage = this.handleClientHello;
  }

  handleClientHello(message) {
    if (message.length < clientHelloPrefix.length || !clientHelloPrefix.equals(message.slice(0, clientHelloPrefix.length)))
      return this.emit('error', new Error(`Invalid client hello`));

    this.sni = message.slice(clientHelloPrefix.length).toString('utf8');

    if (this.sni.length !== 0) {
      this.debug(`client initiated key exchange with SNI ${this.sni}`);
    } else {
      this.debug(`client initiated key exchange without SNI`);
    }

    this.getPublicKeyId(this.sni, (err, id) => {
      if (err) {
        this.debug(`no public key`);
        this.writeMessage(Buffer.concat([errorPrefix, err]));
      } else {
        this.debug(`using public key id ${id.toString('hex').substr(0, 16)}`);
        this.nonce = randomBytes(PROTO_KEY_SIZE);
        this.debug(`generated nonce`);
        this.writeMessage(Buffer.concat([serverHelloPrefix, id, this.nonce]));
        this.handleMessage = this.handlePublicKeyRequest;
      }
    });
  }

  handlePublicKeyRequest(message) {
    if (message.length >= clientEncryptedKeyPrefix.length &&
        clientEncryptedKeyPrefix.equals(message.slice(0, 4))) {
      this.debug(`client skipped public key request`);
      return handleClientEncryptedKey(message);
    }

    if (!message.equals(publicKeyRequestPrefix))
      return this.emit('error', new Error('Invalid public key request'));

    this.debug(`client requested public key`);

    this.getPublicKey(this.sni, (err, key) => {
      if (err) {
        this.debug(`failed to retrieve public key`);
        this.writeMessage(Buffer.concat([errorPrefix, err]));
      } else {
        this.debug(`transmitting public key (${key.length} bytes)`);
        this.writeMessage(Buffer.concat([publicKeyReplyPrefix, key]));
        this.handleMessage = this.handleClientEncryptedKey;
      }
    });
  }

  handleClientEncryptedKey(message) {
    if (message.length !== 4 + kem.encryptedKeySize + PROTO_IV_SIZE)
      return this.emit('error', new Error('Invalid client encrypted key'));

    this.getPrivateKey(this.sni, (err, key) => {
      // TODO: Handle error

      const decryptedKey = kem.decryptKey(key, message.slice(4, 4 + kem.encryptedKeySize));
      this.debug('recovered k\' from encrypted message');

      this.writeMessage(connectionReadyPrefix);
      this.setupEncryption(decryptedKey,
                           this.nonce,
                           message.slice(4 + kem.encryptedKeySize));
    });
  }
}

const computeKeyId = (key) => hash([key]);

module.exports = { PQCClient, PQCServer, computeKeyId, kem };
