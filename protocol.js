'use strict';

const debugClient = require('debug')('pqc:client');
debugClient.color = 5;
const debugServer = require('debug')('pqc:server');
debugServer.color = 2;

const { McEliece } = require('mceliece-nist');
const { Duplex } = require('stream');
const { createHash, createCipheriv, createDecipheriv, randomBytes } = require('crypto');

// Key exchange parameters.
const kHashName   = 'sha256';
const kCipherName = 'aes-256-ctr';
const kKeySize    = 32;
const kIvSize     = 16;
const kKemName    = 'mceliece6960119f';

const kem = new McEliece(kKemName);

// Message tags.
const kTagClientHello      = 0x00;
const kTagServerHello      = 0x01;
const kTagPublicKeyRequest = 0x02;
const kTagPublicKeyReply   = 0x03;
const kTagEncryptedKey     = 0x04;
const kTagTunnelReady      = 0x05;
const kTagError            = 0xff;

const kNextLayer = Symbol('kNextLayer');
const kPending   = Symbol('kPending');
const kBuffer    = Symbol('kBuffer');
const kSecure    = Symbol('kSecure');

function xor(a, b) {
  const result = Buffer.alloc(a.length);
  for (let i = 0; i < result.length; i++)
    result[i] = a[i] ^ b[i];
  return result;
}

function hash(bufs) {
  const h = createHash(kHashName);
  for (const buf of bufs)
    h.update(buf)
  return h.digest();
}

const computeKeyId = (key) => hash([key]);

class PQCBase extends Duplex {
  constructor(nextLayer, options) {
    super(options);
    this[kNextLayer] = nextLayer;
    this[kPending] = [];
    this[kBuffer] = Buffer.alloc(0);

    nextLayer.on('data', (chunk) => {
      if (this[kBuffer]) {
        this[kBuffer] = Buffer.concat([this[kBuffer], chunk]);
        while (this[kBuffer] && this[kBuffer].length >= 4) {
          const tag = this[kBuffer][0];
          const len = this[kBuffer][3] |
                      (this[kBuffer][2] << 8) |
                      (this[kBuffer][1] << 16) |
                      this[kBuffer][3];

          if (this[kBuffer].length < 4 + len)
            break;

          const message = this[kBuffer].slice(4);
          this[kBuffer] = this[kBuffer].slice(4 + len);
          this.handleMessage(tag, message);
        }
      } else {
        this.push(this[kSecure].recv.update(chunk));
      }
    });
  }

  writeMessage(tag, msg) {
    let buf;
    if (msg) {
      buf = Buffer.alloc(4 + msg.length);
      buf.writeUInt32BE((tag << 24) | msg.length);
      msg.copy(buf, 4);
    } else {
      buf = Buffer.from([tag, 0, 0, 0]);
    }
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
      recv: createDecipheriv(kCipherName, keyIn, iv),
      send: createCipheriv(kCipherName, keyOut, iv)
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
      sni = undefined;
    }

    this.writeMessage(kTagClientHello, sni);
  }

  handleServerHello(tag, message) {
    if (tag !== kTagServerHello || message.length !== 2 * kKeySize)
      return this.emit('error', 'Invalid server hello');

    this.publicKeyId = message.slice(0, kKeySize);
    this.nonce = message.slice(kKeySize);
    this.debug(`got valid public key id and nonce`);

    // TODO: Pause processing of messages while waiting for async function
    this.getPublicKey(this.publicKeyId, (err, key) => {
      // TODO: Handle error

      if (key === undefined) {
        this.debug(`unknown public key id`);
        this.handleMessage = this.handlePublicKeyReply;
        this.writeMessage(kTagPublicKeyRequest);
      } else {
        this.actualKeyExchange(key);
      }
    });
  }

  handlePublicKeyReply(tag, publicKey) {
    if (tag !== kTagPublicKeyReply || publicKey.length !== kem.publicKeySize)
      return this.emit('error', 'Invalid public key reply');

    if (!computeKeyId(publicKey).equals(this.publicKeyId))
      return this.emit('error', 'Wrong public key');

    this.rememberPublicKey(this.publicKeyId, publicKey);
    this.actualKeyExchange(publicKey);
  }

  actualKeyExchange(publicKey) {
    const { key, encryptedKey } = kem.generateKey(publicKey);
    const iv = randomBytes(kIvSize);

    this.key = key;
    this.iv = iv;

    this.debug('sending encrypted key and iv');

    this.handleMessage = this.handleTunnelReady;
    this.writeMessage(kTagEncryptedKey, Buffer.concat([encryptedKey, iv]));
  }

  handleTunnelReady(tag, message) {
    if (tag !== kTagTunnelReady || message.length !== 0)
      return this.emit('error', 'Invalid TunnelReady');

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

  handleClientHello(tag, message) {
    if (tag !== kTagClientHello)
      return this.emit('error', new Error(`Invalid ClientHello`));

    this.sni = message.toString('utf8');

    if (this.sni.length !== 0) {
      this.debug(`client initiated key exchange with SNI ${this.sni}`);
    } else {
      this.debug(`client initiated key exchange without SNI`);
    }

    this.getPublicKeyId(this.sni, (err, id) => {
      if (err) {
        this.debug(`no public key`);
        this.writeMessage(kTagError, err);
      } else {
        this.debug(`using public key id ${id.toString('hex').substr(0, 16)}`);
        this.nonce = randomBytes(kKeySize);
        this.debug(`generated nonce`);
        this.writeMessage(kTagServerHello, Buffer.concat([id, this.nonce]));
        this.handleMessage = this.handlePublicKeyRequest;
      }
    });
  }

  handlePublicKeyRequest(tag, message) {
    if (tag === kTagEncryptedKey) {
      this.debug(`client skipped PublicKeyRequest`);
      return this.handleEncryptedKey(tag, message);
    }

    if (tag !== kTagPublicKeyRequest || message.length !== 0)
      return this.emit('error', new Error('Invalid PublicKeyRequest'));

    this.debug(`client requested public key`);

    this.getPublicKey(this.sni, (err, key) => {
      if (err) {
        this.debug(`failed to retrieve public key`);
        this.writeMessage(kTagError, err);
      } else {
        this.debug(`transmitting public key (${key.length} bytes)`);
        this.writeMessage(kTagPublicKeyReply, key);
        this.handleMessage = this.handleEncryptedKey;
      }
    });
  }

  handleEncryptedKey(tag, message) {
    if (tag !== kTagEncryptedKey || message.length !== kem.encryptedKeySize + kIvSize)
      return this.emit('error', new Error('Invalid EncryptedKey'));

    this.getPrivateKey(this.sni, (err, key) => {
      // TODO: Handle error

      const encryptedKey = message.slice(0, kem.encryptedKeySize);
      const decryptedKey = kem.decryptKey(key, encryptedKey);
      const iv = message.slice(kem.encryptedKeySize);
      this.debug('recovered k\' from encrypted message');

      this.writeMessage(kTagTunnelReady);
      this.setupEncryption(decryptedKey, this.nonce, iv);
    });
  }
}

module.exports = { PQCClient, PQCServer, computeKeyId, kem };
