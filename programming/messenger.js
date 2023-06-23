/*
Shoaib Mohammed shoaibmh@stanford.edu
Lovish Chopra lovish@stanford.edu
*/

'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  byteArrayToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib');

/** ******* Implementation ********/

// custom properties
// TODO: figure out what data should be
const dataConstant = "DATA-CONSTANT";

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate   
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    this.EGKeyPair = await generateEG();
    const certificate = {
      username,
      pk: this.EGKeyPair.pub
    };
    return certificate;
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: string
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    const certString = JSON.stringify(certificate);
    const verification = await verifyWithECDSA(this.caPublicKey, certString, signature);
    if(!verification) {
      throw new Error(`Tampering detected, cannot verify certificate with signature ${signature}.`);
    }
    this.certs[certificate.username] = certificate.pk;
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, string]
 */
  async sendMessage (name, plaintext) {
    // if this is the first time we are creating a connection
    if(!this.conns.hasOwnProperty(name)) {
      // public key of the receiver which we need to create the connection   
      const receiverPK = this.certs[name];
      
      // needed to create the root chain
      const sharedRootKey = await computeDH(this.EGKeyPair.sec, receiverPK);
      
      // generate an EG pair again
      const EGKeyPair = await generateEG();
      
      const dhOutput = await computeDH(EGKeyPair.sec, receiverPK);
      
      // we get back a root KDF key and a sending KDF key
      const [RK, CKs] = await HKDF(sharedRootKey, dhOutput, dataConstant);

      this.conns[name] = {
        DHs: EGKeyPair,        // DH key pair of the sender
        DHr: receiverPK,       // DH public key of the receiver
        RK: RK,                 // root KDF key
        CKs: CKs,               // sending KDF key
        CKr: null,              // we do not have the receiver KDF key, this is the first time we are communicating with send
        constantCK: sharedRootKey,  // use the shared root key for the constant CK
        Ns: 0,                  // number of messages sent
        Nr: 0,                  // number of messages received
        PN: 0,
        MKSKIPPED: {},
      };
    }
    
    const receiverIV = await genRandomSalt();
    const ivGov = await genRandomSalt();
    const connection = this.conns[name];
    
    if (connection.CKs == null) {
      // public key of the receiver which we need to create the connection   
      const receiverPK = this.certs[name];
      
      // needed to create the root chain
      const sharedRootKey = await computeDH(this.EGKeyPair.sec, receiverPK);
      
      // generate an EG pair again
      const EGKeyPair = await generateEG();
      
      const dhOutput = await computeDH(EGKeyPair.sec, receiverPK);
      
      // we get back a root KDF key and a sending KDF key
      const [RK, CKs] = await HKDF(sharedRootKey, dhOutput, dataConstant);
      
      connection.DHs = EGKeyPair;
      connection.DHr = receiverPK;
      connection.RK = RK;
      connection.CKs = CKs;
    }
    const [CKs, messageKey] = await HKDF(connection.CKs, connection.constantCK, dataConstant);
    connection.CKs = CKs;
    
    const aesKey = await HMACtoAESKey(messageKey, dataConstant);
    const keyPairObjectGov = await generateEG();
    const dhOutput = await computeDH(keyPairObjectGov.sec, this.govPublicKey);
    const govAesKey = await HMACtoAESKey(dhOutput, govEncryptionDataStr);
    const messageKeyBuffer = await HMACtoAESKey(messageKey, dataConstant, true);
    const cGov = await encryptWithGCM(govAesKey, messageKeyBuffer, ivGov);
    
    const header = {
      DHs: connection.DHs.pub,
      // TODO: add the previous chain length pn
      Ns: connection.Ns,
      receiverIV,
      ivGov,
      cGov,
      vGov: keyPairObjectGov.pub,
      PN: connection.PN,
    };
    
    const ciphertext = await encryptWithGCM(aesKey, plaintext, receiverIV, JSON.stringify(header));
    connection.Ns++;
    
    return [header, ciphertext];
  }
  
  async SkipMessageKeys(connection, until) {
    // TODO: see if you want to keep this part or no
    // if (connection.Nr + MAX_SKIP < until) {
    //   throw new Error("Too many skipped messages.");
    // }
    if (connection.CKr !== null) {
      while (connection.Nr < until) {
        let messageKey;
        [connection.CKr, messageKey] = await HKDF(connection.CKr, connection.constantCK, dataConstant);
        connection.MKSKIPPED[[connection.DHr, connection.Nr]] = messageKey;
        connection.Nr++;
      }
    }
  }
  
  async DHRatchet(connection, header) {
    connection.PN = connection.Ns;
    connection.Ns = 0;
    connection.Nr = 0;
    connection.DHr = header.DHs;
    
    let dhOutput = await computeDH(connection.DHs.sec, connection.DHr);
    [connection.RK, connection.CKr] = await HKDF(connection.RK, dhOutput, dataConstant);
    
    connection.DHs = await generateEG();
    dhOutput = await computeDH(connection.DHs.sec, connection.DHr);
    [connection.RK, connection.CKs] = await HKDF(connection.RK, dhOutput, dataConstant);
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, string]
 *
 * Return Type: string
 */
  async receiveMessage (name, [header, ciphertext]) {
    if (!this.conns.hasOwnProperty(name)) {
      // public key of the sender which we need to create the connection   
      const senderPK = this.certs[name];
      
      // needed to create the root chain
      const sharedRootKey = await computeDH(this.EGKeyPair.sec, senderPK);
      
      // note that we do not generate a new EG key pair here
      const dhOutputSenderPK = header.DHs;
      const dhOutput = await computeDH(this.EGKeyPair.sec, dhOutputSenderPK);
      
      // we get back a root KDF key and a receiver KDF key
      const [RK, CKr] = await HKDF(sharedRootKey, dhOutput, dataConstant);

      this.conns[name] = {
        DHs: this.EGKeyPair,  // DH key pair of the sender
        DHr: header.DHs,              // DH public key of the receiver
        RK,
        CKs: null,               // sending KDF key
        CKr,
        constantCK: sharedRootKey,
        Ns: 0,                  // number of messages sent
        Nr: 0,                  // number of messages received
        PN: 0,
        MKSKIPPED: {},
      }; 
    }
    
    const connection = this.conns[name];
    
    if (connection.CKr == null) {
      // public key of the sender which we need to create the connection   
      const senderPK = this.certs[name];
      
      // needed to create the root chain
      const sharedRootKey = await computeDH(this.EGKeyPair.sec, senderPK);
      
      // note that we do not generate a new EG key pair here
      const dhOutputSenderPK = header.DHs;
      const dhOutput = await computeDH(this.EGKeyPair.sec, dhOutputSenderPK);
      
      // we get back a root KDF key and a receiver KDF key
      const [RK, CKr] = await HKDF(sharedRootKey, dhOutput, dataConstant);
      
      connection.DHs = this.EGKeyPair;
      connection.DHr = header.DHs;
      connection.RK = RK;
      connection.CKr = CKr;
    }
    
    // handle out-of-order messages
    const key = [header.DHs, header.Ns];
    if (connection.MKSKIPPED.hasOwnProperty(key)) {
      const messageKey = connection.MKSKIPPED[key];
      const aesKey = await HMACtoAESKey(messageKey, dataConstant);
      const plaintext = byteArrayToString(await decryptWithGCM(aesKey, ciphertext, header.receiverIV, JSON.stringify(header)));
      delete connection.MKSKIPPED[key];
      return plaintext;
    }
    
    if (header.DHs !== connection.DHr) {
      await this.SkipMessageKeys(connection, header.PN);
      // await this.DHRatchet(connection, header);
    }
    
    await this.SkipMessageKeys(connection, header.Ns);
    
    let messageKey;
    [connection.CKr, messageKey] = await HKDF(connection.CKr, connection.constantCK, dataConstant);
    
    const aesKey = await HMACtoAESKey(messageKey, dataConstant);
    const plaintext = byteArrayToString(await decryptWithGCM(aesKey, ciphertext, header.receiverIV, JSON.stringify(header)));
    connection.Nr++;
    
    return plaintext;
  }
};

module.exports = {
  MessengerClient
}
