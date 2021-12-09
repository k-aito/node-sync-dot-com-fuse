(async () => {
/**
 * Dependences
 */

// npm install dotenv
const dotenv = require("dotenv")
dotenv.config()

// npm install bcrypt
const bCrypt = require('bcrypt')

// npm install got (request is deprecated)
const got = require('got')

// npm install hash.js
const hash = require('hash.js')

// npm install sjcl
const sjcl = require('sjcl')

// npm install fuse-bindings (use node 8.17.0)
// https://github.com/mafintosh/fuse-bindings
const fuse = require('fuse-bindings')

// npm install scanf
const scanf = require('scanf')

// npm install pidcrypt
require("pidcrypt/seedrandom")
const pidCrypt = require('pidcrypt')
require("pidcrypt/rsa")
require("pidcrypt/asn1")
const pidCryptUtil = require('pidcrypt/pidcrypt_util');

const crypto = require('crypto')
const pathmodule = require('path')
const util = require('util');
const fs = require('fs');


/**
 * Variables
 */ 

const api_url = 'https://cp.sync.com/api/?command='
const username = process.env.EMAIL
const password = process.env.PASSWORD

let GCM_PACKET_SIZE = 128 * 1024;
let GCM_PAYLOAD_SIZE = 128 * 1024 - 36;
let CHUNK_SIZE = 10485760


/**
 * Workaround for modules not available in sjcl
 */

/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Arrays of bytes
 * @namespace
 */
sjcl.codec.bytes = {
  /** Convert from a bitArray to an array of bytes. */
  fromBits: function (arr) {
    var out = [], bl = sjcl.bitArray.bitLength(arr), i, tmp;
    for (i=0; i<bl/8; i++) {
      if ((i&3) === 0) {
        tmp = arr[i/4];
      }
      out.push(tmp >>> 24);
      tmp <<= 8;
    }
    return out;
  },
  /** Convert from an array of bytes to a bitArray. */
  toBits: function (bytes) {
    var out = [], i, tmp=0;
    for (i=0; i<bytes.length; i++) {
      tmp = tmp << 8 | bytes[i];
      if ((i&3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i&3) {
      out.push(sjcl.bitArray.partial(8*(i&3), tmp));
    }
    return out;
  }
};

/**
 * Functions for login
 */

async function getSalt(username) {
  const data = await got.post(api_url + 'getloginsalt', {
    json: {
      username_b64: new Buffer(username).toString('base64')
    }
  }).json()
  return data.salt
}

async function getHashedPassword(salt, password) {
  const sha1pass = hash.sha1().update(password).digest('hex')
  let mangle = hash.sha256().update(sha1pass + sha1pass.substring(4, 24)).digest('hex')
  return bCrypt.hashSync(mangle, salt)
}

/**
* Decrypts data using a string password that is keystretched
* @param  {String} b64_crypted A num-prefixed b64 string
* @param  {String|Array} password    The AES key
* @param  {Integer} iterations  iterations for keystretch
* @return {Promise}        [description]
*/
async function passwordDecrypt(b64_crypted, password, iterations) {
  if (b64_crypted.substring(0, 3) === '30:') {
    const raw = sjcl.codec.base64.toBits(b64_crypted.substring(3))
    salt = raw.splice(0, 3)
    iv = raw.splice(0, 3)
    key = sjcl.misc.pbkdf2(password, salt, iterations, 32 * 8, sjcl.misc.hmac)
    aes = new sjcl.cipher.aes(key)
    try {
      return sjcl.codec.utf8String.fromBits(
        sjcl.mode.gcm.decrypt(aes, raw, iv, [], 96)
      )
    } catch (ex) {
      console.error(ex)
    }
  } else {
    console.error('SyncCryptLegacy.passwordDecrypt() failed');
    console.error('Badly formatted password');
    console.error('badly formatted passwd encrypted string ' + b64_crypted);
  }
}

async function userkeyDecrypt(encKey, password) {
    try {
        // must use cryptlegacy because people's passwords will contain weird chars
        return await passwordDecrypt(
            encKey,
            password,
            10000
        );
    } catch (ex) {
        console.error('Error decrypting user keys', ex);
        console.error(2140);
    }
}

async function storeKeys(keys, password) {
    const meta = await userkeyDecrypt(
      keys.enc_meta_key,
      password
    )
    const priv = await userkeyDecrypt(
      keys.enc_priv_key,
      password
    )
    return [meta, priv]
}

async function authenticate(usernameRaw, password) {
  let username = usernameRaw.toLowerCase()
  const hashPass = await getHashedPassword(await getSalt(username), password)
  try {
    const accessData = await got.post(api_url + 'sessionnew', {
      json: {
        username: username,
        password: hashPass,
        // 2FA is not implemented
        twofacode: ''
      }
    }).json()

    const keys = await got.post(api_url + 'getuserkeys', {
      json : {
            username: username,
            password: hashPass,
        }
      }).json()

    return [accessData, await storeKeys(keys, password)]
      
  } catch (ex) {
    console.error("Error in authenticate")
    console.error(ex)
  }
}


/**
 * Functions for operations
 */

/**
 * @ngdoc method
 * @name  list
 * @methodOf sync.service:PathApi
 * @description
 * Gets a path listing for a given sync id.
 * @param  {integer=} sync_id      The pid to get the path listing for.
 * @param  {integer=} hist_id      The current hist id that we have.
 * @param  {integer=} show_deleted switch to show deleted files, 1 = yes
 * @returns {Promise} The promise from the API call
 */
async function list(sync_id, hist_id=0, showdeleted=0) {
  let servtime = Date.now()
  let signature = await getApiHmac(
    accessData['access_secret'],
    [
      accessData['access_token'],
      accessData['uid'],
      accessData['web_device_id'],
      servtime,
    ].join('')
  )

  try {
    return await got.post(api_url + 'pathlist', {
      json: {
        showdeleted: showdeleted,
        hist_id: hist_id,
        sync_id: sync_id,
        offset_metaname_digest: 0,
        servtime: servtime,
        access_token: accessData['access_token'],
        signature: signature
      }
    }).json()
  } catch (ex) {
    console.error(ex)
  }
}


/**
 * @ngdoc method
 * @name  batchDumpDirs
 * @methodOf sync.service:PathApi
 * @description
 * Gets a list of directories recursively from the specified sync id.  The
 * array that is returned is ordered from parent -> child and should be
 * operated in order.  If this is a delete/purge however, the array should
 * be reversed
 *
 * @param  {Integer} sync_id  The path item to be copied
 * @param  {Integer} active_level active -1 == deleted files, > 0 are active
 * @returns {Promise} The promise from the API call
 */
async function batchDumpDirs(sync_id, active_level="1") {
  let servtime = Date.now()
  let signature = await getApiHmac(
    accessData['access_secret'],
    [
      accessData['access_token'],
      accessData['uid'],
      accessData['web_device_id'],
      servtime,
    ].join('')
  )

  try {
    return await got.post(api_url + 'batchdumpdirs', {
      json: {
        active_level: active_level,
        sync_id: sync_id,
        servtime: servtime,
        access_token: accessData['access_token'],
        signature: signature
      }
    }).json()
  } catch (ex) {
    console.error(ex)
  }
}

/**
 * @ngdoc method
 * @name  get
 * @methodOf sync.service:PathApi
 * @description
 * Gets information for a specific path item
 * @param  {integer} sync_id The sync id to retrieve
 * @returns {Promise} The promise from the API call
 */
async function get(sync_id) {
  let servtime = Date.now()
  let signature = await getApiHmac(
    accessData['access_secret'],
    [
      accessData['access_token'],
      accessData['uid'],
      accessData['web_device_id'],
      servtime,
    ].join('')
  )

  try {
    return await got.post(api_url + 'pathget', {
      json: {
        sync_id: sync_id,
        servtime: servtime,
        access_token: accessData['access_token'],
        signature: signature
      }
    }).json()
  } catch (ex) {
    console.error(ex)
  }
}

function mkDownloadUrl(tItem, offset=0, reqLength=0) {
    // console.error('MAKE  DOWNLOAD URL = ' + this.hosts['web'][0])
    let urlParts = [ 'https://cp.sync.com', '/mfs', '/proxyapi.fcgi?command=download',
            '&cachekey=', tItem['cachekey'],
            //~ '&blobtype=', tItem.blobtype,
            '&blobtype=btFILE',
            '&offset=', offset,
            '&engine=', 'cp-' + 2,
            '&userid=', accessData['uid'],
            '&deviceid=', accessData['web_device_id'],
            '&devicetypeid=3'
    ];
    // no length dl all
    if (reqLength) {
        urlParts.push('&length=' + reqLength);
    }

    return urlParts.join('')
}

/**
 * @ngdoc method
 * @name  getData
 * @methodOf sync.service:PathApi
 * @description
 * Gets the encryption keys and path data for a given item.  Typically
 * called before a download.
 * @param  {Array.Object} pathitems List of items to get data for
 * @param  {Integer=} pubkey_id If the user is authenticated, the pubkey
 *                              id will be sent to ensure the correct
 *                              key is retrieved.
 * @returns {Promise} The promise from the API call
 */
async function getData(needKeys, pubkey=null) {
    // var data = (User.isAuthenticated())
    //     ? { pathitems: pathitems, pubkey: User.get('pubkey_id') }
    //     : { pathitems: pathitems };
    let servtime = Date.now()
    let signature = await getApiHmac(
      accessData['access_secret'],
      [
        accessData['access_token'],
        accessData['uid'],
        accessData['web_device_id'],
        servtime,
      ].join('')
    )

    try {
      return await got.post(api_url + 'pathdata', {
        json: {
          pathitems: needKeys,
          pubkey: accessData['pubkey_id'],
          servtime: servtime,
          access_token: accessData['access_token'],
          signature: signature
        }
      }).json()
    } catch (ex) {
      console.error(ex)
    }
};


/**
 * Functions to ease the code
 */

async function getApiHmac(key, data) {
    const hmac = crypto.createHmac('sha1', key)
    hmac.update(data)
    return hmac.digest("hex")
}

function stringToBytes(str) {
    return sjcl.codec.utf8String.toBits(str);
}

function bytesToHex(bits) {
    return sjcl.codec.hex.fromBits(bits);
}

function b64ToBytes(b64) {
    return sjcl.codec.base64.toBits(b64);
}

function bytesToString(bits) {
    return sjcl.codec.utf8String.fromBits(bits);
}

function bytesToB64(bits) {
    return sjcl.codec.base64.fromBits(bits);
}

/**
* @ngdoc method
* @name  arraybufferToBytes
* @methodOf sync.service:SyncCryptLegacy
* @description
* This function doesn't do anything.  It's needed because legacy (sjcl)
* requires it's own "bitArray" instead of array buffers.
* @param  {ArrayBuffer} buffer [description]
* @return {Array}               SJCL's bitArray
*/
function arraybufferToBytes(buffer) {
    const bytes = new Uint8Array(buffer);
    return  sjcl.codec.bytes.toBits(bytes);
}

/**
* @ngdoc method
* @name  getPartialBytes
* @methodOf sync.service:SyncCryptLegacy
* @description
* Gets partial bits from the given data source.
* @param  {Array} array     [description]
* @param  {Integer} byteStart [description]
* @param  {Integer} byteEnd   [description]
* @return {Array}           [description]
*/
function getPartialBytes(data, byteStart, byteEnd) {
  byteStart = byteStart / 32;
  byteEnd = (byteEnd) ? byteEnd / 32 : data.length;
  return data.slice(byteStart, byteEnd);
}

function shareKeyToBytes(sharekey) {
    const bytes = b64ToBytes(sharekey);
    return bytes;
}


/**
 * Functions related to decrypt not related with login
 */

/**
 * This method will always return a string.  Whether it fails or not.
 * @param encName The encrypted name b64 num prefix
 * @param sharekey the b64 of the decrypted share key
 */
async function filenameDecrypt(encName, sharekey=null) {
  const encNameBytes = b64ToBytes(encName.split(':')[1])
  const key = b64ToBytes(meta)

  try {
  // Must use CryptMethodLegacy due to UTF8 characters being 32bit words
  const rawBytes = getPartialBytes(encNameBytes, 96)
  const iv = getPartialBytes(encNameBytes, 0, 96);

  try {
    const nameBytes = await symmetricDecrypt(
      getPartialBytes(key, 256),
      rawBytes,
      iv
    );
    return bytesToString(nameBytes);
  } catch (ex) {
    console.error(`Unable to decrypt the file name ${encName}`, ex);
    fname = encName;
  }
  return fname;
  } catch (ex) {
      console.error('An error occurred in filenameDecrypt', ex);
  }
}

/**
 * Encrypts data using symmetric encryption via asmCrypto
 * @param  {Array} key    The AES key
 * @param  {Array} crypted  [description]
 * @param  {Array} iv     [description]
 * @param  {Array|null} header [description]
 * @return {Promise}        [description]
 */
async function symmetricDecrypt(key, crypted, iv, header) {
    try {
        header = header || [];
        const aes = new sjcl.cipher.aes(key);
        return sjcl.mode.gcm.decrypt(aes, crypted, iv, header, 96);
    } catch (ex) {
       console.error('SyncCryptLegacy.symmetricDecrypt() failed');
       console.error(ex);
    }
}

/**
 * File Data decrypt
 * @param  {Array} data   [description]
 * @param  {Array|String} key    [description]
 * @param  {Integer} offset [description]
 * @return {Promise}
 */
async function filedataDecrypt(data, key, offset=0) {
    let header = getPartialBytes(data, 0, 96),
        iv = getPartialBytes(data, 96, 192),
        encdata = getPartialBytes(data, 192);

    if (!checkHeaderOffset(header, offset)) {
        throw new ErrCode(2020);
    }

    let decrypt_data = await symmetricDecrypt(
        getPartialBytes(key, 0, 256),
        encdata,
        iv,
        header
    );

    //~ return bytesToB64(decrypt_data)
    return bytesToB64(decrypt_data)
}

/**
 * Checks if packed in header offset matches the expected offset
 * @param  {Array|ArrayBuffer} header [description]
 * @param  {Integer} offset [description]
 * @return {Boolean}
 */
function checkHeaderOffset(
    header,
    offset
) {
    let isValid = true;
    if (offset % GCM_PACKET_SIZE !== 0) {
        console.error(
            'offset is not a multiple of ' + GCM_PACKET_SIZE
        );
        isValid = false;
    }
    let expected_offset =
        (offset / GCM_PACKET_SIZE) * GCM_PAYLOAD_SIZE;
    let stored_offset = unpackHeader(header);

    if (expected_offset != stored_offset && stored_offset > -1) {
        isValid = false;
        console.error(
            'offset mismatch: want ' +
                expected_offset +
                ' got ' +
                stored_offset +
                ' header:' +
                header
        );
    }
    //~ else {
       //~ console.log('offset: want ' + expected_offset +
                 //~ ' got ' + stored_offset +
                 //~ ' header:' + header);
    //~ }
    return isValid;
}

/**
 * @ngdoc method
 * @name  unpackHeader
 * @methodOf sync.service:SyncCryptBuffer
 * @description
 * Unpacks the header array and returns the encrypted offset stored within
 * @param  {Uint8Array} header     [description]
 * @return {Integer}           [description]
 */
function unpackHeader(header) {
    const a = new Uint8Array(header);
    let hi = (a[2] << 8) | (a[3] << 0);
    let lo = (a[4] << 24) | (a[5] << 16) | (a[6] << 8) | (a[7] << 0);

    // force to floating point
    hi = hi * 1.0;
    lo = lo * 1.0;
    return hi * (0xFFFFFFFF + 1) + lo;
}

/**
 * Decrypts a data key
 * @param encDataKey base64 number prefix of encrypted data key
 * @param sharekey base64 of the share key (decrypted)
 */
async function datakeyDecrypt(encDataKey, sharekey) {
    const bytes = b64ToBytes(
        encDataKey.split(':')[1]
    );
    try {
        return await decryptDataKey(sharekey, bytes);
    } catch (ex) {
        console.error('Unable to decrypt data key');
        console.error(ex)
    }
}

async function decryptDataKey(sharekey, bytes) {
    const sharekeyBytes = shareKeyToBytes(sharekey);
    if (sharekeyBytes === null) {
        throw new ErrCode(2015);
    }

    const iv = getPartialBytes(bytes, 0, 96),
        rawDk = getPartialBytes(bytes, 96);
    const datakey = await symmetricDecrypt(
        getPartialBytes(sharekeyBytes, 0, 256),
        rawDk,
        iv
    );
    // need to return b64??
    //~ return bytesToB64(datakey);
    return datakey;
}

async function sharekeyDecrypt(
    encShareKey,
    shareKeyId
) {

    const pk = priv;

    try {
        const sharekeyB64 = await asymmetricDecrypt(
            pk,
            encShareKey
        );
        return sharekeyB64;
    } catch (ex) {
        console.errr(
            'Error attempting asymmetric decryption' +
                ' for ' +
                shareKeyId +
                ' ' +
                encShareKey,
            ex
        );
    }
}

/**
 * Decrypts a crypted string with RSA.  Uses PidCrypt's RSA functions.
 * @param  {String} privkey In PEM format with new lines replaced with
 *                          '%' signs.
 * @param  {String} crypted Base64 string
 * @return {Promise}        [description]
 */
async function asymmetricDecrypt(privkey, crypted) {
    try {
        const cert = cleanCertificate(privkey);
        const rsa = new pidCrypt.RSA(),
            key = pidCryptUtil.decodeBase64(cert),
            asn = pidCrypt.ASN1.decode(pidCryptUtil.toByteArray(key)),
            tree = asn.toHexTree();
        const data = pidCryptUtil.decodeBase64(pidCryptUtil.stripLineFeeds(crypted));
        rsa.setPrivateKeyFromASN(tree);

        const ret = pidCryptUtil.encodeBase64(
            rsa.decrypt(pidCryptUtil.convertToHex(data))
        );
        return Promise.resolve(ret);
    } catch (ex) {
        // if errcode 2024 when inviting share, it typically means the enc_password
        // field is invalid.
        console.error('Error in asymmetric decrypt for ' + crypted, ex);
        console.error('SyncCryptLegacy.asymmetricDecrypt() failed');
    }
}

/**
* Cleans a certificate and ensures it's formatted in the correct method.
*
* The certificiate must have all new line chars replaced with '%' signs
*
* @param  {String} privkey [description]
* @return {String}         [description]
*/
function cleanCertificate(privkey) {
    privkey = privkey.split('%').join('\n');
    let cert = '', len, i;
    const lines = privkey.split('\n');
    for (i = 0, len = lines.length; i < len; i++) {
        switch (lines[i].substr(0, 9)) {
            case '-----BEGI': break;
            case '-----END ': break;
            default:
                cert += lines[i].replace(/(\r\n|\n|\r)/gm, ' ');
        }
    }
    return cert;
}


/**
 * Login
 */

let infos = await authenticate(username, password)


/**
 * Store data from login in a decrypted format
 */

const accessData  = infos[0]
const meta        = infos[1][0]
const priv        = infos[1][1]


/**
 * Download and decrypt file
 */

async function download_decrypt_id(id) {
  let getfile = await get(id)
  //~ console.log(getfile)

  let filename = await filenameDecrypt(getfile['enc_name'])
  console.log(filename)

  let data = await getData([getfile])
  //~ console.log(data)

  let datakey_id = getfile['id']
  let sharekey_id = data['datakeys'][datakey_id]['share_key_id']
  let sharekey_dec = await sharekeyDecrypt(data['sharekeys'][sharekey_id], sharekey_id)
  let datakey_enc = data['datakeys'][datakey_id]['enc_data_key']

  let datakey = await datakeyDecrypt(datakey_enc, sharekey_dec)

  // Based if filesize is smaller or larger than GCM PACKET we can download in one time or not
  if (getfile['size'] < GCM_PACKET_SIZE) {
    //~ console.log("smaller file than GCM PACKET")
    const fileStream = fs.createWriteStream(filename)
    // size is size encrypted but we miss the "36" that close the gcm payload
    var download_url = mkDownloadUrl(getfile, 0, getfile['size']+36)
    console.log(download_url)
    
    let data_enc = await got(download_url).buffer()
    let data_bytes_enc = arraybufferToBytes(data_enc)

    fileStream.write(Buffer(await filedataDecrypt(data_bytes_enc, datakey), 'base64'), offset)
  } else {
    //~ console.log("larger file than GCM PACKET")
    var offset = 0
    // CHUNK_SIZE + 1 GCM_PACKET_SIZE
    var length = CHUNK_SIZE + GCM_PACKET_SIZE
    // If filesize is smaller than a chunk we use GCM_PACKET_SIZE instead
    if (getfile['size'] < length){
      //~ console.log("Filesize is smaller than a chunk, use GCM_PACKET_SIZE instead")
      length = GCM_PACKET_SIZE
    }
    const fileStream = fs.createWriteStream(filename)
    while (offset <= getfile['size']) {
      var download_url = mkDownloadUrl(getfile, offset, length)
      //~ console.log("Download started")
      console.log(download_url)
      let data_buffer_enc = await got(download_url).buffer()
      //~ console.log("Download End")
      let start = 0
      let cryptoffset = offset + 0
      while (start < data_buffer_enc.length) {
        let end = start + GCM_PACKET_SIZE
        
        //~ console.log(data_buffer_enc.length)
        //~ console.log('Decrypt...')
        //~ console.log(start)
        //~ console.log(end)

        let data_enc = data_buffer_enc.slice(start, end)
        let data_bytes_enc = arraybufferToBytes(data_enc)
        fileStream.write(Buffer(await filedataDecrypt(data_bytes_enc, datakey), 'base64'), cryptoffset)

        start = start + GCM_PACKET_SIZE
        cryptoffset = cryptoffset + GCM_PACKET_SIZE
      }

      offset = offset + length
      if (getfile['size'] - offset < length) {
        if (length == GCM_PACKET_SIZE) {
          //~ console.log("Calculate last remaining to be downloaded in GCM_PACKET_SIZE")
          // Amount of GCM payload we got
          let gcm_packets_payloads = Math.ceil( (getfile['size'] / GCM_PAYLOAD_SIZE) )
          // For each GCM packets we multiply by 36 for adding authenticated messages
          let additionnal_authenticated_messages = gcm_packets_payloads * 36
          length = ( getfile['size'] - offset ) + additionnal_authenticated_messages
        } else {
          //~ console.log("We cannot download a full chunk anymore, use GCM_PACKET_SIZE")
          length = GCM_PACKET_SIZE
        }
      }

      //~ console.log("next offset: " + offset)
      //~ console.log("next length: " + length)
    }

  }
}


/**
 * Download chunk
 */
async function downloadChunk(getfile, offset, length) {
  let download_url = mkDownloadUrl(getfile, offset, length)       
  //~ console.log(download_url)            
  return await got(download_url).buffer()
}


/**
 * Decrypt chunk
 */
async function decryptChunk(data_buffer_enc, datakey) {
  let decryptArray = []
  let decryptPos = 0

  // We decrypt by GCM_PACKET_SIZE
  while (decryptPos < data_buffer_enc.length) {
    let decryptLen = decryptPos + GCM_PACKET_SIZE

    let data_enc = data_buffer_enc.slice(decryptPos, decryptLen)
    let data_bytes_enc = arraybufferToBytes(data_enc)
    decryptArray.push(Buffer(await filedataDecrypt(data_bytes_enc, datakey), 'base64'))

    decryptPos = decryptPos + GCM_PACKET_SIZE
  }

  return Buffer.concat(decryptArray)
}

/**
 * Download and decrypt to file new
 */
async function download_decrypt_to_file(id) {
    // Variables for download chunk
    let getfile = await get(id)
    let filename = await filenameDecrypt(getfile['enc_name'])
    let size = getfile['size']
    let sizeTotal = (Math.ceil(size / GCM_PAYLOAD_SIZE) * 36) + size

    console.log(filename)

    let fullChunkSize = CHUNK_SIZE + GCM_PACKET_SIZE

    let downloadOffset = 0
    let downloadLen = (sizeTotal - downloadOffset) > fullChunkSize ? fullChunkSize : (sizeTotal - downloadOffset)

    const fileStream = fs.createWriteStream(filename)
    
    while((sizeTotal - downloadOffset) > 0) {
      // Download chunk
      let chunkEncrypted = await downloadChunk(getfile, downloadOffset, downloadLen)

      // Variables needed for decryption
      let data = await getData([getfile])
      let datakey_id = getfile['id']
      let sharekey_id = data['datakeys'][datakey_id]['share_key_id']
      let sharekey_dec = await sharekeyDecrypt(data['sharekeys'][sharekey_id], sharekey_id)
      let datakey_enc = data['datakeys'][datakey_id]['enc_data_key']
      let datakey = await datakeyDecrypt(datakey_enc, sharekey_dec)

      // Decrypt asked chunk
      decryptedChunk = await decryptChunk(chunkEncrypted, datakey)
      fileStream.write(decryptedChunk, downloadOffset)

      // Update downloadOffset and downloadLen
      downloadOffset += downloadLen
      downloadLen = (sizeTotal - downloadOffset) > fullChunkSize ? fullChunkSize : (sizeTotal - downloadOffset)
    }
}


/**
 * Download and decrypt to file new
 */
async function download_decrypt_chunk(id, offset) {
    // Variables for download chunk
    let getfile = await get(id)
    let size = getfile['size']
    let sizeTotal = (Math.ceil(size / GCM_PAYLOAD_SIZE) * 36) + size

    let fullChunkSize = CHUNK_SIZE + GCM_PACKET_SIZE

    let downloadOffset = offset

    // Calculate maximum downloadLen
    // Maximum we can download as length is fullChunkSize
    // fullChunkSize - (downloadOffset % fullChunkSize)
    let downloadLen = (fullChunkSize - (downloadOffset % fullChunkSize))

    // Check if we still get enough to be downloaded for downloadLen
    downloadLen = (sizeTotal - downloadOffset) < downloadLen ? (sizeTotal - downloadOffset) : downloadLen

    // Download chunk
    let chunkEncrypted = await downloadChunk(getfile, downloadOffset, downloadLen)

    // Variables needed for decryption
    let data = await getData([getfile])
    let datakey_id = getfile['id']
    let sharekey_id = data['datakeys'][datakey_id]['share_key_id']
    let sharekey_dec = await sharekeyDecrypt(data['sharekeys'][sharekey_id], sharekey_id)
    let datakey_enc = data['datakeys'][datakey_id]['enc_data_key']
    let datakey = await datakeyDecrypt(datakey_enc, sharekey_dec)

    // Decrypt asked chunk
    return await decryptChunk(chunkEncrypted, datakey)
}


/**
 * Fuse bindings
 */

let mountPath = process.platform !== 'win32' ? './mnt' : 'M:\\'
let vaultID = infos[0]['web_sync_id']
let directories = []

// Variables needed for read function
var decryptedChunk
// Buffering in percent of the file size
let percentBuffering = 25
// Buffering based on percent
var sizeBuffering = 0
// Comment percentBuffering
// And comment "sizeBuffering = 0" if you want use buffering based on size
// Replace x by the amount of MB you wan buffer
// var sizeBuffering =  x * 1024 * 1024
var lastDownloadOffset
// If set to false we must buffering if it's set to true we increment downloadOffset
var flagIncreaseDownloadOffset

fuse.mount(mountPath, {
  readdir: async function (path, cb) {
    //~ console.log('readdir(%s)', path)
    let values
    let path_modified

    if (path === '/') {
      // Search for vaultID
      values = await list(vaultID)
      path_modified = path
    } else {
      // Search for the ID in directories
      let b64_path = new Buffer(path).toString('base64')
      values = await list(directories[b64_path]['id'])
      // Add / at end of path
      path_modified = path + '/'      
    }

    // Prepare the list to be displayed
    let listArray = []

    for( let i of values['pathlist'] ) {
      let filename = await filenameDecrypt(i['enc_name'])

      // Store path as base64 associative value
      let b64 = new Buffer(path_modified + filename).toString('base64')

      // Prepare the array to refresh and keep all dirs
      directories[b64] = {
        filename: filename,
        size: i['size'],
        type: i['type'],
        date: i['date'],
        id: i['id']
      }
      listArray.push(filename)
    }

    return cb(0, listArray)
  },
  getattr: function (path, cb) {
    //~ console.log('getattr(%s)', path)

    if (path === '/') {
      cb(0, {
        mtime: new Date(),
        atime: new Date(),
        ctime: new Date(),
        nlink: 1,
        size: 4096,
        mode: 16877,
        uid: process.getuid ? process.getuid() : 0,
        gid: process.getgid ? process.getgid() : 0
      })
      return
    }

    // Convert path to base64 to search in directories
    let b64 = new Buffer(path).toString('base64')
    if(directories[b64]) {
      if(directories[b64]['type'] == 'dir') {
        cb(0, {
          mtime: directories[b64]['date'],
          atime: directories[b64]['date'],
          ctime: directories[b64]['date'],
          nlink: 1,
          size: 4096,
          mode: 16877,
          uid: process.getuid ? process.getuid() : 0,
          gid: process.getgid ? process.getgid() : 0
        })
        return
      } else {
        cb(0, {
          mtime: directories[b64]['date'],
          atime: directories[b64]['date'],
          ctime: directories[b64]['date'],
          nlink: 1,
          size: directories[b64]['size'],
          mode: 33188,
          uid: process.getuid ? process.getuid() : 0,
          gid: process.getgid ? process.getgid() : 0
        })
        return
      }
    }

    cb(fuse.ENOENT)
  },
  open: function (path, flags, cb) {
    console.log('open(%s, %d)', path, flags)

    // It can happen it start a file when we not want and first action is buffering
    // It's a way to exit properly the action without the need to wait
    console.log("Do you want to buffer (any other answer than 'y' will abort the read operation): ")
    let bufferAsk = scanf('%s')

    // If we not want buffer send error "-1"
    if(bufferAsk != 'y') return cb(-1)

    // Reset variables needed for read
    decryptedChunk = Buffer('')
    lastDownloadOffset = 0
    flagIncreaseDownloadOffset = false

    // If sizeBuffering is 0
    // Define it with percentBuffering and the file size
    if ( percentBuffering ) {
      let path_b64 = new Buffer(path).toString('base64')
      let sizeFile = directories[path_b64]['size']
      let sizeTotal = (Math.ceil(sizeFile / GCM_PAYLOAD_SIZE) * 36) + sizeFile
      //~ console.log("sizeTotal: " + sizeTotal)
      //~ console.log("Math.ceil(sizeTotal/100): " + Math.ceil(sizeTotal/100))
      sizeBuffering = Math.ceil(sizeTotal/100) * percentBuffering
    }

    cb(0, 42)
  },
  read: async function (path, fd, buf, len, pos, cb) {
    console.log('read(%s, %d, %d, %d)', path, fd, len, pos)

    // Define variables to ease code
    let path_b64 = new Buffer(path).toString('base64')
    let sizeFile = directories[path_b64]['size']
    let sizeTotal = (Math.ceil(sizeFile / GCM_PAYLOAD_SIZE) * 36) + sizeFile
    let id =  directories[path_b64]['id']
    let fullChunkSize = CHUNK_SIZE + GCM_PACKET_SIZE

    // Carefull with the sizeBuffering because if the we are at the end of the file we cannot buffer
    let estimatedSizeBuffering = sizeBuffering < sizeFile ? sizeBuffering : sizeFile

    // Start downloading for buffering first later we only add chunk by chunk when we read

    // Only buffering (we compare in bytes) at start
    // After we download the next chunk until the end while reading
    if (flagIncreaseDownloadOffset == false) {
      // Convert pos to posEncrypted
      // pos is the offset in the decrypted file we need to add the aad content to it to have posEncrypted
      let posEncrypted = pos + (Math.ceil(pos / GCM_PAYLOAD_SIZE) * 36)
      //~ console.log("Math.ceil(pos / GCM_PAYLOAD_SIZE): " + Math.ceil(pos / GCM_PAYLOAD_SIZE))
      //~ console.log("GCM_PAYLOAD_SIZE: " + GCM_PAYLOAD_SIZE)

      // Define number of GCM paquet we already get
      // It will be used to define the chunk that we need to download
      // Each fullChunkSize can contain 81 GCM packets
      // TODO what happen at end of file???
      let downloadOffset = Math.floor(Math.ceil(posEncrypted / GCM_PACKET_SIZE) / 81) * fullChunkSize

      // Debug
      console.log("Estimated buffer size: " + estimatedSizeBuffering)

      while ( decryptedChunk.length < estimatedSizeBuffering) {
        // Info related to the buffering
        console.log("Buffering: " + lastDownloadOffset + "/" + estimatedSizeBuffering)

        // Download chunk
        if(flagIncreaseDownloadOffset) {
          downloadOffset += fullChunkSize
          lastDownloadOffset = downloadOffset
          decryptedChunk = Buffer.concat([decryptedChunk, await download_decrypt_chunk(id, downloadOffset)])
        } else {
          decryptedChunk = Buffer.concat([decryptedChunk, await download_decrypt_chunk(id, downloadOffset)])
          lastDownloadOffset = downloadOffset
          flagIncreaseDownloadOffset = true
        }
      }
    } else {
      // First read all what we can download again later so we will download new chunk and have advance in reads
      // Because we not discarding anymore use pos+len instead of len
      //~ if( decryptedChunk.length < len ) {
      if( decryptedChunk.length < (pos+len) ) {
        downloadOffset = lastDownloadOffset + fullChunkSize
        lastDownloadOffset = downloadOffset
        // Download only if lastDownloadOffset + fullChunkSize < sizeTotal
        if ( lastDownloadOffset < sizeTotal ) {
          decryptedChunk = Buffer.concat([decryptedChunk, await download_decrypt_chunk(id, downloadOffset)])
        }
      }
    }

    // Read the asked part from decryptedChunk
    // Discarding parts make having a weird behavior for now just keep everything
    // We will see if it's too much on memory later or not
    //~ let decryptPart = decryptedChunk.slice(0, len)
    //~ decryptedChunk = decryptedChunk.slice(len)
    let decryptPart = decryptedChunk.slice(pos, pos+len)
    if(decryptPart.length > 0) {
      buf.fill(decryptPart)
      cb(decryptPart.length)
    } else {
      return cb(0)
    }
  }
}, function (err) {
  if (err) throw err
  console.log('filesystem mounted on ' + mountPath)
})

process.on('SIGINT', function () {
  fuse.unmount(mountPath, function (err) {
    if (err) {
      console.log('filesystem at ' + mountPath + ' not unmounted', err)
    } else {
      console.log('filesystem at ' + mountPath + ' unmounted')
    }
  })
})

})()

//~ --------

    //~ public uploadItem(tItem: sync.ITransferItemUpload): ng.IPromise<sync.ITransferItemStats> {
        //~ let dfd: ng.IDeferred<sync.ITransferItemStats> = this.$q.defer(),
            //~ startMs = Date.now();
        //~ tItem.sha1_digest = this.SyncDigest.init();
        //~ this.encTime = 0;
        //~ let preUploadTime = 0;
        //~ let uploadTime = 0;
        //~ let finishUploadTime = 0;

        //~ let startPreUpload = Date.now();
        //~ let startUpload: number;
        //~ let startFinishUpload: number;
        //~ // console.log('START UPLOAD ', tItem.filedata);
        //~ tItem.status = this.TransferStatus.STATUS_WORKING;
        //~ this.preUpload(tItem)
            //~ .then((tItem) => {
                //~ preUploadTime = Date.now() - startPreUpload;
                //~ startUpload = Date.now();
                //~ return this.getFile(tItem);
            //~ })
            //~ .then((tItem) => {
                //~ this.Logger.info('Encryption time = ' + this.encTime + ' ms');
                //~ uploadTime = Date.now() - startUpload;
                //~ startFinishUpload = Date.now();
                //~ console.log(tItem);
                //~ if (tItem.linkID) {
                    //~ return this.finishUploadPublic(tItem);
                //~ } else {
                    //~ return this.finishUpload(tItem);
                //~ }
            //~ }).then( () => {
                //~ finishUploadTime = Date.now() - startFinishUpload;
                //~ var timeTaken = (Date.now() - startMs);
                //~ var bps = tItem.filesize / timeTaken / 1000;
                //~ this.Logger.info([
                    //~ ' Upload completed successfully: ', (timeTaken / 1000),' seconds total, ' ,
                    //~ ' pre-upload:', preUploadTime, 'ms, ',
                    //~ ' upload: ', uploadTime, 'ms, ',
                    //~ ' sendTime: ', this.sendTime, ' ms, ',
                    //~ ' packet time : ', this.encTime, ' ms ',
                    //~ ' file encrypt time: ', this.digestTime, ' ms ',
                    //~ ' read time: ', this.readTime, ' ms ',
                    //~ ' finish-upload: ', finishUploadTime, 'ms ',
                    //~ 'at ', (bps / 1000), 'kbps'
                //~ ].join(' '));
                //~ tItem.status = this.TransferStatus.STATUS_SUCCESS;
                //~ tItem.sha1_digest = undefined;
                //~ // console.log('UPLOAD SUCCESS ', tItem.filedata);

                //~ dfd.resolve({
                    //~ size: tItem.filesize,
                    //~ sendTime: this.sendTime,
                    //~ encTime: this.encTime,
                    //~ elapsed: timeTaken,
                    //~ elapsedPreUpload: preUploadTime,
                    //~ elapsedUpload: uploadTime,
                    //~ elapsedFinishUpload: finishUploadTime,
                    //~ bps: bps
                //~ });
            //~ }).
            //~ catch((data) => {
                //~ this.Logger.error('AN ERROR OCCURRED UPLOADING!!');
                //~ if (typeof data === 'object' && data.errors && data.errors.length) {
                    //~ tItem.status = data.errors[0].error_code || this.TransferStatus.STATUS_ERROR;
                    //~ this.Logger.error(data.errors[0].error_msg);
                //~ }
                //~ else if (data.errcode !== 0) {
                    //~ tItem.status = data.errcode;
                //~ } else {
                    //~ tItem.status = this.TransferStatus.STATUS_ERROR;
                //~ }
                //~ this.Logger.error('TransferItem.status = ' + tItem.status);
                //~ dfd.reject(data);
            //~ });

        //~ return dfd.promise;
    //~ }

    //~ private preUpload(tItem: sync.ITransferItemUpload): ng.IPromise<sync.ITransferItemUpload> {
        //~ let dfd: ng.IDeferred<sync.ITransferItemUpload> = this.$q.defer();
        //~ if (tItem.linkID) {
            //~ this.TransferApi.preuploadPublic(
                //~ tItem.sync_pid,
                //~ tItem.enc_share_name,
                //~ tItem.linkID
            //~ ).then( (data) => {
                //~ tItem.user_id = data.user_id;
                //~ tItem.sync_id = data.sync_id;
                //~ tItem.servtime = data.servtime;
                //~ tItem.backup_id = data.backup_id;
                //~ tItem.device_id = data.device_id;
                //~ tItem.device_sig_b64 = data.device_sig_b64;
                //~ dfd.resolve(tItem);
            //~ }). catch((err) => dfd.reject(err));
        //~ } else {
            //~ this.TransferApi.preupload(tItem.sync_pid, tItem.enc_name).
                //~ then((data) => {
                    //~ tItem.user_id = this.User.get('uid');

                    //~ tItem.sync_id = data.sync_id;
                    //~ tItem.servtime = data.servtime;
                    //~ tItem.share_id = data.share_id;
                    //~ tItem.share_sequence = data.share_sequence;
                    //~ tItem.backup_id = data.backup_id;
                    //~ tItem.device_id = data.device_id;
                    //~ tItem.device_sig_b64 = data.device_sig_b64;
                    //~ tItem.enc_share_key = data.enc_share_key;
                    //~ tItem.share_key_id = data.share_key_id;

                    //~ if (!tItem.share_key) {
                        //~ this.SyncCrypt.sharekeyDecrypt(
                            //~ data.enc_share_key, data.share_key_id).
                        //~ then((sharekey) => {
                            //~ tItem.share_key = sharekey;
                            //~ dfd.resolve(tItem);
                        //~ }). catch((err) => dfd.reject(err));;
                    //~ } else {
                        //~ dfd.resolve(tItem);

                    //~ }
                //~ }). catch((err) => dfd.reject(err));
        //~ }
        //~ return dfd.promise;
    //~ }

    //~ private processPiece(tItem: sync.ITransferItemUpload, payload: sync.IUploadPayload, dfd: ng.IDeferred<sync.ITransferItemUpload>) {
        //~ let start = Date.now();
        //~ let queue = tItem.chunkqueue.shift();
        //~ if (payload.data.length === 0) {
            //~ payload.offset = queue.offset;
            //~ payload.enc_offset = queue.enc_offset;
        //~ }
        //~ tItem.status = this.TransferStatus.STATUS_ENC_UPLOAD;
        //~ this.loadPiece(tItem, queue.offset, queue.chunklen)
            //~ .then( (buffer: ArrayBuffer) => {
                //~ let endPiece = Date.now();
                //~ // this.Logger.info('loadPiece at ' + queue.offset + ' len ' + queue.chunklen + ' - ' + (endPiece - start) + ' ms');
                //~ let bytearray = this.SyncCrypt.arraybufferToBytes(buffer);
                //~ tItem.sha1_digest = this.SyncDigest.update(tItem.sha1_digest, bytearray);

                //~ let ss = Date.now();
                //~ this.SyncCrypt.filedataEncrypt(bytearray, tItem.data_key, queue.offset)
                    //~ .then( (encByteArray) => {
                        //~ let ee = Date.now();

                        //~ this.digestTime = this.digestTime + (ee - ss);

                        //~ // this.Logger.info('fileData was successfully encrypted');
                        //~ payload.data = this.SyncCrypt.filedataAppend(
                            //~ payload.data,
                            //~ encByteArray
                        //~ );
                        //~ payload.chunklen += queue.chunklen;
                        //~ let end = Date.now();
                        //~ // console.log ((end - start) + ' ms enc time added for this chunk');
                        //~ this.encTime = this.encTime + (end - start);

                        //~ if (payload.chunklen >= this.CHUNKSIZE || !tItem.chunkqueue.length) {
                            //~ tItem.status = this.TransferStatus.STATUS_UPLOAD;// STATUS_UPLOAD

                            //~ let _s = Date.now();
                            //~ this.sendChunk(tItem, payload)
                                //~ .then((data) => {
                                    //~ let _e = Date.now();
                                    //~ this.sendTime = this.sendTime + (_e - _s);
                                    //~ console.log((_e - _s) + ' ms for send now ')
                                    //~ tItem.blob_id = data.blob_id;
                                    //~ tItem.cachekey = data.cachekey;
                                    //~ payload.data = [];
                                    //~ payload.offset = 0;
                                    //~ payload.chunklen = 0;
                                    //~ payload.enc_offset = 0;
                                    //~ if (tItem.chunkqueue.length) {
                                        //~ this.processPiece(tItem, payload, dfd);
                                    //~ } else {
                                        //~ dfd.resolve(tItem);
                                    //~ }
                                //~ }, (err) => dfd.reject(err),
                            //~ (progEvent: ProgressEvent) => {
                                //~ let bytes = payload.offset + progEvent.loaded;
                                //~ let p = Math.round(bytes / tItem.filesize * 100 * 100) / 100;
                                //~ tItem.progress_percent = (p >= 100) ? 99 : p;
                                //~ tItem.bytes_sent = (bytes > tItem.filesize) ? tItem.filesize : bytes;
                            //~ });
                        //~ } else {
                            //~ if (tItem.chunkqueue.length) {
                                //~ this.processPiece(tItem, payload, dfd);
                            //~ } else {
                                //~ dfd.resolve(tItem);
                            //~ }
                        //~ }

                    //~ }).catch((err) => dfd.reject({errcode: 2050}));
            //~ }).catch((err) => dfd.reject(err));
    //~ }

    //~ private sendChunk(tItem: sync.ITransferItemUpload, payload:sync.IUploadPayload): ng.IPromise<any> {
        //~ let encChunkLen = payload.chunklen + Math.ceil(payload.chunklen / this.SyncCrypt.GCM_PAYLOAD_SIZE) * 36;
        //~ return this.TransferApi.uploadMultiChunk(
            //~ this.SyncCrypt.prepareDataSend(payload.data),
            //~ {
                //~ cachekey: tItem.cachekey || '',
                //~ enc_offset_byte: payload.enc_offset,
                //~ enc_chunk_size_bytes: encChunkLen, // account for gcm tag
                //~ payload_crc32: 'DeadBeef',
                //~ payload_len: encChunkLen, // account for gcm tag

                //~ // authentication data
                //~ device_sig_b64: tItem.device_sig_b64,
                //~ servtime: tItem.servtime,
                //~ backup_id: tItem.backup_id,
                //~ user_id: tItem.user_id || this.User.get('uid'),
                //~ device_id: tItem.device_id,

                //~ // modified_epochtime: new Date(tItem.filedate).getTime(),
                //~ // size_bytes: tItem.filesize,
                //~ // offset_byte: payload.offset,
                //~ // length_bytes: payload.chunklen,
                //~ // blob_id: tItem.blob_id
            //~ }, 0);
    //~ }

//~ ---------------

    //~ /**
     //~ * @ngdoc method
     //~ * @name  preupload
     //~ * @methodOf sync.service:TransferApi
     //~ * @description
     //~ * Prepares to upload a new file.  Returns the inherited share information
     //~ * and generates a backup id to track the blob chunks.
     //~ *
     //~ * @param  {Integer} sync_pid The sync PID where it will be uploaded to.
     //~ * @param  {String} enc_name Base64 string of the meta encrypted name
     //~ * @returns {Promise} The promise from the API call
     //~ */
    //~ public preupload(sync_pid: number, enc_name: string): ng.IPromise<sync.IResultPathPreUpload> {
        //~ return this.execute('pathpreupload', {
            //~ sync_pid: sync_pid,
            //~ enc_name: enc_name
        //~ });
    //~ };

    //~ public uploadMultiChunk(payload: Uint8Array, json: any, count: number, defer: ng.IDeferred<any>) {
        //~ const dfd = defer || this.$q.defer();
        //~ const formData = new FormData();
        //~ let retryCount = count || 0;
        //~ let blob = new Blob([payload]);

        //~ const startTime = Date.now();

        //~ formData.append('json', JSON.stringify({
            //~ 'device_sig_b64': json.device_sig_b64,
            //~ // used for auth
            //~ 'backup_id': json.backup_id,
            //~ 'device_id': json.device_id,
            //~ user_id: json.user_id,
            //~ servtime : json.servtime,
            //~ chunks: [{
                //~ object_type: 'btFILE',
                //~ cachekey: json.cachekey || '',
                //~ payload_crc32: 'DeadBeef',
                //~ enc_offset_byte: json.enc_offset_byte,
                //~ payload_len: json.payload_len,
                //~ enc_chunk_size_bytes: json.enc_chunk_size_bytes

            //~ }]
        //~ }));
        //~ formData.append('payload0', blob, 'payload0.data');

        //~ function doRetryOrFail(resp: any) {
            //~ retryCount++;
            //~ if (retryCount < this.UrlService.uploadhosts.length
                //~ && this.UrlService.uploadhosts[retryCount]) {
                //~ this.Logger.warn(`Retrying upload with host ${this.UrlService.uploadhosts[retryCount]}`)
                //~ this.$timeout(() => {
                    //~ this.Logger.warn('uploadChunk received status -1 || 500, retrying')
                    //~ return this.uploadMultiChunk(
                            //~ payload,
                            //~ json,
                            //~ retryCount,
                            //~ dfd
                        //~ );
                    //~ }, 300 * (retryCount + 1));
            //~ } else {
                //~ this.Logger.error(status + ' ' + url);
                //~ this.Logger.error(`INPUT: ${JSON.stringify(json)}`);
                //~ this.Logger.error(`OUTPUT: ${JSON.stringify(resp)}`);
                //~ dfd.reject({errcode: 7000});
                //~ return;
            //~ }
        //~ }

        //~ if (blob.size != json.payload_len) {
            //~ this.Logger.error('Upload size mismatch.  ' + blob.size + ' != ' + json.payload_len);
            //~ dfd.reject({code: 7011});
            //~ return;
        //~ }
        //~ let url = this.UrlService.mkUpload(this.UrlService.uploadhosts[retryCount], 'uploadmultichunk');
        //~ this.$http({
            //~ method: 'POST',
            //~ url: url,
            //~ data: formData,
            //~ timeout: 100000000,
            //~ headers: { 'Content-Type': undefined},
            //~ eventHandlers: {
                //~ timeout: (evt) => {
                    //~ this.Logger.error('upload timed out');
                    //~ this.Logger.error(`INPUT: ${angular.toJson(json)}`);
                    //~ this.Logger.error('Upload timed out on first chunk');
                    //~ return dfd.reject({errcode: 7005});
                //~ },
                //~ abort: (evt) => {
                    //~ blob = null;
                    //~ this.Logger.error(status + ' ' + url);
                    //~ this.Logger.error('uploadChunk xhr onabort ' +  angular.toJson(evt));
                    //~ dfd.reject({errcode: 7000});
                //~ },
            //~ },
            //~ uploadEventHandlers: {
                //~ progress: (evt) => dfd.notify(evt)
            //~ }
        //~ }).then((response) => {
            //~ const endTime = Date.now();
            //~ this.Logger.info('Upload transfer took ' + (endTime - startTime) + ' ms');

            //~ let jsonData: any = response.data;
            //~ // errcode 2 means the API thinks I should retry
            //~ if (jsonData && jsonData.success == 0 && jsonData.errcode == 2) {
                //~ this.Logger.warn('Error received errcode 2, retrying');
                //~ doRetryOrFail.bind(this, response)();
                //~ return;
            //~ } else if (jsonData.success === 0 && !jsonData.errcode) {
                //~ this.Logger.error(response.status + ' ' + url);
                //~ this.Logger.error(`INPUT: ${JSON.stringify(json)}`);
                //~ this.Logger.error(`OUTPUT: ${JSON.stringify(response)}`);
                //~ this.Logger.error('uploadChunk success == 0, errcode = 7020 in upload chunk');
                //~ return dfd.reject({errcode: 7020});
            //~ } else if (jsonData.success == 0) {
                //~ this.Logger.error(response.status + ' ' + url);
                //~ this.Logger.error(`INPUT: ${JSON.stringify(json)}`);
                //~ this.Logger.error(`OUTPUT: ${response}`);
                //~ if (jsonData.errors) {
                    //~ this.Logger.error(JSON.stringify(jsonData.errors));
                //~ }
                //~ this.Logger.error('uploadChunk success == 0 error in upload chunk');
                //~ return dfd.reject({errcode: 7020});
            //~ } else {
                //~ this.Logger.info(status + ' ' + url + ' success');
                //~ if (jsonData.success == 1 && jsonData.chunks.length == 1) {
                    //~ dfd.resolve(jsonData.chunks[0]);
                //~ } else {
                    //~ this.Logger.error('An unexpected result was received during upload');
                    //~ this.Logger.error(`INPUT: ${JSON.stringify(json)}`);
                    //~ this.Logger.error(`OUTPUT: ${JSON.stringify(jsonData)}`);
                    //~ dfd.reject({errcode: 7020});
                //~ }
            //~ }

        //~ })
        //~ .catch((resp) => {
            //~ this.Logger.error(`${resp.status} ${resp.xhrStatus} ${url}`)
            //~ console.log(resp);
            //~ if (resp.status === 0 || !resp) {
                //~ this.Logger.error('uploadChunk status = 0 || !response ' + url);
                //~ this.Logger.error(`INPUT: ${JSON.stringify(json)}`);
                //~ this.Logger.error(`OUTPUT: ${JSON.stringify(resp)}`);
                //~ dfd.reject({errcode: 7023});
                //~ return;
            //~ } else  if (resp.status === -1 || resp.status >= 500) {
                //~ doRetryOrFail.bind(this, resp)();
                //~ return;
            //~ } else {
                //~ this.Logger.error('An unknown error occurred');
                //~ this.Logger.error(`INPUT: ${JSON.stringify(json)}`);
                //~ this.Logger.error(`OUTPUT: ${JSON.stringify(resp)}`);
                //~ dfd.reject({errcode: 7000})
            //~ }
        //~ })


        //~ return dfd.promise;
    //~ }

    //~ public finishUpload(json: any) {
        //~ let dfd =  this.$q.defer();
        //~ let xhr = new XMLHttpRequest();
        //~ let formData = new FormData();
        //~ formData.append('json', angular.toJson(json));

        //~ xhr.open('POST',
                //~ this.UrlService.mkUpload(this.UrlService.uploadhosts[0], 'webfinishbackup'),
                //~ true
        //~ );
        //~ xhr.ontimeout = (evt) => {
            //~ xhr = null;
            //~ formData = null;
            //~ this.Logger.error('Finish upload timed out');
            //~ return dfd.reject({errcode: 7005});
        //~ };
        //~ xhr.onload = () => {
            //~ let status = xhr.status === 1223 ? 204 : xhr.status;
            //~ let response = xhr.response;
            //~ let statustext = xhr.statusText || '';
            //~ this.Logger.info(status + ' is the status');
            //~ xhr = null;
            //~ formData = null;
            //~ if (status === 0 || !response) {
                //~ this.Logger.error('webfinishbackup An unknown error occurred, no response received and status = 0 during finish backup');
                //~ this.Logger.error(`INPUT: ${angular.toJson(json)}`);
                //~ this.Logger.error(`OUTPUT: ${response}`);
                //~ dfd.reject({errcode: 7023});
            //~ }
            //~ if (status === -1 || status >= 500) {
                    //~ this.Logger.error('finishUpload() status ' + status);
                    //~ this.Logger.error(`INPUT: ${angular.toJson(json)}`);
                    //~ this.Logger.error(`OUTPUT: ${response}`);
                    //~ dfd.reject({errcode: 7020});
            //~ }
            //~ let jsonData: any = {};
            //~ try {
                //~ jsonData = angular.fromJson(response);
            //~ } catch (ex) {

                    //~ this.Logger.error('Exception parsing finishUpload() response ' + ex.toString());
                    //~ this.Logger.error(`INPUT: ${angular.toJson(json)}`);
                    //~ this.Logger.error(`OUTPUT: ${response}`);
                    //~ dfd.reject({errcode: 7020});
            //~ }

            //~ if (parseInt(jsonData.success, 10) === 0 && jsonData.errcode === 2)
            //~ {
                    //~ this.Logger.error(`INPUT: ${angular.toJson(json)}`);
                    //~ this.Logger.error(`OUTPUT: ${response}`);
                    //~ dfd.reject({errcode: 7000});
            //~ }
            //~ else if (jsonData.success === 0 && !jsonData.errcode)
            //~ {
                //~ this.Logger.error('webfinishbackup success == 0, errcode = 7022');
                //~ this.Logger.error(`INPUT: ${angular.toJson(json)}`);
                //~ this.Logger.error(`OUTPUT: ${response}`);
                //~ return dfd.reject({errcode: 7022});
            //~ }
            //~ else if (jsonData.success == 1) {
                //~ return dfd.resolve(jsonData);
            //~ } else {
                //~ this.Logger.error('webfinishbackup case from response output');
                //~ this.Logger.error(`INPUT: ${angular.toJson(json)}`);
                //~ this.Logger.error(`OUTPUT: ${response}`);
                //~ return dfd.reject({errcode: 7022});
            //~ }
        //~ };
        //~ xhr.onerror = reqError;
        //~ xhr.onabort = reqError;
        //~ var reqError = (evt: Event) => {
            //~ xhr = null;
            //~ formData = null;
            //~ dfd.reject({errcode: 7000});
        //~ };

        //~ xhr.send(formData);

        //~ return dfd.promise;
    //~ }

//~ ----------

    //~ public async filedataEncrypt(
        //~ data: ArrayLike<number>,
        //~ key: ArrayLike<number>,
        //~ offset: number
    //~ ): Promise<ArrayLike<number>> {
        //~ offset = offset || 0;
        //~ const iv = this.getRandom(96);

        //~ return await this.mCrypt.symmetricEncrypt(
            //~ this.mCrypt.getPartialBytes(key, 0, 256),
            //~ data,
            //~ iv,
            //~ this.mCrypt.packHeader(offset)
        //~ );
    //~ }

    //~ /**
     //~ * @ngdoc method
     //~ * @name  symmetricEncrypt
     //~ * @methodOf sync.service:CryptMethodLegacy
     //~ * @description
     //~ * Encrypts data using symmetric encryption via sjcl
     //~ * @param  {Array} key    The AES key
     //~ * @param  {Array} plain  [description]
     //~ * @param  {Array} iv     [description]
     //~ * @param  {Array|null} header [description]
     //~ * @return {Promise}        [description]
     //~ */
    //~ public symmetricEncrypt(key: Array<number>, plain: Array<number>, iv: Array<number>, header?: Array<number>): Promise<Array<number>> {
        //~ header = header || [];
        //~ try {
            //~ const aes = new sjcl.cipher.aes(key),
                //~ data = sjcl.mode.gcm.encrypt(aes, plain, iv, header, 96);
            //~ return Promise.resolve([].concat(header).concat(iv).concat(data));
        //~ } catch (ex) {
            //~ this.Logger.e('CryptLegacy symmetric encrypt failed', ex);
            //~ throw new ErrCode(2050);
       //~ }
    //~ }

    //~ /**
    //~ * @ngdoc method
    //~ * @name  unpackHeader
    //~ * @methodOf sync.service:SyncCryptLegacy
    //~ * @description
    //~ * Packs a header for AES and embeds the offset in the first 8 bytes of the
    //~ * header.  The number is encoded as an 8 byte array with the most significant
    //~ * digit at index 0 and least significant at index 7.
    //~ *
    //~ * @param {int} offset the offsset.
    //~ * @return {array} a byte array containing 3 32bit words.
    //~ */
    //~ public packHeader(offset: number): Array<number> {
        //~ const hi = Math.floor(offset / 0xFFFFFFFF),
            //~ lo = offset | 0x0;

        //~ if (hi > 0xFF) {
            //~ throw new Error('offset is too big (max = 2^40)');
        //~ }

        //~ const a = 0 |
            //~ (hi & 0xFF000000) |
            //~ (hi & 0x00FF0000) |
            //~ (hi & 0x0000FF00) |
            //~ (hi & 0x000000FF);

        //~ const b = 0 |
            //~ (lo & 0xFF000000) |
            //~ (lo & 0x00FF0000) |
            //~ (lo & 0x0000FF00) |
            //~ (lo & 0x000000FF);
        //~ return [a, b, 0];
    //~ }
