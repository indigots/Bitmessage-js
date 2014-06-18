eciesBlockSize = 16; // fix later
function eciesEncrypt(dataBytes, pubKeyBytes, optionalSecureRandom){
  var r = new Bitcoin.ECKey(false);
  var RpubBytes = r.getPub();
  var curve = getSECCurveByName("secp256k1").getCurve();
  var curveBytes = Crypto.util.hexToBytes("02ca");
  var pointLenBytes = Crypto.util.hexToBytes("0020");
  // need to convert from raw key to x and y
  var KpointX = pubKeyBytes.slice(1,33);
  KpointX.unshift(0); //remove sign
  var KpointY = pubKeyBytes.slice(33);
  KpointY.unshift(0); //remove sign

  var K = new ECPointFp(curve,
    curve.fromBigInteger(new BigInteger(KpointX, 256)),
    curve.fromBigInteger(new BigInteger(KpointY, 256)));
  var rPrivBigInt = r.priv;
  var P = K.multiply(rPrivBigInt);
  var PxHex = P.getX().toBigInteger().toString(16);
  var PyHex = P.getY().toBigInteger().toString(16);
  PxHex = hexPad(PxHex, 64);
  PyHex = hexPad(PyHex, 64);
  var PPubHex = "04" + PxHex + PyHex;
  var PPubBytes = Crypto.util.hexToBytes(PPubHex);
  var PxBytes = PPubBytes.slice(1,33);
  var shaOfPxBytes = sha512Bytes(PxBytes);
  var key_eBytes = shaOfPxBytes.slice(0,32);
  //updateConsole('key e: ' + Crypto.util.bytesToHex(key_eBytes));
  var key_mBytes = shaOfPxBytes.slice(32);
  //updateConsole('key m: ' + Crypto.util.bytesToHex(key_mBytes));
  var key_eHex = Crypto.util.bytesToHex(key_eBytes);
  var ivBytes = new Array(16);
  if(optionalSecureRandom){
    optionalSecureRandom.nextBytes(ivBytes);
  } else {
    (new SecureRandom()).nextBytes(ivBytes);
  }
  //updateConsole(Crypto.util.bytesToHex(ivBytes));
  var encrypted = CryptoJS.AES.encrypt(bytesToWords(dataBytes), bytesToWords(key_eBytes), {iv: bytesToWords(ivBytes)});
  var encryptedBytes = Crypto.util.base64ToBytes(encrypted);
  //updateConsole(encryptedBytes);
  var hmacObj = CryptoJS.HmacSHA256(bytesToWords(encryptedBytes), bytesToWords(key_mBytes));
  var hmacBytes = Crypto.util.hexToBytes(hmacObj.toString());
  //updateConsole(hmacObj.toString());
  var finalBytes = ivBytes.concat(curveBytes)
    .concat(pointLenBytes)
    .concat(RpubBytes.slice(1,33))
    .concat(pointLenBytes)
    .concat(RpubBytes.slice(33))
    .concat(encryptedBytes)
    .concat(hmacBytes);
  //alert(Crypto.util.bytesToHex(finalBytes));
  return finalBytes;
}

function eciesDecrypt(dataBytes, inprivkeyhex){
  //updateConsole('full crypt text: ' + Crypto.util.bytesToHex(dataBytes));
  if(!dataBytes || dataBytes.length < 134){
    //updateConsole('Message too short.');
    return null;
  }
  var key = new Bitcoin.ECKey(Crypto.util.hexToBytes(inprivkeyhex));
  //updateConsole('priv num: ' + key.priv.toString());
  var ivBytes = dataBytes.slice(0,16);
  //updateConsole('iv: ' + Crypto.util.bytesToHex(ivBytes));
  var curveBytes = dataBytes.slice(16,18);
  //updateConsole('curve bytes: ' + Crypto.util.bytesToHex(curveBytes));
  var xLenBytes = dataBytes.slice(18,20);
  //updateConsole('x len bytes: ' + Crypto.util.bytesToHex(xLenBytes));
  var xBytes = dataBytes.slice(20,52);
  //updateConsole('x bytes: ' + Crypto.util.bytesToHex(xBytes));
  var yLenBytes = dataBytes.slice(52,54);
  //updateConsole('y len bytes: ' + Crypto.util.bytesToHex(yLenBytes));
  var yBytes = dataBytes.slice(54,86);
  //updateConsole('y bytes: ' + Crypto.util.bytesToHex(yBytes));
  var macBytes = dataBytes.slice(-32);
  //updateConsole('mac bytes: ' + Crypto.util.bytesToHex(macBytes));
  var cipherBytes = dataBytes.slice(86,-32);
  //updateConsole('cipher text bytes: ' + Crypto.util.bytesToHex(cipherBytes));
  if(curveBytes[0] != 02 || curveBytes[1] != 202){return null;}
  if(xLenBytes[0] != 0 || xLenBytes[1] != 32){return null;}
  if(yLenBytes[0] != 0 || yLenBytes[1] != 32){return null;}
  //updateConsole('Sane.');

  //Remove sign
  xBytes.unshift(0);
  yBytes.unshift(0);

  var curve = getSECCurveByName("secp256k1").getCurve();
  var R = new ECPointFp(curve,
    curve.fromBigInteger(new BigInteger(xBytes, 256)),
    curve.fromBigInteger(new BigInteger(yBytes, 256)));
  var P = R.multiply(key.priv);
  var PxHex = P.getX().toBigInteger().toString(16);
  var PyHex = P.getY().toBigInteger().toString(16);
  PxHex = hexPad(PxHex, 64);
  PyHex = hexPad(PyHex, 64);
  var PPubHex = "04" + PxHex + PyHex;
  var PPubBytes = Crypto.util.hexToBytes(PPubHex);
  var PxBytes = PPubBytes.slice(1,33);
  var shaOfPxBytes = sha512Bytes(PxBytes);
  var key_eBytes = shaOfPxBytes.slice(0,32);
  //updateConsole('key e: ' + Crypto.util.bytesToHex(key_eBytes));
  var key_mBytes = shaOfPxBytes.slice(32);
  //updateConsole('key m: ' + Crypto.util.bytesToHex(key_mBytes));
  var hmacObj = CryptoJS.HmacSHA256(bytesToWords(cipherBytes), bytesToWords(key_mBytes));
  var resultHmacBytes = Crypto.util.hexToBytes(hmacObj.toString());
  if(Crypto.util.bytesToHex(macBytes) != Crypto.util.bytesToHex(resultHmacBytes)){
    return null;
  }
  var decrypted = CryptoJS.AES.decrypt(Crypto.util.bytesToBase64(cipherBytes), 
    bytesToWords(key_eBytes), 
    {iv: bytesToWords(ivBytes)});
  return Crypto.util.hexToBytes(decrypted.toString());
}

function fullTest(){
  var x = new Bitcoin.ECKey(false);
  updateConsole('priv key: ' + x.priv.toString());
  var xpub = x.getPub();
  var toEncHex = 'abcabcabc';
  var encrypted = eciesEncrypt(Crypto.util.hexToBytes(toEncHex), xpub);
  var decrypted = eciesDecrypt(encrypted, Crypto.util.hexToBytes(x.toString()));
}

function sha512Bytes(inBytes){
  return wordsToBytes(CryptoJS.SHA512(bytesToWords(inBytes)));
}

function testEncrypt(){
  var pubKeyKHex = "0409d4e5c0ab3d25fe048c64c9da1a242c7f19417e9517cd266950d72c755713585c6178e97fe092fc897c9a1f1720d5770ae8eaad2fa8fcbd08e9324a5dde1857";
  var pubKeyK = Crypto.util.hexToBytes(pubKeyKHex);
  var IVHex = "bddb7c2829b08038753084a2f3991681";
  //The following would be randomly generated
  var privKeyrHex = "5be6facd941b76e9d3ead03029fbdb6b6e0809293f7fb197d0c51f84e96b8ba4";
  var r = new Bitcoin.ECKey(Crypto.util.hexToBytes(privKeyrHex));
  var RHex = Crypto.util.bytesToHex(r.getPub());
  var curve = getSECCurveByName("secp256k1").getCurve();
  var Kpointx = pubKeyK.slice(1,33);
  var Kpointy = pubKeyK.slice(33);
  var K = new ECPointFp(curve,
    curve.fromBigInteger(new BigInteger(Kpointx, 256)),
    curve.fromBigInteger(new BigInteger(Kpointy, 256)));
  var rPrivBigInt = r.priv;
  var P = K.multiply(rPrivBigInt);
  var PxHex = P.getX().toBigInteger().toString(16);
  var PyHex = P.getY().toBigInteger().toString(16);
  PxHex = hexPad(PxHex, 64);
  PyHex = hexPad(PyHex, 64);
  var PPubHex = "04" + PxHex + PyHex;
  var PPubBytes = Crypto.util.hexToBytes(PPubHex);
  var PxBytes = PPubBytes.slice(1,33);
  var shaOfPxBytes = sha512Bytes(PxBytes);
  //alert(Crypto.util.bytesToHex(shaOfPxBytes));
  var key_eBytes = shaOfPxBytes.slice(0,32);
  var key_mBytes = shaOfPxBytes.slice(32);
  //alert(Crypto.util.bytesToHex(key_eBytes) + ' ' + Crypto.util.bytesToHex(key_mBytes));
  var key_eHex = Crypto.util.bytesToHex(key_eBytes);
  var encrypted = CryptoJS.AES.encrypt("The quick brown fox jumps over the lazy dog.", bytesToWords(key_eBytes), {iv: CryptoJS.enc.Hex.parse(IVHex)});
  var encryptedBytes = Crypto.util.base64ToBytes(encrypted);
  //alert(Crypto.util.bytesToHex(encryptedBytes));
  var hmacHex = CryptoJS.HmacSHA256(bytesToWords(encryptedBytes), bytesToWords(key_mBytes));
  alert('IV: ' + IVHex
    + ' Public Key: ' + RHex
    + ' Cipher Text: ' + Crypto.util.bytesToHex(encryptedBytes)
    + ' HMAC: ' + hmacHex);
}
function updateConsole(words){
  $('#ecConsole').val(words + '\n' + $('#ecConsole').val().substr(0,2000));
}
function testEcies(hexkey, indata){
  //enckeyhex = '995d6fc3ef13b210abafa83591b7cd7019db59448bc5b4fff6f1f6a8c1eae898';
  //rawdatahex ='000000012145fbe4f34715d56f1c00fcf11270c221a827a5a736af0e3baa952fe2324819a85ed5358e822b85a1fc6749068ef35caadc463d12fb205ec7022f9788817d4e533de7704f5ba19e66982a6311ac08f89aac2199b22ea7d3874371f7b02eb66a31a854d0154dc738fbca9af5d0f0455156a68fef5d7c63a0128c275e8372d6b7fd0280fd36b04630440220318bfb4c1ca50d6887fc8d32a869235adc45f130bedf0db4f5a9ad2d2d86248d0220791e54796b817d41ffcc16339285a6c7c996284227630ee0d4ceb3fbed65ce66';
  //enckeyhex = '28f508c24ed452e5f8d132c3b09719b8af40b8c32cf24895915b6ef95c22c9c1'
  //rawdatahex = '00000001f9f0b90e9fb562a7f73da45a3294c6df54b395811efa79338f93a80c2636b2fdf7687ee92bbeac61c92e9056c801785022f1ed8a537afe5aefbf47f5808663b5bf03115366a7a731ca44aaf1cda09b719a46d83ba950f4db76c131a84a3217e2dc657b6156a059834185a04c1dfa539027f380fcbd38daf329183908695a333cfd0280fd36b0483046022100f587914ec6b03adb65caf29dd1fdd292a9e7e5787d27439cd1505e76e6b40ab5022100dd883fd84142e5d2ad3cf5716d75ea1b579f403acece575e84f67290ae9f6f20'
  var curve = getSECCurveByName("secp256k1").getCurve();
  var nVal = getSECCurveByName("secp256k1").getN().toString();
  updateConsole('Curve N val: ' + nVal);
  //var fauxBigNum = BigInteger.fromByteArrayUnsigned(Crypto.util.hexToBytes(hexkey));
  //var fixedNum = fauxBigNum.mod(getSECCurveByName("secp256k1").getN());
  var fauxKey = new Bitcoin.ECKey(Crypto.util.hexToBytes(hexkey));
  var fauxKeyVal = fauxKey.priv.toString();
  updateConsole('Faux key val: ' + fauxKeyVal);
  pubKeyBytes = fauxKey.getPub();
  pubPoint = fauxKey.getPubPoint();
  updateConsole('pubkey: ' + Crypto.util.bytesToHex(pubKeyBytes));
  updateConsole('To Encrypt: ' + indata);
  //dataBytes = Crypto.util.hexToBytes(rawdatahex);
  var privKeyrHex = "5be6facd941b76e9d3ead03029fbdb6b6e0809293f7fb197d0c51f84e96b8ba4";
  updateConsole('R Priv Hex: ' + privKeyrHex);
  //var r = new Bitcoin.ECKey(false);
  var r = new Bitcoin.ECKey(Crypto.util.hexToBytes(privKeyrHex));
  var RpubBytes = r.getPub();
  updateConsole('r pub: ' + Crypto.util.bytesToHex(RpubBytes));
  var curveBytes = Crypto.util.hexToBytes("02ca");
  var pointLenBytes = Crypto.util.hexToBytes("0020");
  var K = new ECPointFp(curve,
    curve.fromBigInteger(pubPoint.getX().toBigInteger()),
    curve.fromBigInteger(pubPoint.getY().toBigInteger()));
  var rPrivBigInt = r.priv;
  var P = K.multiply(rPrivBigInt);
  updateConsole('Hex test: ' + curve.encodePointHex(P));
  var PxHex = P.getX().toBigInteger().toString(16);
  var PyHex = P.getY().toBigInteger().toString(16);
  PxHex = hexPad(PxHex, 64);
  PyHex = hexPad(PyHex, 64);
  var PPubHex = "04" + PxHex + PyHex;
  var PPubBytes = Crypto.util.hexToBytes(PPubHex);
  updateConsole('PPubBytes: ' + PPubHex);
  var PxBytes = PPubBytes.slice(1,33);
  var shaOfPxBytes = sha512Bytes(PxBytes);
  var key_eBytes = shaOfPxBytes.slice(0,32);
  updateConsole('key e: ' + Crypto.util.bytesToHex(key_eBytes));
  var key_mBytes = shaOfPxBytes.slice(32);
  updateConsole('key m: ' + Crypto.util.bytesToHex(key_mBytes));
  var key_eHex = Crypto.util.bytesToHex(key_eBytes);
  //var ivBytes = Crypto.util.hexToBytes('fc3f81eb2267559e32125b1f3cdf49b0');
  var ivBytes = Crypto.util.hexToBytes('2e2d3ce3d236b9c64fa1a4b8def59bdf');
  var encrypted = CryptoJS.AES.encrypt(indata, bytesToWords(key_eBytes), {iv: bytesToWords(ivBytes)});
  var encryptedBytes = Crypto.util.base64ToBytes(encrypted);
  var hmacObj = CryptoJS.HmacSHA256(bytesToWords(encryptedBytes), bytesToWords(key_mBytes));
  var hmacBytes = Crypto.util.hexToBytes(hmacObj.toString());
  var finalBytes = ivBytes.concat(curveBytes)
    .concat(pointLenBytes)
    .concat(RpubBytes.slice(1,33))
    .concat(pointLenBytes)
    .concat(RpubBytes.slice(33))
    .concat(encryptedBytes)
    .concat(hmacBytes);
  updateConsole('Final: ' + Crypto.util.bytesToHex(finalBytes));
}
function hexPad(str, len){
  var padded = str;
  while(padded.length < len){
    padded = "0" + padded;
  }
  return padded;
}

Array.prototype.compare = function (array) {
    if (!array)
        return false;

    if (this.length != array.length)
        return false;

    for (var i = 0, l=this.length; i < l; i++) {
        if (this[i] instanceof Array && array[i] instanceof Array) {
            if (!this[i].compare(array[i]))
                return false;
        }
        else if (this[i] != array[i]) {
            return false;
        }
    }
    return true;
}
