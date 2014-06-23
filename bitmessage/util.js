function bytesToWords(bytes){
  return CryptoJS.enc.Hex.parse(Crypto.util.bytesToHex(bytes));
}
function wordsToBytes(words){
  return Crypto.util.hexToBytes(CryptoJS.enc.Hex.stringify(words));
}
function sha512ripe160Bytes(bytes){
  var hash = CryptoJS.RIPEMD160(CryptoJS.SHA512(bytesToWords(bytes)));
  return wordsToBytes(hash);
}
function doubleSha512Bytes(bytes){
  var hash = CryptoJS.SHA512(CryptoJS.SHA512(bytesToWords(bytes)));
  return wordsToBytes(hash);
}
function checkPow(inBytes){
  var nonce = inBytes.slice(0,8);
  var data = inBytes.slice(8);
  var powBytes = doubleSha512Bytes(nonce.concat(sha512Bytes(data)));
  var powNum = byteArrayToLong(powBytes.slice(0,8));
  var maxTarget = 18446744073709551615;
  return powNum <= maxTarget / ((data.length + Bitmessage.defaultPayloadExtra) * (Bitmessage.defaultPOWPerByte));
}
function getRandomInt (min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function longToByteArray(toConvert) {
  var byteArray = [0, 0, 0, 0, 0, 0, 0, 0];

  for ( var index = 0; index < byteArray.length; index ++ ) {
    var newByte = toConvert & 0xff;
    //Big endian, work backwards
    byteArray [ 7 - index ] = newByte;
    toConvert = (toConvert - newByte) / 256 ;
  }
  return byteArray;
}
byteArrayToLong = function(byteArray) {
    var value = 0;
    for ( var i = byteArray.length - 1; i >= 0; i--) {
        value = (value * 256) + byteArray[7-i];
    }

    return value;
};
function encodeVarint(integer){
  var byteArray = [0];
  if(integer < 0){
    return byteArray;
  } else if(integer < 253){
    byteArray[0] = integer;
    return byteArray;
  } else if(integer < 65536){
    byteArray[0] = 253;
    var longArray = longToByteArray(integer);
    return byteArray.concat(longArray.slice(6));
  } else if(integer < 2147483648){ //Any more and we overflow into the negatives
    byteArray[0] = 254;
    var longArray = longToByteArray(integer);
    return byteArray.concat(longArray.slice(4));
  } else {
    return null;
  }
}
function decodeVarint(byteArray){
  if(!byteArray || byteArray.length == 0){
    return null;
  } else if(byteArray[0] < 253){
    return [byteArray[0],1];
  } else if(byteArray[0] == 253){
    return [(byteArray[1] << 8) | byteArray[2],3];
  } else if(byteArray[0] == 254){ 
    var value = 0;
    var rev = byteArray.slice(1).reverse();
    for(var i = rev.length - 1; i >= 0; i--){
      value = (value * 256) + rev[i];
    }
    return [value,5];
  } else if(byteArray[0] == 255){
    var value = 0;
    var rev = byteArray.slice(1).reverse();
    for(var i = rev.length - 1; i >= 0; i--){
      value = (value * 256) + rev[i];
    }
    return [value,9];
  }
}

//Should really change the namespace on these
function sign(input, eckey){
  var hash = wordsToBytes(CryptoJS.SHA1(bytesToWords(input)));
  return eckey.sign(hash);
}
function verify(input, sig, pubhex){
  var hash = wordsToBytes(CryptoJS.SHA1(bytesToWords(input)));
  return Bitcoin.ECDSA.verify(hash, sig, Crypto.util.hexToBytes(pubhex));
}
