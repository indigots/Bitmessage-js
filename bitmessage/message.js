Bitmessage.message = (function () {

  var message = function (inBytes, additionalSignedBytes) {
    if(!inBytes){
      //this.version = 1;
      this.stream = 1;
      this.encoding = 2;
      return;
    }

    this.signed = false;
    var senderAddress = {};

    //var verArr = decodeVarint(inBytes.slice(0,10));
    //this.version = verArr[0];
    //var readPos = verArr[1];

    var readPos = 0;
    var addArr = decodeVarint(inBytes.slice(readPos, readPos+10));
    senderAddress.version = addArr[0];
    readPos += addArr[1];

    var streamArr = decodeVarint(inBytes.slice(readPos, readPos+10));
    senderAddress.stream = streamArr[0];
    readPos += streamArr[1];

    senderAddress.bitfield = inBytes.slice(readPos, readPos+4);
    readPos += 4;
    senderAddress.signPub = '04' + Crypto.util.bytesToHex(inBytes.slice(readPos, readPos+64));
    readPos += 64;
    senderAddress.encPub = '04' + Crypto.util.bytesToHex(inBytes.slice(readPos, readPos+64));
    readPos += 64;

    var trialsArr = decodeVarint(inBytes.slice(readPos, readPos+10));
    senderAddress.nonceTrials = trialsArr[0];
    readPos += trialsArr[1];

    var extraArr = decodeVarint(inBytes.slice(readPos, readPos+10));
    senderAddress.extraBytes = extraArr[0];
    readPos += extraArr[1];

    senderAddress.ripe = Crypto.util.bytesToHex(inBytes.slice(readPos, readPos+20));
    readPos += 20;

    var encodingArr = decodeVarint(inBytes.slice(readPos, readPos+10));
    this.encoding = encodingArr[0];
    readPos += encodingArr[1];

    var mLengthArr = decodeVarint(inBytes.slice(readPos, readPos+10));
    readPos += mLengthArr[1];
    var messageStr = bytesToUTF8(inBytes.slice(readPos, readPos+mLengthArr[0]));
    readPos += mLengthArr[0];

    this.subject = '';
    this.message = '';
    if(this.encoding == 1){
      this.message = messageStr;
    } else if(this.encoding == 2){
      var splitArr = messageStr.split('\nBody:');
      this.message = splitArr[1];
      this.subject = splitArr[0].substr(8);
    }

    var ackLengthArr = decodeVarint(inBytes.slice(readPos, readPos+10));
    readPos += ackLengthArr[1];
    this.rawAck = inBytes.slice(readPos, readPos+ackLengthArr[0]);
    readPos += ackLengthArr[0];

    var sigLengthArr = decodeVarint(inBytes.slice(readPos, readPos+10));
    var preSignaturePos = readPos;
    readPos += sigLengthArr[1];
    this.signature = inBytes.slice(readPos, readPos+sigLengthArr[0]);

    //Check signature
    if(verify(additionalSignedBytes.concat(inBytes.slice(0,preSignaturePos)), this.signature, senderAddress.signPub)){
      this.signed = true;
    }
    
    this.senderAddress = new Bitmessage.address(senderAddress);
  };

  message.prototype.messageToBytes = function(){
    var stringMessage = "";
    if(this.encoding == 2){
      stringMessage = "Subject:" + this.subject + "\nBody:" + this.message;
    } else {
      stringMessage = this.message;
    }
    return UTF16toUTF8Bytes(stringMessage);
    //return asciiToBytes(stringMessage);
  };

  message.prototype.toBytes = function(toAddress, additionalBytesToSign){ 
    if(!toAddress || !toAddress.signPub || !toAddress.encPub){
      throw new Error('Invalid _to_ address.');
      return;
    }
    //var toSend = encodeVarint(this.version);
    var toSend = encodeVarint(this.senderAddress.version);
    toSend = toSend.concat(encodeVarint(this.senderAddress.stream));
    toSend = toSend.concat(this.senderAddress.bitfield);
    toSend = toSend.concat(this.senderAddress.signKey.getPub().slice(1));
    toSend = toSend.concat(this.senderAddress.encKey.getPub().slice(1));
    toSend = toSend.concat(encodeVarint(this.senderAddress.nonceTrials));
    toSend = toSend.concat(encodeVarint(this.senderAddress.extraBytes));
    toSend = toSend.concat(toAddress.getRipeBytes());
    toSend = toSend.concat(encodeVarint(this.encoding));
    var messageBytes = this.messageToBytes();
    toSend = toSend.concat(encodeVarint(messageBytes.length));
    toSend = toSend.concat(messageBytes);
    toSend = toSend.concat(encodeVarint(0)); //Skip ack for now
    var signature = sign(additionalBytesToSign.concat(toSend), this.senderAddress.signKey);
    toSend = toSend.concat(encodeVarint(signature.length));
    toSend = toSend.concat(signature);
    return toSend;
  }

  message.prototype.encryptFor = function(toAddress, optionalSecureRandom){
    var objectBytes = longToByteArray(Math.round((new Date()).getTime()/1000) + Bitmessage.defaultTTL)
      .concat(intToByteArray(2)) //Object type
      .concat(encodeVarint(1)) //Object version
      .concat(encodeVarint(toAddress.stream)); //Stream for this message
    var unencrypted = this.toBytes(toAddress, objectBytes);
    var encryptedBytes = eciesEncrypt(unencrypted, Crypto.util.hexToBytes(toAddress.encPub), optionalSecureRandom);
    var payload = objectBytes.concat(encryptedBytes);
    var powParams = powRequirements(payload, toAddress.extraBytes, toAddress.nonceTrials, Bitmessage.defaultTTL);
    return {
      payload: payload,
      target: powParams.target,
      initialhash: powParams.initialHashBytes,
      stream: toAddress.stream
    }
  }

  return message;
})();

function bytesToUTF8(inBytes){
  var str = '';
  for (var i = 0; i < inBytes.length; i++) {
    str += '%' + ('0' + inBytes[i].toString(16)).slice(-2);
  }
  str = decodeURIComponent(str);
  return str;
}

function UTF16toUTF8Bytes(inStr){
  var utf8 = unescape(encodeURIComponent(inStr));
  var byteArr = [];
  for (var i = 0; i < utf8.length; i++) {
    byteArr.push(utf8.charCodeAt(i));
  }
  return byteArr;
}
