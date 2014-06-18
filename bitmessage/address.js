Bitmessage.address = (function (){

  var address = function(input, type, passPhrase, chanAddress){
    //Set public vars
    this.stream = Bitmessage.defaultStream;
    this.version = 4;
    this.name = '';
    this.bitfield = [0,0,0,1];
    this.nonceTrials= Bitmessage.defaultPOWPerByte;
    this.extraBytes = Bitmessage.defaultPayloadExtra;
    this.type = 'private';

    if(typeof input == 'number' && !type){ //generate new trimming the specified number of 0s
      var trimming = input;
      var trimmedEnough = false;
      var pubHash;
      var trimmedHash;
      while(!trimmedEnough){
        this.signKey = new Bitcoin.ECKey(false);
        this.encKey = new Bitcoin.ECKey(false);
        //var signPub = signKey.getPub();
        //var encPub = encKey.getPub();
        var combined = this.signKey.getPub().concat(this.encKey.getPub());
        pubHash = sha512ripe160Bytes(combined);
        trimmedHash = pubHash.slice(0);
        var numTrimmed = 0;
        while (trimmedHash[0] == 0){
          trimmedHash.shift();
          numTrimmed++;
        }
        if(numTrimmed >= trimming){trimmedEnough = true;}
      }
      var address = trimmedHash.slice(0);
      address = encodeVarint(this.stream).concat(address);
      address = encodeVarint(this.version).concat(address);
      var checksum = doubleSha512Bytes(address);
      var summedAddress = address.slice(0).concat(checksum.slice(0,4));
      //alert(Crypto.util.bytesToHex(summedAddress));
      this.label = 'BM-' + Bitcoin.Base58.encode(summedAddress);

      //Create tag for broadcasting purposes
      var tagContentBytes = encodeVarint(this.version).concat(encodeVarint(this.stream)).concat(pubHash);
      //alert(Crypto.util.bytesToHex(tagBytes));
      var preTagBytes = doubleSha512Bytes(tagContentBytes);
      this.tag  = Crypto.util.bytesToHex(preTagBytes.slice(32));
      this.fauxKeyHex = Crypto.util.bytesToHex(preTagBytes.slice(0,32));
    } else if(typeof input == 'number' && type === 'chan' && passPhrase){ // Creating or joining a chan, trim should be 1!
      this.type = 'chan';
      var trimming = input;
      var signNonce = 0;
      var encNonce = 1;
      var trimmedEnough = false;
      var pubHash;
      var trimmedHash;
      var attempts = 0;
      while(!trimmedEnough){
        attempts++;
        //console.log((new Date()) + ' Doing interation...' + attempts + ' generating signing key...');
        var signPrivBytes = sha512Bytes(asciiToBytes(passPhrase).concat(encodeVarint(signNonce))).slice(0,32);
        //console.log((new Date()) + ' Generating enc key.');
        var encPrivBytes = sha512Bytes(asciiToBytes(passPhrase).concat(encodeVarint(encNonce))).slice(0,32);
        //console.log((new Date()) + ' Doing point multi...');
        this.signKey = new Bitcoin.ECKey(signPrivBytes);
        this.encKey = new Bitcoin.ECKey(encPrivBytes);
        var combined = this.signKey.getPub().concat(this.encKey.getPub());
        pubHash = sha512ripe160Bytes(combined);
        trimmedHash = pubHash.slice(0);
        var numTrimmed = 0;
        while (trimmedHash[0] == 0){
          trimmedHash.shift();
          numTrimmed++;
        }
        if(numTrimmed >= trimming){trimmedEnough = true;}
        signNonce += 2;
        encNonce += 2;
      }
      if(chanAddress){ // Joining a chan, use given version and stream
        var givenAddress = new Bitmessage.address(chanAddress);
        if(!givenAddress.valid){
          this.valid = false;
          return;
        } else {
          this.version = givenAddress.version;
          this.stream = givenAddress.stream;
          this.valid = true;
        }
      }
      //Will act as contact and address
      this.encPub = Crypto.util.bytesToHex(this.encKey.getPub());
      this.signPub = Crypto.util.bytesToHex(this.signKey.getPub());

      var address = trimmedHash.slice(0);
      address = encodeVarint(this.stream).concat(address);
      address = encodeVarint(this.version).concat(address);
      var checksum = doubleSha512Bytes(address);
      var summedAddress = address.slice(0).concat(checksum.slice(0,4));
      this.label = 'BM-' + Bitcoin.Base58.encode(summedAddress);
      if(chanAddress && chanAddress !== this.label){ // Check against given address
        this.valid = false;
        return;
      } else {
        this.valid = true;
      }
      //Create tag for broadcasting purposes
      var tagContentBytes = encodeVarint(this.version).concat(encodeVarint(this.stream)).concat(pubHash);
      var preTagBytes = doubleSha512Bytes(tagContentBytes);
      this.tag  = Crypto.util.bytesToHex(preTagBytes.slice(32));
      this.fauxKeyHex = Crypto.util.bytesToHex(preTagBytes.slice(0,32));
    } else if(typeof input == 'object'){
      this.stream = input.stream;
      this.version = input.version;
      this.tag = input.tag;
      this.label = input.label;
      this.fauxKeyHex = input.fauxKeyHex;
      this.name = input.name;
      this.type = input.type;
      if(input.advertized){
        this.advertized = new Date(input.advertized);
      }
      if(input.keyRequested){
        this.keyRequested = new Date(input.keyRequested);
      }
      if(input.encPriv){
        this.encKey = new Bitcoin.ECKey(new BigInteger(input.encPriv));
      }
      if(input.encPub){
        this.encPub = input.encPub;
      }
      if(input.signPriv){
        this.signKey = new Bitcoin.ECKey(new BigInteger(input.signPriv));
      }
      if(input.signPub){
        this.signPub = input.signPub;
      }
      this.nonceTrials = input.nonceTrials;
      this.extraBytes = input.extraBytes;
      if(this.encPub && this.signPub){
        this.generateLabel();
        this.calculateTag();
      }
      if(this.type === 'subscription'){ //A wasteful way to reuse the new subscription code
        var tempAdd = new Bitmessage.address(this.label, 'subscription');
        this.encKey = tempAdd.encKey;
      }
    } else if(typeof input == 'string'){
      if(input.substr(0,3) == "BM-"){
        this.label = input;
      } else {
        this.label = "BM-" + input;
      }
      var base58label = this.label.substr(3);
      var addressBytes = Bitcoin.Base58.decode(base58label);
      var sumBytes = addressBytes.slice(-4);
      var addressBytes = addressBytes.slice(0,-4);
      var checkHash = doubleSha512Bytes(addressBytes);
      if(Crypto.util.bytesToHex(checkHash.slice(0,4)) == Crypto.util.bytesToHex(sumBytes)){
        this.valid = true;
      } else {
        this.valid = false;
        return;
      }
      var readPos = 0;
      var verArr = decodeVarint(addressBytes.slice(readPos));
      this.version = verArr[0];
      readPos += verArr[1];

      var streamArr = decodeVarint(addressBytes.slice(readPos));
      this.stream = streamArr[0];
      readPos += streamArr[1];

      var pubHashBytes = addressBytes.slice(readPos);
      while(pubHashBytes.length < 20){
        pubHashBytes.unshift(0);
      }
      var tagContentBytes = encodeVarint(this.version).concat(encodeVarint(this.stream)).concat(pubHashBytes);
      var preTagBytes = doubleSha512Bytes(tagContentBytes);
      this.tag  = Crypto.util.bytesToHex(preTagBytes.slice(32));
      this.fauxKeyHex = Crypto.util.bytesToHex(preTagBytes.slice(0,32));
      if(type === 'subscription'){
        this.type = 'subscription';
        if(this.version <= 3){
          this.encKey = new Bitcoin.ECKey(sha512Bytes(tagContentBytes).slice(0,32));
        } else {
          this.encKey = new Bitcoin.ECKey(this.fauxKeyHex);
        }
      }
    }
 };
 
  address.prototype.createBroadcastMsg = function(){ 
    // Returns base64 payload, hex payload hash, int target, hex tag in and array
    var embeddedTime = Math.round((new Date).getTime() / 1000);
    var publishTime = embeddedTime + getRandomInt(-300,300);
  
    var payload = encodeVarint(this.stream);
    payload = encodeVarint(this.version).concat(payload);
    payload = longToByteArray(publishTime).concat(payload);
  
    var toEncrypt = this.bitfield;
    toEncrypt = toEncrypt.concat(this.signKey.getPub().slice(1));
    toEncrypt = toEncrypt.concat(this.encKey.getPub().slice(1));
    toEncrypt = toEncrypt.concat(encodeVarint(this.nonceTrials));
    toEncrypt = toEncrypt.concat(encodeVarint(this.extraBytes));
    var toSign = payload.concat(toEncrypt);
    //updateConsole('Signing: ' + Crypto.util.bytesToHex(toSign));
    //updateConsole('Signing with: ' +  this.signKey.priv);
    var signature = sign(toSign, this.signKey);
    //updateConsole('Signing result: ' + Crypto.util.bytesToHex(signature));
    toEncrypt = toEncrypt.concat(encodeVarint(signature.length));
    toEncrypt = toEncrypt.concat(signature);
 
    var tagBytes = Crypto.util.hexToBytes(this.tag); 
    payload = payload.concat(tagBytes); // Add tag to payload
    var fauxPrivKey = Crypto.util.hexToBytes(this.fauxKeyHex); // Grab bytes for priv key
    //alert('Enc key: ' + Crypto.util.bytesToHex(fauxPrivKey));
    var fauxKey = new Bitcoin.ECKey(fauxPrivKey);
    //alert('To Encrypt: ' + Crypto.util.bytesToHex(toEncrypt));
    var encrypted = eciesEncrypt(toEncrypt, fauxKey.getPub());
    //alert('encrypted data: ' + Crypto.util.bytesToHex(encrypted));
    var payload = payload.concat(encrypted);
    var maxTarget = 18446744073709551615; //Math.pow(2,64)
    var target = Math.floor(maxTarget / ((payload.length + defaultPayloadExtra + 8) * defaultPOWPerByte));
    //alert(target);
    var initialHash = sha512Bytes(payload);
    var payloadHash = Crypto.util.bytesToHex(initialHash);
  
    return {payload: Crypto.util.bytesToBase64(payload),
      payloadHash: payloadHash,
      target: target,
      tag: this.tag};
  };

  address.prototype.fromBroadcast = function(inBytes){
    //Parse the pub keys and other info from a pub key broadcast, after removing nonce
    //updateConsole(Crypto.util.bytesToHex(inBytes));
    var timeBytes = inBytes.slice(0,8);

    var verArr = decodeVarint(inBytes.slice(8,18));
    var tempVersion = verArr[0];
    if(tempVersion != 4){
      return;
    }
    var readPos = verArr[1] + 8;

    var streamArr = decodeVarint(inBytes.slice(readPos, readPos+10));
    var tempStream = streamArr[0];
    readPos += streamArr[1];

    var endOfFirstSignedPart = readPos;

    var tagBytes = inBytes.slice(readPos, readPos+32);
    if(Crypto.util.bytesToHex(tagBytes) != this.tag){
      return;
    }
    readPos += 32;

    var encryptedBytes = inBytes.slice(readPos); 
    var decrypted = eciesDecrypt(encryptedBytes, this.fauxKeyHex);
    //updateConsole(Crypto.util.bytesToHex(decrypted));

    var drPos = 0;
    var tempBitfield = decrypted.slice(drPos, drPos+4);
    drPos += 4;

    var tempSignPub = "04" + Crypto.util.bytesToHex(decrypted.slice(drPos, drPos+64));
    drPos += 64;
    var tempEncPub = "04" + Crypto.util.bytesToHex(decrypted.slice(drPos, drPos+64));
    drPos += 64;

    //Test to see if pub keys match the tag
    var combined = Crypto.util.hexToBytes(tempSignPub).concat(Crypto.util.hexToBytes(tempEncPub));
    var testRipe = sha512ripe160Bytes(combined);
    var tagContentBytes = encodeVarint(tempVersion).concat(encodeVarint(tempStream)).concat(testRipe);
    var preTagBytes = doubleSha512Bytes(tagContentBytes);
    var testTag = Crypto.util.bytesToHex(preTagBytes.slice(32));
    if(testTag != this.tag){
      updateConsole('Keys to tag check failed.');
      updateConsole('test ripe: ' + testRipeHex + ' tag: ' + this.tag);
      return;
    }
  
    var trialsArr = decodeVarint(decrypted.slice(drPos, drPos+10));
    var tempNonceTrials = trialsArr[0];
    drPos += trialsArr[1];

    var extraArr = decodeVarint(decrypted.slice(drPos, drPos+10));
    var tempExtraBytes = extraArr[0];
    drPos += extraArr[1];

    var signedEnd = drPos;
    var lenArr = decodeVarint(decrypted.slice(drPos, drPos+10));
    var signLength = lenArr[0];
    drPos += lenArr[1];
    var signature = decrypted.slice(drPos, drPos+signLength);
    drPos += signLength;
    //updateConsole('signature: ' + Crypto.util.bytesToHex(signature));

    if(verify(inBytes.slice(0,endOfFirstSignedPart).concat(decrypted.slice(0,signedEnd)), signature, tempSignPub)){
      this.version = tempVersion;
      this.stream = tempStream;
      this.bitfield = tempBitfield;
      this.signPub = tempSignPub;
      this.encPub = tempEncPub;
      this.nonceTrials = tempNonceTrials;
      this.extraBytes = tempExtraBytes;
      //alert('verified');
      return true;
    } else {
      return false;
    }
  };

  address.prototype.toObj = function(){
    myObj = {};
    myObj.version = this.version;
    myObj.stream = this.stream;
    myObj.label = this.label;
    myObj.type = this.type;
    if(this.encKey){
      myObj.encPriv = this.encKey.priv.toString();
    }
    if(this.encPub){
      myObj.encPub = this.encPub;
    }
    if(this.signKey){
      myObj.signPriv = this.signKey.priv.toString();
    }
    if(this.signPub){
      myObj.signPub = this.signPub;
    }
    myObj.name = this.name;
    myObj.tag = this.tag;
    myObj.fauxKeyHex = this.fauxKeyHex;
    myObj.nonceTrials = this.nonceTrials;
    myObj.extraBytes = this.extraBytes;
    if(this.keyRequested){
      myObj.keyRequested = this.keyRequested.toString();
    }
    if(this.advertized){
      myObj.advertized = this.advertized.toString();
    }
    return myObj;
  };

  address.prototype.toString = function(){
    return JSON.stringify(this.toObj());
  };

  address.prototype.generateLabel = function(){ //Only for public only addresses
    if(!this.encPub || !this.signPub){return;}
    var combined = Crypto.util.hexToBytes(this.signPub).concat(Crypto.util.hexToBytes(this.encPub));
    var pubHash = sha512ripe160Bytes(combined);
    while(pubHash[0] == 0){
      pubHash.shift();
    }
    var address = encodeVarint(this.version).concat(encodeVarint(this.stream)).concat(pubHash);
    var checksum = doubleSha512Bytes(address);
    var summed = address.concat(checksum.slice(0,4));
    this.label = 'BM-' + Bitcoin.Base58.encode(summed);
  };

  address.prototype.calculateTag = function(){ //Only for public only addresses
    if(!this.encPub || !this.signPub){return;}
    var combined = Crypto.util.hexToBytes(this.signPub).concat(Crypto.util.hexToBytes(this.encPub));
    var pubHash = sha512ripe160Bytes(combined);
    var tagContentBytes = encodeVarint(this.version).concat(encodeVarint(this.stream)).concat(pubHash);
    var preTagBytes = doubleSha512Bytes(tagContentBytes);
    this.tag = Crypto.util.bytesToHex(preTagBytes.slice(32));
    this.fauxKeyHex = Crypto.util.bytesToHex(preTagBytes.slice(0,32));
  };

  address.prototype.getRipeBytes = function(){
    if(this.signKey && this.encKey){
      var combined = this.signKey.getPub().concat(this.encKey.getPub());
      return sha512ripe160Bytes(combined);
    } else if(this.signPub && this.encPub){
      var combined = Crypto.util.hexToBytes(this.signPub).concat(Crypto.util.hexToBytes(this.encPub));
      return sha512ripe160Bytes(combined);
    } else {
      return null;
    }
  };

  return address;
})();
