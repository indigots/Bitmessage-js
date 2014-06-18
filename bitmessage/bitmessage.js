(function (exports) {
  var Bitmessage = exports;
  Bitmessage.defaultPOWPerByte = 320;
  Bitmessage.defaultPayloadExtra = 14000;
  Bitmessage.defaultStream = 1;
})(
  'object' === typeof module ? module.exports : (window.Bitmessage = {})
);
