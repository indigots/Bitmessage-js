(function (exports) {
  var Bitmessage = exports;
  Bitmessage.defaultPOWPerByte = 1000;
  Bitmessage.defaultPayloadExtra = 1000;
  Bitmessage.defaultStream = 1;
})(
  'object' === typeof module ? module.exports : (window.Bitmessage = {})
);
