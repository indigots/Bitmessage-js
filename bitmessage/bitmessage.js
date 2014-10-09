(function (exports) {
  var Bitmessage = exports;
  Bitmessage.defaultPOWPerByte = 1000;
  Bitmessage.defaultPayloadExtra = 1000;
  Bitmessage.defaultStream = 1;
  Bitmessage.defaultTTL = 2.5 * 24 * 60 * 60; // 2.5 days
})(
  'object' === typeof module ? module.exports : (window.Bitmessage = {})
);
