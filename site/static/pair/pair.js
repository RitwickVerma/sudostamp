// The pairing link opened in a browser (SudoStamp not installed, or the link not verified for it).
// The secret is after the '#': never sent to this site, and taken out of the address bar at once.
// Nothing here talks to any server; it only builds a link for the app.
(function () {
  "use strict";
  var frag = location.hash.slice(1);
  if (frag) history.replaceState(null, "", location.pathname);
  var android = /Android/i.test(navigator.userAgent);
  if (!android || !/^1\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{0,43}$/.test(frag)) return;
  document.getElementById("android").hidden = false;
  document.getElementById("other").hidden = true;
  // An intent link opens the app itself (Chrome and most Android browsers). The code rides in the
  // query parameter k, inside the intent only: no request is made with it. Without the app,
  // Google Play opens instead.
  var play = "https://play.google.com/store/apps/details?id=com.ritwick.sudostamp";
  document.getElementById("open").href = "intent://" + location.host + "/pair?k=" + frag +
    "#Intent;scheme=https;package=com.ritwick.sudostamp;S.browser_fallback_url=" +
    encodeURIComponent(play) + ";end";
})();
