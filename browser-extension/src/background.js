// Background service worker: checks navigated-to URLs against the backend's
// link-reputation endpoint and flags the tab if the destination is risky.
//
// TODO: implement. Expected behavior: listen for chrome.webNavigation.onBeforeNavigate,
// call the backend's /api/v1/url-reputation endpoint (see backend/app/detection/url_reputation.py,
// not yet implemented) with the target URL, and if flagged, message content.js on that
// tab to render the warning interstitial before the page can capture input.

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // Stub — no-op until url-reputation backend endpoint exists.
});
