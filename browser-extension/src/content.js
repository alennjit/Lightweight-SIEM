// Content script: renders a full-page warning interstitial when background.js
// flags the current navigation as risky, before the underlying page can
// capture any input (credentials, etc.).
//
// TODO: implement. Expected behavior: listen for a message from background.js
// (chrome.runtime.onMessage) carrying a risk flag + rationale, and if present,
// replace document content with a blocking warning screen offering "go back"
// as the only easy action.
