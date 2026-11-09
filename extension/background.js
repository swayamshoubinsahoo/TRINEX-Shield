importScripts('anat.js');
const APP = 'http://127.0.0.1:8000/';
chrome.omnibox.setDefaultSuggestion({ description: 'Investigate with TRINEX Shield: %s' });
chrome.omnibox.onInputEntered.addListener(t => chrome.tabs.create({ url: APP + '?url=' + encodeURIComponent(t) }));
chrome.tabs.onUpdated.addListener((id, info, tab) => {
  if (!tab.url) return;
  const a = analyse(tab.url);
  chrome.action.setBadgeText({ tabId: id, text: a && a.fl.length ? '!' : '' });
  chrome.action.setBadgeBackgroundColor({ tabId: id, color: '#ff4d6d' });
});
