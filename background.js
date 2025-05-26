chrome.runtime.onInstalled.addListener(() => {
  console.log("BrowSafe Extension installed!");
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "openAttackDetails") {
      chrome.tabs.create({ url: request.url });
  }
});