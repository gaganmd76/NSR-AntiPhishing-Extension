// One place that reads every user setting from chrome.storage.sync.
// Keys: sensitivity, showBanner, whitelist, customBrands

export const DEFAULT_SETTINGS = {
  sensitivity: "medium",
  showBanner: true,
  whitelist: [],
  customBrands: [],
};

export async function getSettings() {
  try {
    const data = await chrome.storage.sync.get([
      "sensitivity",
      "showBanner",
      "whitelist",
      "customBrands",
    ]);

    return {
      sensitivity: ["low", "medium", "high"].includes(data.sensitivity)
        ? data.sensitivity
        : DEFAULT_SETTINGS.sensitivity,
      showBanner: data.showBanner !== false,
      whitelist: Array.isArray(data.whitelist) ? data.whitelist : [],
      customBrands: Array.isArray(data.customBrands) ? data.customBrands : [],
    };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}