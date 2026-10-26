// Runs in the PAGE's own JavaScript world, so it can see when the page
// calls the camera, microphone or location APIs. Each call is recorded in a
// data attribute on <html> that content.js reads.

(function () {
  const events = [];

  function flush() {
    const root = document.documentElement;
    if (!root) return setTimeout(flush, 0);
    root.setAttribute("data-nsr-sensors", JSON.stringify(events));
    window.dispatchEvent(new CustomEvent("nsr-sensor"));
  }

  function record(kind) {
    let activated = false;
    try {
      // true only if the user clicked or pressed a key a moment ago
      activated = navigator.userActivation.isActive;
    } catch {}
    events.push({ kind, activated });
    flush();
  }

  // Camera and microphone
  try {
    const proto = window.MediaDevices && window.MediaDevices.prototype;
    if (proto && proto.getUserMedia) {
      const original = proto.getUserMedia;
      proto.getUserMedia = function (constraints) {
        try {
          if (constraints && constraints.video) record("camera");
          else if (constraints && constraints.audio) record("microphone");
        } catch {}
        return original.apply(this, arguments);
      };
    }
  } catch {}

  // Location
  try {
    const geo = window.Geolocation && window.Geolocation.prototype;
    if (geo) {
      ["getCurrentPosition", "watchPosition"].forEach((name) => {
        const original = geo[name];
        if (!original) return;
        geo[name] = function () {
          try {
            record("location");
          } catch {}
          return original.apply(this, arguments);
        };
      });
    }
  } catch {}
})();