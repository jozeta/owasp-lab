document.addEventListener("DOMContentLoaded", function () {
  var banner = document.getElementById("lab-warning-banner");
  if (banner) {
    try {
      if (sessionStorage.getItem("labBannerDismissed") === "1") {
        banner.style.display = "none";
      }
    } catch (e) {
      /* sessionStorage unavailable (e.g. private mode) -- banner stays visible */
    }
  }

  if (window.hljs) {
    hljs.highlightAll();
    if (window.hljs.initLineNumbersOnLoad) {
      hljs.initLineNumbersOnLoad();
    }
  }
  if (window.mermaid) {
    mermaid.initialize({ startOnLoad: true, theme: window.__labTheme === "dark" ? "dark" : "default" });
  }

  if (window.bootstrap) {
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (el) {
      new bootstrap.Tooltip(el);
    });
  }
});

function dismissLabBanner() {
  var banner = document.getElementById("lab-warning-banner");
  if (banner) {
    banner.style.display = "none";
  }
  try {
    sessionStorage.setItem("labBannerDismissed", "1");
  } catch (e) {
    /* ignore -- dismissal just won't persist across reloads */
  }
}

function toggleLabTheme() {
  var current = document.documentElement.getAttribute("data-bs-theme") === "dark" ? "dark" : "light";
  var next = current === "dark" ? "light" : "dark";
  try {
    localStorage.setItem("labTheme", next);
  } catch (e) {
    /* localStorage unavailable -- theme choice won't persist across reloads */
  }
  location.reload();
}
