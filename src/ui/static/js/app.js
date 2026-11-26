// PurpleForge UI glue. No inline scripts anywhere (CSP script-src 'self').
(function () {
  "use strict";

  // Console autoscroll: follow new SSE lines only if the user is already at the bottom.
  function nearBottom(el) {
    return el.scrollHeight - el.scrollTop - el.clientHeight < 80;
  }
  document.addEventListener("htmx:sseBeforeMessage", function (evt) {
    var log = document.getElementById("console-log");
    if (log) log.dataset.follow = nearBottom(log) ? "1" : "0";
  });
  document.addEventListener("htmx:sseMessage", function () {
    var log = document.getElementById("console-log");
    if (log && log.dataset.follow !== "0") log.scrollTop = log.scrollHeight;
  });
  document.addEventListener("DOMContentLoaded", function () {
    var log = document.getElementById("console-log");
    if (log) log.scrollTop = log.scrollHeight;
  });

  // Live console closed (run ended): mark it so the blinking cursor stops.
  document.addEventListener("htmx:sseClose", function () {
    var tail = document.getElementById("console-tail");
    if (tail) tail.classList.remove("cursor");
  });
})();
