document.addEventListener("DOMContentLoaded", function() {
  const form = document.getElementById("uploadForm");
  const fileInput = document.getElementById("fileInput");
  const submitBtn = document.getElementById("submitBtn");
  const status = document.getElementById("status");
  const statusText = document.getElementById("statusText");
  const fileName = document.getElementById("fileName");

  if (fileInput) {
    fileInput.addEventListener("change", function() {
      if (fileInput.files && fileInput.files.length > 0) {
        fileName.textContent = fileInput.files[0].name;
        fileName.style.color = "#8a2be2";
      } else {
        fileName.textContent = "Click here to choose a file";
        fileName.style.color = "#888";
      }
    });
  }

  if (form) {
    form.addEventListener("submit", function(e) {
      if (!fileInput || !fileInput.value) {
        e.preventDefault();
        alert("Please choose a log file (.log, .txt, .evtx).");
        return;
      }
      submitBtn.disabled = true;
      if (status) status.hidden = false;
      if (statusText) statusText.textContent = "Uploading and analyzing — please wait...";
      // Show feedback for up to 35 seconds as fallback
      setTimeout(() => {
        submitBtn.disabled = false;
        if (status) status.hidden = true;
      }, 35000);
    });
  }
});
