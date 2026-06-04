document.addEventListener("DOMContentLoaded", function(){
  const form = document.getElementById("uploadForm");
  const fileInput = document.getElementById("fileInput");
  const submitBtn = document.getElementById("submitBtn");
  const status = document.getElementById("status");
  const statusText = document.getElementById("statusText");
  const fileName = document.getElementById("fileName");
  const headline = document.getElementById("headline");

  // Typing animation for the headline
  if (headline) {
    const text = 'Are you <span class="accent">compromised</span>?';
    let i = 0;
    headline.innerHTML = '<span class="typing-cursor"></span>';
    function typeWriter() {
      if (i < text.length) {
        headline.innerHTML = text.substring(0, i + 1) + '<span class="typing-cursor"></span>';
        i++;
        setTimeout(typeWriter, 100);
      } else {
        headline.querySelector('.typing-cursor').style.animation = 'blink 0.7s infinite';
      }
    }
    typeWriter();
  }

  if (fileInput) {
    fileInput.addEventListener("change", function(){
      if (fileInput.files && fileInput.files.length > 0) {
        fileName.textContent = fileInput.files[0].name;
      } else {
        fileName.textContent = "Click to choose a file";
      }
    });
  }

  if (form) {
    form.addEventListener("submit", function(e){
      if(!fileInput || !fileInput.value) {
        e.preventDefault();
        alert("Please choose a log file.");
        return;
      }
      submitBtn.disabled = true;
      if (status) status.hidden = false;
      if (statusText) statusText.textContent = "Uploading and analyzing...";
      setTimeout(()=> {
        submitBtn.disabled = false;
        if (status) status.hidden = true;
      }, 35000);
    });
  }
});