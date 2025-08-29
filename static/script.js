document.addEventListener("DOMContentLoaded", () => {
  const translateForm = document.getElementById("translate-form");
  const inputText = document.getElementById("inputText");
  const translateBtn = document.getElementById("translateBtn");
  const resultContainer = document.getElementById("result-container");

  const API_ENDPOINT = "/translate";

  translateForm.addEventListener("submit", async (event) => {
    event.preventDefault(); // Prevent the form from reloading the page

    const textToTranslate = inputText.value.trim();
    if (!textToTranslate) return;

    // Show a loading state
    translateBtn.setAttribute("aria-busy", "true");
    translateBtn.disabled = true;
    resultContainer.textContent = "Translating...";

    try {
      const response = await fetch(API_ENDPOINT, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ text: textToTranslate }),
      });

      if (!response.ok) {
        throw new Error(`API Error: ${response.statusText}`);
      }

      const data = await response.json();

      // Display the result safely
      resultContainer.innerHTML = ""; // clear any previous content
      if (data.translated) {
        const block = document.createElement("blockquote");
        block.textContent = data.translated;
        const small = document.createElement("small");
        const strong = document.createElement("strong");
        strong.textContent = (data.detected_language || "")
          .toString()
          .toUpperCase();
        small.textContent = "Detected Language: ";
        small.appendChild(strong);
        resultContainer.appendChild(block);
        resultContainer.appendChild(small);
      } else {
        const p = document.createElement("p");
        p.textContent =
          "Could not translate the text. It might not be a supported Scandinavian language.";
        resultContainer.appendChild(p);
      }
    } catch (error) {
      console.error("Translation failed:", error);
      resultContainer.innerHTML = "";
      const p = document.createElement("p");
      p.style.color = "var(--pico-color-red-500)";
      p.innerHTML =
        "<strong>Error:</strong> Could not connect to the translation service. Please try again later.";
      resultContainer.appendChild(p);
    } finally {
      // Restore the button
      translateBtn.setAttribute("aria-busy", "false");
      translateBtn.disabled = false;
    }
  });
});
