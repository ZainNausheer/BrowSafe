document.addEventListener("DOMContentLoaded", async function () {
    // Set the Live Server port here (update if different from 5500)
    const LIVE_SERVER_PORT = 5500;

    const loading = document.getElementById("loading");
    const result = document.getElementById("result");
    const status = document.getElementById("status");
    const confidence = document.getElementById("confidence");
    const reasons = document.getElementById("reasons");
    const knowMore = document.getElementById("know-more");

    loading.classList.remove("hidden");
    result.classList.add("hidden");

    chrome.tabs.query({ active: true, currentWindow: true }, async function (tabs) {
        let url = tabs[0].url;

        try {
            let response = await fetch("http://127.0.0.1:5000/check", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url }),
            });

            if (!response.ok) throw new Error(`Network error: ${response.statusText}`);

            let data = await response.json();

            loading.classList.add("hidden");
            result.classList.remove("hidden");

            if (data.safe) {
                status.textContent = "✅ SAFE";
                status.className = "text-lg font-semibold text-center text-green-600";
                confidence.textContent = `Detection Confidence: ${data.confidence}%`;
                reasons.textContent = "";
                knowMore.classList.add("hidden");
            } else {
                status.textContent = "❌ NOT SAFE";
                status.className = "text-lg font-semibold text-center text-red-600";
                confidence.textContent = `Detection Confidence: ${data.confidence}%`;
                // Display threat types or a fallback message
                reasons.textContent = data.reasons.length > 0 
                    ? `Threats: ${data.reasons.map(r => r.type).join(", ")}`
                    : "Threats: Unknown (see details)";
                knowMore.classList.remove("hidden");
                knowMore.href = `http://127.0.0.1:${LIVE_SERVER_PORT}/attack_details.html?check_id=${data.check_id}`;
                {
                    data.reasons.forEach(reason => {
                        const p = document.createElement("div");
                        p.className = "bg-red-50 p-4 rounded-lg";
                        p.innerHTML = `
                            
                            <a href="attack_details.html?check_id=${data.check_id}" target="_blank" class="text-blue-500 underline hover:text-blue-700 mt-2 inline-block"> Learn More</a>
                        `;
                        reasons.appendChild(p);
                    });
                }
            }
           

            // Store check history in localStorage
            let history = JSON.parse(localStorage.getItem("checkHistory") || "[]");
            history.unshift({ url, ...data, timestamp: new Date().toISOString() });
            if (history.length > 100) history.pop();
            localStorage.setItem("checkHistory", JSON.stringify(history));
        } catch (error) {
            console.error("Error checking URL:", error);
            loading.classList.add("hidden");
            result.classList.remove("hidden");
            status.textContent = "Error checking site";
            status.className = "text-lg font-semibold text-center text-red-600";
            reasons.textContent = error.message;
            knowMore.classList.add("hidden");
        }
    });
});