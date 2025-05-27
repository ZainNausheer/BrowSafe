// http://127.0.0.1:5000/check 
document.addEventListener("DOMContentLoaded", () => {
    const urlInput = document.getElementById("url-input");
    const checkBtn = document.getElementById("check-btn");
    const loading = document.getElementById("loading");
    const result = document.getElementById("result");
    const status = document.getElementById("status");
    const confidence = document.getElementById("confidence");
    const reasons = document.getElementById("reasons");
    const history = document.getElementById("history");

    // Load check history
    const loadHistory = () => {
        const historyData = JSON.parse(localStorage.getItem("checkHistory") || "[]");
        history.innerHTML = "";
        historyData.forEach((item) => {
            const div = document.createElement("div");
            div.className = "p-4 border-b history-item rounded-lg";
            div.innerHTML = `
                <p class="text-gray-800"><strong>URL:</strong> ${item.url}</p>
                <p class="text-gray-800"><strong>Status:</strong> ${item.safe ? "Safe" : "Not Safe"}</p>
                <p class="text-gray-800"><strong>Confidence:</strong> ${item.confidence}%</p>
                ${item.reasons.length > 0 ? `<a href="attack_details.html?check_id=${item.check_id}" target="_blank" class="text-blue-500 underline hover:text-blue-700">View Threats</a>` : ""}
            `;
            history.appendChild(div);
        });
    };

    checkBtn.addEventListener("click", async () => {
        const url = urlInput.value.trim();
        if (!url) {
            alert("Please enter a URL");
            return;
        }

        loading.classList.add("active");
        result.classList.add("hidden");

        try {
            const response = await fetch("https://browsafe.onrender.com/check", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url }),
            });

            if (!response.ok) throw new Error(`Network error: ${response.statusText}`);

            const data = await response.json();

            loading.classList.remove("active");
            result.classList.remove("hidden");

            status.textContent = data.safe ? "✅ SAFE" : "❌ NOT SAFE";
            status.className = `text-2xl font-semibold text-center ${data.safe ? "text-green-600" : "text-red-600"}`;
            confidence.textContent = `Detection Confidence: ${data.confidence}%`;

            reasons.innerHTML = "";
            if (data.reasons.length > 0) {
                data.reasons.forEach(reason => {
                    const p = document.createElement("div");
                    p.className = "bg-red-50 p-4 rounded-lg";
                    p.innerHTML = `
                        <p class="text-red-600 font-semibold">${reason.type}</p>
                        <p class="text-gray-700">${reason.description}</p>
                        <a href="attack_details.html?check_id=${data.check_id}" target="_blank" class="text-blue-500 underline hover:text-blue-700 mt-2 inline-block"> Learn More</a>
                    `;
                    reasons.appendChild(p);
                });
            }

            // Store in local storage
            const historyData = JSON.parse(localStorage.getItem("checkHistory") || "[]");
            historyData.unshift({ url, ...data, timestamp: new Date().toISOString() });
            if (historyData.length > 100) historyData.pop();
            localStorage.setItem("checkHistory", JSON.stringify(historyData));
            loadHistory();
        } catch (error) {
            console.error("Error checking URL:", error);
            loading.classList.remove("active");
            result.classList.remove("hidden");
            status.textContent = "Error checking site";
            status.className = "text-2xl font-semibold text-center text-red-600";
            reasons.textContent = error.message;
        }
    });

    loadHistory();
});