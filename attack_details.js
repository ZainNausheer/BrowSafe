document.addEventListener("DOMContentLoaded", () => {
    const threatsDiv = document.getElementById("threats");
    const urlParams = new URLSearchParams(window.location.search);
    const checkId = urlParams.get("check_id");

    const historyData = JSON.parse(localStorage.getItem("checkHistory") || "[]");
    const check = historyData.find(item => item.check_id === checkId);

    if (!check || !check.reasons.length) {
        threatsDiv.innerHTML = "<p class='text-red-600 text-lg'>No threat details found.</p>";
        return;
    }

    check.reasons.forEach(reason => {
        const div = document.createElement("div");
        div.className = "bg-gray-50 p-6 rounded-lg shadow-sm";
        div.innerHTML = `
            <h3 class="text-2xl font-semibold text-gray-800 mb-4">${reason.type}</h3>
            <p class="text-gray-700 mb-4 text-lg">${reason.description}</p>
            <h4 class="text-xl font-semibold text-gray-800 mb-2">How to Stay Safe:</h4>
            <ul class="list-disc pl-6 text-gray-700 space-y-2 text-lg">
                ${reason.prevention.map(tip => `<li>${tip}</li>`).join("")}
            </ul>
        `;
        threatsDiv.appendChild(div);
    });
});