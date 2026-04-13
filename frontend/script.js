async function checkURL() {
    const url = document.getElementById("urlInput").value;

    const res = await fetch("http://127.0.0.1:5000/predict", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ url: url })
    });

    const data = await res.json();
    showPopup(data);
}

function showPopup(data) {
    document.getElementById("popup").classList.remove("hidden");

    const icon = document.getElementById("icon");
    const resultText = document.getElementById("resultText");
    const urlDisplay = document.getElementById("urlDisplay");
    const checks = document.getElementById("checks");

    if (data.result === "Legitimate") {
        icon.innerHTML = "✅";
        resultText.innerText = "Legitimate Website";
        resultText.style.color = "lightgreen";
    } else {
        icon.innerHTML = "❌";
        resultText.innerText = "Phishing Website";
        resultText.style.color = "red";
    }

    urlDisplay.innerText = "URL: " + document.getElementById("urlInput").value;
    
    const f = data.features;

    checks.innerHTML = `
    <p class="${f.is_base_domain_match ? 'good' : 'bad'}">
        ${f.is_base_domain_match ? "✔" : "❌"} Trusted domain
    </p>

    <p class="${!f.having_ip ? 'good' : 'bad'}">
        ${!f.having_ip ? "✔" : "❌"} No IP address
    </p>

    <p class="${!f.has_at ? 'good' : 'bad'}">
        ${!f.has_at ? "✔" : "❌"} No '@' symbol
    </p>

    <p class="${!f.has_suspicious_words ? 'good' : 'bad'}">
        ${!f.has_suspicious_words ? "✔" : "❌"} No suspicious words
    </p>

    <p class="${!f.suspicious_tld ? 'good' : 'bad'}">
        ${!f.suspicious_tld ? "✔" : "❌"} Safe TLD
    </p>

    <p class="${f.https ? 'good' : 'bad'}">
        ${f.https ? "✔" : "❌"} Contains HTTPS
    </p>
`;
}

function closePopup() {
    document.getElementById("popup").classList.add("hidden");
}