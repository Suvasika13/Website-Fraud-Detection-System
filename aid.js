document.getElementById('urlForm').addEventListener('submit', function(e) {
    e.preventDefault();

    // Get the URL from the input
    let url = document.getElementById('urlInput').value.trim();

    // Check if the URL is valid
    if (!isValidURL(url)) {
        alert("Please enter a valid URL.");
        return;
    }

    // Check if the URL is fraudulent or not
    let prediction = isFraudulent(url);

    // Show the result
    let resultText = prediction ? "❌ Wrong (Fraudulent URL)" : "✅ Correct (Legitimate URL)";
    document.getElementById('resultText').textContent = resultText;
    document.getElementById('result').classList.remove('hidden');
});

// Function to validate URL format
function isValidURL(url) {
    const regex = /^(ftp|http|https):\/\/[^ "]+$/;
    return regex.test(url);
}

// Function to detect if URL is suspicious
function isFraudulent(url) {
    const fraudKeywords = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'paypal'];
    for (let word of fraudKeywords) {
        if (url.toLowerCase().includes(word)) {
            return true;
        }
    }
    return false;
}
