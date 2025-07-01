document.addEventListener('DOMContentLoaded', function() {
    // Get references to elements
    const primaryTestBtn = document.getElementById('test-primary');
    const backupTestBtn = document.getElementById('test-backup');
    const primaryResult = document.getElementById('primary-result');
    const backupResult = document.getElementById('backup-result');
    
    // Test the primary API endpoint
    primaryTestBtn.addEventListener('click', function() {
        primaryResult.innerHTML = 'Testing...';
        
        fetch('/test-api-connection', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: 'primary' })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                primaryResult.innerHTML = `<span class="success">✓ Connected successfully! Response: ${data.message}</span>`;
            } else {
                primaryResult.innerHTML = `<span class="error">✗ Connection failed: ${data.error}</span>`;
            }
        })
        .catch(error => {
            primaryResult.innerHTML = `<span class="error">✗ Connection error: ${error.message}</span>`;
        });
    });
    
    // Test the backup API endpoint
    backupTestBtn.addEventListener('click', function() {
        backupResult.innerHTML = 'Testing...';
        
        fetch('/test-api-connection', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: 'backup' })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                backupResult.innerHTML = `<span class="success">✓ Connected successfully! Response: ${data.message}</span>`;
            } else {
                backupResult.innerHTML = `<span class="error">✗ Connection failed: ${data.error}</span>`;
            }
        })
        .catch(error => {
            backupResult.innerHTML = `<span class="error">✗ Connection error: ${error.message}</span>`;
        });
    });
    
    // Test direct connection to backup API
    document.getElementById('test-backup-direct').addEventListener('click', function() {
        const resultElem = document.getElementById('backup-direct-result');
        resultElem.innerHTML = 'Testing direct connection...';
        
        // This will show the actual request in the browser's Network tab
        fetch("https://kh03-fraud-detection-api.hf.space/health-check", {
            method: 'GET',
            headers: {
                'Authorization': 'Bearer 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',
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            const status = response.status;
            resultElem.innerHTML += `<br>Status: ${status} (${response.statusText})`;
            return response.text();
        })
        .then(text => {
            resultElem.innerHTML += `<br>Response: ${text}`;
        })
        .catch(error => {
            resultElem.innerHTML += `<br>Error: ${error.message}`;
        });
    });
}); 