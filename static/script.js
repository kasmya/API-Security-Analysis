document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('analyzeForm');
    const resultBox = document.getElementById('result');
    const logsContainer = document.getElementById('logsContainer');
    
    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const url = document.getElementById('url').value;
        const method = document.getElementById('method').value;
        const payloadText = document.getElementById('payload').value;
        
        let payload = null;
        if (payloadText.trim()) {
            try {
                payload = JSON.parse(payloadText);
            } catch (err) {
                payload = payloadText;
            }
        }
        
        const data = {
            url: url,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'SecurityAnalyzer/1.0'
            },
            payload: payload
        };
        
        resultBox.innerHTML = '⏳ Analyzing request...';
        resultBox.className = 'result-box';
        resultBox.classList.remove('hidden');
        
        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });
            
            const result = await response.json();
            
            if (result.valid && (!result.issues || result.issues.length === 0)) {
                resultBox.classList.add('valid');
                resultBox.innerHTML = `
                    <h3>✅ Request appears legitimate</h3>
                    <p>Anomaly Score: ${result.anomaly_score?.toFixed(4) || 'N/A'}</p>
                `;
            } else {
                resultBox.classList.add('threat');
                resultBox.innerHTML = `
                    <h3>⚠️ Potential threats detected!</h3>
                    <p>Anomaly Score: ${result.anomaly_score?.toFixed(4) || 'N/A'}</p>
                    <ul>
                        ${result.issues.map(issue => `<li>• ${issue}</li>`).join('')}
                    </ul>
                `;
            }
        } catch (error) {
            resultBox.classList.add('threat');
            resultBox.innerHTML = `
                <h3>❌ Error analyzing request</h3>
                <p>${error.message}</p>
            `;
        }
    });
    
    window.loadLogs = async function() {
        try {
            const response = await fetch('/api/logs');
            const data = await response.json();
            
            if (data.logs && data.logs.length > 0) {
                logsContainer.innerHTML = data.logs.map(log => 
                    `<div class="log-entry"><span class="timestamp">${log}</span></div>`
                ).join('');
            } else {
                logsContainer.innerHTML = '<p style="color: #888; padding: 1rem;">No logs available</p>';
            }
        } catch (error) {
            logsContainer.innerHTML = `<p style="color: #ff5252; padding: 1rem;">Error loading logs: ${error.message}</p>`;
        }
    };
    
    loadLogs();
});

