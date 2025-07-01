/**
 * URL Form Handler
 * Handles the submission of the URL form using AJAX to prevent page refreshes
 */

document.addEventListener('DOMContentLoaded', function() {
    // Get form elements
    const urlForm = document.getElementById('urlForm');
    const urlInput = document.getElementById('url');
    const submitButton = document.getElementById('submitBtn');
    const loadingElement = document.getElementById('loading');
    const resultsElement = document.getElementById('results');
    const errorContainer = document.getElementById('errorContainer');
    const errorMessage = document.getElementById('errorMessage');
    const errorDetails = document.getElementById('errorDetails');
    const dismissErrorBtn = document.getElementById('dismissError');
    
    console.log('URL Form Handler initialized');
    
    if (!urlForm) {
        console.warn('URL form not found on this page');
        return; // Exit if not on a page with the form
    }
    
    // Check if there's a URL in localStorage from the history page
    const savedUrl = localStorage.getItem('urlToAnalyze');
    if (savedUrl) {
        console.log('Found saved URL to analyze:', savedUrl);
        urlInput.value = savedUrl;
        // Clear it from localStorage
        localStorage.removeItem('urlToAnalyze');
    }
    
    // Check for URL parameter in the query string
    const urlParams = new URLSearchParams(window.location.search);
    const urlParam = urlParams.get('url');
    if (urlParam) {
        console.log('Found URL in query parameters:', urlParam);
        urlInput.value = urlParam;
        // Automatically analyze the URL
        setTimeout(() => {
            analyzeUrl(urlParam);
        }, 500);
    }
    
    // Handle form submission
    urlForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Log form submission
        console.log('Form submitted');
            
        // Get URL
        const url = urlInput.value.trim();
        
        // Simple validation
        if (!url) {
            showError('Please enter a URL to analyze', 'Enter a valid URL to check for potential fraud.');
            return;
        }
        
        analyzeUrl(url);
    });
    
    // Function to analyze URL
    function analyzeUrl(url) {
        // Disable button and show loading
        submitButton.disabled = true;
        loadingElement.style.display = 'block';
        resultsElement.style.display = 'none';
        errorContainer.style.display = 'none';
        
        // Log analysis start
        console.log('Analyzing URL:', url);
        
        // Make AJAX request to analyze URL
        fetch('/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url }),
        })
        .then(response => {
            // Log response
            console.log('Response received, status:', response.status);
            
            if (!response.ok) {
                throw new Error('Network response was not ok: ' + response.status);
            }
            return response.json();
        })
        .then(data => {
            // Log successful analysis
            console.log('Analysis successful, data:', data);
            
            // Hide loading
            loadingElement.style.display = 'none';
            
            // Display results using the display-results.js functions
            if (typeof displayResults === 'function') {
                console.log('Using displayResults function');
                displayResults(data, url);
            } else if (typeof displayAllResults === 'function') {
                console.log('Using displayAllResults function');
                displayAllResults(data, url);
            } else {
                console.error('No display functions found');
                showError('Display function not found', 'There was an error displaying the results. Please try again later.');
                return;
            }
            
            // Show results
            resultsElement.style.display = 'block';
            
            // Save scan to Firestore if user is logged in
            saveToFirestore(url, data);
            
            // Re-enable button
            submitButton.disabled = false;
        })
        .catch(error => {
            // Log error
            console.error('Error analyzing URL:', error);
            
            // Hide loading and show error
            loadingElement.style.display = 'none';
            showError('Error analyzing URL', error.message);
            
            // Re-enable button
            submitButton.disabled = false;
        });
    }
    
    // Handle dismiss error button
    if (dismissErrorBtn) {
        dismissErrorBtn.addEventListener('click', function() {
            errorContainer.style.display = 'none';
        });
    }
    
    // Function to show error messages
    function showError(title, details) {
        console.error(title + ': ' + details);
        errorMessage.textContent = title || 'An error occurred';
        errorDetails.textContent = details || 'Please try again later';
        errorContainer.style.display = 'block';
    }
    
    // Function to save scan results to Firestore
    function saveToFirestore(url, data) {
        // Check if Firebase auth is available and user is logged in
        if (typeof firebase !== 'undefined' && firebase.auth) {
            const currentUser = firebase.auth().currentUser;
            
            if (currentUser) {
                console.log('Saving scan to Firestore for user:', currentUser.uid);
                
                const db = firebase.firestore();
                
                // Calculate the risk score from various possible sources in the data
                let riskScore = 0;
                
                // Look for the score in various locations in the data object
                if (typeof data.score !== 'undefined') {
                    // This is set by displaySectionRiskMeters function
                    riskScore = data.score;
                    console.log('Using data.score for risk score:', riskScore);
                } else if (typeof data.risk_score !== 'undefined') {
                    // This might come directly from the API
                    riskScore = data.risk_score;
                    console.log('Using data.risk_score for risk score:', riskScore);
                } else if (data.section_totals) {
                    // Calculate from section totals if available
                    const sectionTotals = data.section_totals;
                    const keyRiskScore = sectionTotals["Key Risk Factors (AI Predict)"] || sectionTotals["Key Risk Factors"] || 0;
                    const domainInfoScore = sectionTotals["Domain Information"] || 0;
                    const suspiciousPatternsScore = sectionTotals["Suspicious Patterns"] || 0;
                    
                    riskScore = keyRiskScore + domainInfoScore + suspiciousPatternsScore;
                    console.log('Calculated risk score from section totals:', riskScore);
                }
                
                // Normalize to percentage if it's a decimal
                if (riskScore <= 1 && riskScore > 0) {
                    riskScore = Math.round(riskScore * 100);
                    console.log('Normalized risk score to percentage:', riskScore);
                }
                
                // Ensure risk score is a positive integer
                riskScore = Math.max(0, Math.round(riskScore));
                console.log('Final risk score to save:', riskScore);
                
                // Determine risk level based on score
                let riskLevel = 'low';
                if (riskScore > 60) {
                    riskLevel = 'high';
                } else if (riskScore >= 30) {
                    riskLevel = 'medium';
                }
                
                // Add scan record to Firestore
                db.collection('users').doc(currentUser.uid).collection('scans').add({
                    url: url,
                    riskScore: riskScore,
                    riskLevel: riskLevel,
                    timestamp: firebase.firestore.FieldValue.serverTimestamp(),
                    resultData: {
                        suspiciousPatterns: data.suspicious_patterns || [],
                        domainInfo: data.domain_info || {},
                        features: data.feature_table || [],
                        sectionTotals: data.section_totals || {}
                    }
                })
                .then((docRef) => {
                    console.log("Scan saved to Firestore with ID:", docRef.id);
                    // The metrics will be automatically updated by the real-time listeners
                    // without needing to explicitly call initializeDashboard
                })
                .catch((error) => {
                    console.error("Error saving scan to Firestore:", error);
                });
            }
        }
    }
    
    // Function to update user stats with risk information
    function updateUserStatsWithRisk(userId, riskScore, riskLevel) {
        if (typeof firebase !== 'undefined' && firebase.firestore) {
            const db = firebase.firestore();
            const userStatsRef = db.collection('users').doc(userId).collection('stats').doc('overview');
            
            // Use transaction to safely update the counter
            db.runTransaction((transaction) => {
                return transaction.get(userStatsRef).then((statsDoc) => {
                    if (!statsDoc.exists) {
                        // Create initial stats document
                        console.log("Creating new stats document with totalScans = 1");
                        const isHighRisk = riskLevel === 'high';
                        const isLowRisk = riskLevel === 'low';
                        
                        transaction.set(userStatsRef, {
                            totalScans: 1,
                            lastScanDate: firebase.firestore.FieldValue.serverTimestamp(),
                            threatsDetected: isHighRisk ? 1 : 0,
                            safeUrls: isLowRisk ? 1 : 0, // Only count low risk URLs as safe
                            avgRiskScore: riskScore,
                            highRiskScans: isHighRisk ? 1 : 0,
                            mediumRiskScans: riskLevel === 'medium' ? 1 : 0,
                            lowRiskScans: isLowRisk ? 1 : 0
                        });
                    } else {
                        // Get current data
                        const currentData = statsDoc.data();
                        // Increment total scans
                        const newCount = ((currentData && currentData.totalScans) || 0) + 1;
                        console.log("Updating stats document: current totalScans =", 
                                  (currentData && currentData.totalScans) || 0, 
                                  "new totalScans =", newCount);
                        
                        // Calculate new average risk score
                        const currentTotal = (currentData.avgRiskScore || 0) * (currentData.totalScans || 0);
                        const newAvg = (currentTotal + riskScore) / newCount;
                        
                        // Update threat counters based on risk level
                        const isHighRisk = riskLevel === 'high';
                        const isLowRisk = riskLevel === 'low';
                        const newThreats = ((currentData && currentData.threatsDetected) || 0) + (isHighRisk ? 1 : 0);
                        const newSafe = ((currentData && currentData.safeUrls) || 0) + (isLowRisk ? 1 : 0); // Only count low risk URLs as safe
                        
                        // Update risk level counters
                        const highRiskScans = ((currentData && currentData.highRiskScans) || 0) + (riskLevel === 'high' ? 1 : 0);
                        const mediumRiskScans = ((currentData && currentData.mediumRiskScans) || 0) + (riskLevel === 'medium' ? 1 : 0);
                        const lowRiskScans = ((currentData && currentData.lowRiskScans) || 0) + (riskLevel === 'low' ? 1 : 0);
                        
                        transaction.update(userStatsRef, {
                            totalScans: newCount,
                            lastScanDate: firebase.firestore.FieldValue.serverTimestamp(),
                            threatsDetected: newThreats,
                            safeUrls: newSafe,
                            avgRiskScore: newAvg,
                            highRiskScans: highRiskScans,
                            mediumRiskScans: mediumRiskScans,
                            lowRiskScans: lowRiskScans
                        });
                    }
                });
            }).then(() => {
                console.log("User stats updated successfully");
            }).catch((error) => {
                console.error("Error updating user stats:", error);
            });
        }
    }
}); 