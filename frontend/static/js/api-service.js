/**
 * API Service for the Fraud Detection Web App
 * Provides methods for interacting with the backend API
 */

const ApiService = (function() {
// API endpoints
    const API_ENDPOINTS = {
        predict: '/predict',
        analyze: '/analyze'
    };
    
    /**
     * Sends a URL for fraud prediction
     * @param {string} url - The URL to analyze
     * @returns {Promise} A promise that resolves with the prediction result
     */
    function predictUrl(url) {
        console.log('ApiService: Predicting URL:', url);
        
        // Ensure URL has scheme
        let processedUrl = url;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            processedUrl = 'http://' + url;
        }
        
        // Make the API request
        return fetch(API_ENDPOINTS.predict, {
            method: 'POST',
        headers: {
          'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: processedUrl })
      })
    .then(response => {
            if (!response.ok) {
                throw new Error(`API request failed with status ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('ApiService: Prediction result:', data);
            return data;
        })
        .catch(error => {
            console.error('ApiService: Error predicting URL:', error);
            throw error;
        });
    }
    
    /**
     * Generates a detailed analysis report for a URL
     * @param {string} url - The URL to analyze
     * @param {string} format - The format of the report (pdf, json)
     * @returns {Promise} A promise that resolves with the analysis result
     */
    function generateAnalysisReport(url, format = 'json') {
        console.log('ApiService: Generating analysis report for URL:', url);
        
        // Ensure URL has scheme
    let processedUrl = url;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      processedUrl = 'http://' + url;
    }

        // Make the API request
        return fetch(`${API_ENDPOINTS.analyze}?format=${format}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: processedUrl })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`API request failed with status ${response.status}`);
          }
          
            // Handle different formats
            if (format === 'pdf') {
                return response.blob();
            }
            return response.json();
        })
        .then(data => {
            console.log('ApiService: Analysis result received');
            return data;
        })
        .catch(error => {
            console.error('ApiService: Error generating analysis report:', error);
      throw error;
        });
    }
    
    // Public API
    return {
        predictUrl,
        generateAnalysisReport
    };
})();

// Make API service available globally
window.ApiService = ApiService; 