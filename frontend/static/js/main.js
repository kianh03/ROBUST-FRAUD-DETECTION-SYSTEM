// Main JavaScript file for the Phishing Detection Web App

// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('App initialized');

    // Get form elements
    const urlForm = document.getElementById('urlForm');
    const urlInput = document.getElementById('urlInput');
    const analyzeButton = document.querySelector('#urlForm button[type="submit"]');
    const loadingElement = document.getElementById('loading');
    const resultsSection = document.getElementById('results');
    const errorContainer = document.getElementById('errorContainer');
    const errorMessage = document.getElementById('errorMessage');
    const errorDetails = document.getElementById('errorDetails');
    const dismissErrorBtn = document.getElementById('dismissError');

    // Add event listener to the form
    if (urlForm) {
        urlForm.addEventListener('submit', function(event) {
            event.preventDefault();
            
            // Get the URL from the input field
            const url = urlInput.value.trim();
            
            // Validate URL
            if (!url) {
                showError('Please enter a URL', 'The URL field cannot be empty');
                return;
            }
            
            // Show loading state
            setLoading(true);
            hideError();
            hideResults();
            
            // Call the API to analyze the URL
            console.log('Analyzing URL:', url);
            analyzeURL(url);
        });
    }

    // Function to analyze the URL
    function analyzeURL(url) {
        console.log(`Sending URL for analysis: ${url}`);
        
        // Use the API service to predict the URL
        window.ApiService.predictUrl(url)
            .then(result => {
                console.log('Analysis result:', result);
                
                // Process and display the results
                setLoading(false);
                
                // Use the displayResults module if available
                if (window.displayResults && typeof window.displayResults.displayAllResults === 'function') {
                    window.displayResults.displayAllResults(result);
                    // Show results section
                    if (resultsSection) {
                        resultsSection.style.display = 'block';
                    }
                } else {
                    console.error('Display results module not found');
                    showError('Error displaying results', 'Display module not found');
                }
            })
            .catch(error => {
                console.error('Error analyzing URL:', error);
                setLoading(false);
                showError('Error analyzing URL', error.message || 'Unknown error occurred');
            });
    }

    // Helper function to set loading state
    function setLoading(isLoading) {
        if (analyzeButton) analyzeButton.disabled = isLoading;
        if (loadingElement) loadingElement.style.display = isLoading ? 'block' : 'none';
    }

    // Helper function to show error message
    function showError(message, details) {
        if (errorContainer) {
            if (errorMessage) errorMessage.textContent = message;
            if (errorDetails) errorDetails.textContent = details || 'Please try again or check your connection.';
            errorContainer.style.display = 'block';
        }
    }

    // Helper function to hide error message
    function hideError() {
        if (errorContainer) {
            errorContainer.style.display = 'none';
        }
    }

    // Helper function to hide results
    function hideResults() {
        if (resultsSection) {
            resultsSection.style.display = 'none';
        }
    }

    // Add event listener to dismiss error button
    if (dismissErrorBtn) {
        dismissErrorBtn.addEventListener('click', hideError);
    }

    // Initialize any components or features
    initializeExamples();
});

// Function to initialize example links
function initializeExamples() {
    const exampleLinks = document.querySelectorAll('.example-link');
    
    exampleLinks.forEach(link => {
        link.addEventListener('click', function(event) {
            event.preventDefault();
            
            const url = this.getAttribute('data-url');
            if (url) {
                const urlInput = document.getElementById('urlInput');
                if (urlInput) {
                    urlInput.value = url;
                    
                    // Auto-submit the form
                    const form = document.getElementById('urlForm');
                    if (form) {
                        // Create and dispatch a submit event
                        const submitEvent = new Event('submit', {
                            bubbles: true,
                            cancelable: true
                        });
                        form.dispatchEvent(submitEvent);
                    }
                }
            }
        });
    });
} 