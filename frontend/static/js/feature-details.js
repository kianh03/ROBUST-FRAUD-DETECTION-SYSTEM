/**
 * Feature Details Script
 * Handles the display of feature details in the feature details table
 */

// Main function to populate feature details
function populateFeatureDetails(features) {
    const featureDetailsTableBody = document.getElementById('feature-details-table-body');
    if (!featureDetailsTableBody) {
        console.error('Feature details table body element not found');
        return;
    }

    // Clear existing rows
    featureDetailsTableBody.innerHTML = '';
    
    // Get the table header and update it to remove redundant columns
    const tableHeader = document.querySelector('.feature-details-table thead tr');
    if (tableHeader) {
        tableHeader.innerHTML = `
            <th style="width: 40%">Feature</th>
            <th style="width: 20%">Value</th>
            <th style="width: 40%">Risk Impact</th>
        `;
    }

    // Sort features by impact (absolute value)
    const sortedFeatures = [...features].sort((a, b) => 
        Math.abs(b.percentage || 0) - Math.abs(a.percentage || 0)
    );

    // Add each feature to the table
    sortedFeatures.forEach(feature => {
        // Parse feature information
        const name = feature.feature_name || feature.name || 'Unknown Feature';
        const value = typeof feature.value !== 'undefined' ? feature.value : '-';
        
        // Parse percentage - support both percentage and contribution fields
        let percentage = 0;
        if (typeof feature.percentage !== 'undefined') {
            percentage = parseFloat(feature.percentage);
        } else if (typeof feature.contribution !== 'undefined') {
            percentage = parseFloat(feature.contribution) * 100;
        }
        
        // Fix for NaN values
        if (isNaN(percentage)) {
            percentage = 0;
        }
        
        // Determine color class based on percentage
        let colorClass = 'success';
        if (percentage > 60) {
            colorClass = 'danger';
        } else if (percentage > 20) {
            colorClass = 'warning';
        }
        
        // Create table row
        const row = document.createElement('tr');
        
        // Create feature name cell
        const nameCell = document.createElement('td');
        nameCell.innerHTML = `<div class="feature-name"><i class="fas fa-info-circle" style="margin-right: 8px; color: #3b82f6;"></i>${name}</div>`;
        row.appendChild(nameCell);
        
        // Create value cell
        const valueCell = document.createElement('td');
        valueCell.textContent = value;
        valueCell.style.fontWeight = '500';
        row.appendChild(valueCell);
        
        // Create impact cell with percentage bar
        const impactCell = document.createElement('td');
        
        // Create impact indicator container
        const impactIndicator = document.createElement('div');
        impactIndicator.className = 'impact-indicator';
        impactIndicator.style.display = 'flex';
        impactIndicator.style.flexDirection = 'column';
        impactIndicator.style.gap = '4px';
        
        // Create impact bar container
        const impactBarContainer = document.createElement('div');
        impactBarContainer.style.width = '100%';
        impactBarContainer.style.position = 'relative';
        impactBarContainer.style.height = '8px';
        impactBarContainer.style.backgroundColor = 'rgba(30, 41, 59, 0.2)';
        impactBarContainer.style.borderRadius = '4px';
        impactBarContainer.style.overflow = 'hidden';
        
        // Create impact bar
        const impactBar = document.createElement('div');
        impactBar.className = `impact-bar ${colorClass}`;
        impactBar.style.height = '100%';
        impactBar.style.width = `${Math.min(Math.abs(percentage), 100)}%`;
        impactBar.style.transition = 'width 0.5s ease-in-out';
        
        // Set bar color
        if (colorClass === 'danger') {
            impactBar.style.backgroundColor = '#ef4444';
        } else if (colorClass === 'warning') {
            impactBar.style.backgroundColor = '#f59e0b';
        } else {
            impactBar.style.backgroundColor = '#10b981';
        }
        
        impactBarContainer.appendChild(impactBar);
        
        // Create impact value that shows on top of the bar
        const impactValue = document.createElement('div');
        impactValue.className = 'impact-value';
        impactValue.style.display = 'flex';
        impactValue.style.justifyContent = 'space-between';
        impactValue.style.alignItems = 'center';
        
        // Impact percentage text
        const percentText = document.createElement('span');
        percentText.textContent = percentage.toFixed(1) + '%';
        percentText.style.fontWeight = '600';
        percentText.style.color = colorClass === 'danger' ? '#ef4444' : 
                                  colorClass === 'warning' ? '#f59e0b' : '#10b981';
        
        // Impact label
        const impactLabel = document.createElement('span');
        impactLabel.textContent = percentage > 60 ? 'High Impact' : 
                                 percentage > 20 ? 'Medium Impact' : 'Low Impact';
        impactLabel.style.fontSize = '0.8rem';
        impactLabel.style.color = 'var(--text-muted)';
        
        impactValue.appendChild(percentText);
        impactValue.appendChild(impactLabel);
        
        // Add elements to indicator
        impactIndicator.appendChild(impactValue);
        impactIndicator.appendChild(impactBarContainer);
        
        // Add indicator to cell
        impactCell.appendChild(impactIndicator);
        
        // Add cell to row
        row.appendChild(impactCell);
        
        // Add row to table
        featureDetailsTableBody.appendChild(row);
    });
    
    // Add a description below the table
    const tableContainer = featureDetailsTableBody.closest('.card-body');
    if (tableContainer) {
        const existingDescription = tableContainer.querySelector('.feature-description');
        if (existingDescription) {
            existingDescription.remove();
        }
        
        const description = document.createElement('div');
        description.className = 'feature-description';
        description.style.marginTop = '20px';
        description.style.padding = '10px 15px';
        description.style.backgroundColor = 'rgba(15, 23, 42, 0.2)';
        description.style.borderRadius = '8px';
        description.style.fontSize = '0.9rem';
        description.style.color = 'var(--text-muted)';
        description.style.borderLeft = '4px solid #3b82f6';
        
        description.innerHTML = `
            <p style="margin: 0;">
                <i class="fas fa-info-circle" style="margin-right: 8px; color: #3b82f6;"></i>
                <strong>About Feature Details:</strong> These are the URL and domain features analyzed to determine the risk score. 
                Features with higher impact percentages contribute more to the overall risk assessment.
            </p>
        `;
        
        tableContainer.appendChild(description);
    }
}

// Listen for results from the main display-results.js
document.addEventListener('DOMContentLoaded', function() {
    // If the global displayResults object exists, extend it
    if (window.displayResults) {
        // Store original displayAllResults function
        const originalDisplayAllResults = window.displayResults.displayAllResults;
        
        // Override displayAllResults to also populate feature details
        window.displayResults.displayAllResults = function(data) {
            // Call original function first
            originalDisplayAllResults(data);
            
            // Then populate feature details
            if (data.feature_contributions && data.feature_contributions.length > 0) {
                populateFeatureDetails(data.feature_contributions);
            } else if (data.feature_table && data.feature_table.length > 0) {
                populateFeatureDetails(data.feature_table);
            }
        };
    }
});

// Make the function available globally
window.populateFeatureDetails = populateFeatureDetails; 