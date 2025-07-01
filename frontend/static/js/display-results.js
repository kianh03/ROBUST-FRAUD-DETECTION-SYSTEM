// Display Results Module
// This module handles the display of analysis results in the UI

// Main namespace to avoid global pollution
const displayResults = (function() {
  
  /**
   * Displays risk factors in the Key Risk Factors section
   * @param {Object} data - The analysis data from the API
   */
  function displayRiskFactors(data) {
    const riskFactorsContainer = document.getElementById('topFeatures');
    if (!riskFactorsContainer) {
      console.error("Risk factors container not found with ID 'topFeatures'");
      return;
    }
    
    riskFactorsContainer.innerHTML = '';
    
    console.log("Displaying risk factors from data:", data);

    let factors = [];
    
    // Try to get features from feature_table (primary source)
    if (data.feature_table && Array.isArray(data.feature_table)) {
        console.log("Found feature_table:", data.feature_table);
        factors = data.feature_table
            .filter(f => Math.abs(f.impact || 0) > 0.01)
            .sort((a, b) => Math.abs(b.impact || 0) - Math.abs(a.impact || 0))
            .slice(0, 5)
            .map(f => ({
                name: f.feature,
                value: f.value,
                percentage: f.impact || 0,
                color_class: f.color_class || 'success'
            }));
    }
    // Fallback to feature_contributions if available
    else if (data.feature_contributions && Array.isArray(data.feature_contributions)) {
        console.log("Using feature_contributions:", data.feature_contributions);
        factors = data.feature_contributions
            .filter(f => f.section === "Key Risk Factors" && Math.abs(f.percentage || 0) > 0.01)
            .sort((a, b) => Math.abs(b.percentage || 0) - Math.abs(a.percentage || 0))
            .slice(0, 5);
    }

    if (factors.length > 0) {
        // Create and append risk factor elements
        factors.forEach(factor => {
            // Determine color class based on percentage
            const percentage = parseFloat(factor.percentage || 0);
            let colorClass = 'success';
            if (percentage > 30) {
                colorClass = 'danger';
            } else if (percentage > 15) {
                colorClass = 'warning';
            }
            
            const factorEl = document.createElement('div');
            factorEl.className = 'contribution-bar';
            factorEl.style.marginBottom = '16px';
            
            // Create header with name and value
            const headerEl = document.createElement('div');
            headerEl.className = 'contribution-label';
            headerEl.style.display = 'flex';
            headerEl.style.justifyContent = 'space-between';
            headerEl.style.marginBottom = '6px';
            
            const nameEl = document.createElement('span');
            nameEl.className = 'factor-name';
            nameEl.textContent = formatFeatureName(factor.name || factor.feature_name);
            nameEl.style.fontWeight = '500';
            
            const valueEl = document.createElement('span');
            valueEl.className = `contribution-value ${colorClass}`;
            valueEl.textContent = `${percentage.toFixed(1)}%`;
            valueEl.style.fontWeight = '600';
            if (colorClass === 'danger') {
                valueEl.style.color = '#ef4444';
            } else if (colorClass === 'warning') {
                valueEl.style.color = '#f59e0b';
            } else {
                valueEl.style.color = '#10b981';
            }
            
            headerEl.appendChild(nameEl);
            headerEl.appendChild(valueEl);
            
            // Create enhanced bar chart visualization
            const barContainerEl = document.createElement('div');
            barContainerEl.className = 'bar-container';
            barContainerEl.style.position = 'relative';
            barContainerEl.style.height = '12px';
            barContainerEl.style.borderRadius = '6px';
            barContainerEl.style.overflow = 'hidden';
            barContainerEl.style.backgroundColor = 'rgba(30, 41, 59, 0.4)';
            
            const barEl = document.createElement('div');
            barEl.className = `bar-fill ${colorClass}`;
            barEl.style.height = '100%';
            barEl.style.width = `${Math.min(Math.abs(percentage), 100)}%`;
            barEl.style.borderRadius = '6px';
            barEl.style.transition = 'width 1s cubic-bezier(0.22, 1, 0.36, 1)';
            
            // Add gradient to the bar
            if (colorClass === 'danger') {
                barEl.style.background = 'linear-gradient(90deg, #ef4444, #b91c1c)';
            } else if (colorClass === 'warning') {
                barEl.style.background = 'linear-gradient(90deg, #f59e0b, #d97706)';
            } else {
                barEl.style.background = 'linear-gradient(90deg, #10b981, #059669)';
            }
            
            barContainerEl.appendChild(barEl);
            
            // Feature value display
            const valueDisplayEl = document.createElement('div');
            valueDisplayEl.className = 'feature-value-display';
            valueDisplayEl.style.display = 'flex';
            valueDisplayEl.style.justifyContent = 'flex-end';
            valueDisplayEl.style.marginTop = '4px';
            valueDisplayEl.style.fontSize = '0.85rem';
            valueDisplayEl.style.color = '#94a3b8';
            
            // Format and display the feature value
            let displayValue = factor.value;
            if (typeof factor.value === 'boolean') {
                displayValue = factor.value ? 'Yes' : 'No';
            } else if (factor.value === 0 || factor.value === 1) {
                displayValue = factor.value === 1 ? 'Yes' : 'No';
            }
            
            valueDisplayEl.textContent = `Value: ${displayValue}`;
            
            // Assemble the components
            factorEl.appendChild(headerEl);
            factorEl.appendChild(barContainerEl);
            factorEl.appendChild(valueDisplayEl);
            
            // Add to container
            riskFactorsContainer.appendChild(factorEl);
        });
    } else {
        // No risk factors found
        const noFactorsEl = document.createElement('p');
        noFactorsEl.textContent = 'No significant risk factors detected.';
        noFactorsEl.style.textAlign = 'center';
        noFactorsEl.style.padding = '20px';
        noFactorsEl.style.color = '#94a3b8';
        
        riskFactorsContainer.appendChild(noFactorsEl);
    }
  }
  
  /**
   * Displays domain information in the Domain Information section
   * @param {Object} data - The analysis data from the API
   */
  function displayDomainInfo(data) {
    const domainInfoContainer = document.getElementById('domainInfo');
    if (!domainInfoContainer) {
        console.error("Domain info container not found with ID 'domainInfo'");
        return;
    }
    
    domainInfoContainer.innerHTML = '';
    
    // Extract domain info from data
    const domainInfo = data.domain_info || {};
    
    // Get URL parts
    const url = data.url || '';
    const parsed = new URL(url);
    const domain = parsed.hostname;
    const protocol = parsed.protocol.replace(':', '');
    
    // Check if IP address could not be resolved
    const ipNotResolved = !domainInfo.ip_address || 
                          domainInfo.ip_address === 'Unknown' || 
                          domainInfo.ip_address === 'Could not resolve';
    
    // If IP address couldn't be resolved, increase section risk
    if (ipNotResolved) {
      increaseIPResolutionRisk(data);
    }
    
    // Calculate domain age if available
    let domainAge = null;
    let domainAgeStatus = 'neutral';
    
    if (domainInfo.created && domainInfo.created !== 'Unknown') {
        try {
            const createdDate = new Date(domainInfo.created);
            const now = new Date();
            const ageInDays = Math.floor((now - createdDate) / (1000 * 60 * 60 * 24));
            
            // Format the creation date
            const formattedDate = createdDate.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            });
            
            if (ageInDays < 30) {
                domainAge = `${ageInDays} days (Created: ${formattedDate})`;
                domainAgeStatus = 'danger';
            } else if (ageInDays < 90) {
                domainAge = `${Math.floor(ageInDays / 30)} months (Created: ${formattedDate})`;
                domainAgeStatus = 'warning';
            } else if (ageInDays < 365) {
                domainAge = `${Math.floor(ageInDays / 30)} months (Created: ${formattedDate})`;
                domainAgeStatus = 'neutral';
            } else {
                const years = Math.floor(ageInDays / 365);
                domainAge = `${years} ${years === 1 ? 'year' : 'years'} (Created: ${formattedDate})`;
                domainAgeStatus = 'safe';
            }
        } catch (e) {
            console.error('Error calculating domain age:', e);
            domainAge = domainInfo.created;
        }
    }
    
    // Check TLD type
    let tldType = null;
    let tldSuspicious = false;
    let tldDescription = '';
    
    if (domain) {
        try {
            const tld = domain.split('.').pop().toLowerCase();
            const commonTlds = ['com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'me', 'app', 'dev'];
            const suspiciousTlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'online', 'site', 'club', 'icu'];
            
            if (commonTlds.includes(tld)) {
                tldType = `Common TLD (.${tld})`;
                tldDescription = 'Well-established and trusted top-level domain';
            } else if (suspiciousTlds.includes(tld)) {
                tldType = `Suspicious TLD (.${tld})`;
                tldSuspicious = true;
                tldDescription = 'This TLD is commonly associated with malicious websites';
            } else if (tld.length === 2) {
                tldType = `Country Code (.${tld})`;
                tldDescription = 'A country-specific top-level domain';
            } else {
                tldType = `Generic TLD (.${tld})`;
                tldDescription = 'A less common top-level domain';
            }
        } catch (e) {
            console.error('Error determining TLD type:', e);
        }
    }
    
    // Determine if WHOIS privacy is enabled based on organization name
    const whoisPrivacy = domainInfo.organization && 
        /privacy|protect|proxy|private|whois/i.test(domainInfo.organization) ? 'Enabled' : null;

    // Check if we have location data for the map
    const hasLocationData = (domainInfo.latitude && domainInfo.longitude && 
                           (domainInfo.latitude !== 0 || domainInfo.longitude !== 0)) || 
                           (domainInfo.country && domainInfo.country !== 'Unknown');
    
    // Create info items list with actual data
    const infoItems = [];
    
    // Only add items with valid values
    if (domain) {
        infoItems.push({ 
            label: 'Domain Name', 
            value: domain, 
            icon: 'fa-globe',
            description: 'The registered domain name of the website'
        });
    }
    
    if (protocol) {
        infoItems.push({ 
            label: 'Protocol', 
            value: protocol.toUpperCase(), 
            icon: protocol === 'https' ? 'fa-lock' : 'fa-unlock',
            isSecure: protocol === 'https',
            description: protocol === 'https' ? 
                'Secure connection with encryption' : 
                'Insecure connection without encryption'
        });
    }
    
    if (domainInfo.organization && domainInfo.organization !== 'Unknown') {
        infoItems.push({ 
            label: 'Organization', 
            value: domainInfo.organization, 
            icon: 'fa-building',
            description: 'The organization that owns this domain'
        });
    }
    
    if (domainInfo.country && domainInfo.country !== 'Unknown') {
        infoItems.push({ 
            label: 'Location', 
            value: domainInfo.city && domainInfo.city !== 'Unknown' ? 
                `${domainInfo.city}, ${domainInfo.country}` : 
                domainInfo.country, 
            icon: 'fa-location-dot',
            description: 'Geographic location of the hosting server'
        });
    }
    
    if (domainAge) {
        infoItems.push({ 
            label: 'Domain Age', 
            value: domainAge, 
            icon: 'fa-calendar-alt',
            isNew: domainAgeStatus === 'danger' || domainAgeStatus === 'warning',
            description: domainAgeStatus === 'danger' ? 'Very recently registered domain - high risk' :
                        domainAgeStatus === 'warning' ? 'Recently registered domain - potential risk' :
                        domainAgeStatus === 'safe' ? 'Well-established domain - lower risk' :
                        'How long the domain has been registered'
        });
    }
    
    if (tldType) {
        infoItems.push({ 
            label: 'TLD Type', 
            value: tldType, 
            icon: 'fa-tag',
            isSuspicious: tldSuspicious,
            description: tldDescription || 'The type of top-level domain used by this website'
        });
    }
    
    if (whoisPrivacy) {
        infoItems.push({ 
            label: 'WHOIS Privacy', 
            value: whoisPrivacy, 
            icon: 'fa-user-shield',
            description: 'Whether the domain uses privacy protection to hide owner information'
        });
    }
    
    if (data.ssl_info) {
        infoItems.push({ 
            label: 'SSL Certificate', 
            value: data.ssl_info.has_ssl ? 'Valid' : 'Not found', 
            icon: data.ssl_info.has_ssl ? 'fa-shield-check' : 'fa-shield-exclamation',
            isSecure: data.ssl_info.has_ssl,
            description: data.ssl_info.has_ssl ? 
                'SSL certificate is valid and trusted' : 
                'No SSL certificate found, connection is not encrypted'
        });
    }
    
    // Only create the IP and location section if there's an IP to display
    if (domainInfo.ip_address && domainInfo.ip_address !== 'Unknown') {
        // Create a card style container for IP and location
        const ipLocationCard = document.createElement('div');
        ipLocationCard.className = 'domain-info-card';
        ipLocationCard.style.marginBottom = '15px';
        ipLocationCard.style.padding = '15px';
        ipLocationCard.style.backgroundColor = 'rgba(15, 23, 42, 0.3)';
        ipLocationCard.style.borderRadius = '10px';
        ipLocationCard.style.border = '1px solid var(--border-color)';
        
        // Create IP Address header
        const ipHeader = document.createElement('div');
        ipHeader.className = 'ip-header';
        ipHeader.style.marginBottom = '10px';
        ipHeader.style.display = 'flex';
        ipHeader.style.alignItems = 'center';
        ipHeader.style.justifyContent = 'space-between';
        
        const ipLabel = document.createElement('div');
        ipLabel.style.color = 'var(--text-muted)';
        ipLabel.style.fontSize = '0.9rem';
        ipLabel.style.fontWeight = '500';
        ipLabel.innerHTML = '<i class="fas fa-network-wired" style="margin-right: 8px; color: #3b82f6;"></i> IP Address';
        
        const ipValue = document.createElement('div');
        ipValue.style.fontWeight = 'bold';
        ipValue.style.fontSize = '1.1rem';
        
        // Apply red color if IP could not be resolved
        if (domainInfo.ip_address === 'Could not resolve') {
            ipValue.style.color = '#ef4444';
        }
        
        ipValue.textContent = domainInfo.ip_address;
        
        ipHeader.appendChild(ipLabel);
        ipHeader.appendChild(ipValue);
        ipLocationCard.appendChild(ipHeader);
        
        // Only add the map if we have location data
        if (hasLocationData) {
            // Add a server location label with icon
            const serverLocationLabel = document.createElement('div');
            serverLocationLabel.className = 'server-location-label';
            serverLocationLabel.style.marginBottom = '10px';
            serverLocationLabel.style.fontWeight = '500';
            serverLocationLabel.style.display = 'flex';
            serverLocationLabel.style.alignItems = 'center';
            serverLocationLabel.innerHTML = '<i class="fas fa-map-marker-alt" style="margin-right: 8px; color: #ef4444;"></i> Server Location';
            ipLocationCard.appendChild(serverLocationLabel);
            
            // Add geolocation map
            const serverLocationDiv = document.createElement('div');
            serverLocationDiv.id = 'server-location-map';
            serverLocationDiv.style.width = '100%';
            serverLocationDiv.style.height = '180px';
            serverLocationDiv.style.borderRadius = '8px';
            serverLocationDiv.style.overflow = 'hidden';
            serverLocationDiv.style.border = '1px solid var(--border-color)';
            ipLocationCard.appendChild(serverLocationDiv);
            
            // Add the IP location card to the container (only if it has content)
            domainInfoContainer.appendChild(ipLocationCard);
            
            // Initialize map with the server location
            try {
                setTimeout(() => {
                    initMap('server-location-map', domainInfo, false);
                }, 100);
            } catch (e) {
                console.error('Error initializing map:', e);
                serverLocationDiv.innerHTML = '<div style="padding: 10px; text-align: center;">Error loading map</div>';
            }
        } else {
            // Add the IP location card without map if it has the IP but no location
            domainInfoContainer.appendChild(ipLocationCard);
        }
    } else if (!domainInfo.ip_address || domainInfo.ip_address === 'Unknown') {
        // Create a card showing that IP address could not be resolved
        const ipLocationCard = document.createElement('div');
        ipLocationCard.className = 'domain-info-card';
        ipLocationCard.style.marginBottom = '15px';
        ipLocationCard.style.padding = '15px';
        ipLocationCard.style.backgroundColor = 'rgba(15, 23, 42, 0.3)';
        ipLocationCard.style.borderRadius = '10px';
        ipLocationCard.style.border = '1px solid var(--border-color)';
        
        // Create IP Address header
        const ipHeader = document.createElement('div');
        ipHeader.className = 'ip-header';
        ipHeader.style.marginBottom = '10px';
        ipHeader.style.display = 'flex';
        ipHeader.style.alignItems = 'center';
        ipHeader.style.justifyContent = 'space-between';
        
        const ipLabel = document.createElement('div');
        ipLabel.style.color = 'var(--text-muted)';
        ipLabel.style.fontSize = '0.9rem';
        ipLabel.style.fontWeight = '500';
        ipLabel.innerHTML = '<i class="fas fa-network-wired" style="margin-right: 8px; color: #3b82f6;"></i> IP Address';
        
        const ipValue = document.createElement('div');
        ipValue.style.fontWeight = 'bold';
        ipValue.style.fontSize = '1.1rem';
        ipValue.style.color = '#ef4444';  // Red color to indicate error
        ipValue.textContent = 'Could not resolve';
        
        // Add warning message about IP resolution failure
        const warningMessage = document.createElement('div');
        warningMessage.style.marginTop = '10px';
        warningMessage.style.padding = '8px 12px';
        warningMessage.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
        warningMessage.style.borderRadius = '6px';
        warningMessage.style.border = '1px solid rgba(239, 68, 68, 0.3)';
        warningMessage.style.color = '#ef4444';
        warningMessage.style.fontSize = '0.85rem';
        warningMessage.innerHTML = '<i class="fas fa-exclamation-triangle" style="margin-right: 8px;"></i> Unable to resolve IP address. This may indicate domain masking or a newly registered domain, which increases risk.';
        
        ipHeader.appendChild(ipLabel);
        ipHeader.appendChild(ipValue);
        ipLocationCard.appendChild(ipHeader);
        ipLocationCard.appendChild(warningMessage);
        
        // Add the IP card to the container
        domainInfoContainer.appendChild(ipLocationCard);
    }
    
    // Only create domain details card if we have valid items to display
    if (infoItems.length > 0) {
        // Create domain details card
        const domainDetailsCard = document.createElement('div');
        domainDetailsCard.className = 'domain-details-card';
        domainDetailsCard.style.backgroundColor = 'rgba(15, 23, 42, 0.3)';
        domainDetailsCard.style.borderRadius = '10px';
        domainDetailsCard.style.border = '1px solid var(--border-color)';
        domainDetailsCard.style.overflow = 'hidden';
        
        // Add domain details header
        const domainDetailsHeader = document.createElement('div');
        domainDetailsHeader.className = 'domain-details-header';
        domainDetailsHeader.style.padding = '12px 15px';
        domainDetailsHeader.style.borderBottom = '1px solid var(--border-color)';
        domainDetailsHeader.style.backgroundColor = 'rgba(15, 23, 42, 0.5)';
        domainDetailsHeader.style.fontWeight = 'bold';
        domainDetailsHeader.innerHTML = '<i class="fas fa-server" style="margin-right: 8px;"></i> Domain Details';
        domainDetailsCard.appendChild(domainDetailsHeader);
        
        // Create domain details content
        const domainDetailsList = document.createElement('ul');
        domainDetailsList.className = 'domain-details-list';
        domainDetailsList.style.listStyle = 'none';
        domainDetailsList.style.padding = '0';
        domainDetailsList.style.margin = '0';
        
        // Add each info item
        infoItems.forEach(item => {
            const listItem = document.createElement('li');
            listItem.className = 'domain-info-item';
            listItem.style.display = 'flex';
            listItem.style.alignItems = 'center';
            listItem.style.padding = '12px 15px';
            listItem.style.borderBottom = '1px solid rgba(71, 85, 105, 0.2)';
            
            // Add hover effect
            listItem.addEventListener('mouseover', () => {
                listItem.style.backgroundColor = 'rgba(30, 41, 59, 0.3)';
            });
            listItem.addEventListener('mouseout', () => {
                listItem.style.backgroundColor = '';
            });
            
            // Icon part
            const iconDiv = document.createElement('div');
            iconDiv.className = 'info-icon';
            iconDiv.style.marginRight = '12px';
            iconDiv.style.width = '24px';
            iconDiv.style.height = '24px';
            iconDiv.style.display = 'flex';
            iconDiv.style.alignItems = 'center';
            iconDiv.style.justifyContent = 'center';
            
            const iconElement = document.createElement('i');
            iconElement.className = `fas ${item.icon}`;
            
            // Set icon color based on item properties
            if (item.isSecure) {
                iconElement.style.color = '#10b981'; // Green for secure items
            } else if (item.isSuspicious || item.isNew) {
                iconElement.style.color = '#f59e0b'; // Amber for suspicious or new items
            } else if (item.label === 'SSL Certificate' && item.value === 'Not found') {
                iconElement.style.color = '#ef4444'; // Red for missing SSL
            } else {
                iconElement.style.color = '#3b82f6'; // Default blue
            }
            
            iconDiv.appendChild(iconElement);
            listItem.appendChild(iconDiv);
            
            // Content part
            const contentDiv = document.createElement('div');
            contentDiv.className = 'info-content';
            contentDiv.style.flex = '1';
            
            // Label
            const labelDiv = document.createElement('div');
            labelDiv.className = 'info-label';
            labelDiv.style.fontSize = '0.85rem';
            labelDiv.style.color = 'var(--text-muted)';
            labelDiv.textContent = item.label;
            contentDiv.appendChild(labelDiv);
            
            // Value
            const valueDiv = document.createElement('div');
            valueDiv.className = 'info-value';
            valueDiv.style.fontWeight = '500';
            
            // Add visual indicators for certain values
            if (item.label === 'Protocol') {
                if (item.value === 'HTTPS') {
                    valueDiv.innerHTML = `<span style="color: #10b981;">${item.value}</span>`;
                } else {
                    valueDiv.innerHTML = `<span style="color: #ef4444;">${item.value}</span>`;
                }
            } else if (item.label === 'TLD Type' && item.isSuspicious) {
                valueDiv.innerHTML = `<span style="color: #f59e0b;">${item.value}</span> <span class="badge" style="background-color: #f59e0b; color: white; font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; margin-left: 5px;">SUSPICIOUS</span>`;
            } else if (item.label === 'Domain Age' && item.isNew) {
                valueDiv.innerHTML = `<span style="color: #f59e0b;">${item.value}</span>`;
            } else if (item.label === 'SSL Certificate') {
                if (item.value === 'Valid') {
                    valueDiv.innerHTML = `<span style="color: #10b981;">${item.value}</span>`;
                } else {
                    valueDiv.innerHTML = `<span style="color: #ef4444;">${item.value}</span>`;
                }
            } else {
                valueDiv.textContent = item.value;
            }
            
            contentDiv.appendChild(valueDiv);
            listItem.appendChild(contentDiv);
            
            domainDetailsList.appendChild(listItem);
        });
        
        // Append the list to the card and the card to the container
        domainDetailsCard.appendChild(domainDetailsList);
        domainInfoContainer.appendChild(domainDetailsCard);
    }
    
    // If there's no content at all, add a no-info message
    if (domainInfoContainer.childNodes.length === 0) {
        const noInfoMsg = document.createElement('div');
        noInfoMsg.className = 'no-domain-info';
        noInfoMsg.style.padding = '20px';
        noInfoMsg.style.textAlign = 'center';
        noInfoMsg.style.color = 'var(--text-muted)';
        noInfoMsg.style.backgroundColor = 'rgba(15, 23, 42, 0.3)';
        noInfoMsg.style.borderRadius = '10px';
        noInfoMsg.style.border = '1px solid var(--border-color)';
        noInfoMsg.innerHTML = '<i class="fas fa-info-circle" style="font-size: 24px; margin-bottom: 10px;"></i><br>No domain information available.';
        
        domainInfoContainer.appendChild(noInfoMsg);
    }
  }
  
  /**
   * Increases the section risk when IP address cannot be resolved
   * @param {Object} data - The analysis data to modify
   */
  function increaseIPResolutionRisk(data) {
    // Only proceed if we have section_totals
    if (!data.section_totals) {
      data.section_totals = {};
    }
    
    // Get the current domain information section risk or default to 0
    const currentDomainRisk = data.section_totals["Domain Information"] || 0;
    
    // Increase the risk by a significant amount (5-15% range)
    const additionalRisk = 7.5;
    data.section_totals["Domain Information"] = Math.min(100, currentDomainRisk + additionalRisk);
    
    // Also add to total Section Risk if it exists
    if (data.section_totals["Section Risk"] !== undefined) {
      const currentSectionRisk = data.section_totals["Section Risk"] || 0;
      data.section_totals["Section Risk"] = Math.min(100, currentSectionRisk + additionalRisk / 2);
    }
    
    // If there's a feature_contributions array, add or update the IP resolution entry
    if (data.feature_contributions && Array.isArray(data.feature_contributions)) {
      // Check if IP resolution feature already exists
      const ipFeatureIndex = data.feature_contributions.findIndex(
        f => (f.name || "").toLowerCase().includes("ip_resolution") || 
             (f.name || "").toLowerCase().includes("ip_address")
      );
      
      if (ipFeatureIndex >= 0) {
        // Update existing feature
        data.feature_contributions[ipFeatureIndex].value = "Could not resolve";
        data.feature_contributions[ipFeatureIndex].percentage = 
          (parseFloat(data.feature_contributions[ipFeatureIndex].percentage) || 0) + additionalRisk;
        data.feature_contributions[ipFeatureIndex].color_class = "danger";
      } else {
        // Add new feature
        data.feature_contributions.push({
          name: "IP Resolution",
          value: "Could not resolve",
          percentage: additionalRisk,
          color_class: "danger"
        });
      }
      
      // Sort by percentage (importance)
      data.feature_contributions.sort((a, b) => 
        parseFloat(b.percentage || 0) - parseFloat(a.percentage || 0));
    }
    
    // Update the overall score
    if (data.score !== undefined) {
      data.score = Math.min(100, data.score + additionalRisk / 3);
    }
  }
  
  /**
   * Initializes a map to show the geolocation of the domain
   * @param {string} containerId - The ID of the container element for the map
   * @param {Object} domainInfo - Domain information including location data
   * @param {boolean} hasExactCoords - Whether we have exact coordinates
   */
  function initMap(containerId, domainInfo, hasExactCoords) {
    // Default coordinates (center of world map)
    let lat = 0;
    let lng = 0;
    let zoom = 1;
    
    if (hasExactCoords) {
        // Use exact coordinates if available
        lat = parseFloat(domainInfo.latitude);
        lng = parseFloat(domainInfo.longitude);
        zoom = 10; // Zoom in more for exact location
    } else if (domainInfo.country) {
        // Use approximate country location
        const countryCenters = {
            'United States': [37.0902, -95.7129],
            'Russia': [61.5240, 105.3188],
            'China': [35.8617, 104.1954],
            'India': [20.5937, 78.9629],
            'Brazil': [-14.2350, -51.9253],
            'Australia': [-25.2744, 133.7751],
            'Canada': [56.1304, -106.3468],
            'Germany': [51.1657, 10.4515],
            'Japan': [36.2048, 138.2529],
            'United Kingdom': [55.3781, -3.4360],
            'France': [46.2276, 2.2137],
            'Italy': [41.8719, 12.5674],
            'South Korea': [35.9078, 127.7669],
            'Spain': [40.4637, -3.7492],
            'Mexico': [23.6345, -102.5528],
            'Indonesia': [-0.7893, 113.9213],
            'Netherlands': [52.1326, 5.2913],
            'Switzerland': [46.8182, 8.2275],
            'Saudi Arabia': [23.8859, 45.0792],
            'Turkey': [38.9637, 35.2433]
        };
        
        if (countryCenters[domainInfo.country]) {
            [lat, lng] = countryCenters[domainInfo.country];
            zoom = 4; // Country level zoom
        }
    }
    
    // Remove the IP address label above the map - we'll show it directly on the map
    const mapContainer = document.getElementById(containerId);
    
    // Check if the map library is available
    if (typeof L !== 'undefined') {
        try {
            // Initialize the map
            const map = L.map(containerId, {
                center: [lat, lng],
                zoom: zoom,
                zoomControl: true,
                attributionControl: true
            });
            
            // Add the tile layer (OpenStreetMap)
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
                maxZoom: 18
            }).addTo(map);
            
            // Add a marker if we have a location
            if (lat !== 0 || lng !== 0) {
                // Create a marker with a popup
                const marker = L.marker([lat, lng]).addTo(map);
                
                // Prepare popup content
                let popupContent = '<div style="text-align: center; padding: 5px;">';
                
                if (domainInfo.ip_address && domainInfo.ip_address !== 'Unknown') {
                    popupContent += `<strong>IP:</strong> ${domainInfo.ip_address}<br>`;
                }
                
                if (domainInfo.organization && domainInfo.organization !== 'Unknown') {
                    popupContent += `<strong>Organization:</strong> ${domainInfo.organization}<br>`;
                }
                
                if (domainInfo.city && domainInfo.city !== 'Unknown') {
                    popupContent += `<strong>City:</strong> ${domainInfo.city}<br>`;
                }
                
                if (domainInfo.country && domainInfo.country !== 'Unknown') {
                    popupContent += `<strong>Country:</strong> ${domainInfo.country}`;
                }
                
                popupContent += '</div>';
                
                // Add popup to marker
                marker.bindPopup(popupContent);
                
                // Open popup by default
                marker.openPopup();

                // Add a better label with the IP address directly on the map
                if (domainInfo.ip_address && domainInfo.ip_address !== 'Unknown') {
                    const customLabel = L.divIcon({
                        className: 'ip-address-map-label',
                        html: `<div style="background: rgba(15, 23, 42, 0.9); color: white; padding: 6px 10px; border-radius: 6px; font-size: 13px; font-weight: bold; white-space: nowrap; box-shadow: 0 2px 8px rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.2);">IP: ${domainInfo.ip_address}</div>`,
                        iconSize: [140, 30],
                        iconAnchor: [70, 35]
                    });
                    L.marker([lat, lng], { icon: customLabel }).addTo(map);
                }
            }
            
            // Force map to resize to container
            setTimeout(() => {
                map.invalidateSize();
            }, 100);
            
            // Remove any unused space by setting a fixed height
            mapContainer.style.height = '180px';
            mapContainer.style.marginBottom = '0';
            
        } catch (e) {
            console.error('Error creating map:', e);
            document.getElementById(containerId).innerHTML = 
                '<div style="padding: 10px; text-align: center; color: var(--text-muted);">' +
                '<i class="fas fa-map-marked-alt" style="font-size: 24px; margin-bottom: 10px;"></i><br>' +
                'Map data not available</div>';
        }
    } else {
        console.error('Leaflet library not available');
        document.getElementById(containerId).innerHTML = 
            '<div style="padding: 10px; text-align: center; color: var(--text-muted);">' +
            '<i class="fas fa-exclamation-circle" style="font-size: 24px; margin-bottom: 10px;"></i><br>' +
            'Map library not available</div>';
    }
  }
  
  /**
   * Displays suspicious patterns in the Suspicious Patterns section
   * @param {Object} data - The analysis data from the API
   */
  function displaySuspiciousPatterns(data) {
    const suspiciousPatternsContainer = document.getElementById('suspiciousPatterns');
    if (!suspiciousPatternsContainer) return;
    
    // Clear previous content
    suspiciousPatternsContainer.innerHTML = '';
    
    // Get patterns from data
    const patterns = data.suspicious_patterns || [];
    
    // When no patterns are found, the section risk should always be 0%
    // This will override whatever might be in the data
    let sectionRiskValue = patterns && patterns.length > 0 ? 
      (data.section_totals && data.section_totals["Suspicious Patterns"] || 0) : 0;
    
    // Create container
    const patternContainer = document.createElement('div');
    patternContainer.className = 'suspicious-patterns-container';
    
    const header = document.createElement('div');
    header.className = 'section-header';
    
    // Add icon and title
    const titleContainer = document.createElement('div');
    titleContainer.className = 'section-title-container';
    
    const icon = document.createElement('i');
    icon.className = 'fas fa-exclamation-triangle';
    icon.style.color = '#ff6b6b';
    icon.style.marginRight = '10px';
    
    const title = document.createElement('h3');
    title.className = 'section-title';
    title.textContent = 'Suspicious Patterns';
    
    titleContainer.appendChild(icon);
    titleContainer.appendChild(title);
    header.appendChild(titleContainer);
    patternContainer.appendChild(header);
    
    // Create content container
    const contentContainer = document.createElement('div');
    contentContainer.className = 'patterns-content';
    
    if (patterns && patterns.length > 0) {
      // Calculate total risk score from patterns
      const totalPatternRiskScore = patterns.reduce((total, pattern) => total + (pattern.risk_score || 0), 0);
      
      // Add risk overview section
      const riskOverviewSection = document.createElement('div');
      riskOverviewSection.className = 'risk-overview-section';
      riskOverviewSection.style.marginBottom = '20px';
      riskOverviewSection.style.padding = '15px';
      riskOverviewSection.style.backgroundColor = 'rgba(30, 41, 59, 0.3)';
      riskOverviewSection.style.borderRadius = '8px';
      riskOverviewSection.style.border = '1px solid rgba(79, 99, 135, 0.2)';
      
      riskOverviewSection.innerHTML = `
        <div style="display: flex; align-items: center; margin-bottom: 10px;">
            <i class="fas fa-chart-pie" style="color: #f59e0b; margin-right: 8px;"></i>
            <strong style="font-size: 1rem;">Risk Overview</strong>
        </div>
        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
            <span>Total patterns detected:</span>
            <strong>${patterns.length}</strong>
        </div>
        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
            <span>Combined pattern risk score:</span>
            <strong>${totalPatternRiskScore} points</strong>
        </div>
        <div style="display: flex; justify-content: space-between;">
            <span>Section risk contribution:</span>
            <strong style="color: #f59e0b;">${sectionRiskValue.toFixed(1)}%</strong>
        </div>
      `;
      
      contentContainer.appendChild(riskOverviewSection);
      
      // Sort patterns by severity
      patterns.sort((a, b) => {
        const severityOrder = { high: 0, medium: 1, low: 2 };
        return severityOrder[a.severity] - severityOrder[b.severity];
      });
      
      // Add count of patterns by severity
      const severityCounts = {
        high: patterns.filter(p => p.severity === 'high').length,
        medium: patterns.filter(p => p.severity === 'medium').length,
        low: patterns.filter(p => p.severity === 'low').length
      };
      
      // Only add severity badges if we have patterns with that severity
      const severityBadgesContainer = document.createElement('div');
      severityBadgesContainer.className = 'severity-badges';
      severityBadgesContainer.style.display = 'flex';
      severityBadgesContainer.style.marginBottom = '15px';
      
      if (severityCounts.high > 0) {
        severityBadgesContainer.appendChild(createSeverityBadge(severityCounts.high, 'high', 'High'));
      }
      
      if (severityCounts.medium > 0) {
        severityBadgesContainer.appendChild(createSeverityBadge(severityCounts.medium, 'medium', 'Medium'));
      }
      
      if (severityCounts.low > 0) {
        severityBadgesContainer.appendChild(createSeverityBadge(severityCounts.low, 'low', 'Low'));
      }
      
      contentContainer.appendChild(severityBadgesContainer);
      
      // Create patterns list with details for each pattern
      const patternsList = document.createElement('div');
      patternsList.className = 'patterns-list';
      
      patterns.forEach(pattern => {
        const patternItem = document.createElement('div');
        patternItem.className = `pattern-item ${getSeverityClass(pattern.severity)}`;
        patternItem.style.marginBottom = '12px';
        patternItem.style.padding = '15px';
        patternItem.style.borderRadius = '8px';
        patternItem.style.backgroundColor = 'rgba(30, 41, 59, 0.5)';
        patternItem.style.borderLeft = `4px solid ${pattern.severity === 'high' ? '#ff6b6b' : pattern.severity === 'medium' ? '#ffba08' : '#90be6d'}`;
        
        const patternHeader = document.createElement('div');
        patternHeader.className = 'pattern-header';
        patternHeader.style.display = 'flex';
        patternHeader.style.alignItems = 'center';
        patternHeader.style.justifyContent = 'space-between';
        
        const patternTitleWrapper = document.createElement('div');
        patternTitleWrapper.style.display = 'flex';
        patternTitleWrapper.style.alignItems = 'center';
        
        const patternIcon = document.createElement('i');
        patternIcon.className = pattern.severity === 'high' ? 'fas fa-exclamation-circle' : pattern.severity === 'medium' ? 'fas fa-exclamation' : 'fas fa-info-circle';
        patternIcon.style.marginRight = '8px';
        patternIcon.style.color = pattern.severity === 'high' ? '#ff6b6b' : pattern.severity === 'medium' ? '#ffba08' : '#90be6d';
        patternIcon.style.fontSize = '16px'; 
        
        const patternTitle = document.createElement('div');
        patternTitle.className = 'pattern-title';
        patternTitle.style.fontWeight = 'bold';
        patternTitle.style.fontSize = '1rem';
        patternTitle.textContent = pattern.pattern;
        
        patternTitleWrapper.appendChild(patternIcon);
        patternTitleWrapper.appendChild(patternTitle);
        
        // Add risk score badge
        const riskScoreBadge = document.createElement('div');
        riskScoreBadge.className = 'risk-score-badge';
        riskScoreBadge.style.backgroundColor = pattern.severity === 'high' ? 'rgba(239, 68, 68, 0.2)' : pattern.severity === 'medium' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(16, 185, 129, 0.2)';
        riskScoreBadge.style.color = pattern.severity === 'high' ? '#f87171' : pattern.severity === 'medium' ? '#fbbf24' : '#34d399';
        riskScoreBadge.style.fontWeight = 'bold';
        riskScoreBadge.style.padding = '4px 8px';
        riskScoreBadge.style.borderRadius = '12px';
        riskScoreBadge.style.fontSize = '0.8rem';
        riskScoreBadge.style.display = 'flex';
        riskScoreBadge.style.alignItems = 'center';
        riskScoreBadge.style.justifyContent = 'center';
        riskScoreBadge.innerHTML = `<i class="fas fa-exclamation-triangle" style="margin-right: 4px;"></i> ${pattern.risk_score || 0} points`;
        
        patternHeader.appendChild(patternTitleWrapper);
        patternHeader.appendChild(riskScoreBadge);
        
        // Only add the pattern item header (no description or technical details)
        patternItem.appendChild(patternHeader);
        patternsList.appendChild(patternItem);
      });
      
      contentContainer.appendChild(patternsList);
      
      // REMOVED: The duplicate section risk meter has been removed
    } else {
      // Display a message when no patterns are found with a green checkmark
      const safeContainer = document.createElement('div');
      safeContainer.className = 'safe-container';
      safeContainer.style.display = 'flex';
      safeContainer.style.flexDirection = 'column';
      safeContainer.style.alignItems = 'center';
      safeContainer.style.justifyContent = 'center';
      safeContainer.style.padding = '30px 20px';
      safeContainer.style.backgroundColor = 'rgba(15, 30, 50, 0.3)';
      safeContainer.style.borderRadius = '12px';
      safeContainer.style.textAlign = 'center';
      safeContainer.style.margin = '10px 0';
      
      // Large checkmark icon
      const checkIcon = document.createElement('div');
      checkIcon.innerHTML = '<i class="fas fa-check-circle" style="font-size: 48px; color: #10b981; margin-bottom: 15px;"></i>';
      
      // No patterns message
      const noPatternTitle = document.createElement('h4');
      noPatternTitle.textContent = 'No Suspicious Patterns Detected';
      noPatternTitle.style.fontSize = '1.2rem';
      noPatternTitle.style.fontWeight = '600';
      noPatternTitle.style.marginBottom = '10px';
      
      const noPatternMessage = document.createElement('p');
      noPatternMessage.textContent = 'This website does not contain any known suspicious patterns or risky behaviors.';
      noPatternMessage.style.opacity = '0.8';
      noPatternMessage.style.fontSize = '0.95rem';
      noPatternMessage.style.maxWidth = '380px';
      noPatternMessage.style.lineHeight = '1.6';
      
      safeContainer.appendChild(checkIcon);
      safeContainer.appendChild(noPatternTitle);
      safeContainer.appendChild(noPatternMessage);
      
      contentContainer.appendChild(safeContainer);
    }
    
    patternContainer.appendChild(contentContainer);
    suspiciousPatternsContainer.appendChild(patternContainer);
  }
  
  /**
   * Displays feature details in the Feature Details section
   * @param {Object} data - The analysis data from the API
   */
  function displayFeatureDetails(data) {
    const featureDetailsContainer = document.getElementById('featureDetails');
    if (!featureDetailsContainer) {
      console.error("Feature details container not found with ID 'featureDetails'");
      return;
    }
    
    featureDetailsContainer.innerHTML = '';
    
    console.log("Displaying feature details from data:", data);

    let features = [];
    
    // Try to get features from feature_table (primary source)
    if (data.feature_table && Array.isArray(data.feature_table)) {
        console.log("Found feature_table:", data.feature_table);
        features = data.feature_table;
    }
    // Fallback to feature_contributions if available
    else if (data.feature_contributions && Array.isArray(data.feature_contributions)) {
        console.log("Using feature_contributions as fallback:", data.feature_contributions);
        features = data.feature_contributions.map(f => ({
            feature: f.name || f.feature_name,
            value: f.value,
            impact: f.percentage || 0,
            color_class: f.color_class || 'success'
        }));
    }
    // Fallback to feature_values as last resort
    else if (data.feature_values && typeof data.feature_values === 'object') {
        console.log("Using feature_values as fallback:", data.feature_values);
        features = Object.entries(data.feature_values).map(([key, value]) => ({
            feature: key,
            value: value,
            impact: 0,
            color_class: 'success'
        }));
    }

    // Clear any existing description headers (to prevent duplication)
    const existingDescHeaders = document.querySelectorAll('.feature-description-header');
    existingDescHeaders.forEach(header => header.remove());

    // Create a description header with improved explanation
    const descriptionHeader = document.createElement('div');
    descriptionHeader.className = 'feature-description-header';
    descriptionHeader.style.marginBottom = '25px';
    descriptionHeader.style.fontSize = '0.95rem';
    descriptionHeader.style.color = 'var(--text-color)';
    descriptionHeader.style.display = 'flex';
    descriptionHeader.style.alignItems = 'flex-start';
    descriptionHeader.style.gap = '15px';
    descriptionHeader.style.backgroundColor = 'rgba(15, 30, 50, 0.4)';
    descriptionHeader.style.padding = '18px 20px';
    descriptionHeader.style.borderRadius = '12px';
    descriptionHeader.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.1)';
    descriptionHeader.style.border = '1px solid rgba(79, 99, 135, 0.2)';
    
    const infoIcon = document.createElement('i');
    infoIcon.className = 'fas fa-info-circle';
    infoIcon.style.color = '#60a5fa';
    infoIcon.style.marginTop = '3px';
    infoIcon.style.fontSize = '20px';
    
    const infoText = document.createElement('div');
    infoText.style.flex = '1';
    infoText.style.lineHeight = '1.6';
    infoText.innerHTML = `
        These are the URL and domain features analyzed to determine the risk score. 
        Each feature contributes differently to the overall risk assessment and is categorized into one of three sections:
        <ul style="margin-top: 10px; margin-bottom: 0; padding-left: 20px;">
            <li><strong style="color: #60a5fa;">Key Risk Factors (AI Predict):</strong> Core URL and domain characteristics (40% of score)</li>
            <li><strong style="color: #10b981;">Domain Information:</strong> Registration and hosting details (10% of score)</li>
            <li><strong style="color: #f59e0b;">Suspicious Patterns:</strong> Security issues and content analysis (50% of score)</li>
        </ul>
    `;
    
    descriptionHeader.appendChild(infoIcon);
    descriptionHeader.appendChild(infoText);
    
    // Insert the description at the beginning of the main section-content container
    const sectionContent = featureDetailsContainer.closest('.section-content');
    if (sectionContent) {
        sectionContent.insertBefore(descriptionHeader, sectionContent.firstChild);
    }

    // Create explanations for common features
    const featureExplanations = {
        // Key Risk Factors
        "https_present": "Websites without HTTPS are insecure and allow data interception. Phishing sites often lack proper encryption.",
        "domain_length": "Unusually long domain names may be trying to impersonate legitimate sites or hide suspicious elements.",
        "domain_entropy": "Higher entropy (randomness) in domain names is associated with algorithmically generated phishing domains.",
        "special_characters": "An abnormal number of special characters is commonly seen in deceptive URLs trying to confuse users.",
        "tld_score": "Certain top-level domains are more commonly associated with malicious websites due to lower registration restrictions.",
        "url_length": "Excessively long URLs often attempt to hide the true destination or include suspicious parameters.",
        "subdomain_count": "Multiple subdomains can be used to make a URL appear legitimate while hiding the actual domain.",
        "numeric_path": "Paths consisting only of numbers are uncommon in legitimate websites and may indicate an automated attack.",
        "digit_percentage": "High percentage of digits in a URL is unusual and often associated with malicious sites.",
        "keyword_count": "Presence of terms like 'login', 'verify', 'account' may indicate phishing attempts.",
        "path_length": "Unusually long URL paths can be used to hide malicious destinations.",
        "query_length": "Excessively long query parameters may contain obfuscated malicious code.",
        "fragment_length": "Long URL fragments (#) may be used to evade security scanning.",
        
        // Domain Information
        "ip_resolution": "Domains that can't be resolved to an IP address may be newly registered for phishing or no longer active.",
        "rep_domain_age_category": "Newly registered domains have a higher likelihood of being used for malicious purposes.",
        "whois_recently_registered": "Domains registered in the past 30 days have a higher risk of being used for fraud.",
        "geo_suspicious_country": "Some countries have higher rates of hosting malicious websites due to lax cybercrime enforcement.",
        "ct_suspicious_cert_pattern": "Certificate Transparency logs show suspicious certificate issuance patterns for this domain.",
        "ip_blacklisted": "The IP address hosting this domain is on known malware or spam blacklists.",
        "domain_blacklisted": "This domain appears on reputation blacklists for previous malicious activity.",
        
        // Content Features
        "favicon_present": "Legitimate sites typically have a favicon (site icon). Phishing sites often neglect this detail.",
        "content_form_count": "Multiple forms may indicate attempts to collect sensitive information.",
        "content_password_field_count": "Password fields on unexpected pages may indicate credential harvesting.",
        "content_external_resources_count": "High numbers of external resources can indicate content loaded from malicious sources.",
        "content_js_to_html_ratio": "Excessive JavaScript relative to HTML content may indicate obfuscation techniques.",
        "content_title_brand_mismatch": "Mismatch between page title and domain name is common in impersonation attempts.",
        "content_similar_domain_redirect": "Redirects to similar but different domains may indicate a bait-and-switch attack.",
        "html_security_score": "Overall security analysis of the HTML content, including forms, scripts, and iframe usage.",
        "html_risk_factor_count": "Number of suspicious elements detected in the HTML content.",
        "html_has_password_field": "Presence of password fields may indicate an attempt to steal credentials.",
        "html_has_obfuscated_js": "Obfuscated JavaScript is often used to hide malicious code from detection."
    };

    if (features.length > 0) {
        // Sort features by impact
        features.sort((a, b) => Math.abs(b.impact || 0) - Math.abs(a.impact || 0));
        
        // Create feature categories
        const featureCategories = {
            url: ['url_length', 'path_length', 'query_length', 'fragment_length', 'special_char_count', 'numeric_path'],
            domain: ['domain_length', 'domain_entropy', 'subdomain_count', 'tld_score', 'ip_url'],
            security: ['https_present', 'ssl_valid', 'hsts_present'],
            content: ['keyword_count', 'digit_percentage', 'letter_percentage', 'suspicious_keywords']
        };
        
        // Create a direct display (non-accordion) for each category
        const createCategorySection = (title, icon, features, accentColor) => {
            if (features.length === 0) return null;
            
            const sectionContainer = document.createElement('div');
            sectionContainer.className = 'feature-category-section';
            sectionContainer.style.marginBottom = '30px';
            sectionContainer.style.backgroundColor = 'rgba(15, 30, 50, 0.3)';
            sectionContainer.style.borderRadius = '12px';
            sectionContainer.style.overflow = 'hidden';
            sectionContainer.style.boxShadow = '0 4px 15px rgba(0, 0, 0, 0.1)';
            sectionContainer.style.border = '1px solid rgba(79, 99, 135, 0.15)';
            
            // Create header
            const headerEl = document.createElement('div');
            headerEl.className = 'category-header';
            headerEl.style.padding = '16px 20px';
            headerEl.style.backgroundColor = 'rgba(15, 30, 50, 0.6)';
            headerEl.style.borderBottom = `1px solid rgba(79, 99, 135, 0.2)`;
            headerEl.style.display = 'flex';
            headerEl.style.alignItems = 'center';
            headerEl.style.gap = '12px';
            
            const iconEl = document.createElement('i');
            iconEl.className = `fas ${icon}`;
            iconEl.style.width = '24px';
            iconEl.style.height = '24px';
            iconEl.style.display = 'flex';
            iconEl.style.alignItems = 'center';
            iconEl.style.justifyContent = 'center';
            iconEl.style.color = accentColor;
            iconEl.style.fontSize = '16px';
            
            const titleEl = document.createElement('span');
            titleEl.style.fontWeight = '600';
            titleEl.style.fontSize = '1.05rem';
            titleEl.textContent = title;
            
            const countEl = document.createElement('span');
            countEl.style.fontSize = '0.85rem';
            countEl.style.backgroundColor = 'rgba(79, 99, 135, 0.3)';
            countEl.style.color = '#e2e8f0';
            countEl.style.padding = '3px 8px';
            countEl.style.borderRadius = '12px';
            countEl.style.marginLeft = '8px';
            countEl.textContent = `${features.length}`;
            
            headerEl.appendChild(iconEl);
            headerEl.appendChild(titleEl);
            headerEl.appendChild(countEl);
            
            // Create content container
            const contentEl = document.createElement('div');
            contentEl.className = 'category-content';
            contentEl.style.padding = '5px';
            
            // Create table for features
            const tableEl = document.createElement('table');
            tableEl.className = 'feature-table';
            tableEl.style.width = '100%';
            tableEl.style.borderCollapse = 'collapse';
            tableEl.style.margin = '0';
            
            // Add header row
            const theadEl = document.createElement('thead');
            const headerRowEl = document.createElement('tr');
            
            // Check if this is the Content Features section
            const isContentFeatures = title === 'Content Features';
            
            // Define headers based on section type
            const headers = isContentFeatures 
                ? ['Feature', 'Why It Matters'] 
                : ['Feature', 'Value', 'Impact on Risk', 'Why It Matters'];
            
            headers.forEach((headerText, index) => {
                const th = document.createElement('th');
                th.style.padding = '14px 16px';
                th.style.textAlign = 'left';
                th.style.color = '#94a3b8';
                th.style.fontSize = '0.85rem';
                th.style.fontWeight = '600';
                th.style.letterSpacing = '0.025em';
                th.style.textTransform = 'uppercase';
                th.style.borderBottom = '1px solid rgba(79, 99, 135, 0.15)';
                th.textContent = headerText;
                
                // Set column widths
                if (isContentFeatures) {
                    // For Content Features section with only 2 columns
                    if (index === 0) {
                        th.style.width = '25%';
                    } else {
                        th.style.width = '75%';
                    }
                } else {
                    // For other sections with 4 columns
                    if (index === 0) {
                        th.style.width = '18%';
                    } else if (index === 1) {
                        th.style.width = '10%';
                    } else if (index === 2) {
                        th.style.width = '15%';
                    } else {
                        th.style.width = '57%';
                    }
                }
                
                headerRowEl.appendChild(th);
            });
            
            theadEl.appendChild(headerRowEl);
            tableEl.appendChild(theadEl);
            
            // Add body rows
            const tbodyEl = document.createElement('tbody');
            
            features.forEach((feature, index) => {
                const row = document.createElement('tr');
                row.style.transition = 'background-color 0.2s ease, transform 0.1s ease';
                row.style.backgroundColor = index % 2 === 0 ? 'rgba(30, 41, 59, 0.2)' : 'transparent';
                
                // Add hover effect
                row.addEventListener('mouseover', () => {
                    row.style.backgroundColor = 'rgba(51, 65, 85, 0.4)';
                    row.style.transform = 'translateX(3px)';
                });
                row.addEventListener('mouseout', () => {
                    row.style.backgroundColor = index % 2 === 0 ? 'rgba(30, 41, 59, 0.2)' : 'transparent';
                    row.style.transform = 'translateX(0)';
                });
                
                // Feature name cell
                const nameCell = document.createElement('td');
                nameCell.style.padding = '12px 16px';
                nameCell.style.borderBottom = '1px solid rgba(79, 99, 135, 0.1)';
                nameCell.style.fontSize = '0.9rem';
                
                const nameContent = document.createElement('div');
                nameContent.style.display = 'flex';
                nameContent.style.alignItems = 'center';
                nameContent.style.gap = '10px';
                
                // Add feature icon based on category
                const featureIconEl = document.createElement('div');
                featureIconEl.style.width = '28px';
                featureIconEl.style.height = '28px';
                featureIconEl.style.minWidth = '28px';
                featureIconEl.style.borderRadius = '6px';
                featureIconEl.style.display = 'flex';
                featureIconEl.style.alignItems = 'center';
                featureIconEl.style.justifyContent = 'center';
                
                const iconI = document.createElement('i');
                
                if (title === 'URL Features') {
                    featureIconEl.style.backgroundColor = 'rgba(59, 130, 246, 0.15)';
                    iconI.className = 'fas fa-link';
                    iconI.style.color = '#60a5fa';
                } else if (title === 'Domain Features') {
                    featureIconEl.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
                    iconI.className = 'fas fa-globe';
                    iconI.style.color = '#10b981';
                } else if (title === 'Security Features') {
                    featureIconEl.style.backgroundColor = 'rgba(245, 158, 11, 0.15)';
                    iconI.className = 'fas fa-shield-alt';
                    iconI.style.color = '#f59e0b';
    } else {
                    featureIconEl.style.backgroundColor = 'rgba(139, 92, 246, 0.15)';
                    iconI.className = 'fas fa-file-alt';
                    iconI.style.color = '#8b5cf6';
                }
                
                featureIconEl.appendChild(iconI);
                
                const nameTextEl = document.createElement('span');
                nameTextEl.style.fontWeight = '500';
                nameTextEl.textContent = formatFeatureName(feature.feature);
                
                nameContent.appendChild(featureIconEl);
                nameContent.appendChild(nameTextEl);
                nameCell.appendChild(nameContent);
                row.appendChild(nameCell);
                
                // Only add Value and Impact on Risk columns for non-Content Features sections
                if (!isContentFeatures) {
                    // Feature value cell
                    const valueCell = document.createElement('td');
                    valueCell.style.padding = '12px 16px';
                    valueCell.style.borderBottom = '1px solid rgba(79, 99, 135, 0.1)';
                    valueCell.style.fontSize = '0.9rem';
                    
                    // Format value based on feature type
                    let formattedValue = feature.value;
                    const featureName = feature.feature.toLowerCase();
                    
                    if (featureName.includes('present') || featureName.includes('valid') || featureName === 'ip_url') {
                        // Boolean features - show Yes/No
                        const boolValue = parseFloat(feature.value) > 0;
                        formattedValue = boolValue ? 'Yes' : 'No';
                        
                        const valueSpan = document.createElement('span');
                        valueSpan.style.padding = '3px 8px';
                        valueSpan.style.borderRadius = '4px';
                        valueSpan.style.fontSize = '0.85rem';
                        valueSpan.style.fontWeight = '500';
                        
                        if ((featureName.includes('present') || featureName.includes('valid')) && !boolValue) {
                            // Missing security feature - show as risky
                            valueSpan.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
                            valueSpan.style.color = '#f87171';
                        } else if (featureName === 'ip_url' && boolValue) {
                            // IP as URL is risky
                            valueSpan.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
                            valueSpan.style.color = '#f87171';
                        } else {
                            // Normal state
                            valueSpan.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
                            valueSpan.style.color = '#34d399';
                        }
                        
                        valueSpan.textContent = formattedValue;
                        valueCell.appendChild(valueSpan);
                    } else if (featureName.includes('percentage')) {
                        // Percentage values
                        const percentValue = parseFloat(feature.value);
                        formattedValue = percentValue.toFixed(1) + '%';
                        valueCell.textContent = formattedValue;
                    } else if (featureName === 'tld_score') {
                        // TLD score is 0-1
                        const tldValue = parseFloat(feature.value);
                        
                        const tldSpan = document.createElement('span');
                        tldSpan.style.padding = '2px 6px';
                        tldSpan.style.borderRadius = '4px';
                        tldSpan.style.fontSize = '0.85rem';
                        
                        // Color based on TLD risk
                        if (tldValue > 0.6) {
                            tldSpan.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
                            tldSpan.style.color = '#f87171';
                        } else if (tldValue > 0.3) {
                            tldSpan.style.backgroundColor = 'rgba(245, 158, 11, 0.15)';
                            tldSpan.style.color = '#fbbf24';
                        } else {
                            tldSpan.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
                            tldSpan.style.color = '#34d399';
                        }
                        
                        tldSpan.textContent = tldValue.toFixed(2);
                        valueCell.appendChild(tldSpan);
                    } else if (featureName === 'domain_entropy') {
                        // Domain entropy (higher is riskier)
                        const entropyValue = parseFloat(feature.value);
                        
                        const entropySpan = document.createElement('span');
                        entropySpan.style.padding = '2px 6px';
                        entropySpan.style.borderRadius = '4px';
                        entropySpan.style.fontSize = '0.85rem';
                        
                        // Color based on entropy value
                        if (entropyValue > 4) {
                            entropySpan.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
                            entropySpan.style.color = '#f87171';
                        } else if (entropyValue > 3) {
                            entropySpan.style.backgroundColor = 'rgba(245, 158, 11, 0.15)';
                            entropySpan.style.color = '#fbbf24';
                        } else {
                            entropySpan.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
                            entropySpan.style.color = '#34d399';
                        }
                        
                        entropySpan.textContent = entropyValue.toFixed(2);
                        valueCell.appendChild(entropySpan);
                    } else {
                        // Default formatting
                        valueCell.textContent = formattedValue;
                    }
                    
                    row.appendChild(valueCell);
                    
                    // Feature impact cell
                    const impactCell = document.createElement('td');
                    impactCell.style.padding = '12px 16px';
                    impactCell.style.borderBottom = '1px solid rgba(79, 99, 135, 0.1)';
                    
                    const impact = parseFloat(feature.impact || 0);
                    
                    if (!isNaN(impact) && impact > 0) {
                        // Create impact container
                        const impactContainer = document.createElement('div');
                        impactContainer.style.display = 'flex';
                        impactContainer.style.alignItems = 'center';
                        impactContainer.style.gap = '10px';
                        
                        // Create impact value
                        const impactValueEl = document.createElement('div');
                        impactValueEl.style.minWidth = '45px';
                        impactValueEl.style.fontWeight = '600';
                        impactValueEl.style.fontSize = '0.9rem';
                        impactValueEl.style.padding = '2px 6px';
                        impactValueEl.style.borderRadius = '4px';
                        impactValueEl.style.textAlign = 'center';
                        
                        // Set color based on impact
                        let colorClass = feature.color_class || 'success';
                        if (impact > 60) {
                            colorClass = 'danger';
                            impactValueEl.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
                            impactValueEl.style.color = '#f87171';
                        } else if (impact > 20) {
                            colorClass = 'warning';
                            impactValueEl.style.backgroundColor = 'rgba(245, 158, 11, 0.15)';
                            impactValueEl.style.color = '#fbbf24';
                        } else {
                            impactValueEl.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
                            impactValueEl.style.color = '#34d399';
                        }
                        
                        impactValueEl.textContent = `${impact.toFixed(1)}%`;
                        
                        // Create impact bar container
                        const barContainerEl = document.createElement('div');
                        barContainerEl.style.flex = '1';
                        barContainerEl.style.height = '8px';
                        barContainerEl.style.backgroundColor = 'rgba(30, 41, 59, 0.5)';
                        barContainerEl.style.borderRadius = '4px';
                        barContainerEl.style.overflow = 'hidden';
                        barContainerEl.style.position = 'relative';
                        barContainerEl.style.cursor = 'pointer';
                        
                        // Create impact bar
                        const barEl = document.createElement('div');
                        barEl.style.height = '100%';
                        barEl.style.width = `${Math.min(impact * 1.5, 100)}%`;
                        barEl.style.borderRadius = '4px';
                        barEl.style.transition = 'width 1s cubic-bezier(0.34, 1.56, 0.64, 1), filter 0.3s ease';
                        
                        // Set bar color with gradient
                        if (colorClass === 'danger') {
                            barEl.style.background = 'linear-gradient(90deg, #ef4444, #b91c1c)';
                            barEl.style.boxShadow = '0 0 8px rgba(239, 68, 68, 0.3)';
                        } else if (colorClass === 'warning') {
                            barEl.style.background = 'linear-gradient(90deg, #f59e0b, #d97706)';
                            barEl.style.boxShadow = '0 0 8px rgba(245, 158, 11, 0.3)';
                        } else {
                            barEl.style.background = 'linear-gradient(90deg, #10b981, #059669)';
                            barEl.style.boxShadow = '0 0 8px rgba(16, 185, 129, 0.3)';
                        }
                        
                        // Create tooltip for additional impact information
                        const tooltip = document.createElement('div');
                        tooltip.style.position = 'absolute';
                        tooltip.style.bottom = '100%';
                        tooltip.style.left = '50%';
                        tooltip.style.transform = 'translateX(-50%)';
                        tooltip.style.backgroundColor = 'rgba(15, 23, 42, 0.95)';
                        tooltip.style.color = '#f8fafc';
                        tooltip.style.padding = '8px 12px';
                        tooltip.style.borderRadius = '6px';
                        tooltip.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.3)';
                        tooltip.style.fontSize = '0.85rem';
                        tooltip.style.whiteSpace = 'nowrap';
                        tooltip.style.zIndex = '10';
                        tooltip.style.marginBottom = '8px';
                        tooltip.style.border = '1px solid rgba(79, 99, 135, 0.3)';
                        tooltip.style.display = 'none';
                        tooltip.style.textAlign = 'center';
                        tooltip.style.backdropFilter = 'blur(4px)';
                        
                        const featureName = formatFeatureName(feature.feature);
                        let riskLevel = 'Low';
                        if (impact > 60) riskLevel = 'High';
                        else if (impact > 20) riskLevel = 'Medium';
                        
                        tooltip.innerHTML = `
                            <div style="font-weight: 600; margin-bottom: 4px;">${featureName}</div>
                            <div>Impact: <span style="font-weight: 600;">${impact.toFixed(1)}%</span></div>
                            <div>Risk Level: <span style="font-weight: 600; color: ${colorClass === 'danger' ? '#f87171' : colorClass === 'warning' ? '#fbbf24' : '#34d399'}">${riskLevel}</span></div>
                        `;
                        
                        // Add arrow to tooltip
                        const tooltipArrow = document.createElement('div');
                        tooltipArrow.style.position = 'absolute';
                        tooltipArrow.style.bottom = '-5px';
                        tooltipArrow.style.left = '50%';
                        tooltipArrow.style.transform = 'translateX(-50%) rotate(45deg)';
                        tooltipArrow.style.width = '10px';
                        tooltipArrow.style.height = '10px';
                        tooltipArrow.style.backgroundColor = 'rgba(15, 23, 42, 0.95)';
                        tooltipArrow.style.borderRight = '1px solid rgba(79, 99, 135, 0.3)';
                        tooltipArrow.style.borderBottom = '1px solid rgba(79, 99, 135, 0.3)';
                        tooltip.appendChild(tooltipArrow);
                        
                        // Toggle tooltip on hover
                        barContainerEl.addEventListener('mouseover', () => {
                            tooltip.style.display = 'block';
                            barEl.style.filter = 'brightness(1.2)';
                        });
                        
                        barContainerEl.addEventListener('mouseout', () => {
                            tooltip.style.display = 'none';
                            barEl.style.filter = 'brightness(1)';
                        });
                        
                        barContainerEl.appendChild(barEl);
                        barContainerEl.appendChild(tooltip);
                        
                        // Ensure proper assembly of elements
                        impactContainer.appendChild(impactValueEl);
                        impactContainer.appendChild(barContainerEl);
                        
                        impactCell.appendChild(impactContainer);
                    } else {
                        // No impact data - create empty bar instead of just text
                        const impactContainer = document.createElement('div');
                        impactContainer.style.display = 'flex';
                        impactContainer.style.alignItems = 'center';
                        impactContainer.style.gap = '10px';
                        
                        // Create impact value with "No impact" label
                        const impactValueEl = document.createElement('div');
                        impactValueEl.style.minWidth = '70px';
                        impactValueEl.style.fontSize = '0.85rem';
                        impactValueEl.style.padding = '2px 6px';
                        impactValueEl.style.borderRadius = '4px';
                        impactValueEl.style.backgroundColor = 'rgba(100, 116, 139, 0.2)';
                        impactValueEl.style.color = '#94a3b8';
                        impactValueEl.style.textAlign = 'center';
                        impactValueEl.textContent = 'No impact';
                        
                        // Create empty bar container
                        const barContainerEl = document.createElement('div');
                        barContainerEl.style.flex = '1';
                        barContainerEl.style.height = '8px';
                        barContainerEl.style.backgroundColor = 'rgba(30, 41, 59, 0.5)';
                        barContainerEl.style.borderRadius = '4px';
                        barContainerEl.style.overflow = 'hidden';
                        
                        impactContainer.appendChild(impactValueEl);
                        impactContainer.appendChild(barContainerEl);
                        
                        impactCell.appendChild(impactContainer);
                    }
                    
                    row.appendChild(impactCell);
                }
                
                // Add explanation cell
                const explanationCell = document.createElement('td');
                explanationCell.style.padding = '12px 16px';
                explanationCell.style.borderBottom = '1px solid rgba(79, 99, 135, 0.1)';
                explanationCell.style.fontSize = '0.85rem';
                explanationCell.style.lineHeight = '1.5';
                explanationCell.style.color = '#e2e8f0';
                
                // For Content Features, make the explanation cell larger
                if (isContentFeatures) {
                    explanationCell.style.fontSize = '0.9rem';
                    explanationCell.style.lineHeight = '1.6';
                }
                
                // Get explanation for this feature
                let featureKey = feature.feature.toLowerCase();
                let explanation = '';
                
                // Look for exact match first
                if (featureExplanations[featureKey]) {
                    explanation = featureExplanations[featureKey];
                } else {
                    // Look for partial matches in the keys
                    for (const [key, value] of Object.entries(featureExplanations)) {
                        if (featureKey.includes(key) || key.includes(featureKey)) {
                            explanation = value;
                            break;
                        }
                    }
                    
                    // If still no match, provide generic explanations based on feature name
                    if (!explanation) {
                        if (featureKey.includes('https') || featureKey.includes('ssl') || featureKey.includes('security')) {
                            explanation = "Security features help protect user data. Missing security features indicate higher risk.";
                        } else if (featureKey.includes('domain')) {
                            explanation = "Domain characteristics can indicate potential phishing or deception attempts.";
                        } else if (featureKey.includes('content') || featureKey.includes('html')) {
                            explanation = "Website content analysis can reveal suspicious elements used in phishing pages.";
                        } else {
                            explanation = "This feature is analyzed as part of the machine learning model's risk assessment.";
                        }
                    }
                }
                
                // Highlight key terms in the explanation
                const highlightTerms = ["phishing", "malicious", "suspicious", "risk", "fraud", "deceptive", "insecure"];
                let highlightedExplanation = explanation;
                
                highlightTerms.forEach(term => {
                    const regex = new RegExp(`\\b${term}\\b`, 'gi');
                    highlightedExplanation = highlightedExplanation.replace(
                        regex, 
                        `<span style="color: #fcd34d; font-weight: 500;">$&</span>`
                    );
                });
                
                explanationCell.innerHTML = highlightedExplanation;
                row.appendChild(explanationCell);
                
                tbodyEl.appendChild(row);
            });
            
            tableEl.appendChild(tbodyEl);
            contentEl.appendChild(tableEl);
            
            sectionContainer.appendChild(headerEl);
            sectionContainer.appendChild(contentEl);
            
            return sectionContainer;
        };
        
        // Categorize features
        const categorizedFeatures = {
            url: [],
            domain: [],
            security: [],
            content: []
        };
        
        features.forEach(feature => {
            const featureName = feature.feature.toLowerCase();
            
            // Check which category this feature belongs to
            for (const [category, featureList] of Object.entries(featureCategories)) {
                if (featureList.some(f => featureName.includes(f))) {
                    categorizedFeatures[category].push(feature);
                    return;
                }
            }
            
            // Default to content category if not found
            categorizedFeatures.content.push(feature);
        });
        
        // Create sections for each category with specific accent colors
        const urlSection = createCategorySection('URL Features', 'fa-link', categorizedFeatures.url, '#60a5fa');
        const domainSection = createCategorySection('Domain Features', 'fa-globe', categorizedFeatures.domain, '#10b981');
        const securitySection = createCategorySection('Security Features', 'fa-shield-alt', categorizedFeatures.security, '#f59e0b');
        const contentSection = createCategorySection('Content Features', 'fa-file-alt', categorizedFeatures.content, '#8b5cf6');
        
        // Add animation style for staggered appearance
        const animationStyle = document.createElement('style');
        animationStyle.textContent = `
            @keyframes featureSectionFadeIn {
                from {
                    opacity: 0;
                    transform: translateY(15px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
        `;
        document.head.appendChild(animationStyle);
        
        // Add sections to container with staggered animations
        if (urlSection) {
            urlSection.style.animation = 'featureSectionFadeIn 0.5s cubic-bezier(0.4, 0, 0.2, 1) forwards';
            featureDetailsContainer.appendChild(urlSection);
        }
        
        if (domainSection) {
            domainSection.style.animation = 'featureSectionFadeIn 0.5s cubic-bezier(0.4, 0, 0.2, 1) 0.1s forwards';
            domainSection.style.opacity = '0';
            featureDetailsContainer.appendChild(domainSection);
        }
        
        if (securitySection) {
            securitySection.style.animation = 'featureSectionFadeIn 0.5s cubic-bezier(0.4, 0, 0.2, 1) 0.2s forwards';
            securitySection.style.opacity = '0';
            featureDetailsContainer.appendChild(securitySection);
        }
        
        if (contentSection) {
            contentSection.style.animation = 'featureSectionFadeIn 0.5s cubic-bezier(0.4, 0, 0.2, 1) 0.3s forwards';
            contentSection.style.opacity = '0';
            featureDetailsContainer.appendChild(contentSection);
        }
    } else {
        // Add a message if no features found
        const noFeaturesEl = document.createElement('div');
        noFeaturesEl.style.padding = '40px 20px';
        noFeaturesEl.style.textAlign = 'center';
        noFeaturesEl.style.color = '#94a3b8';
        noFeaturesEl.style.backgroundColor = 'rgba(15, 30, 50, 0.3)';
        noFeaturesEl.style.borderRadius = '12px';
        noFeaturesEl.style.border = '1px solid rgba(79, 99, 135, 0.15)';
        noFeaturesEl.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.1)';
        
        const icon = document.createElement('i');
        icon.className = 'fas fa-info-circle';
        icon.style.fontSize = '32px';
        icon.style.marginBottom = '15px';
        icon.style.color = '#60a5fa';
        
        const text = document.createElement('div');
        text.textContent = 'No feature details available for this analysis.';
        text.style.fontSize = '1rem';
        
        noFeaturesEl.appendChild(icon);
        noFeaturesEl.appendChild(text);
        
        featureDetailsContainer.appendChild(noFeaturesEl);
    }
  }
  
  /**
   * Displays HTML security information in the Content Security Analysis section
   * @param {Object} data - The analysis data from the API
   */
  function displayHtmlSecurity(data) {
    const securityRisksContainer = document.getElementById('htmlSecurityRisks');
    const securityChecksContainer = document.getElementById('htmlSecurityChecks');
    const securityScoreElement = document.getElementById('htmlSecurityScore');
    const scoreCircle = document.getElementById('htmlSecurityScoreCircle');
    
    if (!securityRisksContainer || !securityChecksContainer || !securityScoreElement || !scoreCircle) {
      console.error("HTML Security containers not found");
      return;
    }
    
    securityRisksContainer.innerHTML = '';
    securityChecksContainer.innerHTML = '';
    
    // Remove any existing info notes to avoid duplication
    const securityContentContainer = securityScoreElement.closest('.security-analysis-content');
    if (securityContentContainer) {
      const existingInfoNotes = securityContentContainer.querySelectorAll('.content-security-info-note');
      existingInfoNotes.forEach(note => note.remove());
    }
    
    // Add modern informational card about this section
    const infoNote = document.createElement('div');
    infoNote.className = 'content-security-info-note info-note';
    infoNote.style.fontSize = '0.9rem';
    infoNote.style.color = '#cbd5e1';
    infoNote.style.marginTop = '15px';
    infoNote.style.marginBottom = '20px';
    infoNote.style.padding = '12px 16px';
    infoNote.style.backgroundColor = 'rgba(30, 41, 59, 0.4)';
    infoNote.style.borderRadius = '10px';
    infoNote.style.border = '1px solid rgba(71, 85, 105, 0.2)';
    infoNote.style.display = 'flex';
    infoNote.style.alignItems = 'center';
    infoNote.style.gap = '10px';
    infoNote.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.08)';
    infoNote.style.animation = 'fadeIn 0.5s ease-out';
    
    // Create info icon
    const infoIcon = document.createElement('div');
    infoIcon.style.display = 'flex';
    infoIcon.style.alignItems = 'center';
    infoIcon.style.justifyContent = 'center';
    infoIcon.style.width = '32px';
    infoIcon.style.height = '32px';
    infoIcon.style.borderRadius = '50%';
    infoIcon.style.backgroundColor = 'rgba(59, 130, 246, 0.2)';
    infoIcon.style.color = '#60a5fa';
    infoIcon.style.flexShrink = '0';
    infoIcon.innerHTML = '<i class="fas fa-info" style="font-size: 14px;"></i>';
    
    const infoText = document.createElement('div');
    infoText.style.flexGrow = '1';
    infoText.style.lineHeight = '1.5';
    infoText.textContent = 'This analysis examines the website\'s HTML content for security issues. This is shown for informational purposes only and is not included in the overall risk score.';
    
    infoNote.appendChild(infoIcon);
    infoNote.appendChild(infoText);
    
    // Insert the info note after the score display
    if (securityContentContainer) {
      securityContentContainer.insertBefore(infoNote, securityContentContainer.children[1]);
    }
    
    // Case 1: HTML security data is not available
    if (!data.html_security) {
      const noDataContainer = document.createElement('div');
      noDataContainer.className = 'no-data-container';
      noDataContainer.style.textAlign = 'center';
      noDataContainer.style.padding = '25px 20px';
      noDataContainer.style.backgroundColor = 'rgba(15, 23, 42, 0.3)';
      noDataContainer.style.borderRadius = '12px';
      noDataContainer.style.margin = '15px 0';
      
      const noDataIcon = document.createElement('div');
      noDataIcon.innerHTML = '<i class="fas fa-database-slash" style="font-size: 42px; color: #64748b; margin-bottom: 15px;"></i>';
      
      const noDataTitle = document.createElement('h4');
      noDataTitle.textContent = 'No Content Analysis Available';
      noDataTitle.style.fontSize = '1.1rem';
      noDataTitle.style.fontWeight = '600';
      noDataTitle.style.marginBottom = '8px';
      
      const noDataText = document.createElement('p');
      noDataText.textContent = 'The system was unable to analyze the website content.';
      noDataText.style.fontSize = '0.9rem';
      noDataText.style.opacity = '0.8';
      
      noDataContainer.appendChild(noDataIcon);
      noDataContainer.appendChild(noDataTitle);
      noDataContainer.appendChild(noDataText);
      
      securityRisksContainer.appendChild(noDataContainer);
      
      // Set default score
      securityScoreElement.textContent = "N/A";
      scoreCircle.className = 'score-circle';
      return;
    }
    
    // Case 2: HTML security analysis encountered an error
    if (data.html_security.risk_factors && data.html_security.risk_factors.length > 0 && 
        data.html_security.risk_factors[0].includes("Error analyzing content")) {
      
      // Display error message with better styling
      const errorContainer = document.createElement('div');
      errorContainer.className = 'error-container';
      errorContainer.style.display = 'flex';
      errorContainer.style.padding = '16px';
      errorContainer.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
      errorContainer.style.borderRadius = '10px';
      errorContainer.style.borderLeft = '4px solid #ef4444';
      errorContainer.style.margin = '10px 0';
      errorContainer.style.alignItems = 'flex-start';
      errorContainer.style.gap = '12px';
      
      const errorIcon = document.createElement('div');
      errorIcon.className = 'error-icon';
      errorIcon.innerHTML = '<i class="fas fa-exclamation-triangle" style="color: #ef4444; font-size: 20px;"></i>';
      
      const errorContent = document.createElement('div');
      errorContent.className = 'error-content';
      errorContent.style.flexGrow = '1';
      
      const errorTitle = document.createElement('div');
      errorTitle.className = 'error-title';
      errorTitle.textContent = 'Content Analysis Error';
      errorTitle.style.fontWeight = '600';
      errorTitle.style.marginBottom = '4px';
      errorTitle.style.fontSize = '1rem';
      
      const errorDetails = document.createElement('div');
      errorDetails.className = 'error-details';
      errorDetails.textContent = data.html_security.risk_factors[0];
      errorDetails.style.fontSize = '0.9rem';
      errorDetails.style.opacity = '0.9';
      errorDetails.style.lineHeight = '1.5';
      
      errorContent.appendChild(errorTitle);
      errorContent.appendChild(errorDetails);
      
      errorContainer.appendChild(errorIcon);
      errorContainer.appendChild(errorContent);
      
      securityRisksContainer.appendChild(errorContainer);
      
      // Update score to reflect the error risk
      const errorScore = data.html_security.content_score || 25;
      securityScoreElement.textContent = errorScore;
      
      // Update the progress circle
      updateScoreCircle(errorScore);
      return;
    }
    
    // Case 3: Normal operation - Update the score
    const contentScore = data.html_security.content_score || 0;
    securityScoreElement.textContent = contentScore;
    
    // Update the progress circle
    updateScoreCircle(contentScore);
    
    // Display risk factors with improved styles
    const riskFactors = data.html_security.risk_factors || [];
    if (riskFactors.length === 0) {
      // Create a nice "no issues found" card
      const safeContainer = document.createElement('div');
      safeContainer.className = 'safe-container';
      safeContainer.style.display = 'flex';
      safeContainer.style.flexDirection = 'column';
      safeContainer.style.alignItems = 'center';
      safeContainer.style.justifyContent = 'center';
      safeContainer.style.padding = '30px 20px';
      safeContainer.style.backgroundColor = 'rgba(16, 185, 129, 0.1)';
      safeContainer.style.borderRadius = '12px';
      safeContainer.style.textAlign = 'center';
      safeContainer.style.margin = '15px 0';
      safeContainer.style.border = '1px solid rgba(16, 185, 129, 0.3)';
      safeContainer.style.animation = 'fadeIn 0.6s ease-out';
      
      const checkIcon = document.createElement('div');
      checkIcon.innerHTML = '<i class="fas fa-shield-check" style="font-size: 48px; color: #10b981; margin-bottom: 15px;"></i>';
      
      const safeTitle = document.createElement('h4');
      safeTitle.textContent = 'No Content Security Issues Detected';
      safeTitle.style.fontSize = '1.2rem';
      safeTitle.style.fontWeight = '600';
      safeTitle.style.marginBottom = '10px';
      
      const safeDescription = document.createElement('p');
      safeDescription.textContent = 'The website\'s HTML content appears to be safe with no suspicious elements found.';
      safeDescription.style.fontSize = '0.95rem';
      safeDescription.style.maxWidth = '380px';
      safeDescription.style.lineHeight = '1.6';
      safeDescription.style.opacity = '0.9';
      
      safeContainer.appendChild(checkIcon);
      safeContainer.appendChild(safeTitle);
      safeContainer.appendChild(safeDescription);
      
      securityRisksContainer.appendChild(safeContainer);
    } else {
      // Create a styled container for risk factors
      const riskFactorsListContainer = document.createElement('div');
      riskFactorsListContainer.className = 'risk-factors-list';
      riskFactorsListContainer.style.animation = 'fadeIn 0.6s ease-out';
      
      riskFactors.forEach((risk, index) => {
        const riskItem = document.createElement('div');
        riskItem.className = 'risk-item';
        riskItem.style.backgroundColor = 'rgba(30, 41, 59, 0.4)';
        riskItem.style.borderRadius = '10px';
        riskItem.style.padding = '16px';
        riskItem.style.marginBottom = '12px';
        riskItem.style.display = 'flex';
        riskItem.style.alignItems = 'flex-start';
        riskItem.style.gap = '14px';
        riskItem.style.transition = 'transform 0.2s ease';
        riskItem.style.cursor = 'default';
        riskItem.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.05)';
        riskItem.style.animation = `fadeIn 0.${6 + index}s ease-out`;
        
        // Add hover effect
        riskItem.onmouseover = function() {
          this.style.transform = 'translateY(-2px)';
          this.style.boxShadow = '0 8px 16px rgba(0, 0, 0, 0.08)';
        };
        riskItem.onmouseout = function() {
          this.style.transform = 'translateY(0)';
          this.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.05)';
        };
        
        // Determine severity based on content
        const isHighSeverity = risk.toLowerCase().includes("password") || 
                               risk.toLowerCase().includes("form") || 
                               risk.toLowerCase().includes("insecure") || 
                               index === 0;
                               
        const isMediumSeverity = risk.toLowerCase().includes("script") || 
                                risk.toLowerCase().includes("obfuscated") || 
                                risk.toLowerCase().includes("iframe") || 
                                risk.toLowerCase().includes("external");
        
        let severityColor, severityIconClass, severityIconBg;
        
        if (isHighSeverity) {
          severityColor = '#ef4444';
          severityIconClass = 'fa-exclamation-circle';
          severityIconBg = 'rgba(239, 68, 68, 0.2)';
          riskItem.style.borderLeft = '4px solid #ef4444';
        } else if (isMediumSeverity) {
          severityColor = '#f59e0b';
          severityIconClass = 'fa-exclamation';
          severityIconBg = 'rgba(245, 158, 11, 0.2)';
          riskItem.style.borderLeft = '4px solid #f59e0b';
        } else {
          severityColor = '#3b82f6';
          severityIconClass = 'fa-info-circle';
          severityIconBg = 'rgba(59, 130, 246, 0.2)';
          riskItem.style.borderLeft = '4px solid #3b82f6';
        }
        
        // Create icon container
        const iconContainer = document.createElement('div');
        iconContainer.className = 'risk-icon';
        iconContainer.style.width = '36px';
        iconContainer.style.height = '36px';
        iconContainer.style.borderRadius = '50%';
        iconContainer.style.backgroundColor = severityIconBg;
        iconContainer.style.display = 'flex';
        iconContainer.style.alignItems = 'center';
        iconContainer.style.justifyContent = 'center';
        iconContainer.style.flexShrink = '0';
        iconContainer.innerHTML = `<i class="fas ${severityIconClass}" style="color: ${severityColor}; font-size: 16px;"></i>`;
        
        // Create content container
        const contentContainer = document.createElement('div');
        contentContainer.className = 'risk-content';
        contentContainer.style.flexGrow = '1';
        
        // Create risk type label
        const riskTypeLabel = document.createElement('div');
        riskTypeLabel.className = 'risk-type';
        riskTypeLabel.textContent = isHighSeverity ? 'High Risk Factor' : isMediumSeverity ? 'Medium Risk Factor' : 'Low Risk Factor';
        riskTypeLabel.style.fontSize = '0.8rem';
        riskTypeLabel.style.color = severityColor;
        riskTypeLabel.style.fontWeight = '600';
        riskTypeLabel.style.marginBottom = '6px';
        riskTypeLabel.style.textTransform = 'uppercase';
        riskTypeLabel.style.letterSpacing = '0.03em';
        
        // Create risk description
        const riskDescription = document.createElement('div');
        riskDescription.className = 'risk-description';
        riskDescription.textContent = risk;
        riskDescription.style.fontSize = '0.95rem';
        riskDescription.style.lineHeight = '1.5';
        
        // Assemble the components
        contentContainer.appendChild(riskTypeLabel);
        contentContainer.appendChild(riskDescription);
        
        riskItem.appendChild(iconContainer);
        riskItem.appendChild(contentContainer);
        
        riskFactorsListContainer.appendChild(riskItem);
      });
      
      securityRisksContainer.appendChild(riskFactorsListContainer);
    }
    
    // Add a style tag for animations
    const styleTag = document.createElement('style');
    styleTag.textContent = `
      @keyframes fadeIn {
        from { opacity: 0; transform: translateY(8px); }
        to { opacity: 1; transform: translateY(0); }
      }
      @keyframes slideIn {
        from { opacity: 0; transform: translateX(-10px); }
        to { opacity: 1; transform: translateX(0); }
      }
    `;
    document.head.appendChild(styleTag);
    
    // Display security checks with improved styles
    const securityChecks = data.html_security.security_checks || [];
    
    // Create a container for security checks
    const checksContainer = document.createElement('div');
    checksContainer.className = 'security-checks-container';
    checksContainer.style.display = 'flex';
    checksContainer.style.flexDirection = 'column';
    checksContainer.style.gap = '10px';
    checksContainer.style.marginTop = '10px';
    
    if (securityChecks.length > 0) {
      securityChecks.forEach((check, index) => {
        const checkItem = document.createElement('div');
        checkItem.className = 'security-check-item';
        checkItem.style.display = 'flex';
        checkItem.style.alignItems = 'center';
        checkItem.style.gap = '12px';
        checkItem.style.padding = '10px 12px';
        checkItem.style.backgroundColor = 'rgba(16, 185, 129, 0.1)';
        checkItem.style.borderRadius = '8px';
        checkItem.style.animation = `slideIn 0.${4 + index}s ease-out`;
        
        const checkIcon = document.createElement('div');
        checkIcon.className = 'check-icon';
        checkIcon.style.width = '28px';
        checkIcon.style.height = '28px';
        checkIcon.style.borderRadius = '50%';
        checkIcon.style.backgroundColor = 'rgba(16, 185, 129, 0.2)';
        checkIcon.style.display = 'flex';
        checkIcon.style.alignItems = 'center';
        checkIcon.style.justifyContent = 'center';
        checkIcon.style.flexShrink = '0';
        checkIcon.innerHTML = '<i class="fas fa-check" style="color: #10b981; font-size: 14px;"></i>';
        
        const checkText = document.createElement('div');
        checkText.className = 'check-text';
        checkText.textContent = check;
        checkText.style.fontSize = '0.9rem';
        checkText.style.lineHeight = '1.4';
        
        checkItem.appendChild(checkIcon);
        checkItem.appendChild(checkText);
        
        checksContainer.appendChild(checkItem);
      });
    } else {
      const noChecksItem = document.createElement('div');
      noChecksItem.className = 'no-checks-item';
      noChecksItem.style.display = 'flex';
      noChecksItem.style.alignItems = 'center';
      noChecksItem.style.gap = '12px';
      noChecksItem.style.padding = '12px 14px';
      noChecksItem.style.backgroundColor = 'rgba(71, 85, 105, 0.2)';
      noChecksItem.style.borderRadius = '8px';
      noChecksItem.style.animation = 'slideIn 0.4s ease-out';
      
      const infoIcon = document.createElement('div');
      infoIcon.className = 'info-icon';
      infoIcon.style.width = '28px';
      infoIcon.style.height = '28px';
      infoIcon.style.borderRadius = '50%';
      infoIcon.style.backgroundColor = 'rgba(71, 85, 105, 0.2)';
      infoIcon.style.display = 'flex';
      infoIcon.style.alignItems = 'center';
      infoIcon.style.justifyContent = 'center';
      infoIcon.style.flexShrink = '0';
      infoIcon.innerHTML = '<i class="fas fa-info" style="color: #94a3b8; font-size: 14px;"></i>';
      
      const infoText = document.createElement('div');
      infoText.className = 'info-text';
      infoText.textContent = 'No specific security checks passed';
      infoText.style.fontSize = '0.9rem';
      infoText.style.color = '#cbd5e1';
      
      noChecksItem.appendChild(infoIcon);
      noChecksItem.appendChild(infoText);
      
      checksContainer.appendChild(noChecksItem);
    }
    
    securityChecksContainer.appendChild(checksContainer);
  }
  
  /**
   * Updates the score circle visualization for HTML security analysis
   * @param {number} score - The content risk score
   */
  function updateScoreCircle(score) {
    const circle = document.getElementById('htmlSecurityScoreCircle');
    if (!circle) return;
    
    // Ensure the progress value is properly set
    const progressValue = score + '%';
    
    // Define risk level
    if (score < 30) {
      circle.className = 'score-circle low-risk';
      circle.style.setProperty('--progress', progressValue);
      circle.style.setProperty('--color', 'var(--success-color)');
    } else if (score < 70) {
      circle.className = 'score-circle medium-risk';
      circle.style.setProperty('--progress', progressValue);
      circle.style.setProperty('--color', 'var(--warning-color)');
    } else {
      circle.className = 'score-circle high-risk';
      circle.style.setProperty('--progress', progressValue);
      circle.style.setProperty('--color', 'var(--danger-color)');
    }
    
    // Force reflow to ensure the animation takes effect
    void circle.offsetWidth;
    
    // Make sure the score text is set and visible
    const scoreText = document.getElementById('htmlSecurityScore');
    if (scoreText) {
      scoreText.textContent = score;
      scoreText.style.visibility = 'visible';
    }
  }
  
  /**
   * Displays all results from the analysis
   * @param {Object} data - The analysis data from the API
   */
  function displayAllResults(data) {
    console.log("Received data for display:", data);
    
    // Validate data before attempting to display
    if (!data || typeof data !== 'object') {
      console.error("Invalid data object received:", data);
      throw new Error("Invalid or missing data object");
    }
    
    // Show the results section
    const resultsSection = document.getElementById('results');
    if (resultsSection) {
    resultsSection.style.display = 'block';
    } else {
      console.error("Results section not found with ID 'results'");
    }
    
    // Ensure we have the necessary data structures to prevent errors
    data.domain_info = data.domain_info || {};
    data.suspicious_patterns = data.suspicious_patterns || [];
    data.html_security = data.html_security || {};
    data.section_totals = data.section_totals || {};
    data.feature_table = data.feature_table || [];
    data.feature_contributions = data.feature_contributions || [];
    
    // Check for unresolvable IP before displaying results
    const domainInfo = data.domain_info;
    const ipNotResolved = !domainInfo.ip_address || 
                         domainInfo.ip_address === 'Unknown' || 
                         domainInfo.ip_address === 'Could not resolve';
    
    if (ipNotResolved) {
      try {
        increaseIPResolutionRisk(data);
      } catch (error) {
        console.error("Error adjusting IP resolution risk:", error);
      }
    }
    
    // Calculate section scores and update the overall score first
    try {
      displaySectionRiskMeters(data);
    } catch (error) {
      console.error("Error displaying section risk meters:", error);
    }
    
    // Display all components with error handling for each section
    try {
    displayRiskFactors(data);
    } catch (error) {
      console.error("Error displaying risk factors:", error);
    }
    
    try {
    displayDomainInfo(data);
    } catch (error) {
      console.error("Error displaying domain info:", error);
    }
    
    try {
    displaySuspiciousPatterns(data);
    } catch (error) {
      console.error("Error displaying suspicious patterns:", error);
    }
    
    try {
      displayFeatureDetails(data);
    } catch (error) {
      console.error("Error displaying feature details:", error);
    }
    
    try {
      displayHtmlSecurity(data);
    } catch (error) {
      console.error("Error displaying HTML security:", error);
    }
    
    // Update the result URL
    const resultUrlElement = document.getElementById('resultUrl');
    if (resultUrlElement && data.url) {
      resultUrlElement.textContent = data.url;
    }
    
    // Scroll to results
    if (resultsSection) {
    resultsSection.scrollIntoView({ behavior: 'smooth' });
    }
  }
  
  /**
   * Displays section risk meters based on section totals
   * @param {Object} data - The analysis data from the API
   */
  function displaySectionRiskMeters(data) {
    // Get section totals from the data
    const sectionTotals = data.section_totals || {};
    
    // Get section scores
    const keyRiskScore = sectionTotals["Key Risk Factors (AI Predict)"] || sectionTotals["Key Risk Factors"] || 0;
    const domainInfoScore = sectionTotals["Domain Information"] || 0;
    
    // Check if there are any suspicious patterns
    const hasPatterns = data.suspicious_patterns && data.suspicious_patterns.length > 0;
    
    // Force suspicious patterns score to 0 if no patterns were detected
    const suspiciousPatternsScore = hasPatterns ? 
      (sectionTotals["Suspicious Patterns"] || 0) : 0;
    
    // Calculate the total risk from all sections
    const totalRisk = keyRiskScore + domainInfoScore + suspiciousPatternsScore;
    
    // Update the overall fraud risk score to be the sum of the three sections
    data.score = totalRisk;
    
    console.log("Section scores:", {
      keyRiskScore,
      domainInfoScore,
      suspiciousPatternsScore,
      hasPatterns,
      totalRisk
    });
    
    // Display each section's risk contribution
    updateSectionRiskMeter('keyRiskFactors', keyRiskScore, totalRisk);
    updateSectionRiskMeter('domainInfo', domainInfoScore, totalRisk);
    updateSectionRiskMeter('suspiciousPatterns', suspiciousPatternsScore, totalRisk);
    
    // Update the overall score display with the new calculated total
    const riskScoreElement = document.getElementById('riskScore');
    if (riskScoreElement) {
      riskScoreElement.textContent = Math.round(totalRisk) + '%';
      
      // Update risk level
      const riskTagElement = document.getElementById('riskTag');
      let riskClass, riskText;
      
      if (totalRisk < 30) {
        riskClass = 'risk-low';
        riskText = 'Low Risk';
      } else if (totalRisk < 60) {
        riskClass = 'risk-medium';
        riskText = 'Medium Risk';
      } else {
        riskClass = 'risk-high';
        riskText = 'High Risk';
      }
      
      if (riskTagElement) {
        riskTagElement.textContent = riskText;
        riskTagElement.className = `risk-tag ${riskClass}`;
      }
      
      // Update score display container
      const scoreDisplayContainer = document.getElementById('scoreDisplayContainer');
      if (scoreDisplayContainer) {
        scoreDisplayContainer.className = `score-display ${riskClass}`;
      }
      
      // Update meter
      const scoreMeter = document.getElementById('scoreMeter');
      const meterLabel = document.getElementById('meterLabel');
      
      if (scoreMeter) {
        scoreMeter.style.width = `${totalRisk}%`;
        scoreMeter.className = `meter-fill ${totalRisk < 30 ? 'low' : totalRisk < 60 ? 'medium' : 'high'}`;
      }
      
      if (meterLabel) {
        meterLabel.textContent = `${Math.round(totalRisk)}%`;
      }
    }
    
    // Add an explanation about the risk score breakdown
    const resultsSummary = document.querySelector('.results-summary');
    if (resultsSummary) {
      // Remove any existing risk breakdown explanation
      const existingExplanation = resultsSummary.querySelector('.risk-breakdown-explanation');
      if (existingExplanation) {
        resultsSummary.removeChild(existingExplanation);
      }
      
      const breakdownExplanation = document.createElement('div');
      breakdownExplanation.className = 'risk-breakdown-explanation';
      breakdownExplanation.style.fontSize = '0.9rem';
      breakdownExplanation.style.backgroundColor = 'rgba(15, 23, 42, 0.3)';
      breakdownExplanation.style.borderRadius = '8px';
      breakdownExplanation.style.padding = '12px 16px';
      breakdownExplanation.style.marginTop = '20px';
      breakdownExplanation.style.color = '#cbd5e1';
      breakdownExplanation.style.lineHeight = '1.6';
      
      // Create table-like display for the calculation
      breakdownExplanation.innerHTML = `
        <div style="display: flex; align-items: center; margin-bottom: 10px;">
          <i class="fas fa-calculator" style="color: #60a5fa; margin-right: 8px; font-size: 14px;"></i>
          <strong style="color: #f8fafc; font-size: 0.95rem;">Fraud Risk Score Calculation</strong>
        </div>
        <div style="display: flex; flex-direction: column; gap: 4px;">
          <div style="display: flex; justify-content: space-between;">
            <span style="color: #60a5fa;">URL Features (Key Risk Factors):</span>
            <span style="font-weight: 500;">${keyRiskScore.toFixed(1)}%</span>
          </div>
          <div style="display: flex; justify-content: space-between;">
            <span style="color: #10b981;">Domain Information:</span>
            <span style="font-weight: 500;">${domainInfoScore.toFixed(1)}%</span>
          </div>
          <div style="display: flex; justify-content: space-between;">
            <span style="color: #f59e0b;">Suspicious Patterns:</span>
            <span style="font-weight: 500;">${suspiciousPatternsScore.toFixed(1)}%</span>
          </div>
        </div>
      `;
      
      // Add a divider and total
      const totalSection = document.createElement('div');
      totalSection.style.borderTop = '1px solid rgba(100, 116, 139, 0.3)';
      totalSection.style.marginTop = '10px';
      totalSection.style.paddingTop = '10px';
      totalSection.style.display = 'flex';
      totalSection.style.justifyContent = 'space-between';
      totalSection.style.fontWeight = '600';
      
      totalSection.innerHTML = `
        <span>Total Fraud Risk Score:</span>
        <span style="color: #f8fafc;">${totalRisk.toFixed(1)}%</span>
      `;
      
      breakdownExplanation.appendChild(totalSection);
      
      // Find any existing explanation and replace it
      resultsSummary.appendChild(breakdownExplanation);
    }
  }
  
  /**
   * Updates a section risk meter with the provided score
   * @param {string} sectionId - Base ID of the section
   * @param {number} sectionScore - Score for the section
   * @param {number} totalScore - Total risk score
   */
  function updateSectionRiskMeter(sectionId, sectionScore, totalScore) {
    const scoreElement = document.getElementById(`${sectionId}Score`);
    const meterElement = document.getElementById(`${sectionId}Meter`);
    
    if (scoreElement && meterElement) {
      // Round to one decimal place
      const roundedScore = Math.round(sectionScore * 10) / 10;
      
      // Update the score text
      scoreElement.textContent = `${roundedScore}%`;
      
      // Update the meter width
      meterElement.style.width = `${roundedScore}%`;
      
      // Determine and set color based on contribution to total risk
      let colorClass = 'low';
      
      // Calculate relative contribution
      const contribution = totalScore > 0 ? (sectionScore / totalScore) * 100 : 0;
      
      if (contribution >= 50) {
        colorClass = 'high';
      } else if (contribution >= 25) {
        colorClass = 'medium';
      }
      
      // Set color class
      meterElement.className = `section-meter-fill ${colorClass}`;
    }
  }
  
  // Helper functions
  function formatFeatureName(name) {
    if (!name) return 'Unknown Feature';
    
    // Special case for Https Present
    if (name === 'https_present' || name === 'Https Present') {
      return 'Security Weights';
    }
    
    return name
        .replace(/_/g, ' ')
        .replace(/\b\w/g, l => l.toUpperCase());
  }

  function getSeverityClass(severity) {
    const severityLower = String(severity).toLowerCase();
    if (severityLower === 'high') return 'high-severity';
    if (severityLower === 'medium') return 'medium-severity';
    return 'low-severity';
  }

  function capitalizeFirstLetter(string) {
    return string.charAt(0).toUpperCase() + string.slice(1).toLowerCase();
  }

  /**
   * Gets risk level text based on a numeric score
   * @param {number} score - Risk score (0-100)
   * @returns {string} - Risk level text (low, medium, high)
   */
  function get_risk_level(score) {
    const numericScore = parseFloat(score);
    if (isNaN(numericScore)) return "unknown";
    
    if (numericScore < 30) {
      return "low";
    } else if (numericScore < 60) {
      return "medium";
    } else {
      return "high";
    }
  }

  function extractDomainFromData(data) {
    // Try to get domain from various possible locations
    if (data.domain) return data.domain;
    if (data.url) {
        try {
            const url = new URL(data.url);
            return url.hostname;
        } catch (e) {
            return data.url;
        }
    }
    if (data.domain_info && data.domain_info.name) return data.domain_info.name;
    
    return 'Unknown Domain';
  }

  function extractProtocolFromData(data) {
    // Try to get protocol from URL
    if (data.url) {
        try {
            const url = new URL(data.url);
            return url.protocol.replace(':', '');
        } catch (e) {
            return data.url.startsWith('https') ? 'https' : 'http';
        }
    }
    
    // Default to unknown
    return 'Unknown';
  }

  function updateScoreDisplay(score) {
    const scoreElement = document.getElementById('risk-score');
    if (!scoreElement) {
        console.error("Risk score element not found!");
        return;
    }
    
    // Ensure score is a number and within valid range
        const numericScore = parseFloat(score);
    if (isNaN(numericScore)) {
        scoreElement.textContent = 'N/A';
        return;
    }
    
    // Normalize to 0-100 if it's a decimal
    const normalizedScore = numericScore <= 1 
        ? Math.round(numericScore * 100) 
        : Math.round(numericScore);
    
    // Update score text
    scoreElement.textContent = normalizedScore + '%';
    
    // Update color and risk level
    let riskClass, riskText;
    if (normalizedScore < 30) {
        riskClass = 'risk-low';
        riskText = 'Low Risk';
    } else if (normalizedScore < 60) {
        riskClass = 'risk-medium';
        riskText = 'Medium Risk';
    } else {
        riskClass = 'risk-high';
        riskText = 'High Risk';
    }
    
    // Update score element class
    scoreElement.className = `risk-score ${riskClass}`;
    
    // Update risk level text
            const riskLevelElement = document.getElementById('risk-level');
            if (riskLevelElement) {
        riskLevelElement.textContent = riskText;
        riskLevelElement.className = `risk-label ${riskClass}`;
    }
    
    // Update score display container
    const scoreDisplayElement = document.getElementById('score-display');
    if (scoreDisplayElement) {
        scoreDisplayElement.className = `score-display ${riskClass}`;
    }
    
    // Update progress bar if it exists
    const progressBarElement = document.getElementById('score-progress-bar');
    if (progressBarElement) {
        progressBarElement.style.width = `${normalizedScore}%`;
        
        // Update color class
        if (normalizedScore < 30) {
            progressBarElement.style.background = 'var(--success-color)';
        } else if (normalizedScore < 60) {
            progressBarElement.style.background = 'linear-gradient(90deg, var(--warning-color), #f97316)';
        } else {
            progressBarElement.style.background = 'var(--danger-color)';
        }
    }
    
    // Update progress label
    const progressLabelElement = document.getElementById('score-progress-label');
    if (progressLabelElement) {
        progressLabelElement.textContent = `${normalizedScore}%`;
    }
  }
  
  /**
   * Creates a severity badge for suspicious patterns
   * @param {number} count - Number of patterns with this severity
   * @param {string} severity - Severity level ('high', 'medium', 'low')
   * @param {string} label - Display label
   * @returns {HTMLElement} - Badge element
   */
  function createSeverityBadge(count, severity, label) {
    const badge = document.createElement('div');
    badge.className = `severity-badge ${severity}`;
    badge.style.padding = '5px 10px';
    badge.style.borderRadius = '12px';
    badge.style.marginRight = '8px';
    badge.style.display = 'flex';
    badge.style.alignItems = 'center';
    badge.style.justifyContent = 'center';
    badge.style.fontSize = '0.85rem';
    badge.style.fontWeight = 'bold';
    
    const colors = {
      high: {
        bg: 'rgba(239, 68, 68, 0.15)',
        text: '#f87171',
        icon: 'fa-exclamation-circle'
      },
      medium: {
        bg: 'rgba(245, 158, 11, 0.15)',
        text: '#fbbf24',
        icon: 'fa-exclamation-triangle'
      },
      low: {
        bg: 'rgba(16, 185, 129, 0.15)',
        text: '#34d399',
        icon: 'fa-info-circle'
      }
    };
    
    badge.style.backgroundColor = colors[severity].bg;
    badge.style.color = colors[severity].text;
    
    // Add icon instead of any text that could be interpreted as an X
    const icon = document.createElement('i');
    icon.className = `fas ${colors[severity].icon}`;
    icon.style.marginRight = '5px';
    icon.style.fontSize = '0.9rem';
    
    const countSpan = document.createElement('span');
    countSpan.textContent = `${count} ${label}`;
    
    badge.appendChild(icon);
    badge.appendChild(countSpan);
    
    return badge;
  }
  
  // Public API
  return {
    displayAllResults,
    displayRiskFactors,
    displayDomainInfo,
    displaySuspiciousPatterns,
    displayFeatureDetails,
    displayHtmlSecurity,
    increaseIPResolutionRisk
  };
})();

// Make display functions globally available
window.displayResults = displayResults.displayAllResults;
window.displayAllResults = displayResults.displayAllResults;

// Export displayResults object for ES module import
if (typeof module !== 'undefined' && module.exports) {
  module.exports = displayResults;
}