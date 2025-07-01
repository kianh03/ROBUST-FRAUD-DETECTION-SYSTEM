/**
 * Initializes a map to display geolocation data for IP addresses
 * @param {string} elementId - The ID of the element to display the map in
 * @param {Object} geoData - The geolocation data (latitude, longitude, country, etc.)
 * @param {boolean} showPopup - Whether to show a popup on the map
 */
function initMap(elementId, geoData, showPopup = true) {
    // Default to a global view if no coordinates
    let lat = 0;
    let lng = 0;
    let zoom = 1;
    let hasCoordinates = false;
    
    // Check if we have valid coordinates
    if (geoData && geoData.latitude && geoData.longitude &&
        !isNaN(parseFloat(geoData.latitude)) && !isNaN(parseFloat(geoData.longitude))) {
        lat = parseFloat(geoData.latitude);
        lng = parseFloat(geoData.longitude);
        zoom = 5;
        hasCoordinates = true;
    } else if (geoData && geoData.country) {
        // If we have a country but no coordinates, we can approximate
        const countryCoords = getCountryCoordinates(geoData.country);
        if (countryCoords) {
            lat = countryCoords.lat;
            lng = countryCoords.lng;
            zoom = 4;
            hasCoordinates = true;
        }
    }
    
    // Initialize the map
    const map = L.map(elementId, {
        center: [lat, lng],
        zoom: zoom,
        zoomControl: true,
        scrollWheelZoom: false,
        attributionControl: false
    });
    
    // Add dark-themed map tiles
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 20
    }).addTo(map);
    
    // Get or create info for display
    const ip = geoData.ip_address || 'Unknown IP';
    const country = geoData.country || 'Unknown Country';
    const city = geoData.city && geoData.city !== 'Unknown' ? geoData.city : '';
    const location = city ? `${city}, ${country}` : country;
    const org = geoData.organization || '';
    
    // Use a custom marker for better visibility
    if (hasCoordinates) {
        // Create custom icon with IP address
        const customIcon = L.divIcon({
            className: 'custom-ip-marker',
            html: `<div class="ip-marker">
                    <div class="ip-marker-content">
                        <span class="ip-text">${ip}</span>
                        <span class="location-text">${location}</span>
                    </div>
                   </div>`,
            iconSize: [250, 80],
            iconAnchor: [125, 80]
        });
        
        // Add marker with custom icon
        const marker = L.marker([lat, lng], { icon: customIcon }).addTo(map);
        
        // Add detailed popup if requested
        if (showPopup) {
            const popupContent = `
                <div class="map-popup">
                    <div class="popup-header">Server Information</div>
                    <div class="popup-row"><strong>IP:</strong> ${ip}</div>
                    <div class="popup-row"><strong>Location:</strong> ${location}</div>
                    ${org ? `<div class="popup-row"><strong>Organization:</strong> ${org}</div>` : ''}
                </div>
            `;
            marker.bindPopup(popupContent, {
                closeButton: true,
                className: 'custom-popup'
            });
        }
        
        // Add ripple effect animation
        const rippleMarker = L.circleMarker([lat, lng], {
            radius: 15,
            color: '#3b82f6',
            fillColor: '#60a5fa',
            fillOpacity: 0.3,
            weight: 2
        }).addTo(map);
        
        // Animate the ripple effect
        function animateRipple() {
            let radius = 15;
            let opacity = 0.5;
            
            const interval = setInterval(() => {
                radius += 1;
                opacity -= 0.01;
                
                rippleMarker.setStyle({
                    radius: radius,
                    fillOpacity: opacity,
                    opacity: opacity
                });
                
                if (opacity <= 0) {
                    clearInterval(interval);
                    rippleMarker.setStyle({
                        radius: 15,
                        fillOpacity: 0.3,
                        opacity: 0.5
                    });
                    setTimeout(animateRipple, 1000);
                }
            }, 50);
        }
        
        animateRipple();
    } else {
        // If we don't have coordinates, display an info message on the map
        const noLocationDiv = document.createElement('div');
        noLocationDiv.className = 'no-location-info';
        noLocationDiv.innerHTML = `
            <div class="no-location-content">
                <i class="fas fa-map-marker-alt"></i>
                <div>
                    <div>IP: ${ip}</div>
                    <div>Location data unavailable</div>
                </div>
            </div>
        `;
        
        document.getElementById(elementId).appendChild(noLocationDiv);
    }
    
    // Invalidate size to ensure map renders correctly
    setTimeout(() => {
        map.invalidateSize();
    }, 100);
}

/**
 * Gets approximate coordinates for a country
 * @param {string} countryName - The name of the country
 * @returns {Object|null} - The approximate coordinates or null if not found
 */
function getCountryCoordinates(countryName) {
    // This is a simplified mapping of countries to approximate coordinates
    const countryCoords = {
        'United States': { lat: 37.0902, lng: -95.7129 },
        'USA': { lat: 37.0902, lng: -95.7129 },
        'United Kingdom': { lat: 55.3781, lng: -3.4360 },
        'UK': { lat: 55.3781, lng: -3.4360 },
        'Canada': { lat: 56.1304, lng: -106.3468 },
        'Australia': { lat: -25.2744, lng: 133.7751 },
        'Germany': { lat: 51.1657, lng: 10.4515 },
        'France': { lat: 46.2276, lng: 2.2137 },
        'Japan': { lat: 36.2048, lng: 138.2529 },
        'China': { lat: 35.8617, lng: 104.1954 },
        'India': { lat: 20.5937, lng: 78.9629 },
        'Brazil': { lat: -14.2350, lng: -51.9253 },
        'Russia': { lat: 61.5240, lng: 105.3188 },
        'Netherlands': { lat: 52.1326, lng: 5.2913 },
        'Ireland': { lat: 53.1424, lng: -7.6921 },
        'Singapore': { lat: 1.3521, lng: 103.8198 },
        'Switzerland': { lat: 46.8182, lng: 8.2275 },
        'South Africa': { lat: -30.5595, lng: 22.9375 },
        'Mexico': { lat: 23.6345, lng: -102.5528 },
        'Spain': { lat: 40.4637, lng: -3.7492 },
        'Italy': { lat: 41.8719, lng: 12.5674 },
        'South Korea': { lat: 35.9078, lng: 127.7669 },
        'Indonesia': { lat: -0.7893, lng: 113.9213 },
        'Turkey': { lat: 38.9637, lng: 35.2433 },
        'Saudi Arabia': { lat: 23.8859, lng: 45.0792 },
        'Poland': { lat: 51.9194, lng: 19.1451 },
        'Ukraine': { lat: 48.3794, lng: 31.1656 },
        'Sweden': { lat: 60.1282, lng: 18.6435 },
        'Norway': { lat: 60.4720, lng: 8.4689 },
        'Finland': { lat: 61.9241, lng: 25.7482 },
        'Denmark': { lat: 56.2639, lng: 9.5018 }
    };
    
    // Try to find the country in our mapping
    return countryCoords[countryName] || null;
} 