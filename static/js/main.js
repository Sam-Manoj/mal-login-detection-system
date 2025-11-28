document.addEventListener('DOMContentLoaded', function() {

    // 1. Render all Lucide icons on the page
    try {
        lucide.createIcons();
    } catch (e) {
        console.error("Lucide icons failed to create:", e);
    }


    // 2. --- Tabbed Interface Logic (for info.html) ---
    const tabContainers = document.querySelectorAll(".tabs");

    tabContainers.forEach(container => {
        container.addEventListener("click", function (e) {
            const clicked = e.target.closest(".tab-link");
            
            if (!clicked) return;

            // Find the main parent container for the tabs and content
            const mainParent = clicked.closest('.main-content, .info-page');
            if (!mainParent) return;

            const tabLinks = container.querySelectorAll(".tab-link");
            const tabContents = mainParent.querySelectorAll(".tab-content");

            // Deactivate all tabs and content within this specific component
            tabLinks.forEach(tab => tab.classList.remove("active"));
            tabContents.forEach(content => content.classList.remove("active"));

            // Activate the tab that was clicked
            clicked.classList.add("active");

            // Find and activate the corresponding content
            const tabId = clicked.dataset.tab;
            const targetContent = mainParent.querySelector("#" + tabId);
            if(targetContent) {
                targetContent.classList.add("active");
            }
        });
    });

    // 3. --- Socket.IO Logic (for admin_dashboard.html) ---
    const tableBody = document.getElementById('log-table-body');
    if (tableBody) {
        
        // --- NEW: Initialize Map ---
        let map;
        let mapPins;
        try {
            map = L.map('world-map').setView([20, 0], 2); // Center on the globe
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
            }).addTo(map);
            mapPins = L.layerGroup().addTo(map); // Layer to hold our pins
        } catch (e) {
            console.error("Leaflet map failed to initialize:", e);
            const mapDiv = document.getElementById('world-map');
            if (mapDiv) {
                mapDiv.innerHTML = "Error loading map.";
                mapDiv.style.color = "var(--text-secondary)";
            }
        }
        
        // --- NEW: Initialize Stat Counters ---
        const statsTotalEl = document.getElementById('stats-total');
        const statsBlockedEl = document.getElementById('stats-blocked');
        const statsFlaggedEl = document.getElementById('stats-flagged');
        const statsAllowedEl = document.getElementById('stats-allowed');
        
        let total = parseInt(statsTotalEl?.textContent || '0', 10);
        let blocked = parseInt(statsBlockedEl?.textContent || '0', 10);
        let flagged = parseInt(statsFlaggedEl?.textContent || '0', 10);
        let allowed = parseInt(statsAllowedEl?.textContent || '0', 10);
        // --- END: Stat Counters ---

        try {
            // Connect to the WebSocket server
            const socket = io();

            // Listen for the 'new_login' event from the server
            socket.on('new_login', function(data) {
                console.log('Received new login attempt:', data);
                
                // Remove the "No login attempts" row if it exists
                const noAttemptsRow = document.getElementById('no-attempts-row');
                if (noAttemptsRow) {
                    noAttemptsRow.remove();
                }

                // --- Build the new table row (mirroring the new Jinja template) ---
                
                // Determine risk class, status text, and status class
                let risk_class = 'low';
                let status_text = 'Allowed';
                let status_class = 'status-allowed';

                if (data.risk_score > 75) {
                    risk_class = 'high';
                    status_text = 'Blocked';
                    status_class = 'status-blocked';
                } else if (data.risk_score > 40) {
                    risk_class = 'medium';
                    status_text = 'Flagged';
                    status_class = 'status-flagged';
                }
                
                // --- MODIFIED: Update All Stats ---
                total++;
                if (risk_class === 'high') {
                    blocked++;
                    if (statsBlockedEl) statsBlockedEl.textContent = blocked;
                } else if (risk_class === 'medium') {
                    flagged++;
                    if (statsFlaggedEl) statsFlaggedEl.textContent = flagged;
                } else {
                    allowed++;
                    if (statsAllowedEl) statsAllowedEl.textContent = allowed;
                }
                if (statsTotalEl) statsTotalEl.textContent = total;
                // --- END: Update Stats ---

                // Create the new row element
                const newRow = document.createElement('tr');
                newRow.className = `risk-${risk_class} new-row`; // Add animation class

                // Get first letter for avatar
                const avatarLetter = data.username ? data.username[0].toUpperCase() : '?';

                // Set the inner HTML
                newRow.innerHTML = `
                    <td>${escapeHTML(data.login_time)}</td>
                    <td>
                        <div class="user-cell">
                            <span class="user-avatar">${escapeHTML(avatarLetter)}</span>
                            ${escapeHTML(data.username)}
                        </div>
                    </td>
                    <td>${escapeHTML(data.ip_address)}</td>
                    <td>
                        <div class="risk-cell">
                            <span class="risk-bar-wrapper">
                                <span class="risk-bar" style="width: ${data.risk_score}%;"></span>
                            </span>
                            ${data.risk_score}%
                        </div>
                    </td>
                    <td>
                        <span class="status-badge ${status_class}">${escapeHTML(status_text)}</span>
                    </td>
                `;

                // Add the new row to the top of the table
                tableBody.prepend(newRow);

                // --- NEW: Add pin to map if high-risk ---
                if (risk_class === 'high' && data.lat && data.lon && map) {
                    const pinColor = "#e74c3c"; // Red for high risk
                    const svgIcon = L.divIcon({
                        html: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="${pinColor}" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-map-pin"><path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"/><circle cx="12" cy="10" r="3"/></svg>`,
                        className: 'map-pin-icon',
                        iconSize: [24, 24],
                        iconAnchor: [12, 24],
                        popupAnchor: [0, -24]
                    });

                    L.marker([data.lat, data.lon], { icon: svgIcon })
                        .addTo(mapPins)
                        .bindPopup(`<b>High Risk Alert</b><br>User: ${escapeHTML(data.username)}<br>IP: ${escapeHTML(data.ip_address)}`);
                    
                    // Fly to the new location
                    map.flyTo([data.lat, data.lon], 4);
                }
                // --- END: Add Pin ---

                // Re-render icons if any were added
                lucide.createIcons();
            });
        
        } catch (e) {
            console.error("Socket.IO failed to connect or run:", e);
        }
    }

});

// Helper function to prevent XSS attacks
function escapeHTML(str) {
    if (str === null || str === undefined) {
        return '';
    }
    return str.toString()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}