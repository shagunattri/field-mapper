document.addEventListener('DOMContentLoaded', () => {
    const jsonInput = document.getElementById('jsonInput');
    const processBtn = document.getElementById('processBtn');
    const outputTableContainer = document.getElementById('outputTableContainer');
    const errorMessages = document.getElementById('errorMessages');
    const copyBtn = document.getElementById('copyBtn');
    const container = document.querySelector('.container'); // Get the main container
    const outputSection = document.querySelector('.output-section'); // Get output section

    // Store discovered JSON keys for dropdown
    let discoveredJsonKeys = [];

    // --- Categorized Armor Code Fields ---
    const armorCodeFieldCategories = {
        "Core": ["ID", "Summary", "CVE", "CWE", "Category", "Finding URL", "Description","Steps to Reproduce","Impact", "Remediation","Component Name", "Component Affected Version", "Component Fix Version"],
        "Tool Details": ["Tool Finding ID", "Tool Severity", "Tool Finding Status", "Tool Finding Category", "Fixable Using Tool"],
        "Risk & Severity": ["Severity", "Base Score", "CVSS Vector", "Exploit Maturity", "Exploited", "CISA KEV"],
        "Status & Dates": ["Status", "Latest Tool Scan Date", "Found On", "Last Seen Date"],
        "Asset & Environment": ["File Name", "Device", "URL/Endpoint", "Image Name", "IP Addresses", "Repository"],
    };

    // Flatten categories into the main list for consistency (used for total count and initial lowercasing)
    const armorCodeFields = Object.values(armorCodeFieldCategories).flat();
    const armorCodeFieldsLower = armorCodeFields.map(field => field.toLowerCase());

    const ignoredKeys = [
        'total_count', 'ids', 'total_pages', 'page', 'page_size', 'data',
    ];

    processBtn.addEventListener('click', () => {
        const jsonString = jsonInput.value.trim();
        errorMessages.textContent = '';
        outputTableContainer.innerHTML = '<p>Processing...</p>';
        copyBtn.style.display = 'none';
        container.classList.remove('results-active');
        clearSummary();
        discoveredJsonKeys = []; // Reset discovered keys

        if (!jsonString) {
            errorMessages.textContent = 'Please paste JSON data into the input area.';
            outputTableContainer.innerHTML = '<p>Processed results will appear here.</p>';
            return;
        }

        try {
            const jsonData = JSON.parse(jsonString);
            let recordObject = null;

            // --- Identify the primary record object ---
            if (Array.isArray(jsonData.data) && jsonData.data.length > 0) {
                recordObject = jsonData.data[0];
            } else if (typeof jsonData === 'object' && jsonData !== null && !Array.isArray(jsonData) && !jsonData.data) {
                 recordObject = jsonData;
            } else if(Array.isArray(jsonData) && jsonData.length > 0) {
                recordObject = jsonData[0];
            } else {
                 errorMessages.textContent = 'Could not find a suitable record object (e.g., in jsonData.data[0] or as root object/array) to process.';
                 outputTableContainer.innerHTML = '<p>Processed results will appear here.</p>';
                 return;
            }
            // --- End Identification ---

            const flattenedRecord = flattenObject(recordObject);
            const mappingResults = [];
            const mappedArmorCodeFields = new Set();
            discoveredJsonKeys = Object.keys(flattenedRecord); // Store keys

            for (const key in flattenedRecord) {
                if (Object.hasOwnProperty.call(flattenedRecord, key)) {
                    const value = flattenedRecord[key];
                    const baseKey = key.split('.').pop().toLowerCase();

                    if (ignoredKeys.includes(baseKey)) {
                        continue;
                    }

                    const mappedField = findMapping(key);
                    mappingResults.push({
                        jsonKey: key,
                        jsonValue: formatValue(value),
                        mappedField: mappedField
                    });

                    if (mappedField !== 'Tags') {
                        mappedArmorCodeFields.add(mappedField);
                    }
                }
            }

            generateTable(mappingResults);
            generateSummary(mappedArmorCodeFields); // Pass the Set of mapped fields

            copyBtn.style.display = 'block';
            container.classList.add('results-active');

        } catch (error) {
            console.error("Processing Error:", error); // Log detailed error
            errorMessages.textContent = `Error processing JSON: ${error.message}`;
            outputTableContainer.innerHTML = '<p>Processed results will appear here.</p>';
            container.classList.remove('results-active');
            clearSummary();
        }
    });

    // Event delegation for "Add" buttons in summary
    outputSection.addEventListener('click', (event) => {
        if (event.target.classList.contains('add-unmapped-btn')) {
            const fieldToAdd = event.target.dataset.field;
            addUnmappedFieldToTable(fieldToAdd);
            // Remove the list item from the summary
            event.target.closest('li').remove();
             // Optional: Check if category is now empty and remove header?
        }
    });

    copyBtn.addEventListener('click', () => {
        const table = outputTableContainer.querySelector('table');
        if (table) {
            copyTableToClipboard(table);
        }
    });

    // --- Helper Functions ---

    function flattenObject(obj, parentKey = '', result = {}) {
        for (const key in obj) {
            if (Object.hasOwnProperty.call(obj, key)) {
                const newKey = parentKey ? `${parentKey}.${key}` : key;
                if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) {
                    flattenObject(obj[key], newKey, result);
                } else {
                    result[newKey] = obj[key];
                }
            }
        }
        return result;
    }

    function findMapping(jsonKey) {
        const keyLower = jsonKey.split('.').pop().toLowerCase(); // Use the last part of the key for matching
        const index = armorCodeFieldsLower.indexOf(keyLower);

        // 1. Direct Match (case-insensitive)
        if (index !== -1) {
            return armorCodeFields[index]; // Return the original case field name
        }

        // 2. Specific Rules & Common Variations (add more as needed)
        if (keyLower === 'severity') return 'Severity';
        if (keyLower === 'title' || keyLower === 'vulnerability_name') return 'Summary';
        if (keyLower === 'last_seen') return 'Last Seen Date';
        if (keyLower === 'riskscore') return 'Risk Score'; // Handles 'riskscore' explicitly
        if (keyLower === 'cve_id' || keyLower === 'cveid' || keyLower.startsWith('cve-')) return 'CVE';
        if (keyLower === 'cvss_v3_vector' || keyLower === 'vectorstring') return 'CVSS Vector'; // Added common alternative
        if (keyLower === 'first_found' || keyLower === 'firstfound' || keyLower === 'created_at') return 'Found On'; // Or 'Last Seen Date' if preferred
        if (keyLower === 'ip' || keyLower === 'ip_address' || keyLower === 'host_ip') return 'IP Addresses';
        if (keyLower === 'repository' || keyLower.includes('repo_') || keyLower.includes('_repo')) return 'Repo';
        if (keyLower.includes('cwe')) return 'CWE'; // Catch variations like cwe_id
        if (keyLower === 'url' || keyLower === 'endpoint') return 'URL/Endpoint';
        if (keyLower === 'image_name') return 'Image Name';
        if (keyLower === 'tool_name' || keyLower === 'scanner') return 'Source Tool';

        // ... add more specific rules based on common API patterns ...

        // 3. Default to Tags
        console.log(`No specific mapping found for '${keyLower}' (from key '${jsonKey}'). Defaulting to Tags.`);
        return 'Tags';
    }

    function formatValue(value) {
        if (value === null || value === undefined) {
            return 'N/A';
        }
        if (Array.isArray(value)) {
            // Simple array to string conversion, might need refinement
            return value.map(item => typeof item === 'object' ? JSON.stringify(item) : item).join(', ');
        }
        if (typeof value === 'object') {
            // Check if it's an empty object before stringifying
            if (Object.keys(value).length === 0 && value.constructor === Object) {
                return '{}'; // Or 'Empty Object'
            }
            return JSON.stringify(value, null, 2); // Pretty print objects
        }
        return value.toString();
    }

    function generateTable(results) {
        if (results.length === 0) {
            outputTableContainer.innerHTML = '<p>No mappable data found in the JSON record.</p>'; // Updated message
            return;
        }

        let tableHTML = '<table><thead><tr><th>JSON Key</th><th>JSON Value</th><th>Mapped Armor Code Field</th></tr></thead><tbody>';

        results.forEach(item => {
            const safeJsonKey = escapeHtml(item.jsonKey);
            const safeJsonValue = escapeHtml(item.jsonValue);
            const safeMappedField = escapeHtml(item.mappedField);

            // Make value (<pre>) and mapped field (<td>) editable
            tableHTML += `<tr>
                            <td>${safeJsonKey}</td>
                            <td><pre contenteditable="true">${safeJsonValue}</pre></td>
                            <td contenteditable="true">${safeMappedField}</td>
                          </tr>`;
        });

        tableHTML += '</tbody></table>';
        outputTableContainer.innerHTML = tableHTML;
    }

    function escapeHtml(unsafe) {
        if (typeof unsafe !== 'string') {
            // If it's not a string (like a number or boolean from formatValue), return it directly
            return unsafe;
        }
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }

    // Updated copyTableToClipboard to handle select elements and copy HTML
    async function copyTableToClipboard(table) { // Make function async
        let plainText = '';
        const rows = table.querySelectorAll('tbody > tr');

        // --- 1. Generate Plain Text Version --- 
        const headerCells = table.querySelectorAll('thead > tr > th');
        const headerData = Array.from(headerCells).map(cell => (cell.innerText || cell.textContent).trim());
        plainText += headerData.join('\t') + '\n';

        rows.forEach((row) => {
            const cells = row.querySelectorAll('td');
            const rowData = [];
            cells.forEach((cell, cellIndex) => {
                let cellText;
                const selectElement = cell.querySelector('select');
                const preElement = cell.querySelector('pre');

                if (selectElement) {
                    cellText = selectElement.value || 'N/A';
                } else if (preElement) {
                    cellText = preElement.innerText || preElement.textContent;
                } else {
                     cellText = cell.innerText || cell.textContent;
                }
                cellText = cellText.replace(/\n/g, ' ').replace(/\s+/g, ' ').trim();
                rowData.push(cellText);
            });
            plainText += rowData.join('\t') + '\n';
        });

        // --- 2. Generate HTML Version --- 
        const tableClone = table.cloneNode(true);
        const clonedRows = tableClone.querySelectorAll('tbody > tr');

        // Update cloned cells with current values from original table
        rows.forEach((originalRow, rowIndex) => {
            const originalCells = originalRow.querySelectorAll('td');
            const clonedCells = clonedRows[rowIndex].querySelectorAll('td');

            originalCells.forEach((originalCell, cellIndex) => {
                const clonedCell = clonedCells[cellIndex];
                const selectElement = originalCell.querySelector('select');
                const preElement = originalCell.querySelector('pre');

                 // Remove contenteditable from clone
                 if (clonedCell.hasAttribute('contenteditable')) {
                     clonedCell.removeAttribute('contenteditable');
                 }
                 const preInClone = clonedCell.querySelector('pre');
                  if (preInClone && preInClone.hasAttribute('contenteditable')) {
                     preInClone.removeAttribute('contenteditable');
                 }

                // Set the visible text in the clone based on original state
                if (selectElement) {
                     clonedCell.innerHTML = escapeHtml(selectElement.value || 'N/A'); // Replace select with its value
                } else if (preElement) {
                     // Ensure the <pre> tag itself is kept if it exists in the clone
                    const targetElement = clonedCell.querySelector('pre') || clonedCell;
                    targetElement.innerText = preElement.innerText || preElement.textContent;
                } else {
                     clonedCell.innerText = originalCell.innerText || originalCell.textContent;
                }
            });
        });

        const htmlText = tableClone.outerHTML;

        // --- 3. Write both to Clipboard --- 
        try {
            const plainBlob = new Blob([plainText], { type: 'text/plain' });
            const htmlBlob = new Blob([htmlText], { type: 'text/html' });
            const clipboardItem = new ClipboardItem({
                'text/plain': plainBlob,
                'text/html': htmlBlob
            });

            await navigator.clipboard.write([clipboardItem]);
            alert('Table copied to clipboard! (Includes edits and HTML format)');

        } catch (err) {
            console.error('Failed to copy table using write API: ', err);
            // Fallback to text only if write API fails (optional)
            try {
                 await navigator.clipboard.writeText(plainText);
                 alert('Table copied as plain text! (HTML copy failed - check console)');
            } catch (textErr) {
                console.error('Failed to copy table as plain text fallback: ', textErr);
                alert('Failed to copy table. Check console for details.');
            }
        }
    }

    // --- Updated Summary Functions ---
    function generateSummary(mappedFieldsSet) {
        clearSummary();

        const totalAvailableFields = armorCodeFields.length;
        const mappedCount = mappedFieldsSet.size; // Already calculated

        const summaryDiv = document.createElement('div');
        summaryDiv.id = 'mappingSummary';
        summaryDiv.style.marginTop = '15px';
        summaryDiv.style.paddingTop = '15px';
        summaryDiv.style.borderTop = '1px solid #eee';

        let summaryHTML = `<h4>Mapping Summary</h4>`;
        summaryHTML += `<p>Mapped ${mappedCount} out of ${totalAvailableFields} available Armor Code fields (excluding 'Tags').</p>`;
        summaryHTML += `<p><strong>Unmapped Fields:</strong></p>`;

        let unmappedCountTotal = 0;
        // Iterate through categories
        for (const category in armorCodeFieldCategories) {
            const fieldsInCategory = armorCodeFieldCategories[category];
            const unmappedInCategory = fieldsInCategory.filter(field => !mappedFieldsSet.has(field) && field !== 'Tags');

            if (unmappedInCategory.length > 0) {
                summaryHTML += `<details style="margin-bottom: 5px;"><summary style="font-weight: bold; cursor: pointer;">${escapeHtml(category)} (${unmappedInCategory.length})</summary>`;
                summaryHTML += `<ul style="list-style-type: none; padding-left: 15px; margin-top: 5px;">`;
                unmappedInCategory.forEach(field => {
                    unmappedCountTotal++;
                    // Added data-field attribute to button
                    summaryHTML += `<li style="margin-bottom: 3px;">${escapeHtml(field)} 
                                     <button class="add-unmapped-btn" data-field="${escapeHtml(field)}" style="margin-left: 10px; padding: 2px 5px; font-size: 0.8em;">Add</button>
                                   </li>`;
                });
                summaryHTML += `</ul></details>`;
            }
        }

        if (unmappedCountTotal === 0) {
             summaryHTML += `<p>All available Armor Code fields were used in the mapping (or are 'Tags').</p>`;
        }

        summaryDiv.innerHTML = summaryHTML;
        outputSection.appendChild(summaryDiv);
    }

    // --- New function to add unmapped field to table ---
    function addUnmappedFieldToTable(armorCodeField) {
        const tableBody = outputTableContainer.querySelector('table tbody');
        if (!tableBody) {
             console.error("Cannot add row: Table body not found.");
             return; // Should not happen if table exists
        }

        const newRow = tableBody.insertRow(); // Append row to the end

        // Cell 1: JSON Key (Dropdown)
        const cellKey = newRow.insertCell();
        let keyOptionsHTML = '<option value="">-- Select JSON Key --</option>';
        discoveredJsonKeys.forEach(key => {
            keyOptionsHTML += `<option value="${escapeHtml(key)}">${escapeHtml(key)}</option>`;
        });
        cellKey.innerHTML = `<select style="width: 95%;">${keyOptionsHTML}</select>`;

        // Cell 2: JSON Value (Editable Pre)
        const cellValue = newRow.insertCell();
        cellValue.innerHTML = `<pre contenteditable="true">N/A (Manual Map)</pre>`;

        // Cell 3: Mapped Armor Code Field (Editable TD)
        const cellMapped = newRow.insertCell();
        cellMapped.textContent = armorCodeField;
        cellMapped.setAttribute('contenteditable', 'true');
    }

    function clearSummary() {
        const existingSummary = document.getElementById('mappingSummary');
        if (existingSummary) {
            existingSummary.remove();
        }
    }

}); 