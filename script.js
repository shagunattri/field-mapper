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
    // Store the flattened JSON data for value lookups
    let flattenedJsonData = {};
    // Store the current mapping state: { armorCodeField: jsonKey | null }
    let currentMappings = {};

    // --- Categorized Armor Code Fields ---
    const armorCodeFieldCategories = {
        "Core": ["ID", "Summary", "CVE", "CWE", "Category", "Finding URL", "Description","Steps to Reproduce","Impact", "Remediation","Component Name", "Component Affected Version", "Component Fix Version", "Tags"],
        "Tool Details": ["Tool Finding ID", "Tool Severity", "Tool Finding Status", "Tool Finding Category", "Fixable Using Tool"],
        "Risk & Severity": ["Severity", "Base Score", "CVSS Vector", "Exploit Maturity", "Exploited", "CISA KEV"],
        "Status & Dates": ["Status", "Latest Tool Scan Date", "Found On", "Last Seen Date"],
        "Asset & Environment": ["File Name", "Device", "URL/Endpoint", "Image Name", "IP Addresses", "Repository"],
    };

    // Flatten categories into the main list for consistency (used for total count and initial lowercasing)
    const armorCodeFields = Object.values(armorCodeFieldCategories).flat();
    const armorCodeFieldsLower = armorCodeFields.map(field => field.toLowerCase());
    // Add a 'None' option for dropdowns
    const allArmorCodeFieldsWithNone = ['None', ...armorCodeFields];

    const ignoredKeys = [
        'total_count', 'ids', 'total_pages', 'page', 'page_size', 'data',
    ];

    processBtn.addEventListener('click', () => {
        const jsonString = jsonInput.value.trim();
        errorMessages.textContent = '';
        outputTableContainer.innerHTML = '<p>Processing...</p>';
        copyBtn.style.display = 'none';
        container.classList.remove('results-active');
        discoveredJsonKeys = []; // Reset discovered keys
        flattenedJsonData = {}; // Reset flattened data
        currentMappings = {}; // Reset current mappings

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
            flattenedJsonData = flattenedRecord; // Store for later use
            const initialMappingResults = {}; // Store initial mappings { jsonKey: armorCodeField }
            const mappedJsonKeys = new Set();
            discoveredJsonKeys = Object.keys(flattenedRecord); // Store keys

            // --- Initial Mapping Pass ---
            for (const key in flattenedRecord) {
                if (Object.hasOwnProperty.call(flattenedRecord, key)) {
                    const value = flattenedRecord[key];
                    const baseKey = key.split('.').pop().toLowerCase();

                    if (ignoredKeys.includes(baseKey)) {
                        continue;
                    }

                    const mappedField = findMapping(key);

                    // Only store the first mapping found for a given ArmorCode field (excluding 'Tags')
                    if (mappedField !== 'Tags' && !Object.values(initialMappingResults).includes(mappedField)) {
                         initialMappingResults[key] = mappedField;
                         mappedJsonKeys.add(key);
                    } else if (mappedField === 'Tags' && !mappedJsonKeys.has(key)) {
                         // Allow 'Tags' mapping only if the key isn't already mapped more specifically
                         initialMappingResults[key] = 'Tags';
                         mappedJsonKeys.add(key);
                    }
                }
            }

            // --- Initialize currentMappings ---
            // Start with all ArmorCode fields unmapped
            armorCodeFields.forEach(field => currentMappings[field] = null);
            // Apply initial mappings found above
            for (const [jsonKey, armorField] of Object.entries(initialMappingResults)) {
                if (armorField !== 'Tags') { // Don't pre-fill 'Tags' as a primary mapping
                     // Check if this armor field was already assigned (shouldn't happen with current logic, but safe check)
                    if (currentMappings[armorField] === null) {
                        currentMappings[armorField] = jsonKey;
                    } else {
                        console.warn(`ArmorCode field '${armorField}' potentially mapped by multiple keys. Using first found: '${currentMappings[armorField]}'. Key '${jsonKey}' ignored for initial mapping.`);
                    }
                }
            }
             // Add explicit 'Tags' mapping for keys that weren't mapped to anything else
            for (const [jsonKey, armorField] of Object.entries(initialMappingResults)) {
                if (armorField === 'Tags') {
                    // Check if this jsonKey ended up being mapped to a *specific* AC field
                    let isJsonKeyMappedSpecifically = false;
                    for(const acField in currentMappings){
                        if(currentMappings[acField] === jsonKey){
                            isJsonKeyMappedSpecifically = true;
                            break;
                        }
                    }
                    if (!isJsonKeyMappedSpecifically) {
                         // Ensure 'Tags' entry exists if not already explicitly mapped
                        if (!currentMappings['Tags']) {
                            currentMappings['Tags'] = []; // Initialize Tags as an array if needed
                        }
                        // Add the jsonKey to the Tags mapping if not already there
                        if (Array.isArray(currentMappings['Tags']) && !currentMappings['Tags'].includes(jsonKey)) {
                           currentMappings['Tags'].push(jsonKey);
                        } else if (!Array.isArray(currentMappings['Tags'])) {
                            // Handle potential override if 'Tags' was mistakenly set to a single key earlier
                            currentMappings['Tags'] = [jsonKey];
                        }
                    }
                }
            }

            generateTable(); // Generate the unified table

            copyBtn.style.display = 'block';
            container.classList.add('results-active');

        } catch (error) {
            console.error("Processing Error:", error); // Log detailed error
            errorMessages.textContent = `Error processing JSON: ${error.message}`;
            outputTableContainer.innerHTML = '<p>Processed results will appear here.</p>';
            container.classList.remove('results-active');
            clearSummaryDisplay();
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
            return ''; // Return empty string instead of 'N/A' for cleaner display
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

    // --- New generateTable Function ---
    function generateTable() {
        let tableHTML = `
            <table>
                <thead>
                    <tr>
                        <th>JSON Key</th>
                        <th>JSON Value</th>
                        <th>Armor Code Field</th>
                    </tr>
                </thead>
                <tbody>
        `;

        // Separate handling for 'Tags' if it exists as a special case
        const regularArmorCodeFields = armorCodeFields.filter(field => field !== 'Tags');
        const hasTagsMapping = currentMappings['Tags'] && Array.isArray(currentMappings['Tags']);

        // Generate rows for non-'Tags' ArmorCode fields
        regularArmorCodeFields.forEach(armorField => {
            const mappedJsonKey = currentMappings[armorField];

            if (mappedJsonKey) {
                // --- Render Mapped Row ---
                const jsonValue = flattenedJsonData[mappedJsonKey] ?? '';
                tableHTML += `
                    <tr data-armorcode-field="${escapeHtml(armorField)}">
                        <td class="json-key">${escapeHtml(mappedJsonKey)}</td>
                        <td class="json-value">${escapeHtml(formatValue(jsonValue))}</td>
                        <td class="armorcode-field-cell">
                            ${createArmorCodeDropdown(armorField, true)}
                        </td>
                    </tr>
                `;
            } else {
                // --- Render Unmapped Row ---
                tableHTML += `
                     <tr data-armorcode-field="${escapeHtml(armorField)}">
                        <td class="json-key-cell">
                            ${createJsonKeyDropdown(armorField)}
                        </td>
                        <td class="json-value">---</td>
                        <td class="armorcode-field-name">${escapeHtml(armorField)}</td>
                    </tr>
                `;
            }
        });

         // --- Generate Rows for 'Tags' ---
        if (hasTagsMapping) {
             currentMappings['Tags'].forEach(jsonKeyForTag => {
                 const jsonValue = flattenedJsonData[jsonKeyForTag] ?? '';
                 tableHTML += `
                    <tr data-armorcode-field="Tags" data-json-key-source="${escapeHtml(jsonKeyForTag)}">
                        <td class="json-key">${escapeHtml(jsonKeyForTag)}</td>
                        <td class="json-value">${escapeHtml(formatValue(jsonValue))}</td>
                        <td class="armorcode-field-cell">
                            ${createArmorCodeDropdown('Tags', true)}
                         </td>
                    </tr>
                 `;
             });
        }
         // Add a row specifically for assigning *new* keys to Tags if Tags is an option
        if (armorCodeFields.includes('Tags')) {
             // Add a row allowing selection of a JSON key to map to 'Tags'
             // This row appears even if 'Tags' already has mappings.
             tableHTML += `
                 <tr data-armorcode-field="Tags">
                     <td class="json-key-cell">
                         ${createJsonKeyDropdown('Tags', true)}
                     </td>
                     <td class="json-value">---</td>
                     <td class="armorcode-field-name">Tags (Add New)</td>
                 </tr>
             `;
        }


        tableHTML += '</tbody></table>';
        outputTableContainer.innerHTML = tableHTML;

        // Add event listeners after table generation
        addDropdownListeners();
    }

    function createArmorCodeDropdown(selectedField, isMappedRow) {
        // Always include 'None' and 'Tags' as options if they aren't the selected field yet
        const options = allArmorCodeFieldsWithNone.map(field => {
             // Allow selecting 'Tags' even on a mapped row if the current field isn't 'Tags'
            if (field === 'Tags' && selectedField !== 'Tags' && !isMappedRow) return ''; // Don't show Tags as option on unmapped rows initially
            if (field === 'Tags' && selectedField !== 'Tags' && isMappedRow) {
                 // Allow selecting Tags on mapped rows
            } else if (field === 'None' && !isMappedRow) {
                return ''; // Don't show 'None' on unmapped rows (use JSON key dropdown)
            }

            const isSelected = field === selectedField;
            // Disable selection if this field is already mapped elsewhere (unless it's the current row's field or 'None'/'Tags')
            const mappedElsewhere = field !== 'None' && field !== 'Tags' && currentMappings[field] !== null && currentMappings[field] !== findJsonKeyForArmorCode(selectedField);
            const disabled = mappedElsewhere ? 'disabled' : '';
            const displayText = mappedElsewhere ? `${field} (mapped)` : field;

            return `<option value="${escapeHtml(field)}" ${isSelected ? 'selected' : ''} ${disabled}>${escapeHtml(displayText)}</option>`;
        }).join('');

        return `<select class="armorcode-select">${options}</select>`;
    }


     function createJsonKeyDropdown(armorField, forTagsAdd = false) {
        // Remove filtering of mapped keys since we now allow reuse
        let options = '<option value="">-- Select JSON Key --</option>'; // Default empty option
        discoveredJsonKeys.forEach(key => {
            options += `<option value="${escapeHtml(key)}">${escapeHtml(key)}</option>`;
        });
        const selectClass = forTagsAdd ? "json-key-select-tags-add" : "json-key-select";
        return `<select class="${selectClass}" data-target-armorcode="${escapeHtml(armorField)}">${options}</select>`;
    }

    function addDropdownListeners() {
        outputTableContainer.querySelectorAll('.armorcode-select').forEach(select => {
            select.addEventListener('change', handleArmorCodeChange);
        });
        outputTableContainer.querySelectorAll('.json-key-select').forEach(select => {
            select.addEventListener('change', handleJsonKeyChange);
        });
         outputTableContainer.querySelectorAll('.json-key-select-tags-add').forEach(select => {
            select.addEventListener('change', handleTagsAddChange);
        });
    }

    function handleArmorCodeChange(event) {
        const select = event.target;
        const newArmorCodeField = select.value;
        const row = select.closest('tr');
        const originalArmorCodeField = row.dataset.armorcodeField;
        const sourceJsonKey = row.querySelector('.json-key')?.textContent || 
                            findJsonKeyForArmorCode(originalArmorCodeField);

        console.log(`ArmorCode Change: Row for '${originalArmorCodeField}' (JSON Key: ${sourceJsonKey}), New AC Field: '${newArmorCodeField}'`);

        if (!sourceJsonKey) {
            console.error("Could not find source JSON key for row:", row);
            return;
        }

        // Handle 'None': Unmap the original AC field from this JSON key
        if (newArmorCodeField === 'None') {
            if (originalArmorCodeField === 'Tags') {
                // Remove sourceJsonKey from Tags array
                if (currentMappings['Tags'] && Array.isArray(currentMappings['Tags'])) {
                    currentMappings['Tags'] = currentMappings['Tags'].filter(key => key !== sourceJsonKey);
                }
            } else {
                // Unmap the specific field
                if (currentMappings[originalArmorCodeField] === sourceJsonKey) {
                    currentMappings[originalArmorCodeField] = null;
                }
            }
        }
        // Handle 'Tags': Add sourceJsonKey to Tags array
        else if (newArmorCodeField === 'Tags') {
            // Add to Tags array (ensure it's an array)
            if (!currentMappings['Tags']) currentMappings['Tags'] = [];
            if (Array.isArray(currentMappings['Tags']) && !currentMappings['Tags'].includes(sourceJsonKey)) {
                currentMappings['Tags'].push(sourceJsonKey);
            }
            // Unmap from original field if it was a specific field
            if (originalArmorCodeField !== 'Tags' && currentMappings[originalArmorCodeField] === sourceJsonKey) {
                currentMappings[originalArmorCodeField] = null;
            }
        }
        // Handle Specific Field: Map the new AC field to this JSON key
        else {
            // Simply update the mapping for the new field
            currentMappings[newArmorCodeField] = sourceJsonKey;
            // Unmap from original field if different
            if (originalArmorCodeField !== newArmorCodeField && currentMappings[originalArmorCodeField] === sourceJsonKey) {
                currentMappings[originalArmorCodeField] = null;
            }
        }

        // Regenerate the table to reflect the state change
        regenerateTableWithState();
    }

    function handleJsonKeyChange(event) {
        const select = event.target;
        const selectedJsonKey = select.value;
        const targetArmorCodeField = select.dataset.targetArmorcode;

        console.log(`JSON Key Change: Target AC Field '${targetArmorCodeField}', Selected JSON Key: '${selectedJsonKey}'`);

        // If a valid JSON key is selected (not the placeholder)
        if (selectedJsonKey) {
            // Simply map the selected key to the target field - no need to check for existing mappings
            currentMappings[targetArmorCodeField] = selectedJsonKey;
        } else {
            // If '-- Select JSON Key --' is chosen, ensure the AC field is unmapped
            currentMappings[targetArmorCodeField] = null;
        }

        // Regenerate the table to reflect the state change
        regenerateTableWithState();
    }

    function handleTagsAddChange(event) {
        const select = event.target;
        const selectedJsonKey = select.value;

        console.log(`Tags Add Change: Selected JSON Key: '${selectedJsonKey}'`);

        if (selectedJsonKey) {
            // Add the selected key to the 'Tags' array (ensure it exists and is an array)
            if (!currentMappings['Tags']) currentMappings['Tags'] = [];
            if (Array.isArray(currentMappings['Tags']) && !currentMappings['Tags'].includes(selectedJsonKey)) {
                currentMappings['Tags'].push(selectedJsonKey);
            }
            // Reset the dropdown after adding
            select.value = "";
        }
        // Regenerate the table to reflect the state change
        regenerateTableWithState();
    }

    // Helper to find the JSON key currently mapped to a given AC field
    function findJsonKeyForArmorCode(armorCodeField) {
        if(armorCodeField === 'Tags') return null; // Tags mapping is handled differently
        return currentMappings[armorCodeField] || null;
    }

    // Function to regenerate table based on currentMappings state
    function regenerateTableWithState() {
        // Store scroll position
        const scrollY = window.scrollY;
        // Regenerate table HTML using the existing generateTable logic which now reads currentMappings
        generateTable();
        // Restore scroll position
        window.scrollTo(0, scrollY);
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

    async function copyTableToClipboard(table) { // Make function async
        let plainText = '';
        const rows = table.querySelectorAll('tbody > tr');

        // --- 1. Generate Plain Text Version ---
        // Use explicit headers matching the visual table
        const headers = ["JSON Key", "JSON Value", "Armor Code Field"];
        plainText += headers.join('\t') + '\n';


        rows.forEach((row) => {
            const cells = row.querySelectorAll('td');
            const rowData = [];

            // Determine ArmorCode Field first (might be text or selected value)
            const armorCodeCell = cells[2];
            let armorCodeValue = '';
            const armorCodeSelect = armorCodeCell.querySelector('.armorcode-select');
            if (armorCodeSelect) {
                armorCodeValue = armorCodeSelect.value;
            } else {
                armorCodeValue = armorCodeCell.textContent.trim(); // Get text if it's not a dropdown
                // Handle the 'Tags (Add New)' case - don't copy this row
                if (armorCodeValue.includes('Tags (Add New)')) {
                    return; // Skip this row
                }
            }

             // Skip rows where ArmorCode field ended up as 'None' after edits
             if (armorCodeValue === 'None') {
                 return; // Skip this row
             }


            // Determine JSON Key (might be text or selected value)
            const jsonKeyCell = cells[0];
            let jsonKeyValue = '';
            const jsonKeySelect = jsonKeyCell.querySelector('.json-key-select, .json-key-select-tags-add');
            if (jsonKeySelect) {
                jsonKeyValue = jsonKeySelect.value;
                 // Skip rows where JSON Key is not selected in an unmapped row
                 if (!jsonKeyValue && armorCodeValue !== 'Tags') { // Allow empty key for Tags source rows initially
                    const rowArmorField = row.dataset.armorcodeField;
                    // Check if this row was originally an unmapped row (has json-key-cell) AND json key is still empty
                    if (jsonKeyCell.classList.contains('json-key-cell') && !jsonKeyValue) {
                         return; // Skip row if JSON key wasn't selected for an unmapped field
                    }
                 } else if (!jsonKeyValue && jsonKeySelect.classList.contains('json-key-select-tags-add')) {
                     return; // Skip the 'Tags (Add New)' template row if no key selected
                 }
            } else {
                jsonKeyValue = jsonKeyCell.textContent.trim();
            }


            // Get JSON Value
            const jsonValueCell = cells[1];
            const jsonValueText = jsonValueCell.textContent.trim(); // Take text content directly

             // Skip rows that represent unmapped fields where no JSON key was selected
            if (jsonValueText === '---' && !jsonKeyValue) {
                 return;
            }


            rowData.push(jsonKeyValue || 'N/A'); // Use N/A if JSON Key is somehow empty
            rowData.push(jsonValueText);
            rowData.push(armorCodeValue);

            plainText += rowData.join('\t') + '\n';
        });

        // --- 2. Generate HTML Version (Optional, but good for rich paste) ---
         // Create a temporary table clone for HTML copy, ensuring select values are reflected
         const tempTable = table.cloneNode(true);
         tempTable.querySelectorAll('select').forEach(select => {
             const selectedValue = select.value;
             // Remove the select and replace with its selected value text
             const parentTd = select.parentNode;
             if (parentTd) {
                 // Handle 'Tags (Add New)' row specifically
                 if (parentTd.classList.contains('armorcode-field-name') && parentTd.textContent.includes('Tags (Add New)')) {
                    parentTd.closest('tr')?.remove(); // Remove the whole row
                 } else if (parentTd.classList.contains('json-key-cell')) {
                     // Replace JSON key select with value or N/A
                     if(!selectedValue) {
                         // If JSON key wasn't selected for an unmapped field, remove row
                         parentTd.closest('tr')?.remove();
                     } else {
                        parentTd.textContent = selectedValue;
                     }
                 } else if (parentTd.classList.contains('armorcode-field-cell')) {
                     // Replace ArmorCode select with value
                      if (selectedValue === 'None') {
                         parentTd.closest('tr')?.remove(); // Remove row if mapped to None
                      } else {
                         parentTd.textContent = selectedValue;
                      }

                 } else {
                      // Fallback: Replace select with its value
                     parentTd.textContent = selectedValue;
                 }

             } else {
                  select.remove(); // Remove select if it somehow has no parent TD
             }
         });
         // Remove rows that were placeholders for unmapped fields where no key was selected
        tempTable.querySelectorAll('tbody > tr').forEach(row => {
             const cells = row.querySelectorAll('td');
             if (cells.length >= 3 && cells[1].textContent.trim() === '---' && cells[0].textContent.trim() === '') {
                 row.remove();
             }
         });


         const tableHTML = tempTable.outerHTML;


        // --- 3. Use Clipboard API ---
        try {
            const blobHtml = new Blob([tableHTML], { type: 'text/html' });
            const blobText = new Blob([plainText], { type: 'text/plain' });
            const clipboardItem = new ClipboardItem({
                'text/html': blobHtml,
                'text/plain': blobText
            });
            await navigator.clipboard.write([clipboardItem]);
            alert('Table copied to clipboard (HTML & Plain Text)!');
        } catch (err) {
            console.error('Failed to copy table: ', err);
            // Fallback to text only if HTML fails or isn't supported well
            try {
                await navigator.clipboard.writeText(plainText);
                alert('Table copied to clipboard (Plain Text only).');
            } catch (textErr) {
                console.error('Failed to copy plain text fallback: ', textErr);
                alert('Failed to copy table to clipboard.');
            }
        }
    }

    // Utility to clear summary div if it exists (might be artifacts)
    function clearSummaryDisplay() {
        const summaryDiv = document.getElementById('mappingSummary'); // Assuming an ID if one existed
        if (summaryDiv) summaryDiv.innerHTML = '';
         // Or clear by class if needed
    }
     // Call this once initially and after processing
    clearSummaryDisplay();

}); 