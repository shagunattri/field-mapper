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
    // Store the selected attribute type
    let currentAttributeType = 'finding'; // Default to finding

    // --- Armor Code Asset Fields ---
    const assetFields = [
        "ID", "Name", "Type", "OS", "First Seen", "Owner", "Source", "Status",
        "DNS Name", "OS Version", "Cloud Provider", "Cloud Account ID",
        "Cloud Resource Type", "Location", "Image Repo", "Tags", "Registry",
        "Cluster", "Namespace", "Cloud Resource", "Publicly Accessible", "Region",
        "Runtime", "Architecture", "VPC ID", "Role", "Version", "Storage Type",
        "Engine Version", "Engine", "Instance Status", "Subnet IDs"
    ];
    const assetFieldsLower = assetFields.map(field => field.toLowerCase());
    const allAssetFieldsWithNone = ['None', ...assetFields];


    // --- Categorized Armor Code Finding Fields ---
    const armorCodeFieldCategories = {
        "Core": ["ID", "Summary", "CVE", "CWE", "Category", "Finding URL", "Description", "Steps to Reproduce", "Impact", "Remediation", "Component Name", "Component Affected Version", "Component Fix Version", "Tags"],
        "Tool Details": ["Tool Finding ID", "Tool Severity", "Tool Finding Status", "Tool Finding Category", "Fixable Using Tool"],
        "Risk & Severity": ["Severity", "Base Score", "CVSS Vector", "Exploit Maturity", "Exploited", "CISA KEV"],
        "Status & Dates": ["Status", "Latest Tool Scan Date", "Found On", "Last Seen Date"],
        "Asset & Environment": ["File Name", "Device", "URL/Endpoint", "Image Name", "IP Addresses", "Repository"],
    };

    // Flatten categories into the main list for consistency (used for total count and initial lowercasing)
    const findingFields = Object.values(armorCodeFieldCategories).flat();
    const findingFieldsLower = findingFields.map(field => field.toLowerCase());
    // Add a 'None' option for dropdowns
    const allFindingFieldsWithNone = ['None', ...findingFields];

    // Dynamically set fields based on selection (will be updated in click handler)
    let armorCodeFields = findingFields;
    let armorCodeFieldsLower = findingFieldsLower;
    let allArmorCodeFieldsWithNone = allFindingFieldsWithNone;


    const ignoredKeys = [
        'total_count', 'ids', 'total_pages', 'page', 'page_size', 'data',
    ];

    processBtn.addEventListener('click', () => {
        // --- Get Selected Attribute Type from Dropdown ---
        const attributeSelect = document.getElementById('attributeTypeSelect');
        const selectedAttributeType = attributeSelect.value;
        currentAttributeType = selectedAttributeType; // Store for use in other functions

        // --- Set Field Lists Based on Selection ---
        if (currentAttributeType === 'asset') {
            armorCodeFields = assetFields;
            armorCodeFieldsLower = assetFieldsLower;
            allArmorCodeFieldsWithNone = allAssetFieldsWithNone;
        } else { // Default to 'finding'
            armorCodeFields = findingFields;
            armorCodeFieldsLower = findingFieldsLower;
            allArmorCodeFieldsWithNone = allFindingFieldsWithNone;
        }
        // --- End Field List Setup ---


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

    copyBtn.addEventListener('click', async () => { // Make listener async
        const table = outputTableContainer.querySelector('table');
        if (table) {
            const originalText = copyBtn.textContent;
            copyBtn.disabled = true; // Disable button
            copyBtn.textContent = 'Copying...'; // Indicate activity
            errorMessages.textContent = ''; // Clear previous errors

            const success = await copyTableToClipboard(table); // Await the result

            if (success) {
                copyBtn.textContent = 'Copied!';
                setTimeout(() => {
                    copyBtn.textContent = originalText;
                    copyBtn.disabled = false; // Re-enable button
                }, 2000); // Revert after 2 seconds
            } else {
                // Handle cases where copy failed or nothing was copied
                 copyBtn.textContent = originalText; // Revert text immediately on failure
                 copyBtn.disabled = false; // Re-enable button
                 // Error message is handled within copyTableToClipboard or if no data
                 if (!errorMessages.textContent) { // Avoid overwriting clipboard error
                    errorMessages.textContent = 'No valid data mapped to copy.';
                 }
            }
             // Note: Button remains disabled until timeout completes on success
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
        // Use the currently active armorCodeFieldsLower for mapping
        const keyLower = jsonKey.split('.').pop().toLowerCase(); // Use the last part of the key for matching
        const index = armorCodeFieldsLower.indexOf(keyLower);

        // 1. Direct Match (case-insensitive)
        if (index !== -1) {
            // Use the currently active armorCodeFields list
            return armorCodeFields[index]; // Return the original case field name
        }

        // 2. Specific Rules & Common Variations (Apply ONLY if findingAttributes is selected)
        if (currentAttributeType === 'finding') {
            if (keyLower === 'severity') return 'Severity';
            if (keyLower === 'title' || keyLower === 'vulnerability_name') return 'Summary';
            if (keyLower === 'last_seen') return 'Last Seen Date';
            // Removed 'riskscore' mapping as it's not a standard finding field - adjust if needed
            if (keyLower === 'cve_id' || keyLower === 'cveid' || keyLower.startsWith('cve-')) return 'CVE';
            if (keyLower === 'cvss_v3_vector' || keyLower === 'vectorstring') return 'CVSS Vector';
            if (keyLower === 'first_found' || keyLower === 'firstfound' || keyLower === 'created_at') return 'Found On';
            if (keyLower === 'ip' || keyLower === 'ip_address' || keyLower === 'host_ip') return 'IP Addresses';
            if (keyLower === 'repository' || keyLower.includes('repo_') || keyLower.includes('_repo')) return 'Repository'; // Changed from 'Repo' to 'Repository'
            if (keyLower.includes('cwe')) return 'CWE';
            if (keyLower === 'url' || keyLower === 'endpoint') return 'URL/Endpoint';
            if (keyLower === 'image_name') return 'Image Name';
            // Removed 'tool_name'/'scanner' mapping to 'Source Tool' as it's not a standard finding field
            if (keyLower === 'status') return 'Status'; // Map 'status' directly if finding
        } else if (currentAttributeType === 'asset') {
             // Add specific asset mapping rules here if needed in the future
             // Example: if (keyLower === 'operating_system') return 'OS';
            if (keyLower === 'tags') return 'Tags'; // Map 'tags' directly if asset
        }


        // 3. General "Tags" check (moved lower priority)
        // If the key contains 'tag' and wasn't matched above, suggest 'Tags'
        // This check applies to both finding and asset attributes.
        if (keyLower.includes('tag')) {
             // Check if 'Tags' exists in the current field list
             const tagsFieldIndex = armorCodeFieldsLower.indexOf('tags');
             if (tagsFieldIndex !== -1) {
                 return armorCodeFields[tagsFieldIndex]; // Return 'Tags' with correct casing
             }
        }


        return null; // No mapping found
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
        outputTableContainer.innerHTML = ''; // Clear previous content
        const table = document.createElement('table');
        const thead = document.createElement('thead');
        const tbody = document.createElement('tbody');

        // --- Header Row ---
        const headerRow = document.createElement('tr');
        ['JSON Key', 'JSON Value (Sample)', 'Mapped Armor Code Field'].forEach(text => {
            const th = document.createElement('th');
            th.textContent = text;
            headerRow.appendChild(th);
        });
        thead.appendChild(headerRow);
        table.appendChild(thead);

        // Store rows by ArmorCode field for sorting/grouping later if needed
        const rowsByArmorCodeField = {};
        const unmappedJsonRows = [];

        // --- Populate Rows ---
        // Add rows for ArmorCode fields that have a mapping in currentMappings
        for (const armorField in currentMappings) {
            const jsonKey = currentMappings[armorField];

            if (jsonKey && armorField !== 'Tags') { // Handle single mappings
                 if (!rowsByArmorCodeField[armorField]) {
                    rowsByArmorCodeField[armorField] = [];
                }
                rowsByArmorCodeField[armorField].push({ jsonKey: jsonKey, armorField: armorField, isMapped: true });
            } else if (armorField === 'Tags' && Array.isArray(jsonKey) && jsonKey.length > 0) { // Handle Tags array
                 if (!rowsByArmorCodeField[armorField]) {
                    rowsByArmorCodeField[armorField] = [];
                }
                jsonKey.forEach(jk => {
                    rowsByArmorCodeField[armorField].push({ jsonKey: jk, armorField: armorField, isMapped: true });
                });
            }
        }

        // Add rows for JSON keys that *weren't* mapped initially
        const mappedJsonKeysInCurrentMappings = new Set();
        Object.values(currentMappings).forEach(val => {
            if (typeof val === 'string') mappedJsonKeysInCurrentMappings.add(val);
            else if (Array.isArray(val)) val.forEach(item => mappedJsonKeysInCurrentMappings.add(item));
        });

        discoveredJsonKeys.forEach(jsonKey => {
            if (!mappedJsonKeysInCurrentMappings.has(jsonKey)) {
                unmappedJsonRows.push({ jsonKey: jsonKey, armorField: null, isMapped: false });
            }
        });

         // --- Generate Table Body ---
        const createRow = (rowData) => {
            const tr = document.createElement('tr');
            const jsonKey = rowData.jsonKey;
            const mappedField = rowData.armorField; // This is the initially determined or current mapping
            const sampleValue = flattenedJsonData[jsonKey];

            tr.dataset.jsonKey = jsonKey; // Store json key for reference

            // JSON Key Cell
            const tdKey = document.createElement('td');
            tdKey.textContent = jsonKey;
            tr.appendChild(tdKey);

            // JSON Value Cell
            const tdValue = document.createElement('td');
            tdValue.innerHTML = formatValue(sampleValue); // Use innerHTML for formatted links/etc.
            tr.appendChild(tdValue);

            // Mapped Field Cell (Dropdown)
            const tdMapped = document.createElement('td');
            // Pass true if the row represents an existing mapping, false otherwise
            tdMapped.appendChild(createArmorCodeDropdown(mappedField, rowData.isMapped));
            tr.appendChild(tdMapped);

            tbody.appendChild(tr);
        };

        // --- Render Rows (Categorized for Findings, Flat for Assets) ---
        if (currentAttributeType === 'finding') {
            // Render Finding Attributes (Categorized)
            Object.keys(armorCodeFieldCategories).forEach(category => {
                const categoryHeaderRow = document.createElement('tr');
                const categoryHeaderCell = document.createElement('th');
                categoryHeaderCell.colSpan = 3; // Span across all columns
                categoryHeaderCell.textContent = category;
                categoryHeaderCell.classList.add('category-header');
                categoryHeaderRow.appendChild(categoryHeaderCell);
                tbody.appendChild(categoryHeaderRow);

                armorCodeFieldCategories[category].forEach(armorField => {
                    if (rowsByArmorCodeField[armorField]) {
                        rowsByArmorCodeField[armorField].forEach(createRow);
                         delete rowsByArmorCodeField[armorField]; // Remove processed field
                    } else if (currentMappings[armorField] === null) {
                        // Add placeholder row for unmapped AC fields in this category
                         const placeholderRowData = { jsonKey: `<i>(No Mapping Found for ${armorField})</i>`, armorField: armorField, isMapped: false };
                         const tr = document.createElement('tr');
                         tr.classList.add('unmapped-ac-row');

                         const tdKey = document.createElement('td');
                         // Place the dropdown in the first column (JSON Key)
                         tdKey.appendChild(createPlaceholderJsonKeyDropdown(armorField));
                         tr.appendChild(tdKey);

                         const tdValue = document.createElement('td');
                         // Put placeholder text in the second column (JSON Value)
                         tdValue.textContent = '---';
                         tr.appendChild(tdValue);

                         const tdMapped = document.createElement('td');
                         tdMapped.appendChild(createArmorCodeDropdown(armorField, false)); // Show dropdown for potential mapping
                         tr.appendChild(tdMapped);
                         tbody.appendChild(tr);
                    }
                });
            });

             // Add a header for remaining mapped fields (e.g., 'Tags' if it wasn't in a category)
             const remainingMappedFields = Object.keys(rowsByArmorCodeField);
             if(remainingMappedFields.length > 0){
                 const remainingHeaderRow = document.createElement('tr');
                 const remainingHeaderCell = document.createElement('th');
                 remainingHeaderCell.colSpan = 3;
                 remainingHeaderCell.textContent = "Other Mapped Fields";
                 remainingHeaderCell.classList.add('category-header');
                 remainingHeaderRow.appendChild(remainingHeaderCell);
                 tbody.appendChild(remainingHeaderRow);
                 remainingMappedFields.forEach(armorField => {
                     rowsByArmorCodeField[armorField].forEach(createRow);
                 });
             }


        } else {
            // Render Asset Attributes (Flat List)
             armorCodeFields.forEach(armorField => {
                 if (rowsByArmorCodeField[armorField]) {
                     rowsByArmorCodeField[armorField].forEach(createRow);
                 } else if (currentMappings[armorField] === null) {
                    // Add placeholder row for unmapped AC fields
                     const placeholderRowData = { jsonKey: `<i>(No Mapping Found for ${armorField})</i>`, armorField: armorField, isMapped: false };
                     const tr = document.createElement('tr');
                     tr.classList.add('unmapped-ac-row');

                     const tdKey = document.createElement('td');
                     // Place the dropdown in the first column (JSON Key)
                     tdKey.appendChild(createPlaceholderJsonKeyDropdown(armorField));
                     tr.appendChild(tdKey);

                     const tdValue = document.createElement('td');
                      // Put placeholder text in the second column (JSON Value)
                     tdValue.textContent = '---';
                     tr.appendChild(tdValue);

                     const tdMapped = document.createElement('td');
                     tdMapped.appendChild(createArmorCodeDropdown(armorField, false)); // Show dropdown
                     tr.appendChild(tdMapped);
                     tbody.appendChild(tr);
                 }
            });
        }


        // Add Header for Unmapped JSON Keys
        if (unmappedJsonRows.length > 0) {
            const unmappedHeaderRow = document.createElement('tr');
            const unmappedHeaderCell = document.createElement('th');
            unmappedHeaderCell.colSpan = 3;
            unmappedHeaderCell.textContent = 'Unmapped JSON Keys';
            unmappedHeaderCell.classList.add('category-header', 'unmapped-header');
            unmappedHeaderRow.appendChild(unmappedHeaderCell);
            tbody.appendChild(unmappedHeaderRow);
        }

        // Add Unmapped JSON Key Rows
        unmappedJsonRows.forEach(createRow);


        table.appendChild(tbody);
        outputTableContainer.appendChild(table);
        addDropdownListeners(); // Re-attach listeners after table generation
        // clearSummaryDisplay(); // Clear summary when table regenerates
        displayMappingSummary(); // Update summary display
    }


    function createArmorCodeDropdown(selectedField, isMappedRow) {
        const select = document.createElement('select');
        select.classList.add('armorcode-field-select');
        // If the row represents an initially unmapped JSON key, add a specific class
        if (!isMappedRow && selectedField === null) {
             select.classList.add('unmapped-json-key-row');
        }

        // Use the currently selected attribute type's list
        const optionsList = currentAttributeType === 'asset' ? allAssetFieldsWithNone : allFindingFieldsWithNone;

        optionsList.forEach(field => {
            const option = document.createElement('option');
            option.value = field === 'None' ? '' : field; // Store 'None' as empty string value
            option.textContent = field;
            if (field === selectedField) {
                option.selected = true;
            }
            select.appendChild(option);
        });
        return select;
    }


    function createPlaceholderJsonKeyDropdown(armorField) {
        const select = document.createElement('select');
        select.classList.add('json-key-select-placeholder'); // Use a specific class
        select.dataset.targetArmorcode = escapeHtml(armorField); // Store the target AC field

        // Add default option
        const defaultOption = document.createElement('option');
        defaultOption.value = '';
        defaultOption.textContent = '-- Select JSON Key --';
        select.appendChild(defaultOption);

        // Add options for discovered keys
        discoveredJsonKeys.sort().forEach(key => { // Sort keys alphabetically
            const option = document.createElement('option');
            option.value = escapeHtml(key); // Escape for safety
            option.textContent = key;
            select.appendChild(option);
        });
        return select;
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
        // Listener for ArmorCode Field selection changes (both mapped and unmapped rows)
        outputTableContainer.querySelectorAll('.armorcode-field-select').forEach(select => {
            select.removeEventListener('change', handleArmorCodeChange); // Prevent duplicate listeners
            select.addEventListener('change', handleArmorCodeChange);
        });

        // Listener for JSON Key selection changes in UNMAPPED JSON Key rows
        // (These dropdowns are generated by createJsonKeyDropdown, typically for "Tags (Add New)")
        outputTableContainer.querySelectorAll('.json-key-select:not(.json-key-select-tags-add)').forEach(select => {
             select.removeEventListener('change', handleJsonKeyChange); // Prevent duplicate listeners
             select.addEventListener('change', handleJsonKeyChange);
        });

        // Listener for JSON Key selection changes in PLACEHOLDER ArmorCode rows
        outputTableContainer.querySelectorAll('.json-key-select-placeholder').forEach(select => {
            select.removeEventListener('change', handleJsonKeyChange); // Prevent duplicate listeners
            select.addEventListener('change', handleJsonKeyChange); // Use the same handler
        });


        // Listener for the "Add New Tag" JSON key dropdown
        outputTableContainer.querySelectorAll('.json-key-select-tags-add').forEach(select => {
            select.addEventListener('change', handleTagsAddChange);
        });
    }

    function handleArmorCodeChange(event) {
        const selectElement = event.target;
        const newArmorCodeField = selectElement.value; // This is the AC field selected in the dropdown
        const tableRow = selectElement.closest('tr');
        const originalJsonKey = tableRow.dataset.jsonKey; // Key associated with this row (might be placeholder)
        const isUnmappedAcRow = tableRow.classList.contains('unmapped-ac-row');


        console.log(`AC Change: Row JSON Key: ${originalJsonKey}, New AC Field: ${newArmorCodeField}, Is Placeholder Row: ${isUnmappedAcRow}`);


        if (isUnmappedAcRow) {
            // --- Handling change on a placeholder AC row ---
            const originalArmorCodeField = selectElement.querySelector('option[selected]').textContent; // Get the AC field this row represents

             console.log(` -> Placeholder Row Change. Original AC Field: ${originalArmorCodeField}`);


            // 1. Remove potential previous mapping for the NEW AC field (if any)
             if (newArmorCodeField && currentMappings[newArmorCodeField]) {
                console.log(` -> New AC field '${newArmorCodeField}' was already mapped to JSON key '${currentMappings[newArmorCodeField]}'. Removing old mapping.`);
                 // If the old mapping was for Tags, remove the specific original AC field if present
                if (newArmorCodeField === 'Tags' && Array.isArray(currentMappings[newArmorCodeField])) {
                     const index = currentMappings[newArmorCodeField].indexOf(currentMappings[newArmorCodeField]); // This seems wrong, should be JSON key?
                     // TODO: This logic needs review. How do we know which JSON key to remove from Tags?
                } else {
                     currentMappings[newArmorCodeField] = null; // Clear single mapping
                }
            }


             // 2. Clear the mapping for the ORIGINAL AC field represented by this row
             if (originalArmorCodeField && currentMappings[originalArmorCodeField] !== null) {
                 console.log(` -> Clearing existing mapping for original AC field '${originalArmorCodeField}'`);
                 currentMappings[originalArmorCodeField] = null;
             }


             // 3. If a new AC field (not 'None') was selected, mark it as unmapped for now.
             //    The user needs to select a JSON key using the *other* dropdown mechanism (e.g., for Tags or via JSON key rows).
             //    For direct 1-to-1 mapping from placeholder, this isn't the primary flow.
             if (newArmorCodeField) {
                 console.warn(` -> Mapping AC field '${newArmorCodeField}' directly from a placeholder row is not fully supported yet. Regenerating table.`);
                  // Mark the new field as unmapped so it appears correctly
                 if(currentMappings[newArmorCodeField] === undefined){ // Should not happen, but safety check
                      currentMappings[newArmorCodeField] = null;
                 }
             } else {
                 console.log(" -> 'None' selected on placeholder row. Original AC field remains unmapped.");
             }

        } else {
             // --- Handling change on a regular JSON key row ---
             const jsonKeyForThisRow = originalJsonKey;
             console.log(` -> Regular Row Change. JSON Key: ${jsonKeyForThisRow}`);


            // Find which AC field (if any) *was* previously mapped to this JSON key
             let previousArmorCodeField = null;
             for (const acField in currentMappings) {
                 if (currentMappings[acField] === jsonKeyForThisRow) {
                     previousArmorCodeField = acField;
                     break;
                 } else if (acField === 'Tags' && Array.isArray(currentMappings[acField]) && currentMappings[acField].includes(jsonKeyForThisRow)) {
                     previousArmorCodeField = 'Tags'; // Special handling for tags
                     break;
                 }
             }
              console.log(` -> Previous AC mapping for this JSON key: ${previousArmorCodeField}`);


            // 1. Clear the previous mapping for this JSON key
             if (previousArmorCodeField) {
                 if (previousArmorCodeField === 'Tags') {
                     const index = currentMappings['Tags'].indexOf(jsonKeyForThisRow);
                     if (index > -1) {
                         currentMappings['Tags'].splice(index, 1);
                         console.log(` -> Removed '${jsonKeyForThisRow}' from Tags array.`);
                     }
                 } else {
                     currentMappings[previousArmorCodeField] = null;
                      console.log(` -> Cleared single mapping for '${previousArmorCodeField}'.`);
                 }
             }


            // 2. Handle potential conflict with the NEW AC field selection
            if (newArmorCodeField) { // If a specific field (not 'None') was selected
                const existingJsonKeyForNewField = currentMappings[newArmorCodeField];
                 console.log(` -> Checking for conflicts with new AC field '${newArmorCodeField}'. Currently mapped to: ${existingJsonKeyForNewField}`);


                if (existingJsonKeyForNewField) {
                    // Conflict: The chosen AC field is already mapped to a DIFFERENT JSON key.
                    // We need to clear that old mapping.
                     console.warn(` -> Conflict detected! '${newArmorCodeField}' was mapped to '${existingJsonKeyForNewField}'. Clearing old mapping.`);
                    currentMappings[newArmorCodeField] = null;
                     // We also need to find the row for that other JSON key and update its dropdown to 'None' in the UI (handled by regenerateTable)
                }


                 // 3. Apply the new mapping
                 if (newArmorCodeField === 'Tags') {
                     if (!Array.isArray(currentMappings['Tags'])) {
                         currentMappings['Tags'] = []; // Initialize if needed
                     }
                     if (!currentMappings['Tags'].includes(jsonKeyForThisRow)) {
                         currentMappings['Tags'].push(jsonKeyForThisRow);
                         console.log(` -> Added '${jsonKeyForThisRow}' to Tags array.`);
                     }
                 } else {
                     currentMappings[newArmorCodeField] = jsonKeyForThisRow;
                     console.log(` -> Mapped '${newArmorCodeField}' to '${jsonKeyForThisRow}'.`);
                 }
            } else {
                 console.log(` -> 'None' selected. JSON Key '${jsonKeyForThisRow}' is now unmapped.`);
            }
        }


        regenerateTableWithState(); // Regenerate table to reflect all changes and ensure consistency
    }

    function handleJsonKeyChange(event) {
        const select = event.target;
        const selectedJsonKey = select.value;
        const targetArmorCodeField = select.dataset.targetArmorcode;

        console.log(`JSON Key Change: Target AC Field '${targetArmorCodeField}', Selected JSON Key: '${selectedJsonKey}'`);

        // --- Logic for Updating Mappings ---

        // 1. Clear any previous mapping *for this specific ArmorCode field*
        // This handles cases where the user changes the JSON key selection for an AC field.
        if (currentMappings[targetArmorCodeField]) {
            console.log(` -> Clearing previous mapping for '${targetArmorCodeField}' (was: ${currentMappings[targetArmorCodeField]})`);
            currentMappings[targetArmorCodeField] = null;
        }
         // Special handling for Tags: If the previous mapping was the *only* key in the Tags array, clear Tags.
         // If other keys remain, we don't clear the whole Tags mapping here. The removal logic for Tags is complex
         // and primarily handled when the *ArmorCode* field dropdown changes. This prevents accidental full clears.
         // NOTE: This function primarily handles mapping *to* an AC field.

        // 2. Check if the *selected JSON key* is already mapped to a *different* ArmorCode field.
        let conflictingAcField = null;
        for (const acField in currentMappings) {
            if (acField === 'Tags' && Array.isArray(currentMappings[acField]) && currentMappings[acField].includes(selectedJsonKey)) {
                // Check if the selected key is in the Tags array
                if (acField !== targetArmorCodeField) { // Don't conflict with itself if target is Tags
                   conflictingAcField = acField; // It's used in Tags
                   break;
                }
            } else if (currentMappings[acField] === selectedJsonKey && acField !== targetArmorCodeField) {
                // Check if the selected key is mapped to a different single AC field
                conflictingAcField = acField;
                break;
            }
        }

        // 3. Handle conflict: If the selected JSON key is already used elsewhere, clear that old mapping.
        if (conflictingAcField) {
             console.warn(` -> Conflict: Selected JSON key '${selectedJsonKey}' is already mapped to '${conflictingAcField}'. Clearing old mapping for '${conflictingAcField}'.`);
            if (conflictingAcField === 'Tags' && Array.isArray(currentMappings['Tags'])) {
                // Remove the specific key from the Tags array
                currentMappings['Tags'] = currentMappings['Tags'].filter(key => key !== selectedJsonKey);
                if (currentMappings['Tags'].length === 0) {
                    currentMappings['Tags'] = null; // Clear Tags if empty
                }
            } else {
                // Clear the single mapping
                currentMappings[conflictingAcField] = null;
            }
        }


        // 4. Apply the new mapping if a valid JSON key was selected
        if (selectedJsonKey) {
            // Map the selected JSON key to the target AC field
            console.log(` -> Mapping '${targetArmorCodeField}' to '${selectedJsonKey}'`);
            currentMappings[targetArmorCodeField] = selectedJsonKey;

             // If the placeholder row's AC dropdown still shows the AC field name (meaning it wasn't changed),
             // ensure the AC dropdown in the corresponding JSON key row (if it exists) is updated to 'None'.
             // This is handled implicitly by regenerateTableWithState, as the conflictingAcField logic above clears the old mapping.

        } else {
            // If '-- Select JSON Key --' was chosen, the target AC field remains unmapped (already cleared in step 1).
            console.log(` -> '-- Select JSON Key --' chosen. '${targetArmorCodeField}' remains unmapped.`);
        }


        // Regenerate the table to reflect the state change and update all dropdowns
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
         // Check direct mappings first
         if (currentMappings[armorCodeField] && typeof currentMappings[armorCodeField] === 'string') {
             return currentMappings[armorCodeField];
         }
         // If checking for Tags, return the array (or null if empty/not array)
         if (armorCodeField === 'Tags') {
            return (Array.isArray(currentMappings['Tags']) && currentMappings['Tags'].length > 0) ? currentMappings['Tags'] : null;
         }
         // Check if any other single mapping uses this AC field (shouldn't happen with current logic but safe check)
         for(const acField in currentMappings){
             if(currentMappings[acField] === armorCodeField && acField !== 'Tags'){
                 // This indicates a potential state issue where AC field name is stored as value? Log warning.
                 console.warn(`Potential state issue: Found ArmorCode field '${armorCodeField}' stored as a value for key '${acField}'. Returning null.`);
                 return null;
             }
         }

        return null; // Not found or mapped to multiple keys (excluding Tags)
    }

    function regenerateTableWithState() {
        // Don't reset mappings here, just regenerate the table based on the current state
        console.log("Regenerating table with current mappings:", JSON.stringify(currentMappings));
        generateTable(); // Use the existing generateTable function
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

    async function copyTableToClipboard(table) {
        let plainText = '';
        const rows = table.querySelectorAll('tbody > tr'); // Get all body rows
        const headers = ["JSON Key", "JSON Value", "Mapped Armor Code Field"]; // Match visible headers
        plainText += headers.join('\t') + '\n';
        let rowCount = 0;

        // --- Create a temporary clone for HTML processing ---
        const tableClone = document.createElement('table');
        const tbodyClone = document.createElement('tbody');
        tableClone.appendChild(tbodyClone);
        // Apply basic table styles inline for HTML copy
        tableClone.style.borderCollapse = 'collapse';
        tableClone.style.width = '100%';
        tableClone.style.border = '1px solid #ddd';

        // Add Header row to the clone for HTML output
        const headerRowClone = document.createElement('tr');
        headers.forEach(headerText => {
            const th = document.createElement('th');
            th.textContent = headerText;
            th.style.border = '1px solid #ddd';
            th.style.padding = '8px';
            th.style.textAlign = 'left';
            th.style.backgroundColor = '#f2f2f2'; // Match visual style
            th.style.fontWeight = 'bold';
            headerRowClone.appendChild(th);
        });
        tbodyClone.appendChild(headerRowClone); // Add header to the body clone for simplicity

        // --- Iterate through original rows to build Plain Text and HTML Clone ---
        rows.forEach((row) => {
            if (row.querySelector('th.category-header')) {
                return; // Skip category header rows
            }

            const cells = row.querySelectorAll('td');
            if (cells.length !== 3) { // Ensure it's a data row with 3 cells
                return;
            }

            let jsonKeyValue = '';
            let jsonValueText = '';
            let armorCodeValue = '';

            // Cell 1: JSON Key (might be text or select)
            const keyCell = cells[0];
            const keySelect = keyCell.querySelector('.json-key-select-placeholder'); // Check for placeholder dropdown
            const keyInputSelect = keyCell.querySelector('.json-key-select'); // Check for unmapped JSON row dropdown
            if (keySelect) {
                jsonKeyValue = keySelect.value;
            } else if (keyInputSelect) {
                jsonKeyValue = keyInputSelect.value;
            } else {
                jsonKeyValue = keyCell.textContent.trim();
            }

            // Cell 2: JSON Value (always text content)
            const valueCell = cells[1];
            jsonValueText = valueCell.textContent.trim();

            // Cell 3: Armorcode Field (always a select in current setup)
            const mappedCell = cells[2];
            const mappedSelect = mappedCell.querySelector('.armorcode-field-select');
            if (mappedSelect) {
                armorCodeValue = mappedSelect.value;
            } else {
                 // Fallback, though should ideally not happen for data rows
                armorCodeValue = mappedCell.textContent.trim();
            }

            // --- Filtering Logic ---
            // Skip if ArmorCode field is 'None' or empty
            if (!armorCodeValue || armorCodeValue === 'None' || armorCodeValue === '') {
                return;
            }
            // Skip placeholder rows where no JSON key was selected
            if (keySelect && !jsonKeyValue) {
                return; // Placeholder dropdown exists but no value selected
            }
            // Skip unmapped JSON Key rows where no ArmorCode field was selected
             if (keyInputSelect && !armorCodeValue) {
                 return; // Unmapped key row dropdown exists but no AC field selected
             }

            // Construct the plain text row string
            const plainRowData = [
                jsonKeyValue,
                jsonValueText,
                armorCodeValue
            ];
            plainText += plainRowData.join('\t') + '\n';

            // --- Add filtered row to the HTML Clone ---
            const trClone = document.createElement('tr');
            plainRowData.forEach(cellData => {
                const td = document.createElement('td');
                td.textContent = cellData;
                // Apply inline styles for borders and padding
                td.style.border = '1px solid #ddd';
                td.style.padding = '8px';
                td.style.verticalAlign = 'top';
                trClone.appendChild(td);
            });
            tbodyClone.appendChild(trClone);

            rowCount++;
        });

        // Remove trailing newline if exists
        plainText = plainText.trimEnd();

        if (rowCount === 0) {
             console.warn("No valid mapped data found to copy.");
             errorMessages.textContent = 'No valid mapped data to copy.';
            return false; // Indicate nothing was copied
        }

        // --- Get the HTML string from the clone ---
        const htmlString = tableClone.outerHTML;

        try {
            // Use Clipboard API to write both formats
            const blobHtml = new Blob([htmlString], { type: 'text/html' });
            const blobText = new Blob([plainText], { type: 'text/plain' });
            const clipboardItem = new ClipboardItem({
                'text/html': blobHtml,
                'text/plain': blobText
            });
            await navigator.clipboard.write([clipboardItem]);
            console.log("Table copied to clipboard (HTML & Plain Text)!");
            errorMessages.textContent = '';
            return true; // Indicate success
        } catch (err) {
            console.error('Failed to copy table: ', err);
            // Fallback: Try plain text only if ClipboardItem fails (e.g., older browser)
            try {
                await navigator.clipboard.writeText(plainText);
                console.warn("Copied as plain text only (ClipboardItem API might have failed).");
                errorMessages.textContent = ''; // Clear error if plain text fallback succeeds
                return true; // Still indicate success as *something* was copied
            } catch (textErr) {
                console.error('Failed to copy plain text fallback: ', textErr);
                errorMessages.textContent = `Error: Could not copy to clipboard. ${textErr.message}`;
                return false; // Indicate failure
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

    function displayMappingSummary() {
        const jsonOutputElement = document.getElementById('finalJsonOutput'); // Make sure you have an element with this ID
        const summaryContainer = document.getElementById('mappingSummaryContainer'); // Container for the summary

        if (!summaryContainer) {
            console.error("Summary container not found!");
            return;
        }
         summaryContainer.innerHTML = ''; // Clear previous summary

         let mappedCount = 0;
         let totalFields = 0;
         const list = document.createElement('ul');

        // Use the correct field list based on current selection
        const fieldsToList = currentAttributeType === 'asset' ? assetFields : findingFields;

         fieldsToList.forEach(field => {
             totalFields++;
             const mappedJson = findJsonKeyForArmorCode(field); // Use helper to find mapped JSON key(s)
             const listItem = document.createElement('li');
             listItem.textContent = `${field}: `;
             if (mappedJson) {
                 mappedCount++;
                 listItem.classList.add('mapped');
                 if (field === 'Tags' && Array.isArray(mappedJson)) {
                     listItem.textContent += mappedJson.join(', ');
                 } else {
                    listItem.textContent += mappedJson;
                 }

             } else {
                 listItem.classList.add('unmapped');
                 listItem.textContent += ' (Not Mapped)';
             }
             list.appendChild(listItem);
         });

         const summaryText = document.createElement('p');
         summaryText.textContent = `Mapping Summary (${currentAttributeType} attributes): ${mappedCount} of ${totalFields} fields mapped.`;
         summaryContainer.prepend(summaryText); // Add summary text before the list
         summaryContainer.appendChild(list);
    }
}); 