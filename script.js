document.addEventListener('DOMContentLoaded', () => {
    const jsonInput = document.getElementById('jsonInput');
    const processBtn = document.getElementById('processBtn');
    const outputTableContainer = document.getElementById('outputTableContainer');
    const errorMessages = document.getElementById('errorMessages');
    const copyBtn = document.getElementById('copyBtn');
    const renderDescriptionLayoutBtn = document.getElementById('renderDescriptionLayoutBtn');
    const container = document.querySelector('.container');
    const outputSection = document.querySelector('.output-section');
    const attributeSelect = document.getElementById('attributeTypeSelect');

    // --- NEW: Input Type Handling Elements ---
    const inputTypeRadios = document.querySelectorAll('input[name="inputType"]');
    const jsonInputArea = document.getElementById('jsonInputArea');
    const csvInputArea = document.getElementById('csvInputArea');
    const fileInputCsv = document.getElementById('fileInputCsv');
    const fileNameDisplayCsv = document.getElementById('fileNameDisplayCsv');

    // --- State for input type ---
    let currentInputMode = 'json'; // Default to JSON

    // Description Modal Elements
    const descriptionModal = document.getElementById('descriptionModal');
    const closeDescriptionModalBtn = document.getElementById('closeDescriptionModalBtn');
    const combinedSortableItemsList = document.getElementById('combinedSortableItems');
    const combinedPreviewArea = document.getElementById('combinedPreviewArea');
    const copyRenderedDescriptionBtn = document.getElementById('copyRenderedDescriptionBtn');

    // Description Modal State
    let draggedItemModal = null; // For drag/drop tracking
    // Stores the ordered list of items, including category markers
    // Example: [{type: 'header', category: 'description'}, {type: 'item', key: 'plugin.description'}, ...]
    let modalLayoutData = [];
    const descriptionCategories = ['description', 'steps', 'remediation', 'impact']; // Order matters
    const descriptionCategoryFields = {
        description: 'Description',
        steps: 'Steps to Reproduce',
        remediation: 'Remediation',
        impact: 'Impact'
    };
    const categoryTitleMap = {
        description: "Description",
        steps: "Steps to Reproduce",
        remediation: "Remediation",
        impact: "Impact"
    };

    // Store discovered JSON keys for dropdown
    let discoveredJsonKeys = [];
    // Store the flattened JSON data for value lookups
    let flattenedJsonData = {};
    // Store the current mapping state: { armorCodeField: jsonKey | null }
    let currentMappings = {};
    // Store the selected attribute type
    let currentAttributeType = 'finding'; // Default to finding

    let uploadedFileContent = null;
    let uploadedFileType = null; // 'json' or 'csv' - this might be simplified if only one file input active at a time
    let currentRecordObjectForSave = null; // To store the processed record for saving

    // --- NEW: Listener for Input Type Change ---
    inputTypeRadios.forEach(radio => {
        radio.addEventListener('change', (event) => {
            currentInputMode = event.target.value;
            errorMessages.textContent = ''; // Clear errors on mode switch
            uploadedFileContent = null; // Clear any previously uploaded file content
            
            if (currentInputMode === 'json') {
                jsonInputArea.style.display = 'block';
                csvInputArea.style.display = 'none';
                processBtn.textContent = 'Process JSON';
                fileNameDisplayCsv.textContent = ''; // Clear CSV file name display
                fileInputCsv.value = ''; // Reset file input
            } else if (currentInputMode === 'csv') {
                jsonInputArea.style.display = 'none';
                csvInputArea.style.display = 'block';
                processBtn.textContent = 'Process CSV';
                jsonInput.value = ''; // Clear JSON text area
            }
        });
    });

    // --- NEW: Listener for CSV File Input ---
    fileInputCsv.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (e) => {
                uploadedFileContent = e.target.result;
                // For CSV input, we strictly expect CSV type based on this input field.
                // No need to guess uploadedFileType like before.
                fileNameDisplayCsv.textContent = file.name;
                errorMessages.textContent = ''; // Clear previous errors
            };
            reader.onerror = () => {
                errorMessages.textContent = 'Error reading CSV file.';
                uploadedFileContent = null;
                fileNameDisplayCsv.textContent = '';
            };
            reader.readAsText(file);
        } else {
            uploadedFileContent = null;
            fileNameDisplayCsv.textContent = '';
        }
    });

    // --- Armor Code Asset Fields ---
    const assetFields = [
        "ID", "Name","Tags", "Type", "OS", "First Seen", "Owner", "Source", "Status", "IP Address",
        "DNS Name", "OS Version", "Cloud Provider", "Cloud Account ID",
        "Cloud Resource Type", "Location", "Image Repo", "Registry",
        "Cluster", "Namespace", "Cloud Resource", "Publicly Accessible", "Region",
        "Runtime", "Architecture", "VPC ID", "Role", "Version", "Storage Type",
        "Engine Version", "Engine", "Instance Status", "Subnet IDs",
        "Last Seen", "Asset Subtype", "MAC Address" // Added new fields
    ];
    const assetFieldsLower = assetFields.map(field => field.toLowerCase());
    const allAssetFieldsWithNone = ['None', ...assetFields];


    // --- Categorized Armor Code Finding Fields ---
    const armorCodeFieldCategories = {
        "Core": ["ID", "Summary", "CVE", "CWE", "Category", "Finding URL", "Description", "Steps to Reproduce", "Impact", "Remediation", "Component Name", "Component Affected Version", "Component Fix Version", "Tags"],
        "Tool Details": ["Tool Finding ID", "Tool Severity", "Tool Finding Status", "Tool Finding Category", "Fixable Using Tool"],
        "Risk & Severity": ["Severity", "Base Score", "CVSS Vector", "Exploit Maturity", "Exploited", "CISA KEV", "EPSS Score", "EPSS Percentile"],
        "Status & Dates": ["Status", "Latest Tool Scan Date", "Found On", "Last Seen Date", "CVE Published Date", "CVE Modified Date"],
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

    // --- NEW: Sidebar Elements ---
    const sidebar = document.getElementById('sidebar');
    const sidebarToggleBtn = document.getElementById('sidebarToggleBtn'); // New toggle button
    const mappingCountBadge = document.getElementById('mappingCountBadge'); // New badge
    const saveMappingBtn = document.getElementById('saveMappingBtn');
    const savedMappingsList = document.getElementById('savedMappingsList');

    // --- NEW: Saved Mappings State ---
    let savedMappings = []; // Array to hold { name: string, json: string, config: object, type: string }
    const LOCAL_STORAGE_KEY = 'fieldMapperSavedMappings';

    // --- NEW: Function to parse CSV to an array of objects ---
    function parseCsv(csvString) {
        // Normalize line endings to \n and then split
        const lines = csvString.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim().split('\n');
        
        if (lines.length === 0 || (lines.length === 1 && lines[0].trim() === '')) {
            console.warn("CSV string is empty or contains only whitespace after normalization.");
            return [];
        }

        // Extract headers: split by comma, trim whitespace from each header
        const headers = lines[0].split(',').map(header => header.trim());
        
        // Validate headers
        if (headers.length === 0 || (headers.length === 1 && headers[0] === '')) {
            console.warn("CSV headers are empty or invalid.");
            return []; // No valid headers
        }
        if (headers.some(header => header === '')) {
            console.warn("CSV contains empty header fields. This might cause issues.");
            // Depending on strictness, you might choose to throw an error or filter them out
        }

        const records = [];

        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (line === '') continue; // Skip empty lines

            // Simple split by comma for values. For more complex CSVs (e.g., with commas in quotes), a more robust parser would be needed.
            const values = line.split(',').map(value => value.trim());
            
            if (values.length === headers.length) {
                const record = {};
                headers.forEach((header, index) => {
                    // Ensure we don't try to assign to an empty header key
                    if (header) { 
                        record[header] = values[index];
                    }
                });
                // Only add record if it has at least one property (in case all headers were empty and skipped)
                if (Object.keys(record).length > 0) {
                    records.push(record);
                }
            } else {
                console.warn(`Skipping CSV line ${i + 1}: Mismatch in number of columns. Expected ${headers.length}, got ${values.length}. Line content: "${line}"`);
            }
        }
        return records;
    }

    // --- NEW: Function to display results based on current state ---
    function displayProcessedResults() {
        console.log("Displaying processed results with current mappings:", JSON.stringify(currentMappings));
        // Ensure field lists are set based on currentAttributeType
        if (currentAttributeType === 'asset') {
            armorCodeFields = assetFields;
            armorCodeFieldsLower = assetFieldsLower;
            allArmorCodeFieldsWithNone = allAssetFieldsWithNone;
        } else { // Default to 'finding'
            armorCodeFields = findingFields;
            armorCodeFieldsLower = findingFieldsLower;
            allArmorCodeFieldsWithNone = allFindingFieldsWithNone;
        }

        // Flatten the current record object for save
        try {
            if (!currentRecordObjectForSave) {
                 throw new Error("No record object available to display. Process input first.");
            }
             flattenedJsonData = flattenObject(currentRecordObjectForSave); // Use the stored record object
             discoveredJsonKeys = Object.keys(flattenedJsonData);
        } catch (e) {
             console.error("Error flattening JSON during display setup:", e);
             errorMessages.textContent = `Error processing current JSON: ${e.message}`;
             outputTableContainer.innerHTML = '<p>Error displaying results.</p>';
             // Hide buttons on error
             copyBtn.style.display = 'none';
             saveMappingBtn.style.display = 'none';
             renderDescriptionLayoutBtn.style.display = 'none';
             container.classList.remove('results-active');
             return; // Stop processing
        }

        // Generate the table using the current state
        generateTable();

        // Show relevant buttons
        copyBtn.style.display = 'inline-block';
        saveMappingBtn.style.display = 'inline-block';
        if (currentAttributeType === 'finding') {
            renderDescriptionLayoutBtn.style.display = 'inline-block';
        }
        container.classList.add('results-active');
        displayMappingSummary(); // Update summary
    }

    // Process Button Listener (Refactored)
    processBtn.addEventListener('click', () => {
        // Reset state and UI
        flattenedJsonData = {};
        discoveredJsonKeys = [];
        currentMappings = {}; 
        currentRecordObjectForSave = null; 
        container.classList.remove('results-active');
        outputTableContainer.innerHTML = '<p>Processing...</p>';
        copyBtn.style.display = 'none';
        saveMappingBtn.style.display = 'none';
        renderDescriptionLayoutBtn.style.display = 'none';
        closeModal(descriptionModal);
        clearSummaryDisplay();
        errorMessages.textContent = '';

        currentAttributeType = attributeSelect.value;

        let inputDataString = '';
        let processingMode = currentInputMode; // Use the selected mode

        if (processingMode === 'csv') {
            if (!uploadedFileContent) {
                errorMessages.textContent = 'Please select a CSV file to process.';
                outputTableContainer.innerHTML = '<p>Processed results will appear here.</p>';
                return;
            }
            inputDataString = uploadedFileContent;
            console.log(`Processing CSV file: ${fileNameDisplayCsv.textContent}`);
        } else { // Default to JSON processing
            inputDataString = jsonInput.value.trim();
            console.log(`Processing text area input (JSON)`);
            if (!inputDataString) {
                errorMessages.textContent = 'Please paste JSON data.';
                outputTableContainer.innerHTML = '<p>Processed results will appear here.</p>';
                return;
            }
        }

        try {
            let jsonData; 
            if (processingMode === 'csv') {
                const parsedCsv = parseCsv(inputDataString);
                if (parsedCsv.length === 0) {
                    throw new Error('CSV file is empty or could not be parsed correctly.');
                }
                jsonData = parsedCsv; 
            } else { // JSON processing
                jsonData = JSON.parse(inputDataString);
            }

            // --- Find Record --- (Modified to handle array from CSV or JSON array)
            let recordObject = null;
            if (Array.isArray(jsonData)) {
                if (jsonData.length > 0) recordObject = jsonData[0]; // Use first element if array
                else throw new Error('Input array is empty.');
            } else if (typeof jsonData === 'object' && jsonData !== null && jsonData.data && Array.isArray(jsonData.data)) {
                 if (jsonData.data.length > 0) recordObject = jsonData.data[0];
                 else throw new Error('Input array under \'data\' key is empty.');
            } else if (typeof jsonData === 'object' && jsonData !== null) {
                recordObject = jsonData; // It's already a single object
            } else {
                throw new Error('Could not find a suitable record object in the input.');
            }

            currentRecordObjectForSave = recordObject; // Store the determined record object for later use (e.g. saving)

            // --- Perform Initial Auto-Mapping --- 
            const tempFlattened = flattenObject(recordObject); // Flatten temporarily for mapping
            const initialMappingResults = {};
            const mappedJsonKeys = new Set();
            const tempDiscoveredKeys = Object.keys(tempFlattened);

            // Initialize currentMappings (based on selected type *before* loop)
            const fieldsForMapping = currentAttributeType === 'asset' ? assetFields : findingFields;
            const fieldsForMappingLower = currentAttributeType === 'asset' ? assetFieldsLower : findingFieldsLower;
            fieldsForMapping.forEach(field => currentMappings[field] = null);

            // Define which fields can have multiple mappings (Needed for initial mapping logic here)
            const multiMappingFields = ['Tags', 'IP Address', 'URL/Endpoint', 'Repository', 'Description', 'Steps to Reproduce', 'Remediation', 'Impact', 'DNS Name']; // Corrected to IP Address (singular)

            for (const key in tempFlattened) {
                if (Object.hasOwnProperty.call(tempFlattened, key)) {
                    const baseKey = key.split('.').pop().toLowerCase();
                    if (ignoredKeys.includes(baseKey)) continue;
                    
                    // Pass currently selected fields to findMapping context if needed by findMapping itself
                    const mappedField = findMapping(key, fieldsForMapping, fieldsForMappingLower); 
                    
                    // Only store the first mapping found (excluding multi-fields handled later)
                    if (mappedField && !multiMappingFields.includes(mappedField) && !Object.values(initialMappingResults).includes(mappedField)) {
                         initialMappingResults[key] = mappedField;
                         mappedJsonKeys.add(key);
                    } else if (mappedField && multiMappingFields.includes(mappedField) && !mappedJsonKeys.has(key)) {
                         // Allow multi-mapping field only if the key isn't already mapped more specifically
                         initialMappingResults[key] = mappedField;
                         mappedJsonKeys.add(key);
                    }
                }
            }

            // Apply initial mappings to currentMappings
            for (const [jsonKey, armorField] of Object.entries(initialMappingResults)) {
                if (multiMappingFields.includes(armorField)) {
                    if (!Array.isArray(currentMappings[armorField])) currentMappings[armorField] = [];
                    if (!currentMappings[armorField].includes(jsonKey)) currentMappings[armorField].push(jsonKey);
                } else {
                    if (currentMappings[armorField] === null) currentMappings[armorField] = jsonKey;
                    else console.warn(`Initial map conflict for ${armorField}. Key ${jsonKey} ignored.`);
                }
            }
            // --- End Initial Auto-Mapping ---

            // Call the display function
            displayProcessedResults();

        } catch (error) {
            console.error("Processing Error:", error);
            errorMessages.textContent = `Error processing JSON: ${error.message}`;
            outputTableContainer.innerHTML = '<p>Processed results will appear here.</p>';
            container.classList.remove('results-active');
            copyBtn.style.display = 'none';
            saveMappingBtn.style.display = 'none';
            renderDescriptionLayoutBtn.style.display = 'none';
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

    // --- Description Layout Modal Logic (Simplified) ---

    // Open Modal
    renderDescriptionLayoutBtn.addEventListener('click', () => {
        // 1. Gather all keys mapped to the relevant AC fields
        const keysByCategory = {};
        let totalKeys = 0;
        descriptionCategories.forEach(cat => {
            const acField = descriptionCategoryFields[cat];
            const mappedKeys = currentMappings[acField];
            if (Array.isArray(mappedKeys)) {
                keysByCategory[cat] = [...mappedKeys]; // Copy array
                totalKeys += mappedKeys.length;
            } else if (typeof mappedKeys === 'string') {
                keysByCategory[cat] = [mappedKeys]; // Put single key in array
                totalKeys += 1;
            } else {
                keysByCategory[cat] = []; // No keys mapped
            }
        });

        if (totalKeys === 0) {
            alert('No JSON fields are currently mapped to Description, Steps to Reproduce, Remediation, or Impact.');
            return;
        }

        // 2. Initialize modalLayoutData based on gathered keys
        modalLayoutData = [];
        descriptionCategories.forEach(cat => {
            if (keysByCategory[cat].length > 0) {
                // Add category header marker
                modalLayoutData.push({ type: 'header', category: cat });
                // Add item markers for this category
                keysByCategory[cat].forEach(key => {
                    modalLayoutData.push({ type: 'item', key: key, category: cat });
                });
            }
        });

        // 3. Populate the UI
        populateCombinedList();
        updateCombinedPreview();
        openModal(descriptionModal);
    });

    // Close Modal
    closeDescriptionModalBtn.addEventListener('click', () => closeModal(descriptionModal));
    // Optional: Close modal if clicking outside the content
    window.addEventListener('click', (event) => {
        if (event.target == descriptionModal) {
            closeModal(descriptionModal);
        }
    });

    function openModal(modalElement) {
        if (modalElement) modalElement.style.display = 'flex'; // Use flex to enable centering
    }

    function closeModal(modalElement) {
         if (modalElement) modalElement.style.display = 'none';
    }

    // Populate the single combined sortable list
    function populateCombinedList() {
        combinedSortableItemsList.innerHTML = ''; // Clear previous content

        modalLayoutData.forEach(entry => {
            if (entry.type === 'header') {
                const headerDiv = document.createElement('div');
                headerDiv.classList.add('sortable-category-header');
                headerDiv.textContent = categoryTitleMap[entry.category];
                headerDiv.dataset.category = entry.category;
                combinedSortableItemsList.appendChild(headerDiv);
            } else if (entry.type === 'item') {
                const jsonKey = entry.key;
                const value = flattenedJsonData[jsonKey];
                const item = document.createElement('div');
                item.classList.add('description-item-modal');
                item.draggable = true;
                item.dataset.jsonKey = jsonKey;
                item.dataset.category = entry.category; // Store original category

                const keySpan = document.createElement('span');
                keySpan.classList.add('item-key');
                keySpan.textContent = jsonKey;

                const valuePreviewSpan = document.createElement('span');
                valuePreviewSpan.classList.add('item-value-preview');
                valuePreviewSpan.textContent = formatValue(value);

                item.appendChild(keySpan);
                item.appendChild(valuePreviewSpan);

                // Add Drag Listeners to the item
                item.addEventListener('dragstart', handleDragStartModal);
                item.addEventListener('dragend', handleDragEndModal);

                combinedSortableItemsList.appendChild(item);
            }
        });

        // Add common listeners to the container *once* after populating
        combinedSortableItemsList.removeEventListener('dragover', handleDragOverModal);
        combinedSortableItemsList.removeEventListener('drop', handleDropModal);
        combinedSortableItemsList.addEventListener('dragover', handleDragOverModal);
        combinedSortableItemsList.addEventListener('drop', handleDropModal);
    }

    // Update the single combined preview area
    function updateCombinedPreview() {
        let previewHTML = '';
        let firstSection = true;

        if (modalLayoutData.length === 0) {
            combinedPreviewArea.innerHTML = `<p style="color: #888; font-style: italic;">(No items mapped or arranged)</p>`;
            return;
        }

        modalLayoutData.forEach((entry, index) => {
            if (entry.type === 'header') {
                // Add separator before the new header (unless it's the first section)
                if (!firstSection) {
                    previewHTML += `<hr style="margin: 15px 0; border: none; border-top: 1px solid #eee;">`; // Use HR for visual separation
                }
                previewHTML += `<h4 style="margin-bottom: 8px; font-weight: bold;">${escapeHtml(categoryTitleMap[entry.category])}</h4>`; // Use H4 for section titles
                firstSection = false;
            } else if (entry.type === 'item') {
                const key = entry.key;
                const value = flattenedJsonData[key] || '';
                const formattedValue = formatValue(value); // Get the potentially multi-line value
                const formattedTitle = formatJsonKeyForTitle(key);

                // Add item details using paragraphs and line breaks
                previewHTML += `<p style="margin-bottom: 10px;">`; // Add some space below each item
                previewHTML += `<strong>${escapeHtml(formattedTitle)}</strong><br>`; // Title on its own line
                // Replace newline characters in the value with <br> tags for HTML rendering
                previewHTML += escapeHtml(formattedValue).replace(/\n/g, '<br>');
                previewHTML += `</p>`;
            }
        });

        combinedPreviewArea.innerHTML = previewHTML;
    }

    // Copy the structured content from the single rendered preview
    copyRenderedDescriptionBtn.addEventListener('click', async () => {
        let markdownText = '';
        let htmlContent = '';
        let hasContent = false;

        modalLayoutData.forEach((entry, index) => {
             if (entry.type === 'header') {
                 hasContent = true;
                 const categoryTitle = categoryTitleMap[entry.category];
                 if (index > 0) { // Add separator before new section in both formats
                    markdownText += `\n-----\n\n`;
                    htmlContent += `<hr>`;
                 }
                 markdownText += `## ${categoryTitle}\n\n`;
                 htmlContent += `<h2>${escapeHtml(categoryTitle)}</h2>`;
             } else if (entry.type === 'item') {
                 hasContent = true;
                 const key = entry.key;
                 const value = flattenedJsonData[key] || '';
                 const formattedValue = formatValue(value);
                 const formattedTitle = formatJsonKeyForTitle(key);
                 const escapedValue = escapeHtml(formattedValue);
                 const escapedFormattedTitle = escapeHtml(formattedTitle);

                 // Markdown
                 markdownText += `**${formattedTitle}**\n${formattedValue}`;
                 // HTML
                 htmlContent += `<p><strong>${escapedFormattedTitle}</strong><br>${escapedValue.replace(/\n/g, '<br>')}</p>`;

                 // Check if next item is different type or end of list to add spacing
                 const nextEntry = modalLayoutData[index + 1];
                 if (nextEntry && nextEntry.type === 'item') {
                    markdownText += '\n\n'; // Space between items in the same category
                 }
             }
        });


        if (!hasContent) {
            alert('Nothing to copy. Please add/map fields to description sections.');
            return;
        }

        // --- Final Clipboard Operations ---
        markdownText = markdownText.trim();
        htmlContent = htmlContent.trim();

        try {
            // Use ClipboardItem API for rich text
            const blobHtml = new Blob([htmlContent], { type: 'text/html' });
            const blobText = new Blob([markdownText], { type: 'text/plain' });
            const clipboardItem = new ClipboardItem({
                'text/html': blobHtml,
                'text/plain': blobText
            });
            await navigator.clipboard.write([clipboardItem]);

             // --- Feedback ---
            copyRenderedDescriptionBtn.textContent = 'Copied!';
            copyRenderedDescriptionBtn.disabled = true;
            setTimeout(() => {
                copyRenderedDescriptionBtn.textContent = 'Copy Rendered Description';
                copyRenderedDescriptionBtn.disabled = false;
            }, 2000);

        } catch (err) {
            console.error('Failed to copy rendered description using ClipboardItem: ', err);
            // Fallback attempt: Try copying only plain text (Markdown)
            try {
                await navigator.clipboard.writeText(markdownText);
                copyRenderedDescriptionBtn.textContent = 'Copied as Markdown!';
                copyRenderedDescriptionBtn.disabled = true;
                setTimeout(() => {
                    copyRenderedDescriptionBtn.textContent = 'Copy Rendered Description';
                    copyRenderedDescriptionBtn.disabled = false;
                }, 2500);
                 console.warn('ClipboardItem failed, copied as plain text (Markdown) instead.');
            } catch (textErr) {
                console.error('Failed to copy plain text fallback: ', textErr);
                alert('Failed to copy description. Clipboard API error.');
            }
        }
    });

    // --- Drag and Drop Handlers for Modal (Simplified) ---
    function handleDragStartModal(e) {
        // Only allow dragging items, not headers
        if (!this.classList.contains('description-item-modal')) {
            e.preventDefault();
            return;
        }
        draggedItemModal = this; // The element being dragged
        setTimeout(() => this.classList.add('dragging'), 0);
        e.dataTransfer.effectAllowed = 'move';
        // Store JSON key (enough data to identify the item)
        e.dataTransfer.setData('text/plain', this.dataset.jsonKey);
    }

    function handleDragEndModal() {
        // Clear dragging state regardless of drop success
         if (draggedItemModal) {
            draggedItemModal.classList.remove('dragging');
         }
         draggedItemModal = null;
         // Update the preview after drop completes
         updateCombinedPreview();
    }

    function handleDragOverModal(e) {
        e.preventDefault(); // Necessary to allow dropping
        e.dataTransfer.dropEffect = 'move';

        const targetList = combinedSortableItemsList; // Only one list now
        if (!targetList || !draggedItemModal) return;

        const afterElement = getDragAfterElementModal(targetList, e.clientY);

        // Insert the dragged item visually for immediate feedback
        if (afterElement == null) {
            targetList.appendChild(draggedItemModal);
        } else {
            // Prevent dropping onto a header
            if (!afterElement.classList.contains('sortable-category-header')) {
                targetList.insertBefore(draggedItemModal, afterElement);
            }
        }
    }

    function handleDropModal(e) {
        e.preventDefault();
        const targetList = combinedSortableItemsList; // Only one list now

        if (!targetList || !draggedItemModal) {
            console.warn("Drop occurred but draggedItemModal is null.");
            return;
        }

        // --- Update the underlying modalLayoutData state --- //
        const currentKey = draggedItemModal.dataset.jsonKey;

        // 1. Find the current index of the dragged item in the DOM
        const domItems = Array.from(targetList.children);
        const newDomIndex = domItems.indexOf(draggedItemModal);
        if (newDomIndex < 0) {
             console.error(`Could not find dropped item ${currentKey} in the DOM.`);
             return; // Abort if visual item not found
        }

        // 2. Remove the item marker from its old position in modalLayoutData
        const oldLayoutIndex = modalLayoutData.findIndex(item => item.type === 'item' && item.key === currentKey);
        if (oldLayoutIndex < 0) {
            console.error(`Could not find item ${currentKey} in modalLayoutData.`);
            return; // Abort if data item not found
        }
        const [removedItemData] = modalLayoutData.splice(oldLayoutIndex, 1);

        // 3. Determine the new position in modalLayoutData based on the DOM position
        let newLayoutIndex = 0;
        let elementCounter = 0;
        for (let i = 0; i < domItems.length; i++) {
            if (domItems[i] === draggedItemModal) {
                newLayoutIndex = elementCounter;
                break;
            }
            // Only increment counter for actual data elements (items or headers)
            if (domItems[i].classList.contains('description-item-modal') || domItems[i].classList.contains('sortable-category-header')) {
                 elementCounter++;
            }
        }

        // 4. Insert the item marker at the new position in modalLayoutData
        modalLayoutData.splice(newLayoutIndex, 0, removedItemData);

        // 5. Recalculate category for the moved item and potentially others
        // (Headers don't move, so find the preceding header for the dropped item)
        let currentItemCategory = 'description'; // Default if no header found before it
        for (let i = newLayoutIndex - 1; i >= 0; i--) {
             if (modalLayoutData[i].type === 'header') {
                 currentItemCategory = modalLayoutData[i].category;
                 break;
             }
        }
        removedItemData.category = currentItemCategory;
        draggedItemModal.dataset.category = currentItemCategory; // Update DOM dataset too

        // --- Update the Preview --- (moved to dragend for efficiency)
        // updateCombinedPreview();

        console.log("Updated modalLayoutData:", modalLayoutData);

    }

    // Helper function for modal drag/drop positioning (Simplified)
    function getDragAfterElementModal(container, y) {
         // Consider all direct children (items and headers)
         const draggableElements = [...container.querySelectorAll(':scope > .description-item-modal:not(.dragging), :scope > .sortable-category-header')];

        return draggableElements.reduce((closest, child) => {
            const box = child.getBoundingClientRect();
            const offset = y - box.top - box.height / 2;
            if (offset < 0 && offset > closest.offset) {
                return { offset: offset, element: child };
            } else {
                return closest;
            }
        }, { offset: Number.NEGATIVE_INFINITY }).element;
    }

    // --- Helper to format JSON Key for Display Titles ---
    function formatJsonKeyForTitle(jsonKey) {
        if (!jsonKey || typeof jsonKey !== 'string') {
            return jsonKey ? jsonKey.toString() + ':' : ''; // Handle non-strings or empty
        }

        // List of acronyms to keep uppercase
        const acronyms = ['ID', 'IP', 'OS', 'DNS', 'VPC', 'CVE', 'CWE', 'CVSS', 'URL', 'KEV', 'CISA'];
        const acronymsLower = acronyms.map(a => a.toLowerCase());

        // Replace dots/underscores with spaces, then split into words
        const words = jsonKey.replace(/[._]/g, ' ').split(' ');

        const titleWords = words.map(word => {
            if (!word) return ''; // Skip empty strings resulting from multiple separators
            const lowerWord = word.toLowerCase();
            const acronymIndex = acronymsLower.indexOf(lowerWord);

            if (acronymIndex !== -1) {
                return acronyms[acronymIndex]; // Return the correct casing from the acronyms list
            } else {
                // Capitalize the first letter, lowercase the rest
                return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
            }
        });

        // Join words, filter out empty strings, and add colon
        return titleWords.filter(Boolean).join(' ') + ':';
    }

    // --- End Modal Logic ---

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

    function findMapping(jsonKey, fieldsForMapping, fieldsForMappingLower) {
        // Use the currently active armorCodeFieldsLower for mapping
        const keyLower = jsonKey.split('.').pop().toLowerCase(); // Use the last part of the key for matching
        const index = fieldsForMappingLower.indexOf(keyLower);

        // 1. Direct Match (case-insensitive)
        if (index !== -1) {
            // Use the currently active armorCodeFields list
            return fieldsForMapping[index]; // Return the original case field name
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
            // New EPSS and CVE Date mappings
            if (keyLower === 'epss_score' || keyLower === 'epssscore') return 'EPSS Score';
            if (keyLower === 'epss_percentile' || keyLower === 'epsspercentile') return 'EPSS Percentile';
            if (keyLower === 'cve_published_date' || keyLower === 'cve_published' || keyLower === 'published_date' || keyLower === 'publish_date') return 'CVE Published Date';
            if (keyLower === 'cve_modified_date' || keyLower === 'cve_modified' || keyLower === 'modified_date' || keyLower === 'last_modified_date') return 'CVE Modified Date';
        } else if (currentAttributeType === 'asset') {
             // Add specific asset mapping rules here if needed in the future
             // Example: if (keyLower === 'operating_system') return 'OS';
            if (keyLower === 'tags') return 'Tags'; // Map 'tags' directly if asset
            if (keyLower === 'last_seen' || keyLower === 'lastseen') return 'Last Seen';
            if (keyLower === 'asset_subtype' || keyLower === 'assetsubtype' || keyLower === 'asset_sub_type') return 'Asset Subtype';
            if (keyLower === 'mac_address' || keyLower === 'macaddress') return 'MAC Address';
            if (keyLower === 'ip' || keyLower === 'ip_address' || keyLower === 'host_ip') return 'IP Address'; // Ensure IP Address is correctly mapped for assets too
            if (keyLower === 'dns_name' || keyLower === 'dnsname' || keyLower === 'hostname') return 'DNS Name'; // Ensure DNS Name is correctly mapped for assets
        }


        // 3. General "Tags" check (moved lower priority)
        // If the key contains 'tag' and wasn't matched above, suggest 'Tags'
        // This check applies to both finding and asset attributes.
        if (keyLower.includes('tag')) {
             // Check if 'Tags' exists in the current field list
             const tagsFieldIndex = fieldsForMappingLower.indexOf('tags');
             if (tagsFieldIndex !== -1) {
                 return fieldsForMapping[tagsFieldIndex]; // Return 'Tags' with correct casing
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
        ['JSON Key', 'JSON Value (Sample)', 'ArmorCode Field'].forEach(text => {
            const th = document.createElement('th');
            th.textContent = text;
            headerRow.appendChild(th);
        });
        thead.appendChild(headerRow);
        table.appendChild(thead);

        // Store rows by ArmorCode field for sorting/grouping later if needed
        const rowsByArmorCodeField = {};
        const unmappedJsonRowsData = []; // Store data for unmapped JSON rows
        const placeholderAcRows = []; // Store placeholder row elements

        // --- Populate Data Structures ---
        // Group mapped JSON keys by ArmorCode field
        for (const armorField in currentMappings) {
            const jsonKeyOrKeys = currentMappings[armorField];

            if (jsonKeyOrKeys) { // If mapped
                 if (!rowsByArmorCodeField[armorField]) {
                    rowsByArmorCodeField[armorField] = [];
                }
                if (Array.isArray(jsonKeyOrKeys)) {
                    jsonKeyOrKeys.forEach(jk => {
                         rowsByArmorCodeField[armorField].push({ jsonKey: jk, armorField: armorField, isMapped: true });
                    });
                } else { // Single mapping
                    rowsByArmorCodeField[armorField].push({ jsonKey: jsonKeyOrKeys, armorField: armorField, isMapped: true });
                }
            }
        }

        // Identify unmapped JSON keys
        const mappedJsonKeysInCurrentMappings = new Set();
        Object.values(currentMappings).forEach(val => {
            if (typeof val === 'string') mappedJsonKeysInCurrentMappings.add(val);
            else if (Array.isArray(val)) val.forEach(item => mappedJsonKeysInCurrentMappings.add(item));
        });

        discoveredJsonKeys.forEach(jsonKey => {
            if (!mappedJsonKeysInCurrentMappings.has(jsonKey)) {
                unmappedJsonRowsData.push({ jsonKey: jsonKey, armorField: null, isMapped: false });
            }
        });

         // --- Helper to Create a Single Row Element ---
        const createRowElement = (rowData) => {
            const tr = document.createElement('tr');
            const jsonKey = rowData.jsonKey;
            const mappedField = rowData.armorField;
            const sampleValue = flattenedJsonData[jsonKey]; // May be undefined for placeholders

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

            return tr;
        };

        // --- Helper to Create Placeholder Row Element ---
        const createPlaceholderRowElement = (armorField) => {
             const tr = document.createElement('tr');
             tr.classList.add('unmapped-ac-row');
             tr.dataset.jsonKey = `placeholder-for-${armorField}`; // Add a unique identifier

             const tdKey = document.createElement('td');
             tdKey.appendChild(createPlaceholderJsonKeyDropdown(armorField)); // Dropdown in the first column
             tr.appendChild(tdKey);

             const tdValue = document.createElement('td');
             tdValue.textContent = ''; // << CHANGE: Make the value cell blank
             tr.appendChild(tdValue);

             const tdMapped = document.createElement('td');
             tdMapped.appendChild(createArmorCodeDropdown(armorField, false)); // Show AC dropdown
             tr.appendChild(tdMapped);

             return tr;
        };

        // --- Generate and Append Rows in Order --- //

        // 1. Mapped ArmorCode Fields (Categorized or Flat)
        const processedMappedFields = new Set(); // Keep track of fields added
        if (currentAttributeType === 'finding') {
            Object.keys(armorCodeFieldCategories).forEach(category => {
                // Add category header
                const categoryHeaderRow = document.createElement('tr');
                const categoryHeaderCell = document.createElement('th');
                categoryHeaderCell.colSpan = 3; // Span across all columns
                categoryHeaderCell.textContent = category;
                categoryHeaderCell.classList.add('category-header');
                categoryHeaderRow.appendChild(categoryHeaderCell);
                tbody.appendChild(categoryHeaderRow);

                // Add rows for this category
                armorCodeFieldCategories[category].forEach(armorField => {
                    if (rowsByArmorCodeField[armorField]) {
                        rowsByArmorCodeField[armorField].forEach(rowData => {
                            tbody.appendChild(createRowElement(rowData));
                        });
                        processedMappedFields.add(armorField);
                    }
                });
            });

            // Add remaining mapped fields (e.g., Tags if not in a category)
            const remainingMappedFields = Object.keys(rowsByArmorCodeField).filter(f => !processedMappedFields.has(f));
            if (remainingMappedFields.length > 0) {
                // Add 'Other Mapped Fields' header if needed
                const remainingHeaderRow = document.createElement('tr');
                const remainingHeaderCell = document.createElement('th');
                remainingHeaderCell.colSpan = 3;
                remainingHeaderCell.textContent = "Other Mapped Fields";
                remainingHeaderCell.classList.add('category-header');
                remainingHeaderRow.appendChild(remainingHeaderCell);
                tbody.appendChild(remainingHeaderRow);
                remainingMappedFields.forEach(armorField => {
                    rowsByArmorCodeField[armorField].forEach(rowData => {
                        tbody.appendChild(createRowElement(rowData));
                    });
                    processedMappedFields.add(armorField);
                });
            }
        } else {
            // Render Asset Attributes (Flat List)
            armorCodeFields.forEach(armorField => {
                if (rowsByArmorCodeField[armorField]) {
                    rowsByArmorCodeField[armorField].forEach(rowData => {
                        tbody.appendChild(createRowElement(rowData));
                    });
                     processedMappedFields.add(armorField);
                }
            });
        }

        // 2. Unmapped JSON Keys
        if (unmappedJsonRowsData.length > 0) {
            const unmappedHeaderRow = document.createElement('tr');
            const unmappedHeaderCell = document.createElement('th');
            unmappedHeaderCell.colSpan = 3;
            unmappedHeaderCell.textContent = 'Unmapped JSON Keys';
            unmappedHeaderCell.classList.add('category-header', 'unmapped-header');
            unmappedHeaderRow.appendChild(unmappedHeaderCell);
            tbody.appendChild(unmappedHeaderRow);

            unmappedJsonRowsData.forEach(rowData => {
                tbody.appendChild(createRowElement(rowData));
            });
        }

        // 3. Placeholder Rows for Unmapped ArmorCode Fields (Generate and Store)
        const unmappedAcFields = [];
        armorCodeFields.forEach(armorField => {
             // Check if field was already added as a mapped field
            if (!processedMappedFields.has(armorField)) {
                 // Also check if it's currently mapped (even if rowsByArmorCodeField was empty, e.g. empty Tags array)
                const isCurrentlyMapped = currentMappings[armorField] !== null && 
                                          (!Array.isArray(currentMappings[armorField]) || currentMappings[armorField].length > 0);
                if (!isCurrentlyMapped) {
                    unmappedAcFields.push(armorField);
                    placeholderAcRows.push(createPlaceholderRowElement(armorField));
                }
            }
        });

        // Add Header for Placeholder Rows if any exist
        if (placeholderAcRows.length > 0) {
            const placeholderHeaderRow = document.createElement('tr');
            const placeholderHeaderCell = document.createElement('th');
            placeholderHeaderCell.colSpan = 3;
            placeholderHeaderCell.textContent = 'Unmapped ArmorCode Fields';
            placeholderHeaderCell.classList.add('category-header', 'placeholder-header'); // Add specific class
            placeholderHeaderRow.appendChild(placeholderHeaderCell);
            tbody.appendChild(placeholderHeaderRow);

            // Append stored placeholder rows
            placeholderAcRows.forEach(row => tbody.appendChild(row));
        }

        // --- Finalize Table ---
        table.appendChild(tbody);
        outputTableContainer.appendChild(table);
        addDropdownListeners(); // Re-attach listeners after table generation
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

        // Define which fields can have multiple mappings
        const multiMappingFields = ['Tags', 'IP Address', 'URL/Endpoint', 'Repository', 'Description', 'Steps to Reproduce', 'Remediation', 'Impact', 'DNS Name']; // Corrected to IP Address (singular)

        if (isUnmappedAcRow) {
            // --- Handling change on a placeholder AC row ---
            const originalArmorCodeField = selectElement.querySelector('option[selected]').textContent;

            console.log(` -> Placeholder Row Change. Original AC Field: ${originalArmorCodeField}`);

            // 1. Remove potential previous mapping for the NEW AC field (if any)
            if (newArmorCodeField && currentMappings[newArmorCodeField]) {
                console.log(` -> New AC field '${newArmorCodeField}' was already mapped.`);
                // Only clear if it's not a multi-mapping field
                if (!multiMappingFields.includes(newArmorCodeField)) {
                    currentMappings[newArmorCodeField] = null;
                }
            }

            // 2. Clear the mapping for the ORIGINAL AC field represented by this row
            if (originalArmorCodeField && currentMappings[originalArmorCodeField] !== null) {
                console.log(` -> Clearing existing mapping for original AC field '${originalArmorCodeField}'`);
                currentMappings[originalArmorCodeField] = null;
            }

            // 3. If a new AC field (not 'None') was selected, mark it as unmapped for now.
            if (newArmorCodeField) {
                console.warn(` -> Mapping AC field '${newArmorCodeField}' directly from a placeholder row is not fully supported yet. Regenerating table.`);
                if(currentMappings[newArmorCodeField] === undefined){
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
                } else if (Array.isArray(currentMappings[acField]) && currentMappings[acField].includes(jsonKeyForThisRow)) {
                    previousArmorCodeField = acField;
                    break;
                }
            }
            console.log(` -> Previous AC mapping for this JSON key: ${previousArmorCodeField}`);

            // 1. Clear the previous mapping for this JSON key
            if (previousArmorCodeField) {
                if (Array.isArray(currentMappings[previousArmorCodeField])) {
                    const index = currentMappings[previousArmorCodeField].indexOf(jsonKeyForThisRow);
                    if (index > -1) {
                        currentMappings[previousArmorCodeField].splice(index, 1);
                        console.log(` -> Removed '${jsonKeyForThisRow}' from ${previousArmorCodeField} array.`);
                    }
                } else {
                    currentMappings[previousArmorCodeField] = null;
                    console.log(` -> Cleared single mapping for '${previousArmorCodeField}'.`);
                }
            }

            // 2. Handle the NEW AC field selection
            if (newArmorCodeField) {
                // Initialize array for multi-mapping fields if needed
                if (multiMappingFields.includes(newArmorCodeField)) {
                    if (!Array.isArray(currentMappings[newArmorCodeField])) {
                        currentMappings[newArmorCodeField] = [];
                    }
                    if (!currentMappings[newArmorCodeField].includes(jsonKeyForThisRow)) {
                        currentMappings[newArmorCodeField].push(jsonKeyForThisRow);
                        console.log(` -> Added '${jsonKeyForThisRow}' to ${newArmorCodeField} array.`);
                    }
                } else {
                    // For single-mapping fields, check for conflicts
                    const existingJsonKeyForNewField = currentMappings[newArmorCodeField];
                    if (existingJsonKeyForNewField) {
                        console.warn(` -> Conflict detected! '${newArmorCodeField}' was mapped to '${existingJsonKeyForNewField}'. Clearing old mapping.`);
                        currentMappings[newArmorCodeField] = null;
                    }
                    currentMappings[newArmorCodeField] = jsonKeyForThisRow;
                    console.log(` -> Mapped '${newArmorCodeField}' to '${jsonKeyForThisRow}'.`);
                }
            } else {
                console.log(` -> 'None' selected. JSON Key '${jsonKeyForThisRow}' is now unmapped.`);
            }
        }

        regenerateTableWithState();
    }

    function handleJsonKeyChange(event) {
        const select = event.target;
        const selectedJsonKey = select.value;
        const targetArmorCodeField = select.dataset.targetArmorcode;

        console.log(`JSON Key Change: Target AC Field '${targetArmorCodeField}', Selected JSON Key: '${selectedJsonKey}'`);

        // Define which fields can have multiple mappings
        const multiMappingFields = ['Tags', 'IP Address', 'URL/Endpoint', 'Repository', 'Description', 'Steps to Reproduce', 'Remediation', 'Impact', 'DNS Name']; // Corrected to IP Address (singular)

        // 1. Clear any previous mapping *for this specific ArmorCode field*
        if (currentMappings[targetArmorCodeField]) {
            console.log(` -> Clearing previous mapping for '${targetArmorCodeField}' (was: ${currentMappings[targetArmorCodeField]})`);
            // Only clear if it's not a multi-mapping field
            if (!multiMappingFields.includes(targetArmorCodeField)) {
                currentMappings[targetArmorCodeField] = null;
            }
        }

        // 2. Check if the *selected JSON key* is already mapped to a *different* ArmorCode field
        let conflictingAcField = null;
        for (const acField in currentMappings) {
            if (Array.isArray(currentMappings[acField]) && currentMappings[acField].includes(selectedJsonKey)) {
                // Check if the selected key is in any multi-mapping field array
                if (acField !== targetArmorCodeField) {
                    conflictingAcField = acField;
                    break;
                }
            } else if (currentMappings[acField] === selectedJsonKey && acField !== targetArmorCodeField) {
                // Check if the selected key is mapped to a different single AC field
                conflictingAcField = acField;
                break;
            }
        }

        // 3. Handle conflict: If the selected JSON key is already used elsewhere, clear that old mapping
        if (conflictingAcField) {
            console.warn(` -> Conflict: Selected JSON key '${selectedJsonKey}' is already mapped to '${conflictingAcField}'. Clearing old mapping for '${conflictingAcField}'.`);
            if (Array.isArray(currentMappings[conflictingAcField])) {
                // Remove the specific key from the array
                currentMappings[conflictingAcField] = currentMappings[conflictingAcField].filter(key => key !== selectedJsonKey);
                if (currentMappings[conflictingAcField].length === 0) {
                    currentMappings[conflictingAcField] = null; // Clear if empty
                }
            } else {
                // Clear the single mapping
                currentMappings[conflictingAcField] = null;
            }
        }

        // 4. Apply the new mapping if a valid JSON key was selected
        if (selectedJsonKey) {
            if (multiMappingFields.includes(targetArmorCodeField)) {
                // Initialize array if needed
                if (!Array.isArray(currentMappings[targetArmorCodeField])) {
                    currentMappings[targetArmorCodeField] = [];
                }
                // Add the key if not already present
                if (!currentMappings[targetArmorCodeField].includes(selectedJsonKey)) {
                    currentMappings[targetArmorCodeField].push(selectedJsonKey);
                    console.log(` -> Added '${selectedJsonKey}' to ${targetArmorCodeField} array.`);
                }
            } else {
                // For single-mapping fields
                currentMappings[targetArmorCodeField] = selectedJsonKey;
                console.log(` -> Mapped '${targetArmorCodeField}' to '${selectedJsonKey}'.`);
            }
        } else {
            console.log(` -> '-- Select JSON Key --' chosen. '${targetArmorCodeField}' remains unmapped.`);
        }

        // Regenerate the table to reflect the state change and update all dropdowns
        regenerateTableWithState();
    }

    function handleTagsAddChange(event) {
        const select = event.target;
        const selectedJsonKey = select.value;
        const targetArmorCodeField = select.dataset.targetArmorcode;

        console.log(`Tags Add Change: Selected JSON Key: '${selectedJsonKey}' for field '${targetArmorCodeField}'`);

        if (selectedJsonKey) {
            // Initialize array if needed
            if (!currentMappings[targetArmorCodeField]) {
                currentMappings[targetArmorCodeField] = [];
            }

            // Add the selected key if not already present
            if (Array.isArray(currentMappings[targetArmorCodeField]) && !currentMappings[targetArmorCodeField].includes(selectedJsonKey)) {
                currentMappings[targetArmorCodeField].push(selectedJsonKey);
                console.log(` -> Added '${selectedJsonKey}' to ${targetArmorCodeField} array.`);
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

        // Hide render button if type is not finding, otherwise ensure it's visible
        renderDescriptionLayoutBtn.style.display = (currentAttributeType === 'finding') ? 'inline-block' : 'none';

        // Close the modal if the table is regenerated, as mappings might be invalid
        closeModal(descriptionModal);
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
        const headers = ["JSON Key", "JSON Value", "ArmorCode Field"]; // Match visible headers
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

    // --- NEW: Local Storage Functions ---
    function loadMappingsFromStorage() {
        const storedData = localStorage.getItem(LOCAL_STORAGE_KEY);
        if (storedData) {
            try {
                savedMappings = JSON.parse(storedData);
                if (!Array.isArray(savedMappings)) {
                    savedMappings = []; // Reset if data is corrupted
                    console.warn('Stored mapping data was not an array, resetting.');
                }
            } catch (e) {
                console.error('Error parsing saved mappings from Local Storage:', e);
                savedMappings = []; // Reset on parsing error
            }
        } else {
            savedMappings = []; // Initialize if nothing is stored
        }
        console.log('Loaded mappings:', savedMappings.length);
        // Update sidebar collapse state based on user interaction, not load
        // updateSidebarCollapseState(); // REMOVED
    }

    function saveMappingsToStorage() {
        try {
            localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(savedMappings));
        } catch (e) {
            console.error('Error saving mappings to Local Storage:', e);
            // Potentially notify user if storage is full
            alert('Error saving mapping. Local storage might be full.');
        }
    }

    function addMapping(name, json, config, type, sourceType = 'json-paste') {
        // Check for duplicate name (case-insensitive)
        const existingIndex = savedMappings.findIndex(m => m.name.toLowerCase() === name.toLowerCase());
        if (existingIndex !== -1) {
            if (!confirm(`A mapping named "${name}" already exists. Overwrite it?`)) {
                return false; // User cancelled overwrite
            }
            // Remove existing entry before adding the new one
            savedMappings.splice(existingIndex, 1);
        }

        const newMapping = {
            name: name,
            json: json,
            config: JSON.parse(JSON.stringify(config)), // Deep copy of config
            type: type,
            sourceType: sourceType // 'json-paste', 'json-file', 'csv-file'
        };
        savedMappings.push(newMapping);
        savedMappings.sort((a, b) => a.name.localeCompare(b.name)); // Keep sorted
        saveMappingsToStorage();
        // updateSidebarCollapseState(); // REMOVED - Manual toggle now
        renderSavedMappingsList(); // Update list which updates badge
        return true;
    }

    function deleteMapping(nameToDelete) {
        savedMappings = savedMappings.filter(m => m.name !== nameToDelete);
        saveMappingsToStorage();
        renderSavedMappingsList(); // Re-render the list after deletion, updates badge
        // updateSidebarCollapseState(); // REMOVED - Manual toggle now
    }

    // --- NEW: UI Function for Sidebar ---
    function renderSavedMappingsList() {
        savedMappingsList.innerHTML = ''; // Clear current list
        if (savedMappings.length === 0) {
            savedMappingsList.innerHTML = '<li class="no-mappings"><em>No mappings saved yet.</em></li>';
            return;
        }

        savedMappings.forEach(mapping => {
            const li = document.createElement('li');
            li.dataset.mappingName = mapping.name;

            const nameSpan = document.createElement('span');
            nameSpan.classList.add('mapping-name');
            nameSpan.textContent = mapping.name;
            nameSpan.title = `Click to load mapping: ${mapping.name}`; // Tooltip

            const deleteBtn = document.createElement('button');
            deleteBtn.classList.add('delete-mapping-btn');
            deleteBtn.innerHTML = '&times;'; // Multiplication sign for delete
            deleteBtn.title = `Delete mapping: ${mapping.name}`;
            deleteBtn.addEventListener('click', (e) => {
                e.stopPropagation(); // Prevent li click listener from firing
                if (confirm(`Are you sure you want to delete the mapping "${mapping.name}"?`)) {
                    deleteMapping(mapping.name);
                }
            });

            // NEW: Add placeholder for an icon
            const iconSpan = document.createElement('span');
            iconSpan.classList.add('mapping-icon');
            iconSpan.innerHTML = '&#128196;'; // Simple document icon

            // Assemble the list item
            li.appendChild(iconSpan); // Add icon first
            li.appendChild(nameSpan);
            li.appendChild(deleteBtn);

            // Add listener to load the mapping when the list item (not the delete button) is clicked
            li.addEventListener('click', () => {
                loadMapping(mapping.name);
            });

            savedMappingsList.appendChild(li);
        });

        // Update badge count
        const count = savedMappings.length;
        mappingCountBadge.textContent = count;
        mappingCountBadge.style.display = count > 0 ? 'inline-block' : 'none';

    }

    // --- NEW: Load Mapping Function (Refactored) ---
    function loadMapping(nameToLoad) {
        const mapping = savedMappings.find(m => m.name === nameToLoad);
        if (!mapping) {
            alert(`Error: Could not find saved mapping named "${nameToLoad}".`);
            return;
        }

        console.log(`Loading mapping: ${nameToLoad}`);

        // 1. Restore JSON Input
        jsonInput.value = mapping.json;

        // 2. Restore Attribute Type
        currentAttributeType = mapping.type;
        attributeSelect.value = currentAttributeType;

        // 3. Restore Mappings (important: use a deep copy)
        currentMappings = JSON.parse(JSON.stringify(mapping.config));

        // 4. Reset derived state & UI
        flattenedJsonData = {}; // Will be recalculated
        discoveredJsonKeys = []; // Will be recalculated
        container.classList.remove('results-active'); // Hide results initially
        outputTableContainer.innerHTML = '<p>Loading mapping...</p>';
        copyBtn.style.display = 'none';
        renderDescriptionLayoutBtn.style.display = 'none';
        saveMappingBtn.style.display = 'none'; // Hide Save button while loading
        closeModal(descriptionModal); // Close modal if open
        clearSummaryDisplay();

        // 5. Display the loaded state *without* re-processing initial mappings
        displayProcessedResults();

        // Optional: Add a visual cue that loading finished
        errorMessages.textContent = `Mapping "${nameToLoad}" loaded successfully.`;
        setTimeout(() => errorMessages.textContent = '', 3000); // Clear message after 3s
    }

    // --- NEW: Sidebar Toggle Listener ---
    sidebarToggleBtn.addEventListener('click', () => {
        sidebar.classList.toggle('sidebar-collapsed');
        // Ensure badge visibility is correctly updated based on count, regardless of collapsed state
        const count = savedMappings.length;
        mappingCountBadge.style.display = count > 0 ? 'inline-block' : 'none'; 
        // The line above correctly handles showing the badge if count > 0, whether collapsed or not.
        // The commented-out line below was an alternative consideration and is not needed.
        // mappingCountBadge.style.display = (sidebar.classList.contains('sidebar-collapsed') && count > 0) ? 'inline-block' : 'none';
    });

    // --- Re-applying Save Button Listener ---
    // Ensure this listener is correctly placed within DOMContentLoaded
    saveMappingBtn.addEventListener('click', () => {
        // Check if mappings exist (i.e., after processing)
        if (!currentMappings || Object.keys(currentMappings).length === 0) {
            alert('Please process some JSON/CSV and configure mappings before saving.');
            return;
        }
        if (!currentRecordObjectForSave) { 
            alert('No processed data available to save. Please process input first.');
            return;
        }

        const mappingName = prompt('Enter a name for this mapping configuration:');
        if (!mappingName || mappingName.trim() === '') {
            return;
        }

        const jsonToSave = JSON.stringify(currentRecordObjectForSave, null, 2); 
        let sourceTypeOfSave = 'json-paste'; // Default

        if (currentInputMode === 'csv' && uploadedFileContent) { 
            sourceTypeOfSave = 'csv-file';
        } else if (currentInputMode === 'json') { 
            // If JSON mode, it implies either paste or potentially a JSON file upload if we were to add that back.
            // For now, this logic correctly identifies pasted JSON vs CSV file.
            sourceTypeOfSave = 'json-paste'; // Or determine if it was from a JSON file if that feature is re-added
        }
        
        const configToSave = currentMappings;
        const typeToSave = currentAttributeType;

        if (addMapping(mappingName.trim(), jsonToSave, configToSave, typeToSave, sourceTypeOfSave)) {
            renderSavedMappingsList(); 
            alert(`Mapping \"${mappingName.trim()}\" saved successfully!`);
             sidebar.classList.remove('sidebar-collapsed'); 
        }
    });

    // --- Initial Load ---
    loadMappingsFromStorage();
    renderSavedMappingsList(); // Renders list and updates badge
    // Ensure sidebar is collapsed by default
    sidebar.classList.add('sidebar-collapsed');
}); 