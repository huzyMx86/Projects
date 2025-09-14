// STIX Generator JavaScript - Main Application Logic
// This file handles the main converter interface and user interactions

class STIXGenerator {
  constructor() {
    // Initialise all UI elements and event handlers
    this.setupElements();
    this.setupEventListeners();
    this.relationships = []; // Store user-defined relationships
    this.availableObjects = []; // Store detected objects for relationship building
  }

  /**
   * Sets up references to all DOM elements used by the application
   */
  setupElements() {
    // Get references to main UI elements
    this.inputArea = document.getElementById("inputArea");
    this.relationshipsList = document.getElementById("relationshipsList");
    this.generateBtn = document.getElementById("generateBtn");
    this.clearBtn = document.getElementById("clearBtn");
    this.addRelationshipBtn = document.getElementById("addRelationshipBtn");
    this.suggestionsList = document.getElementById("suggestionsList");

    // Get references to modal elements
    this.relationshipModal = document.getElementById("relationshipModal");
    this.sourceObject = document.getElementById("sourceObject");
    this.targetObject = document.getElementById("targetObject");
    this.relationshipType = document.getElementById("relationshipType");
    this.saveRelationshipBtn = document.getElementById("saveRelationshipBtn");
    this.cancelRelationshipBtn = document.getElementById(
      "cancelRelationshipBtn"
    );
    this.closeModal = document.querySelector(".close");
  }

  /**
   * Attaches event listeners to all interactive elements
   */
  setupEventListeners() {
    // Input field event listener
    if (this.inputArea) {
      this.inputArea.addEventListener("input", () => this.handleInputChange());
    }

    // Button event listeners
    if (this.generateBtn)
      this.generateBtn.addEventListener("click", () => this.generateSTIX());
    if (this.clearBtn)
      this.clearBtn.addEventListener("click", () => this.clearAll());
    if (this.addRelationshipBtn) {
      this.addRelationshipBtn.addEventListener("click", () =>
        this.openRelationshipModal()
      );
    }

    // Modal button event listeners
    if (this.saveRelationshipBtn) {
      this.saveRelationshipBtn.addEventListener("click", () =>
        this.saveRelationship()
      );
    }

    if (this.cancelRelationshipBtn) {
      this.cancelRelationshipBtn.addEventListener("click", () =>
        this.closeRelationshipModal()
      );
    }

    if (this.closeModal) {
      this.closeModal.addEventListener("click", () =>
        this.closeRelationshipModal()
      );
    }

    // Close modal when clicking outside of it
    window.addEventListener("click", (e) => {
      if (e.target === this.relationshipModal) {
        this.closeRelationshipModal();
      }
    });
  }

  /**
   * Handles changes to the input text area
   * Updates button states and triggers suggestion updates
   */
  handleInputChange() {
    const text = this.inputArea.value.trim();
    this.updateButtons();
    this.handleLiveSuggestions();
  }

  /**
   * Fetches and displays live suggestions based on current word being typed
   */
  async handleLiveSuggestions() {
    const text = this.inputArea.value;
    const cursorPosition = this.inputArea.selectionStart;

    // Get the text before the cursor
    const beforeCursor = text.substring(0, cursorPosition);
    const words = beforeCursor.split(/\s+/);
    const currentWord = words[words.length - 1];

    // Only search for suggestions if word is at least 2 characters
    if (currentWord.length < 2) {
      this.showDefaultSuggestions();
      return;
    }

    try {
      // Call the API for suggestions
      const response = await fetch("/api/live-suggestions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ current_word: currentWord }),
      });

      const data = await response.json();

      // Display suggestions if any were found
      if (data.suggestions && data.suggestions.length > 0) {
        this.displaySuggestions(data.suggestions, currentWord);
      } else {
        // Show confirmation that the word looks good
        this.suggestionsList.innerHTML = `
          <div class="suggestion-item">
            <span class="suggestion-icon">✅</span>
            <span>"${currentWord}" looks good</span>
          </div>
        `;
      }
    } catch (error) {
      // Show default message on error
      this.showDefaultSuggestions();
    }
  }

  /**
   * Displays the list of suggestions in the UI
   * @param {Array} suggestions - Array of suggestion objects
   * @param {String} currentWord - The word being typed
   */
  displaySuggestions(suggestions, currentWord) {
    const suggestionsHtml = suggestions
      .map((suggestion) => {
        return `
          <div class="suggestion-item" onclick="stixGenerator.applySuggestion('${currentWord}', '${suggestion.word}')">
            <span class="suggestion-icon">💡</span>
            <span>${suggestion.word}</span>
          </div>
        `;
      })
      .join("");

    this.suggestionsList.innerHTML = suggestionsHtml;
  }

  /**
   * Shows the default suggestion message when no input is detected
   */
  showDefaultSuggestions() {
    this.suggestionsList.innerHTML = `
      <div class="suggestion-item">
        <span class="suggestion-icon">🔍</span>
        <span>Type threat intelligence terms to see suggestions...</span>
      </div>
    `;
  }

  /**
   * Replaces the current word with the selected suggestion
   * @param {String} original - The original word being replaced
   * @param {String} suggested - The suggested replacement word
   */
  applySuggestion(original, suggested) {
    const text = this.inputArea.value;
    const cursorPosition = this.inputArea.selectionStart;

    // Calculate the position of the current word
    const beforeCursor = text.substring(0, cursorPosition);
    const afterCursor = text.substring(cursorPosition);
    const words = beforeCursor.split(/\s+/);
    const currentWord = words[words.length - 1];

    // Replace the current word with the suggestion
    const beforeWord = text.substring(0, cursorPosition - currentWord.length);
    const newText = beforeWord + suggested + afterCursor;

    this.inputArea.value = newText;

    // Move cursor to end of the suggested word
    const newCursorPosition = beforeWord.length + suggested.length;
    this.inputArea.setSelectionRange(newCursorPosition, newCursorPosition);
    this.inputArea.focus();

    // Reset suggestions panel
    this.showDefaultSuggestions();
  }

  /**
   * Updates the enabled/disabled state of buttons based on input
   */
  updateButtons() {
    const text = this.inputArea.value.trim();
    const wordCount = text
      .split(/\s+/)
      .filter((word) => word.length > 0).length;

    // Enable generate button only if there are at least 10 words
    this.generateBtn.disabled = wordCount < 10;
    // Enable clear button only if there is text
    this.clearBtn.disabled = text.length === 0;
  }

  /**
   * Sends the input text to the server for STIX conversion
   */
  async generateSTIX() {
    const text = this.inputArea.value.trim();
    const wordCount = text
      .split(/\s+/)
      .filter((word) => word.length > 0).length;

    // Validate minimum word count
    if (wordCount < 10) {
      this.showMessage("Please enter more text (at least 10 words)", "warning");
      return;
    }

    // Update button state while processing
    this.generateBtn.disabled = true;
    this.generateBtn.textContent = "Generating...";

    try {
      // Send conversion request to server
      const response = await fetch("/api/convert", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: text,
          relationships: this.relationships,
        }),
      });

      const data = await response.json();

      if (data.stix) {
        // Store the STIX output in session storage
        sessionStorage.setItem("stixOutput", JSON.stringify(data.stix));
        // Navigate to results page
        window.location.href = "/results";
      } else {
        // Show error message if conversion failed
        this.showMessage(data.error || "Generation failed", "error");
      }
    } catch (error) {
      // Handle network errors
      this.showMessage("Network error occurred", "error");
    } finally {
      // Reset button state
      this.generateBtn.disabled = false;
      this.generateBtn.textContent = "Generate STIX";
    }
  }

  /**
   * Clears all input and relationships
   */
  clearAll() {
    this.inputArea.value = "";
    this.relationships = [];
    this.updateRelationshipsList();
    this.updateButtons();
    this.showDefaultSuggestions();
    this.showMessage("All content cleared", "info");
  }

  /**
   * Loads available objects from the current text for relationship building
   */
  async loadAvailableObjects() {
    try {
      // Request object extraction from server
      const response = await fetch("/api/get-objects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: this.inputArea.value.trim() }),
      });

      const data = await response.json();
      this.availableObjects = data.objects || [];
    } catch (error) {
      this.showMessage("Error loading objects", "error");
    }
  }

  /**
   * Opens the relationship creation modal
   */
  openRelationshipModal() {
    // Load objects first, then show modal
    this.loadAvailableObjects().then(() => {
      this.populateObjectDropdowns();
      this.relationshipModal.style.display = "block";
    });
  }

  /**
   * Closes the relationship creation modal and resets form
   */
  closeRelationshipModal() {
    this.relationshipModal.style.display = "none";
    // Reset form fields
    this.sourceObject.value = "";
    this.targetObject.value = "";
    this.relationshipType.value = "";
  }

  /**
   * Populates the dropdown menus with detected objects
   */
  populateObjectDropdowns() {
    // Clear existing options
    this.sourceObject.innerHTML =
      '<option value="">Select source object...</option>';
    this.targetObject.innerHTML =
      '<option value="">Select target object...</option>';

    // Add each object as an option in both dropdowns
    this.availableObjects.forEach((obj) => {
      const option = document.createElement("option");
      option.value = obj.name;
      option.textContent = `${obj.name} (${obj.type})`;

      // Add to both source and target dropdowns
      this.sourceObject.appendChild(option.cloneNode(true));
      this.targetObject.appendChild(option);
    });
  }

  /**
   * Saves a new relationship between two objects
   */
  saveRelationship() {
    const sourceName = this.sourceObject.value;
    const targetName = this.targetObject.value;
    const relationshipType = this.relationshipType.value;

    // Validate all fields are filled
    if (!sourceName || !targetName || !relationshipType) {
      this.showMessage("Please fill in all fields", "warning");
      return;
    }

    // Prevent self-referential relationships
    if (sourceName === targetName) {
      this.showMessage("Source and target cannot be the same", "warning");
      return;
    }

    // Create relationship object
    const relationship = {
      source_name: sourceName,
      target_name: targetName,
      relationship_type: relationshipType,
    };

    // Add to relationships array
    this.relationships.push(relationship);
    this.updateRelationshipsList();
    this.closeRelationshipModal();
    this.showMessage("Relationship created successfully!", "success");
  }

  /**
   * Updates the display of created relationships
   */
  updateRelationshipsList() {
    // Show default message if no relationships exist
    if (this.relationships.length === 0) {
      this.relationshipsList.innerHTML = `
        <div class="relationship-item">
          <span class="relationship-icon">🔗</span>
          <span>No relationships created yet. Click "Add Relationship" to create one.</span>
        </div>
      `;
      return;
    }

    // Display each relationship with remove button
    this.relationshipsList.innerHTML = this.relationships
      .map(
        (rel, index) => `
        <div class="relationship-item">
          <span class="relationship-icon">🔗</span>
          <span>${rel.source_name} <strong>${rel.relationship_type}</strong> ${rel.target_name}</span>
          <button onclick="stixGenerator.removeRelationship(${index})" class="secondary-btn" style="margin-left: auto; padding: 5px 10px; font-size: 12px;">Remove</button>
        </div>
      `
      )
      .join("");
  }

  /**
   * Removes a relationship at the specified index
   * @param {Number} index - Index of the relationship to remove
   */
  removeRelationship(index) {
    this.relationships.splice(index, 1);
    this.updateRelationshipsList();
    this.showMessage("Relationship removed", "info");
  }

  /**
   * Shows a temporary notification message to the user
   * @param {String} message - The message to display
   * @param {String} type - The type of message (success, error, warning, info)
   */
  showMessage(message, type) {
    // Create notification element
    const notification = document.createElement("div");
    notification.innerHTML = message;

    // Style the notification
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: ${this.getMessageColor(type)};
      color: white;
      padding: 10px 15px;
      border-radius: 4px;
      font-size: 14px;
      z-index: 1000;
    `;

    document.body.appendChild(notification);

    // Remove notification after 3 seconds
    setTimeout(() => {
      if (document.body.contains(notification)) {
        document.body.removeChild(notification);
      }
    }, 3000);
  }

  /**
   * Returns the appropriate color for a message type
   * @param {String} type - The message type
   * @returns {String} - The hex color code
   */
  getMessageColor(type) {
    const colors = {
      success: "#27ae60",
      error: "#e74c3c",
      warning: "#f39c12",
      info: "#3498db",
    };
    return colors[type] || colors.info;
  }
}

// Initialise the application when the page loads
let stixGenerator;
document.addEventListener("DOMContentLoaded", function () {
  stixGenerator = new STIXGenerator();
});
