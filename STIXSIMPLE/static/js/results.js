// Results Page JavaScript - STIX Results Handler
// This file manages the display and export of generated STIX data

class STIXResults {
  constructor() {
    // Initialise component references and load data
    this.setupElements();
    this.loadResults();
    this.setupEventListeners();
  }

  /**
   * Gets references to all UI elements on the results page
   */
  setupElements() {
    this.outputArea = document.getElementById("outputArea");
    this.copyBtn = document.getElementById("copyBtn");
    this.downloadBtn = document.getElementById("downloadBtn");
    this.editBtn = document.getElementById("editBtn");
    this.newAnalysisBtn = document.getElementById("newAnalysisBtn");
  }

  /**
   * Sets up event listeners for all interactive elements
   */
  setupEventListeners() {
    // Attach click handlers to buttons
    this.copyBtn.addEventListener("click", () => this.copyToClipboard());
    this.downloadBtn.addEventListener("click", () => this.downloadJSON());
    this.editBtn.addEventListener("click", () => this.toggleEditable());
    this.newAnalysisBtn.addEventListener("click", () =>
      this.startNewAnalysis()
    );
  }

  /**
   * Loads the STIX results from session storage and displays them
   */
  loadResults() {
    try {
      // Retrieve STIX data from session storage
      const stixOutput = sessionStorage.getItem("stixOutput");

      if (stixOutput) {
        // Parse and format the JSON for display
        const stixData = JSON.parse(stixOutput);
        this.outputArea.value = JSON.stringify(stixData, null, 2);

        // Log the number of objects for debugging
        console.log("STIX objects loaded:", stixData.objects?.length || 0);
      } else {
        // Show error message if no data found
        this.outputArea.value =
          "No STIX data found. Please generate STIX first.";
      }
    } catch (error) {
      // Handle JSON parsing errors
      console.log("Error loading results:", error);
      this.outputArea.value = "Error loading STIX data.";
    }
  }

  /**
   * Toggles the edit mode for the output text area
   */
  toggleEditable() {
    // Check current state of the text area
    const isEditable = !this.outputArea.hasAttribute("readonly");

    if (isEditable) {
      // Make text area read-only
      this.outputArea.setAttribute("readonly", true);
      this.editBtn.classList.remove("active");
    } else {
      // Make text area editable
      this.outputArea.removeAttribute("readonly");
      this.editBtn.classList.add("active");
    }
  }

  /**
   * Copies the STIX JSON to the clipboard
   */
  copyToClipboard() {
    // Check if there is content to copy
    if (this.outputArea.value.trim()) {
      // Try modern clipboard API first
      navigator.clipboard
        .writeText(this.outputArea.value)
        .then(() =>
          this.showMessage("STIX JSON copied to clipboard!", "success")
        )
        .catch(() => {
          // Fallback to older method if modern API fails
          this.outputArea.select();
          document.execCommand("copy");
          this.showMessage("STIX JSON copied to clipboard!", "success");
        });
    } else {
      this.showMessage("No content to copy", "warning");
    }
  }

  /**
   * Downloads the STIX JSON as a file
   */
  downloadJSON() {
    // Check if there is content to download
    if (this.outputArea.value.trim()) {
      try {
        // Parse JSON to validate it
        const jsonData = JSON.parse(this.outputArea.value);

        // Create a blob with the formatted JSON
        const blob = new Blob([JSON.stringify(jsonData, null, 2)], {
          type: "application/json",
        });

        // Create download link
        const url = URL.createObjectURL(blob);
        const downloadLink = document.createElement("a");
        downloadLink.href = url;
        // Generate filename with timestamp
        downloadLink.download = "stix-bundle-" + new Date().getTime() + ".json";

        // Trigger download
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);

        // Clean up the URL object
        URL.revokeObjectURL(url);

        this.showMessage("STIX JSON downloaded successfully!", "success");
      } catch (error) {
        // Handle invalid JSON
        this.showMessage("Invalid JSON format - cannot download", "error");
      }
    } else {
      this.showMessage("No content to download", "warning");
    }
  }

  /**
   * Clears session storage and returns to the main page
   */
  startNewAnalysis() {
    // Clear the stored STIX data
    sessionStorage.removeItem("stixOutput");
    // Navigate back to main converter page
    window.location.href = "/main";
  }

  /**
   * Displays a temporary notification message
   * @param {String} message - The message text to display
   * @param {String} type - The message type (success, error, warning, info)
   */
  showMessage(message, type) {
    // Create the notification element
    const notification = document.createElement("div");
    notification.innerHTML = message;

    // Apply inline styles for the notification
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
      box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    `;

    // Add notification to the page
    document.body.appendChild(notification);

    // Remove notification after 3 seconds
    setTimeout(() => {
      if (document.body.contains(notification)) {
        document.body.removeChild(notification);
      }
    }, 3000);
  }

  /**
   * Returns the background color for different message types
   * @param {String} type - The message type
   * @returns {String} - The hex color code
   */
  getMessageColor(type) {
    // Define color scheme for notifications
    const colors = {
      success: "#27ae60", // Green for success
      error: "#e74c3c", // Red for errors
      warning: "#f39c12", // Orange for warnings
      info: "#3498db", // Blue for information
    };
    // Return the color or default to info color
    return colors[type] || colors.info;
  }
}

// Initialise the results handler when the page loads
let stixResults;
document.addEventListener("DOMContentLoaded", function () {
  stixResults = new STIXResults();
});
