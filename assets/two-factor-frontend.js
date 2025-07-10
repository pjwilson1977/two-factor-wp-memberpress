/**
 * Two Factor WordPress for MemberPress - Frontend JavaScript
 */

(function () {
	"use strict";

	// Wait for DOM to be ready
	document.addEventListener("DOMContentLoaded", function () {
		initTwoFactorFrontend();
	});

	function initTwoFactorFrontend() {
		// Auto-focus on authentication code input
		var authCodeInput = document.querySelector(
			'input[name="two-factor-totp-authcode"], input[name="authcode"]'
		);
		if (authCodeInput) {
			authCodeInput.focus();
		}

		// Handle backup code toggle
		var backupToggle = document.querySelector(".backup-code-toggle-link");
		if (backupToggle) {
			backupToggle.addEventListener("click", function (e) {
				e.preventDefault();
				toggleBackupCode();
			});
		}

		// Auto-submit on 6-digit code entry (for TOTP)
		if (authCodeInput && authCodeInput.name === "two-factor-totp-authcode") {
			authCodeInput.addEventListener("input", function () {
				var value = this.value.replace(/\D/g, ""); // Remove non-digits
				this.value = value;

				if (value.length === 6) {
					// Small delay to allow user to see the complete code
					setTimeout(function () {
						var form = authCodeInput.closest("form");
						if (form) {
							form.submit();
						}
					}, 300);
				}
			});
		}

		// Format backup code input
		var backupCodeInput = document.querySelector(
			'input[name="two-factor-backup-code"]'
		);
		if (backupCodeInput) {
			backupCodeInput.addEventListener("input", function () {
				// Remove any non-alphanumeric characters and convert to uppercase
				var value = this.value.replace(/[^a-zA-Z0-9]/g, "").toUpperCase();
				this.value = value;
			});
		}

		// Handle form submission loading state
		var forms = document.querySelectorAll(".two-factor-form form");
		forms.forEach(function (form) {
			form.addEventListener("submit", function () {
				showLoadingState(form);
			});
		});

		// Handle provider switching
		var providerLinks = document.querySelectorAll(
			".two-factor-provider-list a"
		);
		providerLinks.forEach(function (link) {
			link.addEventListener("click", function (e) {
				// Add loading state while switching
				showLoadingState(document.querySelector(".two-factor-form"));
			});
		});
	}

	function toggleBackupCode() {
		console.log("Toggling backup code form visibility");
		var backupForm = document.getElementById("backup-code-form");
		var toggle = document.querySelector(".backup-code-toggle-link");

		if (backupForm) {
			if (backupForm.classList.contains("show")) {
				backupForm.classList.remove("show");
				if (toggle) {
					toggle.textContent = toggle.dataset.showText || "Use a backup code";
				}
			} else {
				backupForm.classList.add("show");
				if (toggle) {
					toggle.dataset.showText = toggle.textContent;
					toggle.textContent = "Use authenticator app instead";
				}

				// Focus on backup code input
				var backupInput = backupForm.querySelector(
					'input[name="two-factor-backup-code"]'
				);
				if (backupInput) {
					setTimeout(function () {
						backupInput.focus();
					}, 100);
				}
			}
		}
	}

	function showLoadingState(element) {
		if (element) {
			element.classList.add("loading");

			// Disable form inputs
			var inputs = element.querySelectorAll("input, button, select, textarea");
			inputs.forEach(function (input) {
				input.disabled = true;
			});
		}
	}

	// QR Code generation for setup (if needed)
	function generateQRCode(text, element) {
		// This would integrate with a QR code library if needed
		// For now, we're using an external service in the template
		console.log("QR Code text:", text);
	}

	// Copy backup codes to clipboard
	function copyBackupCodes() {
		var codesList = document.querySelector(".two-factor-backup-codes-list");
		if (codesList) {
			var codes = Array.from(codesList.querySelectorAll("li")).map(function (
				li
			) {
				return li.textContent.trim();
			});

			var codesText = codes.join("\n");

			if (navigator.clipboard && navigator.clipboard.writeText) {
				navigator.clipboard
					.writeText(codesText)
					.then(function () {
						showMessage("Backup codes copied to clipboard", "success");
					})
					.catch(function () {
						fallbackCopyToClipboard(codesText);
					});
			} else {
				fallbackCopyToClipboard(codesText);
			}
		}
	}

	function fallbackCopyToClipboard(text) {
		var textArea = document.createElement("textarea");
		textArea.value = text;
		textArea.style.position = "fixed";
		textArea.style.left = "-999999px";
		textArea.style.top = "-999999px";
		document.body.appendChild(textArea);
		textArea.focus();
		textArea.select();

		try {
			document.execCommand("copy");
			showMessage("Backup codes copied to clipboard", "success");
		} catch (err) {
			showMessage("Failed to copy backup codes", "error");
		}

		document.body.removeChild(textArea);
	}

	function showMessage(message, type) {
		var messageDiv = document.createElement("div");
		messageDiv.className = "two-factor-message " + type;
		messageDiv.textContent = message;

		var container = document.querySelector(".two-factor-form");
		if (container) {
			container.insertBefore(messageDiv, container.firstChild);

			// Auto-hide after 3 seconds
			setTimeout(function () {
				if (messageDiv.parentNode) {
					messageDiv.parentNode.removeChild(messageDiv);
				}
			}, 3000);
		}
	}

	// Expose useful functions globally
	window.TwoFactorMemberPress = {
		toggleBackupCode: toggleBackupCode,
		copyBackupCodes: copyBackupCodes,
		showMessage: showMessage,
	};
})();
