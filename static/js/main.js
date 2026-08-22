/**
 * static/js/main.js
 * ─────────────────────────────────────────────────────────────
 * Hardened Vanilla JavaScript Module for Secure Steganography
 * 
 * Phase 9 Audit & Completion:
 *   - Strict client-side file extension & format pre-checks (JPEG rejected early)
 *   - Error boundary for corrupted/non-decodeable image files
 *   - Drag-and-drop & native file input synchronization
 *   - Instant client-side metadata extraction & spatial capacity estimation
 *   - Accurate UTF-8 byte & character counter (handles Emojis & multi-byte Unicode)
 *   - Real-time password confirmation & accessibility-compliant toggles
 *   - Form submission loading state with bfcache restoration
 *   - Dual clipboard copy API (navigator.clipboard with legacy fallback)
 *   - XSS-safe toast notifications using textContent
 *   - Zero credential logging or local storage exposure
 * ─────────────────────────────────────────────────────────────
 */

document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initAlerts();
    initFileUploads();
    initMessageCounter();
    initPasswordHandlers();
    initCopyButtons();
    initFormSubmits();
    initBfCacheHandler();
});

// ── 1. Active Navigation Indicator ────────────────────────────
function initNavigation() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll(".nav-link");

    navLinks.forEach((link) => {
        const href = link.getAttribute("href");
        if (href === currentPath || (currentPath !== "/" && href !== "/" && currentPath.startsWith(href))) {
            link.classList.add("active");
            link.setAttribute("aria-current", "page");
        } else {
            link.classList.remove("active");
            link.removeAttribute("aria-current");
        }
    });
}

// ── 2. Dismissible Alerts & Keyboard Support ──────────────────
function initAlerts() {
    document.querySelectorAll(".alert").forEach((alert) => {
        const closeBtn = alert.querySelector(".alert-close");
        if (closeBtn) {
            closeBtn.addEventListener("click", () => dismissAlert(alert));
            closeBtn.addEventListener("keydown", (e) => {
                if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    dismissAlert(alert);
                }
            });
        }
    });
}

function dismissAlert(alert) {
    alert.style.transition = "opacity 0.2s ease, transform 0.2s ease";
    alert.style.opacity = "0";
    alert.style.transform = "translateY(-6px)";
    setTimeout(() => alert.remove(), 200);
}

// ── Global image state for live capacity calculations ─────────
let currentImageCapacity = 0;

// ── 3. File Uploads, Drag & Drop, and Image Previews ───────────
function initFileUploads() {
    const dropzones = document.querySelectorAll(".dropzone");

    dropzones.forEach((dropzone) => {
        const input = dropzone.querySelector('input[type="file"]');
        const previewBox = document.getElementById(dropzone.dataset.preview || "image-preview-box");

        if (!input) return;

        // Prevent browser default open on drag & drop
        ["dragenter", "dragover", "dragleave", "drop"].forEach((eventName) => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
            });
        });

        // Highlight dropzone on drag
        ["dragenter", "dragover"].forEach((eventName) => {
            dropzone.addEventListener(eventName, () => dropzone.classList.add("dragover"));
        });

        ["dragleave", "drop"].forEach((eventName) => {
            dropzone.addEventListener(eventName, () => dropzone.classList.remove("dragover"));
        });

        // Handle file drop
        dropzone.addEventListener("drop", (e) => {
            const files = e.dataTransfer.files;
            if (files && files.length > 0) {
                input.files = files;
                handleFileSelect(files[0], previewBox, dropzone, input);
            }
        });

        // Handle standard file selection
        input.addEventListener("change", (e) => {
            if (e.target.files && e.target.files.length > 0) {
                handleFileSelect(e.target.files[0], previewBox, dropzone, input);
            }
        });
    });
}

function handleFileSelect(file, previewBox, dropzone, input) {
    if (!file) return;

    // Strict client-side extension check
    const validExtensions = [".png", ".bmp"];
    const fileNameLower = file.name.toLowerCase();
    const isValid = validExtensions.some((ext) => fileNameLower.endsWith(ext));

    if (!isValid) {
        showToast("⚠️ Unsupported format! Only PNG and BMP images are supported (lossy JPEG destroys hidden data).", 4000);
        // Reset selection
        if (input) input.value = "";
        if (previewBox) previewBox.classList.remove("active");
        const title = dropzone ? dropzone.querySelector(".dropzone-title") : null;
        if (title) title.textContent = "Drop your cover image here";
        currentImageCapacity = 0;
        updateCapacityMeter();
        return;
    }

    const reader = new FileReader();
    reader.onerror = () => {
        showToast("Failed to read the selected file.", 3000);
        if (input) input.value = "";
    };

    reader.onload = (e) => {
        const dataUrl = e.target.result;
        const img = new Image();

        img.onerror = () => {
            showToast("Failed to decode image data. The file may be corrupted.", 3500);
            if (input) input.value = "";
            if (previewBox) previewBox.classList.remove("active");
            currentImageCapacity = 0;
            updateCapacityMeter();
        };

        img.onload = () => {
            const width = img.naturalWidth;
            const height = img.naturalHeight;
            const sizeKb = (file.size / 1024).toFixed(1);

            if (width <= 0 || height <= 0) {
                showToast("Invalid image dimensions detected.", 3000);
                return;
            }

            // Compute spatial LSB capacity: floor(width * height * 3 / 8) - 4
            currentImageCapacity = Math.max(0, Math.floor((width * height * 3) / 8) - 4);

            // Render preview box
            if (previewBox) {
                const previewImg = previewBox.querySelector("img");
                const nameChip = previewBox.querySelector(".meta-filename");
                const dimChip = previewBox.querySelector(".meta-dimensions");
                const sizeChip = previewBox.querySelector(".meta-size");
                const capChip = previewBox.querySelector(".meta-capacity");

                if (previewImg) previewImg.src = dataUrl;
                if (nameChip) nameChip.textContent = file.name;
                if (dimChip) dimChip.textContent = `${width} × ${height} px`;
                if (sizeChip) sizeChip.textContent = `${sizeKb} KB`;
                if (capChip) capChip.textContent = `${currentImageCapacity.toLocaleString()} bytes max`;

                previewBox.classList.add("active");
            }

            // Update dropzone title to filename
            const title = dropzone ? dropzone.querySelector(".dropzone-title") : null;
            if (title) {
                title.textContent = file.name;
            }

            updateCapacityMeter();
        };

        img.src = dataUrl;
    };

    reader.readAsDataURL(file);
}

// ── 4. Live Message Byte & Character Counter ──────────────────
function initMessageCounter() {
    const messageInput = document.getElementById("message");
    const charCountEl = document.getElementById("char-count");
    const byteCountEl = document.getElementById("byte-count");

    if (!messageInput) return;

    const updateCounts = () => {
        const text = messageInput.value;
        // Count actual Unicode code points so emojis count as 1 character
        const charCount = [...text].length;

        // Accurate UTF-8 byte count using standard TextEncoder
        const byteCount = new TextEncoder().encode(text).length;

        if (charCountEl) charCountEl.textContent = `${charCount.toLocaleString()} chars`;
        if (byteCountEl) byteCountEl.textContent = `${byteCount.toLocaleString()} UTF-8 bytes`;

        updateCapacityMeter();
    };

    messageInput.addEventListener("input", updateCounts);
    updateCounts();
}

// ── 5. Client-side Capacity Meter Update ──────────────────────
function updateCapacityMeter() {
    const meterWrapper = document.getElementById("capacity-meter-wrapper");
    const fillEl = document.getElementById("capacity-bar-fill");
    const percentEl = document.getElementById("capacity-percentage");
    const usedTextEl = document.getElementById("capacity-used-text");
    const messageInput = document.getElementById("message");

    if (!meterWrapper || !fillEl) return;

    if (currentImageCapacity <= 0) {
        meterWrapper.style.display = "none";
        return;
    }

    meterWrapper.style.display = "block";

    const msgText = messageInput ? messageInput.value : "";
    const msgBytes = new TextEncoder().encode(msgText).length;

    // Estimate total serialized JSON payload size:
    // msgBytes (ciphertext) + 16B GCM tag + 12B nonce + 32B salt + 64B SHA256 hex + JSON scaffolding ~ 280 bytes
    const estimatedPayloadBytes = msgBytes > 0 ? msgBytes + 280 : 0;

    const rawPercent = currentImageCapacity > 0
        ? (estimatedPayloadBytes / currentImageCapacity) * 100
        : 0;

    const displayPercent = Math.min(100, Math.round(rawPercent));

    fillEl.style.width = `${Math.min(100, rawPercent)}%`;
    if (percentEl) percentEl.textContent = `${displayPercent}%`;

    if (usedTextEl) {
        usedTextEl.textContent = `${estimatedPayloadBytes.toLocaleString()} bytes est. / ${currentImageCapacity.toLocaleString()} bytes capacity`;
    }

    fillEl.classList.remove("warning", "danger");
    if (rawPercent > 95) {
        fillEl.classList.add("danger");
    } else if (rawPercent > 75) {
        fillEl.classList.add("warning");
    }
}

// ── 6. Password Visibility & Confirmation Matching ────────────
function initPasswordHandlers() {
    // Password visibility toggles
    document.querySelectorAll(".toggle-password-btn").forEach((btn) => {
        btn.setAttribute("aria-pressed", "false");
        btn.addEventListener("click", () => {
            const targetId = btn.dataset.target;
            const input = document.getElementById(targetId);
            if (!input) return;

            if (input.type === "password") {
                input.type = "text";
                btn.textContent = "👁️";
                btn.title = "Hide password";
                btn.setAttribute("aria-label", "Hide password");
                btn.setAttribute("aria-pressed", "true");
            } else {
                input.type = "password";
                btn.textContent = "👁️‍🗨️";
                btn.title = "Show password";
                btn.setAttribute("aria-label", "Show password");
                btn.setAttribute("aria-pressed", "false");
            }
        });
    });

    // Password confirmation match check
    const passwordInput = document.getElementById("password");
    const confirmInput = document.getElementById("confirm_password");
    const matchStatus = document.getElementById("password-match-status");

    if (passwordInput && confirmInput && matchStatus) {
        const checkMatch = () => {
            const p1 = passwordInput.value;
            const p2 = confirmInput.value;

            if (!p2) {
                matchStatus.className = "password-match-status";
                matchStatus.textContent = "";
                return;
            }

            if (p1 === p2) {
                matchStatus.className = "password-match-status match";
                matchStatus.textContent = "✓ Passwords match";
            } else {
                matchStatus.className = "password-match-status mismatch";
                matchStatus.textContent = "✕ Passwords do not match";
            }
        };

        passwordInput.addEventListener("input", checkMatch);
        confirmInput.addEventListener("input", checkMatch);
    }
}

// ── 7. Copy to Clipboard Utility with Robust Fallback ─────────
function initCopyButtons() {
    document.querySelectorAll(".copy-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            const targetId = btn.dataset.copyTarget;
            const targetEl = document.getElementById(targetId);
            if (!targetEl) return;

            const textToCopy = targetEl.textContent || targetEl.innerText;

            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(textToCopy).then(() => {
                    showToast("✓ Copied to clipboard!");
                }).catch(() => {
                    fallbackCopyText(textToCopy);
                });
            } else {
                fallbackCopyText(textToCopy);
            }
        });
    });
}

function fallbackCopyText(text) {
    try {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "fixed";
        textArea.style.left = "-999999px";
        textArea.style.top = "-999999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        const successful = document.execCommand("copy");
        document.body.removeChild(textArea);
        if (successful) {
            showToast("✓ Copied to clipboard!");
        } else {
            showToast("Could not copy automatically. Please select text manually.");
        }
    } catch (err) {
        showToast("Could not copy automatically. Please select text manually.");
    }
}

// ── 8. Form Submission Loading States ─────────────────────────
function initFormSubmits() {
    document.querySelectorAll("form.crypto-form").forEach((form) => {
        form.addEventListener("submit", () => {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (!submitBtn) return;

            const loadingText = submitBtn.dataset.loadingText || "⏳ Processing...";

            setTimeout(() => {
                if (!form.checkValidity()) return;

                submitBtn.disabled = true;
                submitBtn.innerHTML = `<span class="spinner" aria-hidden="true"></span> ${loadingText}`;
            }, 10);
        });
    });
}

// ── 9. Back-Forward Cache (bfcache) Restoration ───────────────
function initBfCacheHandler() {
    window.addEventListener("pageshow", (event) => {
        // If restored from bfcache or back navigation, re-enable submit buttons
        if (event.persisted || performance.getEntriesByType("navigation")[0]?.type === "back_forward") {
            document.querySelectorAll('form.crypto-form button[type="submit"]').forEach((btn) => {
                btn.disabled = false;
                // Revert to original content
                if (btn.dataset.loadingText) {
                    if (btn.closest("form").action.includes("hide")) {
                        btn.innerHTML = `<span>🔐</span> Encrypt &amp; Hide Message`;
                    } else if (btn.closest("form").action.includes("extract")) {
                        btn.innerHTML = `<span>🔓</span> Extract &amp; Decrypt Message`;
                    } else {
                        btn.innerHTML = `<span>📊</span> Run Quality Analysis`;
                    }
                }
            });
        }
    });
}

// ── Toast Notification System (XSS-Safe) ──────────────────────
function showToast(message, duration = 3000) {
    const existing = document.querySelector(".toast");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.className = "toast";
    toast.setAttribute("role", "status");
    toast.setAttribute("aria-live", "polite");
    toast.textContent = message; // Safe: uses textContent to prevent HTML injection
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.transition = "opacity 0.3s ease, transform 0.3s ease";
        toast.style.opacity = "0";
        toast.style.transform = "translateY(10px)";
        setTimeout(() => toast.remove(), 300);
    }, duration);
}
