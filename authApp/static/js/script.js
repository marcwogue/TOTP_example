/* ==========================================================================
   PyCon Cameroon - Démonstrateur TOTP (RFC 6238)
   ========================================================================== */

let currentStep = 1;
let cachedOtp = "";

// Helper sécurisé pour récupérer un élément du DOM
const getEl = id => document.getElementById(id);

// Helper pour récupérer la valeur d'un groupe de boutons radio
const getRadiosVal = (name, fallback) => {
    const r = Array.from(document.getElementsByName(name)).find(r => r.checked);
    return r ? (isNaN(r.value) ? r.value : parseInt(r.value, 10)) : fallback;
};

/* ==========================================================================
   Navigation entre les Phases (Exposée sur window pour le HTML)
   ========================================================================== */
window.updateStepVisibility = function() {
    [1, 2, 3].forEach(step => {
        const card = getEl(`step-card-${step}`);
        const indicator = getEl(`step-indicator-${step}`);

        if (card) {
            if (step === currentStep) {
                card.style.display = "block";
                card.classList.add("active-step");
            } else {
                card.style.display = "none";
                card.classList.remove("active-step");
            }
        }

        if (indicator) {
            if (step === currentStep) {
                indicator.classList.add("active");
            } else {
                indicator.classList.remove("active");
            }
        }
    });

    const prevBtn = getEl("prev-step-btn");
    const nextBtn = getEl("next-step-btn");

    if (prevBtn) {
        prevBtn.style.visibility = currentStep === 1 ? "hidden" : "visible";
    }
    
    if (nextBtn) {
        nextBtn.innerHTML = currentStep === 3 ? "Recommencer &#8634;" : "Suivant &#8594;";
    }
};

window.navigatePrev = function() {
    if (currentStep > 1) {
        currentStep--;
        window.updateStepVisibility();
    }
};

window.navigateNext = function() {
    if (currentStep < 3) {
        currentStep++;
    } else {
        currentStep = 1;
    }
    window.updateStepVisibility();
};

window.goToStep = function(step) {
    if (step >= 1 && step <= 3) {
        currentStep = step;
        window.updateStepVisibility();
    }
};

/* ==========================================================================
   Fonctions Cryptographiques et Helpers TOTP
   ========================================================================== */
window.setRandomSecret = function() {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let result = "";
    for (let i = 0; i < 16; i++) {
        result += alphabet[Math.floor(Math.random() * alphabet.length)];
    }
    const secretInput = getEl("secret-input");
    if (secretInput) {
        secretInput.value = result;
        triggerCalculation();
    }
};

function getSelectedPeriod() { 
    return getRadiosVal("period-radio", 30); 
}

function base32ToBytes(str) {
    str = str.replace(/\s+/g, "").toUpperCase();
    if (!str) return new Uint8Array(0);
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const bytes = [];
    let buffer = 0, bitsLeft = 0;

    for (let i = 0; i < str.length; i++) {
        const value = alphabet.indexOf(str[i]);
        if (value === -1) {
            if (str[i] === "=") break;
            throw new Error("Clé secrète invalide : le format Base32 n'est pas respecté.");
        }
        buffer = (buffer << 5) | value;
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            bytes.push((buffer >> (bitsLeft - 8)) & 0xff);
            bitsLeft -= 8;
        }
    }
    return new Uint8Array(bytes);
}

function bytesToHexSpace(bytes) {
    return Array.from(bytes).map(b => b.toString(16).toUpperCase().padStart(2, "0")).join(" ");
}

async function calculateHMAC(keyBytes, timeStep) {
    const msgBytes = new Uint8Array(8);
    const high = Math.floor(timeStep / 0x100000000);
    const low = timeStep % 0x100000000;

    msgBytes[0] = (high >> 24) & 0xff; 
    msgBytes[1] = (high >> 16) & 0xff;
    msgBytes[2] = (high >> 8) & 0xff;  
    msgBytes[3] = high & 0xff;
    msgBytes[4] = (low >> 24) & 0xff;  
    msgBytes[5] = (low >> 16) & 0xff;
    msgBytes[6] = (low >> 8) & 0xff;   
    msgBytes[7] = low & 0xff;

    const cryptoKey = await crypto.subtle.importKey(
        "raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
    );
    const signature = await crypto.subtle.sign("HMAC", cryptoKey, msgBytes);
    return new Uint8Array(signature);
}

/* ==========================================================================
   Moteur de Calcul et Mise à Jour du DOM
   ========================================================================== */
async function triggerCalculation() {
    const secretInput = getEl("secret-input");
    const secretError = getEl("secret-error");
    if (!secretInput) return;

    const secret = secretInput.value.trim();

    if (secret.length === 0) {
        if (secretError) {
            secretError.innerText = "Clé secrète requise.";
            secretError.style.display = "block";
        }
        if (getEl("decode-hex")) getEl("decode-hex").innerText = "En attente...";
        if (getEl("decode-ascii")) getEl("decode-ascii").innerText = "En attente...";
        if (getEl("hmac-byte-grid")) getEl("hmac-byte-grid").innerHTML = '<div style="color: #718096;">Saisissez une clé secrète.</div>';
        if (getEl("otp-output-text")) getEl("otp-output-text").innerText = "------";
        return;
    }

    const period = getSelectedPeriod();
    const digits = 6;
    const nowSec = Math.floor(Date.now() / 1000);

    try {
        let keyBytes;
        try {
            keyBytes = base32ToBytes(secret);
        } catch (error) {
            if (secretError) {
                secretError.innerText = error.message || "Clé secrète invalide.";
                secretError.style.display = "block";
            }
            if (getEl("decode-hex")) getEl("decode-hex").innerText = "Erreur";
            if (getEl("decode-ascii")) getEl("decode-ascii").innerText = "Erreur";
            if (getEl("otp-output-text")) getEl("otp-output-text").innerText = "------";
            return;
        }

        if (secretError) {
            secretError.style.display = "none";
            secretError.innerText = "";
        }

        // ASCII Conversion
        let asciiChars = [];
        keyBytes.forEach(byte => {
            if (byte >= 32 && byte <= 126) asciiChars.push(String.fromCharCode(byte));
            else asciiChars.push(".");
        });
        const asciiStr = asciiChars.join("");

        // Pas de Temps (T)
        const timeStep = Math.floor(nowSec / period);
        const high = Math.floor(timeStep / 0x100000000);
        const low = timeStep % 0x100000000;
        const msgBytes = new Uint8Array([
            (high >> 24) & 0xff, (high >> 16) & 0xff, (high >> 8) & 0xff, high & 0xff,
            (low >> 24) & 0xff, (low >> 16) & 0xff, (low >> 8) & 0xff, low & 0xff
        ]);

        const timeStepHex = "0x" + high.toString(16).toUpperCase().padStart(8, "0") + low.toString(16).toUpperCase().padStart(8, "0");
        const timeStepBytesHex = Array.from(msgBytes).map(b => b.toString(16).toUpperCase().padStart(2, "0")).join(" ");

        // HMAC Calculation
        const hmacBytes = await calculateHMAC(keyBytes, timeStep);
        const hmacHexList = Array.from(hmacBytes).map(b => b.toString(16).toUpperCase().padStart(2, "0"));

        // Truncation
        const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
        const extractedBytes = hmacBytes.slice(offset, offset + 4);
        const extractedBytesHex = Array.from(extractedBytes).map(b => "0x" + b.toString(16).toUpperCase().padStart(2, "0"));

        const binaryCode = (((extractedBytes[0] & 0x7f) << 24) | (extractedBytes[1] << 16) | (extractedBytes[2] << 8) | extractedBytes[3]) >>> 0;
        const otpValue = binaryCode % Math.pow(10, digits);
        const otpStr = otpValue.toString().padStart(digits, "0");
        const formattedOtp = `${otpStr.slice(0, 3)} ${otpStr.slice(3)}`;

        /* RENDER PHASE 1 */
        if (getEl("decode-hex")) getEl("decode-hex").innerText = bytesToHexSpace(keyBytes);
        if (getEl("decode-ascii")) getEl("decode-ascii").innerText = asciiStr || "Vide";
        if (getEl("step-decimal")) getEl("step-decimal").innerText = timeStep;
        if (getEl("step-hex")) getEl("step-hex").innerText = timeStepHex;

        /* RENDER PHASE 2 */
        if (getEl("hmac-msg-input")) getEl("hmac-msg-input").innerText = "0x" + timeStepBytesHex;
        if (getEl("hmac-key-input")) getEl("hmac-key-input").innerText = "0x" + bytesToHexSpace(keyBytes);

        const byteGrid = getEl("hmac-byte-grid");
        if (byteGrid) {
            byteGrid.innerHTML = "";
            hmacBytes.forEach((_, i) => {
                const box = document.createElement("div");
                box.className = "byte-box";
                box.style.display = "inline-block";
                box.style.padding = "6px 10px";
                box.style.margin = "3px";
                box.style.borderRadius = "4px";
                box.style.fontFamily = "monospace";
                box.style.fontSize = "12px";
                box.innerText = hmacHexList[i];

                if (i === hmacBytes.length - 1) {
                    box.style.border = "1px solid #d97706";
                    box.style.background = "#fef3c7";
                    box.title = `Dernier octet (Offset = ${offset})`;
                } else if (i >= offset && i < offset + 4) {
                    box.style.border = "1px solid #6b5ce7";
                    box.style.background = "#e0e7ff";
                    box.title = `Octet tronqué ${i - offset}`;
                } else {
                    box.style.border = "1px solid #e2e8f0";
                    box.style.background = "#ffffff";
                }
                byteGrid.appendChild(box);
            });
        }

        /* RENDER PHASE 3 */
        if (getEl("trunc-offset-calc")) {
            getEl("trunc-offset-calc").innerHTML = `Offset = Dernier Octet (0x${hmacHexList[hmacBytes.length - 1]}) & 0x0F = <strong>${offset}</strong>`;
        }
        if (getEl("trunc-bytes-extracted")) {
            getEl("trunc-bytes-extracted").innerHTML = `Octets extraits [offset ${offset} à ${offset + 3}] = <strong>[${extractedBytesHex.join(", ")}]</strong>`;
        }
        if (getEl("trunc-modulo-calc")) {
            getEl("trunc-modulo-calc").innerHTML = `Code Modulo = ${binaryCode.toLocaleString()} % 10^6 = <strong>${formattedOtp}</strong>`;
        }

        /* CODE TOTP FINAL */
        const otpTextEl = getEl("otp-output-text");
        if (otpTextEl) {
            cachedOtp = formattedOtp;
            otpTextEl.innerText = cachedOtp;
        }

    } catch (error) {
        console.error("Erreur de calcul TOTP:", error);
    }
}

function runRealtimeClock() {
    const nowSec = Math.floor(Date.now() / 1000);
    const period = getSelectedPeriod();
    const remaining = period - (nowSec % period);

    const labelEl = getEl("timer-label");
    if (labelEl) labelEl.innerText = remaining + "s";

    const progressBar = getEl("timer-progress-bar");
    if (progressBar) {
        progressBar.style.width = ((remaining / period) * 100) + "%";
        progressBar.style.backgroundColor = remaining <= 5 ? "#e53e3e" : "#6b5ce7";
    }

    triggerCalculation();
}

/* ==========================================================================
   Initialisation des Événements du DOM
   ========================================================================== */
document.addEventListener("DOMContentLoaded", () => {
    window.updateStepVisibility();

    const secretInput = getEl("secret-input");
    if (secretInput) {
        secretInput.addEventListener("input", triggerCalculation);
    }

    document.getElementsByName("period-radio").forEach(radio => {
        radio.addEventListener("change", triggerCalculation);
    });

    if (secretInput && secretInput.value.trim() === "") {
        window.setRandomSecret();
    } else {
        triggerCalculation();
    }

    setInterval(runRealtimeClock, 250);
});