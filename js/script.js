// Toggle HMAC key input visibility
document.getElementById('use-hmac').addEventListener('change', function() {
    const hmacContainer = document.getElementById('hmac-key-container');
    hmacContainer.style.display = this.checked ? 'block' : 'none';
});

// Initialize hash calculation on page load
document.addEventListener('DOMContentLoaded', function() {
    calculateHash();
});

// Caesar Cipher Encryption
function encryptCaesar() {
    const shift = parseInt(document.getElementById('caesar-shift').value);
    const plaintext = document.getElementById('caesar-plaintext').value.toUpperCase();
    let result = '';

    for (let i = 0; i < plaintext.length; i++) {
        let char = plaintext[i];
        if (char.match(/[A-Z]/)) {
            const code = plaintext.charCodeAt(i);
            let shifted = ((code - 65 + shift) % 26) + 65;
            result += String.fromCharCode(shifted);
        } else {
            result += char;
        }
    }

    document.getElementById('caesar-result').textContent = result;
}

// Vigenère Cipher Encryption
function encryptVigenere() {
    const key = document.getElementById('vigenere-key').value.toUpperCase();
    const plaintext = document.getElementById('vigenere-plaintext').value.toUpperCase();
    let result = '';

    for (let i = 0; i < plaintext.length; i++) {
        const char = plaintext[i];
        if (char.match(/[A-Z]/)) {
            const keyChar = key[i % key.length];
            const keyShift = keyChar.charCodeAt(0) - 65;
            const code = char.charCodeAt(0);
            const shifted = ((code - 65 + keyShift) % 26) + 65;
            result += String.fromCharCode(shifted);
        } else {
            result += char;
        }
    }

    document.getElementById('vigenere-result').textContent = result;
}

// AES Encryption/Decryption
function encryptAES() {
    try {
        const message = document.getElementById('symmetric-message').value;
        const key = document.getElementById('aes-key').value.padEnd(32, '0').slice(0, 32);
        const iv = document.getElementById('aes-iv').value.padEnd(16, '0').slice(0, 16);
        
        // Encrypt
        const encrypted = CryptoJS.AES.encrypt(message, 
            CryptoJS.enc.Utf8.parse(key),
            {
                iv: CryptoJS.enc.Utf8.parse(iv),
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            }
        );
        
        document.getElementById('aes-result').value = encrypted.toString();
        return encrypted.toString();
    } catch (error) {
        console.error('Encryption error:', error);
        document.getElementById('aes-result').value = 'Error: ' + error.message;
        return '';
    }
}

function decryptAES() {
    try {
        const ciphertext = document.getElementById('aes-result').value;
        if (!ciphertext) {
            alert('No encrypted text to decrypt');
            return;
        }
        
        const key = document.getElementById('aes-key').value.padEnd(32, '0').slice(0, 32);
        const iv = document.getElementById('aes-iv').value.padEnd(16, '0').slice(0, 16);
        
        // Decrypt
        const decrypted = CryptoJS.AES.decrypt(ciphertext, 
            CryptoJS.enc.Utf8.parse(key),
            {
                iv: CryptoJS.enc.Utf8.parse(iv),
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            }
        );
        
        document.getElementById('aes-decrypted').value = decrypted.toString(CryptoJS.enc.Utf8);
    } catch (error) {
        console.error('Decryption error:', error);
        document.getElementById('aes-decrypted').value = 'Error: ' + error.message;
    }
}

// Hashing and HMAC
function calculateHash() {
    try {
        const input = document.getElementById('hash-input').value;
        const algorithm = document.getElementById('hash-algorithm').value;
        const useHMAC = document.getElementById('use-hmac').checked;
        
        let hash;
        let hashBits = 0;
        
        if (useHMAC) {
            const hmacKey = document.getElementById('hmac-key').value;
            hash = CryptoJS.HmacSHA256(input, hmacKey);
            
            // Convert to selected algorithm
            switch(algorithm) {
                case 'MD5':
                    hash = CryptoJS.HmacMD5(input, hmacKey);
                    hashBits = 128;
                    break;
                case 'SHA-1':
                    hash = CryptoJS.HmacSHA1(input, hmacKey);
                    hashBits = 160;
                    break;
                case 'SHA-256':
                    hash = CryptoJS.HmacSHA256(input, hmacKey);
                    hashBits = 256;
                    break;
                case 'SHA-512':
                    hash = CryptoJS.HmacSHA512(input, hmacKey);
                    hashBits = 512;
                    break;
                case 'SHA3-256':
                    hash = CryptoJS.HmacSHA3(input, hmacKey, { outputLength: 256 });
                    hashBits = 256;
                    break;
                case 'SHA3-512':
                    hash = CryptoJS.HmacSHA3(input, hmacKey, { outputLength: 512 });
                    hashBits = 512;
                    break;
            }
        } else {
            // Regular hash
            switch(algorithm) {
                case 'MD5':
                    hash = CryptoJS.MD5(input);
                    hashBits = 128;
                    break;
                case 'SHA-1':
                    hash = CryptoJS.SHA1(input);
                    hashBits = 160;
                    break;
                case 'SHA-256':
                    hash = CryptoJS.SHA256(input);
                    hashBits = 256;
                    break;
                case 'SHA-512':
                    hash = CryptoJS.SHA512(input);
                    hashBits = 512;
                    break;
                case 'SHA3-256':
                    hash = CryptoJS.SHA3(input, { outputLength: 256 });
                    hashBits = 256;
                    break;
                case 'SHA3-512':
                    hash = CryptoJS.SHA3(input, { outputLength: 512 });
                    hashBits = 512;
                    break;
            }
        }
        
        const hashHex = hash.toString(CryptoJS.enc.Hex);
        const hashBase64 = hash.toString(CryptoJS.enc.Base64);
        
        // Update UI
        document.getElementById('hash-result').innerHTML = 
            `<strong>Hex:</strong> ${hashHex}<br><br>` +
            `<strong>Base64:</strong> ${hashBase64}`;
            
        // Update hash length indicator
        document.getElementById('hash-length').textContent = hashBits;
        const progress = Math.min(100, (hashBits / 512) * 100);
        const progressBar = document.getElementById('hash-progress');
        progressBar.style.width = `${progress}%`;
        
        // Set color based on algorithm security
        if (['MD5', 'SHA-1'].includes(algorithm)) {
            progressBar.className = 'progress-bar bg-danger';
        } else if (['SHA-256', 'SHA3-256'].includes(algorithm)) {
            progressBar.className = 'progress-bar bg-warning';
        } else {
            progressBar.className = 'progress-bar bg-success';
        }
        
    } catch (error) {
        console.error('Hash calculation error:', error);
        document.getElementById('hash-result').textContent = 'Error: ' + error.message;
    }
}

// RSA Encryption Demo
function demoRSA() {
    try {
        const message = document.getElementById('rsa-message').value;
        
        // Generate RSA key pair
        const crypt = new JSEncrypt({default_key_size: 2048});
        const publicKey = crypt.getPublicKey();
        const privateKey = crypt.getPrivateKey();
        
        // Display public key
        const publicKeyElement = document.getElementById('rsa-public');
        const encryptedElement = document.getElementById('rsa-encrypted');
        const decryptedElement = document.getElementById('rsa-decrypted');
        
        publicKeyElement.textContent = publicKey;
        
        // Encrypt with public key
        const encrypt = new JSEncrypt();
        encrypt.setPublicKey(publicKey);
        const encrypted = encrypt.encrypt(message);
        
        if (!encrypted) {
            throw new Error('Encryption failed - message might be too long for the key size');
        }
        
        encryptedElement.textContent = encrypted;
        
        // Decrypt with private key
        const decrypt = new JSEncrypt();
        decrypt.setPrivateKey(privateKey);
        const decrypted = decrypt.decrypt(encrypted);
        
        if (!decrypted) {
            throw new Error('Decryption failed - invalid key or ciphertext');
        }
        
        decryptedElement.textContent = decrypted;
        
        // Show key information
        const keyInfo = crypt.getKey();
        const keySize = keyInfo.keySize || 2048;
        
        // Update UI with key information
        const keyInfoElement = document.createElement('div');
        keyInfoElement.className = 'mt-3 small text-muted';
        keyInfoElement.innerHTML = `
            <strong>Key Information:</strong><br>
            - Key Size: ${keySize} bits<br>
            - Key Format: PEM
        `;
        
        // Remove previous key info if it exists
        const existingKeyInfo = document.getElementById('rsa-key-info');
        if (existingKeyInfo) {
            existingKeyInfo.remove();
        }
        
        keyInfoElement.id = 'rsa-key-info';
        publicKeyElement.parentNode.insertBefore(keyInfoElement, publicKeyElement.nextSibling);
        
    } catch (error) {
        console.error('RSA operation failed:', error);
        alert('Error: ' + error.message);
    }
}

// Initialize tooltips
function initTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Initialize the page
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    initTooltips();
    
    // Run initial demos
    encryptCaesar();
    encryptVigenere();
    
    // Add event listeners
    document.getElementById('caesar-shift').addEventListener('input', encryptCaesar);
    document.getElementById('caesar-plaintext').addEventListener('input', encryptCaesar);
    document.getElementById('vigenere-key').addEventListener('input', encryptVigenere);
    document.getElementById('vigenere-plaintext').addEventListener('input', encryptVigenere);
    
    // Initialize hash calculation
    calculateHash();
    
    // Set up HMAC toggle
    document.getElementById('use-hmac').addEventListener('change', function() {
        const hmacContainer = document.getElementById('hmac-key-container');
        hmacContainer.style.display = this.checked ? 'block' : 'none';
        calculateHash();
    });
    
    // Set up hash algorithm change
    document.getElementById('hash-algorithm').addEventListener('change', calculateHash);
    document.getElementById('hash-input').addEventListener('input', calculateHash);
    document.getElementById('hmac-key').addEventListener('input', calculateHash);
    
    // Add animation on scroll
    const observerOptions = {
        threshold: 0.1
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);
    
    // Observe all sections
    document.querySelectorAll('section').forEach(section => {
        section.style.opacity = '0';
        section.style.transform = 'translateY(20px)';
        section.style.transition = 'opacity 0.5s ease-out, transform 0.5s ease-out';
        observer.observe(section);
    });
    
    // Initialize AES demo
    encryptAES();
});
