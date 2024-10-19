async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-CBC", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encrypt(content, password) {
    const enc = new TextEncoder();
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(16));

    const key = await deriveKey(password, salt);
    const encrypted = await window.crypto.subtle.encrypt(
        {
            name: "AES-CBC",
            iv: iv
        },
        key,
        enc.encode(content)
    );

    // Combine salt, IV, and encrypted data, and encode in base64
    const combined = new Uint8Array([...salt, ...iv, ...new Uint8Array(encrypted)]);
    return btoa(String.fromCharCode(...combined));
}

async function decrypt(encryptedData, password) {
    const combined = new Uint8Array(atob(encryptedData).split("").map(char => char.charCodeAt(0)));

    const salt = combined.slice(0, 16); // Extract salt
    const iv = combined.slice(16, 32); // Extract IV
    const encrypted = combined.slice(32); // Extract encrypted data

    const key = await deriveKey(password, salt);
    const decrypted = await window.crypto.subtle.decrypt(
        {
            name: "AES-CBC",
            iv: iv
        },
        key,
        encrypted
    );

    const dec = new TextDecoder();
    return dec.decode(decrypted);
}

const $encodeBtn = document.getElementById("encode");
const $decodeBtn = document.getElementById("decode");

$encodeBtn.addEventListener('click', async () => {
    const content = document.getElementById('content').value;
    const password = document.getElementById('password').value;

    const encrypted = await encrypt(content, password);

    document.getElementById('result').innerText = encrypted
});

$decodeBtn.addEventListener('click', async () => {
    const content = document.getElementById('content').value;
    const password = document.getElementById('password').value;

    const decrypted = await decrypt(content, password);

    document.getElementById('result').innerText = decrypted;
});
