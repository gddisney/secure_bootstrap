async function passkeyRegister(username) {
    try {
        if (!username) throw new Error("Please enter a username");
        
        // 1. Begin Phase
        const resp = await fetch('/auth/register/begin?username=' + encodeURIComponent(username));
        if (!resp.ok) throw new Error("Server error: " + await resp.text());
        const opts = await resp.json();
        
        opts.publicKey.challenge = base64urlToBuffer(opts.publicKey.challenge);
        opts.publicKey.user.id = base64urlToBuffer(opts.publicKey.user.id);
        if(opts.publicKey.excludeCredentials) {
            opts.publicKey.excludeCredentials.forEach(c => c.id = base64urlToBuffer(c.id));
        }

        // 2. Browser API Call
        const cred = await navigator.credentials.create({ publicKey: opts.publicKey });
        
        // 3. Finish Phase
        // Use standard POST. The server's loginInterceptor will catch the result 
        // and set the 'session_id' cookie automatically.
        const finishResp = await fetch('/auth/register/finish?username=' + encodeURIComponent(username), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                id: cred.id,
                rawId: bufferToBase64url(cred.rawId),
                type: cred.type,
                response: {
                    attestationObject: bufferToBase64url(cred.response.attestationObject),
                    clientDataJSON: bufferToBase64url(cred.response.clientDataJSON),
                },
            }),
        });
        
        if (!finishResp.ok) throw new Error("Registration Failed: " + await finishResp.text());
        
        // Redirect to trigger session validation
        window.location.href = "/";
    } catch (err) {
        console.error(err);
        alert("Registration Failed: " + err.message);
    }
}

async function passkeyLogin(username) {
    try {
        if (!username) throw new Error("Please enter a username");

        // 1. Begin Phase
        const resp = await fetch('/auth/login/begin?username=' + encodeURIComponent(username));
        if (!resp.ok) throw new Error("Server error: " + await resp.text());
        const opts = await resp.json();
        
        opts.publicKey.challenge = base64urlToBuffer(opts.publicKey.challenge);
        if (opts.publicKey.allowCredentials) {
            opts.publicKey.allowCredentials.forEach(c => c.id = base64urlToBuffer(c.id));
        }

        // 2. Browser API Call
        const assertion = await navigator.credentials.get({ publicKey: opts.publicKey });
        
        // 3. Finish Phase
        const finishResp = await fetch('/auth/login/finish?username=' + encodeURIComponent(username), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                id: assertion.id,
                rawId: bufferToBase64url(assertion.rawId),
                type: assertion.type,
                response: {
                    authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                    clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                    signature: bufferToBase64url(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null,
                },
            }),
        });

        if (!finishResp.ok) throw new Error("Login Rejected: " + await finishResp.text());
        
        // Redirect will now succeed because the 'session_id' cookie was set 
        // by the server's loginInterceptor during the fetch call above.
        window.location.href = "/";
        
    } catch (err) {
        console.error(err);
        alert("Login Failed: " + err.message);
    }
}

// Utility functions remain identical
function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const charCode of bytes) { str += String.fromCharCode(charCode); }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlToBuffer(base64url) {
    const padding = '=='.slice(0, (4 - base64url.length % 4) % 4);
    const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
    const str = atob(base64);
    const buffer = new ArrayBuffer(str.length);
    const byteView = new Uint8Array(buffer);
    for (let i = 0; i < str.length; i++) { byteView[i] = str.charCodeAt(i); }
    return buffer;
}
