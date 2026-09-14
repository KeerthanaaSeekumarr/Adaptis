let chatOpen = false;

// Create a Trusted Types policy for secure innerHTML assignment
let escapeHTMLPolicy;
if (window.trustedTypes && window.trustedTypes.createPolicy) {
    try {
        escapeHTMLPolicy = window.trustedTypes.createPolicy("default", {
            createHTML: (string) => string
        });
    } catch (e) {
        escapeHTMLPolicy = window.trustedTypes.defaultPolicy;
    }
}

function getTrustedHTML(str) {
    return escapeHTMLPolicy ? escapeHTMLPolicy.createHTML(str) : str;
}

function toggleChat() {
    chatOpen = !chatOpen;
    const body = document.getElementById("chat-body");
    const icon = document.getElementById("chat-toggle-icon");
    
    if(chatOpen) {
        body.style.display = "block";
        icon.className = "fas fa-chevron-down";
    } else {
        body.style.display = "none";
        icon.className = "fas fa-chevron-up";
    }
}

function appendMessage(text, isUser=false) {
    const wrap = document.getElementById("chat-messages");
    const div = document.createElement("div");
    
    div.className = isUser ? "chat-message-user" : "chat-message-bot";
    
    // Quick simple markdown rendering
    // Ensure text is a string
    text = String(text || "");
    let html = text.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
                   .replace(/\*(.*?)\*/g, "<em>$1</em>")
                   .replace(/`(.*?)`/g, "<span style='font-family: monospace; background:rgba(255,255,255,0.1); padding:2px 4px; border-radius:3px;'>$1</span>")
                   .replace(/\n\n/g, "<br><br>")
                   .replace(/\n/g, "<br>");
                   
    div.innerHTML = getTrustedHTML(html);
    wrap.appendChild(div);
    wrap.scrollTop = wrap.scrollHeight;
}

async function sendChatMessage(presetMsg=null, payloadContext=null) {
    const input = document.getElementById("chatInput");
    const apiKeyInput = document.getElementById("apiKeyInput");
    const apiKey = apiKeyInput ? apiKeyInput.value.trim() : "";
    
    // Ensure presetMsg is actually a string and not an Event object leaked from an onclick handler
    const actualPresetMsg = (typeof presetMsg === 'string') ? presetMsg : null;
    const msg = actualPresetMsg || input.value.trim();
    
    if(!msg) return;
    
    if(!actualPresetMsg) {
        input.value = "";
    }
    
    if(!chatOpen) toggleChat();
    
    appendMessage(msg, true);
    
    // Add loading indicator
    const wrap = document.getElementById("chat-messages");
    const loadingDiv = document.createElement("div");
    loadingDiv.className = "chat-message-bot";
    loadingDiv.id = "chat-loading";
    loadingDiv.innerHTML = getTrustedHTML(`<i class="fas fa-circle-notch fa-spin text-blue"></i> Analyzing...`);
    wrap.appendChild(loadingDiv);
    wrap.scrollTop = wrap.scrollHeight;
    
    try {
        const res = await fetch("/api/bot/chat", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                message: msg,
                api_key: apiKey || null,
                context: payloadContext
            })
        });
        
        document.getElementById("chat-loading").remove();
        
        if(!res.ok) {
            appendMessage("Error communicating with AI backend.");
            return;
        }
        
        const data = await res.json();
        appendMessage(data.response);
        
    } catch(e) {
        document.getElementById("chat-loading").remove();
        appendMessage("Network error reaching AI Engine.");
    }
}

// Global function exposed to push alerts to AI analyzer
window.analyzeAlertWithAI = function(alertObj) {
    if(!chatOpen) toggleChat();
    
    const context = {
        title: alertObj.title,
        ip: alertObj.ip,
        summary: alertObj.summary,
        packet: alertObj.raw_packet
    };
    
    sendChatMessage(`Analyze this incident: ${alertObj.title}. What is the attacker's intent and how should I mitigate it?`, context);
}
