document.addEventListener('DOMContentLoaded', () => {
  const chatMessages = document.getElementById('chatMessages');
  const companionInput = document.getElementById('companionInput');
  const companionSendBtn = document.getElementById('companionSendBtn');
  const apiKeyInput = document.getElementById('apiKeyInput');
  const newChatBtn = document.getElementById('newChatBtn');

  // Load API Key from localStorage
  const savedKey = localStorage.getItem('sentinel_api_key');
  if (savedKey) {
    apiKeyInput.value = savedKey;
  }

  apiKeyInput.addEventListener('change', () => {
    localStorage.setItem('sentinel_api_key', apiKeyInput.value);
  });

  // Maintain chat history explicitly for LLM context
  let conversationHistory = [];
  let currentContext = null;

  // Check if we arrived from the SOC page with context
  const contextRaw = sessionStorage.getItem('sentinel_tutor_context');
  if (contextRaw) {
    try {
      const contextData = JSON.parse(contextRaw);
      sessionStorage.removeItem('sentinel_tutor_context'); // consume it
      
      currentContext = {
         title: contextData.title,
         ip: contextData.ip,
         asset: contextData.asset,
         threat_score: contextData.hybrid_threat_score,
         severity: contextData.severity,
         summary: contextData.summary
      };

      // Build a detailed prompt based on the SOC alert
      const autoPrompt = `I am investigating a critical SOC alert. Please analyze this incident.\n\n` + 
                         `Title: ${contextData.title}\n` +
                         `Severity: ${contextData.severity}\n` + 
                         `Attacker IP: ${contextData.ip || 'Unknown'}\n` + 
                         `Target Asset: ${contextData.asset || 'Unknown'}\n` +
                         `Threat Score: ${contextData.hybrid_threat_score || 'N/A'}\n` +
                         `Summary: ${contextData.summary || 'N/A'}\n` +
                         `Tags: ${(contextData.tags || []).join(', ')}`;

      // Simulate the user typing and sending it
      setTimeout(() => {
        companionInput.value = autoPrompt;
        companionSendBtn.disabled = false;
        sendChatMessage();
      }, 500);

    } catch(e) {
      console.error("Failed to parse context:", e);
    }
  }

  // Auto-resize textarea
  companionInput.addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = (this.scrollHeight) + 'px';
    if(this.value.trim() !== '') {
      companionSendBtn.disabled = false;
    } else {
      companionSendBtn.disabled = true;
    }
  });

  companionInput.addEventListener('focus', () => {
    companionInput.parentElement.classList.add('focused');
  });
  companionInput.addEventListener('blur', () => {
    companionInput.parentElement.classList.remove('focused');
  });

  // Handle Enter (Send) and Shift+Enter (New Line)
  companionInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (!companionSendBtn.disabled) sendChatMessage();
    }
  });

  companionSendBtn.addEventListener('click', sendChatMessage);

  newChatBtn.addEventListener('click', () => {
    chatMessages.innerHTML = `
      <div class="companion-message bot">
        <div class="companion-avatar"><i class="fas fa-shield-alt"></i></div>
        <div class="companion-bubble">
          <p>Hello! I am your Sentinel AI Security Companion.</p>
          <p>I can help you investigate attacks, understand threat patterns, and provide real-world context.</p>
          <p>Ask me a question to get started. If you have an API key, provide it in the sidebar for full conversational context!</p>
        </div>
      </div>
    `;
    conversationHistory = [];
    currentContext = null;
  });

  function appendUserMessage(text) {
    const msgDiv = document.createElement('div');
    msgDiv.className = 'companion-message user';
    msgDiv.innerHTML = `
      <div class="companion-avatar"><i class="fas fa-user-astronaut"></i></div>
      <div class="companion-bubble">${escapeHtml(text)}</div>
    `;
    chatMessages.appendChild(msgDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  function appendBotMessage(text, isTyping = false) {
    const msgDiv = document.createElement('div');
    msgDiv.className = 'companion-message bot';
    msgDiv.id = isTyping ? 'typingIndicator' : '';
    
    let content = '';
    if (isTyping) {
      content = `
        <div class="companion-typing-indicator">
          <div class="companion-typing-dot"></div>
          <div class="companion-typing-dot"></div>
          <div class="companion-typing-dot"></div>
        </div>
      `;
    } else {
      // Parse markdown and sanitize HTML
      const rawHtml = marked.parse(text);
      const cleanHtml = DOMPurify.sanitize(rawHtml);
      content = cleanHtml;
    }

    msgDiv.innerHTML = `
      <div class="companion-avatar"><i class="fas fa-shield-alt"></i></div>
      <div class="companion-bubble">${content}</div>
    `;
    chatMessages.appendChild(msgDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  function removeTypingIndicator() {
    const typingMsg = document.getElementById('typingIndicator');
    if (typingMsg) typingMsg.remove();
  }

  async function sendChatMessage() {
    const text = companionInput.value.trim();
    if (!text) return;

    // UI Updates
    companionInput.value = '';
    companionInput.style.height = 'auto';
    companionSendBtn.disabled = true;
    appendUserMessage(text);
    appendBotMessage('', true);

    // Save to history
    conversationHistory.push({ role: 'user', content: text });

    const payload = {
      messages: conversationHistory,
      api_key: apiKeyInput.value,
      context: currentContext
    };

    try {
      const response = await fetch('/api/tutor/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const data = await response.json();
      removeTypingIndicator();

      if (data.error) {
        appendBotMessage(`**Error:** ${data.error}`);
        // Pop the failed user message history optionally
        conversationHistory.pop();
      } else {
        const botText = data.response;
        appendBotMessage(botText);
        conversationHistory.push({ role: 'assistant', content: botText });
      }
    } catch (err) {
      removeTypingIndicator();
      appendBotMessage("**Connection Error:** Could not reach the AI Companion backend.");
      console.error(err);
      conversationHistory.pop();
    }
  }

  function escapeHtml(unsafe) {
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
  }
});
