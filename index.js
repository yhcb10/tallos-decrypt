const express = require('express');
const cors = require('cors');
const jose = require('jose');

const app = express();

// Configurar CORS
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Rota principal
app.get('/', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'Tallos Decrypt Service',
    version: '1.0.0'
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Descriptografar
app.post('/decrypt', async (req, res) => {
  try {
    const { jwe, privateKey } = req.body;
    
    if (!jwe || !privateKey) {
      return res.status(400).json({ 
        error: 'Missing jwe or privateKey' 
      });
    }
    
    const key = await jose.importJWK(privateKey, privateKey.alg);
    const { plaintext } = await jose.compactDecrypt(jwe, key);
    const decryptedData = new TextDecoder().decode(plaintext);
    const messages = JSON.parse(decryptedData);
    
    res.json({
      success: true,
      messages: messages,
      count: Array.isArray(messages) ? messages.length : 0
    });
    
  } catch (error) {
    res.status(500).json({ 
      error: 'Decryption failed', 
      details: error.message 
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

} catch (error) {
    console.error('Erro ao descriptografar:', error);
    console.error('Stack trace:', error.stack);
    res.status(500).json({ 
      error: 'Decryption failed', 
      details: error.message,
      type: error.constructor.name
    });
  }
