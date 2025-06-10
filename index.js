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
    
    console.log('=== Recebendo requisição de descriptografia ===');
    console.log('JWE recebido:', jwe ? 'Sim' : 'Não');
    console.log('Tamanho do JWE:', jwe ? jwe.length : 0);
    console.log('Chave privada recebida:', privateKey ? 'Sim' : 'Não');
    
    if (!jwe || !privateKey) {
      console.log('Erro: Faltando jwe ou privateKey');
      return res.status(400).json({ 
        error: 'Missing jwe or privateKey' 
      });
    }
    
    console.log('Importando chave JWK...');
    const key = await jose.importJWK(privateKey, privateKey.alg);
    console.log('Chave importada com sucesso');
    
    console.log('Iniciando descriptografia...');
    const { plaintext } = await jose.compactDecrypt(jwe, key);
    console.log('Descriptografia concluída');
    
    const decryptedData = new TextDecoder().decode(plaintext);
    console.log('Dados decodificados, fazendo parse JSON...');
    
    const messages = JSON.parse(decryptedData);
    console.log('Parse concluído. Total de mensagens:', Array.isArray(messages) ? messages.length : 'não é array');
    
    res.json({
      success: true,
      messages: messages,
      count: Array.isArray(messages) ? messages.length : 0
    });
    
  } catch (error) {
    console.error('=== ERRO NA DESCRIPTOGRAFIA ===');
    console.error('Tipo do erro:', error.constructor.name);
    console.error('Mensagem:', error.message);
    console.error('Stack trace:', error.stack);
    
    res.status(500).json({ 
      error: 'Decryption failed', 
      details: error.message,
      type: error.constructor.name
    });
  }
});

// Endpoint de teste/debug
app.post('/test', async (req, res) => {
  console.log('=== TESTE ENDPOINT ===');
  console.log('Body recebido:', JSON.stringify(req.body).substring(0, 200));
  res.json({ 
    received: true, 
    bodySize: JSON.stringify(req.body).length 
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Endpoints disponíveis:');
  console.log('  GET  / - Status do serviço');
  console.log('  GET  /health - Health check');
  console.log('  POST /decrypt - Descriptografar JWE');
  console.log('  POST /test - Teste de requisição');
});
