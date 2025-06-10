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
    service: 'Tallos Decrypt Service',
    status: 'running',
    version: '1.0.0',
    endpoints: [
      'GET  / - Status do serviço',
      'GET  /health - Health check',
      'POST /decrypt - Descriptografar JWE',
      'POST /test - Teste de requisição'
    ]
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Teste de requisição
app.post('/test', (req, res) => {
  console.log('=== TESTE ENDPOINT ===');
  console.log('Body recebido:', JSON.stringify(req.body));
  res.json({
    received: true,
    bodySize: JSON.stringify(req.body).length
  });
});

// Função para escapar strings JSON corretamente
function escapeJsonString(str) {
  return str
    .replace(/\\/g, '\\\\')     // Escapar barras invertidas PRIMEIRO
    .replace(/"/g, '\\"')       // Escapar aspas duplas
    .replace(/\b/g, '\\b')      // Backspace
    .replace(/\f/g, '\\f')      // Form feed
    .replace(/\n/g, '\\n')      // New line
    .replace(/\r/g, '\\r')      // Carriage return
    .replace(/\t/g, '\\t')      // Tab
    .replace(/[\x00-\x1F\x7F-\x9F]/g, function(c) {
      // Escapar outros caracteres de controle
      return '\\u' + ('0000' + c.charCodeAt(0).toString(16)).slice(-4);
    });
}

// Função para processar mensagens com formatação especial
function fixMessagesJson(jsonStr) {
  // Estratégia: processar o JSON campo por campo
  // Procurar por padrões problemáticos conhecidos
  
  // 1. Substituir sequências problemáticas de backticks
  jsonStr = jsonStr.replace(/"`\s+`/g, '\\n'); // "` ` para nova linha
  jsonStr = jsonStr.replace(/"\s*`\s*`\s*/g, '\\n'); // Variações de backticks
  
  // 2. Corrigir escape de barras invertidas em campos de conteúdo
  // Procurar por patterns como ,"content":"...\n..." e corrigir
  jsonStr = jsonStr.replace(/"content"\s*:\s*"([^"]*(?:\\.[^"]*)*)"/g, function(match, content) {
    // Re-escapar o conteúdo corretamente
    const fixed = escapeJsonString(content);
    return `"content":"${fixed}"`;
  });
  
  // 3. Corrigir campos text similares
  jsonStr = jsonStr.replace(/"text"\s*:\s*"([^"]*(?:\\.[^"]*)*)"/g, function(match, text) {
    const fixed = escapeJsonString(text);
    return `"text":"${fixed}"`;
  });
  
  return jsonStr;
}

// Função para tentar múltiplas estratégias de parse
function tryParseJson(data) {
  const strategies = [
    // Estratégia 1: Parse direto
    () => JSON.parse(data),
    
    // Estratégia 2: Limpar e parsear
    () => JSON.parse(cleanJsonString(data)),
    
    // Estratégia 3: Remover quebras de linha e parsear
    () => JSON.parse(data.replace(/[\r\n]+/g, ' ')),
    
    // Estratégia 4: Escapar caracteres problemáticos
    () => {
      const escaped = data
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/[\r\n]+/g, '\\n')
        .replace(/[\t]+/g, '\\t');
      return JSON.parse(`"${escaped}"`);
    },
    
    // Estratégia 5: Usar a função extractValidJson
    () => {
      const extracted = extractValidJson(data);
      return JSON.parse(extracted);
    }
  ];
  
  let lastError;
  for (let i = 0; i < strategies.length; i++) {
    try {
      console.log(`Tentando estratégia ${i + 1}...`);
      const result = strategies[i]();
      console.log(`Estratégia ${i + 1} bem sucedida!`);
      return result;
    } catch (error) {
      lastError = error;
      console.log(`Estratégia ${i + 1} falhou:`, error.message);
    }
  }
  
  throw lastError;
}

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
    console.log('Dados decodificados, tamanho:', decryptedData.length);
    
    // Nova estratégia: corrigir o JSON antes de parsear
    let messages;
    try {
      // Primeiro, tentar corrigir problemas conhecidos
      const fixedData = fixMessagesJson(decryptedData);
      messages = JSON.parse(fixedData);
      console.log('Parse com correções bem sucedido!');
    } catch (e1) {
      console.log('Correção inicial falhou, tentando estratégia manual...');
      
      try {
        // Estratégia manual: processar linha por linha
        // Dividir por objetos e processar cada um
        const objects = decryptedData.match(/\{[^{}]*\}/g);
        if (objects && objects.length > 0) {
          messages = objects.map(objStr => {
            try {
              // Limpar cada objeto individualmente
              const cleaned = objStr
                .replace(/\\n/g, ' ')
                .replace(/\\r/g, ' ')
                .replace(/\\t/g, ' ')
                .replace(/"\s*`\s*`\s*/g, ' ')
                .replace(/[\x00-\x1F\x7F-\x9F]/g, '');
              
              return JSON.parse(cleaned);
            } catch (e) {
              console.log('Falha ao parsear objeto:', objStr.substring(0, 100));
              return null;
            }
          }).filter(obj => obj !== null);
          
          console.log(`Parse manual: ${messages.length} mensagens recuperadas`);
        } else {
          throw new Error('Não foi possível extrair objetos JSON');
        }
      } catch (e2) {
        // Última tentativa: usar regex para extrair o array completo
        console.log('Tentando extração por regex...');
        
        // Procurar o array de mensagens
        const arrayMatch = decryptedData.match(/\[[\s\S]*\]/);
        if (arrayMatch) {
          let arrayStr = arrayMatch[0];
          
          // Aplicar correções específicas para o problema identificado
          // Substituir sequências problemáticas
          arrayStr = arrayStr.replace(/\\n"\s*`\s*`/g, '\\n'); 
          arrayStr = arrayStr.replace(/"\s*`\s*`\s*/g, ' ');
          arrayStr = arrayStr.replace(/\\"/g, '\\"');
          arrayStr = arrayStr.replace(/\\\\/g, '\\\\');
          
          // Remover caracteres de controle
          arrayStr = arrayStr.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
          
          try {
            messages = JSON.parse(arrayStr);
            console.log('Extração por regex bem sucedida!');
          } catch (e3) {
            // Se ainda falhar, mostrar detalhes do erro
            const errorPos = 6801;
            const sample = decryptedData.substring(errorPos - 200, errorPos + 200);
            
            return res.status(500).json({
              error: 'JSON Parse Failed',
              details: e1.message,
              position: errorPos,
              characterCode: decryptedData.charCodeAt(errorPos),
              sample: sample,
              suggestion: 'Problema com formatação de mensagens contendo backticks'
            });
          }
        }
      }
    }
    
    // Validar resultado
    if (!messages) {
      throw new Error('Não foi possível processar as mensagens');
    }
    
    console.log('Parse concluído. Total de mensagens:', Array.isArray(messages) ? messages.length : 'não é array');
    
    // Limpar mensagens individualmente
    if (Array.isArray(messages)) {
      console.log(`✅ Sucesso! ${messages.length} mensagens processadas`);
      
      // Garantir que cada mensagem está limpa
      const cleanedMessages = messages.map(msg => {
        if (msg && typeof msg === 'object') {
          // Limpar campos de texto
          ['text', 'content', 'caption'].forEach(field => {
            if (msg[field] && typeof msg[field] === 'string') {
              // Remover caracteres problemáticos mas preservar formatação básica
              msg[field] = msg[field]
                .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
                .trim();
            }
          });
        }
        return msg;
      });
      
      res.json({
        success: true,
        messages: cleanedMessages,
        count: cleanedMessages.length
      });
    } else {
      res.json({
        success: true,
        messages: messages,
        count: 0
      });
    }
    
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

// Endpoint de debug detalhado
app.post('/debug-decrypt', async (req, res) => {
  try {
    const { jwe, privateKey } = req.body;
    
    // Descriptografar
    const key = await jose.importJWK(privateKey, privateKey.alg);
    const { plaintext } = await jose.compactDecrypt(jwe, key);
    const decryptedData = new TextDecoder().decode(plaintext);
    
    // Análise detalhada
    const analysis = {
      length: decryptedData.length,
      firstChars: decryptedData.substring(0, 100),
      lastChars: decryptedData.substring(decryptedData.length - 100),
      charCodes: []
    };
    
    // Analisar caracteres ao redor da posição problemática
    for (let i = 220; i < 240 && i < decryptedData.length; i++) {
      analysis.charCodes.push({
        position: i,
        char: decryptedData[i],
        code: decryptedData.charCodeAt(i),
        hex: '0x' + decryptedData.charCodeAt(i).toString(16)
      });
    }
    
    res.json({
      success: true,
      analysis: analysis,
      tip: 'Procure por caracteres com código < 32 ou > 126 - estes são problemáticos'
    });
    
  } catch (error) {
    res.status(500).json({ 
      error: 'Debug failed', 
      details: error.message 
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Endpoints disponíveis:');
  console.log('  GET  / - Status do serviço');
  console.log('  GET  /health - Health check');
  console.log('  POST /decrypt - Descriptografar JWE');
  console.log('  POST /test - Teste de requisição');
  console.log('  POST /debug-decrypt - Debug detalhado');
});
