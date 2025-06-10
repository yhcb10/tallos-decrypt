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

// Função auxiliar para limpar strings JSON
function cleanJsonString(str) {
  // Estratégia mais agressiva para limpar o JSON
  let cleaned = str;
  
  // 1. Substituir quebras de linha reais por escape sequences
  cleaned = cleaned.replace(/\r\n/g, '\\n');
  cleaned = cleaned.replace(/\n/g, '\\n');
  cleaned = cleaned.replace(/\r/g, '\\n');
  cleaned = cleaned.replace(/\t/g, '\\t');
  
  // 2. Remover caracteres de controle não imprimíveis
  cleaned = cleaned.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, '');
  
  // 3. Escapar aspas não escapadas dentro de strings
  // Isso é complexo, então vamos usar uma abordagem diferente
  
  return cleaned;
}

// Função para extrair e limpar JSON de forma mais inteligente
function extractValidJson(data) {
  // Procurar pelo início e fim do array JSON
  const startIndex = data.indexOf('[');
  const endIndex = data.lastIndexOf(']') + 1;
  
  if (startIndex === -1 || endIndex === 0) {
    throw new Error('No JSON array found in decrypted data');
  }
  
  // Extrair apenas a parte JSON
  const jsonPart = data.substring(startIndex, endIndex);
  
  // Tentar limpar caracteres problemáticos dentro das strings JSON
  // Esta regex encontra strings JSON e aplica limpeza nelas
  const cleanedJson = jsonPart.replace(/"([^"\\]*(\\.[^"\\]*)*)"/g, function(match, content) {
    // Limpar o conteúdo dentro das aspas
    const cleaned = content
      .replace(/[\x00-\x1F\x7F-\x9F]/g, '') // Remove caracteres de controle
      .replace(/\\/g, '\\\\') // Escapa barras invertidas
      .replace(/"/g, '\\"'); // Escapa aspas
    return `"${cleaned}"`;
  });
  
  return cleanedJson;
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
    
    // Estratégia 1: Tentar parse direto
    let messages;
    try {
      messages = JSON.parse(decryptedData);
      console.log('Parse direto bem sucedido!');
    } catch (e1) {
      console.log('Parse direto falhou, tentando limpar dados...');
      
      // Estratégia 2: Extrair e limpar JSON
      try {
        const cleanedJson = extractValidJson(decryptedData);
        messages = JSON.parse(cleanedJson);
        console.log('Parse após limpeza bem sucedido!');
      } catch (e2) {
        console.log('Limpeza falhou, tentando estratégia de emergência...');
        
        // Estratégia 3: Usar eval como último recurso (CUIDADO!)
        try {
          // Remover caracteres problemáticos de forma mais agressiva
          const emergencyClean = decryptedData
            .replace(/[\x00-\x1F\x7F-\x9F]/g, ' ') // Substitui controles por espaço
            .replace(/\\/g, '\\\\') // Escapa barras
            .replace(/\n/g, ' ') // Remove quebras de linha
            .replace(/\r/g, ' ') // Remove retornos
            .replace(/\t/g, ' '); // Remove tabs
          
          // Tentar encontrar o array JSON
          const match = emergencyClean.match(/\[[\s\S]*\]/);
          if (match) {
            // Limpar o match antes de parsear
            const arrayStr = match[0]
              .replace(/,\s*,/g, ',') // Remove vírgulas duplas
              .replace(/,\s*\]/g, ']') // Remove vírgula antes de ]
              .replace(/\[\s*,/g, '['); // Remove vírgula depois de [
            
            messages = JSON.parse(arrayStr);
            console.log('Parse de emergência bem sucedido!');
          } else {
            throw new Error('No JSON array found');
          }
        } catch (e3) {
          // Se tudo falhar, retornar erro detalhado
          console.error('Todas as estratégias falharam');
          console.log('Amostra dos dados ao redor do erro (posição 6801):');
          const errorPos = 6801;
          const start = Math.max(0, errorPos - 100);
          const end = Math.min(decryptedData.length, errorPos + 100);
          console.log(decryptedData.substring(start, end));
          
          // Identificar o caractere problemático
          if (errorPos < decryptedData.length) {
            const problemChar = decryptedData.charCodeAt(errorPos);
            console.log(`Caractere na posição ${errorPos}: código ${problemChar} (0x${problemChar.toString(16)})`);
          }
          
          return res.status(500).json({
            error: 'JSON Parse Failed',
            details: e1.message,
            position: errorPos,
            sample: decryptedData.substring(start, end),
            suggestion: 'The decrypted data contains invalid JSON. Check logs for details.'
          });
        }
      }
    }
    
    console.log('Parse concluído. Total de mensagens:', Array.isArray(messages) ? messages.length : 'não é array');
    
    // Validar e processar mensagens
    if (Array.isArray(messages)) {
      console.log(`✅ Sucesso! ${messages.length} mensagens processadas`);
      
      // Limpar cada mensagem individualmente
      const cleanedMessages = messages.map(msg => {
        if (msg && typeof msg === 'object') {
          // Limpar campos de texto que possam ter caracteres problemáticos
          if (msg.text && typeof msg.text === 'string') {
            msg.text = msg.text
              .replace(/[\x00-\x1F\x7F-\x9F]/g, '')
              .trim();
          }
          if (msg.caption && typeof msg.caption === 'string') {
            msg.caption = msg.caption
              .replace(/[\x00-\x1F\x7F-\x9F]/g, '')
              .trim();
          }
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

// Adicione este endpoint antes do listen() no index.js

// Debug detalhado da posição do erro
app.post('/debug-error-position', async (req, res) => {
  try {
    const { jwe, privateKey, errorPosition = 6801 } = req.body;
    
    // Descriptografar
    const key = await jose.importJWK(privateKey, privateKey.alg);
    const { plaintext } = await jose.compactDecrypt(jwe, key);
    const decryptedData = new TextDecoder().decode(plaintext);
    
    // Análise ao redor da posição do erro
    const start = Math.max(0, errorPosition - 200);
    const end = Math.min(decryptedData.length, errorPosition + 200);
    
    const analysis = {
      totalLength: decryptedData.length,
      errorPosition: errorPosition,
      context: {
        before: decryptedData.substring(start, errorPosition),
        at: decryptedData.substring(errorPosition, errorPosition + 1),
        after: decryptedData.substring(errorPosition + 1, end)
      },
      characterAnalysis: []
    };
    
    // Analisar caracteres ao redor do erro
    for (let i = errorPosition - 10; i < errorPosition + 10 && i < decryptedData.length; i++) {
      if (i >= 0) {
        const char = decryptedData[i];
        const code = decryptedData.charCodeAt(i);
        analysis.characterAnalysis.push({
          position: i,
          char: code >= 32 && code <= 126 ? char : `[${code}]`,
          code: code,
          hex: '0x' + code.toString(16),
          type: code < 32 ? 'control' : code > 126 ? 'extended' : 'normal'
        });
      }
    }
    
    // Tentar identificar o padrão JSON ao redor
    const jsonContext = decryptedData.substring(errorPosition - 50, errorPosition + 50);
    analysis.jsonPattern = jsonContext;
    
    // Sugestão de correção
    analysis.suggestion = 'Procure por aspas não escapadas, quebras de linha ou caracteres especiais';
    
    res.json(analysis);
    
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
