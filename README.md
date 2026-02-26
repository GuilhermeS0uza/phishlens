# PhishLens 🔍  
Detector de URLs de Phishing com Heurísticas e Threat Intelligence

O **PhishLens** é uma ferramenta de linha de comando (CLI) voltada para **detecção de URLs de phishing**, criada com foco em **Segurança de Aplicações** e **segurança defensiva**.

O projeto combina **análise heurística** com **inteligência de ameaças real** (Google Safe Browsing) para calcular um **score de risco explicável**, ajudando a identificar links maliciosos **antes que o usuário interaja com eles**.

---

## 🚀 Funcionalidades

- Análise e validação da estrutura de URLs
- Identificação de técnicas comuns de phishing:
  - TLDs suspeitos ou frequentemente abusados
  - Typosquatting e ataques de homoglyph (ex: `g00gle.com`)
  - Uso de encurtadores de URL
  - URLs baseadas em endereço IP
  - Portas incomuns
  - Palavras-chave suspeitas em paths e queries (`login`, `verify`, `update`, etc.)
  - Abuso de múltiplos subdomínios
- Integração opcional com **Google Safe Browsing API**
- Sistema de **pontuação de risco (0–100)** com explicação dos indicadores
- Classificação clara: SAFE, SUSPICIOUS ou DANGEROUS
- Análise individual ou em lote (arquivo `.txt`)
- Suporte a exportação de resultados em JSON

---

## 🧠 Como o PhishLens funciona

Cada URL passa por várias camadas de análise:

### 1️⃣ Análise Estrutural
- Comprimento excessivo da URL
- Caracteres codificados ou suspeitos
- Padrões de ofuscação comuns em phishing

### 2️⃣ Análise de Domínio e Reputação
- Verificação de TLDs conhecidos por abuso
- Detecção de encurtadores de URL
- Identificação de hosts baseados em IP
- Portas não padrão

### 3️⃣ Typosquatting e Homoglyphs
- Comparação de similaridade com domínios legítimos
- Normalização de substituições comuns (`0 → o`, `1 → l`, `rn → m`)

### 4️⃣ Threat Intelligence (Opcional)
- Consulta ao **Google Safe Browsing**
- Detecta URLs já conhecidas como:
  - Phishing
  - Malware
  - Engenharia social
- Caso a API não esteja configurada, o sistema continua funcionando normalmente

### 5️⃣ Score de Risco
Cada indicador soma pontos ao score final, que varia de **0 a 100**, acompanhado de justificativas claras.

---

## 📊 Classificação de Risco

| Score | Classificação |
|------|---------------|
| 0 – 34 | SAFE |
| 35 – 69 | SUSPICIOUS |
| 70 – 100 | DANGEROUS |

---

## 🖥️ Como usar

### Analisar uma URL individual
```bash
python -m phishlens https://example.com

