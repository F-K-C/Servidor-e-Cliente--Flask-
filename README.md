#  ️ Computação Quântica para Defesa Cibernética - Fabrício Kolk; Rafael Servo

#  ️ Simulação de Criptografia Híbrida Pós-Quântica

### **Servidor: Python + OpenSSL 3.5 + OQS-Provider**
### **Cliente: via cURL**

Demonstração de um projeto que implementa um esquema híbrido de criptografia cliente-servidor que combina:

- Pós-quântico (PQC/KEM) — via OQS-Provider  
- Clássico (X25519 ou RSA)  
- Simétrico (AES-GCM) — com chave derivada via HKDF

---

##   Estrutura Base do Projeto 

```
openssl-3.5
oqsprovider
liboqs
pq3_server/
│
├── main.py # Servidor principal com FastAPI/Flask
├──	pqcserver
├── crypto/
│ ├── __init__.py
│ ├── encryptor.py # Funções de encapsulamento, derivação e cifragem
│ └── openssl_utils.py # Auxiliares para executar comandos OpenSSL
├── policy/
│ └── policy_pqc.json # Política de criptografia configurável
├── keys/
│ ├── pqc_pub.pem # Chave pública PQC (gerada dinamicamente)
│ ├── pqc_priv.pem # Chave privada PQC
│ ├── dh_pub.pem # Chave pública X25519
│ └── dh_priv.pem # Chave privada X25519
├── requirements.txt # Lista de dependências Python
└── README.md # Instruções do projeto

```

---

##   Pré-requisitos

Instale nesta ordem:

1. OpenSSL 3.5  
2. liboqs  
3. oqsprovider

---

##   Política Criptográfica

- Arquivo do tipo json que define os algoritmos utilizados no esquema híbrido de criptografia.

```json
{
  "pqc_kem": "mlkem512",
  "classical_kex": "X25519",
  "symmetric": {
    "algorithm": "AES-256-GCM",
    "key_len": 32,
    "nonce_len": 12
  }
}
```
- Quanto ao campo "pqc_kem", substitua por um algoritmo existente na lista dos providers da biblioteca.
- Quanto ao campo "classical_kex", substitua por "rsa" ou "x25519".
---

##   Executando o Servidor

- Basta escrever no terminal o comando "pqcserver", sem as aspas, que irá ativar a venv e rodar o servidor do Flask.

```bash
pqcserver
```
Ele roda:

```
#!/bin/bash
cd ~/Desktop/PQCnovo/pq3_server
source venv/bin/activate
python3 main.py
```
- Via terminal, altere o path (com os comandos export abaixo), de forma que o sistema operacional use o OpenSSL 3.5 em vez do OpenSSL embarcado por padrão. Isso faz com que o OpenSSL 3.5 carregue suas próprias libs e o oqsprovider. Altere o caminho conforme o diretório de seu ambiente.

export LD_LIBRARY_PATH=$HOME/Desktop/PQCnovo/openssl-3.5/lib64:$LD_LIBRARY_PATH
export PATH=$HOME/Desktop/PQCnovo/openssl-3.5/bin:$PATH

- Observação importante: substitua o caminho em "cd" para o caminho absoluto do seu diretório.

Servidor disponível em:

```
http://localhost:3030
```

##   Endpoint /encrypt

Endpoint para criptografar os dados em plain text.

### Requisição:

Com o servidor rodando em um primeiro terminal (por meio de seu start via comando "pqcserver") abra um segundo terminal e execute um curl conforme abaixo, substituindo, no campo valor de "data", a mensagem que deseja criptografar.

```bash
curl -X POST http://localhost:3030/encrypt   -H "Content-Type: application/json"   -d '{"data": "mensagem confidencial"}'
```

### Resposta:

A resposta gerada seguirá o padrão abaixo. Todas as informações serão apresentadas em base64.

```json
{
  "ciphertext": "<base64>",
  "nonce": "<base64>",
  "kem_ciphertext": "<base64>",
  "public_keys": {
    "pqc_pub": "<base64>",
    "classical_pub": "<base64>"
  }
}
```
- O campo "ciphertext" é a mensagem criptografada.
- O campo "nonce" é um valor aleatório de 12 bytes, usado pelo AES-GCM para garantir segurança, unicidade e integridade da cifra.
- O campo "kem_ciphertext" é o ciphertext gerado pelo KEM pós-quântico. Ele contém os bytes da encapsulação KEM.
- O campo "public_keys" possui as chaves públicas do tipo clássica e do tipo PQC.
---

##   Endpoint /decrypt

Endpoint para descriptografar os dados que se encontram em texto cifrado (ciphertext) para texto plano (plain text).

### Requisição:

Execute o comando cURL conforme abaixo, preenchendo os campos "kem_ciphertext", "nonce" e "ciphertext".
```bash
curl -X POST http://localhost:3030/decrypt   -H "Content-Type: application/json"   -d '{
        "kem_ciphertext": "<ciphertext PQC>",
        "nonce": "<nonce AES-GCM>",
        "ciphertext": "<ciphertext AES-GCM>"
      }'
```

### Resposta:

Com os campos devidamente preenchidos, aguarde sua mensagem original ser descriptografada, conforme o exemplo abaixo:

```json
{
  "plaintext": "mensagem confidencial"
}
```
---

##   Fluxo Completo

1. Cliente chama `/encrypt`
2. Servidor:
   - lê política
   - gera chaves PQC/clássicas
   - executa KEM encapsulation
   - deriva chave simétrica via HKDF
   - cifra com AES-GCM
   - retorna JSON completo
3. Cliente chama `/decrypt`
4. Servidor:
   - decapsula o KEM
   - deriva novamente a chave
   - descriptografa com AES-GCM
   - retorna plaintext