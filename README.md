# pq3_server - quick start

## Requisitos
- Python 3.9+
- OpenSSL 3.x com OQS-provider (preferencialmente 3.4+ para `pkeyutl -encap` support) OR um OpenSSL com suporte a KEMs.
- pip install -r requirements.txt

## Instalação
1. pip install -r requirements.txt
2. Ajuste policy/policy_pqc.json se quiser outro KEM.
3. Executar:
   python main.py

## Teste (cliente)
curl -X POST http://localhost:3030/encrypt \
 -H "Content-Type: application/json" \
 -d '{"data":"mensagem confidencial"}'

## Observações importantes
- A funcionalidade `openssl pkeyutl -encap/-decap` é relativamente nova e depende de OpenSSL + OQS-provider com suporte a KEM encoding/decoding. Se `pkeyutl -encap` não existir, instale/build oqs-provider e um OpenSSL compatível. :contentReference[oaicite:2]{index=2}
- Algumas distribuições/versões do `openssl enc` ou `openssl` CLI podem não suportar corretamente AES-GCM via streaming; por isso usei a biblioteca `cryptography` para a cifragem AES-GCM no Python (mais portátil). :contentReference[oaicite:3]{index=3}
