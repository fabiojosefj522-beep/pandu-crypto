# pandu-crypto

**Português** · [English](#english)

QR codes com dados sensíveis (ficha médica, alergias, contato de emergência, plaquinha de pet) que **nem o servidor consegue ler**. É o mesmo método que o [Pandu SOS](https://usepandu.com.br) usa em produção, aberto para qualquer pessoa usar e conferir.

- Sem dependências: um arquivo de ~120 linhas usando a Web Crypto do próprio navegador.
- Roda no navegador, Node 18+, Deno, Bun e Cloudflare Workers.
- Servidor de referência pronto para Cloudflare Pages + D1 (grátis para começar).
- Licença MIT, uso comercial liberado. Empresas: veja [Para empresas](#para-empresas).

## Como funciona

1. **No celular.** Os dados são cifrados antes de sair do aparelho, com AES-GCM e uma chave aleatória de 128 bits (ou 256, se preferir) criada só para aquele QR. Cada gravação usa um IV aleatório novo de 96 bits.
2. **No QR.** O link é `https://seu-site/#D=<id><chave>`: um id aleatório de 80 bits e a chave. Tudo o que vem depois do `#` fica no navegador e nunca é enviado a servidor nenhum.
3. **No servidor.** Ele guarda só `{id, ct, iv, data, sha256(token)}`: bytes cifrados e o hash do token de edição do dono. Sem a chave, não serve para nada, nem para quem administra o servidor, nem para quem invadir.
4. **Quem escaneia.** O navegador busca `ct` e `iv` pelo id e decifra com a chave do próprio link. Não precisa instalar nada.
5. **Editar e desligar.** Só quem tem o token edita ou apaga. Apagado, o QR passa a responder "desativado" (410).

| O servidor vê | O servidor não vê |
|---|---|
| Um id aleatório, os bytes cifrados, o IV e a data | Os dados (nome, saúde, contatos) |
| O hash SHA-256 do token de edição | A chave, que só existe no QR |
| O endereço IP de quem acessa, como qualquer site | Conta, e-mail ou senha (não existem) |

## Para empresas

Planos de saúde, clínicas, escolas, eventos, segurança do trabalho, pet shops e apps de saúde podem usar o pandu-crypto para oferecer um QR de emergência **sem guardar dados de saúde legíveis**.

**Onde se encaixa**

- **Saúde:** carteirinha, pulseira ou app com alergias, remédios e contato de emergência.
- **Escolas, colônias de férias e eventos:** pulseira ou tatuagem temporária com o contato dos pais.
- **Segurança do trabalho e equipes em campo:** adesivo no capacete ou no crachá (construção, mineração, logística, entregadores).
- **Esporte:** número de peito em corridas e provas de ciclismo.
- **Pets:** plaquinha com o contato do tutor, para pet shops, clínicas veterinárias e seguradoras.

**O que a sua empresa ganha**

- **Menos risco com dado sensível.** Dado de saúde é dado pessoal sensível na LGPD (art. 5º, II). Com o pandu-crypto, o seu servidor guarda só bytes cifrados: se o banco vazar, sem a chave não há o que ler.
- **Ajuda em caso de incidente.** Na LGPD, ao avaliar a gravidade de um incidente, considera-se se os dados estavam ininteligíveis para terceiros (art. 48, § 3º). No GDPR, a criptografia é citada como medida de segurança (art. 32) e pode dispensar o aviso aos titulares (art. 34, 3, a).
- **Sem cadastro para quem socorre.** Quem escaneia abre a ficha pela câmera, sem instalar app e sem login.
- **Simples e barato.** Um arquivo, sem dependências. O servidor de referência cabe no plano gratuito da Cloudflare para começar.
- **Uso comercial liberado.** Licença MIT: pode usar, modificar e vender produtos com ela, desde que mantenha o aviso de copyright e a licença.

**Boas práticas para não estragar a proteção**

1. **Gere a chave no aparelho do usuário** (`newCard()` no navegador ou no app), nunca no servidor.
2. **Não coloque scripts de terceiros na página que abre a ficha** (analytics, chat, anúncios, pixels): eles conseguem ler o `location.hash`, onde está a chave.
3. **Não grave o link completo** em logs, planilhas, CRM ou e-mail. Se precisar de uma referência, guarde só o id.
4. **Use HTTPS e uma Content-Security-Policy restrita** na página da ficha.
5. **Deixe o usuário apagar e trocar o QR** (`remove()` e um `newCard()` novo).
6. **Diga na política de privacidade o que o servidor guarda:** id, bytes cifrados, IV, data e o hash do token.

Textos oficiais: [LGPD (Lei 13.709/2018)](https://planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709compilado.htm) · [GDPR (Regulamento UE 2016/679)](https://eur-lex.europa.eu/eli/reg/2016/679/oj/por). Isto não é aconselhamento jurídico: confirme com o seu jurídico ou com o encarregado de dados (DPO).

Se usar o pandu-crypto, você pode mostrar "Criptografia: pandu-crypto" com um link para este repositório.

## Uso

```js
import { newCard, encrypt, decrypt, makeLink, parseLink } from './src/pandu-crypto.js';

const card = newCard();                 // { id, key, tok } — guarde o tok só no aparelho do dono
const { ct, iv } = await encrypt({ nome: 'Maria', alergias: ['penicilina'] }, card.key);
// envie { id: card.id, tok: card.tok, ct, iv } ao servidor
const link = makeLink('https://seu-site.com/', card.id, card.key);   // coloque este link no QR

// quem escaneia:
const { id, key } = parseLink(location.hash);
// busque { ct, iv } pelo id no servidor e:
const dados = await decrypt(ct, iv, key);   // null se a chave estiver errada ou os bytes tiverem sido alterados
```

Com o servidor de referência, há atalhos: `save(api, card, dados)`, `load(api, link)` e `remove(api, card)`.

### Servidor de referência (Cloudflare Pages + D1)

1. Copie `server/cloudflare/functions/` para a raiz do seu projeto do Pages.
2. Crie o banco: `npx wrangler d1 create meus-cartoes` e ligue-o com o nome `DB` (veja `server/cloudflare/wrangler.example.toml`).
3. Publique. A tabela é criada no primeiro uso.

### Testes e demonstração

- `node test/test.mjs`: 31 testes, sem instalar nada.
- `example/index.html`: sirva a pasta (por exemplo `python3 -m http.server`) e abra `/example/` para ver, lado a lado, o que o servidor guardaria e o que fica só no link.

## E os computadores quânticos?

Os dados já estão protegidos:

- **Os computadores quânticos ameaçam a criptografia de chave pública** (RSA e curvas elípticas, quebradas pelo algoritmo de Shor). O pandu-crypto não usa nada disso para trancar os dados: a chave vai dentro do QR, sem troca de chaves pela internet.
- **AES-GCM é criptografia simétrica.** Contra ela, o melhor ataque quântico conhecido é o algoritmo de Grover, que na prática quase não ajuda: o [NIST](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs) diz que o AES-128 deve continuar seguro por décadas.
- **O token de edição** tem 256 bits aleatórios e o servidor guarda só o SHA-256 dele, que também resiste a computadores quânticos.
- **Na conexão (HTTPS),** quem hospeda na Cloudflare já ganha a troca de chaves pós-quântica (ML-KEM) com os navegadores atuais, [sem configurar nada](https://developers.cloudflare.com/ssl/post-quantum-cryptography/pqc-support/).

Se as regras do seu projeto exigirem chaves de 256 bits (como a CNSA 2.0 da NSA), use `newCard({ bits: 256 })`. Funciona igual, e o QR fica um tamanho maior (versão 5 em vez de 4 para um link típico). Links de 128 e de 256 bits podem conviver no mesmo servidor.

## Limites, com honestidade

- **Quem tem o link (ou uma foto do QR) abre os dados.** É para isso que o QR existe. Para cortar o acesso de quem já fotografou, apague o cartão ou gere um id e uma chave novos.
- **Quem tem o token edita.** Guarde-o só no aparelho do dono (ou num código de recuperação).
- **O servidor entrega o JavaScript.** Um servidor mal-intencionado poderia trocar o código da página para capturar a chave. Por isso o código é aberto: dá para conferir, e quem quiser pode hospedar o próprio.
- **Não é um serviço médico** e não substitui o atendimento de emergência.

## Contribuir e reportar falhas

Pull requests são bem-vindos. Falhas de segurança: veja [SECURITY.md](SECURITY.md).

Feito por Fábio José dos Santos, criador do [Pandu SOS](https://usepandu.com.br). Se usar no seu projeto, um link de volta é muito bem-vindo.

---

## English

[Português](#pandu-crypto) · **English**

QR codes for sensitive data (medical card, allergies, emergency contacts, pet tags) that **not even the server can read**. It is the same method [Pandu SOS](https://usepandu.com.br) uses in production, open for anyone to use and audit.

- No dependencies: one ~120-line file on top of the browser's own Web Crypto.
- Runs in browsers, Node 18+, Deno, Bun and Cloudflare Workers.
- A reference server ready for Cloudflare Pages + D1 (free to start).
- MIT License, commercial use allowed. Companies: see [For companies](#for-companies).

### How it works

1. **On the phone.** The data is encrypted before it leaves the device, with AES-GCM and a random 128-bit key (or 256-bit, if you prefer) created only for that QR. Every save uses a fresh random 96-bit IV.
2. **In the QR.** The link is `https://your-site/#D=<id><key>`: a random 80-bit id and the key. Everything after the `#` stays in the browser and is never sent to any server.
3. **On the server.** It stores only `{id, ct, iv, date, sha256(token)}`: ciphertext and the hash of the owner's edit token. Without the key it is useless, to the server's admin and to an attacker alike.
4. **Whoever scans.** The browser fetches `ct` and `iv` by id and decrypts them with the key from the link itself. Nothing to install.
5. **Edit and turn off.** Only the token holder can edit or delete. Once deleted, the QR answers "turned off" (410).

### For companies

Health plans, clinics, schools, events, workplace safety teams, pet businesses and health apps can use pandu-crypto to offer an emergency QR **without storing readable health data**.

**Where it fits**

- **Health:** member cards, bracelets or apps with allergies, medicines and emergency contacts.
- **Schools, summer camps and events:** a bracelet or temporary tattoo with the parents' contact.
- **Workplace safety and field teams:** a sticker on the helmet or badge (construction, mining, logistics, couriers).
- **Sports:** race bibs for running and cycling events.
- **Pets:** tags with the owner's contact, for pet shops, vets and insurers.

**What your company gets**

- **Less risk with sensitive data.** Health data is special-category data under the GDPR (art. 9) and sensitive data under Brazil's LGPD. With pandu-crypto your server stores only ciphertext: if the database leaks, there is nothing to read without the key.
- **Help if an incident happens.** The GDPR names encryption as a security measure (art. 32), and data rendered unintelligible can exempt you from notifying data subjects (art. 34(3)(a)). The LGPD weighs whether the data was unintelligible to third parties when assessing an incident (art. 48 § 3).
- **No sign-up for whoever helps.** The person scanning opens the card with the camera, no app and no login.
- **Simple and cheap.** One file, no dependencies. The reference server fits Cloudflare's free plan to start.
- **Commercial use allowed.** MIT License: use it, change it and sell products built on it, as long as you keep the copyright notice and the license.

**Good practice, so the protection holds**

1. **Create the key on the user's device** (`newCard()` in the browser or app), never on the server.
2. **No third-party scripts on the page that opens the card** (analytics, chat, ads, pixels): they can read `location.hash`, where the key is.
3. **Never store the full link** in logs, spreadsheets, CRMs or email. If you need a reference, keep only the id.
4. **Use HTTPS and a strict Content-Security-Policy** on the card page.
5. **Let users delete and replace their QR** (`remove()` and a fresh `newCard()`).
6. **Say in your privacy policy what the server keeps:** id, ciphertext, IV, date and the token hash.

Official texts: [GDPR (Regulation (EU) 2016/679)](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng) · [LGPD (Brazilian Law 13,709/2018, in Portuguese)](https://planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709compilado.htm). This is not legal advice: check with your legal team or data protection officer.

If you use pandu-crypto, you can show "Encryption: pandu-crypto" with a link to this repository.

### Usage

```js
import { newCard, encrypt, decrypt, makeLink, parseLink } from './src/pandu-crypto.js';

const card = newCard();                 // { id, key, tok } — keep tok only on the owner's device
const { ct, iv } = await encrypt({ name: 'Maria', allergies: ['penicillin'] }, card.key);
// send { id: card.id, tok: card.tok, ct, iv } to the server
const link = makeLink('https://your-site.com/', card.id, card.key);  // put this link in the QR

// whoever scans:
const { id, key } = parseLink(location.hash);
// fetch { ct, iv } by id from the server, then:
const data = await decrypt(ct, iv, key);    // null if the key is wrong or the bytes were changed
```

With the reference server there are shortcuts: `save(api, card, data)`, `load(api, link)` and `remove(api, card)`.

**Reference server (Cloudflare Pages + D1):** copy `server/cloudflare/functions/` to your Pages project root, create a database with `npx wrangler d1 create my-cards`, bind it as `DB` (see `server/cloudflare/wrangler.example.toml`) and deploy. The table is created on first use.

**Tests and demo:** `node test/test.mjs` (31 tests, nothing to install). Serve the folder and open `/example/` to see, side by side, what a server would store and what stays only in the link.

### What about quantum computers?

The data is already protected. Quantum computers threaten public-key cryptography (RSA and elliptic curves, broken by Shor's algorithm), which pandu-crypto does not use: the key travels inside the QR, with no key exchange over the internet. AES-GCM is symmetric; the best known quantum attack on it, Grover's algorithm, helps very little in practice, and [NIST](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs) says AES-128 "will remain secure for decades to come". The edit token is 256 random bits and the server keeps only its SHA-256, which is also quantum-resistant. On the connection, sites hosted on Cloudflare already get hybrid post-quantum key exchange (ML-KEM) with current browsers, [with nothing to configure](https://developers.cloudflare.com/ssl/post-quantum-cryptography/pqc-support/).

If your rules require 256-bit keys (such as the NSA's CNSA 2.0), use `newCard({ bits: 256 })`. It works the same and makes the QR one size bigger (version 5 instead of 4 for a typical link). 128-bit and 256-bit links can live on the same server.

### Honest limits

- **Whoever has the link (or a photo of the QR) can open the data.** That is what the QR is for. To cut off someone who photographed it, delete the card or issue a new id and key.
- **Whoever has the token can edit.** Keep it only on the owner's device (or in a recovery code).
- **The server delivers the JavaScript.** A malicious server could swap the page code to capture the key. That is why the code is open: it can be audited, and anyone can host their own.
- **It is not a medical service** and does not replace emergency care.

Security issues: see [SECURITY.md](SECURITY.md). Made by Fábio José dos Santos, creator of [Pandu SOS](https://usepandu.com.br). If you use it, a link back is much appreciated.
