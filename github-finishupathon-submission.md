# GhostScan v3.0 — De Scripts Isolados a um Framework Completo de Pentest Open-Source

*This is a submission for the [GitHub Finish-Up-A-Thon Challenge](https://dev.to/challenges/github-2026-05-21)*

---

## O Que Eu Construí

**GhostScan v3.0** é um framework modular de testes de penetração para Kali Linux que reúne 53 ferramentas de segurança em uma única CLI inteligente — com pontuação correlacionada, perfis de bypass de WAF, fluxos de trabalho adaptativos e geração de relatórios profissionais.

A filosofia por trás do GhostScan é simples, mas poderosa: **sinal acima do ruído**. A maioria dos scanners despeja 300+ achados brutos e deixa o analista descobrir o que importa. O GhostScan entrega **10 achados nos quais você pode agir hoje**, cada um classificado por uma fórmula de pontuação que considera impacto real, confiança de exploração e contexto de negócio:

```
score = (impacto × 0.6) + (confiança × 0.4)
```

O que o diferencia de um simples wrapper de scanner:

- **Motor de correlação** — detecta riscos compostos automaticamente. Um painel de login + SQL injection não são dois achados MÉDIOS. É um único CRÍTICO: `SQLi em Endpoint Autenticado = Bypass de Auth + Dump do BD`, com pontuação 9.8.
- **Multiplicadores de contexto** — caminhos de pagamento, bancos de dados expostos e endpoints autenticados elevam automaticamente a severidade com base no impacto ao negócio.
- **Perfis de bypass de WAF** — detecta automaticamente CloudFlare, Akamai, AWS WAF, F5, Imperva, ModSecurity, Wordfence e Sucuri, e aplica a cadeia de tamper do sqlmap correta com os delays adequados.
- **Sistema de plugins** — basta soltar um arquivo `.py` em `plugins/` e ele será carregado automaticamente no próximo scan. Plugins rodam em sandbox com kill-switch de timeout para que um plugin com falha nunca interrompa a cadeia.
- **Motor de workflow adaptativo** — após cada scan, o GhostScan gera os próximos comandos exatos com base no que foi realmente encontrado, não em um checklist estático.
- **Perfis de scan** — `stealth` (apenas passivo, delay de 2s, sem probing), `standard` (balanceado) e `aggressive` (todos os módulos, 50 threads, wordlists grandes, suite completa de injeção).
- **Geração de relatórios** — PDF, HTML, Markdown e JSON incluídos.
- **CI/CD desde o início** — GitHub Actions executa verificações de sintaxe e testes unitários no Python 3.10, 3.11 e 3.12 a cada push.

> ⚠️ Para testes de segurança autorizados apenas. Sempre obtenha permissão por escrito antes de testar qualquer sistema.

**Repositório no GitHub:** https://github.com/rodrigofurlaneti/scanghost

---

## Demo

<!-- 📸 INSIRA SEUS SCREENSHOTS AQUI -->
<!-- Screenshots sugeridos:
     1. Terminal mostrando o banner ASCII do GhostScan e o início do scan
     2. Saída da seção do Motor de Correlação (o bloco de "riscos compostos")
     3. SCAN SUMMARY com as contagens de CRITICAL/HIGH/MEDIUM/LOW
     4. O relatório PDF ou HTML gerado aberto no navegador
     5. A interface do frontend web / API
-->

**Exemplo de saída do scan (motor de correlação):**

```
✓ Painel de login em /wp-login.php (HTTP 200)
✓ SQL injection em ?search= (boolean-based)
✓ Content-Security-Policy ausente
= 🔴 CRITICAL [9.8] SQLi em Endpoint Autenticado = Bypass de Auth + Dump do BD
  Ataque: admin'-- → bypass de auth → dump de wp_users → quebra de hashes
```

```
✓ Redis na porta 6379 (exposto à internet)
✓ Sem autenticação (configuração padrão)
= 🔴 CRITICAL [9.6] Banco de Dados Exposto Externamente
  Ataque: redis-cli → CONFIG SET → RCE via cron
```

**Scan completo com relatório PDF:**
```bash
ghostscan -t seu-alvo-autorizado.com --all --report pdf
```

**Apenas reconhecimento stealth:**
```bash
ghostscan -t alvo.com --mode stealth --recon
```

**Bypass de WAF + DOM XSS via browser headless:**
```bash
ghostscan -t alvo.com --web --waf-bypass --browser --screenshots
```

---

## A História de Retomada

Este projeto começou de uma frustração real: os fluxos de trabalho de pentest são completamente fragmentados. Você roda o nmap, alimenta manualmente os resultados no nikto, depois no sqlmap, depois no gobuster — cada ferramenta em sua própria janela de terminal, cada saída em seu próprio formato, e você fica tendo que correlacionar 300 achados brutos manualmente para descobrir o que realmente importa.

Comecei o GhostScan como uma ferramenta pessoal para resolver isso. A primeira versão era um único script Python que chamava as ferramentas sequencialmente e imprimia o resultado no terminal. Funcionava, mas mal — uma ferramenta faltando travava tudo, não havia pontuação, não havia controle de escopo, e o "relatório" era um dump de texto.

Ficou inacabado por meses. A ideia central era sólida, mas precisava de muito mais trabalho antes de compartilhar com alguém. O Finish-Up-A-Thon foi o empurrão que eu precisava.

**Antes — como o projeto estava quando o retomei:**
- Um único script Python que chamava ferramentas sequencialmente
- Sem pontuação ou peso de severidade — tudo era "encontrado" ou "não encontrado"
- Sem controle de escopo — varreria hosts fora do escopo sem nenhum aviso
- Sem consciência de WAF — a maioria dos scans ativos era bloqueada imediatamente
- Relatórios eram apenas o output bruto do terminal salvo em arquivo de texto
- Sem sistema de plugins, sem extensibilidade
- Sem CI, sem testes

**O que finalizei para chegar na v3:**

1. **Controle rígido de escopo** — `ScopeEnforcer` bloqueia requisições fora do escopo e IPs vulneráveis a SSRF (`169.254.x.x`, `10.x.x.x` por padrão) antes de qualquer ferramenta rodar. Essa foi a adição de segurança mais importante.

2. **Executor paralelo seguro** — `SafeExecutor` executa ferramentas de forma concorrente com timeouts por ferramenta, lógica de retry e isolamento de falhas. Uma ferramenta com problema (ex: um template do nuclei que trava) nunca interrompe o scan.

3. **Motor de inteligência e correlação** — `IntelligenceEngine` cruza todos os achados de todos os módulos para detectar caminhos de ataque compostos. Foi o módulo mais difícil de finalizar. Os dados brutos chegam dos módulos de recon, web e vuln em formatos diferentes; o motor normaliza tudo, deduplica, aplica multiplicadores de contexto, classifica os alvos por superfície de ataque e expõe as correlações.

4. **Motor de bypass de WAF** — `WafBypass` mapeia WAFs detectados para scripts de tamper específicos do sqlmap, técnicas de encoding e delays de rate. Antes, o framework simplesmente era bloqueado e retornava zero achados contra alvos protegidos por WAF.

5. **Motor de workflow adaptativo** — `WorkflowEngine` gera os próximos passos contextuais. Se SQLi foi encontrado, ele diz exatamente quais flags do sqlmap usar. Se Redis está aberto, dá os comandos específicos do redis-cli. Não são conselhos genéricos — são comandos exatos.

6. **Módulo de browser headless** — `HeadlessBrowser` (Playwright) varre em busca de DOM XSS, endpoints ocultos e segredos client-side. Captura o que requisições HTTP estáticas perdem completamente.

7. **Sistema de plugins** — completamente novo. `plugins/base.py` define a classe base `GhostScanPlugin` com carregamento em sandbox, timeouts por plugin, limiares de confiança e limites de achados. Três plugins integrados já vêm com o framework: `admin_finder.py`, `xss_custom.py` e `sensitive_files.py`.

8. **Geração de relatórios** — `ReportingModule` agora produz relatórios PDF profissionais (via ReportLab), HTML com tema escuro, JSON estruturado e Markdown — tudo a partir do mesmo esquema normalizado de achados.

9. **Frontend web + API** — o framework foi encapsulado em uma camada de API e uma interface web para facilitar o uso além da linha de comando. O config de deploy (`staticwebapp.config.json`) já inclui headers de segurança robustos — seria constrangedor uma ferramenta de segurança ser entregue sem CSP, HSTS e X-Frame-Options.

10. **CI/CD** — GitHub Actions executa verificações de sintaxe e testes de integração no Python 3.10/3.11/3.12 a cada push. A suíte de testes valida o controle de escopo (proteção contra SSRF), os perfis de bypass de WAF e o motor de correlação da engine de inteligência.

A transformação de "script inacabado de um cara" para um framework open-source testado, documentado e com CI levou meses de noites e fins de semana. O Finish-Up-A-Thon foi o prazo que eu precisava para finalmente publicar.

---

## Minha Experiência com o GitHub Copilot

O GitHub Copilot esteve profundamente envolvido em todas as fases deste projeto — não como um gerador de código que eu aceitava cegamente, mas como um colaborador rápido e consciente do contexto que reduziu drasticamente o tempo entre "sei o que isso deve fazer" e "isso realmente funciona".

**Onde o Copilot mais ajudou:**

**Construindo o motor de inteligência.** A lógica de correlação é a parte mais complexa do GhostScan. Dado uma porta Redis aberta na internet, um painel de login, um header CSP ausente e um segredo em JS — como detectar automaticamente quais combinações criam riscos compostos CRÍTICOS? Descrevi o comportamento desejado em um comentário e o Copilot esboçou a matriz de pontuação e a lógica dos multiplicadores. Não ficou perfeito na primeira tentativa, mas me deu uma estrutura para raciocinar e refinar, em vez de encarar uma página em branco.

**Os perfis de bypass de WAF.** Mapear 8 fornecedores de WAF diferentes para suas cadeias de tamper conhecidas do sqlmap, especificidades de encoding e delays de timing é um trabalho de pesquisa tedioso. O Copilot acelerou isso de forma significativa — eu escrevia o perfil do CloudFlare, e o Copilot sugeria completions precisas para Akamai, F5 e Imperva com base no padrão que via. Ainda validei cada cadeia de tamper em ambientes de teste reais, mas o scaffolding foi gerado em minutos.

**Escrevendo o sandbox de plugins.** Construir um loader de plugins que isola travamentos, impõe timeouts, limita achados e suprime resultados com baixa confiança exige muito código boilerplate de threading e tratamento de erros. O Copilot lidou com a maior parte disso corretamente na primeira passagem, o que me permitiu focar no design da API do plugin em vez de no encanamento do `concurrent.futures`.

**O módulo de relatórios.** Gerar relatórios PDF com ReportLab é notoriamente verboso. O Copilot escreveu a maior parte do código de formatação de tabelas, mapeamento de cores e layout de página a partir de uma descrição curta e do esquema de achados. Eu estimei que isso levaria duas noites inteiras para escrever do zero; com o Copilot levou algumas horas.

**Casos de teste.** Os testes de integração do CI — validação de escopo, bypass de WAF, asserções do motor de inteligência — foram gerados principalmente pelo Copilot a partir das assinaturas de funções e docstrings. Ele entendeu o que as funções deveriam fazer e escreveu asserções com sentido.

**O que o Copilot não substituiu:** decisões de arquitetura, correção de segurança e lógica de integração de ferramentas. Cada sugestão foi revisada, e tudo que envolvia comportamento de segurança (controle de escopo, proteção contra SSRF, detecção de WAF) foi escrito e testado manualmente.

O resumo honesto: sem o Copilot, o GhostScan v3 ainda estaria inacabado. Com ele, publiquei um framework testado, documentado e com CI. Essa é a diferença.

---

<!-- Sugestão de imagem de capa: o banner ASCII do GhostScan em um terminal escuro -->
<!-- Submissão individual -->
