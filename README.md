# GhostScan v3 - Manual Técnico

## Introdução
O **GhostScan** é um framework de Penetration Testing para Kali Linux focado em resultados acionáveis.

## Funcionalidades Principais
1. **Deteção de Rootkits:** Identificação de processos ocultos e módulos de kernel suspeitos.
2. **Correlação de Falhas:** Agrupamento de vulnerabilidades (ex: Login + SQLi = Crítico).
3. **Evasão de WAF:** Perfis de tamper para contornar proteções como Cloudflare e Akamai.
4. **Scoring Automático:** Cálculo de risco real baseado em impacto e confiança.

## Comandos Rápidos
- Reconhecimento: `ghostscan -t alvo.com --recon`
- Web & Vulnerabilidades: `ghostscan -t alvo.com --web --vuln`
- Relatório Completo: `ghostscan -t alvo.com --all --report both`

## Estrutura do Projeto
- `/modules`: Motores de inteligência e integração de ferramentas (53 ferramentas).
- `/plugins`: Sistema extensível para novos checks em Python.
- `/results`: Output em JSON, PDF e HTML.

## Graphify
[Graphify Out]([http://exemplo.com/](https://github.com/rodrigofurlaneti/scanghost/blob/main/graphify-out/graph.html))

---
**⚠️ Use com responsabilidade.**

