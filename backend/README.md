# GhostScan Backend API

**GhostScan v3 — .NET 8.0 Vulnerability Scanner API**

API REST construída com DDD + CQRS, baseada no GhostScan POC Python.

## Arquitetura

```
GhostScan.Backend/
├── src/
│   ├── GhostScan.Domain/           ← Domínio rico (entidades, value objects, eventos)
│   ├── GhostScan.Application/      ← CQRS (Commands, Queries, Handlers, Validators)
│   ├── GhostScan.Infrastructure/   ← Módulos de scan, repositórios, orquestrador
│   └── GhostScan.Api/             ← Controllers, SignalR Hub, Swagger, Program.cs
└── tests/
    ├── GhostScan.Domain.Tests/
    └── GhostScan.Application.Tests/
```

## Como rodar

```bash
cd src/GhostScan.Api
dotnet run
```

Swagger estará disponível em: **http://localhost:5000**

## Endpoints principais

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `POST` | `/api/scans` | Iniciar um novo scan (assíncrono) |
| `GET` | `/api/scans/{id}/status` | Verificar progresso do scan |
| `GET` | `/api/scans/{id}/report` | Obter relatório completo |
| `DELETE` | `/api/scans/{id}` | Cancelar um scan em andamento |
| `GET` | `/api/scans` | Histórico de scans |
| `POST` | `/api/scans/quick` | Scan síncrono (aguarda até 5 min) |
| `GET` | `/health` | Health check |

## Uso básico — Swagger

1. Abra http://localhost:5000
2. Use `POST /api/scans/quick` com:
```json
{
  "target": "example.com",
  "profile": "standard",
  "runRecon": true,
  "runWeb": true,
  "runVuln": true,
  "minSeverity": "info"
}
```
3. Aguarde e receba o relatório completo.

## Profiles de scan

| Profile | Threads | Rate | SQLi | XSS | Brute | WAF |
|---------|---------|------|------|-----|-------|-----|
| `stealth` | 5 | 2s | ✗ | ✗ | ✗ | ✗ |
| `standard` | 20 | 0.1s | ✓ | ✓ | ✗ | auto |
| `aggressive` | 50 | 0.05s | ✓ | ✓ | ✓ | ✓ |

## Scoring

```
score = (impact × 0.6) + (confidence × 0.4) × exploitability × businessImpact
```

## Real-time (SignalR)

Conecte ao WebSocket: `ws://localhost:5000/hubs/scan`

```javascript
const connection = new signalR.HubConnectionBuilder()
  .withUrl("/hubs/scan")
  .build();

await connection.start();
await connection.invoke("SubscribeToScan", scanId);

connection.on("ScanProgress", (data) => {
  console.log(`${data.percentComplete}% — ${data.phase}: ${data.activity}`);
});

connection.on("ScanCompleted", (data) => {
  console.log(`Scan completed! ${data.totalFindings} findings.`);
});
```

## Módulos implementados

| Módulo | Funcionalidades |
|--------|----------------|
| **Recon** | DNS enum, zone transfer, subdomain brute-force, port scan (nmap + socket fallback), OSINT, WHOIS |
| **Web Analysis** | Crawling, probing de paths sensíveis, header audit, JS secret scan, WAF detection, CORS, cookies |
| **Vuln Detection** | SQLi (sqlmap + built-in), XSS, CVE correlation (16 CVEs), SSL/TLS, open redirect, brute-force |
| **Intelligence** | Correlação de findings, scoring contextual, ranking de alvos, recomendações priorizadas |

## Dependências externas (opcionais)

Os módulos detectam automaticamente ferramentas instaladas no sistema:

| Ferramenta | Módulo | Fallback |
|-----------|--------|---------|
| `nmap` | Recon | Socket scan |
| `amass` | Recon | DNS brute-force |
| `sqlmap` | Vuln | Built-in error detection |
| `gobuster` / `ffuf` | Web | — |
| `whatweb` | Web | — |
| `wafw00f` | Web | Header detection |
| `testssl.sh` | Vuln | Basic SSL check |
| `hydra` | Vuln | — |

> ⚠️ **Uso autorizado somente.** Este software é para testes de segurança autorizados.
