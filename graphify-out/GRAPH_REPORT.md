# Graph Report - scanghost  (2026-05-11)

## Corpus Check
- 104 files · ~52,073 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 636 nodes · 881 edges · 63 communities (44 shown, 19 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 6 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `66b37766`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 40|Community 40]]

## God Nodes (most connected - your core abstractions)
1. `WebAnalysisScanModule` - 37 edges
2. `WafBypassEngine` - 25 edges
3. `VulnDetectionScanModule` - 24 edges
4. `ReconScanModule` - 23 edges
5. `ScopeEnforcer` - 23 edges
6. `Scan` - 20 edges
7. `GetScanReportQueryHandler` - 19 edges
8. `IntelligenceEngineScanModule` - 18 edges
9. `ScanOrchestrator` - 16 edges
10. `BrowserScanModule` - 15 edges

## Surprising Connections (you probably didn't know these)
- `SignalRScanProgressNotifier` --inherits--> `IScanProgressNotifier`  [EXTRACTED]
  backend/src/GhostScan.Api/Hubs/ScanProgressHub.cs → backend/src/GhostScan.Infrastructure/Orchestration/ScanOrchestrator.cs
- `ScanOrchestrator` --references--> `ILogger`  [EXTRACTED]
  backend/src/GhostScan.Infrastructure/Orchestration/ScanOrchestrator.cs → backend/src/GhostScan.Infrastructure/Tools/SafeExecutor.cs
- `BrowserScanModule` --references--> `ILogger`  [EXTRACTED]
  backend/src/GhostScan.Infrastructure/ScanModules/BrowserScanModule.cs → backend/src/GhostScan.Infrastructure/Tools/SafeExecutor.cs
- `ReconScanModule` --references--> `ILogger`  [EXTRACTED]
  backend/src/GhostScan.Infrastructure/ScanModules/ReconScanModule.cs → backend/src/GhostScan.Infrastructure/Tools/SafeExecutor.cs
- `VulnDetectionScanModule` --references--> `ILogger`  [EXTRACTED]
  backend/src/GhostScan.Infrastructure/ScanModules/VulnDetectionScanModule.cs → backend/src/GhostScan.Infrastructure/Tools/SafeExecutor.cs

## Communities (63 total, 19 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.05
Nodes (50): getScanReport(), getScans(), startScan(), Theme, ThemeConfig, ThemeContext, ThemeContextValue, THEMES (+42 more)

### Community 1 - "Community 1"
Cohesion: 0.05
Nodes (9): IReadOnlyDictionary, ScanProgress, ScanStatus, ValueObject, FindingCategory, ScanConfiguration, ScanProfile, Severity (+1 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (10): CancelScanCommandHandler, ConcurrentDictionary, GetScanHistoryQueryHandler, GetScanReportQueryHandler, GetScanStatusQueryHandler, IRequestHandler, IScanRepository, IServiceScopeFactory (+2 more)

### Community 3 - "Community 3"
Cohesion: 0.08
Nodes (9): AbstractValidator, IHttpClientFactory, IScanModule, Regex, BrowserScanModule, VulnDetectionScanModule, string, StartScanCommandValidator (+1 more)

### Community 4 - "Community 4"
Cohesion: 0.08
Nodes (13): Dictionary, ExternalToolRunner, ILogger, int, ValidationExceptionMiddleware, RequestDelegate, IntelligenceEngineScanModule, ScopeEnforcer (+5 more)

### Community 5 - "Community 5"
Cohesion: 0.09
Nodes (29): api, cancelScan(), getScanStatus(), ConnectionState, useSignalR(), UseSignalROptions, LogLine, now() (+21 more)

### Community 7 - "Community 7"
Cohesion: 0.12
Nodes (5): Random, WafBypassEngine, WafBypassFactory, WafProfile, WafProfile

### Community 8 - "Community 8"
Cohesion: 0.1
Nodes (12): BrowserScanModule, Hub, ScanProgressHub, SignalRScanProgressNotifier, IHubContext, IntelligenceEngineScanModule, IScanOrchestrator, IScanProgressNotifier (+4 more)

### Community 9 - "Community 9"
Cohesion: 0.17
Nodes (6): bool, Exception, HashSet, ScopeEnforcer, ScopeStats, ScopeViolationException

### Community 10 - "Community 10"
Cohesion: 0.13
Nodes (3): AggregateRoot, FindingCollection, Scan

### Community 12 - "Community 12"
Cohesion: 0.14
Nodes (3): ScanAggregateTests, ScanTargetTests, VulnerabilityScoreTests

### Community 13 - "Community 13"
Cohesion: 0.11
Nodes (9): ThemeProvider(), ErrorBoundary, Props, State, Dashboard, History, Report, ScanTerminal (+1 more)

### Community 14 - "Community 14"
Cohesion: 0.14
Nodes (3): Entity, FindingCollection, List

### Community 15 - "Community 15"
Cohesion: 0.12
Nodes (15): Arquitetura, code:block1 (GhostScan.Backend/), code:bash (cd src/GhostScan.Api), code:json ({), code:block4 (score = (impact × 0.6) + (confidence × 0.4) × exploitability), code:javascript (const connection = new signalR.HubConnectionBuilder()), Como rodar, Dependências externas (opcionais) (+7 more)

### Community 16 - "Community 16"
Cohesion: 0.14
Nodes (13): CorrelationDto, DirectoryBruteResultDto, HeaderAuditDto, IntelligenceResultDto, JsSecretDto, PortInfoDto, RankedTargetDto, RecommendationDto (+5 more)

### Community 17 - "Community 17"
Cohesion: 0.15
Nodes (3): IScanModule, ScanContext, ScanModuleResult

### Community 18 - "Community 18"
Cohesion: 0.18
Nodes (4): ControllerBase, ScansController, StartScanResponse, IMediator

### Community 19 - "Community 19"
Cohesion: 0.18
Nodes (3): AggregateRoot, Finding, Entity

### Community 22 - "Community 22"
Cohesion: 0.29
Nodes (6): BaseAxisProps, DataKey, ImportMeta, ImportMetaEnv, MotionProps, Variant

### Community 23 - "Community 23"
Cohesion: 0.33
Nodes (5): Comandos Rápidos, Estrutura do Projeto, Funcionalidades Principais, GhostScan v3 - Manual Técnico, Introdução

### Community 24 - "Community 24"
Cohesion: 0.4
Nodes (3): ValidationPipelineBehavior, IEnumerable, IPipelineBehavior

## Knowledge Gaps
- **107 isolated node(s):** `IMediator`, `StartScanResponse`, `IHubContext`, `RequestDelegate`, `IEnumerable` (+102 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **19 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ILogger` connect `Community 4` to `Community 3`, `Community 6`, `Community 8`, `Community 9`, `Community 11`?**
  _High betweenness centrality (0.129) - this node is a cross-community bridge._
- **Why does `ScanOrchestrator` connect `Community 8` to `Community 2`, `Community 4`?**
  _High betweenness centrality (0.094) - this node is a cross-community bridge._
- **Why does `WebAnalysisScanModule` connect `Community 6` to `Community 3`, `Community 4`?**
  _High betweenness centrality (0.069) - this node is a cross-community bridge._
- **What connects `IMediator`, `StartScanResponse`, `IHubContext` to the rest of the system?**
  _107 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.05 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.05 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.06 - nodes in this community are weakly interconnected._