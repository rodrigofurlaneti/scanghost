# Graph Report - scanghost  (2026-05-11)

## Corpus Check
- 151 files · ~51,773 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 754 nodes · 963 edges · 110 communities (79 shown, 31 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 6 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `88a9d247`
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
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]
- [[_COMMUNITY_Community 51|Community 51]]
- [[_COMMUNITY_Community 52|Community 52]]
- [[_COMMUNITY_Community 53|Community 53]]
- [[_COMMUNITY_Community 54|Community 54]]
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 57|Community 57]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 60|Community 60]]

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
- `Dashboard()` --calls--> `useTheme()`  [EXTRACTED]
  frontend/src/pages/Dashboard.tsx → frontend/src/contexts/ThemeContext.tsx
- `SignalRScanProgressNotifier` --inherits--> `IScanProgressNotifier`  [EXTRACTED]
  backend/src/GhostScan.Api/Hubs/ScanProgressHub.cs → backend/src/GhostScan.Infrastructure/Orchestration/ScanOrchestrator.cs
- `ScanOrchestrator` --references--> `ILogger`  [EXTRACTED]
  backend/src/GhostScan.Infrastructure/Orchestration/ScanOrchestrator.cs → backend/src/GhostScan.Infrastructure/Tools/SafeExecutor.cs
- `BrowserScanModule` --references--> `ILogger`  [EXTRACTED]
  backend/src/GhostScan.Infrastructure/ScanModules/BrowserScanModule.cs → backend/src/GhostScan.Infrastructure/Tools/SafeExecutor.cs
- `ReconScanModule` --references--> `ILogger`  [EXTRACTED]
  backend/src/GhostScan.Infrastructure/ScanModules/ReconScanModule.cs → backend/src/GhostScan.Infrastructure/Tools/SafeExecutor.cs

## Communities (110 total, 31 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.07
Nodes (16): Dictionary, DnsTakeoverEngine, GhostScan.Infrastructure.ScanModules.Web.Engines, ExternalToolRunner, IDnsTakeoverEngine, ILogger, int, ValidationExceptionMiddleware (+8 more)

### Community 1 - "Community 1"
Cohesion: 0.05
Nodes (9): IReadOnlyDictionary, ScanProgress, ScanStatus, ValueObject, FindingCategory, ScanConfiguration, ScanProfile, Severity (+1 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (10): CancelScanCommandHandler, ConcurrentDictionary, GetScanHistoryQueryHandler, GetScanReportQueryHandler, GetScanStatusQueryHandler, IRequestHandler, IScanRepository, IServiceScopeFactory (+2 more)

### Community 3 - "Community 3"
Cohesion: 0.08
Nodes (22): Theme, ThemeConfig, ThemeContext, ThemeContextValue, ThemeProvider(), THEMES, useTheme(), LANGS (+14 more)

### Community 5 - "Community 5"
Cohesion: 0.12
Nodes (4): IHttpClientFactory, IScanModule, BrowserScanModule, VulnDetectionScanModule

### Community 6 - "Community 6"
Cohesion: 0.12
Nodes (5): Random, WafBypassEngine, WafBypassFactory, WafProfile, WafProfile

### Community 7 - "Community 7"
Cohesion: 0.1
Nodes (12): BrowserScanModule, Hub, ScanProgressHub, SignalRScanProgressNotifier, IHubContext, IntelligenceEngineScanModule, IScanOrchestrator, IScanProgressNotifier (+4 more)

### Community 8 - "Community 8"
Cohesion: 0.17
Nodes (6): bool, Exception, HashSet, ScopeEnforcer, ScopeStats, ScopeViolationException

### Community 9 - "Community 9"
Cohesion: 0.11
Nodes (19): api, getScanStatus(), startScan(), CorrelationDto, HeaderAuditDto, IntelligenceResultDto, JsSecretDto, PagedResult (+11 more)

### Community 10 - "Community 10"
Cohesion: 0.13
Nodes (3): AggregateRoot, FindingCollection, Scan

### Community 12 - "Community 12"
Cohesion: 0.14
Nodes (3): ScanAggregateTests, ScanTargetTests, VulnerabilityScoreTests

### Community 13 - "Community 13"
Cohesion: 0.14
Nodes (3): Entity, FindingCollection, List

### Community 14 - "Community 14"
Cohesion: 0.14
Nodes (12): Dashboard(), PROFILES, CHARS, MatrixRain(), MatrixRainProps, PIPELINE, PROFILES, ScanDocs() (+4 more)

### Community 15 - "Community 15"
Cohesion: 0.12
Nodes (6): ErrorAnalyzer, GhostScan.Infrastructure.ScanModules.Web.Engines, SecretScanner, ISecretScanner, Regex, ScanTarget

### Community 16 - "Community 16"
Cohesion: 0.12
Nodes (15): Arquitetura, code:block1 (GhostScan.Backend/), code:bash (cd src/GhostScan.Api), code:json ({), code:block4 (score = (impact × 0.6) + (confidence × 0.4) × exploitability), code:javascript (const connection = new signalR.HubConnectionBuilder()), Como rodar, Dependências externas (opcionais) (+7 more)

### Community 17 - "Community 17"
Cohesion: 0.16
Nodes (7): AbstractValidator, PathProber, SecurityAuditEngine, IPathProber, ISecurityAuditEngine, string, StartScanCommandValidator

### Community 18 - "Community 18"
Cohesion: 0.14
Nodes (13): CorrelationDto, DirectoryBruteResultDto, HeaderAuditDto, IntelligenceResultDto, JsSecretDto, PortInfoDto, RankedTargetDto, RecommendationDto (+5 more)

### Community 19 - "Community 19"
Cohesion: 0.21
Nodes (10): cancelScan(), ConnectionState, useSignalR(), UseSignalROptions, LogLine, now(), ScanTerminal(), ScanCompletedEvent (+2 more)

### Community 20 - "Community 20"
Cohesion: 0.19
Nodes (11): getScanReport(), formatDate(), severityColor(), FindingRow(), Report(), SEVERITY_ORDER, SeverityBadge(), SeverityBadgeProps (+3 more)

### Community 21 - "Community 21"
Cohesion: 0.15
Nodes (3): IScanModule, ScanContext, ScanModuleResult

### Community 22 - "Community 22"
Cohesion: 0.26
Nodes (8): cn(), statusVariant(), CopyButton(), CopyButtonProps, GlitchText(), GlitchTextProps, StatusBadge(), StatusBadgeProps

### Community 23 - "Community 23"
Cohesion: 0.18
Nodes (4): ControllerBase, ScansController, StartScanResponse, IMediator

### Community 24 - "Community 24"
Cohesion: 0.18
Nodes (3): AggregateRoot, Finding, Entity

### Community 25 - "Community 25"
Cohesion: 0.22
Nodes (5): GhostScan.Infrastructure.ScanModules.Web.Adapters, NiktoAdapter, GhostScan.Infrastructure.ScanModules.Web.Adapters, NucleiAdapter, IToolAdapter

### Community 26 - "Community 26"
Cohesion: 0.25
Nodes (6): getScans(), formatDuration(), STATUS_OPTIONS, TerminalCard(), TerminalCardProps, ScanStatus

### Community 29 - "Community 29"
Cohesion: 0.29
Nodes (6): BaseAxisProps, DataKey, ImportMeta, ImportMetaEnv, MotionProps, Variant

### Community 30 - "Community 30"
Cohesion: 0.33
Nodes (5): Comandos Rápidos, Estrutura do Projeto, Funcionalidades Principais, GhostScan v3 - Manual Técnico, Introdução

### Community 31 - "Community 31"
Cohesion: 0.4
Nodes (3): ValidationPipelineBehavior, IEnumerable, IPipelineBehavior

### Community 34 - "Community 34"
Cohesion: 0.4
Nodes (3): ApiFuzzerEngine, GhostScan.Infrastructure.ScanModules.Web.Engines, IApiFuzzerEngine

## Knowledge Gaps
- **122 isolated node(s):** `IMediator`, `StartScanResponse`, `IHubContext`, `RequestDelegate`, `IEnumerable` (+117 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **31 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ILogger` connect `Community 0` to `Community 4`, `Community 5`, `Community 7`, `Community 8`, `Community 11`?**
  _High betweenness centrality (0.100) - this node is a cross-community bridge._
- **Why does `ScanOrchestrator` connect `Community 7` to `Community 0`, `Community 2`?**
  _High betweenness centrality (0.073) - this node is a cross-community bridge._
- **Why does `Dictionary` connect `Community 0` to `Community 4`, `Community 5`, `Community 6`, `Community 10`, `Community 11`, `Community 15`, `Community 17`, `Community 21`?**
  _High betweenness centrality (0.064) - this node is a cross-community bridge._
- **What connects `IMediator`, `StartScanResponse`, `IHubContext` to the rest of the system?**
  _122 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.07 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.05 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.06 - nodes in this community are weakly interconnected._