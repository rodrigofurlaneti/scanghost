using GhostScan.Application.DTOs;
using MediatR;

namespace GhostScan.Application.Commands.StartScan;

public sealed record StartScanCommand(StartScanRequest Request) : IRequest<Guid>;
