package ee.taltech.EITS_auditor_back.dto.response;

public record Sys223M18DTO(
        boolean allRemoteAssistanceRulesAreAllowed,
        boolean RemoteAssistanceDCOMInTCPNoScopeActive,
        boolean RemoteAssistanceRAServerInTCPNoScopeActive,
        boolean RemoteAssistancePnrpSvcUDPInEdgeScope,
        boolean RemoteAssistancePnrpSvcUDPInEdgeScopeActive,
        boolean RemoteAssistanceSSDPSrvInUDPActive,
        boolean RemoteAssistanceInTCPEdgeScope,
        boolean RemoteAssistanceSSDPSrvInTCPActive,
        boolean RemoteAssistanceInTCPEdgeScopeActive
        ) {
}
