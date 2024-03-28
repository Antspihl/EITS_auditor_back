package ee.taltech.EITS_auditor_back.dto.response;

public record Sys223M18DTO(
        boolean allRemoteAssistanceRulesAreAllowed,
        boolean remoteAssistanceDCOMInTCPNoScopeActive,
        boolean remoteAssistanceRAServerInTCPNoScopeActive,
        boolean remoteAssistancePnrpSvcUDPInEdgeScope,
        boolean remoteAssistancePnrpSvcUDPInEdgeScopeActive,
        boolean remoteAssistanceSSDPSrvInUDPActive,
        boolean remoteAssistanceInTCPEdgeScope,
        boolean remoteAssistanceSSDPSrvInTCPActive,
        boolean remoteAssistanceInTCPEdgeScopeActive
        ) {
}
