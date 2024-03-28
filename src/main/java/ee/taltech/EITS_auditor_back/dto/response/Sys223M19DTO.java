package ee.taltech.EITS_auditor_back.dto.response;

public record Sys223M19DTO(
        boolean allRDPRulesAreAllowed,
        boolean remoteDesktopShadowInTCP,
        boolean remoteDesktopUserModeInTCP,
        boolean remoteDesktopUserModeInUDP
) {
}
