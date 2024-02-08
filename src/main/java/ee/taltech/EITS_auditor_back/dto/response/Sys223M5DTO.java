package ee.taltech.EITS_auditor_back.dto.response;

public record Sys223M5DTO(
        boolean firewallEnabled,
        boolean antivirusEnabled,
        boolean firewallUpToDate,
        boolean antivirusUpToDate
) {
}
