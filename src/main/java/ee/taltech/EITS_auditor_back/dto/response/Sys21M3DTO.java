package ee.taltech.EITS_auditor_back.dto.response;

public record Sys21M3DTO(
        boolean automaticUpdatingEnabled,
        boolean checkForUpdatesDailyEnabled,
        boolean controlUpdateServerAuthenticity,
        boolean checkUpdatePackagesIntegrity,
        boolean usesWSUS,
        boolean previousStateIsRestorable
) {
}
