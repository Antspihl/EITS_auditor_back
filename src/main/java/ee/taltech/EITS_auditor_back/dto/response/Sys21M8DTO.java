package ee.taltech.EITS_auditor_back.dto.response;

public record Sys21M8DTO(
        boolean autoStartFromExternalDrivesDisabled,
        boolean secureBootEnabled,
        boolean secureBootSetupModeDisabled
        //boolean onlyAdminsCanChangeBootSettings
) {
}
