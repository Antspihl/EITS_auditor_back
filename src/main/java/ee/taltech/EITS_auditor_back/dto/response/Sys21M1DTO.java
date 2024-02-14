package ee.taltech.EITS_auditor_back.dto.response;

public record Sys21M1DTO(
        boolean screenSaverIsEnabled,
        boolean screenSaverPasswordProtected,
        boolean needAuthToChangePassword,
        boolean autoLogonIsDisabled,
        boolean baseObjectsAreAudited
) {
}
