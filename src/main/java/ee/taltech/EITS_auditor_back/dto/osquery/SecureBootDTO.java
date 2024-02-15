package ee.taltech.EITS_auditor_back.dto.osquery;

public record SecureBootDTO(
        Integer secure_boot,
        Integer setup_mode
) {
}
