package ee.taltech.EITS_auditor_back.dto.osquery;

public record SecurityDTO(
        String name,
        String state,
        String type,
        String up_to_date
) {
}
