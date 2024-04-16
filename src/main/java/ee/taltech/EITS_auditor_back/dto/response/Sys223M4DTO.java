package ee.taltech.EITS_auditor_back.dto.response;

public record Sys223M4DTO(
        boolean telemetrySendingDisabled,
        boolean telemetrySendingDisabledByFirewall
) {
}
