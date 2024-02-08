package ee.taltech.EITS_auditor_back.service;

import ee.taltech.EITS_auditor_back.dto.response.Sys223M5DTO;
import ee.taltech.EITS_auditor_back.dto.osquery.SecurityDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
@Slf4j
@RequiredArgsConstructor
public class CheckService {

    private final OSQueryService OSQuery;
    private final ObjectMapper objectMapper;

    /*
     * Corresponds to E-ITS SYS.2.2.3.M5
     * https://eits.ria.ee/et/versioon/2023/eits-poohidokumendid/etalonturbe-kataloog/sys-itsuesteemid/sys2-klientarvutid/sys22-windows-kliendid/sys223-windows-10-ja-windows-11/3-meetmed/32-poohimeetmed/sys223m5-windows-klientarvuti-kahjurvara-toorje/
     */
    public Sys223M5DTO getWindowsDefenderStatus() throws IOException {
        log.debug("Checking Windows Defender status, Service");
        String response = OSQuery.executeOSQueryCommand(
                "SELECT type, name, state, signatures_up_to_date AS up_to_date FROM windows_security_products"
        );

        List<SecurityDTO> securityProducts = objectMapper.readValue(response, new TypeReference<>() {
        });

        AtomicBoolean firewallEnabled = new AtomicBoolean(false);
        AtomicBoolean antivirusEnabled = new AtomicBoolean(false);
        AtomicBoolean firewallUpToDate = new AtomicBoolean(false);
        AtomicBoolean antivirusUpToDate = new AtomicBoolean(false);

        securityProducts.forEach(securityDTO -> {
            if (securityDTO.name().toLowerCase().contains("firewall")
                    && securityDTO.state().equalsIgnoreCase("on")) {
                firewallEnabled.set(true);
                if (securityDTO.up_to_date().equalsIgnoreCase("1")) {
                    firewallUpToDate.set(true);
                }
            } else if (securityDTO.name().toLowerCase().contains("antivirus")
                    && (securityDTO.state().equalsIgnoreCase("on"))) {
                antivirusEnabled.set(true);
                if (securityDTO.up_to_date().equalsIgnoreCase("1")) {
                    antivirusUpToDate.set(true);
                }
            }
        });
        return new Sys223M5DTO(firewallEnabled.get(), antivirusEnabled.get(), firewallUpToDate.get(), antivirusUpToDate.get());
    }
}
