package ee.taltech.EITS_auditor_back.service;

import ee.taltech.EITS_auditor_back.dto.SecurityDTO;
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
    * Checks the status of Windows Defender
    * Return True:
        - Microsoft Defender Antivirus is enabled and Windows Firewall is enabled
        - Something with type "Firewall" is enabled and up to date,
          and Something with type "Antivirus" is enabled and up-to-date
    * Return False:
        - If the above conditions are not met
     */
    public boolean getWindowsDefenderStatus() throws IOException {
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

        return securityProducts.stream().anyMatch(securityDTO -> {
            if (securityDTO.type().equals("Firewall")) {
                firewallEnabled.set(true);
                firewallUpToDate.set(securityDTO.up_to_date().equals("1"));
            }
            if (securityDTO.type().equals("Antivirus")) {
                antivirusEnabled.set(true);
                antivirusUpToDate.set(securityDTO.up_to_date().equals("1"));
            }
            return firewallEnabled.get() && antivirusEnabled.get() && firewallUpToDate.get() && antivirusUpToDate.get();
        });
    }
}
