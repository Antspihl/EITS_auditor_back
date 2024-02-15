package ee.taltech.EITS_auditor_back.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import ee.taltech.EITS_auditor_back.dto.osquery.AuthDTO;
import ee.taltech.EITS_auditor_back.dto.osquery.RegistryDTO;
import ee.taltech.EITS_auditor_back.dto.osquery.SecureBootDTO;
import ee.taltech.EITS_auditor_back.dto.osquery.SecurityDTO;
import ee.taltech.EITS_auditor_back.dto.response.Sys21M1DTO;
import ee.taltech.EITS_auditor_back.dto.response.Sys21M8DTO;
import ee.taltech.EITS_auditor_back.dto.response.Sys223M5DTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
@Slf4j
public class CheckService {

    private final OSQueryService OSQuery;
    private final ObjectMapper objectMapper;

    public CheckService(OSQueryService osQuery, ObjectMapper objectMapper) throws IOException {
        this.OSQuery = osQuery;
        this.objectMapper = objectMapper;
        if (!isWindows11()) {
            throw new UnsupportedOperationException("This service is only supported on Windows 11");
        }
    }

    private boolean isWindows11() throws IOException {
        String response = OSQuery.executeOSQueryCommand(
                "SELECT name FROM os_version"
        );
        return response.contains("Microsoft") && response.contains("Windows") && response.contains("11");
    }

    /**
     * Corresponds to
     * <a href="https://eits.ria.ee/et/versioon/2023/eits-poohidokumendid/etalonturbe-kataloog/sys-itsuesteemid/sys2-klientarvutid/sys22-windows-kliendid/sys223-windows-10-ja-windows-11/3-meetmed/32-poohimeetmed/sys223m5-windows-klientarvuti-kahjurvara-toorje/">E-ITS SYS.2.2.3.M5</a>
     */
    public Sys223M5DTO getWindowsDefenderStatus() throws IOException {
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

    /**
     * Corresponds to
     * <a href="https://eits.ria.ee/et/versioon/2023/eits-poohidokumendid/etalonturbe-kataloog/sys-itsuesteemid/sys2-klientarvutid/sys21-klientarvuti-ueldiselt/3-meetmed/32-poohimeetmed/sys21m1-kasutajate-turvaline-autentimine-kasutaja/">E-ITS SYS.2.1.M1</a>
     */
    public Sys21M1DTO getSecureAuthenticationOfUsers() throws IOException {
        boolean screenSaverIsEnabled = false;
        boolean screenSaverPasswordProtected = false;
        boolean needAuthToChangePassword;
        boolean autoLoginDisabled;
        boolean baseObjectsAreAudited;

        String passwordChangingResponse = OSQuery.executeOSQueryCommand(
                "SELECT logon_to_change_password FROM security_profile_info"
        );
        String screenSaverResponse = OSQuery.executeOSQueryCommand(
                "SELECT name, data FROM registry WHERE key = 'HKEY_CURRENT_USER\\Control Panel\\Desktop' AND name LIKE '%ScreenSave%'"
        );
        String autoLoginResponse = OSQuery.executeOSQueryCommand(
                "SELECT name, data FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' AND name == 'AutoAdminLogin'"
        );
        String auditResponse = OSQuery.executeOSQueryCommand(
                "SELECT name, data FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' AND name == 'auditbaseobjects'"
        );

        List<AuthDTO> securityProducts = objectMapper.readValue(passwordChangingResponse, new TypeReference<>() {
        });
        AuthDTO securityProduct = securityProducts.get(0);
        List<RegistryDTO> screenSaver = objectMapper.readValue(screenSaverResponse, new TypeReference<>() {
        });
        List<RegistryDTO> audit = objectMapper.readValue(auditResponse, new TypeReference<>() {
        });

        needAuthToChangePassword = securityProduct.logon_to_change_password() == 1;
        for (RegistryDTO registryDTO : screenSaver) {
            if (registryDTO.name().equalsIgnoreCase("ScreenSaveActive")) {
                screenSaverIsEnabled = registryDTO.data().equalsIgnoreCase("1");
            } else if (registryDTO.name().equalsIgnoreCase("ScreenSaverIsSecure")) {
                screenSaverPasswordProtected = registryDTO.data().equalsIgnoreCase("1");
            }
        }
        autoLoginDisabled = autoLoginResponse.equalsIgnoreCase("[]");
        baseObjectsAreAudited = audit.get(0).data().equalsIgnoreCase("1");

        return new Sys21M1DTO(screenSaverIsEnabled, screenSaverPasswordProtected, needAuthToChangePassword, autoLoginDisabled, baseObjectsAreAudited);
    }

    public Sys21M8DTO getBootUpSecurity() throws IOException {
        boolean secureBootEnabled = false;
        boolean secureBootSetupModeDisabled = false;
        boolean autoStartFromExternalDrivesDisabled = false;
        // boolean onlyAdminsCanChangeBootSettings = false;

        String secureBootResponse = OSQuery.executeOSQueryCommand(
                "SELECT secure_boot, setup_mode FROM secureboot"
        );
        String autostartResponse = OSQuery.executeOSQueryCommand(
                "SELECT name, data FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' AND name == 'NoDriveTypeAutoRun'"
        );

        List<SecureBootDTO> secureBoot = objectMapper.readValue(secureBootResponse, new TypeReference<>() {
        });
        List<RegistryDTO> autoStart = objectMapper.readValue(autostartResponse, new TypeReference<>() {
        });

        if (!secureBoot.isEmpty()) {
            secureBootEnabled = secureBoot.get(0).secure_boot() == 1;
            secureBootSetupModeDisabled = secureBoot.get(0).setup_mode() == 0;
        }
        for (RegistryDTO registryDTO : autoStart) {
            // the 4th bit is the flag for disabling auto start from external drives
            autoStartFromExternalDrivesDisabled = (Integer.parseInt(registryDTO.data()) & 0x10) == 0x10;
        }

        return new Sys21M8DTO(autoStartFromExternalDrivesDisabled, secureBootEnabled, secureBootSetupModeDisabled);
    }
}
