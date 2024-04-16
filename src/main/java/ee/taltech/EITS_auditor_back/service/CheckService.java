package ee.taltech.EITS_auditor_back.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import ee.taltech.EITS_auditor_back.dto.osquery.AuthDTO;
import ee.taltech.EITS_auditor_back.dto.osquery.RegistryDTO;
import ee.taltech.EITS_auditor_back.dto.osquery.SecurityDTO;
import ee.taltech.EITS_auditor_back.dto.response.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.prefs.Preferences;


@Service
@Slf4j
public class CheckService {

    private final OSQueryService OSQuery;
    private final ObjectMapper objectMapper;
    private static final String POWERSHELL = "powershell.exe";

    public CheckService(OSQueryService osQuery, ObjectMapper objectMapper) throws IOException {
        this.OSQuery = osQuery;
        this.objectMapper = objectMapper;
        if (!isWindows11()) {
            throw new UnsupportedOperationException("This service is only supported on Windows 11");
        }
    }

    private List<RegistryDTO> getRegistryValue(String commandEnd) throws IOException {
        String response = OSQuery.executeOSQueryCommand(
                "SELECT name, data FROM registry WHERE key = " + commandEnd
        );
        return objectMapper.readValue(response, new TypeReference<>() {
        });
    }

    private List<RegistryDTO> getLikeRegistryValue(String commandEnd) throws IOException {
        String response = OSQuery.executeOSQueryCommand(
                "SELECT name, data FROM registry WHERE key LIKE " + commandEnd
        );
        return objectMapper.readValue(response, new TypeReference<>() {
        });
    }

    private boolean isWindows11() throws IOException {
        String response = OSQuery.executeOSQueryCommand(
                "SELECT name FROM os_version"
        );
        return response.contains("Microsoft") && response.contains("Windows") && response.contains("11");
    }

    /**
     * Corresponds to
     * <a href="https://eits.ria.ee/et/versioon/2023/eits-poohidokumendid/etalonturbe-kataloog/sys-itsuesteemid/sys2-klientarvutid/sys21-klientarvuti-ueldiselt/3-meetmed/32-poohimeetmed/sys21m1-kasutajate-turvaline-autentimine-kasutaja/">E-ITS SYS.2.1.M1</a>
     **/
    public Sys21M1DTO getSecureAuthenticationOfUsers() throws IOException {
        Sys21M1DTO screenSaverStatusPartialDTO = getScreenSaverStatus();
        boolean needAuthToChangePassword = getNeedAuthToChangePassword();
        boolean autoLoginDisabled = getAutoLoginDisabled();
        boolean baseObjectsAreAudited = areBaseObjectsAudited();

        return new Sys21M1DTO(
                screenSaverStatusPartialDTO.screenSaverIsEnabled(),
                screenSaverStatusPartialDTO.screenSaverPasswordProtected(),
                needAuthToChangePassword,
                autoLoginDisabled,
                baseObjectsAreAudited);
    }

    /**
     * Corresponds to
     * <a href="https://eits.ria.ee/et/versioon/2023/eits-poohidokumendid/etalonturbe-kataloog/sys-itsuesteemid/sys2-klientarvutid/sys21-klientarvuti-ueldiselt/3-meetmed/32-poohimeetmed/sys21m3-uuendite-automaatpaigaldus/">E-ITS SYS.2.1.M3</a>
     **/
    public Sys21M3DTO getAutomaticUpdating() {
        boolean automaticUpdatingEnabled = areAutomaticUpdatesEnabled();
        boolean checkForUpdatesDailyEnabled = areUpdatesCheckedDaily();
        boolean controlUpdateServerAuthenticity = isUpdateServerAuthenticityControlled();
        boolean checkUpdatePackagesIntegrity = isUpdatePackagesIntegrityChecked();
        boolean usesWSUS = isWSUSUsed();
        boolean previousStateIsRestorable = isPreviousStateRestorable();

        return new Sys21M3DTO(automaticUpdatingEnabled, checkForUpdatesDailyEnabled, controlUpdateServerAuthenticity, checkUpdatePackagesIntegrity, usesWSUS, previousStateIsRestorable);
    }

    /**
     * Corresponds to
     * <a href="https://eits.ria.ee/et/versioon/2023/eits-poohidokumendid/etalonturbe-kataloog/sys-itsuesteemid/sys2-klientarvutid/sys21-klientarvuti-ueldiselt/3-meetmed/32-poohimeetmed/sys21m6-kahjurvaratoorje-tarkvara/">E-ITS SYS.2.1.M6</a>
     **/
    public Sys21M6DTO getAntiMalwareStatus() throws IOException {
        Sys223M5DTO windowsDefenderStatus = getWindowsDefenderStatus();
        return new Sys21M6DTO(windowsDefenderStatus.antivirusEnabled(), windowsDefenderStatus.antivirusUpToDate());
    }

    /**
     * Corresponds to
     * <a href="https://eits.ria.ee/et/versioon/2023/eits-poohidokumendid/etalonturbe-kataloog/sys-itsuesteemid/sys2-klientarvutid/sys22-windows-kliendid/sys223-windows-10-ja-windows-11/3-meetmed/32-poohimeetmed/sys223m4-telemeetria-andmekaitseseaded/">E-ITS SYS.2.2.3.M4</a>
     */
    public Sys223M4DTO getTelemetrySending() {
        boolean telemetryStatus = isTelemetryDisabled();
        boolean telemetryStatusByFirewall = isTelemetryDisabledByFirewall();
        return new Sys223M4DTO(telemetryStatus, telemetryStatusByFirewall);
    }

    /**
     * Corresponds to
     * <a href="https://eits.ria.ee/et/versioon/2023/eits-poohidokumendid/etalonturbe-kataloog/sys-itsuesteemid/sys2-klientarvutid/sys22-windows-kliendid/sys223-windows-10-ja-windows-11/3-meetmed/32-poohimeetmed/sys223m5-windows-klientarvuti-kahjurvara-toorje/">E-ITS SYS.2.2.3.M5</a>
     **/
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
     * <a href="https://eits.ria.ee/et/versioon/2023/eits-poohidokumendid/etalonturbe-kataloog/sys-itsuesteemid/sys2-klientarvutid/sys22-windows-kliendid/sys223-windows-10-ja-windows-11/3-meetmed/33-standardmeetmed/sys223m9-keskne-autentimine/">E-ITS SYS.2.2.3.M9</a>
     */
    public Sys223M9DTO getCentralAuthenticationStatus() {
        boolean isKerberosEnabled = isKerberosEnabled();
        boolean isNTLMv2Enabled = isNTLMv2Enabled();
        return new Sys223M9DTO(isKerberosEnabled || isNTLMv2Enabled);
    }

    /**
     * Corresponds to
     * <a href="https://eits.ria.ee/et/versioon/2023/eits-poohidokumendid/etalonturbe-kataloog/sys-itsuesteemid/sys2-klientarvutid/sys22-windows-kliendid/sys223-windows-10-ja-windows-11/3-meetmed/33-standardmeetmed/sys223m13-funktsiooni-smartscreen-desaktiveerimine/">E-ITS SYS.2.2.3.M13</a>
     */
    public Sys223M13DTO getSmartScreenStatus() throws IOException {
        boolean smartscreenEdgeDisabled = isSmartscreenEdgeDisabled();
        boolean smartScreenPuaDisabled = isSmartscreenPuaDisabled();
        return new Sys223M13DTO(smartscreenEdgeDisabled, smartScreenPuaDisabled);
    }

    /**
     * Corresponds to
     * <a href="https://eits.ria.ee/et/versioon/2023/eits-poohidokumendid/etalonturbe-kataloog/sys-itsuesteemid/sys2-klientarvutid/sys22-windows-kliendid/sys223-windows-10-ja-windows-11/3-meetmed/33-standardmeetmed/sys223m14-digitaalse-assistendi-cortana-desaktiveerimine-kasutaja/">E-ITS SYS.2.2.3.M14</a>
     */
    public Sys223M14DTO getCortanaStatus() throws IOException {
        boolean cortanaDisabled = isCortanaDisabled();
        return new Sys223M14DTO(cortanaDisabled);
    }

    /**
     * Corresponds to
     * <a href="https://eits.ria.ee/et/versioon/2023/eits-poohidokumendid/etalonturbe-kataloog/sys-itsuesteemid/sys2-klientarvutid/sys22-windows-kliendid/sys223-windows-10-ja-windows-11/3-meetmed/33-standardmeetmed/sys223m18-remote-assistance-kaugtoe-turvaline-rakendamine/">E-ITS SYS.2.2.3.M18</a>
     */
    public Sys223M18DTO getAllRemoteAssistanceStatus() throws IOException {
        // Get-NetFirewallRule -DisplayGroup 'Remote Assistance' | Where-Object { $_.Direction -eq 'Inbound' } | Format-Table -Property Name, Enabled
        boolean remoteAssistanceDCOMInTCPNoScopeActive = false;
        boolean remoteAssistanceRAServerInTCPNoScopeActive = false;
        boolean remoteAssistancePnrpSvcUDPInEdgeScope = false;
        boolean remoteAssistancePnrpSvcUDPInEdgeScopeActive = false;
        boolean remoteAssistanceSSDPSrvInUDPActive = false;
        boolean remoteAssistanceInTCPEdgeScope = false;
        boolean remoteAssistanceSSDPSrvInTCPActive = false;
        boolean remoteAssistanceInTCPEdgeScopeActive = false;
        Process process = new ProcessBuilder(POWERSHELL,
                "Get-NetFirewallRule", "-DisplayGroup", "'Remote Assistance'",
                "|", "Where-Object", "{", "$_.Direction", "-eq", "'Inbound'", "}",
                "|", "Format-Table", "-Property", "Name,Enabled").start();
        Map<String, String> textBlockAsList = getTextBlockAsList(process);
        boolean allAreTrue = textBlockAsList.values().stream().allMatch(s -> s.equalsIgnoreCase("True"));
        for (Map.Entry<String, String> entry : textBlockAsList.entrySet()) {
            String key = entry.getKey();
            if (key.contains("DCOM")) {
                remoteAssistanceDCOMInTCPNoScopeActive = entry.getValue().equalsIgnoreCase("True");
            } else if (key.contains("RAServer")) {
                remoteAssistanceRAServerInTCPNoScopeActive = entry.getValue().equalsIgnoreCase("True");
            } else if (key.contains("PnrpSvc-UDP-In-EdgeScope")) {
                remoteAssistancePnrpSvcUDPInEdgeScope = true;
                remoteAssistancePnrpSvcUDPInEdgeScopeActive = entry.getValue().equalsIgnoreCase("True");
            } else if (key.contains("SSDPSrv-UDP-In-Active")) {
                remoteAssistanceSSDPSrvInUDPActive = entry.getValue().equalsIgnoreCase("True");
            } else if (key.contains("In-TCPEdgeScope")) {
                remoteAssistanceInTCPEdgeScope = true;
                remoteAssistanceInTCPEdgeScopeActive = entry.getValue().equalsIgnoreCase("True");
            } else if (key.contains("SSDPSrv-TCP-In-Active")) {
                remoteAssistanceSSDPSrvInTCPActive = entry.getValue().equalsIgnoreCase("True");
            }
        }
        return new Sys223M18DTO(allAreTrue,
                remoteAssistanceDCOMInTCPNoScopeActive,
                remoteAssistanceRAServerInTCPNoScopeActive,
                remoteAssistancePnrpSvcUDPInEdgeScope,
                remoteAssistancePnrpSvcUDPInEdgeScopeActive,
                remoteAssistanceSSDPSrvInUDPActive,
                remoteAssistanceInTCPEdgeScope,
                remoteAssistanceSSDPSrvInTCPActive,
                remoteAssistanceInTCPEdgeScopeActive);

    }

    /**
     * Corresponds to
     * <a href="https://eits.ria.ee/et/versioon/2023/eits-poohidokumendid/etalonturbe-kataloog/sys-itsuesteemid/sys2-klientarvutid/sys22-windows-kliendid/sys223-windows-10-ja-windows-11/3-meetmed/33-standardmeetmed/sys223m19-kaughaldusvahendi-rdp-turvaline-rakendamine-kasutaja/">E-ITS SYS.2.2.3.M19</a>
     */
    public Sys223M19DTO getAllRDPStatus() throws IOException {
        Sys223M19DTO partialDTO = getAllRDPRuleStatuses();
        boolean allRDPRulesAreAllowed = partialDTO.remoteDesktopShadowInTCP() && partialDTO.remoteDesktopUserModeInTCP() && partialDTO.remoteDesktopUserModeInUDP();
        return new Sys223M19DTO(
                allRDPRulesAreAllowed,
                partialDTO.remoteDesktopShadowInTCP(),
                partialDTO.remoteDesktopUserModeInTCP(),
                partialDTO.remoteDesktopUserModeInUDP());
    }

    private Sys223M19DTO getAllRDPRuleStatuses() throws IOException {
        // Get-NetFirewallRule -DisplayGroup 'Remote Desktop' | Where-Object { $_.Direction -eq 'Inbound' } | Format-Table -Property Name, Enabled
        boolean remoteDesktopShadowInTCP = false;
        boolean remoteDesktopUserModeInTCP = false;
        boolean remoteDesktopUserModeInUDP = false;
        Process process = new ProcessBuilder(POWERSHELL,
                "Get-NetFirewallRule", "-DisplayGroup", "'Remote Desktop'",
                "|", "Where-Object", "{", "$_.Direction", "-eq", "'Inbound'", "}",
                "|", "Format-Table", "-Property", "Name, Enabled").start();
        Map<String, String> textBlockAsList = getTextBlockAsList(process);
        for (Map.Entry<String, String> entry : textBlockAsList.entrySet()) {
            if (entry.getKey().contains("Shadow")) {
                remoteDesktopShadowInTCP = entry.getValue().equalsIgnoreCase("True");
            } else if (entry.getKey().contains("UserMode")) {
                remoteDesktopUserModeInTCP = entry.getValue().equalsIgnoreCase("True");
            } else if (entry.getKey().contains("UserMode-In-UDP")) {
                remoteDesktopUserModeInUDP = entry.getValue().equalsIgnoreCase("True");
            }
        }
        return new Sys223M19DTO(false, remoteDesktopShadowInTCP, remoteDesktopUserModeInTCP, remoteDesktopUserModeInUDP);
    }

    private static Map<String, String> getTextBlockAsList(Process process) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        Map<String, String> result = new HashMap<>();
        while ((line = reader.readLine()) != null) {
            if (line.contains("Name") || line.contains("----") || line.isEmpty()) {
                continue;
            }
            String[] split = line.split("\\s+");
            result.put(split[0], split[1]);
        }
        return result;
    }

    public static boolean isKerberosEnabled() {
        try {
            // Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "LogLevel"
            Process process = new ProcessBuilder(POWERSHELL, "Get-ItemProperty", "-Path", "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters", "-Name", "LogLevel", "-ErrorAction", "SilentlyContinue").start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("LogLevel")) {
                    int value = Integer.parseInt(line.split(":")[1].trim());
                    return 0 <= value && value <= 1;
                }
            }
        } catch (Exception e) {
            log.debug("Error occurred while checking if Kerberos is enabled", e);
        }
        return false;
    }

    public boolean isTelemetryDisabled() {
        // Get-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"
        try {
            Process process = new ProcessBuilder(POWERSHELL, "Get-ItemProperty", "-Path", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", "-Name", "AllowTelemetry", "-ErrorAction", "SilentlyContinue").start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("AllowTelemetry")) {
                    int value = Integer.parseInt(line.split(":")[1].trim());
                    return value == 0;
                }
            }
        } catch (Exception e) {
            log.debug("Error occurred while checking if telemetry is enabled", e);
        }
        return false;
    }

    private boolean isTelemetryDisabledByFirewall() {
        // Get-NetFirewallRule -DisplayName "DiagTrack*" | Where-Object { $_.Direction -eq 'Outbound' -and $_.Enabled -eq $true -and $_.Action -eq 'Allow' }
        try {
            Process process = new ProcessBuilder(POWERSHELL, "Get-NetFirewallRule", "-DisplayName",
                    "DiagTrack*", "|", "Where-Object", "{", "$_.Direction", "-eq", "'Outbound'", "-and",
                    "$_.Enabled", "-eq", "$true", "-and", "$_.Action", "-eq", "'Allow'", "}").start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isEmpty()) {
                    return false;
                }
            }
            // Get-NetFirewallRule -DisplayName "DiagTrack*" | Where-Object { $_.Direction -eq 'Outbound' -and $_.Enabled -eq $true -and $_.Action -ne 'Allow' }
            process = new ProcessBuilder(POWERSHELL, "Get-NetFirewallRule", "-DisplayName",
                    "DiagTrack*", "|", "Where-Object", "{", "$_.Direction", "-eq", "'Outbound'", "-and",
                    "$_.Enabled", "-eq", "$true", "-and", "$_.Action", "-ne", "'Allow'", "}").start();
            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            while ((line = reader.readLine()) != null) {
                if (!line.isEmpty()) {
                    return true;
                }
            }
        } catch (Exception e) {
            log.debug("Error occurred while checking if telemetry is disabled by firewall", e);
        }
        return false;

    }

    public static boolean isNTLMv2Enabled() {
        try {
            // Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel"
            Process process = new ProcessBuilder(POWERSHELL, "Get-ItemProperty", "-Path", "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "-Name", "LMCompatibilityLevel", "-ErrorAction", "SilentlyContinue").start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("LMCompatibilityLevel")) {
                    int value = Integer.parseInt(line.split(":")[1].trim());
                    return 3 <= value && value <= 5;
                }
            }
        } catch (Exception e) {
            log.debug("Error occurred while checking if NTLMv2 is enabled", e);
        }
        return false;
    }

    public boolean isCortanaDisabled() throws IOException {
        List<RegistryDTO> cortana = getLikeRegistryValue(
                "'HKEY_USERS\\%\\Software\\Microsoft\\Windows\\CurrentVersion\\Cortana' AND name == 'IsAvailable'");
        return cortana.get(0).data().equalsIgnoreCase("0");
    }

    private boolean isSmartscreenEdgeDisabled() throws IOException {
        List<RegistryDTO> smartScreen = getLikeRegistryValue(
                "'HKEY_USERS\\%\\Software\\Microsoft\\Edge\\SmartScreenEnabled'");
        if (smartScreen.isEmpty()) {
            return false;
        }
        return smartScreen.get(0).data().equalsIgnoreCase("0");
    }

    private boolean isSmartscreenPuaDisabled() throws IOException {
        List<RegistryDTO> smartScreen = getLikeRegistryValue(
                "'HKEY_USERS\\%\\Software\\Microsoft\\Edge\\SmartScreenPuaEnabled'");
        if (smartScreen.isEmpty()) {
            return false;
        }
        return smartScreen.get(0).data().equalsIgnoreCase("0");
    }

    private boolean areAutomaticUpdatesEnabled() {
        String windowsUpdateKeyPath = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update";
        String groupPolicyValueName = "UseWUServer";
        List<Integer> allowedStates = List.of(2, 3, 4);

        try {
            Preferences prefs = Preferences.systemRoot().node(windowsUpdateKeyPath);
            int auOptions = prefs.getInt("AUOptions", -1);
            boolean isGroupPolicySet = prefs.nodeExists(groupPolicyValueName);

            return allowedStates.contains(auOptions) && !isGroupPolicySet;
        } catch (Exception e) {
            log.debug("Error occurred while checking if automatic updates are enabled", e);
            return false;
        }
    }

    private boolean areUpdatesCheckedDaily() {
        String registryPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update";

        try {
            Preferences prefs = Preferences.systemRoot().node(registryPath);

            return prefs.getBoolean("AUOptions", false);
        } catch (Exception e) {
            log.debug("Error occurred while checking if updates are checked daily", e);
            return false;
        }
    }

    private boolean isUpdateServerAuthenticityControlled() {
        String registryPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";

        try {
            Preferences prefs = Preferences.systemRoot().node(registryPath);

            return prefs.getBoolean("ValidateAdminCodeSignatures", false);
        } catch (Exception e) {
            log.debug("Error occurred while checking if update server authenticity is controlled", e);
            return false;
        }
    }

    private boolean isUpdatePackagesIntegrityChecked() {
        String registryPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";

        try {
            Preferences prefs = Preferences.systemRoot().node(registryPath);

            return prefs.getBoolean("HideFastSwitchNotification", false);
        } catch (Exception e) {
            log.debug("Error occurred while checking if update packages integrity is checked", e);
            return false;
        }
    }

    private boolean isWSUSUsed() {
        String registryPath = "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate";

        try {
            Preferences prefs = Preferences.systemRoot().node(registryPath);

            return prefs.getBoolean("WUServer", false);
        } catch (Exception e) {
            log.debug("Error occurred while checking if WSUS is used", e);
            return false;
        }
    }

    private boolean isPreviousStateRestorable() {
        String registryPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";

        try {
            Preferences prefs = Preferences.systemRoot().node(registryPath);

            return prefs.getBoolean("DisableAutomaticRestartSignOn", false);
        } catch (Exception e) {
            log.debug("Error occurred while checking if previous state is restorable", e);
            return false;
        }
    }

    private boolean areBaseObjectsAudited() throws IOException {
        List<RegistryDTO> audit = getRegistryValue("'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' AND name == 'auditbaseobjects'");
        if (audit.isEmpty()) {
            return false;
        }
        return audit.get(0).data().equalsIgnoreCase("1");
    }

    private boolean getAutoLoginDisabled() throws IOException {
        String autoLoginResponse = OSQuery.executeOSQueryCommand(
                "SELECT name, data FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' AND name == 'AutoAdminLogin'"
        );

        return autoLoginResponse.equalsIgnoreCase("[]");
    }

    private boolean getNeedAuthToChangePassword() throws IOException {
        String passwordChangingResponse = OSQuery.executeOSQueryCommand(
                "SELECT logon_to_change_password FROM security_profile_info"
        );
        List<AuthDTO> securityProducts = objectMapper.readValue(passwordChangingResponse, new TypeReference<>() {
        });
        if (securityProducts.isEmpty()) {
            return false;
        }
        AuthDTO securityProduct = securityProducts.get(0);
        return securityProduct.logon_to_change_password() == 1;
    }

    private Sys21M1DTO getScreenSaverStatus() throws IOException {
        boolean screenSaverIsEnabled = false;
        boolean screenSaverPasswordProtected = false;

        List<RegistryDTO> screenSaver = getRegistryValue("'HKEY_CURRENT_USER\\Control Panel\\Desktop' AND name LIKE '%ScreenSave%'");

        for (RegistryDTO registryDTO : screenSaver) {
            if (registryDTO.name().equalsIgnoreCase("ScreenSaveActive")) {
                screenSaverIsEnabled = registryDTO.data().equalsIgnoreCase("1");
            } else if (registryDTO.name().equalsIgnoreCase("ScreenSaverIsSecure")) {
                screenSaverPasswordProtected = registryDTO.data().equalsIgnoreCase("1");
            }
        }

        return new Sys21M1DTO(screenSaverIsEnabled, screenSaverPasswordProtected, false, false, false);
    }
}
