package ee.taltech.EITS_auditor_back.controller;

import ee.taltech.EITS_auditor_back.dto.response.*;
import ee.taltech.EITS_auditor_back.service.CheckService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/api/")
@RequiredArgsConstructor
@Slf4j
public class CheckController {

    private final CheckService checkService;


    @GetMapping("/SYS21M1")
    public Sys21M1DTO checkSecureAuthenticationOfUsers() throws IOException {
        return checkService.getSecureAuthenticationOfUsers();
    }

    @GetMapping("/SYS21M3")
    public Sys21M3DTO automaticUpdating() {
        return checkService.getAutomaticUpdating();
    }

    @GetMapping("/SYS21M6")
    public Sys21M6DTO checkAntiMalwareStatus() throws IOException {
        return checkService.getAntiMalwareStatus();
    }

    @GetMapping("/SYS223M5")
    public Sys223M5DTO checkWindowsDefenderStatus() throws IOException {
        return checkService.getWindowsDefenderStatus();
    }

    @GetMapping("/SYS223M13")
    public Sys223M13DTO checkSmartScreenStatus() throws IOException {
        return checkService.getSmartScreenStatus();
    }

    @GetMapping("/SYS223M14")
    public Sys223M14DTO checkCortanaStatus() throws IOException {
        return checkService.getCortanaStatus();
    }

    @GetMapping("/SYS223M9")
    public Sys223M9DTO checkCentralAuthenticationStatus() {
        return checkService.getCentralAuthenticationStatus();
    }
}
