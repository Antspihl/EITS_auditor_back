package ee.taltech.EITS_auditor_back.controller;

import ee.taltech.EITS_auditor_back.dto.response.Sys21M1DTO;
import ee.taltech.EITS_auditor_back.dto.response.Sys223M5DTO;
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

    @GetMapping("/SYS.2.2.3.M5")
    public Sys223M5DTO checkWindowsDefenderStatus() throws IOException {
        return checkService.getWindowsDefenderStatus();
    }

    @GetMapping("/SYS.2.1.M1")
    public Sys21M1DTO checkSecureAuthenticationOfUsers() throws IOException {
        return checkService.getSecureAuthenticationOfUsers();
    }
}
