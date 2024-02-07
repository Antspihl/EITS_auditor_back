package ee.taltech.EITS_auditor_back.exceptions;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.io.IOException;

@ControllerAdvice
@Slf4j
public class AuditorExceptionHandler {

    @ExceptionHandler(IOException.class)
    public ResponseEntity<Object> handleUserException(IOException e) {
        log.debug("IO exception: {}", e.getMessage());
        return ResponseEntity
                .badRequest()
                .body(e.getMessage());
    }

    @ExceptionHandler(InterruptedException.class)
    public ResponseEntity<Object> handleUserException(InterruptedException e) {
        log.debug("Interrupted exception: {}", e.getMessage());
        return ResponseEntity
                .badRequest()
                .body(e.getMessage());
    }
}
