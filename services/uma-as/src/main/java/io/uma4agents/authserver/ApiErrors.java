package io.uma4agents.authserver;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

/** FastAPI-shaped error bodies: {@code {"detail": <reason>}}. */
@RestControllerAdvice
public class ApiErrors {

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, Object>> handle(ResponseStatusException e) {
        return ResponseEntity.status(e.getStatusCode())
                .body(Map.of("detail", e.getReason() == null ? "error" : e.getReason()));
    }
}
