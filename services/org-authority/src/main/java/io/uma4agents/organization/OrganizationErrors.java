package io.uma4agents.organization;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
final class OrganizationErrors {
    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<Map<String, String>> status(ResponseStatusException failure) {
        return ResponseEntity.status(failure.getStatusCode())
                .body(Map.of("detail", failure.getReason() == null
                        ? "request refused" : failure.getReason()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<Map<String, String>> invalid(IllegalArgumentException failure) {
        return ResponseEntity.badRequest().body(Map.of("detail",
                failure.getMessage() == null ? "invalid request" : failure.getMessage()));
    }
}
