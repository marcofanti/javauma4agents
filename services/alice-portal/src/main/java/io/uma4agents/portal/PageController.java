package io.uma4agents.portal;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Serves the pinned upstream SPA, vendored unchanged under conformance/upstream. */
@RestController
public class PageController {

    private final Path staticDir;
    private final Sessions sessions;

    public PageController(PortalConfig config, Sessions sessions) {
        this.staticDir = Path.of(config.staticDir);
        this.sessions = sessions;
    }

    @GetMapping("/login")
    public ResponseEntity<byte[]> loginPage() throws IOException {
        return file("login.html", MediaType.TEXT_HTML);
    }

    @GetMapping("/")
    public ResponseEntity<byte[]> index(HttpServletRequest request) throws IOException {
        if (sessions.currentUser(request) == null) {
            return ResponseEntity.status(HttpStatus.FOUND).header("Location", "/login").build();
        }
        return file("index.html", MediaType.TEXT_HTML);
    }

    @GetMapping("/static/{name:.+}")
    public ResponseEntity<byte[]> staticFile(@org.springframework.web.bind.annotation.PathVariable
                                             String name) throws IOException {
        if (name.contains("..") || name.contains("/")) {
            return ResponseEntity.notFound().build();
        }
        MediaType type = name.endsWith(".css") ? MediaType.valueOf("text/css")
                : name.endsWith(".js") ? MediaType.valueOf("text/javascript")
                : name.endsWith(".html") ? MediaType.TEXT_HTML
                : MediaType.APPLICATION_OCTET_STREAM;
        return file(name, type);
    }

    private ResponseEntity<byte[]> file(String name, MediaType type) throws IOException {
        Path path = staticDir.resolve(name);
        if (!Files.exists(path)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok().contentType(type).body(Files.readAllBytes(path));
    }
}
