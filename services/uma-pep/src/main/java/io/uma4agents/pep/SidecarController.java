package io.uma4agents.pep;

import io.uma4agents.common.SslContexts;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.ObjectMapper;

@RestController
@ConditionalOnProperty(name = "uma.pep.upstream")
final class SidecarController {
    private static final Set<String> REQUEST_HEADERS = Set.of("content-type", "accept", "mcp-session-id",
            "mcp-protocol-version", "mcp-method", "mcp-name", "last-event-id", "traceparent", "tracestate");
    private static final Set<String> RESPONSE_HEADERS = Set.of("content-type", "content-encoding",
            "mcp-session-id", "mcp-protocol-version", "cache-control", "retry-after", "content-length");

    private final CheckController authorization;
    private final PepConfig config;
    private final ObjectMapper json;
    private final URI upstream = URI.create(System.getenv("UMA_PEP_UPSTREAM"));
    private final String upstreamHeader = PepConfig.env("UMA_PEP_UPSTREAM_HEADER", "");
    private final String upstreamAuth = PepConfig.env("UMA_PEP_UPSTREAM_AUTH", "");
    private final Duration timeout = Duration.ofMillis((long) (1000
            * Double.parseDouble(PepConfig.env("UMA_PEP_UPSTREAM_TIMEOUT_S", "60"))));
    private final HttpClient http;

    SidecarController(CheckController authorization, PepConfig config, ObjectMapper json) {
        this.authorization = authorization;
        this.config = config;
        this.json = json;
        if (!Set.of("http", "https").contains(String.valueOf(upstream.getScheme()))
                || upstream.getHost() == null || upstream.getUserInfo() != null || upstream.getFragment() != null) {
            throw new IllegalArgumentException("UMA_PEP_UPSTREAM must be an HTTP(S) endpoint");
        }
        if (upstreamHeader.isEmpty() != upstreamAuth.isEmpty()) {
            throw new IllegalArgumentException("configure both the upstream header name and its value");
        }
        var builder = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5));
        String ca = PepConfig.env("UMA4A_CA_BUNDLE", "");
        if (!ca.isEmpty()) {
            builder.sslContext(SslContexts.withAdditionalRoots(Path.of(ca)));
        }
        http = builder.build();
    }

    @PostMapping({"/mcp", "/mcp/{*rest}"})
    void forward(HttpServletRequest request, HttpServletResponse response) throws IOException {
        byte[] body = authorization.boundedBody(request);
        if (body == null) {
            reply(response, 413, "invalid_request", "request body too large");
            return;
        }
        var verdict = authorization.decide(request, request.getRequestURI(), body);
        if (verdict.getStatusCode().value() != 200) {
            response.setStatus(verdict.getStatusCode().value());
            verdict.getHeaders().forEach((name, values) -> values.forEach(value -> response.addHeader(name, value)));
            if (verdict.getBody() != null) {
                response.getOutputStream().write(json.writeValueAsBytes(verdict.getBody()));
            }
            return;
        }
        var outgoing = HttpRequest.newBuilder(target(request)).timeout(timeout)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        for (String name : Collections.list(request.getHeaderNames())) {
            if (REQUEST_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                Collections.list(request.getHeaders(name)).forEach(value -> outgoing.header(name, value));
            }
        }
        String contract = verdict.getHeaders().getFirst("x-uma-contract");
        outgoing.setHeader("x-uma-contract", contract == null ? "" : contract);
        outgoing.setHeader("x-forwarded-host", config.expectedAuthority);
        outgoing.setHeader("x-forwarded-proto", URI.create(config.publicBase).getScheme());
        if (!upstreamHeader.isEmpty()) {
            outgoing.setHeader(upstreamHeader, upstreamAuth);
        }
        HttpResponse<java.io.InputStream> received;
        try {
            received = http.send(outgoing.build(), HttpResponse.BodyHandlers.ofInputStream());
        } catch (ConnectException | HttpConnectTimeoutException unreachable) {
            reply(response, 502, "upstream_unreachable",
                    "the protected resource could not be reached; the call was not delivered");
            return;
        } catch (IOException uncertain) {
            reply(response, 504, "upstream_timeout",
                    "no answer came back from the protected resource; the call may have been carried out");
            return;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            reply(response, 504, "upstream_timeout",
                    "the protected resource call was interrupted; it may have been carried out");
            return;
        }
        response.setStatus(received.statusCode());
        received.headers().map().forEach((name, values) -> {
            if (RESPONSE_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                values.forEach(value -> response.addHeader(name, value));
            }
        });
        try (var upstreamBody = received.body()) {
            var downstream = response.getOutputStream();
            byte[] buffer = new byte[8192];
            for (int bytes; (bytes = upstreamBody.read(buffer)) != -1;) {
                downstream.write(buffer, 0, bytes);
                downstream.flush();
            }
        }
    }

    private URI target(HttpServletRequest request) {
        String base = upstream.toString();
        String path = upstream.getRawPath();
        if (path == null || path.isEmpty() || "/".equals(path)) {
            int end = base.indexOf('?');
            String origin = end < 0 ? base : base.substring(0, end);
            base = origin.replaceFirst("/$", "") + request.getRequestURI() + (end < 0 ? "" : base.substring(end));
        }
        String query = request.getQueryString();
        if (query != null && !query.isEmpty()) {
            base += (base.contains("?") ? "&" : "?") + query;
        }
        return URI.create(base);
    }

    private void reply(HttpServletResponse response, int status, String error, String description)
            throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getOutputStream().write(json.writeValueAsBytes(
                Map.of("error", error, "error_description", description)));
    }
}
