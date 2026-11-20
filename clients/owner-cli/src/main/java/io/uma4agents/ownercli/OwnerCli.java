package io.uma4agents.ownercli;

import io.uma4agents.common.EdDsa;
import io.uma4agents.common.HttpSignature;
import io.uma4agents.common.PyJson;
import io.uma4agents.common.SslContexts;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.time.Duration;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/** The resource owner's local-key interface, signed independently of the browser session. */
public final class OwnerCli {
    private static final String USAGE = """
            Owner commands
              key                    Print the public key to enrol
              pending                Show the requests waiting on you
              approve <family>       Approve one pending request
              deny <family>          Decline one pending request
              policy                 Read your policy tiers
              resources              List the resources the authority protects
              connections            List standing agent connections
              revoke <handle>        Revoke an agent connection
              ledger                 Read the authorization ledger
              watch                  Poll for requests that need your answer

            Configure UMA4A_OWNER_AS, UMA4A_OWNER_AUTHORITY and UMA4A_OWNER_KEY.
            Set UMA4A_CA_BUNDLE to the PEM trust root for an HTTPS lab authority.
            """;
    private static final ObjectMapper JSON = new ObjectMapper();
    private final String as = env("UMA4A_OWNER_AS", "http://localhost:9000").replaceFirst("/+$", "");
    private final String authority = env("UMA4A_OWNER_AUTHORITY", "alice-as.uma.lab");
    private final Path keyPath = Path.of(env("UMA4A_OWNER_KEY",
            Path.of(System.getProperty("user.home"), ".uma4agents", "owner-key.pem").toString())).toAbsolutePath();
    private final HttpClient http;

    private OwnerCli() {
        var builder = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER);
        String ca = env("UMA4A_CA_BUNDLE", env("SSL_CERT_FILE", ""));
        if (!ca.isEmpty()) {
            builder.sslContext(SslContexts.fromPem(Path.of(ca)));
        }
        http = builder.build();
    }

    public static void main(String[] args) {
        int code;
        try {
            code = new OwnerCli().command(args);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            code = 0;
        } catch (IOException | IllegalArgumentException | IllegalStateException failed) {
            System.err.println(failed.getMessage());
            code = 1;
        }
        System.exit(code);
    }

    private int command(String[] args) throws IOException, InterruptedException {
        if (args.length == 0 || Set.of("help", "-h", "--help").contains(args[0])) {
            System.out.print(USAGE);
            return args.length == 0 ? 2 : 0;
        }
        boolean needsArgument = Set.of("approve", "deny", "revoke").contains(args[0]);
        if (args.length != (needsArgument ? 2 : 1)) {
            System.err.println(args[0] + (needsArgument ? " needs one argument" : " takes no arguments"));
            return 2;
        }
        return switch (args[0]) {
            case "key" -> {
                System.out.print(publicPem(loadOrCreate()));
                yield 0;
            }
            case "pending" -> pending(false);
            case "watch" -> pending(true);
            case "approve", "deny" -> {
                String family = args[1];
                if (!family.matches("[A-Za-z0-9_-]+")) {
                    System.err.println("invalid negotiation family");
                    yield 2;
                }
                yield show(call("POST", "/owner/pending/" + family + "/decision",
                        Map.of("decision", "approve".equals(args[0]) ? "approved" : "denied")));
            }
            case "revoke" -> show(call("POST", "/owner/connections/revoke", Map.of("handle", args[1])));
            case "policy" -> show(call("GET", "/owner/policies", null));
            case "resources" -> show(call("GET", "/owner/resources", null));
            case "connections" -> show(call("GET", "/owner/connections", null));
            case "ledger" -> show(call("GET", "/owner/ledger", null));
            default -> {
                System.out.print(USAGE);
                yield 2;
            }
        };
    }

    private int pending(boolean watch) throws IOException, InterruptedException {
        Set<Object> seen = new HashSet<>();
        if (watch) {
            System.err.println("watching for requests — ctrl-c to stop");
        }
        do {
            var response = call("GET", "/owner/pending", null);
            if (response.statusCode() >= 400) {
                return show(response);
            }
            var items = JSON.readValue(response.body(), new TypeReference<List<Map<String, Object>>>() {});
            if (!watch && items.isEmpty()) {
                System.out.println("nothing is waiting on you");
            }
            for (var item : items) {
                Object family = item.get("family");
                if (!watch || seen.add(family)) {
                    System.out.printf("%s  %s  tier=%s%n", family, item.getOrDefault("kind", "operation"),
                            item.get("tier"));
                    System.out.println("  purpose:   " + item.get("purpose"));
                    if (item.get("operation") instanceof Map<?, ?> op && !op.isEmpty()) {
                        System.out.printf("  operation: %s(%s)%n", op.get("tool"),
                                PyJson.dumpsSorted(op.containsKey("params") ? op.get("params") : Map.of()));
                    }
                    System.out.println("  agent:     " + item.get("identity"));
                    if (item.get("prohibited") instanceof List<?> rules && !rules.isEmpty()) {
                        System.out.println("  prohibited: " + String.join(", ", rules.stream()
                                .map(String::valueOf).toList()));
                    }
                    if (watch) {
                        System.out.println("  approve with: make owner ARGS='approve " + family + "'");
                    }
                    System.out.println();
                }
            }
            if (watch) {
                seen.retainAll(items.stream().map(item -> item.get("family")).toList());
                Thread.sleep(Duration.ofSeconds(2));
            }
        } while (watch);
        return 0;
    }

    private HttpResponse<String> call(String method, String path, Map<String, Object> body)
            throws IOException, InterruptedException {
        byte[] bytes = body == null ? null : PyJson.dumpsSorted(body).getBytes(StandardCharsets.UTF_8);
        KeyPair key = loadOrCreate();
        var request = HttpRequest.newBuilder(URI.create(as + path)).timeout(Duration.ofSeconds(30))
                .header("Accept", "application/json")
                .method(method, bytes == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofByteArray(bytes));
        var headers = HttpSignature.sign(method, authority, path, "", key.getPrivate(), "owner",
                new HttpSignature.SignOptions(null, null, null, null, bytes));
        headers.forEach(request::header);
        if (bytes != null) {
            request.header("Content-Type", "application/json");
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static int show(HttpResponse<String> response) {
        if (response.statusCode() >= 400) {
            System.err.println(response.statusCode() + " " + response.body());
            return 1;
        }
        try {
            System.out.println(JSON.writerWithDefaultPrettyPrinter().writeValueAsString(
                    JSON.readTree(response.body())));
        } catch (tools.jackson.core.JacksonException text) {
            System.out.println(response.body());
        }
        return 0;
    }

    private KeyPair loadOrCreate() throws IOException {
        if (Files.exists(keyPath)) {
            return EdDsa.load(keyPath);
        }
        Path parent = keyPath.getParent();
        Files.createDirectories(parent);
        boolean posix = Files.getFileStore(parent).supportsFileAttributeView("posix");
        Path staged = posix ? Files.createTempFile(parent, ".owner-key-", ".pem",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
                : Files.createTempFile(parent, ".owner-key-", ".pem");
        try {
            KeyPair pair = EdDsa.generate();
            Files.writeString(staged, EdDsa.toPkcs8Pem(pair.getPrivate()));
            try {
                Files.createLink(keyPath, staged);
            } catch (FileAlreadyExistsException concurrent) {
                return EdDsa.load(keyPath);
            }
            String name = keyPath.getFileName().toString();
            Path publicPath = keyPath.resolveSibling(name.endsWith(".pem")
                    ? name.substring(0, name.length() - 4) + ".pub" : name + ".pub");
            try {
                Files.writeString(publicPath, publicPem(pair), StandardOpenOption.CREATE_NEW);
                System.err.println("Enrol the public key at " + publicPath);
            } catch (FileAlreadyExistsException exists) {
                System.err.println("A public key file already exists at " + publicPath
                        + ". Use the key command to read the public half of the active key.");
            }
            return pair;
        } finally {
            Files.deleteIfExists(staged);
        }
    }

    private static String publicPem(KeyPair pair) {
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(
                pair.getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n";
    }

    private static String env(String name, String fallback) {
        return System.getenv().getOrDefault(name, fallback);
    }
}
