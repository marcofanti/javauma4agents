package io.uma4agents.authserver;

import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Flow;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import tools.jackson.databind.ObjectMapper;

/** An HTTP client serving canned documents by URL, recording each request it sees. */
final class FakeHttp extends HttpClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    final Map<String, byte[]> documents = new HashMap<>();
    final List<HttpRequest> requests = new ArrayList<>();

    void json(String url, Object value) {
        documents.put(url, MAPPER.writeValueAsString(value).getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException {
        requests.add(request);
        byte[] body = documents.get(request.uri().toString());
        int status = body == null ? 404 : 200;
        byte[] bytes = body == null ? new byte[0] : body;
        HttpResponse.ResponseInfo info = new HttpResponse.ResponseInfo() {
            @Override
            public int statusCode() {
                return status;
            }

            @Override
            public HttpHeaders headers() {
                return HttpHeaders.of(Map.of(), (a, b) -> true);
            }

            @Override
            public Version version() {
                return Version.HTTP_1_1;
            }
        };
        HttpResponse.BodySubscriber<T> subscriber = handler.apply(info);
        subscriber.onSubscribe(new Flow.Subscription() {
            @Override
            public void request(long n) {
                // Everything is delivered at once below.
            }

            @Override
            public void cancel() {
                // Nothing to cancel.
            }
        });
        subscriber.onNext(List.of(ByteBuffer.wrap(bytes)));
        subscriber.onComplete();
        T value = subscriber.getBody().toCompletableFuture().join();
        return new HttpResponse<>() {
            @Override
            public int statusCode() {
                return status;
            }

            @Override
            public HttpRequest request() {
                return request;
            }

            @Override
            public Optional<HttpResponse<T>> previousResponse() {
                return Optional.empty();
            }

            @Override
            public HttpHeaders headers() {
                return info.headers();
            }

            @Override
            public T body() {
                return value;
            }

            @Override
            public Optional<javax.net.ssl.SSLSession> sslSession() {
                return Optional.empty();
            }

            @Override
            public URI uri() {
                return request.uri();
            }

            @Override
            public Version version() {
                return Version.HTTP_1_1;
            }
        };
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
            HttpResponse.BodyHandler<T> handler) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
            HttpResponse.BodyHandler<T> handler, HttpResponse.PushPromiseHandler<T> push) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return Optional.empty();
    }

    @Override
    public Optional<Duration> connectTimeout() {
        return Optional.empty();
    }

    @Override
    public Redirect followRedirects() {
        return Redirect.NEVER;
    }

    @Override
    public Optional<ProxySelector> proxy() {
        return Optional.empty();
    }

    @Override
    public SSLContext sslContext() {
        return null;
    }

    @Override
    public SSLParameters sslParameters() {
        return null;
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return Optional.empty();
    }

    @Override
    public Version version() {
        return Version.HTTP_1_1;
    }

    @Override
    public Optional<Executor> executor() {
        return Optional.empty();
    }
}
