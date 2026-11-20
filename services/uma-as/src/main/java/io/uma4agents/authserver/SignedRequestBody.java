package io.uma4agents.authserver;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;

/** Keeps exact digest inputs while retaining the servlet's former default form size limit. */
final class SignedRequestBody {
    private static final int LIMIT = 2 * 1024 * 1024;

    private SignedRequestBody() {}

    static byte[] read(HttpServletRequest request) throws IOException {
        if (request.getContentLengthLong() > LIMIT) {
            return null;
        }
        byte[] body = request.getInputStream().readNBytes(LIMIT + 1);
        return body.length <= LIMIT ? body : null;
    }
}
