package io.uma4agents.authserver;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

/**
 * Fan-out for the owner event stream (the Python OWNER_QUEUE list): every
 * subscriber owns an unbounded queue drained by a virtual thread into its
 * {@link SseEmitter}, with the same {@code event: <type>} + JSON data framing.
 */
@Component
public class SseHub {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final List<LinkedBlockingQueue<Map<String, Object>>> queues =
            new CopyOnWriteArrayList<>();

    public void publish(Map<String, Object> item) {
        for (LinkedBlockingQueue<Map<String, Object>> queue : queues) {
            queue.offer(item);
        }
    }

    public SseEmitter subscribe() {
        SseEmitter emitter = new SseEmitter(0L);
        LinkedBlockingQueue<Map<String, Object>> queue = new LinkedBlockingQueue<>();
        queues.add(queue);
        Runnable cleanup = () -> queues.remove(queue);
        emitter.onCompletion(cleanup);
        emitter.onTimeout(cleanup);
        emitter.onError(e -> cleanup.run());
        Thread.startVirtualThread(() -> {
            try {
                while (true) {
                    Map<String, Object> item = queue.take();
                    emitter.send(SseEmitter.event()
                            .name(String.valueOf(item.get("type")))
                            .data(MAPPER.writeValueAsString(item)));
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IOException | IllegalStateException e) {
                // Subscriber went away; drop the queue.
            } finally {
                cleanup.run();
            }
        });
        return emitter;
    }
}
