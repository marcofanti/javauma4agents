package io.uma4agents.authserver.store;

import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/** One subscriber's view of an owner's event stream. Close it when the subscriber goes. */
public final class Subscription implements AutoCloseable {

    private final LinkedBlockingQueue<Map<String, Object>> queue = new LinkedBlockingQueue<>();
    private final Runnable onClose;

    Subscription(java.util.function.Consumer<Subscription> onClose) {
        this.onClose = () -> onClose.accept(this);
    }

    void deliver(Map<String, Object> event) {
        queue.offer(StoreJson.copy(event));
    }

    /** The next event, waiting as long as it takes. */
    public Map<String, Object> take() throws InterruptedException {
        return queue.take();
    }

    /** The next event, or null after {@code timeout}. */
    public Map<String, Object> poll(long timeout, TimeUnit unit) throws InterruptedException {
        return queue.poll(timeout, unit);
    }

    @Override
    public void close() {
        onClose.run();
    }
}
