package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;

class ApiExceptionHandlerTest {

    @Test
    void queueFullUsesConfiguredRetryHeaderAndReturnsQueueMetrics() {
        ApiExceptionHandler handler = new ApiExceptionHandler(
                Clock.fixed(Instant.parse("2026-08-12T00:00:00Z"), ZoneOffset.UTC));
        ApiException exception = new ApiException(
                HttpStatus.TOO_MANY_REQUESTS,
                ApiErrorCode.QUEUE_FULL,
                "queue full",
                Map.of("retryAfterSeconds", 17, "queueLength", 20, "queueCapacity", 20));

        var response = handler.api(exception, new MockHttpServletRequest());

        assertEquals(HttpStatus.TOO_MANY_REQUESTS, response.getStatusCode());
        assertEquals("17", response.getHeaders().getFirst("Retry-After"));
        assertEquals(20, response.getBody().details().get("queueLength"));
        assertEquals(20, response.getBody().details().get("queueCapacity"));
    }
}
