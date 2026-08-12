package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.intake.SourceIntakeException;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

@RestControllerAdvice
final class ApiExceptionHandler {

    private final Clock clock;

    ApiExceptionHandler(Clock clock) {
        this.clock = clock;
    }

    @ExceptionHandler(ApiException.class)
    ResponseEntity<ApiErrorResponse> api(ApiException exception, HttpServletRequest request) {
        ResponseEntity<ApiErrorResponse> response = response(
                exception.status(), exception.code(), exception.getMessage(), exception.details(), request);
        if (exception.code() == ApiErrorCode.QUEUE_FULL) {
            Object configured = exception.details().getOrDefault("retryAfterSeconds", 30);
            String retryAfter = configured instanceof Number number
                    ? Long.toString(Math.max(1, number.longValue()))
                    : "30";
            return ResponseEntity.status(response.getStatusCode())
                    .header("Retry-After", retryAfter)
                    .body(response.getBody());
        }
        return response;
    }

    @ExceptionHandler(SourceIntakeException.class)
    ResponseEntity<ApiErrorResponse> intake(SourceIntakeException exception, HttpServletRequest request) {
        HttpStatus status = switch (exception.code()) {
            case "ARCHIVE_LIMIT_EXCEEDED" -> HttpStatus.PAYLOAD_TOO_LARGE;
            case "INVALID_MAVEN_ARGUMENT" -> HttpStatus.BAD_REQUEST;
            default -> HttpStatus.UNPROCESSABLE_ENTITY;
        };
        ApiErrorCode code;
        try {
            code = ApiErrorCode.valueOf(exception.code());
        } catch (IllegalArgumentException ignored) {
            code = ApiErrorCode.INVALID_REQUEST;
        }
        return response(status, code, exception.getMessage(), exception.details(), request);
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    ResponseEntity<ApiErrorResponse> uploadLimit(
            MaxUploadSizeExceededException exception, HttpServletRequest request) {
        return response(HttpStatus.PAYLOAD_TOO_LARGE, ApiErrorCode.ARCHIVE_LIMIT_EXCEEDED,
                "上传文件超过 HTTP 层容量限制。", Map.of(), request);
    }

    @ExceptionHandler({
            HttpMessageNotReadableException.class,
            MissingServletRequestPartException.class,
            MethodArgumentTypeMismatchException.class
    })
    ResponseEntity<ApiErrorResponse> malformedRequest(Exception exception, HttpServletRequest request) {
        return response(HttpStatus.BAD_REQUEST, ApiErrorCode.INVALID_REQUEST,
                "请求结构或参数格式不正确。", Map.of(), request);
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ApiErrorResponse> unexpected(Exception exception, HttpServletRequest request) {
        return response(HttpStatus.INTERNAL_SERVER_ERROR, ApiErrorCode.INTERNAL_ERROR,
                "平台内部错误。", Map.of(), request);
    }

    private ResponseEntity<ApiErrorResponse> response(
            HttpStatus status,
            ApiErrorCode code,
            String message,
            Map<String, Object> details,
            HttpServletRequest request) {
        String requestId = request.getHeader("X-Request-Id");
        if (requestId == null || requestId.isBlank()) {
            requestId = UUID.randomUUID().toString();
        }
        return ResponseEntity.status(status).body(new ApiErrorResponse(
                clock.instant(), status.value(), code, message, details, requestId));
    }
}
