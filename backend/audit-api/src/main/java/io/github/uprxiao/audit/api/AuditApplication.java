package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.orchestrator.DefaultScanPlanner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class AuditApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuditApplication.class, args);
    }

    @Bean
    DefaultScanPlanner scanPlanner() {
        return new DefaultScanPlanner();
    }
}
