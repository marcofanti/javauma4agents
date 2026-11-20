package io.uma4agents.operator;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** The public web presence of the firm that operates the requesting agent. */
@SpringBootApplication
public class OperatorApplication {

    public static void main(String[] args) {
        SpringApplication.run(OperatorApplication.class, args);
    }
}
