package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.intake.SourceCredential;
import org.junit.jupiter.api.Test;

class SvnScanRequestTest {

    @Test
    void passwordIsWriteOnlyAndClearedWhenCredentialOwnershipTransfers() throws Exception {
        String canary = "svn-canary-password-7ec3";
        SvnScanRequest request = new ObjectMapper().readValue("""
                {"repositoryUrl":"https://svn.example.test/repo/trunk",
                 "username":"alice","password":"%s","profile":"QUICK"}
                """.formatted(canary), SvnScanRequest.class);

        assertFalse(request.toString().contains(canary));
        try (SourceCredential credential = request.transferCredential()) {
            assertTrue(request.isClosed());
            assertThrows(IllegalStateException.class, request::passwordCopy);
        }
        Exception serializationFailure = assertThrows(Exception.class,
                () -> new ObjectMapper().writeValueAsString(request));
        assertNotNull(serializationFailure.getMessage());
        assertFalse(serializationFailure.getMessage().contains(canary));
    }
}
