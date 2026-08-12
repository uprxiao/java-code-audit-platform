package io.github.uprxiao.audit.intake;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SourceCredentialTest {

    @Test
    void ownsCopiesAndRefusesAccessAfterClear() {
        char[] supplied = "canary-password".toCharArray();
        SourceCredential credential = new SourceCredential("alice", supplied);
        supplied[0] = 'X';
        assertArrayEquals("canary-password".toCharArray(), credential.passwordCopy());

        credential.close();
        assertTrue(credential.isClosed());
        assertThrows(IllegalStateException.class, credential::passwordCopy);
        assertThrows(IllegalStateException.class, credential::username);
    }
}
