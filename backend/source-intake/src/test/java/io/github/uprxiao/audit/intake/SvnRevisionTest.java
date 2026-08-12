package io.github.uprxiao.audit.intake;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class SvnRevisionTest {

    @Test
    void blankOrHeadMeansCurrentSnapshotAndDecimalSelectsOneRevision() throws Exception {
        assertFalse(SvnRevision.parse(null).number().isPresent());
        assertFalse(SvnRevision.parse("").number().isPresent());
        assertFalse(SvnRevision.parse("head").number().isPresent());
        assertEquals(12345, SvnRevision.parse("12345").number().orElseThrow());
    }

    @Test
    void rejectsRangesDatesSignsAndOverflow() {
        for (String value : new String[]{"-1", "+1", "1:2", "{2026-08-12}", " 1 ", "999999999999999999999"}) {
            SourceIntakeException failure = assertThrows(SourceIntakeException.class, () -> SvnRevision.parse(value));
            assertEquals("INVALID_SVN_REVISION", failure.code());
        }
    }
}
