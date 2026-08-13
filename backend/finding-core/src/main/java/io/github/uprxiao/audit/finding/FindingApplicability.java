package io.github.uprxiao.audit.finding;

/** What the available project evidence proves about a detector hit. */
public enum FindingApplicability {
    UNKNOWN,
    AFFECTED_VERSION,
    TRIGGER_PRESENT,
    TRIGGER_NOT_FOUND,
    NOT_AFFECTED,
    CONFIRMED_DEFECT,
    FALSE_POSITIVE
}
