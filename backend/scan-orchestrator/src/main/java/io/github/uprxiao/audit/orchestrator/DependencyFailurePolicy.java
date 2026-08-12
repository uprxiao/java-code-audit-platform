package io.github.uprxiao.audit.orchestrator;

/** Defines whether a DAG task may run after one of its dependencies fails. */
public enum DependencyFailurePolicy {
    /** Skip the task when any dependency does not complete successfully or partially. */
    SKIP,

    /** Run after every dependency is terminal, regardless of its outcome. */
    RUN_AFTER_TERMINAL
}
