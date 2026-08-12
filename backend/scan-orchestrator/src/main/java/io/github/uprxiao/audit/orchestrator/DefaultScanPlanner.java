package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.finding.ScanProfile;
import java.util.Objects;

public final class DefaultScanPlanner {

    private final ProfileCatalog catalog;

    public DefaultScanPlanner() {
        this(ProfileCatalogLoader.loadDefaults());
    }

    public DefaultScanPlanner(ProfileCatalog catalog) {
        this.catalog = Objects.requireNonNull(catalog, "catalog");
    }

    public ScanPlan plan(ScanProfile profile) {
        return catalog.plan(profile);
    }
}
