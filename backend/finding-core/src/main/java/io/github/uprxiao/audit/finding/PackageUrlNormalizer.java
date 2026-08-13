package io.github.uprxiao.audit.finding;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/** Normalizes Maven PURLs for cross-scanner identity without discarding meaningful qualifiers. */
public final class PackageUrlNormalizer {

    public String identity(String purl) {
        if (purl == null) return "";
        String value = purl.trim();
        if (!value.toLowerCase(Locale.ROOT).startsWith("pkg:maven/")) return value;
        int hash = value.indexOf('#');
        String subpath = hash >= 0 ? value.substring(hash) : "";
        String withoutSubpath = hash >= 0 ? value.substring(0, hash) : value;
        int query = withoutSubpath.indexOf('?');
        if (query < 0) return withoutSubpath + subpath;
        String base = withoutSubpath.substring(0, query);
        List<String> qualifiers = new ArrayList<>();
        for (String qualifier : withoutSubpath.substring(query + 1).split("&")) {
            if (qualifier.isBlank() || qualifier.equalsIgnoreCase("type=jar")) continue;
            qualifiers.add(qualifier);
        }
        qualifiers.sort(Comparator.naturalOrder());
        return base + (qualifiers.isEmpty() ? "" : "?" + String.join("&", qualifiers)) + subpath;
    }
}
