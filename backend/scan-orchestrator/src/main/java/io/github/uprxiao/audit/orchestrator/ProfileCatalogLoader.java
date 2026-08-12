package io.github.uprxiao.audit.orchestrator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.github.uprxiao.audit.finding.ScanProfile;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class ProfileCatalogLoader {

    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());

    private ProfileCatalogLoader() {
    }

    public static ProfileCatalog loadDefaults() {
        List<ProfileDefinition> definitions = new ArrayList<>();
        for (ScanProfile profile : ScanProfile.values()) {
            String resource = "audit/profiles/" + profile.name().toLowerCase() + ".yaml";
            try (InputStream input = ProfileCatalogLoader.class.getClassLoader().getResourceAsStream(resource)) {
                if (input == null) {
                    throw new ProfileConfigurationException("missing profile resource: " + resource);
                }
                definitions.add(YAML.readValue(input, ProfileDefinition.class));
            } catch (IOException exception) {
                throw new ProfileConfigurationException("cannot load profile resource: " + resource, exception);
            }
        }
        return new ProfileCatalog(definitions);
    }

    public static ProfileCatalog loadDirectory(Path directory) throws IOException {
        List<ProfileDefinition> definitions = new ArrayList<>();
        for (ScanProfile profile : ScanProfile.values()) {
            Path file = directory.resolve(profile.name().toLowerCase() + ".yaml");
            try (InputStream input = Files.newInputStream(file)) {
                definitions.add(YAML.readValue(input, ProfileDefinition.class));
            }
        }
        return new ProfileCatalog(definitions);
    }
}
