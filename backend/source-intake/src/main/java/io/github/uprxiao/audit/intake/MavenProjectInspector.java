package io.github.uprxiao.audit.intake;

import io.github.uprxiao.audit.finding.ScanProfile;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public final class MavenProjectInspector {

    private static final Set<String> EXCLUDED_DIRECTORIES = Set.of("target", ".git", ".svn");

    public ProjectContext inspect(Path extractionRoot, SourceDescriptor source, ScanProfile requestedProfile)
            throws IOException {
        Objects.requireNonNull(extractionRoot, "extractionRoot");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(requestedProfile, "requestedProfile");
        Path root = extractionRoot.toAbsolutePath().normalize();
        List<Path> poms = discoverPoms(root);
        List<Path> candidates = independentRoots(poms);
        if (candidates.isEmpty()) {
            throw new SourceIntakeException("NO_MAVEN_ROOT", "archive does not contain a Maven root pom.xml");
        }
        if (candidates.size() > 1) {
            List<String> values = candidates.stream().map(path -> portable(root.relativize(path))).toList();
            throw new SourceIntakeException("MULTIPLE_MAVEN_ROOTS",
                    "archive contains multiple independent Maven roots", Map.of("candidates", values));
        }

        Path rootPom = candidates.get(0);
        Path projectRoot = rootPom.getParent().toAbsolutePath().normalize();
        PomModel rootModel = readPom(rootPom);
        int javaVersion = detectJavaVersion(rootModel);
        if (javaVersion != 17) {
            throw new SourceIntakeException("UNSUPPORTED_JAVA_VERSION",
                    "V1 only accepts Maven projects configured for Java 17",
                    Map.of("detected", javaVersion));
        }
        List<MavenModule> modules = discoverModules(projectRoot, rootPom);
        String relativeRoot = root.equals(projectRoot) ? "." : portable(root.relativize(projectRoot));
        ProjectManifest manifest = new ProjectManifest(
                ProjectManifest.CURRENT_SCHEMA_VERSION,
                relativeRoot,
                "pom.xml",
                javaVersion,
                rootModel.packaging(),
                modules,
                source,
                EnumSet.allOf(ScanProfile.class),
                List.of());
        return new ProjectContext(projectRoot, manifest);
    }

    private List<Path> discoverPoms(Path root) throws IOException {
        try (var paths = Files.walk(root)) {
            return paths.filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().equals("pom.xml"))
                    .filter(path -> !isExcluded(root.relativize(path)))
                    .map(path -> path.toAbsolutePath().normalize())
                    .sorted()
                    .toList();
        }
    }

    private boolean isExcluded(Path relative) {
        for (Path segment : relative) {
            if (EXCLUDED_DIRECTORIES.contains(segment.toString())) {
                return true;
            }
        }
        return false;
    }

    private List<Path> independentRoots(List<Path> poms) {
        return poms.stream().filter(pom -> poms.stream().noneMatch(other ->
                !other.equals(pom) && pom.startsWith(other.getParent()))).toList();
    }

    private List<MavenModule> discoverModules(Path projectRoot, Path rootPom) throws IOException {
        Map<Path, MavenModule> modules = new LinkedHashMap<>();
        collectModule(projectRoot, rootPom, modules, new HashSet<>());
        return List.copyOf(modules.values());
    }

    private void collectModule(
            Path projectRoot,
            Path pom,
            Map<Path, MavenModule> modules,
            Set<Path> visiting) throws IOException {
        Path normalizedPom = pom.toAbsolutePath().normalize();
        if (!normalizedPom.startsWith(projectRoot) || !visiting.add(normalizedPom)) {
            throw new SourceIntakeException("INVALID_MAVEN_REACTOR", "Maven module cycle or path escape detected");
        }
        PomModel model = readPom(normalizedPom);
        Path moduleRoot = normalizedPom.getParent();
        String path = moduleRoot.equals(projectRoot) ? "." : portable(projectRoot.relativize(moduleRoot));
        modules.putIfAbsent(moduleRoot, new MavenModule(path, model.artifactId(), model.packaging()));
        for (String declaredModule : model.modules()) {
            Path childRoot = moduleRoot.resolve(declaredModule).normalize();
            if (!childRoot.startsWith(projectRoot)) {
                throw new SourceIntakeException("INVALID_MAVEN_REACTOR",
                        "Maven module path escapes project root: " + declaredModule);
            }
            Path childPom = Files.isDirectory(childRoot) ? childRoot.resolve("pom.xml") : childRoot;
            if (!Files.isRegularFile(childPom)) {
                throw new SourceIntakeException("INVALID_MAVEN_REACTOR",
                        "declared Maven module does not contain pom.xml: " + declaredModule);
            }
            collectModule(projectRoot, childPom, modules, visiting);
        }
        visiting.remove(normalizedPom);
    }

    private PomModel readPom(Path pom) throws IOException {
        try (InputStream input = Files.newInputStream(pom)) {
            var builder = secureFactory().newDocumentBuilder();
            builder.setErrorHandler(new DefaultHandler());
            Document document = builder.parse(input);
            Element project = document.getDocumentElement();
            String artifactId = directText(project, "artifactId");
            if (artifactId.isBlank()) {
                throw new SourceIntakeException("INVALID_MAVEN_POM", "pom.xml has no artifactId: " + pom);
            }
            String packaging = directText(project, "packaging");
            if (packaging.isBlank()) {
                packaging = "jar";
            }
            Map<String, String> properties = new LinkedHashMap<>();
            Element propertiesElement = directChild(project, "properties");
            if (propertiesElement != null) {
                NodeList children = propertiesElement.getChildNodes();
                for (int index = 0; index < children.getLength(); index++) {
                    Node child = children.item(index);
                    if (child instanceof Element element) {
                        properties.put(element.getTagName(), element.getTextContent().trim());
                    }
                }
            }
            List<String> modules = new ArrayList<>();
            Element modulesElement = directChild(project, "modules");
            if (modulesElement != null) {
                NodeList values = modulesElement.getElementsByTagName("module");
                for (int index = 0; index < values.getLength(); index++) {
                    String value = values.item(index).getTextContent().trim();
                    if (!value.isBlank()) {
                        modules.add(value);
                    }
                }
            }
            String compilerRelease = findCompilerConfiguration(project, "release");
            String compilerSource = findCompilerConfiguration(project, "source");
            return new PomModel(artifactId, packaging, properties, modules, compilerRelease, compilerSource);
        } catch (ParserConfigurationException | SAXException exception) {
            throw new SourceIntakeException("INVALID_MAVEN_POM", "cannot securely parse pom.xml: " + pom);
        }
    }

    private DocumentBuilderFactory secureFactory() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory;
    }

    private int detectJavaVersion(PomModel model) throws SourceIntakeException {
        for (String value : List.of(
                model.properties().getOrDefault("maven.compiler.release", ""),
                model.properties().getOrDefault("java.version", ""),
                model.compilerRelease(),
                model.properties().getOrDefault("maven.compiler.source", ""),
                model.compilerSource())) {
            int parsed = parseJavaVersion(resolve(value, model.properties()));
            if (parsed > 0) {
                return parsed;
            }
        }
        throw new SourceIntakeException("UNSUPPORTED_JAVA_VERSION",
                "project must explicitly configure maven.compiler.release, java.version, or compiler source");
    }

    private String resolve(String value, Map<String, String> properties) {
        if (value != null && value.startsWith("${") && value.endsWith("}")) {
            return properties.getOrDefault(value.substring(2, value.length() - 1), "");
        }
        return value == null ? "" : value;
    }

    private int parseJavaVersion(String value) {
        String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (normalized.startsWith("1.")) {
            normalized = normalized.substring(2);
        }
        String digits = normalized.chars().takeWhile(Character::isDigit)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString();
        return digits.isEmpty() ? -1 : Integer.parseInt(digits);
    }

    private String findCompilerConfiguration(Element project, String field) {
        NodeList plugins = project.getElementsByTagName("plugin");
        for (int index = 0; index < plugins.getLength(); index++) {
            Element plugin = (Element) plugins.item(index);
            if ("maven-compiler-plugin".equals(directText(plugin, "artifactId"))) {
                Element configuration = directChild(plugin, "configuration");
                return configuration == null ? "" : directText(configuration, field);
            }
        }
        return "";
    }

    private Element directChild(Element parent, String name) {
        NodeList children = parent.getChildNodes();
        for (int index = 0; index < children.getLength(); index++) {
            Node child = children.item(index);
            if (child instanceof Element element && element.getTagName().equals(name)) {
                return element;
            }
        }
        return null;
    }

    private String directText(Element parent, String name) {
        Element child = directChild(parent, name);
        return child == null ? "" : child.getTextContent().trim();
    }

    private String portable(Path path) {
        return path.toString().replace(path.getFileSystem().getSeparator(), "/");
    }

    private record PomModel(
            String artifactId,
            String packaging,
            Map<String, String> properties,
            List<String> modules,
            String compilerRelease,
            String compilerSource) {
    }
}
