package io.uma4agents.pep;

import io.uma4agents.common.Consequence;
import io.uma4agents.pep.core.EnforcerSettings.ToolSurface;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

record ToolSurfaceFile(Map<String, ToolSurface> tools, Set<String> singleUse) {
    static ToolSurfaceFile read(Path file) {
        ObjectMapper json = new ObjectMapper();
        Map<String, Object> specification;
        try {
            specification = json.readValue(Files.readString(file), new TypeReference<>() {});
        } catch (IOException | tools.jackson.core.JacksonException invalid) {
            throw new IllegalArgumentException("cannot read the tool surface from " + file, invalid);
        }
        var tools = new LinkedHashMap<String, ToolSurface>();
        var singleUse = new LinkedHashSet<String>();
        if (specification != null) {
            specification.forEach((name, value) -> {
                if (name.startsWith("_")) {
                    return;
                }
                if (!(value instanceof Map<?, ?> spec)) {
                    throw new IllegalArgumentException("tool " + name + " must be an object");
                }
                if (!(spec.get("resource") instanceof String resource) || resource.isBlank()) {
                    throw new IllegalArgumentException("tool " + name + " needs a resource id");
                }
                if (!(spec.get("scopes") instanceof List<?> offered)
                        || !offered.stream().allMatch(String.class::isInstance)) {
                    throw new IllegalArgumentException("tool " + name + " needs a list of scopes");
                }
                String consequence = Consequence.normalise(spec.get("consequence"));
                if (spec.get("consequence") != null && consequence == null) {
                    throw new IllegalArgumentException("tool " + name + " declares an unknown consequence");
                }
                var scopes = offered.stream().map(String.class::cast).toList();
                tools.put(name, new ToolSurface(resource, scopes, consequence));
                if (Boolean.TRUE.equals(spec.get("single_use")) || Consequence.singleUse(consequence)) {
                    singleUse.add(name);
                }
            });
        }
        if (tools.isEmpty()) {
            throw new IllegalArgumentException(file + " defined no tools");
        }
        return new ToolSurfaceFile(java.util.Collections.unmodifiableMap(tools), Set.copyOf(singleUse));
    }
}
