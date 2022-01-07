package mui;

import java.util.ArrayList;
import java.util.Map;

public class MUISettings {

	private static Map<String, Map<String, Map<Map<String, Object>, Map<String, Object>>>> SETTINGS =
		Map.of(
			"NATIVE_RUN_SETTINGS",
			Map.of(
				"concreteStart", Map.of(
					Map.of(
						"title", "Concrete Start",
						"description", "Initial concrete data for the input symbolic buffer",
						"type", "string",
						"default", ""),
					Map.of()),
				"stdinSize", Map.of(
					Map.of(
						"title", "Stdin Size",
						"description", "Stdin size to use for manticore",
						"type", "number",
						"default", 256),
					Map.of()),
				"argv", Map.of(
					Map.of(
						"title", "Program arguments (use + as a wildcard)",
						"description", "Argv to use for manticore",
						"type", "array",
						"elementType", "string",
						"default", new ArrayList<String>()),
					Map.of()),
				"workspaceURL", Map.of(
					Map.of(
						"title", "Workspace URL",
						"description", "Workspace URL to use for manticore",
						"type", "string",
						"default", "mem:"),
					Map.of(
						"is_dir_path", true)),
				"env", Map.of(
					Map.of(
						"title", "Environment Variables",
						"description", "Environment variables for manticore",
						"type", "array",
						"elementType", "string",
						"default", new ArrayList<String>()),
					Map.of()),
				"symbolicFiles", Map.of(
					Map.of(
						"title", "Symbolic Input Files",
						"description", "Symbolic input files for manticore",
						"type", "array",
						"elementType", "string",
						"default", new ArrayList<String>()),
					Map.of())));

}
