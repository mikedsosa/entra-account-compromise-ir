// Offline static check for the .kql files in ../../queries.
// Parses each query with Microsoft's Kusto.Language library and binds it
// against table schemas transcribed from the Azure Monitor table reference
// pages (see schemas/*.schema and SOURCES.md). This catches syntax errors and
// references to columns or functions that don't exist in the documented
// schema. It does NOT run the query or prove that it returns useful results.
using Kusto.Language;
using Kusto.Language.Symbols;

var root = args.Length > 0 ? args[0] : Path.Combine("..", "..");
var schemaDir = Path.Combine(AppContext.BaseDirectory, "schemas");
if (!Directory.Exists(schemaDir)) schemaDir = "schemas";

var tables = new List<TableSymbol>();
foreach (var f in Directory.GetFiles(schemaDir, "*.schema"))
{
    var lines = File.ReadAllLines(f);
    tables.Add(new TableSymbol(lines[0].Trim(), "(" + lines[1].Trim() + ")"));
}
var globals = GlobalState.Default.WithDatabase(new DatabaseSymbol("workspace", tables));

var failed = 0;
foreach (var file in Directory.GetFiles(Path.Combine(root, "queries"), "*.kql").OrderBy(x => x))
{
    var code = KustoCode.ParseAndAnalyze(File.ReadAllText(file), globals);
    var errors = code.GetDiagnostics().Where(d => d.Severity == "Error").ToList();
    Console.WriteLine($"{(errors.Count == 0 ? "PASS" : "FAIL")}  {Path.GetFileName(file)}");
    foreach (var d in errors) Console.WriteLine($"      {d.Code} at {d.Start}: {d.Message}");
    if (errors.Count > 0) failed++;
}
Environment.Exit(failed == 0 ? 0 : 1);
