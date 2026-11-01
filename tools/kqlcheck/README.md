# kqlcheck: offline static check for the queries

This is a small .NET console app. It parses every file in `queries/` with
Microsoft's [Kusto.Language](https://github.com/microsoft/Kusto-Query-Language)
library (NuGet package `Microsoft.Azure.Kusto.Language`) and binds each query
against the table schemas in `schemas/`.

The schemas were extracted automatically on 2026-11-01 from the column tables
on these Azure Monitor reference pages:

- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aaduserriskevents
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity

## What it does and doesn't prove

- **It catches** syntax errors, unknown table or column names, unknown functions,
  and type mismatches against the *documented* schema.
- **It doesn't catch** wrong values (for example a misspelled `OperationName`
  string or a JSON path inside a `dynamic` column that doesn't exist in real
  data). It also doesn't catch logic errors, poor tuning or false positives.
- It never connects to a workspace or tenant.

## Run

```bash
cd tools/kqlcheck
dotnet run -- ../..
```
