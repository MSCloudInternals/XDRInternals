import { config } from "./config.js";
import type { InvokeResult } from "./bridge.js";

export type ResponseFormat = "markdown" | "json";

export interface RenderOptions {
  /** Heading shown above the records. */
  title: string;
  result: InvokeResult;
  format: ResponseFormat;
  /** Columns worth showing in markdown mode, in priority order. */
  summaryFields?: string[];
  /** Extra guidance appended after the records (next steps, applied defaults, caveats). */
  notes?: string[];
  /** Sentence used when the cmdlet returned nothing at all. */
  emptyMessage?: string;
  maxChars?: number;
}

const MAX_CELL_LENGTH = 160;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function toCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") {
    const flattened = value.replace(/\s+/g, " ").trim();
    return flattened.length > MAX_CELL_LENGTH ? `${flattened.slice(0, MAX_CELL_LENGTH)}…` : flattened;
  }
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) {
    if (value.length === 0) return "";
    const rendered = value.map((entry) => toCell(entry)).filter(Boolean).join(", ");
    return rendered.length > MAX_CELL_LENGTH ? `${rendered.slice(0, MAX_CELL_LENGTH)}…` : rendered;
  }
  const json = JSON.stringify(value);
  if (!json) return "";
  return json.length > MAX_CELL_LENGTH ? `${json.slice(0, MAX_CELL_LENGTH)}…` : json;
}

function escapeCell(text: string): string {
  return text.replace(/\|/g, "\\|");
}

/** Picks columns for objects that arrive without a curated field list. */
function deriveColumns(items: Record<string, unknown>[]): string[] {
  const scored = new Map<string, number>();
  for (const item of items.slice(0, 10)) {
    for (const [key, value] of Object.entries(item)) {
      if (value === null || value === undefined) continue;
      const simple = typeof value === "string" || typeof value === "number" || typeof value === "boolean";
      scored.set(key, (scored.get(key) ?? 0) + (simple ? 2 : 1));
    }
  }
  return [...scored.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([key]) => key);
}

function renderTable(items: Record<string, unknown>[], summaryFields?: string[]): string {
  const requested = summaryFields?.filter((field) => items.some((item) => item[field] !== undefined));
  const columns = requested && requested.length > 0 ? requested : deriveColumns(items);
  if (columns.length === 0) {
    return items.map((item, index) => `${index + 1}. ${toCell(item)}`).join("\n");
  }

  const header = `| ${columns.join(" | ")} |`;
  const divider = `| ${columns.map(() => "---").join(" | ")} |`;
  const rows = items.map(
    (item) => `| ${columns.map((column) => escapeCell(toCell(item[column]))).join(" | ")} |`,
  );
  return [header, divider, ...rows].join("\n");
}

function renderBody(items: unknown[], format: ResponseFormat, summaryFields?: string[]): string {
  if (format === "json") {
    return ["```json", JSON.stringify(items, null, 2), "```"].join("\n");
  }

  const objects = items.filter(isPlainObject);
  if (objects.length === items.length && objects.length > 0) {
    return renderTable(objects, summaryFields);
  }
  return items.map((item, index) => `${index + 1}. ${toCell(item)}`).join("\n");
}

/**
 * Renders a cmdlet result as the text payload of a tool response.
 *
 * Records are dropped from the tail until the payload fits the character budget, so a broad query
 * degrades into a smaller sample with an explicit note instead of flooding the context window.
 */
export function renderResult(options: RenderOptions): string {
  const { result, format, title, summaryFields } = options;
  const budget = options.maxChars ?? config.maxChars;

  const notes = [...(options.notes ?? [])];
  const warnings = result.warnings.filter(Boolean);
  const information = result.information.filter(Boolean).slice(-5);

  if (result.items.length === 0) {
    const lines = [`## ${title}`, "", options.emptyMessage ?? "No records were returned."];
    if (warnings.length > 0) lines.push("", "**Warnings**", ...warnings.map((entry) => `- ${entry}`));
    if (information.length > 0) lines.push("", "**Progress**", ...information.map((entry) => `- ${entry}`));
    if (notes.length > 0) lines.push("", ...notes.map((entry) => `> ${entry}`));
    return lines.join("\n");
  }

  let shown = result.items.length;
  for (;;) {
    const items = result.items.slice(0, shown);
    const trimmedHere = shown < result.items.length;
    const countLine =
      result.totalCount > items.length
        ? `Showing ${items.length} of ${result.totalCount} record(s).`
        : `${items.length} record(s).`;

    const lines = [`## ${title}`, "", countLine, "", renderBody(items, format, summaryFields)];

    const tail = [...notes];
    if (result.truncated) {
      tail.push(
        "The result set was capped server-side. Raise `max_items` or narrow the query to see the rest.",
      );
    }
    if (trimmedHere) {
      tail.push(
        `Only ${items.length} of ${result.items.length} retrieved record(s) fit the response budget. Narrow the filters, or request specific fields, to see the rest.`,
      );
    }
    if (format === "markdown") {
      tail.push("Columns are a summary. Use `response_format: \"json\"` for the complete records.");
    }

    if (warnings.length > 0) lines.push("", "**Warnings**", ...warnings.map((entry) => `- ${entry}`));
    if (information.length > 0) {
      lines.push("", "**Progress**", ...information.map((entry) => `- ${entry}`));
    }
    if (tail.length > 0) lines.push("", ...tail.map((entry) => `> ${entry}`));

    const text = lines.join("\n");
    if (text.length <= budget || shown <= 1) return text;

    shown = Math.max(1, Math.floor(shown / 2));
  }
}

/** Formats a short confirmation for tools that act rather than read. */
export function renderAction(title: string, summary: string, result: InvokeResult, notes: string[] = []): string {
  const lines = [`## ${title}`, "", summary];

  if (result.items.length > 0) {
    lines.push("", "```json", JSON.stringify(result.items.slice(0, 10), null, 2), "```");
  }
  const information = result.information.filter(Boolean);
  if (information.length > 0) lines.push("", ...information.map((entry) => `- ${entry}`));
  const warnings = result.warnings.filter(Boolean);
  if (warnings.length > 0) lines.push("", "**Warnings**", ...warnings.map((entry) => `- ${entry}`));
  if (notes.length > 0) lines.push("", ...notes.map((entry) => `> ${entry}`));

  const text = lines.join("\n");
  return text.length > config.maxChars ? `${text.slice(0, config.maxChars)}\n> Output truncated.` : text;
}
