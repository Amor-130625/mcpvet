/**
 * Schema rules: the contract a tool offers to the model.
 *
 * A tool's input schema is part of its security surface. `{"type": "string"}`
 * for a field named `command` tells the model that anything goes; an enum or a
 * pattern tells it — and the server's validation — where the boundary is.
 *
 * @module rules/schema
 */

import { isPlainObject } from "../util.js";

/** Parameter names that reach something dangerous on the other side. */
const SENSITIVE_PARAMETERS = /^(?:command|cmd|shell|exec|execute|script|code|path|file|filepath|filename|dir|directory|folder|url|uri|endpoint|host|query|sql|statement|expression|eval|template)$/i;

/** Tool names that imply a state change. */
const DESTRUCTIVE_NAMES = /(?:^|_)(?:delete|remove|drop|destroy|truncate|purge|reset|wipe|kill|exec|execute|run|write|update|insert|create|modify|patch|move|rename|upload|deploy|send|post)(?:$|_)/i;
const DESTRUCTIVE_DESCRIPTIONS = /\b(?:delete|remove|destroy|overwrite|drop|truncate|wipe|erase|execute|run|spawn|kill|reset)\b/i;

/**
 * @param {any} schema
 * @returns {Record<string, any>|null}
 */
function propertiesOf(schema) {
  if (!isPlainObject(schema)) return null;
  if (!isPlainObject(schema.properties)) return null;
  return schema.properties;
}

/** @type {import("./types.js").Rule[]} */
export const schemaRules = [
  {
    id: "MCP060",
    title: "Tool parameter accepts unconstrained input",
    category: "schema",
    severity: "medium",
    target: "tool",
    summary: "A sensitive parameter is a free-form string with no enum, pattern, format, or length limit.",
    why:
      "The schema is the model's only specification of what a value may be. For parameters that become a path, a " +
      "URL, or a command, the absence of a constraint is an invitation to pass anything — and it removes the " +
      "client-side validation that would otherwise reject a traversal or an injected flag.",
    remediation:
      "Constrain the parameter: an `enum` for known choices, `format`/`pattern` for paths and URLs, `maxLength`, and " +
      "`additionalProperties: false` on the object.",
    references: ["https://json-schema.org/understanding-json-schema/"],
    check({ tool }) {
      const schema = tool.inputSchema;
      if (!isPlainObject(schema)) return null;
      /** @type {import("./types.js").RuleHit[]} */
      const hits = [];

      if (schema.additionalProperties === true) {
        hits.push({
          message: `Tool "${tool.name}" accepts arbitrary additional properties.`,
          evidence: `additionalProperties: true`,
          fingerprintKey: `${tool.name}:additionalProperties`,
        });
      }

      const properties = propertiesOf(schema) ?? {};
      for (const [name, definition] of Object.entries(properties)) {
        if (!isPlainObject(definition)) continue;
        if (!SENSITIVE_PARAMETERS.test(name)) continue;
        const type = definition.type;
        const constrained =
          definition.enum !== undefined ||
          definition.const !== undefined ||
          definition.pattern !== undefined ||
          definition.format !== undefined ||
          definition.maxLength !== undefined ||
          definition.anyOf !== undefined ||
          definition.oneOf !== undefined;
        if (constrained) continue;
        if (type !== undefined && type !== "string") continue;
        hits.push({
          message: `Tool "${tool.name}" parameter "${name}" is an unconstrained string.`,
          evidence: `${name}: ${JSON.stringify(definition).slice(0, 80)}`,
          fingerprintKey: `${tool.name}:${name}`,
        });
      }
      return hits;
    },
  },

  {
    id: "MCP061",
    title: "Destructive tool is not annotated as destructive",
    category: "schema",
    severity: "medium",
    target: "tool",
    summary: "A tool that changes or destroys state carries no destructiveHint, so clients cannot gate it.",
    why:
      "MCP tool annotation hints are what a client uses to decide whether to ask the human first. A tool named " +
      "`delete_branch` that declares no hints is indistinguishable from a read-only one to any client that relies on " +
      "annotations, and a tool marked `readOnlyHint: true` while deleting data actively misleads the review.",
    remediation:
      "Declare `annotations: { destructiveHint: true, readOnlyHint: false }`, and keep the name accurate.",
    references: ["https://modelcontextprotocol.io/specification/2025-06-18/server/tools#tool-annotations"],
    check({ tool }) {
      const looksDestructive =
        DESTRUCTIVE_NAMES.test(tool.name) || DESTRUCTIVE_DESCRIPTIONS.test(tool.description);
      if (!looksDestructive) return null;
      const annotations = tool.annotations;

      if (annotations && annotations.readOnlyHint === true) {
        return {
          message: `Tool "${tool.name}" describes a state change but declares readOnlyHint: true.`,
          evidence: `readOnlyHint: true, name: ${tool.name}`,
          severity: "high",
        };
      }
      if (annotations && annotations.destructiveHint === true) return null;
      return {
        message: `Tool "${tool.name}" is destructive but does not declare destructiveHint.`,
        evidence: annotations ? JSON.stringify(annotations).slice(0, 120) : "annotations: absent",
      };
    },
  },

  {
    id: "MCP062",
    title: "Tool input schema is malformed",
    category: "schema",
    severity: "low",
    target: "tool",
    summary: "inputSchema is missing, is not an object, or has the wrong shape for properties/required.",
    why:
      "A malformed schema is not merely untidy: clients that generate a tool definition from it may fall back to " +
      "accepting anything, and clients that validate will fail at call time — after the user has already approved " +
      "the action.",
    remediation: "Publish a valid JSON Schema object with `type: \"object\"`, a `properties` map, and `required` as an array of names.",
    references: ["https://json-schema.org/"],
    check({ tool }) {
      const schema = tool.inputSchema;
      if (schema === null || schema === undefined) {
        return {
          message: `Tool "${tool.name}" has no inputSchema.`,
          evidence: "inputSchema: missing",
        };
      }
      if (!isPlainObject(schema)) {
        return {
          message: `Tool "${tool.name}" inputSchema is ${Array.isArray(schema) ? "an array" : typeof schema}, not an object.`,
          evidence: `${typeof schema}`,
        };
      }
      if (schema.type !== undefined && schema.type !== "object") {
        return {
          message: `Tool "${tool.name}" inputSchema type is "${schema.type}" rather than "object".`,
          evidence: `type: ${JSON.stringify(schema.type)}`,
        };
      }
      if (schema.properties !== undefined && !isPlainObject(schema.properties)) {
        return {
          message: `Tool "${tool.name}" inputSchema.properties is not an object.`,
          evidence: `properties: ${Array.isArray(schema.properties) ? "array" : typeof schema.properties}`,
        };
      }
      if (schema.required !== undefined && !Array.isArray(schema.required)) {
        return {
          message: `Tool "${tool.name}" inputSchema.required is not an array.`,
          evidence: `required: ${typeof schema.required}`,
        };
      }
      return null;
    },
  },
];
