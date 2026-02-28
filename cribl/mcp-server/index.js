#!/usr/bin/env node
/**
 * Cribl Stream MCP Server
 *
 * Exposes Cribl Stream pipeline management as MCP tools for Claude Code.
 * Enables the full Detection Engineering lifecycle:
 *   - Review live data flowing through pipelines
 *   - Write regex parsers for field extraction and CIM compliance
 *   - Add log reduction rules (Drop functions for noisy events)
 *   - Test pipeline changes against sample events before deploying
 *   - Monitor throughput metrics and reduction ratios
 *   - Manage routing rules between sources and destinations
 *
 * Usage:
 *   node index.js
 *   CRIBL_URL=http://localhost:9000 CRIBL_PASS=admin node index.js
 *
 * Environment variables:
 *   CRIBL_URL   — Cribl Stream URL (default: http://localhost:9000)
 *   CRIBL_USER  — Username (default: admin)
 *   CRIBL_PASS  — Password (default: admin)
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import http from "http";
import https from "https";

// ─── Configuration ────────────────────────────────────────────────────────────
const CRIBL_URL  = process.env.CRIBL_URL   || "http://localhost:9000";
const CRIBL_USER = process.env.CRIBL_USER  || "admin";
const CRIBL_PASS = process.env.CRIBL_PASS  || "admin";

let authToken = null;
let tokenExpiry = 0;

// ─── HTTP Helper ──────────────────────────────────────────────────────────────
function request(method, path, body = null, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, CRIBL_URL);
    const isHttps = url.protocol === "https:";
    const lib = isHttps ? https : http;
    const headers = {
      "Content-Type": "application/json",
      ...extraHeaders,
    };
    if (body) {
      headers["Content-Length"] = Buffer.byteLength(JSON.stringify(body));
    }
    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method,
      headers,
      rejectUnauthorized: false,
    };
    const req = lib.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });
    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
async function getToken() {
  if (authToken && Date.now() < tokenExpiry) return authToken;
  const res = await request("POST", "/api/v1/auth/login", {
    username: CRIBL_USER,
    password: CRIBL_PASS,
  });
  if (res.status !== 200 || !res.body.token) {
    throw new Error(`Cribl auth failed (${res.status}): ${JSON.stringify(res.body)}`);
  }
  authToken = res.body.token;
  tokenExpiry = Date.now() + 55 * 60 * 1000; // refresh 5 min before 1hr expiry
  return authToken;
}

async function criblGet(path) {
  const token = await getToken();
  const res = await request("GET", path, null, { Authorization: `Bearer ${token}` });
  if (res.status === 401) { authToken = null; return criblGet(path); }
  return res;
}

async function criblPost(path, body) {
  const token = await getToken();
  const res = await request("POST", path, body, { Authorization: `Bearer ${token}` });
  if (res.status === 401) { authToken = null; return criblPost(path, body); }
  return res;
}

async function criblPatch(path, body) {
  const token = await getToken();
  const res = await request("PATCH", path, body, { Authorization: `Bearer ${token}` });
  if (res.status === 401) { authToken = null; return criblPatch(path, body); }
  return res;
}

// ─── Tool Implementations ─────────────────────────────────────────────────────

async function criblHealth() {
  try {
    const res = await criblGet("/api/v1/health");
    const info = await criblGet(`/api/v1/system/info`);
    return {
      healthy: res.body.healthy || false,
      url: CRIBL_URL,
      version: info.body?.version,
      license: info.body?.license?.type || "unknown",
    };
  } catch (e) {
    return { healthy: false, error: e.message, url: CRIBL_URL };
  }
}

async function criblListPipelines() {
  const res = await criblGet(`/api/v1/pipelines`);
  const pipelines = res.body.items || res.body || [];
  return pipelines.map((p) => ({
    id: p.id,
    description: p.description || "",
    function_count: (p.functions || []).length,
    functions: (p.functions || []).map((f) => ({
      id: f.id,
      filter: f.filter || "true",
      disabled: f.disabled || false,
    })),
  }));
}

async function criblGetPipeline(id) {
  const res = await criblGet(`/api/v1/pipelines/${id}`);
  if (res.status !== 200) throw new Error(`Pipeline '${id}' not found (${res.status})`);
  const p = res.body;
  return {
    id: p.id,
    description: p.description || "",
    functions: (p.functions || []).map((f, i) => ({
      index: i,
      id: f.id,
      type: f.id,
      filter: f.filter || "true",
      disabled: f.disabled || false,
      conf: f.conf || {},
      description: f.description || "",
    })),
  };
}

async function criblPreviewPipeline(pipelineId, sampleEvents) {
  // POST sample events through the pipeline to see how they are transformed
  const events = Array.isArray(sampleEvents)
    ? sampleEvents
    : [sampleEvents];

  const body = {
    events: events.map((e) =>
      typeof e === "string" ? { _raw: e } : e
    ),
    timeout: 5000,
  };
  const res = await criblPost(
    `/api/v1/pipelines/${pipelineId}/preview`,
    body
  );
  if (res.status !== 200) {
    throw new Error(`Preview failed (${res.status}): ${JSON.stringify(res.body)}`);
  }
  return {
    pipeline: pipelineId,
    input_count: events.length,
    results: res.body.results || res.body,
  };
}

async function criblAddPipelineFunction(pipelineId, functionDef, insertAt = -1) {
  // Get current pipeline
  const pipelineRes = await criblGet(`/api/v1/pipelines/${pipelineId}`);
  if (pipelineRes.status !== 200) throw new Error(`Pipeline '${pipelineId}' not found`);

  const pipeline = pipelineRes.body;
  const functions = pipeline.functions || [];

  const newFn = {
    id: functionDef.type,
    filter: functionDef.filter || "true",
    disabled: functionDef.disabled || false,
    conf: functionDef.conf || {},
    description: functionDef.description || "",
  };

  if (insertAt === -1 || insertAt >= functions.length) {
    functions.push(newFn);
  } else {
    functions.splice(insertAt, 0, newFn);
  }

  pipeline.functions = functions;
  const res = await criblPatch(`/api/v1/pipelines/${pipelineId}`, pipeline);
  if (res.status !== 200) {
    throw new Error(`Update failed (${res.status}): ${JSON.stringify(res.body)}`);
  }
  return {
    pipeline: pipelineId,
    added: newFn,
    total_functions: functions.length,
    message: `Function '${newFn.id}' added to pipeline '${pipelineId}' at position ${insertAt === -1 ? functions.length - 1 : insertAt}`,
  };
}

async function criblRemovePipelineFunction(pipelineId, functionIndex) {
  const pipelineRes = await criblGet(`/api/v1/pipelines/${pipelineId}`);
  if (pipelineRes.status !== 200) throw new Error(`Pipeline '${pipelineId}' not found`);

  const pipeline = pipelineRes.body;
  const functions = pipeline.functions || [];

  if (functionIndex < 0 || functionIndex >= functions.length) {
    throw new Error(`Invalid function index ${functionIndex} (pipeline has ${functions.length} functions)`);
  }

  const removed = functions.splice(functionIndex, 1)[0];
  pipeline.functions = functions;

  const res = await criblPatch(`/api/v1/pipelines/${pipelineId}`, pipeline);
  if (res.status !== 200) {
    throw new Error(`Update failed (${res.status}): ${JSON.stringify(res.body)}`);
  }
  return {
    pipeline: pipelineId,
    removed: removed,
    remaining_functions: functions.length,
    message: `Function at index ${functionIndex} removed from '${pipelineId}'`,
  };
}

async function criblGetMetrics() {
  const res = await criblGet(`/api/v1/system/metrics/totals`);
  const items = res.body.items || res.body || [];
  return {
    pipelines: items.map((m) => ({
      pipeline: m.pipeline || m.id || "unknown",
      events_in: m.total_in_events || 0,
      events_out: m.total_out_events || 0,
      bytes_in: m.total_in_bytes || 0,
      bytes_out: m.total_out_bytes || 0,
      reduction_pct: m.total_in_events > 0
        ? (((m.total_in_events - m.total_out_events) / m.total_in_events) * 100).toFixed(1) + "%"
        : "N/A",
    })),
    summary: "Use reduction_pct to measure how much Cribl reduces log volume before indexing.",
  };
}

async function criblListInputs() {
  const res = await criblGet(`/api/v1/system/inputs`);
  const inputs = res.body.items || res.body || [];
  return inputs.map((i) => ({
    id: i.id,
    type: i.type,
    disabled: i.disabled || false,
    pipeline: i.pipeline || null,
    description: i.description || "",
    port: i.port || null,
    conf_summary: Object.keys(i.conf || {}).join(", "),
  }));
}

async function criblGetInputSamples(inputId, count = 10) {
  // Retrieve captured sample events from an input's event capture buffer
  const res = await criblGet(`/api/v1/system/inputs/${inputId}/samples`);
  const samples = (res.body.items || res.body || []).slice(0, count);
  return {
    input: inputId,
    sample_count: samples.length,
    events: samples,
    hint: "Use these samples with cribl_preview_pipeline to test your pipeline changes before deploying.",
  };
}

async function criblListOutputs() {
  const res = await criblGet(`/api/v1/system/outputs`);
  const outputs = res.body.items || res.body || [];
  return outputs.map((o) => ({
    id: o.id,
    type: o.type,
    disabled: o.disabled || false,
    description: o.description || "",
    url: o.url || o.hosts || null,
  }));
}

async function criblTestOutput(outputId) {
  const res = await criblPost(`/api/v1/system/outputs/${outputId}/test`, {});
  return {
    output: outputId,
    success: res.status === 200,
    status: res.status,
    result: res.body,
  };
}

async function criblGetRoutes() {
  const res = await criblGet(`/api/v1/routes`);
  const routes = res.body.routes || res.body.items || res.body || [];
  return {
    total: routes.length,
    routes: routes.map((r, i) => ({
      index: i,
      id: r.id,
      name: r.name || "",
      filter: r.filter || "true",
      pipeline: r.pipeline || "passthru",
      output: r.output || "default",
      final: r.final || false,
      disabled: r.disabled || false,
      description: r.description || "",
    })),
  };
}

async function criblUpdateRoutes(routes) {
  const body = { routes };
  const res = await criblPost(`/api/v1/routes`, body);
  if (res.status !== 200) {
    throw new Error(`Routes update failed (${res.status}): ${JSON.stringify(res.body)}`);
  }
  return {
    success: true,
    total_routes: routes.length,
    routes: routes.map((r) => ({
      id: r.id,
      filter: r.filter,
      pipeline: r.pipeline,
      output: r.output,
    })),
  };
}

// ─── Tool Definitions ─────────────────────────────────────────────────────────
const TOOLS = [
  {
    name: "cribl_health",
    description:
      "Check if Cribl Stream is running and healthy. Returns version, license tier, and worker group status. " +
      "Use this first to verify Cribl is reachable before other operations.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "cribl_list_pipelines",
    description:
      "List all Cribl pipelines with their IDs, descriptions, and function counts. " +
      "Pipelines are log transformation chains that normalize, filter, and route events. " +
      "Use this to see what processing is already configured.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "cribl_get_pipeline",
    description:
      "Get full details of a specific Cribl pipeline including all transformation functions in order. " +
      "Each function has a type (eval, drop, regex_extract, serialize, etc.), filter, and configuration. " +
      "Use this to understand current normalization logic before making changes.",
    inputSchema: {
      type: "object",
      required: ["id"],
      properties: {
        id: { type: "string", description: "Pipeline ID (e.g., 'cim_normalize')" },
      },
    },
  },
  {
    name: "cribl_preview_pipeline",
    description:
      "Test how a pipeline transforms sample events WITHOUT changing live traffic. " +
      "Send sample log events and see exactly what fields are added/modified/dropped at each step. " +
      "This is the primary tool for validating pipeline changes before deploying. " +
      "Use with raw event strings or JSON objects. Essential for verifying CIM field mapping and regex parsers.",
    inputSchema: {
      type: "object",
      required: ["pipeline_id", "sample_events"],
      properties: {
        pipeline_id: { type: "string", description: "Pipeline ID to test against" },
        sample_events: {
          description: "Array of events to test. Can be strings (raw log lines) or JSON objects.",
          oneOf: [
            { type: "array", items: { type: "object" } },
            { type: "array", items: { type: "string" } },
          ],
        },
      },
    },
  },
  {
    name: "cribl_add_pipeline_function",
    description:
      "Add a new transformation function to a Cribl pipeline. " +
      "Use this to: add regex parsers (type: 'regex_extract'), add field drops (type: 'drop'), " +
      "add field renames/CIM mappings (type: 'eval'), add log sampling (type: 'sampling'), " +
      "add event cloning for dual-SIEM routing (type: 'clone'). " +
      "ALWAYS test with cribl_preview_pipeline before adding to a live pipeline. " +
      "Common function types: eval, drop, regex_extract, serialize, mask, sampling, clone, publish_metrics.",
    inputSchema: {
      type: "object",
      required: ["pipeline_id", "function_def"],
      properties: {
        pipeline_id: { type: "string", description: "Pipeline ID to modify" },
        function_def: {
          type: "object",
          description: "Function definition",
          required: ["type"],
          properties: {
            type: {
              type: "string",
              description: "Function type: eval | drop | regex_extract | serialize | mask | sampling | clone | publish_metrics",
            },
            filter: {
              type: "string",
              description: "JavaScript filter expression (e.g., \"event.code == '1'\" or \"true\" for all events)",
              default: "true",
            },
            description: { type: "string", description: "Human-readable description of what this function does" },
            disabled: { type: "boolean", default: false },
            conf: {
              type: "object",
              description: "Function-specific configuration. Examples: eval: {add:[{name:'dest_ip',value:'destination.ip'}]}, drop: {filter:'process.name==\"svchost.exe\"'}, regex_extract: {field:'_raw',regex:'(?<process_name>[^\\\\s]+\\.exe)'}",
            },
          },
        },
        insert_at: {
          type: "integer",
          description: "Position to insert the function (0=first, -1=last). Default: -1 (append at end)",
          default: -1,
        },
      },
    },
  },
  {
    name: "cribl_remove_pipeline_function",
    description:
      "Remove a function from a pipeline by its index position. " +
      "Use cribl_get_pipeline first to see the current function list with indices. " +
      "After removal, test with cribl_preview_pipeline to confirm behavior is correct.",
    inputSchema: {
      type: "object",
      required: ["pipeline_id", "function_index"],
      properties: {
        pipeline_id: { type: "string", description: "Pipeline ID" },
        function_index: { type: "integer", description: "Index of the function to remove (0-based, from cribl_get_pipeline)" },
      },
    },
  },
  {
    name: "cribl_get_metrics",
    description:
      "Get pipeline throughput metrics: events in/out, bytes in/out, and reduction percentage per pipeline. " +
      "Use this to measure the effectiveness of log reduction rules. " +
      "A pipeline reducing 30-50% of events is typical; >70% may indicate over-filtering. " +
      "Also useful for confirming data is flowing after configuration changes.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "cribl_list_inputs",
    description:
      "List all configured Cribl inputs (sources) with type, port, and assigned pipeline. " +
      "Inputs are how data enters Cribl: HEC, Beats/Logstash, Syslog, TCP, HTTP, S3, Kafka, etc. " +
      "Use this to understand what data sources are configured and which pipelines they use.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "cribl_get_input_samples",
    description:
      "Retrieve captured sample events from an input's buffer. " +
      "These are real events that have flowed through the input recently. " +
      "Use these samples with cribl_preview_pipeline to test pipeline changes against actual production data.",
    inputSchema: {
      type: "object",
      required: ["input_id"],
      properties: {
        input_id: { type: "string", description: "Input ID (from cribl_list_inputs)" },
        count: { type: "integer", description: "Number of sample events to retrieve (default: 10)", default: 10 },
      },
    },
  },
  {
    name: "cribl_list_outputs",
    description:
      "List all configured Cribl outputs (destinations): Elasticsearch, Splunk HEC, S3, TCP, etc. " +
      "Use this to see where logs are being sent after pipeline processing.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "cribl_test_output",
    description:
      "Test connectivity to a Cribl output destination. " +
      "Verifies that Cribl can reach Elasticsearch, Splunk HEC, or another destination. " +
      "Use this after configuration changes to confirm data will flow to the SIEM.",
    inputSchema: {
      type: "object",
      required: ["output_id"],
      properties: {
        output_id: { type: "string", description: "Output ID (from cribl_list_outputs)" },
      },
    },
  },
  {
    name: "cribl_get_routes",
    description:
      "Get all Cribl routing rules with filters, pipeline assignments, and output destinations. " +
      "Routes determine which pipeline processes an event and where it is sent. " +
      "Routes are evaluated in order; first matching route wins (if final=true) or all matches apply (final=false).",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "cribl_update_routes",
    description:
      "Replace the full Cribl routing table. Use this to add/modify/reorder routes. " +
      "CAUTION: This replaces ALL routes. Always call cribl_get_routes first to get current routes, " +
      "then modify and submit the full updated list. " +
      "Route example: {id:'attack_route', filter:\"_simulation && _simulation.type=='attack'\", pipeline:'cim_normalize', output:'elastic_out', final:false}",
    inputSchema: {
      type: "object",
      required: ["routes"],
      properties: {
        routes: {
          type: "array",
          description: "Complete ordered list of routing rules",
          items: {
            type: "object",
            required: ["id", "filter", "pipeline", "output"],
            properties: {
              id: { type: "string" },
              name: { type: "string" },
              filter: { type: "string", description: "JavaScript filter expression" },
              pipeline: { type: "string" },
              output: { type: "string" },
              final: { type: "boolean", default: false },
              disabled: { type: "boolean", default: false },
              description: { type: "string" },
            },
          },
        },
      },
    },
  },
];

// ─── MCP Server ───────────────────────────────────────────────────────────────
const server = new Server(
  { name: "cribl-stream", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let result;

    switch (name) {
      case "cribl_health":
        result = await criblHealth();
        break;
      case "cribl_list_pipelines":
        result = await criblListPipelines();
        break;
      case "cribl_get_pipeline":
        result = await criblGetPipeline(args.id);
        break;
      case "cribl_preview_pipeline":
        result = await criblPreviewPipeline(args.pipeline_id, args.sample_events);
        break;
      case "cribl_add_pipeline_function":
        result = await criblAddPipelineFunction(args.pipeline_id, args.function_def, args.insert_at ?? -1);
        break;
      case "cribl_remove_pipeline_function":
        result = await criblRemovePipelineFunction(args.pipeline_id, args.function_index);
        break;
      case "cribl_get_metrics":
        result = await criblGetMetrics();
        break;
      case "cribl_list_inputs":
        result = await criblListInputs();
        break;
      case "cribl_get_input_samples":
        result = await criblGetInputSamples(args.input_id, args.count ?? 10);
        break;
      case "cribl_list_outputs":
        result = await criblListOutputs();
        break;
      case "cribl_test_output":
        result = await criblTestOutput(args.output_id);
        break;
      case "cribl_get_routes":
        result = await criblGetRoutes();
        break;
      case "cribl_update_routes":
        result = await criblUpdateRoutes(args.routes);
        break;
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  } catch (error) {
    return {
      content: [{ type: "text", text: `Error: ${error.message}` }],
      isError: true,
    };
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
const transport = new StdioServerTransport();
await server.connect(transport);
// Server is running on stdio — Claude Code will communicate via stdin/stdout
