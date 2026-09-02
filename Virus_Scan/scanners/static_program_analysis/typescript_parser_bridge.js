"use strict";

/*
 * Canonical bounded TypeScript-compiler AST bridge.
 *
 * This process parses source text only. It never executes the target, resolves
 * imports, loads target modules, performs network access, or maps ATT&CK data.
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const ts = require(path.join(__dirname, "typescript_parser_resource", "typescript.js"));

const BRIDGE_SCHEMA_VERSION = "javascript_typescript_ast_bridge_v2";
const MAX_REQUEST_BYTES = 2_100_000;
const MAX_RESPONSE_BYTES = 12_000_000;

function digest(parts) {
  return crypto.createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}
function identity(prefix, ...parts) {
  return prefix + digest(parts).slice(0, 40);
}
function exactObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function boundedText(value, maximum) {
  return String(value).slice(0, maximum);
}
function readRequest() {
  const data = fs.readFileSync(0);
  if (data.length > MAX_REQUEST_BYTES) throw new Error("bridge_request_limit_exceeded");
  const value = JSON.parse(data.toString("utf8"));
  if (!exactObject(value)) throw new Error("bridge_request_invalid");
  return value;
}
function scriptKind(extension) {
  switch (extension) {
    case ".ts": case ".mts": case ".cts": return ts.ScriptKind.TS;
    case ".tsx": return ts.ScriptKind.TSX;
    case ".jsx": return ts.ScriptKind.JSX;
    case ".json": return ts.ScriptKind.JSON;
    default: return ts.ScriptKind.JS;
  }
}
function operatorText(kind) {
  return ts.tokenToString(kind) || ts.SyntaxKind[kind] || "unknown";
}

class Analyzer {
  constructor(sourceFile, request) {
    this.sourceFile = sourceFile;
    this.source = request.source;
    this.extension = request.extension;
    this.maxNodes = request.max_nodes;
    this.maxDepth = request.max_depth;
    this.maxOperations = request.max_operations;
    this.maxEdges = request.max_edges;
    this.maxFunctions = request.max_functions;
    this.maxUnresolved = request.max_unresolved;
    this.maxText = request.max_text;
    this.nodeCount = 0;
    this.ordinal = 0;
    this.operations = [];
    this.edges = [];
    this.functions = new Map();
    this.ambiguousFunctions = new Set();
    this.functionReachability = new Map();
    this.unresolved = new Set();
    this.limitations = new Set();
    this.moduleKey = "<module>";
    this.importAliases = new Map();
  }

  touch(node, depth) {
    this.nodeCount += 1;
    if (this.nodeCount > this.maxNodes) {
      this.limitations.add("ast_node_limit_exceeded");
      return false;
    }
    if (depth > this.maxDepth) {
      this.limitations.add("ast_depth_limit_exceeded");
      return false;
    }
    return true;
  }
  rememberUnresolved(value) {
    if (this.unresolved.size >= this.maxUnresolved) {
      this.limitations.add("unresolved_construct_limit_exceeded");
      return;
    }
    this.unresolved.add(boundedText(value, 512));
  }
  location(node) {
    const start = node.getStart(this.sourceFile, false);
    const end = node.getEnd();
    const first = this.sourceFile.getLineAndCharacterOfPosition(start);
    const last = this.sourceFile.getLineAndCharacterOfPosition(end);
    return {
      line: first.line + 1,
      column: first.character,
      end_line: last.line + 1,
      end_column: last.character,
    };
  }
  callName(expression, env) {
    if (ts.isIdentifier(expression)) {
      const name = expression.text;
      const state = env.get(name);
      if (state && typeof state.resolved === "string" && state.resolved.startsWith("callable:")) {
        return state.resolved.slice("callable:".length);
      }
      return this.importAliases.get(name) || name;
    }
    if (ts.isCallExpression(expression) && ts.isIdentifier(expression.expression) && expression.expression.text === "require" && expression.arguments.length && ts.isStringLiteral(expression.arguments[0])) {
      return expression.arguments[0].text;
    }
    if (ts.isPropertyAccessExpression(expression)) {
      const left = this.callName(expression.expression, env);
      return left ? `${left}.${expression.name.text}` : expression.name.text;
    }
    if (ts.isElementAccessExpression(expression)) {
      const left = this.callName(expression.expression, env);
      const key = this.literalValue(expression.argumentExpression, env);
      return left && key.resolved !== null ? `${left}.${key.resolved}` : left;
    }
    if (ts.isParenthesizedExpression(expression)) return this.callName(expression.expression, env);
    return "";
  }
  literalValue(expression, env, depth = 0) {
    if (!expression || !this.touch(expression, depth)) return this.emptyState("limit");
    if (ts.isStringLiteralLike(expression)) return this.valueState(expression.text);
    if (ts.isNumericLiteral(expression)) return this.valueState(Number(expression.text));
    if (expression.kind === ts.SyntaxKind.TrueKeyword) return this.valueState(true);
    if (expression.kind === ts.SyntaxKind.FalseKeyword) return this.valueState(false);
    if (expression.kind === ts.SyntaxKind.NullKeyword) return this.valueState(null, true);
    if (ts.isIdentifier(expression)) {
      return env.get(expression.text) || this.emptyState(`identifier:${expression.text}`);
    }
    if (ts.isParenthesizedExpression(expression)) return this.literalValue(expression.expression, env, depth + 1);
    if (ts.isAsExpression(expression) || ts.isTypeAssertionExpression(expression) || ts.isNonNullExpression(expression)) {
      return this.literalValue(expression.expression, env, depth + 1);
    }
    if (ts.isAwaitExpression(expression)) return this.evaluateExpression(expression.expression, env, this.moduleKey, "await", "conditionally_reachable", depth + 1);
    if (ts.isTemplateExpression(expression)) {
      let text = expression.head.text;
      const states = [];
      for (const span of expression.templateSpans) {
        const state = this.literalValue(span.expression, env, depth + 1);
        states.push(state);
        if (!state.known || typeof state.resolved === "object") return this.combineStates(states, "template_unresolved");
        text += String(state.resolved) + span.literal.text;
      }
      const combined = this.combineStates(states, "template");
      return {...combined, known: true, resolved: boundedText(text, this.maxText)};
    }
    if (ts.isNoSubstitutionTemplateLiteral(expression)) return this.valueState(expression.text);
    if (ts.isBinaryExpression(expression) && expression.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const left = this.literalValue(expression.left, env, depth + 1);
      const right = this.literalValue(expression.right, env, depth + 1);
      const combined = this.combineStates([left, right], "binary_plus");
      if (left.known && right.known && [left.resolved, right.resolved].every(v => ["string", "number"].includes(typeof v))) {
        return {...combined, known: true, resolved: boundedText(String(left.resolved) + String(right.resolved), this.maxText)};
      }
      return combined;
    }
    if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
      const name = this.callName(expression, env);
      return name ? this.valueState(`callable:${name}`) : this.emptyState("property_unresolved");
    }
    if (ts.isArrayLiteralExpression(expression)) {
      const values = expression.elements.slice(0, 64).map(item => this.literalValue(item, env, depth + 1));
      const combined = this.combineStates(values, "array");
      if (values.every(item => item.known)) return {...combined, known: true, resolved: values.map(item => item.resolved)};
      return combined;
    }
    if (ts.isObjectLiteralExpression(expression)) {
      const values = [];
      const output = {};
      for (const property of expression.properties.slice(0, 64)) {
        if (ts.isPropertyAssignment(property)) {
          const key = property.name.getText(this.sourceFile).replace(/^['"]|['"]$/g, "");
          const state = this.literalValue(property.initializer, env, depth + 1);
          values.push(state);
          if (state.known) output[key] = state.resolved;
        } else if (ts.isShorthandPropertyAssignment(property)) {
          const state = env.get(property.name.text) || this.emptyState(`identifier:${property.name.text}`);
          values.push(state);
          if (state.known) output[property.name.text] = state.resolved;
        }
      }
      const combined = this.combineStates(values, "object");
      return {...combined, known: Object.keys(output).length === values.length, resolved: output};
    }
    return this.emptyState(`expression:${ts.SyntaxKind[expression.kind] || expression.kind}`);
  }
  emptyState(reason = "") {
    return {valueId: "", known: false, resolved: null, flowIdentity: "", sourceOperation: null, sourceOperations: [], dynamic: false, reason};
  }
  valueState(value, explicitKnown = false) {
    return {valueId: "", known: explicitKnown || value !== undefined, resolved: value, flowIdentity: "", sourceOperation: null, sourceOperations: [], dynamic: false, reason: ""};
  }
  combineStates(states, reason) {
    const sources = [...new Set(states.flatMap(item => item.sourceOperations || (item.sourceOperation === null ? [] : [item.sourceOperation])))];
    const flows = [...new Set(states.map(item => item.flowIdentity).filter(Boolean))];
    const valueIds = [...new Set(states.map(item => item.valueId).filter(Boolean))];
    return {
      valueId: valueIds.length === 1 ? valueIds[0] : "",
      known: false,
      resolved: null,
      flowIdentity: flows.length === 1 && sources.length === 1 ? flows[0] : "",
      sourceOperation: sources.length === 1 ? sources[0] : null,
      sourceOperations: sources,
      dynamic: states.some(item => item.dynamic),
      reason,
    };
  }
  functionName(node) {
    if (node.name && ts.isIdentifier(node.name)) return node.name.text;
    return "";
  }
  collectImportsAndFunctions(statements, depth = 0) {
    for (const statement of statements) {
      if (!this.touch(statement, depth)) continue;
      if (ts.isImportDeclaration(statement) && statement.moduleSpecifier && ts.isStringLiteral(statement.moduleSpecifier)) {
        const moduleName = statement.moduleSpecifier.text;
        const clause = statement.importClause;
        if (clause) {
          if (clause.name) this.importAliases.set(clause.name.text, moduleName);
          if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
            this.importAliases.set(clause.namedBindings.name.text, moduleName);
          } else if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
            for (const specifier of clause.namedBindings.elements) {
              this.importAliases.set(specifier.name.text, `${moduleName}.${(specifier.propertyName || specifier.name).text}`);
            }
          }
        }
      } else if (ts.isImportEqualsDeclaration(statement)) {
        const ref = statement.moduleReference;
        if (ts.isExternalModuleReference(ref) && ref.expression && ts.isStringLiteral(ref.expression)) {
          this.importAliases.set(statement.name.text, ref.expression.text);
        }
      }
      if (ts.isFunctionDeclaration(statement) && statement.name) this.registerFunction(statement.name.text, statement);
      if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          if (ts.isIdentifier(declaration.name) && declaration.initializer && (ts.isArrowFunction(declaration.initializer) || ts.isFunctionExpression(declaration.initializer))) {
            this.registerFunction(declaration.name.text, declaration.initializer);
          }
        }
      }
      if (ts.isBlock(statement)) this.collectImportsAndFunctions(statement.statements, depth + 1);
      if (ts.isIfStatement(statement)) {
        this.collectImportsAndFunctions(this.statementList(statement.thenStatement), depth + 1);
        if (statement.elseStatement) this.collectImportsAndFunctions(this.statementList(statement.elseStatement), depth + 1);
      }
    }
  }
  registerFunction(name, node) {
    if (this.ambiguousFunctions.has(name)) return;
    if (this.functions.has(name)) {
      this.functions.delete(name);
      this.ambiguousFunctions.add(name);
      this.limitations.add("duplicate_function_name");
      this.rememberUnresolved(`duplicate_function:${name}`);
      return;
    }
    if (this.functions.size >= this.maxFunctions) {
      this.limitations.add("function_limit_exceeded");
      return;
    }
    this.functions.set(name, node);
  }
  statementList(statement) {
    if (!statement) return [];
    return ts.isBlock(statement) ? [...statement.statements] : [statement];
  }
  collectCalls(node, output, depth = 0, skipFunctions = false) {
    if (!node || !this.touch(node, depth)) return;
    if (skipFunctions && (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node))) return;
    if (ts.isCallExpression(node)) {
      const name = this.callName(node.expression, new Map());
      if (name && !name.includes(".")) output.add(name);
    }
    ts.forEachChild(node, child => this.collectCalls(child, output, depth + 1, skipFunctions));
  }
  resolveFunctionReachability() {
    const calls = new Map();
    const moduleCalls = new Set();
    for (const statement of this.sourceFile.statements) this.collectCalls(statement, moduleCalls, 0, true);
    calls.set(this.moduleKey, moduleCalls);
    for (const [name, node] of this.functions) {
      const set = new Set();
      if (node.body) this.collectCalls(node.body, set, 0, false);
      calls.set(name, set);
    }
    const reachable = new Set([...moduleCalls].filter(name => this.functions.has(name)));
    const queue = [...reachable].sort();
    while (queue.length) {
      const current = queue.shift();
      for (const called of [...(calls.get(current) || [])].sort()) {
        if (this.functions.has(called) && !reachable.has(called)) {
          reachable.add(called); queue.push(called);
        }
      }
    }
    for (const name of this.functions.keys()) this.functionReachability.set(name, reachable.has(name) ? "entrypoint_reachable" : "locally_reachable");
  }
  evaluateCondition(expression, env) {
    const state = this.literalValue(expression, env);
    if (state.known && typeof state.resolved === "boolean") return state.resolved;
    return null;
  }
  cloneEnv(env) { return new Map(env); }
  mergeEnvs(left, right) {
    const out = new Map();
    for (const [key, a] of left) {
      const b = right.get(key);
      if (!b) continue;
      if (JSON.stringify(a) === JSON.stringify(b)) out.set(key, a);
    }
    return out;
  }
  analyze() {
    this.collectImportsAndFunctions(this.sourceFile.statements);
    this.resolveFunctionReachability();
    const moduleEnv = new Map();
    for (const [name, value] of this.importAliases) moduleEnv.set(name, this.valueState(`callable:${value}`));
    const moduleStatements = this.sourceFile.statements.filter(statement => !ts.isFunctionDeclaration(statement));
    this.visitStatements(moduleStatements, this.moduleKey, "module_entry", "entrypoint_reachable", moduleEnv, 0);
    for (const name of [...this.functions.keys()].sort()) {
      const node = this.functions.get(name);
      const env = new Map();
      for (const [alias, value] of this.importAliases) env.set(alias, this.valueState(`callable:${value}`));
      for (const parameter of node.parameters || []) if (ts.isIdentifier(parameter.name)) env.set(parameter.name.text, this.emptyState(`parameter:${parameter.name.text}`));
      const body = node.body && ts.isBlock(node.body) ? node.body.statements : [];
      this.visitStatements(body, name, "function_entry", this.functionReachability.get(name) || "locally_reachable", env, 0);
    }
    return this.finish();
  }
  visitStatements(statements, functionKey, blockKey, reachability, env, depth) {
    let currentReachability = reachability;
    for (let index = 0; index < statements.length; index += 1) {
      const statement = statements[index];
      if (!this.touch(statement, depth)) continue;
      const statementBlock = `${blockKey}:${index}`;
      if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) this.visitDeclaration(declaration, functionKey, statementBlock, currentReachability, env, depth + 1);
      } else if (ts.isExpressionStatement(statement)) {
        this.evaluateExpression(statement.expression, env, functionKey, statementBlock, currentReachability, depth + 1);
      } else if (ts.isIfStatement(statement)) {
        const condition = this.evaluateCondition(statement.expression, env);
        const thenEnv = this.cloneEnv(env); const elseEnv = this.cloneEnv(env);
        const thenReach = condition === false ? "unreachable" : condition === true ? currentReachability : "conditionally_reachable";
        const elseReach = condition === true ? "unreachable" : condition === false ? currentReachability : "conditionally_reachable";
        this.visitStatements(this.statementList(statement.thenStatement), functionKey, `${statementBlock}:then`, thenReach, thenEnv, depth + 1);
        if (statement.elseStatement) this.visitStatements(this.statementList(statement.elseStatement), functionKey, `${statementBlock}:else`, elseReach, elseEnv, depth + 1);
        const merged = this.mergeEnvs(thenEnv, elseEnv); env.clear(); for (const [key, value] of merged) env.set(key, value);
      } else if (ts.isBlock(statement)) {
        this.visitStatements(statement.statements, functionKey, statementBlock, currentReachability, env, depth + 1);
      } else if (ts.isReturnStatement(statement)) {
        if (statement.expression) this.evaluateExpression(statement.expression, env, functionKey, statementBlock, currentReachability, depth + 1);
        currentReachability = "unreachable";
      } else if (ts.isForStatement(statement) || ts.isForOfStatement(statement) || ts.isForInStatement(statement) || ts.isWhileStatement(statement) || ts.isDoStatement(statement)) {
        this.visitStatements(this.statementList(statement.statement), functionKey, `${statementBlock}:loop`, "conditionally_reachable", this.cloneEnv(env), depth + 1);
      } else if (ts.isTryStatement(statement)) {
        this.visitStatements(statement.tryBlock.statements, functionKey, `${statementBlock}:try`, currentReachability, this.cloneEnv(env), depth + 1);
        if (statement.catchClause) this.visitStatements(statement.catchClause.block.statements, functionKey, `${statementBlock}:catch`, "conditionally_reachable", this.cloneEnv(env), depth + 1);
        if (statement.finallyBlock) this.visitStatements(statement.finallyBlock.statements, functionKey, `${statementBlock}:finally`, currentReachability, env, depth + 1);
      } else if (ts.isClassDeclaration(statement)) {
        this.rememberUnresolved("class_body_analysis_unavailable");
        continue;
      } else if (ts.isFunctionDeclaration(statement) || ts.isInterfaceDeclaration(statement) || ts.isTypeAliasDeclaration(statement) || ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement)) {
        continue;
      } else {
        this.rememberUnresolved(`statement:${ts.SyntaxKind[statement.kind] || statement.kind}`);
      }
    }
  }
  visitDeclaration(declaration, functionKey, blockKey, reachability, env, depth) {
    if (!ts.isIdentifier(declaration.name)) {
      this.rememberUnresolved("binding_pattern"); return;
    }
    const name = declaration.name.text;
    if (!declaration.initializer) { env.set(name, this.emptyState(`uninitialized:${name}`)); return; }
    if (ts.isCallExpression(declaration.initializer) && ts.isIdentifier(declaration.initializer.expression) && declaration.initializer.expression.text === "require" && declaration.initializer.arguments.length && ts.isStringLiteral(declaration.initializer.arguments[0])) {
      const moduleName = declaration.initializer.arguments[0].text;
      env.set(name, this.valueState(`callable:${moduleName}`)); return;
    }
    if (ts.isArrowFunction(declaration.initializer) || ts.isFunctionExpression(declaration.initializer)) return;
    const state = this.evaluateExpression(declaration.initializer, env, functionKey, blockKey, reachability, depth + 1);
    const sourceValueId = state.valueId;
    const valueId = identity("val_", this.sourceFile.fileName, functionKey, blockKey, name);
    env.set(name, {...state, valueId});
    if (state.flowIdentity && state.sourceOperation !== null && sourceValueId) {
      this.addEdge("assignment", state.flowIdentity, sourceValueId, valueId, state.sourceOperation, null);
    }
  }
  evaluateExpression(expression, env, functionKey, blockKey, reachability, depth) {
    if (!expression || !this.touch(expression, depth)) return this.emptyState("limit");
    if (ts.isCallExpression(expression) || ts.isNewExpression(expression)) return this.evaluateCall(expression, env, functionKey, blockKey, reachability, depth + 1);
    if (ts.isBinaryExpression(expression) && expression.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const state = this.evaluateExpression(expression.right, env, functionKey, blockKey, reachability, depth + 1);
      if (ts.isIdentifier(expression.left)) {
        const sourceValueId = state.valueId;
        const valueId = identity("val_", this.sourceFile.fileName, functionKey, blockKey, expression.left.text);
        env.set(expression.left.text, {...state, valueId});
        if (state.flowIdentity && state.sourceOperation !== null && sourceValueId) this.addEdge("assignment", state.flowIdentity, sourceValueId, valueId, state.sourceOperation, null);
      } else this.rememberUnresolved("assignment_target_unresolved");
      return state;
    }
    if (ts.isConditionalExpression(expression)) {
      const condition = this.evaluateCondition(expression.condition, env);
      if (condition === true) return this.evaluateExpression(expression.whenTrue, env, functionKey, blockKey, reachability, depth + 1);
      if (condition === false) return this.evaluateExpression(expression.whenFalse, env, functionKey, blockKey, reachability, depth + 1);
      const left = this.evaluateExpression(expression.whenTrue, this.cloneEnv(env), functionKey, `${blockKey}:true`, "conditionally_reachable", depth + 1);
      const right = this.evaluateExpression(expression.whenFalse, this.cloneEnv(env), functionKey, `${blockKey}:false`, "conditionally_reachable", depth + 1);
      return this.combineStates([left, right], "conditional_expression");
    }
    return this.literalValue(expression, env, depth + 1);
  }
  resolvedOptions(state) {
    return state && exactObject(state.resolved) ? state.resolved : {};
  }
  classifyCall(name, argumentStates, expression, env) {
    const low = name.toLowerCase();
    const first = argumentStates[0] || this.emptyState();
    const second = argumentStates[1] || this.emptyState();
    const options = this.resolvedOptions(second);
    const method = String(options.method || "GET").toUpperCase();
    if (["eval", "function", "global.eval", "window.eval"].includes(low) || low.endsWith(".eval")) return {dynamic: true, reason: `dynamic_execution:${low}`};
    if (["settimeout", "setinterval"].includes(low) && first.known && typeof first.resolved === "string") return {dynamic: true, reason: `dynamic_execution:${low}`};
    if (["fs.readfile", "fs.readfilesync", "fs.promises.readfile", "node:fs.readfile", "node:fs.readfilesync", "deno.readfile", "deno.readtextfile"].includes(low)) {
      const target = firstResolvedText(argumentStates);
      const resourceFamily = credentialResourceFamily(target);
      return {
        kind: "file_read",
        source: true,
        additionalKinds: resourceFamily ? [{kind: "credential_store_discovery", resolvedArguments: {resource_family: resourceFamily}}] : [],
      };
    }
    if (["fs.writefile", "fs.writefilesync", "fs.appendfile", "fs.appendfilesync", "deno.writefile", "deno.writetextfile"].includes(low)) return {kind: "file_write", sink: true};
    if (["child_process.exec", "child_process.execsync", "child_process.spawn", "child_process.spawnsync", "child_process.execfile", "child_process.fork", "bun.spawn"].includes(low)) return {kind: "process_launch", sink: true};
    if (["fetch", "global.fetch", "window.fetch"].includes(low)) return method === "GET" || method === "HEAD" ? {kind: "network_download", source: true} : {kind: "network_send", sink: true, additionalKinds: [{kind: "network_upload", sink: true}]};
    if (["axios.get", "http.get", "https.get", "got.get"].includes(low)) return {kind: "network_download", source: true};
    if (low === "axios.request") {
      const requestOptions = this.resolvedOptions(argumentStates[0]);
      const requestMethod = String(requestOptions.method || "GET").toUpperCase();
      return requestMethod === "GET" || requestMethod === "HEAD" ? {kind: "network_download", source: true} : {kind: "network_send", sink: true, additionalKinds: [{kind: "network_upload", sink: true}]};
    }
    if (["axios.post", "axios.put", "axios.patch", "navigator.sendbeacon"].includes(low)) return {kind: "network_send", sink: true, additionalKinds: [{kind: "network_upload", sink: true}]};
    if (["socket.write", "socket.send", "websocket.send", "xmlhttprequest.send"].includes(low)) return {kind: "network_send", sink: true};
    if (["net.connect", "tls.connect", "websocket"].includes(low)) return {kind: "network_connect", handle: true, handleType: "network_handle"};
    if (["buffer.from", "atob"].includes(low) && (low === "atob" || String(second.resolved || "").toLowerCase() === "base64")) return {kind: "decode", transform: true};
    if (["crypto.privatedecrypt", "crypto.publicdecrypt", "crypto.subtle.decrypt", "subtle.decrypt"].includes(low)) return {kind: "decrypt", transform: true};
    if (["zlib.gunzip", "zlib.gunzipsync", "zlib.unzip", "zlib.unzipsync", "zlib.inflate", "zlib.inflatesync", "zlib.brotlidecompress", "zlib.brotlidecompresssync"].includes(low)) return {kind: "decompress", transform: true};
    if (low === "json.stringify") return {kind: "serialize", transform: true};
    if (["sqlite3.database", "better-sqlite3"].includes(low)) return {kind: "database_open", handle: true, handleType: "database_handle"};
    if (ts.isPropertyAccessExpression(expression.expression) && ts.isIdentifier(expression.expression.expression)) {
      const receiver = env.get(expression.expression.expression.text);
      if (receiver && receiver.resolved === "database_handle" && ["get", "all", "each", "query"].includes(expression.expression.name.text.toLowerCase())) return {kind: "database_query", source: true};
      if (receiver && receiver.resolved === "network_handle" && ["send", "write"].includes(expression.expression.name.text.toLowerCase())) return {kind: "network_send", sink: true};
    }
    return {};
  }
  evaluateCall(expression, env, functionKey, blockKey, reachability, depth) {
    const args = [...(expression.arguments || [])];
    const argumentStates = args.map(arg => this.evaluateExpression(arg, env, functionKey, blockKey, reachability, depth + 1));
    let name = this.callName(expression.expression, env);
    if (expression.kind === ts.SyntaxKind.NewExpression && name) name = name;
    const low = name.toLowerCase();
    if (this.ambiguousFunctions.has(name)) {
      this.rememberUnresolved(`ambiguous_function_call:${name}`); return this.emptyState("ambiguous_function");
    }
    if (this.functions.has(name)) return this.emptyState(`local_function_call:${name}`);
    if (expression.expression && expression.expression.kind === ts.SyntaxKind.ImportKeyword) {
      this.rememberUnresolved("dynamic_import");
      return {...this.emptyState("dynamic_import"), dynamic: true};
    }
    const classification = this.classifyCall(name, argumentStates, expression, env);
    if (classification.dynamic) {
      this.rememberUnresolved(classification.reason); return {...this.emptyState(classification.reason), dynamic: true};
    }
    if (!classification.kind) {
      if (low === "import") this.rememberUnresolved("dynamic_import");
      return this.combineStates(argumentStates, `call_unclassified:${boundedText(name || "unknown", 160)}`);
    }
    const sourceOps = [...new Set(argumentStates.flatMap(item => item.sourceOperations || (item.sourceOperation === null ? [] : [item.sourceOperation])))];
    const flows = [...new Set(argumentStates.map(item => item.flowIdentity).filter(Boolean))];
    let flowIdentity = "";
    let resolution = "resolved";
    const limitations = [];
    if (classification.source) flowIdentity = identity("flow_", this.sourceFile.fileName, functionKey, blockKey, this.ordinal, classification.kind);
    else if (classification.transform || classification.sink) {
      if (flows.length === 1 && sourceOps.length === 1 && !argumentStates.some(item => item.dynamic)) flowIdentity = flows[0];
      else if (sourceOps.length > 1 || flows.length > 1) { resolution = "partial"; limitations.push("ambiguous_source_flow"); }
      else if (classification.sink && argumentStates.some(item => !item.known && !item.flowIdentity)) { resolution = "partial"; limitations.push("argument_unresolved"); }
    }
    const outputValueId = (classification.source || classification.transform || classification.handle) ? identity("val_", this.sourceFile.fileName, functionKey, blockKey, this.ordinal, "output") : "";
    const targetText = firstResolvedText(argumentStates);
    const resolvedArguments = {call: boundedText(name || "unknown", 256)};
    const resolvedValues = argumentStates.map(item => item.known ? item.resolved : null).slice(0, 32);
    resolvedArguments.arguments = resolvedValues;
    if (name.toLowerCase().includes("fetch") && Object.keys(this.resolvedOptions(argumentStates[1])).length) resolvedArguments.options = this.resolvedOptions(argumentStates[1]);
    const operationDrafts = [
      {kind: classification.kind, sink: Boolean(classification.sink), resolvedArguments: {}},
      ...((classification.additionalKinds || []).map(item => ({kind: item.kind, sink: Boolean(item.sink), resolvedArguments: item.resolvedArguments || {}}))),
    ];
    const operationIndices = [];
    for (const operationDraft of operationDrafts) {
      const operationIndex = this.addOperation({
        kind: operationDraft.kind,
        node: expression,
        functionKey,
        blockKey,
        reachability,
        platform: low.includes("win32") ? "windows" : "",
        targetResource: targetText,
        inputValues: argumentStates.map(item => item.valueId).filter(Boolean),
        outputValues: outputValueId ? [outputValueId] : [],
        flowIdentity,
        resolvedArguments: {...resolvedArguments, ...operationDraft.resolvedArguments},
        resolution,
        limitations,
        integrity: resolution === "resolved" ? "verified" : "partial",
      });
      operationIndices.push({index: operationIndex, sink: operationDraft.sink});
    }
    if (flowIdentity && sourceOps.length === 1) {
      const sourceState = argumentStates.find(item => item.sourceOperation === sourceOps[0] || (item.sourceOperations || []).includes(sourceOps[0]));
      const sourceValue = sourceState && sourceState.valueId ? sourceState.valueId : identity("val_", this.sourceFile.fileName, "source", sourceOps[0]);
      for (const item of operationIndices) {
        if (!(classification.transform || item.sink) || item.index === null) continue;
        const targetValue = outputValueId || identity("val_", this.sourceFile.fileName, functionKey, blockKey, item.index, "sink");
        this.addEdge("source_to_sink", flowIdentity, sourceValue, targetValue, sourceOps[0], item.index);
      }
    }
    const primaryOperationIndex = operationIndices.length ? operationIndices[0].index : null;
    return {
      valueId: outputValueId,
      known: Boolean(classification.handle),
      resolved: classification.handle ? (classification.handleType || "opaque_handle") : null,
      flowIdentity,
      sourceOperation: (classification.source || classification.transform) ? primaryOperationIndex : (sourceOps.length === 1 ? sourceOps[0] : null),
      sourceOperations: (classification.source || classification.transform) && primaryOperationIndex !== null ? [primaryOperationIndex] : sourceOps,
      dynamic: false,
      reason: "",
    };
  }
  addOperation(draft) {
    if (this.operations.length >= this.maxOperations) { this.limitations.add("operation_limit_exceeded"); return null; }
    const index = this.operations.length;
    const location = this.location(draft.node);
    this.operations.push({
      operation_kind: draft.kind,
      source_location: location,
      function_key: draft.functionKey,
      block_key: draft.blockKey,
      control_flow_ordinal: this.ordinal++,
      reachability_state: draft.reachability,
      platform: draft.platform,
      target_resource: boundedText(draft.targetResource || "", this.maxText),
      input_value_ids: draft.inputValues,
      output_value_ids: draft.outputValues,
      flow_identity: draft.flowIdentity,
      resolved_arguments: draft.resolvedArguments,
      resolution_state: draft.resolution,
      limitations: draft.limitations,
      integrity_status: draft.integrity,
    });
    return index;
  }
  addEdge(kind, flowIdentity, sourceValue, targetValue, sourceOperation, targetOperation) {
    if (!flowIdentity || !sourceValue || !targetValue) return;
    if (this.edges.length >= this.maxEdges) { this.limitations.add("flow_edge_limit_exceeded"); return; }
    this.edges.push({
      edge_kind: kind,
      flow_identity: flowIdentity,
      source_value_id: sourceValue,
      target_value_id: targetValue,
      source_operation_index: sourceOperation,
      target_operation_index: targetOperation,
      resolution_state: "resolved",
      limitations: [],
      integrity_status: "verified",
    });
  }
  finish() {
    const limited = [...this.limitations].some(item => item.endsWith("limit_exceeded"));
    return {
      schema_version: BRIDGE_SCHEMA_VERSION,
      typescript_version: ts.version,
      parser_status: limited ? "truncated" : "complete",
      language: [".ts", ".tsx", ".mts", ".cts"].includes(this.extension) ? "typescript" : "javascript",
      operations: this.operations,
      flow_edges: this.edges,
      entrypoint_function_keys: [this.moduleKey],
      unresolved_constructs: [...this.unresolved].sort(),
      limitations: [...this.limitations].sort(),
      node_count: this.nodeCount,
    };
  }
}
function credentialResourceFamily(value) {
  const normalized = String(value || "").toLowerCase().replaceAll("\\", "/");
  if (normalized.includes("login data")) return "browser_login_data";
  if (normalized.includes("local state")) return "browser_local_state";
  return "";
}
function firstResolvedText(states) {
  for (const state of states) {
    if (state && state.known && ["string", "number"].includes(typeof state.resolved)) return String(state.resolved);
  }
  return "";
}

function validateRequest(request) {
  const expected = ["extension", "file_name", "max_depth", "max_edges", "max_functions", "max_nodes", "max_operations", "max_text", "max_unresolved", "source"];
  if (Object.keys(request).sort().join("|") !== expected.sort().join("|")) throw new Error("bridge_request_fields_invalid");
  if (typeof request.source !== "string" || typeof request.extension !== "string" || typeof request.file_name !== "string") throw new Error("bridge_request_identity_invalid");
  for (const name of ["max_depth", "max_edges", "max_functions", "max_nodes", "max_operations", "max_text", "max_unresolved"]) {
    if (!Number.isSafeInteger(request[name]) || request[name] <= 0) throw new Error("bridge_request_limit_invalid");
  }
}
function main() {
  const request = readRequest();
  validateRequest(request);
  const sourceFile = ts.createSourceFile(
    request.file_name,
    request.source,
    ts.ScriptTarget.Latest,
    true,
    scriptKind(request.extension),
  );
  const diagnostics = (sourceFile.parseDiagnostics || []).filter(item => item.category === ts.DiagnosticCategory.Error);
  let result;
  if (diagnostics.length) {
    result = {
      schema_version: BRIDGE_SCHEMA_VERSION,
      typescript_version: ts.version,
      parser_status: "failed",
      language: [".ts", ".tsx", ".mts", ".cts"].includes(request.extension) ? "typescript" : "javascript",
      operations: [], flow_edges: [], entrypoint_function_keys: [], unresolved_constructs: [], limitations: [], node_count: 0,
      parse_diagnostics: diagnostics.slice(0, 64).map(item => ({code: item.code, start: item.start || 0, length: item.length || 0})),
    };
  } else {
    result = new Analyzer(sourceFile, request).analyze();
    result.parse_diagnostics = [];
  }
  const encoded = Buffer.from(JSON.stringify(result), "utf8");
  if (encoded.length > MAX_RESPONSE_BYTES) throw new Error("bridge_response_limit_exceeded");
  process.stdout.write(encoded);
}
try { main(); }
catch (error) {
  const reason = error && error.message ? String(error.message) : "bridge_failed";
  process.stderr.write(boundedText(reason, 512));
  process.exitCode = 2;
}
