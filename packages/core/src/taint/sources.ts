import ts from 'typescript';
import type { Confidence, SourceKind, TypeOrigin } from '@ngbastion/plugin-api';
import { originIs, type Symbols } from '../symbols.js';
import { memberName, memberObject, skipOuter } from '../util.js';

export interface SourceMatch {
  kind: SourceKind;
  description: string;
  trust: Confidence;
}

const ROUTER = '@angular/router';
const FORMS = '@angular/forms';
const LOCATION_PROPS = new Set(['href', 'search', 'hash', 'pathname']);
const ROUTE_CONTAINERS = new Set(['queryParams', 'params', 'queryParamMap', 'paramMap']);
const FORM_TYPES = ['FormControl', 'FormGroup', 'FormArray', 'AbstractControl', 'UntypedFormControl', 'UntypedFormGroup', 'FormRecord', 'NgModel', 'NgControl'];

/** ActivatedRoute / ActivatedRouteSnapshot, including `route.snapshot` when router types are unavailable. */
export function routeKind(expr: ts.Expression, symbols: Symbols): 'route' | 'snapshot' | undefined {
  const e = skipOuter(expr);
  const o = symbols.typeOrigin(e);
  if (originIs(o, ROUTER, 'ActivatedRoute')) return 'route';
  if (originIs(o, ROUTER, 'ActivatedRouteSnapshot')) return 'snapshot';
  if (memberName(e) === 'snapshot') {
    const obj = memberObject(e)!;
    if (routeKind(obj, symbols) === 'route') return 'snapshot';
  }
  return undefined;
}

/** `snapshot.queryParams`, `snapshot.paramMap`, … — a container of attacker-controlled URL values. */
function routeContainer(expr: ts.Expression, symbols: Symbols): string | undefined {
  const name = memberName(expr);
  if (!name || !ROUTE_CONTAINERS.has(name)) return undefined;
  return routeKind(memberObject(expr)!, symbols) === 'snapshot' ? name : undefined;
}

function isDom(o: TypeOrigin | undefined, ...names: string[]): boolean {
  return originIs(o, 'dom', ...names);
}

/** Request headers that carry the client-chosen host or scheme. */
const HOST_HEADERS = new Set(['host', 'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-server', 'x-original-host', 'x-host', 'forwarded']);
const NODE_REQUEST_MODULES = ['express', 'express-serve-static-core', 'http', 'node:http', 'http2', 'node:http2'];

/** Server-side incoming request: Express / Node `IncomingMessage`, or the Fetch `Request` (Angular `REQUEST` token). */
function requestKind(expr: ts.Expression, symbols: Symbols): 'node' | 'fetch' | undefined {
  const o = symbols.typeOrigin(skipOuter(expr));
  if (originIs(o, NODE_REQUEST_MODULES, 'Request', 'IncomingMessage', 'Http2ServerRequest')) return 'node';
  if (isDom(o, 'Request')) return 'fetch';
  return undefined;
}

const headerSource = (name: string): SourceMatch => ({ kind: 'request-header', description: `request header '${name}'`, trust: 'medium' });

/** Classifies an expression that directly yields an untrusted value. */
export function matchSource(expression: ts.Expression, symbols: Symbols): SourceMatch | undefined {
  const e = skipOuter(expression);

  if (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) {
    const m = matchMemberSource(e.expression, memberName(e), symbols);
    if (m) return m;
  }
  return matchNonMemberSource(e, symbols);
}

/** Source check for `obj.name` (also used for destructuring `const { name } = obj`). */
export function matchMemberSource(obj: ts.Expression, name: string | undefined, symbols: Symbols): SourceMatch | undefined {
  {
    if (!name) {
      // `params[key]` with a dynamic key on a route container.
      const container = routeContainer(obj, symbols);
      return container ? { kind: 'url', description: `route ${container} (dynamic key)`, trust: 'high' } : undefined;
    }
    const container = routeContainer(obj, symbols);
    if (container === 'queryParams' || container === 'params') {
      return { kind: 'url', description: `${container === 'params' ? 'route parameter' : 'URL query parameter'} '${name}' (ActivatedRoute)`, trust: 'high' };
    }
    const objOrigin = symbols.typeOrigin(obj);
    if (name === 'fragment' && routeKind(obj, symbols) === 'snapshot') return { kind: 'url', description: 'URL fragment (ActivatedRoute snapshot)', trust: 'high' };
    if (LOCATION_PROPS.has(name) && isDom(objOrigin, 'Location')) return { kind: 'url', description: `location.${name}`, trust: 'high' };
    if (['URL', 'documentURI', 'baseURI'].includes(name) && isDom(objOrigin, 'Document')) return { kind: 'url', description: `document.${name}`, trust: 'high' };
    if (name === 'referrer' && isDom(objOrigin, 'Document')) return { kind: 'referrer', description: 'document.referrer', trust: 'medium' };
    if (name === 'cookie' && isDom(objOrigin, 'Document')) return { kind: 'cookie', description: 'document.cookie', trust: 'low' };
    if (name === 'name' && isDom(objOrigin, 'Window')) return { kind: 'window-name', description: 'window.name', trust: 'high' };
    if (name === 'data' && isDom(objOrigin, 'MessageEvent')) return { kind: 'message', description: 'MessageEvent.data', trust: 'high' };
    if (name === 'value' && isDom(objOrigin, 'HTMLInputElement', 'HTMLTextAreaElement', 'HTMLSelectElement')) {
      return { kind: 'user-input', description: `${objOrigin!.name}.value`, trust: 'medium' };
    }
    if (name === 'value' && originIs(objOrigin, FORMS, ...FORM_TYPES)) return { kind: 'user-input', description: `${objOrigin!.name}.value (Angular forms)`, trust: 'medium' };
    if (name === 'url' && originIs(objOrigin, ROUTER, 'Router')) return { kind: 'url', description: 'Router.url', trust: 'high' };
    if (HOST_HEADERS.has(name.toLowerCase()) && memberName(obj) === 'headers' && requestKind(memberObject(obj)!, symbols) === 'node') return headerSource(name.toLowerCase());
    if ((name === 'hostname' || name === 'host' || name === 'protocol') && requestKind(obj, symbols) === 'node') return { kind: 'request-header', description: `request.${name} (from the Host / X-Forwarded-* headers)`, trust: 'medium' };
    // Express / Node only: browser code builds Fetch `Request` objects itself, so their `url` is not attacker input.
    if ((name === 'query' || name === 'params' || name === 'originalUrl' || name === 'url') && requestKind(obj, symbols) === 'node') {
      return { kind: 'url', description: `server request ${name} (Express / Node)`, trust: 'high' };
    }
    if (isDom(objOrigin, 'Storage') && name !== 'length' && !['getItem', 'setItem', 'removeItem', 'clear', 'key'].includes(name)) {
      return { kind: 'storage', description: `Web Storage key '${name}'`, trust: 'low' };
    }
  }
  return undefined;
}

function matchNonMemberSource(e: ts.Expression, symbols: Symbols): SourceMatch | undefined {
  if (ts.isCallExpression(e)) {
    const callee = skipOuter(e.expression);
    const name = memberName(callee);
    const recv = memberObject(callee);
    if (recv && (name === 'get' || name === 'getAll')) {
      const container = routeContainer(recv, symbols);
      if (container === 'queryParamMap' || container === 'paramMap') {
        const key = e.arguments[0] ? symbols.constantString(e.arguments[0]) : undefined;
        return { kind: 'url', description: `${container === 'paramMap' ? 'route parameter' : 'URL query parameter'}${key ? ` '${key}'` : ''} (ActivatedRoute)`, trust: 'high' };
      }
    }
    if (recv && name === 'getItem' && isDom(symbols.typeOrigin(recv), 'Storage')) {
      const key = e.arguments[0] ? symbols.constantString(e.arguments[0]) : undefined;
      return { kind: 'storage', description: `Web Storage getItem(${key ? `'${key}'` : '…'})`, trust: 'low' };
    }
    // req.get('host') / req.header('x-forwarded-host') (Express); request.headers.get('host') / headers.get(…) (Fetch)
    if (recv && (name === 'get' || name === 'header') && e.arguments[0]) {
      const key = symbols.constantString(e.arguments[0])?.toLowerCase();
      if (key && HOST_HEADERS.has(key)) {
        if (requestKind(recv, symbols) === 'node') return headerSource(key);
        if (name === 'get' && (isDom(symbols.typeOrigin(recv), 'Headers') || (memberName(recv) === 'headers' && requestKind(memberObject(recv)!, symbols)))) return headerSource(key);
      }
    }
    if (recv && name === 'path' && originIs(symbols.typeOrigin(recv), '@angular/common', 'Location')) {
      return { kind: 'url', description: 'Location.path() (@angular/common)', trust: 'high' };
    }
    if (recv && name === 'getRawValue' && originIs(symbols.typeOrigin(recv), FORMS, ...FORM_TYPES)) {
      return { kind: 'user-input', description: 'form getRawValue()', trust: 'medium' };
    }
    if (ts.isIdentifier(callee) && callee.text === 'fetch') {
      const o = symbols.callee(e)?.origin;
      if (!o || o.module === 'dom' || o.module === 'lib') return { kind: 'http-response', description: 'fetch() response', trust: 'medium' };
    }
  }
  // `location` / `document.location` used as a string.
  if ((ts.isIdentifier(e) || ts.isPropertyAccessExpression(e)) && isDom(symbols.typeOrigin(e), 'Location')) {
    return { kind: 'url', description: 'location (stringified)', trust: 'high' };
  }
  return undefined;
}

const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'request', 'jsonp', 'head', 'options']);

/** Observables that emit untrusted values. */
export function matchObservableSource(expression: ts.Expression, symbols: Symbols): SourceMatch | undefined {
  const e = skipOuter(expression);
  const name = memberName(e);
  if (name && (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e))) {
    const kind = routeKind(e.expression, symbols);
    if (kind === 'route') {
      if (name === 'queryParams' || name === 'queryParamMap') return { kind: 'url', description: `ActivatedRoute.${name}`, trust: 'high' };
      if (name === 'params' || name === 'paramMap') return { kind: 'url', description: `ActivatedRoute.${name} (route parameters)`, trust: 'high' };
      if (name === 'fragment') return { kind: 'url', description: 'ActivatedRoute.fragment', trust: 'high' };
    }
    if (name === 'valueChanges' && originIs(symbols.typeOrigin(e.expression), FORMS, ...FORM_TYPES)) {
      return { kind: 'user-input', description: 'form valueChanges', trust: 'medium' };
    }
  }
  if (ts.isCallExpression(e)) {
    const callee = skipOuter(e.expression);
    const method = memberName(callee);
    const recv = memberObject(callee);
    if (recv && method && HTTP_METHODS.has(method) && originIs(symbols.typeOrigin(recv), '@angular/common/http', 'HttpClient')) {
      const url = e.arguments[0] ? symbols.constantString(e.arguments[0]) : undefined;
      return { kind: 'http-response', description: `HttpClient.${method}(${url ? `'${url}'` : '…'}) response`, trust: 'medium' };
    }
    if (ts.isIdentifier(callee) && callee.text === 'fromEvent' && e.arguments[1]) {
      const evt = symbols.constantString(e.arguments[1]);
      const imp = symbols.importOrigin(callee);
      if (evt === 'message' && (!imp || imp.module === 'rxjs')) return { kind: 'message', description: "fromEvent(…, 'message') MessageEvent", trust: 'high' };
    }
  }
  return undefined;
}
